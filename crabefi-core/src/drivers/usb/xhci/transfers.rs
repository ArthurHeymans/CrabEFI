//! xHCI control transfers and descriptors.

use super::{TrbRing, XhciError};
use crate::barrier;
use crate::drivers::pci;
use crate::efi::dma::{DmaBuffer, DmaDirection, DmaMask};
use xhci::ring::trb::{command, event, transfer};

const TRB_BOUNDARY: usize = 0x10000;

/// A Data Stage TRB must not cross a 64 KiB boundary in device address space.
fn ep0_data_offset(address: u64, len: usize) -> usize {
    let to_boundary = TRB_BOUNDARY - ((address as usize) & (TRB_BOUNDARY - 1));
    if len <= to_boundary { 0 } else { to_boundary }
}

#[cfg(test)]
#[test]
fn ep0_data_offset_keeps_one_data_stage_inside_its_dma_boundary() {
    assert_eq!(ep0_data_offset(0x10000, 0xffff), 0);
    assert_eq!(ep0_data_offset(0x1fff0, 16), 0);
    assert_eq!(ep0_data_offset(0x1fff0, 17), 16);
    assert_eq!(ep0_data_offset(0x12000, 0xffff), 0xe000);
}

impl super::XhciController {
    fn ep0_buffer(&mut self, len: usize) -> Result<(DmaBuffer, usize), XhciError> {
        if let Some(buffer) = self.control_buffer.take() {
            let offset = ep0_data_offset(buffer.dma_address(), len);
            if offset + len <= buffer.len() {
                return Ok((buffer, offset));
            }
        }
        let domain = pci::dma_domain(self.pci_address).ok_or(XhciError::NotReady)?;
        let mask = if self
            .registers
            .capability
            .hccparams1
            .read_volatile()
            .addressing_capability()
        {
            DmaMask::bits64()
        } else {
            DmaMask::bits32()
        };
        let capacity = len.max(crate::efi::allocator::PAGE_SIZE_USIZE);
        let buffer = DmaBuffer::allocate_in_domain(capacity, mask, domain)
            .map_err(|_| XhciError::AllocationFailed)?;
        if ep0_data_offset(buffer.dma_address(), len) == 0 {
            return Ok((buffer, 0));
        }
        // Keep small transfers to one page on page-aligned DMA domains.
        // Allocate alignment slack only when the address actually crosses.
        drop(buffer);
        let buffer = DmaBuffer::allocate_in_domain(capacity + TRB_BOUNDARY - 1, mask, domain)
            .map_err(|_| XhciError::AllocationFailed)?;
        let offset = ep0_data_offset(buffer.dma_address(), len);
        Ok((buffer, offset))
    }
    /// Control transfer
    ///
    /// Performs a USB control transfer (Setup -> Data -> Status stages).
    /// Uses the "deferred first TRB" technique: the Setup TRB is initially
    /// written with an inverted cycle bit so the HC won't start processing
    /// until the entire TD (Setup + optional Data + Status) is built.
    /// Automatically recovers from stall errors by resetting the endpoint.
    pub(super) fn control_transfer(
        &mut self,
        slot_id: u8,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: Option<&mut [u8]>,
    ) -> Result<usize, XhciError> {
        const DCI_EP0: u8 = 1; // Control endpoint is always DCI 1

        if self
            .get_slot(slot_id)
            .and_then(|slot| slot.transfer_rings[0].as_ref())
            .is_none()
        {
            return Err(XhciError::DeviceNotFound);
        }
        let is_in = (request_type & 0x80) != 0;
        let data_len = data.as_ref().map_or(0, |buf| buf.len());
        let length = u16::try_from(data_len).map_err(|_| XhciError::InvalidParameter)?;
        let direction = if is_in {
            DmaDirection::FromDevice
        } else {
            DmaDirection::ToDevice
        };
        let mut bounce = None;
        let mut offset = 0;
        if let Some(data) = data.as_deref().filter(|data| !data.is_empty()) {
            let (mut buffer, start) = self.ep0_buffer(data.len())?;
            offset = start;
            if !is_in {
                buffer.as_mut_slice()[offset..offset + data.len()].copy_from_slice(data);
            }
            buffer
                .sync_for_device(0..buffer.len(), direction)
                .map_err(|_| XhciError::NotReady)?;
            bounce = Some(buffer);
        }

        let ring = self
            .get_slot_mut(slot_id)
            .and_then(|slot| slot.transfer_rings[0].as_mut())
            .ok_or(XhciError::DeviceNotFound)?;
        // Save cycle state before enqueuing the first (deferred) TRB
        let first_trb_cycle = ring.cycle;

        // Setup Stage TRB — enqueued with DEFERRED cycle bit
        let mut setup = transfer::SetupStage::new();
        setup
            .set_request_type(request_type)
            .set_request(request)
            .set_value(value)
            .set_index(index)
            .set_length(length)
            .set_transfer_type(if data_len == 0 {
                transfer::TransferType::No
            } else if is_in {
                transfer::TransferType::In
            } else {
                transfer::TransferType::Out
            });

        let first_trb_addr = ring.enqueue(setup, true); // defer_cycle = true

        let data_trb_addr = bounce.as_ref().map(|buffer| {
            let mut data_trb = transfer::DataStage::new();
            data_trb
                .set_data_buffer_pointer(buffer.dma_address() + offset as u64)
                .set_trb_transfer_length(data_len as u32)
                .set_direction(if is_in {
                    transfer::Direction::In
                } else {
                    transfer::Direction::Out
                });
            if is_in {
                data_trb.set_interrupt_on_short_packet();
            }
            ring.enqueue(data_trb, false)
        });

        // Status Stage TRB
        let mut status = transfer::StatusStage::new();
        if data_len == 0 || !is_in {
            status.set_direction();
        }
        status.set_interrupt_on_completion();

        let status_trb_addr = ring.enqueue(status, false);

        // Commit the deferred first TRB — atomically makes the entire TD live
        TrbRing::commit_deferred_trb(first_trb_addr, first_trb_cycle);

        // Publish the DMA transfer ring before its MMIO doorbell.
        barrier::mmio_write();
        self.ring_doorbell(slot_id, DCI_EP0);

        // Wait for completion
        match self.wait_control_transfer(slot_id, first_trb_addr, data_trb_addr, status_trb_addr) {
            Ok(total_residual) => {
                let transferred = data_len.saturating_sub(total_residual as usize);
                if is_in && transferred < data_len {
                    log::debug!("xHCI: EP0 short IN: {transferred}/{data_len} bytes");
                }
                if let Some(buffer) = &bounce {
                    buffer
                        .sync_for_cpu(0..buffer.len(), direction)
                        .map_err(|_| XhciError::NotReady)?;
                    if is_in && let Some(data) = data {
                        data[..transferred]
                            .copy_from_slice(&buffer.as_slice()[offset..offset + transferred]);
                    }
                    self.control_buffer = bounce;
                }
                Ok(transferred)
            }
            Err(error) => {
                let recovered = match error {
                    XhciError::Timeout => self.stop_endpoint(slot_id, DCI_EP0),
                    XhciError::StallError
                    | XhciError::TransferFailed(Ok(
                        event::CompletionCode::BabbleDetectedError
                        | event::CompletionCode::UsbTransactionError,
                    )) => self.reset_endpoint(slot_id, DCI_EP0),
                    _ => Err(XhciError::NotReady),
                };
                if recovered.is_ok() {
                    if let Some(buffer) = &bounce
                        && buffer.sync_for_cpu(0..buffer.len(), direction).is_ok()
                    {
                        self.control_buffer = bounce;
                    }
                } else {
                    // Stop/Reset and Set TR Dequeue must both succeed before
                    // the old TD cannot run again. Do not ring EP0 or return
                    // the mapping to the allocator on an unconfirmed error.
                    core::mem::forget(bounce);
                    if let Some(slot) = self.get_slot_mut(slot_id) {
                        slot.transfer_rings[0] = None;
                    }
                    log::warn!("xHCI: quarantined EP0 on slot {slot_id} after {error:?}");
                }
                Err(error)
            }
        }
    }

    /// Update a full-speed device's EP0 max packet size.
    pub(super) fn update_full_speed_ep0_max_packet(
        &mut self,
        slot_id: u8,
        max_packet: u16,
    ) -> Result<(), XhciError> {
        if !matches!(max_packet, 8 | 16 | 32 | 64) {
            log::error!("xHCI: invalid full-speed EP0 max packet size {max_packet}");
            return Err(XhciError::InvalidParameter);
        }

        let context_size = self.context_size;
        let input_context = {
            let slot = self
                .slots
                .get_mut(slot_id as usize)
                .and_then(|slot| slot.as_deref_mut())
                .ok_or(XhciError::DeviceNotFound)?;
            let input = slot.input_context;
            unsafe {
                core::ptr::write_bytes(input, 0, Self::input_context_len(context_size));
            }
            Self::copy_device_ep_context(input, slot.device_context, context_size, 0);
            let ep0 = Self::input_ep_context(input, context_size, 0);
            ep0.set_max_packet_size(max_packet);
            Self::input_control_context(input, context_size).set_add_context_flag(1);
            input as u64
        };

        let mut command = command::EvaluateContext::new();
        command
            .set_input_context_pointer(input_context)
            .set_slot_id(slot_id);

        self.cmd_ring.enqueue(command, false);
        barrier::mmio_write();
        self.ring_doorbell(0, 0);
        self.wait_command_completion()?;
        Ok(())
    }
}
