//! xHCI control transfers and descriptors.

use super::super::controller::{DeviceDescriptor, desc_type, req_type, request};
use super::{TrbRing, XhciError};
use crate::barrier;
use xhci::ring::trb::{command, transfer};
use zerocopy::FromBytes;

impl super::XhciController {
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

        let slot = self
            .slots
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::DeviceNotFound)?;

        let ring = slot.transfer_rings[0]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        let is_in = (request_type & 0x80) != 0;
        let data_len = data.as_ref().map(|h| h.len()).unwrap_or(0);

        // Save cycle state before enqueuing the first (deferred) TRB
        let first_trb_cycle = ring.cycle;

        // Setup Stage TRB — enqueued with DEFERRED cycle bit
        let mut setup = transfer::SetupStage::new();
        setup
            .set_request_type(request_type)
            .set_request(request)
            .set_value(value)
            .set_index(index)
            .set_length(data_len as u16)
            .set_transfer_type(if data_len == 0 {
                transfer::TransferType::No
            } else if is_in {
                transfer::TransferType::In
            } else {
                transfer::TransferType::Out
            });

        let first_trb_addr = ring.enqueue(setup, true); // defer_cycle = true

        // Data Stage TRB (if needed)
        // Note: We intentionally do NOT set ISP (Interrupt on Short Packet) on the
        // Data Stage TRB. With ISP, a short packet would generate an extra event
        // before the Status Stage's IOC event, but wait_transfer_completion only
        // expects 1 event. The orphaned Status event would corrupt later transfers.
        // EDK2 also relies solely on IOC on the Status Stage TRB.
        if let Some(data_buf) = data {
            let mut data_trb = transfer::DataStage::new();
            data_trb
                .set_data_buffer_pointer(data_buf.as_ptr() as u64)
                .set_trb_transfer_length(data_buf.len() as u32)
                .set_direction(if is_in {
                    transfer::Direction::In
                } else {
                    transfer::Direction::Out
                });

            ring.enqueue(data_trb, false);
        }

        // Status Stage TRB
        let mut status = transfer::StatusStage::new();
        if data_len == 0 || !is_in {
            status.set_direction();
        }
        status.set_interrupt_on_completion();

        ring.enqueue(status, false);

        // Commit the deferred first TRB — atomically makes the entire TD live
        TrbRing::commit_deferred_trb(first_trb_addr, first_trb_cycle);

        // Publish the DMA transfer ring before its MMIO doorbell.
        barrier::mmio_write();
        self.ring_doorbell(slot_id, DCI_EP0);

        // Wait for completion
        match self.wait_transfer_completion(slot_id, 0, 1) {
            Ok(total_residual) => {
                // Return transfer length
                Ok(data_len.saturating_sub(total_residual as usize))
            }
            Err(XhciError::StallError) => {
                // Control endpoint stalled - reset it
                log::debug!(
                    "xHCI: Control transfer stalled on slot={}, resetting endpoint",
                    slot_id
                );
                if let Err(e) = self.reset_endpoint(slot_id, DCI_EP0) {
                    log::warn!(
                        "xHCI: Failed to reset control endpoint after stall: {:?}",
                        e
                    );
                }
                Err(XhciError::StallError)
            }
            Err(e) => Err(e),
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
                .and_then(|slot| slot.as_mut())
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

    /// Get the device descriptor.
    pub(super) fn get_device_descriptor(
        &mut self,
        slot_id: u8,
    ) -> Result<DeviceDescriptor, XhciError> {
        let mut desc = [0u8; 18];

        // First, get just 8 bytes to determine max packet size.
        let mut short_desc = [0u8; 8];
        self.control_transfer(
            slot_id,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::DEVICE as u16) << 8,
            0,
            Some(&mut short_desc),
        )?;

        let full_speed = self
            .slots
            .get(slot_id as usize)
            .and_then(|slot| slot.as_ref())
            .is_some_and(|slot| slot.speed == 1);
        if full_speed {
            self.update_full_speed_ep0_max_packet(slot_id, short_desc[7] as u16)?;
        }

        // Now get full descriptor
        self.control_transfer(
            slot_id,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::DEVICE as u16) << 8,
            0,
            Some(&mut desc),
        )?;

        // Parse device descriptor using zerocopy
        DeviceDescriptor::read_from_prefix(&desc)
            .map(|(d, _)| d)
            .map_err(|_| XhciError::InvalidParameter)
    }

    /// Set configuration
    pub(super) fn set_configuration(&mut self, slot_id: u8, config: u8) -> Result<(), XhciError> {
        self.control_transfer(
            slot_id,
            req_type::DIR_OUT | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::SET_CONFIGURATION,
            config as u16,
            0,
            None,
        )?;
        Ok(())
    }
}
