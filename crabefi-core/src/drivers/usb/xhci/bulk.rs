//! xHCI bulk and interrupt transfers.

use xhci::context::EndpointType;
use xhci::ring::trb::{command, event, transfer};

use super::{TrbRing, XhciError};
use crate::barrier;
use crate::drivers::pci;
use crate::efi;
use crate::efi::dma::{DmaBuffer, DmaDirection, DmaMask};

const TD_MAX_TRANSFER_SIZE: usize = 0x10000;

/// Offset to a 64 KiB boundary in device (not necessarily CPU) address space.
fn bulk_dma_offset(address: u64) -> usize {
    (address.wrapping_neg() & (TD_MAX_TRANSFER_SIZE as u64 - 1)) as usize
}

impl super::XhciController {
    /// Perform a single synchronous interrupt IN transfer.
    ///
    /// Queues one Normal TRB on the interrupt endpoint's transfer ring,
    /// uses a DMA-domain bounce buffer, and waits for its completion event.
    /// Failed polls cancel the old TD before releasing that buffer.
    pub(super) fn interrupt_transfer_impl(
        &mut self,
        slot_id: u8,
        endpoint: u8,
        data: &mut [u8],
    ) -> Result<usize, XhciError> {
        if endpoint == 0 || endpoint > 15 || data.len() > TD_MAX_TRANSFER_SIZE {
            return Err(XhciError::InvalidParameter);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let in_dci = (endpoint as usize * 2) + 1;
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
        let bounce =
            DmaBuffer::allocate_in_domain(data.len() + TD_MAX_TRANSFER_SIZE - 1, mask, domain)
                .map_err(|_| XhciError::AllocationFailed)?;
        let offset = bulk_dma_offset(bounce.dma_address());
        bounce
            .sync_for_device(0..bounce.len(), DmaDirection::FromDevice)
            .map_err(|_| XhciError::NotReady)?;
        let td = self.queue_bulk_trb(
            slot_id,
            in_dci,
            true,
            bounce.dma_address() + offset as u64,
            data.len(),
        )?;
        barrier::mmio_write();
        self.ring_doorbell(slot_id, in_dci as u8);

        match self.wait_transfer_td(slot_id, endpoint, td) {
            Ok(residual) => {
                bounce
                    .sync_for_cpu(0..bounce.len(), DmaDirection::FromDevice)
                    .map_err(|_| XhciError::NotReady)?;
                let transferred = data.len().saturating_sub(residual as usize);
                data[..transferred]
                    .copy_from_slice(&bounce.as_slice()[offset..offset + transferred]);
                Ok(transferred)
            }
            Err(error) => {
                // A timeout does not cancel DMA. Stop and skip the old TD before
                // allowing another poll; Reset Endpoint is only for halted EPs.
                let cancelled = if matches!(error, XhciError::StallError) {
                    self.reset_endpoint(slot_id, in_dci as u8)
                } else {
                    self.stop_endpoint(slot_id, in_dci as u8)
                };
                if cancelled.is_err() {
                    // Quarantine the endpoint and retain its DMA mapping if we
                    // cannot prove the old TD is no longer controller-owned.
                    core::mem::forget(bounce);
                    if let Some(slot) = self
                        .slots
                        .get_mut(slot_id as usize)
                        .and_then(Option::as_mut)
                    {
                        slot.transfer_rings[in_dci - 1] = None;
                    }
                } else {
                    bounce
                        .sync_for_cpu(0..bounce.len(), DmaDirection::FromDevice)
                        .map_err(|_| XhciError::NotReady)?;
                }
                Err(error)
            }
        }
    }

    /// Configure bulk endpoints
    pub(super) fn configure_bulk_endpoints(
        &mut self,
        slot_id: u8,
        bulk_in: u8,
        bulk_out: u8,
        in_max_packet: u16,
        out_max_packet: u16,
    ) -> Result<(), XhciError> {
        let slot = self
            .slots
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::DeviceNotFound)?;

        // Allocate transfer rings for bulk endpoints
        let in_ring_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        let in_ring_addr = in_ring_mem.as_ptr() as u64;
        let out_ring_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        let out_ring_addr = out_ring_mem.as_ptr() as u64;

        let in_ring = TrbRing::new(in_ring_addr, 256);
        let out_ring = TrbRing::new(out_ring_addr, 256);
        let context_size = self.context_size;

        // Calculate DCI (Device Context Index) for endpoints
        // DCI = (Endpoint Number * 2) + Direction (0=OUT, 1=IN)
        let in_dci = (bulk_in as usize * 2) + 1;
        let out_dci = bulk_out as usize * 2;

        // Set up input context
        let input = slot.input_context;
        unsafe {
            core::ptr::write_bytes(input, 0, Self::input_context_len(context_size));
        }

        // Copy slot context from device context
        Self::copy_device_slot_context(input, slot.device_context, context_size);
        let slot_ctx = Self::input_slot_context(input, context_size);
        slot_ctx.set_context_entries(in_dci.max(out_dci) as u8);

        // Set up endpoint contexts
        let control = Self::input_control_context(input, context_size);
        control.set_add_context_flag(0);
        control.set_add_context_flag(in_dci);
        control.set_add_context_flag(out_dci);

        // Bulk IN endpoint
        let in_ep_ctx = Self::input_ep_context(input, context_size, in_dci - 1);
        in_ep_ctx.set_endpoint_type(EndpointType::BulkIn);
        in_ep_ctx.set_max_packet_size(in_max_packet);
        in_ep_ctx.set_max_burst_size(0);
        in_ep_ctx.set_error_count(3);
        in_ep_ctx.set_tr_dequeue_pointer(in_ring_addr);
        in_ep_ctx.set_dequeue_cycle_state();
        in_ep_ctx.set_average_trb_length(in_max_packet);

        // Bulk OUT endpoint
        let out_ep_ctx = Self::input_ep_context(input, context_size, out_dci - 1);
        out_ep_ctx.set_endpoint_type(EndpointType::BulkOut);
        out_ep_ctx.set_max_packet_size(out_max_packet);
        out_ep_ctx.set_max_burst_size(0);
        out_ep_ctx.set_error_count(3);
        out_ep_ctx.set_tr_dequeue_pointer(out_ring_addr);
        out_ep_ctx.set_dequeue_cycle_state();
        out_ep_ctx.set_average_trb_length(out_max_packet);

        // Store rings
        slot.transfer_rings[in_dci - 1] = Some(in_ring);
        slot.transfer_rings[out_dci - 1] = Some(out_ring);

        // Send Configure Endpoint command
        let mut command = command::ConfigureEndpoint::new();
        command
            .set_input_context_pointer(slot.input_context as u64)
            .set_slot_id(slot_id);

        self.cmd_ring.enqueue(command, false);
        barrier::mmio_write();
        self.ring_doorbell(0, 0);

        self.wait_command_completion()?;

        Ok(())
    }

    /// Bulk transfer
    ///
    /// Large requests are submitted as a sequence of independent 64 KiB TDs.
    /// Only one TD is visible to the controller at a time, so a short packet
    /// ends the request before a later TD can consume the following BOT CSW.
    /// A device-aligned bounce window keeps every TRB inside a 64 KiB boundary.
    /// Full TDs remain multiples of every supported bulk max-packet size, unlike
    /// splitting at an arbitrary caller buffer boundary (which can end OUT early
    /// or truncate an IN packet). No chained TRBs or extra ZLPs are needed.
    pub fn bulk_transfer(
        &mut self,
        slot_id: u8,
        ep: u8,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<usize, XhciError> {
        if data.is_empty() {
            return Ok(0);
        }

        let dci = if is_in {
            (ep as usize * 2) + 1
        } else {
            ep as usize * 2
        };

        log::trace!(
            "xHCI: bulk_transfer slot={} ep={} dci={} dir={} len={} addr={:#x}",
            slot_id,
            ep,
            dci,
            if is_in { "IN" } else { "OUT" },
            data.len(),
            data.as_ptr() as u64
        );

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
        // DmaBuffer only guarantees page alignment. Reserve enough padding to
        // align a complete TD in device space, including translated DMA domains.
        let capacity = data.len().min(TD_MAX_TRANSFER_SIZE);
        let mut bounce =
            DmaBuffer::allocate_in_domain(capacity + TD_MAX_TRANSFER_SIZE - 1, mask, domain)
                .map_err(|_| XhciError::AllocationFailed)?;
        let offset = bulk_dma_offset(bounce.dma_address());
        let dma_address = bounce.dma_address() + offset as u64;
        let direction = if is_in {
            DmaDirection::FromDevice
        } else {
            DmaDirection::ToDevice
        };

        let mut transferred_total = 0usize;
        while transferred_total < data.len() {
            let chunk_len = (data.len() - transferred_total).min(TD_MAX_TRANSFER_SIZE);
            let chunk = &mut data[transferred_total..transferred_total + chunk_len];
            if !is_in {
                bounce.as_mut_slice()[offset..offset + chunk_len].copy_from_slice(chunk);
            }
            // Synchronize the whole exclusive allocation: non-coherent DMA
            // ownership cannot safely be handed off for partial cache lines.
            bounce
                .sync_for_device(0..bounce.len(), direction)
                .map_err(|_| XhciError::NotReady)?;
            let td = self.queue_bulk_trb(slot_id, dci, is_in, dma_address, chunk_len)?;

            barrier::mmio_write();
            self.ring_doorbell(slot_id, dci as u8);

            // Error paths retain the allocation: a timeout or failed recovery
            // does not prove that the controller has stopped referencing it.
            match self.wait_transfer_td(slot_id, ep, td) {
                Ok(residual) => {
                    bounce
                        .sync_for_cpu(0..bounce.len(), direction)
                        .map_err(|_| XhciError::NotReady)?;
                    let transferred = chunk.len().saturating_sub(residual as usize);
                    if is_in {
                        chunk[..transferred]
                            .copy_from_slice(&bounce.as_slice()[offset..offset + transferred]);
                    }
                    transferred_total += transferred;
                    if transferred < chunk.len() {
                        log::trace!(
                            "xHCI: bulk transfer ended on short packet, transferred={}/{}",
                            transferred_total,
                            data.len()
                        );
                        return Ok(transferred_total);
                    }
                }
                Err(XhciError::StallError) => {
                    core::mem::forget(bounce);
                    log::debug!(
                        "xHCI: Bulk transfer stalled on slot={} dci={}, resetting endpoint",
                        slot_id,
                        dci
                    );
                    if let Err(e) = self.reset_endpoint(slot_id, dci as u8) {
                        log::warn!("xHCI: Failed to reset endpoint after stall: {:?}", e);
                    }
                    return Err(XhciError::StallError);
                }
                Err(XhciError::TransferFailed(Ok(
                    cc @ (event::CompletionCode::BabbleDetectedError
                    | event::CompletionCode::UsbTransactionError),
                ))) => {
                    core::mem::forget(bounce);
                    log::debug!(
                        "xHCI: Bulk transfer failed with {:?} on slot={} dci={}, resetting endpoint",
                        cc,
                        slot_id,
                        dci
                    );
                    if let Err(e) = self.reset_endpoint(slot_id, dci as u8) {
                        log::warn!(
                            "xHCI: Failed to reset endpoint after completion code {:?}: {:?}",
                            cc,
                            e
                        );
                    }
                    return Err(XhciError::TransferFailed(Ok(cc)));
                }
                Err(e) => {
                    core::mem::forget(bounce);
                    return Err(e);
                }
            }
        }

        log::trace!(
            "xHCI: bulk transfer complete, transferred={}",
            transferred_total
        );
        Ok(transferred_total)
    }

    /// Queue one independent bulk TD.
    ///
    /// Keeping the TD to one 64 KiB TRB avoids the chained-TRB interactions
    /// that cause BABBLE on some Intel xHCI controllers.
    fn queue_bulk_trb(
        &mut self,
        slot_id: u8,
        dci: usize,
        is_in: bool,
        dma_address: u64,
        len: usize,
    ) -> Result<u64, XhciError> {
        debug_assert!(len <= TD_MAX_TRANSFER_SIZE);
        debug_assert_eq!(dma_address & (TD_MAX_TRANSFER_SIZE as u64 - 1), 0);

        let slot = self
            .slots
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::DeviceNotFound)?;

        let ring = slot.transfer_rings[dci - 1]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        let mut trb = transfer::Normal::new();
        trb.set_data_buffer_pointer(dma_address)
            .set_trb_transfer_length(len as u32)
            .set_interrupt_on_completion();
        if is_in {
            trb.set_interrupt_on_short_packet();
        }

        let td = ring.enqueue(trb, false);
        log::trace!("xHCI: queued {}B TD", len);
        Ok(td)
    }
}

#[cfg(test)]
mod tests {
    use super::{TD_MAX_TRANSFER_SIZE, bulk_dma_offset};

    #[test]
    fn bounce_window_fits_all_device_address_alignments() {
        // Include non-page-aligned device addresses: a DMA domain translation
        // need not preserve the CPU allocation's page alignment.
        for low in 0..TD_MAX_TRANSFER_SIZE as u64 {
            let address = 0x1_0000_0000 + low;
            let offset = bulk_dma_offset(address);
            let start = address + offset as u64;
            assert_eq!(start & 0xffff, 0);
            assert!(offset < TD_MAX_TRANSFER_SIZE);
            for len in [13, 31, 512, TD_MAX_TRANSFER_SIZE] {
                assert!(offset + len < len + TD_MAX_TRANSFER_SIZE);
                assert_eq!(start >> 16, (start + len as u64 - 1) >> 16);
            }
        }
        assert_eq!(bulk_dma_offset(0), 0);
        assert_eq!(bulk_dma_offset(0xffff), 1);
    }
}
