//! xHCI bulk and interrupt transfers.

use super::{TrbRing, XhciError};
use crate::barrier;
use crate::efi;
use xhci::context::EndpointType;
use xhci::ring::trb::{command, event, transfer};

impl super::XhciController {
    /// Perform a single synchronous interrupt IN transfer.
    ///
    /// Queues one Normal TRB on the interrupt endpoint's transfer ring,
    /// rings the doorbell, and waits for the completion event.  Reuses the
    /// existing `wait_transfer_completion` path.
    pub(super) fn interrupt_transfer_impl(
        &mut self,
        slot_id: u8,
        endpoint: u8,
        data: &mut [u8],
    ) -> Result<usize, XhciError> {
        let in_dci = (endpoint as usize * 2) + 1;

        let slot = self
            .slots
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::DeviceNotFound)?;

        let ring = slot.transfer_rings[in_dci - 1]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        // Queue a Normal TRB for the interrupt IN transfer
        let mut trb = transfer::Normal::new();
        trb.set_data_buffer_pointer(data.as_ptr() as u64)
            .set_trb_transfer_length((data.len() as u32) & 0x1ffff)
            .set_interrupt_on_completion()
            .set_interrupt_on_short_packet();

        ring.enqueue(trb, false);
        barrier::mmio_write();
        self.ring_doorbell(slot_id, in_dci as u8);

        // Reuse the existing transfer completion path (expects 1 TRB event).
        let residual = self.wait_transfer_completion(slot_id, endpoint, 1)?;
        let transferred = data.len().saturating_sub(residual as usize);
        Ok(transferred)
    }

    /// Configure bulk endpoints
    pub(super) fn configure_bulk_endpoints(
        &mut self,
        slot_id: u8,
        bulk_in: u8,
        bulk_out: u8,
        max_packet: u16,
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
        in_ep_ctx.set_max_packet_size(max_packet);
        in_ep_ctx.set_max_burst_size(0);
        in_ep_ctx.set_error_count(3);
        in_ep_ctx.set_tr_dequeue_pointer(in_ring_addr);
        in_ep_ctx.set_dequeue_cycle_state();
        in_ep_ctx.set_average_trb_length(max_packet);

        // Bulk OUT endpoint
        let out_ep_ctx = Self::input_ep_context(input, context_size, out_dci - 1);
        out_ep_ctx.set_endpoint_type(EndpointType::BulkOut);
        out_ep_ctx.set_max_packet_size(max_packet);
        out_ep_ctx.set_max_burst_size(0);
        out_ep_ctx.set_error_count(3);
        out_ep_ctx.set_tr_dequeue_pointer(out_ring_addr);
        out_ep_ctx.set_dequeue_cycle_state();
        out_ep_ctx.set_average_trb_length(max_packet);

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
    /// This retains large SCSI commands without relying on chained xHCI TRBs.
    pub fn bulk_transfer(
        &mut self,
        slot_id: u8,
        ep: u8,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<usize, XhciError> {
        const TD_MAX_TRANSFER_SIZE: usize = 0x10000;

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

        let mut transferred_total = 0usize;
        while transferred_total < data.len() {
            let chunk_end = (transferred_total + TD_MAX_TRANSFER_SIZE).min(data.len());
            let chunk = &mut data[transferred_total..chunk_end];
            self.queue_bulk_trb(slot_id, dci, is_in, chunk)?;

            barrier::mmio_write();
            self.ring_doorbell(slot_id, dci as u8);

            match self.wait_transfer_completion(slot_id, ep, 1) {
                Ok(residual) => {
                    let transferred = chunk.len().saturating_sub(residual as usize);
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
                Err(e) => return Err(e),
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
    pub(super) fn queue_bulk_trb(
        &mut self,
        slot_id: u8,
        dci: usize,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<(), XhciError> {
        debug_assert!(data.len() <= 0x10000);

        let slot = self
            .slots
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::DeviceNotFound)?;

        let ring = slot.transfer_rings[dci - 1]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        let mut trb = transfer::Normal::new();
        trb.set_data_buffer_pointer(data.as_ptr() as u64)
            .set_trb_transfer_length(data.len() as u32)
            .set_interrupt_on_completion();
        if is_in {
            trb.set_interrupt_on_short_packet();
        }

        ring.enqueue(trb, false);
        log::trace!("xHCI: queued {}B bulk TD", data.len());
        Ok(())
    }
}
