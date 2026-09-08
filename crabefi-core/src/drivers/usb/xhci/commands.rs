//! xHCI command submission and event-ring processing.

use super::{XhciError, raw_completion_code, raw_trb_type, read_event_control, read_event_trb};
use crate::time::Timeout;
use xhci::ring::trb::{self, event};

impl super::XhciController {
    /// Wait for and process a command completion event
    pub(super) fn wait_command_completion(
        &mut self,
    ) -> Result<event::CommandCompletion, XhciError> {
        let timeout = Timeout::from_ms(5000);
        // Commands are synchronous. Ignore late completions from an earlier
        // timed-out command, especially when proving Disable/Stop completed.
        let index = self
            .cmd_ring
            .enqueue_idx
            .checked_sub(1)
            .unwrap_or(self.cmd_ring.size - 2);
        let expected = self.cmd_ring.base + (index * trb::BYTES) as u64;

        log::debug!(
            "xHCI: Waiting for command, dequeue_idx={}, expect_cycle={}",
            self.event_ring.dequeue_idx,
            self.event_ring.cycle,
        );

        while !timeout.is_expired() {
            let erdp = self.event_ring.base + (self.event_ring.dequeue_idx * trb::BYTES) as u64;
            let raw = read_event_trb(erdp, self.event_ring.cycle);

            if let Some(raw) = raw {
                log::debug!(
                    "xHCI: Got event type={}, cc={}, param={:#x}",
                    raw_trb_type(&raw),
                    raw_completion_code(&raw),
                    u64::from(raw[0]) | (u64::from(raw[1]) << 32)
                );

                self.event_ring.dequeue_idx += 1;
                if self.event_ring.dequeue_idx >= self.event_ring.size {
                    self.event_ring.dequeue_idx = 0;
                    self.event_ring.cycle = !self.event_ring.cycle;
                }
                self.update_erdp();

                if self.capture_interrupt_event(raw) {
                    continue;
                }
                match event::Allowed::try_from(raw) {
                    Ok(event::Allowed::CommandCompletion(completion)) => {
                        if (u64::from(raw[0]) | (u64::from(raw[1]) << 32)) != expected {
                            continue;
                        }
                        let completion_code = completion.completion_code();
                        if completion_code == Ok(event::CompletionCode::Success) {
                            return Ok(completion);
                        }
                        return Err(XhciError::CommandFailed(completion_code));
                    }
                    Ok(event::Allowed::PortStatusChange(_)) => continue,
                    Ok(event::Allowed::HostController(host)) => {
                        log::error!(
                            "xHCI: Host Controller Event (fatal HSE), cc={:?}",
                            host.completion_code()
                        );
                        return Err(XhciError::CommandFailed(host.completion_code()));
                    }
                    _ => {}
                }
            }
            core::hint::spin_loop();
        }

        self.update_erdp();
        let usbsts = self.registers.operational.usbsts.read_volatile();
        log::warn!(
            "xHCI: Command timeout, USBSTS={:?}, event_ring[0].control={:#x}",
            usbsts,
            read_event_control(self.event_ring.base)
        );

        Err(XhciError::Timeout)
    }

    /// Wait for transfer completion events
    ///
    /// Each TRB is its own independent TD with IOC=1. CrabEFI keeps its
    /// polling, timeout, and ERDP policy while decoding events upstream.
    pub(super) fn wait_transfer_completion(
        &mut self,
        slot: u8,
        ep: u8,
        expected_trbs: usize,
    ) -> Result<u32, XhciError> {
        self.wait_transfer_events(slot, ep, expected_trbs, None)
    }

    /// Wait for one particular TD, rejecting stale completions after cancellation.
    pub(super) fn wait_transfer_td(
        &mut self,
        slot: u8,
        ep: u8,
        trb: u64,
    ) -> Result<u32, XhciError> {
        self.wait_transfer_events(slot, ep, 1, Some(trb))
    }

    fn wait_transfer_events(
        &mut self,
        slot: u8,
        ep: u8,
        expected_trbs: usize,
        expected_td: Option<u64>,
    ) -> Result<u32, XhciError> {
        let timeout = Timeout::from_ms(5000);
        let mut completed = 0usize;
        let mut total_residual = 0u32;

        while !timeout.is_expired() {
            let erdp = self.event_ring.base + (self.event_ring.dequeue_idx * trb::BYTES) as u64;
            let raw = read_event_trb(erdp, self.event_ring.cycle);

            if let Some(raw) = raw {
                self.event_ring.dequeue_idx += 1;
                if self.event_ring.dequeue_idx >= self.event_ring.size {
                    self.event_ring.dequeue_idx = 0;
                    self.event_ring.cycle = !self.event_ring.cycle;
                }
                self.update_erdp();

                if self.capture_interrupt_event(raw) {
                    continue;
                }
                match event::Allowed::try_from(raw) {
                    Ok(event::Allowed::TransferEvent(transfer_event)) => {
                        let event_slot = (raw[3] >> 24) as u8;
                        let event_dci = ((raw[3] >> 16) & 0x1f) as u8;
                        let pointer = u64::from(raw[0]) | (u64::from(raw[1]) << 32);
                        if event_slot != slot
                            || event_dci / 2 != ep
                            || expected_td.is_some_and(|expected| expected != pointer)
                        {
                            continue;
                        }
                        let residual = transfer_event.trb_transfer_length();
                        let completion_code = transfer_event.completion_code();
                        log::trace!(
                            "xHCI: Transfer event cc={:?} residue={} [{}/{}]",
                            completion_code,
                            residual,
                            completed + 1,
                            expected_trbs
                        );

                        if matches!(
                            completion_code,
                            Ok(event::CompletionCode::Success | event::CompletionCode::ShortPacket)
                        ) {
                            completed += 1;
                            total_residual += residual;
                            if completed >= expected_trbs {
                                return Ok(total_residual);
                            }
                        } else if completion_code == Ok(event::CompletionCode::StallError) {
                            log::debug!(
                                "xHCI: Transfer stalled [{}/{}]",
                                completed + 1,
                                expected_trbs
                            );
                            self.drain_remaining_transfer_events(expected_trbs - completed - 1);
                            return Err(XhciError::StallError);
                        } else {
                            log::debug!(
                                "xHCI: Transfer failed with cc={:?} [{}/{}]",
                                completion_code,
                                completed + 1,
                                expected_trbs
                            );
                            self.drain_remaining_transfer_events(expected_trbs - completed - 1);
                            return Err(XhciError::TransferFailed(completion_code));
                        }
                    }
                    Ok(event::Allowed::HostController(host)) => {
                        log::error!(
                            "xHCI: Host Controller Event (fatal HSE) during transfer, cc={:?}",
                            host.completion_code()
                        );
                        return Err(XhciError::TransferFailed(host.completion_code()));
                    }
                    _ => log::trace!(
                        "xHCI: Got event type {} while waiting for transfer",
                        raw_trb_type(&raw)
                    ),
                }
            }
            core::hint::spin_loop();
        }

        log::warn!(
            "xHCI: Transfer timeout, completed={}/{}, event ring dequeue_idx={}, cycle={}",
            completed,
            expected_trbs,
            self.event_ring.dequeue_idx,
            self.event_ring.cycle
        );
        Err(XhciError::Timeout)
    }

    /// Drain remaining transfer events after an error
    ///
    /// When a multi-TRB transfer fails on one TRB, the controller may have
    /// already queued completion events for subsequent TRBs. These must be
    /// consumed to prevent them from confusing later transfers.
    pub(super) fn drain_remaining_transfer_events(&mut self, max_events: usize) {
        let timeout = Timeout::from_ms(100); // Short timeout — events should already be there
        let mut drained = 0usize;
        let mut consumed = 0usize;

        while drained < max_events && !timeout.is_expired() {
            let erdp = self.event_ring.base + (self.event_ring.dequeue_idx * trb::BYTES) as u64;
            let raw = read_event_trb(erdp, self.event_ring.cycle);

            if let Some(raw) = raw {
                self.event_ring.dequeue_idx += 1;
                if self.event_ring.dequeue_idx >= self.event_ring.size {
                    self.event_ring.dequeue_idx = 0;
                    self.event_ring.cycle = !self.event_ring.cycle;
                }
                consumed += 1;

                if !self.capture_interrupt_event(raw) && event::TransferEvent::try_from(raw).is_ok()
                {
                    drained += 1;
                }
            } else {
                break; // No more events ready
            }
            core::hint::spin_loop();
        }

        if consumed > 0 {
            self.update_erdp();
            log::trace!(
                "xHCI: drained {} orphaned transfer events ({} total consumed)",
                drained,
                consumed
            );
        }
    }

    /// Update the Event Ring Dequeue Pointer (ERDP) in hardware
    ///
    /// This writes the current software dequeue pointer to the interrupter's
    /// ERDP register with the EHB (Event Handler Busy) bit set to clear it.
    /// This is a 64-bit split write (two PCIe MMIO writes), so it should be
    /// called as infrequently as possible.
    #[inline]
    pub(super) fn update_erdp(&mut self) {
        let new_erdp = self.event_ring.base + (self.event_ring.dequeue_idx * 16) as u64;
        self.registers
            .interrupter_register_set
            .interrupter_mut(0)
            .erdp
            .update_volatile(|erdp| {
                erdp.set_event_ring_dequeue_pointer(new_erdp);
                erdp.clear_event_handler_busy();
            });
    }
}
