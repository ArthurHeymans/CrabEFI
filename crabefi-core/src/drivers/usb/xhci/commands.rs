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

    pub(super) fn wait_control_transfer(
        &mut self,
        slot: u8,
        setup: u64,
        data: Option<u64>,
        status: u64,
    ) -> Result<u32, XhciError> {
        self.wait_transfer_events(
            slot,
            1,
            TransferCompletion::Control {
                setup,
                data,
                status,
                residual: 0,
            },
        )
    }

    /// Wait for one particular TD, rejecting stale completions after cancellation.
    pub(super) fn wait_transfer_td(
        &mut self,
        slot: u8,
        dci: u8,
        trb: u64,
    ) -> Result<u32, XhciError> {
        self.wait_transfer_events(slot, dci, TransferCompletion::Bulk(trb))
    }

    fn wait_transfer_events(
        &mut self,
        slot: u8,
        endpoint: u8,
        mut completion: TransferCompletion,
    ) -> Result<u32, XhciError> {
        let timeout = Timeout::from_ms(5000);
        while !timeout.is_expired() {
            let erdp = self.event_ring.base + (self.event_ring.dequeue_idx * trb::BYTES) as u64;
            if let Some(raw) = read_event_trb(erdp, self.event_ring.cycle) {
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
                    Ok(event::Allowed::PortStatusChange(_)) => continue,
                    Ok(event::Allowed::TransferEvent(event)) => {
                        let event_slot = (raw[3] >> 24) as u8;
                        let event_dci = ((raw[3] >> 16) & 0x1f) as u8;
                        if event_slot == slot
                            && endpoint == event_dci
                            && let Some(result) = completion.observe(
                                event.trb_pointer(),
                                event.completion_code(),
                                event.trb_transfer_length(),
                            )
                        {
                            return result;
                        }
                    }
                    Ok(event::Allowed::HostController(host)) => {
                        log::error!(
                            "xHCI: Host Controller Event (fatal HSE) during transfer, cc={:?}",
                            host.completion_code()
                        );
                        return Err(XhciError::TransferFailed(host.completion_code()));
                    }
                    _ => {}
                }
            }
            core::hint::spin_loop();
        }
        log::warn!(
            "xHCI: Transfer timeout, event ring dequeue_idx={}, cycle={}",
            self.event_ring.dequeue_idx,
            self.event_ring.cycle
        );
        Err(XhciError::Timeout)
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

// A short Data Stage can generate a Transfer Event before Status completes.
// Its residual is the only actual length information for a short control IN.
enum TransferCompletion {
    Bulk(u64),
    Control {
        setup: u64,
        data: Option<u64>,
        status: u64,
        residual: u32,
    },
}

impl TransferCompletion {
    fn observe(
        &mut self,
        pointer: u64,
        code: Result<event::CompletionCode, u8>,
        length: u32,
    ) -> Option<Result<u32, XhciError>> {
        use event::CompletionCode::{ShortPacket, StallError, Success};
        let result = match *self {
            Self::Bulk(trb) if trb == pointer => length,
            Self::Control {
                setup,
                data,
                status,
                residual,
            } if pointer == setup || Some(pointer) == data || pointer == status => {
                if code == Ok(ShortPacket) && Some(pointer) == data {
                    if let Self::Control { residual, .. } = self {
                        *residual = length;
                    }
                    return None;
                }
                if code == Ok(Success) && pointer != status {
                    return None;
                }
                residual
            }
            _ => return None, // Not part of the current transfer.
        };
        Some(match code {
            Ok(Success | ShortPacket) => Ok(result),
            Ok(StallError) => Err(XhciError::StallError),
            _ => Err(XhciError::TransferFailed(code)),
        })
    }
}

#[cfg(test)]
#[test]
fn control_short_data_records_residual_but_waits_for_its_status() {
    use event::CompletionCode::{ShortPacket, StallError, Success};
    let mut td = TransferCompletion::Control {
        setup: 0x1000,
        data: Some(0x1010),
        status: 0x1020,
        residual: 0,
    };
    assert!(td.observe(0x1010, Ok(ShortPacket), 27).is_none());
    assert!(td.observe(0x1030, Ok(Success), 0).is_none());
    assert!(matches!(td.observe(0x1020, Ok(Success), 0), Some(Ok(27))));
    assert!(matches!(
        td.observe(0x1000, Ok(StallError), 0),
        Some(Err(XhciError::StallError))
    ));
}
