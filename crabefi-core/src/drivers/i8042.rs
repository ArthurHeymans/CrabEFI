//! Shared i8042 command transport. Device commands must run with the other
//! interface disabled: controller replies have no keyboard/AUX source tag.

pub(super) const OUTPUT_FULL: u8 = 1 << 0;
const INPUT_FULL: u8 = 1 << 1;
pub(super) const AUX_DATA: u8 = 1 << 5;
#[cfg(any(feature = "ui", test))]
const KB_DISABLE: u8 = 1 << 4;
#[cfg(any(feature = "ui", test))]
const AUX_DISABLE: u8 = 1 << 5;
#[cfg(any(feature = "ui", test))]
const INTERRUPTS: u8 = 3;
const POLL_US: u64 = 50;
const CONTROLLER_TIMEOUT_US: u64 = 500_000;
const ACK_TIMEOUT_US: u64 = 200_000;

/// Small I/O boundary so command ordering and timeouts can be tested without
/// executing privileged port instructions.
pub(super) trait Controller {
    fn status(&self) -> u8;
    fn read_data(&self) -> u8;
    fn write_data(&self, byte: u8);
    fn write_command(&self, byte: u8);

    fn now_us(&self) -> u64 {
        ((crate::time::read_counter() as u128 * 1_000_000)
            / crate::time::counter_frequency().max(1) as u128) as u64
    }

    fn delay(&self) {
        crate::time::delay_us(POLL_US);
    }

    /// Poll selected status bits with an elapsed-time bound, not a CPU-speed
    /// dependent iteration count.
    fn wait_status(&self, mask: u8, value: u8) -> bool {
        let start = self.now_us();
        loop {
            if self.status() & mask == value {
                return true;
            }
            if self.now_us().wrapping_sub(start) >= CONTROLLER_TIMEOUT_US {
                return false;
            }
            self.delay();
        }
    }

    fn wait_input_ready(&self) -> bool {
        self.wait_status(INPUT_FULL, 0)
    }

    fn wait_output_ready(&self) -> bool {
        self.wait_status(OUTPUT_FULL, OUTPUT_FULL)
    }

    /// Wait before and after sending a controller command. A timeout after
    /// the write does not imply the command had no effect; callers must still
    /// restore any interface they may have inhibited.
    fn send_controller_cmd(&self, command: u8) -> bool {
        if !self.wait_input_ready() {
            return false;
        }
        self.write_command(command);
        self.wait_input_ready()
    }

    /// Drain stale replies only while the interfaces are inhibited.
    fn flush_output(&self) -> bool {
        for _ in 0..128 {
            if self.status() & OUTPUT_FULL == 0 {
                return true;
            }
            self.read_data();
            self.delay();
        }
        false
    }

    /// Ignore unrelated bytes rather than mistaking the first byte for an ACK.
    /// The caller must inhibit the other interface for the whole transaction.
    fn send_device_byte(&self, aux: bool, byte: u8) -> bool {
        for _ in 0..3 {
            if aux && !self.send_controller_cmd(0xD4) {
                return false;
            }
            if !self.wait_input_ready() {
                return false;
            }
            self.write_data(byte);
            let start = self.now_us();
            loop {
                let status = self.status();
                if status & OUTPUT_FULL != 0 {
                    let response = self.read_data();
                    if (status & AUX_DATA != 0) == aux {
                        match response {
                            0xFA => return true,
                            0xFE => break,
                            _ => {}
                        }
                    }
                }
                if self.now_us().wrapping_sub(start) >= ACK_TIMEOUT_US {
                    return false;
                }
                self.delay();
            }
        }
        false
    }
}

/// Run AUX discovery without letting keyboard replies or scancodes masquerade
/// as controller configuration/test replies. The keyboard reset must already
/// have completed (or timed out) before calling this.
#[cfg(any(feature = "ui", test))]
pub(super) fn init_aux<C: Controller>(io: &mut C, init: impl FnOnce(&mut C) -> bool) -> bool {
    let result = (|| {
        // Even a failed wait after writing DISABLE_KB can leave the keyboard
        // inhibited. Keep this command inside the keyboard-restoration path.
        if !io.send_controller_cmd(0xAD) || !io.send_controller_cmd(0xA7) || !io.flush_output() {
            return false;
        }
        // The AUX port-test reply is untagged too. Read it with both clocks
        // inhibited, before the configuration write enables AUX traffic.
        if !io.send_controller_cmd(0xA9) || !io.wait_output_ready() || io.read_data() != 0 {
            return false;
        }
        if !io.send_controller_cmd(0x20) || !io.wait_output_ready() {
            return false;
        }
        // Keep the keyboard inhibited while enabling the AUX clock. We poll
        // both devices, so do not inherit IRQ enables from an earlier firmware.
        let config = (io.read_data() | KB_DISABLE) & !(AUX_DISABLE | INTERRUPTS);
        if !io.send_controller_cmd(0x60) || !io.wait_input_ready() {
            return false;
        }
        io.write_data(config);
        if !io.wait_input_ready() {
            return false;
        }
        init(io)
    })();
    // Restore the keyboard on every exit, including failed AUX discovery.
    let restored = io.send_controller_cmd(0xAE);
    result && restored
}

#[cfg(test)]
#[path = "i8042_tests.rs"]
mod tests;
