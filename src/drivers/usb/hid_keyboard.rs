//! USB HID Keyboard Driver
//!
//! This module implements USB HID keyboard support using the boot protocol.
//! The boot protocol is simpler than the report protocol and is supported by
//! all HID-compliant keyboards.
//!
//! # References
//! - USB HID Specification 1.11
//! - libpayload usbhid.c

use super::controller::{UsbController, UsbError, hid_request, req_type};
use spin::Mutex;

// ============================================================================
// HID Boot Protocol Keyboard
// ============================================================================

/// Boot protocol keyboard report (8 bytes)
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct KeyboardReport {
    /// Modifier keys (Ctrl, Shift, Alt, GUI)
    pub modifiers: u8,
    /// Reserved byte
    pub reserved: u8,
    /// Key codes (up to 6 simultaneous keys)
    pub keys: [u8; 6],
}

impl KeyboardReport {
    /// Left Control
    pub const MOD_LEFT_CTRL: u8 = 1 << 0;
    /// Left Shift
    pub const MOD_LEFT_SHIFT: u8 = 1 << 1;
    /// Left Alt
    pub const MOD_LEFT_ALT: u8 = 1 << 2;
    /// Left GUI (Windows key)
    pub const MOD_LEFT_GUI: u8 = 1 << 3;
    /// Right Control
    pub const MOD_RIGHT_CTRL: u8 = 1 << 4;
    /// Right Shift
    pub const MOD_RIGHT_SHIFT: u8 = 1 << 5;
    /// Right Alt
    pub const MOD_RIGHT_ALT: u8 = 1 << 6;
    /// Right GUI
    pub const MOD_RIGHT_GUI: u8 = 1 << 7;

    /// Check if any shift is pressed
    pub fn shift_pressed(&self) -> bool {
        (self.modifiers & (Self::MOD_LEFT_SHIFT | Self::MOD_RIGHT_SHIFT)) != 0
    }

    /// Check if any control is pressed
    pub fn ctrl_pressed(&self) -> bool {
        (self.modifiers & (Self::MOD_LEFT_CTRL | Self::MOD_RIGHT_CTRL)) != 0
    }

    /// Check if any alt is pressed
    pub fn alt_pressed(&self) -> bool {
        (self.modifiers & (Self::MOD_LEFT_ALT | Self::MOD_RIGHT_ALT)) != 0
    }

    /// Check if a key is pressed (in this report)
    pub fn is_key_pressed(&self, keycode: u8) -> bool {
        self.keys.iter().any(|&k| k == keycode && k != 0)
    }

    /// Find new keys that weren't in the previous report
    pub fn new_keys<'a>(&'a self, prev: &'a KeyboardReport) -> impl Iterator<Item = u8> + 'a {
        self.keys
            .iter()
            .copied()
            .filter(move |&k| k != 0 && !prev.keys.contains(&k))
    }
}

// ============================================================================
// USB HID Keyboard State
// ============================================================================

/// USB HID keyboard state
pub struct UsbHidKeyboard {
    /// Controller index
    controller_idx: usize,
    /// Device address
    device_address: u8,
    /// Interrupt endpoint number (kept for hardware completeness)
    #[allow(dead_code)]
    endpoint: u8,
    /// Max packet size (kept for hardware completeness)
    #[allow(dead_code)]
    max_packet: u16,
    /// Polling interval (ms, kept for hardware completeness)
    #[allow(dead_code)]
    interval: u8,
    /// Previous report (for detecting changes)
    prev_report: KeyboardReport,
    /// Caps Lock state
    caps_lock: bool,
    /// Num Lock state
    num_lock: bool,
    /// Key buffer
    key_buffer: [u16; 16],
    /// Buffer read index
    read_idx: usize,
    /// Buffer write index
    write_idx: usize,
    /// Last key for repeat
    last_key: u16,
    /// Repeat counter
    repeat_counter: u32,
}

impl UsbHidKeyboard {
    /// Create a new USB HID keyboard
    pub fn new(
        controller_idx: usize,
        device_address: u8,
        endpoint: u8,
        max_packet: u16,
        interval: u8,
    ) -> Self {
        Self {
            controller_idx,
            device_address,
            endpoint,
            max_packet,
            interval,
            prev_report: KeyboardReport::default(),
            caps_lock: false,
            num_lock: false,
            key_buffer: [0; 16],
            read_idx: 0,
            write_idx: 0,
            last_key: 0,
            repeat_counter: 0,
        }
    }

    /// Set boot protocol mode
    pub fn set_boot_protocol<C: UsbController>(
        &mut self,
        controller: &mut C,
    ) -> Result<(), UsbError> {
        // SET_PROTOCOL with protocol = 0 (boot protocol)
        controller.control_transfer(
            self.device_address,
            req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE,
            hid_request::SET_PROTOCOL,
            0, // Boot protocol
            0, // Interface 0
            None,
        )?;
        Ok(())
    }

    /// Set idle rate (key repeat rate)
    pub fn set_idle<C: UsbController>(
        &mut self,
        controller: &mut C,
        rate_ms: u8,
    ) -> Result<(), UsbError> {
        // SET_IDLE with duration in 4ms units
        let duration = rate_ms / 4;
        controller.control_transfer(
            self.device_address,
            req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE,
            hid_request::SET_IDLE,
            (duration as u16) << 8, // Duration in high byte
            0,                      // Interface 0
            None,
        )?;
        Ok(())
    }

    /// Set LED state
    pub fn set_leds<C: UsbController>(&mut self, controller: &mut C) -> Result<(), UsbError> {
        let mut led_byte = 0u8;
        if self.num_lock {
            led_byte |= 1;
        }
        if self.caps_lock {
            led_byte |= 2;
        }
        // Scroll Lock would be bit 2

        let mut data = [led_byte];
        controller.control_transfer(
            self.device_address,
            req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE,
            hid_request::SET_REPORT,
            0x0200, // Report type = Output (2), Report ID = 0
            0,      // Interface 0
            Some(&mut data),
        )?;
        Ok(())
    }

    /// Process a keyboard report
    pub fn process_report(&mut self, report: &KeyboardReport) {
        // Collect new keycodes first to avoid borrow conflict
        let new_keycodes: heapless::Vec<u8, 6> = report.new_keys(&self.prev_report).collect();

        // Process each new keycode
        for keycode in new_keycodes {
            if let Some(efi_key) = self.translate_keycode(keycode, report) {
                self.enqueue_key(efi_key);

                // Handle lock keys
                match keycode {
                    0x39 => {
                        // Caps Lock
                        self.caps_lock = !self.caps_lock;
                    }
                    0x53 => {
                        // Num Lock
                        self.num_lock = !self.num_lock;
                    }
                    _ => {}
                }

                // Set last key for repeat
                self.last_key = efi_key;
                self.repeat_counter = 0;
            }
        }

        // Check for key release
        if !report.keys.iter().any(|&k| k != 0) {
            self.last_key = 0;
            self.repeat_counter = 0;
        }

        self.prev_report = *report;
    }

    /// Handle key repeat
    pub fn handle_repeat(&mut self) {
        if self.last_key != 0 {
            self.repeat_counter += 1;
            // Initial delay of ~500ms (50 polls at 10ms), then repeat at ~30ms (3 polls)
            if self.repeat_counter > 50 && (self.repeat_counter - 50).is_multiple_of(3) {
                self.enqueue_key(self.last_key);
            }
        }
    }

    /// Enqueue a key
    fn enqueue_key(&mut self, key: u16) {
        let next_write = (self.write_idx + 1) % self.key_buffer.len();
        if next_write != self.read_idx {
            self.key_buffer[self.write_idx] = key;
            self.write_idx = next_write;
        }
    }

    /// Check if keys are available
    pub fn has_key(&self) -> bool {
        self.read_idx != self.write_idx
    }

    /// Get a key from the buffer
    pub fn get_key(&mut self) -> Option<u16> {
        if self.read_idx == self.write_idx {
            return None;
        }
        let key = self.key_buffer[self.read_idx];
        self.read_idx = (self.read_idx + 1) % self.key_buffer.len();
        Some(key)
    }

    /// Translate HID keycode to EFI key
    ///
    /// Returns packed (scan_code << 8) | unicode_char
    fn translate_keycode(&self, keycode: u8, report: &KeyboardReport) -> Option<u16> {
        let shift = report.shift_pressed() ^ self.caps_lock;
        let ctrl = report.ctrl_pressed();

        // EFI scan codes
        const SCAN_UP: u16 = 0x01;
        const SCAN_DOWN: u16 = 0x02;
        const SCAN_RIGHT: u16 = 0x03;
        const SCAN_LEFT: u16 = 0x04;
        const SCAN_HOME: u16 = 0x05;
        const SCAN_END: u16 = 0x06;
        const SCAN_INSERT: u16 = 0x07;
        const SCAN_DELETE: u16 = 0x08;
        const SCAN_PAGE_UP: u16 = 0x09;
        const SCAN_PAGE_DOWN: u16 = 0x0A;
        const SCAN_F1: u16 = 0x0B;
        const SCAN_F2: u16 = 0x0C;
        const SCAN_F3: u16 = 0x0D;
        const SCAN_F4: u16 = 0x0E;
        const SCAN_F5: u16 = 0x0F;
        const SCAN_F6: u16 = 0x10;
        const SCAN_F7: u16 = 0x11;
        const SCAN_F8: u16 = 0x12;
        const SCAN_F9: u16 = 0x13;
        const SCAN_F10: u16 = 0x14;
        const SCAN_F11: u16 = 0x15;
        const SCAN_F12: u16 = 0x16;
        const SCAN_ESC: u16 = 0x17;

        // Special keys (return scan_code << 8)
        let scan_code = match keycode {
            0x29 => return Some(SCAN_ESC << 8), // Escape
            0x3A => return Some(SCAN_F1 << 8),
            0x3B => return Some(SCAN_F2 << 8),
            0x3C => return Some(SCAN_F3 << 8),
            0x3D => return Some(SCAN_F4 << 8),
            0x3E => return Some(SCAN_F5 << 8),
            0x3F => return Some(SCAN_F6 << 8),
            0x40 => return Some(SCAN_F7 << 8),
            0x41 => return Some(SCAN_F8 << 8),
            0x42 => return Some(SCAN_F9 << 8),
            0x43 => return Some(SCAN_F10 << 8),
            0x44 => return Some(SCAN_F11 << 8),
            0x45 => return Some(SCAN_F12 << 8),
            0x49 => return Some(SCAN_INSERT << 8),
            0x4A => return Some(SCAN_HOME << 8),
            0x4B => return Some(SCAN_PAGE_UP << 8),
            0x4C => return Some(SCAN_DELETE << 8),
            0x4D => return Some(SCAN_END << 8),
            0x4E => return Some(SCAN_PAGE_DOWN << 8),
            0x4F => return Some(SCAN_RIGHT << 8),
            0x50 => return Some(SCAN_LEFT << 8),
            0x51 => return Some(SCAN_DOWN << 8),
            0x52 => return Some(SCAN_UP << 8),
            _ => 0,
        };

        if scan_code != 0 {
            return Some(scan_code << 8);
        }

        // Character keys
        let ch = match keycode {
            // Letters (a-z: 0x04-0x1D)
            0x04..=0x1D => {
                let base = b'a' + (keycode - 0x04);
                if ctrl {
                    base - b'a' + 1 // Ctrl+A = 1, Ctrl+Z = 26
                } else if shift {
                    base.to_ascii_uppercase()
                } else {
                    base
                }
            }

            // Numbers (1-9, 0: 0x1E-0x27)
            0x1E => {
                if shift {
                    b'!'
                } else {
                    b'1'
                }
            }
            0x1F => {
                if shift {
                    b'@'
                } else {
                    b'2'
                }
            }
            0x20 => {
                if shift {
                    b'#'
                } else {
                    b'3'
                }
            }
            0x21 => {
                if shift {
                    b'$'
                } else {
                    b'4'
                }
            }
            0x22 => {
                if shift {
                    b'%'
                } else {
                    b'5'
                }
            }
            0x23 => {
                if shift {
                    b'^'
                } else {
                    b'6'
                }
            }
            0x24 => {
                if shift {
                    b'&'
                } else {
                    b'7'
                }
            }
            0x25 => {
                if shift {
                    b'*'
                } else {
                    b'8'
                }
            }
            0x26 => {
                if shift {
                    b'('
                } else {
                    b'9'
                }
            }
            0x27 => {
                if shift {
                    b')'
                } else {
                    b'0'
                }
            }

            // Special characters
            0x28 => 0x0D, // Enter
            0x2A => 0x08, // Backspace
            0x2B => 0x09, // Tab
            0x2C => b' ', // Space
            0x2D => {
                if shift {
                    b'_'
                } else {
                    b'-'
                }
            }
            0x2E => {
                if shift {
                    b'+'
                } else {
                    b'='
                }
            }
            0x2F => {
                if shift {
                    b'{'
                } else {
                    b'['
                }
            }
            0x30 => {
                if shift {
                    b'}'
                } else {
                    b']'
                }
            }
            0x31 => {
                if shift {
                    b'|'
                } else {
                    b'\\'
                }
            }
            0x33 => {
                if shift {
                    b':'
                } else {
                    b';'
                }
            }
            0x34 => {
                if shift {
                    b'"'
                } else {
                    b'\''
                }
            }
            0x35 => {
                if shift {
                    b'~'
                } else {
                    b'`'
                }
            }
            0x36 => {
                if shift {
                    b'<'
                } else {
                    b','
                }
            }
            0x37 => {
                if shift {
                    b'>'
                } else {
                    b'.'
                }
            }
            0x38 => {
                if shift {
                    b'?'
                } else {
                    b'/'
                }
            }

            // Keypad numbers (if NumLock is on)
            0x59 => {
                if self.num_lock {
                    b'1'
                } else {
                    return Some(SCAN_END << 8);
                }
            }
            0x5A => {
                if self.num_lock {
                    b'2'
                } else {
                    return Some(SCAN_DOWN << 8);
                }
            }
            0x5B => {
                if self.num_lock {
                    b'3'
                } else {
                    return Some(SCAN_PAGE_DOWN << 8);
                }
            }
            0x5C => {
                if self.num_lock {
                    b'4'
                } else {
                    return Some(SCAN_LEFT << 8);
                }
            }
            0x5D => {
                if self.num_lock {
                    b'5'
                } else {
                    return None;
                }
            }
            0x5E => {
                if self.num_lock {
                    b'6'
                } else {
                    return Some(SCAN_RIGHT << 8);
                }
            }
            0x5F => {
                if self.num_lock {
                    b'7'
                } else {
                    return Some(SCAN_HOME << 8);
                }
            }
            0x60 => {
                if self.num_lock {
                    b'8'
                } else {
                    return Some(SCAN_UP << 8);
                }
            }
            0x61 => {
                if self.num_lock {
                    b'9'
                } else {
                    return Some(SCAN_PAGE_UP << 8);
                }
            }
            0x62 => {
                if self.num_lock {
                    b'0'
                } else {
                    return Some(SCAN_INSERT << 8);
                }
            }
            0x63 => {
                if self.num_lock {
                    b'.'
                } else {
                    return Some(SCAN_DELETE << 8);
                }
            }

            // Keypad operators
            0x54 => b'/',
            0x55 => b'*',
            0x56 => b'-',
            0x57 => b'+',
            0x58 => 0x0D, // Keypad Enter

            _ => return None,
        };

        Some(ch as u16)
    }

    /// Get device address
    pub fn device_address(&self) -> u8 {
        self.device_address
    }

    /// Get controller index
    pub fn controller_idx(&self) -> usize {
        self.controller_idx
    }
}

// ============================================================================
// Global USB Keyboard
// ============================================================================

/// Global USB keyboard instance
static USB_KEYBOARD: Mutex<Option<UsbHidKeyboard>> = Mutex::new(None);

/// Initialize USB keyboard from a controller
pub fn init_keyboard<C: UsbController>(
    controller: &mut C,
    controller_idx: usize,
) -> Result<(), UsbError> {
    // Find HID keyboard device
    let device_addr = controller
        .find_hid_keyboard()
        .ok_or(UsbError::DeviceNotFound)?;

    // Get interrupt endpoint
    let ep_info = controller
        .get_interrupt_endpoint(device_addr)
        .ok_or(UsbError::DeviceNotFound)?;

    log::info!(
        "USB HID keyboard found: device {}, endpoint {}, interval {}ms",
        device_addr,
        ep_info.number,
        ep_info.interval
    );

    let mut keyboard = UsbHidKeyboard::new(
        controller_idx,
        device_addr,
        ep_info.number,
        ep_info.max_packet_size,
        ep_info.interval,
    );

    // Set boot protocol
    log::debug!("Setting boot protocol for keyboard device {}", device_addr);
    if let Err(e) = keyboard.set_boot_protocol(controller) {
        log::warn!("Failed to set boot protocol: {:?}", e);
    }
    log::debug!("Boot protocol set");

    // Set idle rate (30ms)
    log::debug!("Setting idle rate");
    if let Err(e) = keyboard.set_idle(controller, 30) {
        log::warn!("Failed to set idle rate: {:?}", e);
    }
    log::debug!("Idle rate set");

    *USB_KEYBOARD.lock() = Some(keyboard);

    log::info!("USB HID keyboard initialized");
    Ok(())
}

/// Check if USB keyboard has keys
pub fn has_key() -> bool {
    USB_KEYBOARD
        .lock()
        .as_ref()
        .map(|k| k.has_key())
        .unwrap_or(false)
}

/// Get key from USB keyboard
pub fn get_key() -> Option<(u16, u16)> {
    let mut keyboard = USB_KEYBOARD.lock();
    let key = keyboard.as_mut()?.get_key()?;

    let scan_code = (key >> 8) & 0xFF;
    let unicode = key & 0xFF;
    Some((scan_code, unicode))
}

/// Poll USB keyboard (called periodically)
pub fn poll<C: UsbController>(controller: &mut C) {
    let mut keyboard_guard = USB_KEYBOARD.lock();
    let keyboard = match keyboard_guard.as_mut() {
        Some(k) => k,
        None => return,
    };

    // Try to get a report via control transfer (since interrupt queues aren't implemented)
    let mut report_buf = [0u8; 8];
    let result = controller.control_transfer(
        keyboard.device_address(),
        req_type::DIR_IN | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE,
        hid_request::GET_REPORT,
        0x0100, // Report type = Input (1), Report ID = 0
        0,      // Interface 0
        Some(&mut report_buf),
    );

    match result {
        Ok(_) => {
            let report = KeyboardReport {
                modifiers: report_buf[0],
                reserved: report_buf[1],
                keys: [
                    report_buf[2],
                    report_buf[3],
                    report_buf[4],
                    report_buf[5],
                    report_buf[6],
                    report_buf[7],
                ],
            };
            keyboard.process_report(&report);
        }
        Err(_) => {
            // Silently ignore errors - keyboard might not have anything new
        }
    }

    keyboard.handle_repeat();
}

/// Check if USB keyboard is available
pub fn is_available() -> bool {
    USB_KEYBOARD.lock().is_some()
}

/// Get the controller index that has the keyboard
pub fn controller_idx() -> Option<usize> {
    USB_KEYBOARD.lock().as_ref().map(|k| k.controller_idx())
}
