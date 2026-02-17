//! Shared utilities for menu modules
//!
//! Contains keyboard input handling shared by the boot menu, Secure Boot
//! settings menu, and CFR firmware settings menu.

use crate::drivers::keyboard;
use crate::drivers::serial as serial_driver;
use crate::time::delay_ms;

/// Key press types for menu navigation
#[derive(Debug, Clone, Copy)]
pub enum KeyPress {
    Up,
    Down,
    Left,
    Right,
    Enter,
    Escape,
    Char(char),
}

/// Read a key from keyboard (PS/2, USB, or serial)
pub fn read_key() -> Option<KeyPress> {
    // Try PS/2 keyboard first
    if let Some((scan_code, unicode_char)) = keyboard::try_read_key() {
        return match scan_code {
            0x01 => Some(KeyPress::Up),                         // SCAN_UP
            0x02 => Some(KeyPress::Down),                       // SCAN_DOWN
            0x03 => Some(KeyPress::Right),                      // SCAN_RIGHT
            0x04 => Some(KeyPress::Left),                       // SCAN_LEFT
            0x17 => Some(KeyPress::Escape),                     // SCAN_ESC
            0 if unicode_char == 0x0D => Some(KeyPress::Enter), // Carriage return
            0 if unicode_char > 0 => Some(KeyPress::Char(unicode_char as u8 as char)),
            _ => None,
        };
    }

    // Try USB keyboard
    if let Some((scan_code, unicode_char)) = crate::drivers::usb::keyboard_get_key() {
        return match scan_code {
            0x01 => Some(KeyPress::Up),
            0x02 => Some(KeyPress::Down),
            0x03 => Some(KeyPress::Right),
            0x04 => Some(KeyPress::Left),
            0x17 => Some(KeyPress::Escape),
            0 if unicode_char == 0x0D => Some(KeyPress::Enter),
            0 if unicode_char > 0 => Some(KeyPress::Char(unicode_char as u8 as char)),
            _ => None,
        };
    }

    // Try serial input
    if let Some(byte) = serial_driver::try_read() {
        return match byte {
            0x1B => {
                // Escape - check for escape sequence
                delay_ms(10);
                if let Some(b'[') = serial_driver::try_read() {
                    match serial_driver::try_read() {
                        Some(b'A') => Some(KeyPress::Up),
                        Some(b'B') => Some(KeyPress::Down),
                        Some(b'C') => Some(KeyPress::Right),
                        Some(b'D') => Some(KeyPress::Left),
                        _ => Some(KeyPress::Escape),
                    }
                } else {
                    Some(KeyPress::Escape)
                }
            }
            b'\r' | b'\n' => Some(KeyPress::Enter),
            c => Some(KeyPress::Char(c as char)),
        };
    }

    None
}
