//! Shared utilities for menu modules
//!
//! Contains keyboard input handling, screen control, and serial output helpers
//! shared by both the boot menu and the Secure Boot settings menu.

use crate::drivers::keyboard;
use crate::drivers::serial as serial_driver;
use crate::framebuffer_console::{FramebufferConsole, TITLE_COLOR};
use crate::time::delay_ms;
use core::fmt::Write;

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

/// Clear both serial and framebuffer screens
pub fn clear_screen(fb_console: &mut Option<FramebufferConsole>) {
    serial_driver::write_str("\x1b[2J\x1b[H");
    if let Some(console) = fb_console {
        console.clear();
    }
}

/// Draw a menu header with a title on both serial and framebuffer
pub fn draw_header(title: &str, fb_console: &mut Option<FramebufferConsole>, cols: usize) {
    // Build horizontal line
    let mut line = [0u8; 128];
    let line_len = cols.min(line.len());
    line[..line_len].fill(b'=');
    let line_str = core::str::from_utf8(&line[..line_len]).unwrap_or("");

    // Serial output
    serial_driver::write_str("\x1b[H"); // Home cursor
    serial_driver::write_str("\x1b[1;33m"); // Yellow, bold
    serial_driver::write_str(line_str);
    serial_driver::write_str("\r\n");

    // Center title
    let title_pad = (cols.saturating_sub(title.len())) / 2;
    for _ in 0..title_pad {
        serial_driver::write_str(" ");
    }
    serial_driver::write_str(title);
    serial_driver::write_str("\r\n");

    serial_driver::write_str(line_str);
    serial_driver::write_str("\r\n\x1b[0m"); // Reset attributes

    // Framebuffer output
    if let Some(console) = fb_console {
        console.set_position(0, 0);
        console.set_fg_color(TITLE_COLOR);
        let _ = console.write_str(line_str);
        console.set_position(0, 1);
        console.write_centered(1, title);
        console.set_position(0, 2);
        let _ = console.write_str(line_str);
        console.reset_colors();
    }
}

/// Helper for serial formatted output
pub struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial_driver::write_str(s);
        Ok(())
    }
}
