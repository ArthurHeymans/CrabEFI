//! Shared utilities for menu modules
//!
//! Contains keyboard input handling, screen control, and serial output helpers
//! shared by both the boot menu and the Secure Boot settings menu.

use crate::drivers::keyboard_common as keyboard;
use crate::drivers::serial as serial_driver;
use crate::framebuffer_console::{Color, FramebufferConsole, TITLE_COLOR};
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
    /// Mouse click at pixel coordinates.
    #[cfg(feature = "ui")]
    MouseClick {
        x: u32,
        y: u32,
    },
    /// Mouse scroll (positive = down, negative = up)
    #[cfg(feature = "ui")]
    MouseScroll(i32),
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

    // Check mouse state (if UI feature is enabled).
    // Note: callers must call mouse_cursor::poll() before read_key() —
    // we only inspect the current state here, we do NOT poll again.
    #[cfg(feature = "ui")]
    {
        let scroll = crate::drivers::mouse_cursor::get_scroll();
        if scroll != 0 {
            return Some(KeyPress::MouseScroll(scroll));
        }

        if crate::drivers::mouse_cursor::left_clicked() {
            let (px, py) = crate::drivers::mouse_cursor::position();
            return Some(KeyPress::MouseClick {
                x: px as u32,
                y: py as u32,
            });
        }
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

/// Draw centered help text in cyan on both serial and framebuffer
pub fn draw_help(
    row: usize,
    help_text: &str,
    fb_console: &mut Option<FramebufferConsole>,
    cols: usize,
) {
    // Serial output
    let _ = write!(SerialWriter, "\x1b[{};1H", row + 1);
    serial_driver::write_str("\x1b[36m"); // Cyan
    let help_pad = (cols.saturating_sub(help_text.len())) / 2;
    for _ in 0..help_pad {
        serial_driver::write_str(" ");
    }
    serial_driver::write_str(help_text);
    serial_driver::write_str("\x1b[0m");

    // Framebuffer output
    if let Some(console) = fb_console {
        console.set_fg_color(Color::new(0, 192, 192)); // Cyan
        console.write_centered(row as u32, help_text);
        console.reset_colors();
    }
}

/// Draw a status message in green (success) or red (failure) on both outputs
pub fn draw_status_message(
    row: usize,
    message: &str,
    is_success: bool,
    fb_console: &mut Option<FramebufferConsole>,
) {
    let color = if is_success {
        Color::new(0, 255, 0)
    } else {
        Color::new(255, 0, 0)
    };

    let _ = write!(SerialWriter, "\x1b[{};1H", row + 1);
    if is_success {
        serial_driver::write_str("\x1b[32m");
    } else {
        serial_driver::write_str("\x1b[31m");
    }
    serial_driver::write_str("  ");
    serial_driver::write_str(message);
    serial_driver::write_str("\x1b[0m");

    if let Some(console) = fb_console {
        console.set_fg_color(color);
        console.write_centered(row as u32, message);
        console.reset_colors();
    }
}

/// Show a yes/no confirmation dialog on both serial and framebuffer
///
/// Clears the screen, displays the `prompt` in yellow and the
/// `instruction` below it, then waits for Y (true) or N/Escape (false).
pub fn confirm_dialog(
    fb_console: &mut Option<FramebufferConsole>,
    prompt: &str,
    instruction: &str,
) -> bool {
    let rows = fb_console.as_ref().map(|c| c.rows()).unwrap_or(25);
    let confirm_row = rows / 2;

    // Serial
    serial_driver::write_str("\x1b[2J\x1b[H");
    serial_driver::write_str("\r\n\r\n");
    serial_driver::write_str("\x1b[1;33m"); // Yellow bold
    serial_driver::write_str("  ");
    serial_driver::write_str(prompt);
    serial_driver::write_str("\x1b[0m\r\n\r\n");
    serial_driver::write_str("  ");
    serial_driver::write_str(instruction);
    serial_driver::write_str("\r\n");

    // Framebuffer
    if let Some(console) = fb_console {
        console.clear();
        console.set_fg_color(Color::new(255, 255, 0)); // Yellow
        console.write_centered(confirm_row, prompt);
        console.reset_colors();
        console.write_centered(confirm_row + 2, instruction);
    }

    // Wait for response
    loop {
        if let Some(key) = read_key() {
            match key {
                KeyPress::Char('y') | KeyPress::Char('Y') => return true,
                KeyPress::Char('n') | KeyPress::Char('N') | KeyPress::Escape => return false,
                _ => {}
            }
        }
        delay_ms(10);
    }
}

/// Clear remaining characters on the current framebuffer line with spaces
pub fn clear_line_remainder(console: &mut FramebufferConsole) {
    let (col, _) = console.position();
    for _ in col..console.cols() {
        let _ = console.write_str(" ");
    }
}
