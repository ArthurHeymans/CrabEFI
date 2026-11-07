//! Shared utilities for menu modules
//!
//! Contains keyboard input handling, screen control, and serial output helpers
//! shared by both the boot menu and the Secure Boot settings menu.

use crate::drivers::keyboard_common as keyboard;
use crate::drivers::serial as serial_driver;
use crate::framebuffer_console::{Color, FramebufferConsole, TITLE_COLOR};
use crate::time::{Timeout, delay_ms};
use core::fmt::Write;

/// Key press types for menu navigation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPress {
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Tab,
    BackTab,
    Delete,
    F8,
    F10,
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

/// Read a key from any keyboard or serial
pub fn read_key() -> Option<KeyPress> {
    if let Some((key, state)) = keyboard::try_read_key_with_state() {
        return decode_keyboard_key(key.scancode, key.unicode_char, state.shift_state);
    }

    read_pointer_or_serial()
}

fn decode_keyboard_key(scan_code: u16, unicode_char: u16, shift: u32) -> Option<KeyPress> {
    match scan_code {
        0x01 => Some(KeyPress::Up),    // SCAN_UP
        0x02 => Some(KeyPress::Down),  // SCAN_DOWN
        0x03 => Some(KeyPress::Right), // SCAN_RIGHT
        0x04 => Some(KeyPress::Left),  // SCAN_LEFT
        0x05 => Some(KeyPress::Home),
        0x06 => Some(KeyPress::End),
        0x09 => Some(KeyPress::PageUp),
        0x0A => Some(KeyPress::PageDown),
        0x08 => Some(KeyPress::Delete),
        0x12 => Some(KeyPress::F8),
        0x14 => Some(KeyPress::F10),
        0x17 => Some(KeyPress::Escape), // SCAN_ESC
        0 if unicode_char == 0x0D => Some(KeyPress::Enter), // Carriage return
        0 if unicode_char == 9 => Some(if shift & 3 != 0 {
            KeyPress::BackTab
        } else {
            KeyPress::Tab
        }),
        0 if unicode_char > 0 => char::from_u32(u32::from(unicode_char)).map(KeyPress::Char),
        _ => None,
    }
}

fn read_pointer_or_serial() -> Option<KeyPress> {
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

    read_serial_key()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SerialState {
    Ground,
    Escape,
    Csi,
    Ss3,
}

/// Retain incomplete escape sequences across polls until the caller expires
/// them. Unsupported sequences are consumed through their final byte, never
/// replayed as command/editor input.
struct SerialKeyParser {
    state: SerialState,
    primary: u16,
    first_parameter: bool,
    pending: Option<u8>,
}

impl SerialKeyParser {
    const fn new() -> Self {
        Self {
            state: SerialState::Ground,
            primary: 0,
            first_parameter: true,
            pending: None,
        }
    }

    fn feed(&mut self, byte: u8) -> Option<KeyPress> {
        match self.state {
            SerialState::Ground => match byte {
                0x1b => {
                    self.state = SerialState::Escape;
                    None
                }
                b'\t' => Some(KeyPress::Tab),
                b'\r' | b'\n' => Some(KeyPress::Enter),
                byte => Some(KeyPress::Char(byte as char)),
            },
            SerialState::Escape => {
                self.state = match byte {
                    b'[' => SerialState::Csi,
                    b'O' => SerialState::Ss3,
                    _ => {
                        self.pending = Some(byte);
                        SerialState::Ground
                    }
                };
                self.primary = 0;
                self.first_parameter = true;
                (self.state == SerialState::Ground).then_some(KeyPress::Escape)
            }
            SerialState::Csi | SerialState::Ss3 => {
                if byte == 0x1b {
                    self.state = SerialState::Escape;
                } else if (0x40..=0x7e).contains(&byte) {
                    self.state = SerialState::Ground;
                    return match byte {
                        b'~' => match self.primary {
                            1 | 7 => Some(KeyPress::Home),
                            4 | 8 => Some(KeyPress::End),
                            5 => Some(KeyPress::PageUp),
                            6 => Some(KeyPress::PageDown),
                            3 => Some(KeyPress::Delete),
                            19 => Some(KeyPress::F8),
                            21 => Some(KeyPress::F10),
                            _ => None,
                        },
                        _ => serial_navigation_key(byte),
                    };
                } else if byte == b';' {
                    self.first_parameter = false;
                } else if self.first_parameter && byte.is_ascii_digit() {
                    self.primary = self
                        .primary
                        .saturating_mul(10)
                        .saturating_add(u16::from(byte - b'0'));
                }
                None
            }
        }
    }

    /// The sequence deadline passed with bytes outstanding. A lone ESC is a
    /// key press; an abandoned CSI/SS3 is dropped (its bytes stay consumed)
    /// so later ordinary input is never reinterpreted as its final byte.
    fn expire_partial(&mut self) -> Option<KeyPress> {
        let key = match self.state {
            SerialState::Escape => Some(KeyPress::Escape),
            SerialState::Ground | SerialState::Csi | SerialState::Ss3 => None,
        };
        let pending = self.pending;
        *self = Self::new();
        self.pending = pending;
        key
    }
}

fn serial_navigation_key(byte: u8) -> Option<KeyPress> {
    match byte {
        b'A' => Some(KeyPress::Up),
        b'B' => Some(KeyPress::Down),
        b'C' => Some(KeyPress::Right),
        b'D' => Some(KeyPress::Left),
        b'H' => Some(KeyPress::Home),
        b'F' => Some(KeyPress::End),
        b'Z' => Some(KeyPress::BackTab),
        _ => None,
    }
}

fn read_serial_key() -> Option<KeyPress> {
    static SERIAL: spin::Mutex<(SerialKeyParser, Option<Timeout>)> =
        spin::Mutex::new((SerialKeyParser::new(), None));
    let mut serial = SERIAL.lock();
    let (parser, deadline) = &mut *serial;
    // Bound work per poll even if serial input is continuously available.
    for _ in 0..32 {
        let Some(byte) = parser.pending.take().or_else(serial_driver::try_read) else {
            break;
        };
        let key = parser.feed(byte);
        // One absolute deadline from the initial ESC covers the whole
        // sequence; arriving parameter bytes do not extend it, so a
        // truncated or trickling CSI/SS3 cannot stay armed indefinitely.
        match parser.state {
            SerialState::Ground => *deadline = None,
            _ if deadline.is_none() => *deadline = Some(Timeout::from_ms(30)),
            _ => {}
        }
        if key.is_some() {
            return key;
        }
    }
    if deadline.as_ref().is_some_and(Timeout::is_expired) {
        *deadline = None;
        return parser.expire_partial();
    }
    None
}

#[cfg(test)]
mod serial_tests {
    use super::*;

    #[test]
    fn physical_and_serial_backward_tab_and_delete_agree() {
        assert_eq!(decode_keyboard_key(0, 9, 0), Some(KeyPress::Tab));
        assert_eq!(decode_keyboard_key(0, 9, 1), Some(KeyPress::BackTab));
        assert_eq!(decode_keyboard_key(0, 9, 2), Some(KeyPress::BackTab));
        assert_eq!(decode_keyboard_key(8, 0, 0), Some(KeyPress::Delete));
        let mut p = SerialKeyParser::new();
        let keys: alloc::vec::Vec<_> = b"\t\x1b[Z\x1b[3~\x1b[19~\x1b[21~"
            .iter()
            .filter_map(|b| p.feed(*b))
            .collect();
        assert_eq!(
            keys,
            [
                KeyPress::Tab,
                KeyPress::BackTab,
                KeyPress::Delete,
                KeyPress::F8,
                KeyPress::F10
            ]
        );
    }

    #[test]
    fn modified_and_fragmented_sequences_never_leak_editor_characters() {
        let mut parser = SerialKeyParser::new();
        let keys: alloc::vec::Vec<_> = b"\x1b[1;5C"
            .iter()
            .filter_map(|b| parser.feed(*b))
            .collect();
        assert_eq!(keys, [KeyPress::Right]);
        for byte in b"\x1b[5" {
            assert_eq!(parser.feed(*byte), None);
        }
        // An incomplete CSI survives polls until the caller expires it.
        assert_eq!(parser.feed(b'~'), Some(KeyPress::PageUp));
        for byte in b"\x1b[99;5~" {
            assert_eq!(parser.feed(*byte), None);
        }
        assert_eq!(parser.feed(b'x'), Some(KeyPress::Char('x')));
        assert_eq!(parser.feed(0x1b), None);
        assert_eq!(parser.expire_partial(), Some(KeyPress::Escape));
    }

    #[test]
    fn an_expired_partial_sequence_never_reinterprets_later_input() {
        let mut parser = SerialKeyParser::new();
        // The final byte of ESC [ 5 ~ is lost (line noise, unplugged cable).
        for byte in b"\x1b[5" {
            assert_eq!(parser.feed(*byte), None);
        }
        assert_eq!(parser.expire_partial(), None);
        // Later bytes are ordinary input: not Up, and Enter is not swallowed.
        assert_eq!(parser.feed(b'A'), Some(KeyPress::Char('A')));
        assert_eq!(parser.feed(b'\r'), Some(KeyPress::Enter));
        // Same abandonment for an SS3 left waiting for its final byte.
        for byte in b"\x1bO" {
            assert_eq!(parser.feed(*byte), None);
        }
        assert_eq!(parser.expire_partial(), None);
        assert_eq!(parser.feed(b'P'), Some(KeyPress::Char('P')));
    }

    #[test]
    fn escape_does_not_eat_the_next_ordinary_character() {
        let mut parser = SerialKeyParser::new();
        assert_eq!(parser.feed(0x1b), None);
        assert_eq!(parser.feed(b'f'), Some(KeyPress::Escape));
        let pending = parser.pending.take().unwrap();
        assert_eq!(parser.feed(pending), Some(KeyPress::Char('f')));
    }
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
