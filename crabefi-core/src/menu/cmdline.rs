//! One-shot kernel command-line editor for the text boot menu.

use crate::drivers::serial as serial_driver;
use crate::framebuffer_console::{
    Color, DEFAULT_FG, FramebufferConsole, HIGHLIGHT_BG, HIGHLIGHT_FG, TITLE_COLOR,
};
use crate::menu_common::{self, KeyPress, SerialWriter};
use crate::time::delay_ms;
use core::fmt::Write;
use heapless::String;

/// Result of command line editing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EditResult {
    /// Edit cancelled (Escape) - drop the edited buffer
    Cancelled,
    /// Edit confirmed (Enter) - keep the edited buffer, return to menu
    Confirmed,
    /// Boot now (Ctrl+X) - keep the edited buffer and boot immediately
    Boot,
}

/// Edit the command line of a boot entry
///
/// Displays a full-screen editor for the kernel command line.
///
/// # Arguments
///
/// * `entry_name` - Display name of the entry being edited
/// * `initial` - Command line to start editing from
/// * `fb_console` - Optional framebuffer console for display
///
/// # Returns
///
/// The returned buffer is the edited text; the caller records it as the
/// menu's one-shot override for `Confirmed`/`Boot` and drops it otherwise.
/// Nothing is written into the entry here.
///
/// `EditResult::Cancelled` if the user pressed Escape
/// `EditResult::Confirmed` if the user pressed Enter (return to menu)
/// `EditResult::Boot` if the user pressed Ctrl+X (boot immediately)
pub(super) fn edit_cmdline(
    entry_name: &str,
    initial: &str,
    fb_console: &mut Option<FramebufferConsole>,
) -> (EditResult, String<512>) {
    // Create a working buffer for editing
    let mut buffer: String<512> = String::new();
    let _ = buffer.push_str(initial);
    let mut cursor_pos = buffer.len();

    // Calculate scroll offset for long command lines
    let cols = fb_console.as_ref().map(|c| c.cols()).unwrap_or(80) as usize;
    let edit_width = cols.saturating_sub(4); // Leave margin for decoration

    // Draw static parts once
    draw_cmdline_editor_static(entry_name, fb_console, cols);

    // Track if display needs updating
    let mut needs_redraw = true;

    loop {
        // Only redraw if something changed
        if needs_redraw {
            draw_cmdline_editor_line(&buffer, cursor_pos, edit_width, fb_console);
            needs_redraw = false;
        }

        // Wait for input
        if let Some(key) = menu_common::read_key() {
            match key {
                KeyPress::Enter => {
                    return (EditResult::Confirmed, buffer);
                }
                KeyPress::Escape => {
                    // Cancel - caller drops the buffer
                    return (EditResult::Cancelled, buffer);
                }
                KeyPress::Char(c) => {
                    // Handle special characters
                    match c {
                        '\x18' => {
                            // Ctrl+X - boot immediately
                            return (EditResult::Boot, buffer);
                        }
                        '\x08' | '\x7f' if cursor_pos > 0 => {
                            // Backspace - remove character before cursor
                            let mut new_buffer: String<512> = String::new();
                            for (i, ch) in buffer.chars().enumerate() {
                                if i != cursor_pos - 1 {
                                    let _ = new_buffer.push(ch);
                                }
                            }
                            buffer = new_buffer;
                            cursor_pos -= 1;
                            needs_redraw = true;
                        }
                        '\x01' if cursor_pos != 0 => {
                            // Ctrl+A - move to beginning
                            cursor_pos = 0;
                            needs_redraw = true;
                        }
                        '\x05' if cursor_pos != buffer.len() => {
                            // Ctrl+E - move to end
                            cursor_pos = buffer.len();
                            needs_redraw = true;
                        }
                        '\x0b' if cursor_pos < buffer.len() => {
                            // Ctrl+K - delete to end of line
                            let mut new_buffer: String<512> = String::new();
                            for (i, ch) in buffer.chars().enumerate() {
                                if i < cursor_pos {
                                    let _ = new_buffer.push(ch);
                                }
                            }
                            buffer = new_buffer;
                            needs_redraw = true;
                        }
                        '\x15' if cursor_pos > 0 => {
                            // Ctrl+U - delete to beginning of line
                            let mut new_buffer: String<512> = String::new();
                            for (i, ch) in buffer.chars().enumerate() {
                                if i >= cursor_pos {
                                    let _ = new_buffer.push(ch);
                                }
                            }
                            buffer = new_buffer;
                            cursor_pos = 0;
                            needs_redraw = true;
                        }
                        _ if (c.is_ascii_graphic() || c == ' ') && buffer.len() < 511 => {
                            // Regular printable character - insert at cursor (ASCII only)
                            let mut new_buffer: String<512> = String::new();
                            for (i, ch) in buffer.chars().enumerate() {
                                if i == cursor_pos {
                                    let _ = new_buffer.push(c);
                                }
                                let _ = new_buffer.push(ch);
                            }
                            if cursor_pos == buffer.len() {
                                let _ = new_buffer.push(c);
                            }
                            buffer = new_buffer;
                            cursor_pos += 1;
                            needs_redraw = true;
                        }
                        _ => {}
                    }
                }
                KeyPress::Left => {
                    // Move cursor left
                    if cursor_pos > 0 {
                        cursor_pos -= 1;
                        needs_redraw = true;
                    }
                }
                KeyPress::Right => {
                    // Move cursor right
                    if cursor_pos < buffer.len() {
                        cursor_pos += 1;
                        needs_redraw = true;
                    }
                }
                KeyPress::Home => {
                    cursor_pos = 0;
                    needs_redraw = true;
                }
                KeyPress::End => {
                    cursor_pos = buffer.len();
                    needs_redraw = true;
                }
                // These have no meaning in the legacy single-line editor.
                KeyPress::Up
                | KeyPress::Down
                | KeyPress::PageUp
                | KeyPress::PageDown
                | KeyPress::Tab
                | KeyPress::BackTab
                | KeyPress::Delete
                | KeyPress::F8
                | KeyPress::F10 => {}
                // Mouse events are ignored in the command line editor
                KeyPress::MouseClick { .. } | KeyPress::MouseScroll(_) => {}
            }
        }

        delay_ms(10);
    }
}

/// Draw the static parts of the command line editor UI (header, title, help)
/// This is called once when entering the editor.
fn draw_cmdline_editor_static(
    entry_name: &str,
    fb_console: &mut Option<FramebufferConsole>,
    cols: usize,
) {
    let title = "Edit Kernel Command Line";

    // Serial output - clear and draw static content
    serial_driver::write_str("\x1b[2J\x1b[H"); // Clear and home
    serial_driver::write_str("\x1b[1;33m"); // Yellow, bold

    // Draw header
    let header_line = [b'='; 128];
    let header_len = cols.min(128);
    serial_driver::write_str(core::str::from_utf8(&header_line[..header_len]).unwrap_or(""));
    serial_driver::write_str("\r\n");

    // Title
    let title_pad = (cols.saturating_sub(title.len())) / 2;
    for _ in 0..title_pad {
        serial_driver::write_str(" ");
    }
    serial_driver::write_str(title);
    serial_driver::write_str("\r\n");

    serial_driver::write_str(core::str::from_utf8(&header_line[..header_len]).unwrap_or(""));
    serial_driver::write_str("\r\n\x1b[0m");

    // Entry name
    serial_driver::write_str("\x1b[36m"); // Cyan
    serial_driver::write_str("Entry: ");
    serial_driver::write_str(entry_name);
    serial_driver::write_str("\x1b[0m\r\n\r\n");

    // Command line label
    serial_driver::write_str("Command line:\r\n");

    // Leave space for edit line (row 7)
    serial_driver::write_str("\r\n\r\n");

    // Help text (row 9-10)
    serial_driver::write_str("\x1b[36m"); // Cyan
    serial_driver::write_str(
        "Enter: Confirm | Esc: Cancel | Ctrl+X: Boot | Left/Right: Move cursor\r\n",
    );
    serial_driver::write_str(
        "Ctrl+A: Start | Ctrl+E: End | Ctrl+K: Delete to end | Ctrl+U: Delete to start",
    );
    serial_driver::write_str("\x1b[0m\r\n");

    // Framebuffer output
    if let Some(console) = fb_console {
        console.clear();

        // Header
        console.set_fg_color(TITLE_COLOR);
        let mut header: String<128> = String::new();
        for _ in 0..cols {
            let _ = header.push('=');
        }
        console.set_position(0, 0);
        let _ = console.write_str(&header);
        console.write_centered(1, title);
        console.set_position(0, 2);
        let _ = console.write_str(&header);
        console.reset_colors();

        // Entry name
        console.set_position(0, 4);
        console.set_fg_color(Color::new(0, 192, 192)); // Cyan
        let _ = console.write_str("Entry: ");
        console.reset_colors();
        let _ = console.write_str(entry_name);

        // Command line label
        console.set_position(0, 6);
        let _ = console.write_str("Command line:");

        // Help text
        console.set_position(0, 9);
        console.set_fg_color(Color::new(0, 192, 192));
        let _ = console
            .write_str("Enter: Confirm | Esc: Cancel | Ctrl+X: Boot | Left/Right: Move cursor");
        console.set_position(0, 10);
        let _ = console.write_str(
            "Ctrl+A: Start | Ctrl+E: End | Ctrl+K: Delete to end | Ctrl+U: Delete to start",
        );
        console.reset_colors();
    }
}

/// Draw just the edit line and length indicator (called on each change)
fn draw_cmdline_editor_line(
    buffer: &str,
    cursor_pos: usize,
    edit_width: usize,
    fb_console: &mut Option<FramebufferConsole>,
) {
    // Calculate visible portion of the buffer (scroll if needed)
    let buffer_len = buffer.len();
    let (visible_start, visible_end, display_cursor) = if buffer_len <= edit_width {
        (0, buffer_len, cursor_pos)
    } else if cursor_pos < edit_width / 2 {
        // Cursor near start - show from beginning
        (0, edit_width, cursor_pos)
    } else if cursor_pos > buffer_len.saturating_sub(edit_width / 2) {
        // Cursor near end - show end portion
        let start = buffer_len.saturating_sub(edit_width);
        (start, buffer_len, cursor_pos - start)
    } else {
        // Cursor in middle - center the view
        let start = cursor_pos - edit_width / 2;
        let end = start + edit_width;
        (start, end.min(buffer_len), edit_width / 2)
    };

    let visible_text = &buffer[visible_start..visible_end];

    // Serial output - position cursor at edit line (row 7)
    serial_driver::write_str("\x1b[7;1H"); // Row 7, column 1
    serial_driver::write_str("\x1b[K"); // Clear line
    serial_driver::write_str("\x1b[44m"); // Blue background

    // Show scroll indicators
    if visible_start > 0 {
        serial_driver::write_str("<");
    } else {
        serial_driver::write_str(" ");
    }

    // Draw text before cursor
    if display_cursor > 0 {
        serial_driver::write_str(&visible_text[..display_cursor]);
    }

    // Draw cursor position with inverse video
    serial_driver::write_str("\x1b[7m"); // Inverse
    if display_cursor < visible_text.len() {
        let cursor_char = &visible_text[display_cursor..display_cursor + 1];
        serial_driver::write_str(cursor_char);
    } else {
        serial_driver::write_str(" ");
    }
    serial_driver::write_str("\x1b[27m"); // Normal (but still blue bg)

    // Draw text after cursor
    if display_cursor < visible_text.len() {
        serial_driver::write_str(&visible_text[display_cursor + 1..]);
    }

    // Pad to width and show scroll indicator
    let displayed_len = visible_text.len() + 2; // +2 for scroll indicators
    for _ in displayed_len..edit_width {
        serial_driver::write_str(" ");
    }

    if visible_end < buffer_len {
        serial_driver::write_str(">");
    } else {
        serial_driver::write_str(" ");
    }

    serial_driver::write_str("\x1b[0m"); // Reset colors

    // Length indicator (row 12)
    serial_driver::write_str("\x1b[12;1H"); // Row 12
    serial_driver::write_str("\x1b[K"); // Clear line
    let _ = write!(SerialWriter, "\x1b[33mLength: {}/512\x1b[0m", buffer_len);

    // Framebuffer output - only update edit line and length
    if let Some(console) = fb_console {
        // Edit area with blue background (row 7)
        console.set_position(0, 7);
        console.set_colors(DEFAULT_FG, Color::new(0, 0, 128)); // Blue bg

        // Scroll indicator left
        if visible_start > 0 {
            let _ = console.write_str("<");
        } else {
            let _ = console.write_str(" ");
        }

        // Text before cursor
        if display_cursor > 0 {
            let _ = console.write_str(&visible_text[..display_cursor]);
        }

        // Cursor with highlight
        console.set_colors(HIGHLIGHT_FG, HIGHLIGHT_BG);
        if display_cursor < visible_text.len() {
            let _ = console.write_str(&visible_text[display_cursor..display_cursor + 1]);
        } else {
            let _ = console.write_str(" ");
        }
        console.set_colors(DEFAULT_FG, Color::new(0, 0, 128));

        // Text after cursor
        if display_cursor < visible_text.len() {
            let _ = console.write_str(&visible_text[display_cursor + 1..]);
        }

        // Pad and right scroll indicator
        let displayed_len = visible_text.len() + 2;
        for _ in displayed_len..edit_width {
            let _ = console.write_str(" ");
        }
        if visible_end < buffer_len {
            let _ = console.write_str(">");
        } else {
            let _ = console.write_str(" ");
        }
        console.reset_colors();

        // Length indicator (row 12)
        console.set_position(0, 12);
        console.set_fg_color(Color::new(255, 255, 0)); // Yellow
        let mut len_str: String<32> = String::new();
        let _ = write!(len_str, "Length: {}/512    ", buffer_len); // Extra spaces to clear old longer values
        let _ = console.write_str(&len_str);
        console.reset_colors();
    }
}
