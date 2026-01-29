//! EFI Console Protocols
//!
//! This module implements the Simple Text Input and Simple Text Output protocols
//! for console I/O.
//!
//! # Keyboard Input
//!
//! Input is gathered from two sources:
//! - Serial console: ANSI escape sequences are parsed for arrow keys, function keys, etc.
//! - PS/2 keyboard: Scancodes are translated to EFI keys via the i8042 keyboard controller.

use crate::coreboot::FramebufferInfo;
use crate::drivers::keyboard;
use crate::drivers::serial;
use crate::efi::boot_services::KEYBOARD_EVENT_ID;
use crate::framebuffer_console::{CHAR_HEIGHT, CHAR_WIDTH, VGA_FONT_8X16};
use crate::state::{self, InputState};
use core::ffi::c_void;
use r_efi::efi::{Boolean, Event, Guid, Status};
use r_efi::protocols::simple_text_input::{InputKey, Protocol as SimpleTextInputProtocol};
use r_efi::protocols::simple_text_output::{
    Mode as SimpleTextOutputMode, Protocol as SimpleTextOutputProtocol,
};

// ============================================================================
// EFI Framebuffer Console State (stored in state::ConsoleState)
// ============================================================================

/// Initialize the EFI console with framebuffer support
pub fn init_framebuffer(fb: FramebufferInfo) {
    let cols = fb.x_resolution / CHAR_WIDTH;
    let rows = fb.y_resolution / CHAR_HEIGHT;

    // Reserve top portion for debug log, use bottom portion for EFI console
    // Use bottom half of screen for EFI console output
    let efi_start_row = rows / 2;

    state::with_console_mut(|console| {
        console.dimensions = (cols, rows - efi_start_row);
        console.cursor_pos = (0, efi_start_row);
        console.start_row = efi_start_row;
        console.efi_framebuffer = Some(fb);
    });

    log::info!(
        "EFI console initialized: {}x{} chars, starting at row {}",
        cols,
        rows - efi_start_row,
        efi_start_row
    );
}

/// Write a character to the EFI framebuffer console
fn fb_put_char(c: char) {
    state::with_console_mut(|console| {
        let Some(ref fb) = console.efi_framebuffer else {
            return;
        };

        let (cols, _rows) = console.dimensions;
        let total_rows = fb.y_resolution / CHAR_HEIGHT;
        let start_row = console.start_row;

        let (mut col, mut row) = console.cursor_pos;

        match c {
            '\n' => {
                col = 0;
                row += 1;
                if row >= total_rows {
                    // Scroll up the bottom half
                    fb_scroll_up(fb, start_row, total_rows);
                    row = total_rows - 1;
                }
            }
            '\r' => {
                col = 0;
            }
            _ => {
                fb_draw_char(fb, c, col, row);
                col += 1;
                if col >= cols {
                    col = 0;
                    row += 1;
                    if row >= total_rows {
                        fb_scroll_up(fb, start_row, total_rows);
                        row = total_rows - 1;
                    }
                }
            }
        }

        console.cursor_pos = (col, row);
    });
}

/// Draw a character at a specific position
fn fb_draw_char(fb: &FramebufferInfo, c: char, col: u32, row: u32) {
    let x_base = col * CHAR_WIDTH;
    let y_base = row * CHAR_HEIGHT;

    let glyph = if (c as usize) < 256 {
        &VGA_FONT_8X16[c as usize]
    } else {
        &VGA_FONT_8X16[b'?' as usize]
    };

    // White on black for EFI console
    let (fg_r, fg_g, fg_b) = (255u8, 255u8, 255u8);
    let (bg_r, bg_g, bg_b) = (0u8, 0u8, 0u8);

    for glyph_row in 0..CHAR_HEIGHT {
        let bits = glyph[glyph_row as usize];
        for glyph_col in 0..CHAR_WIDTH {
            let pixel_set = (bits >> (7 - glyph_col)) & 1 != 0;
            let (r, g, b) = if pixel_set {
                (fg_r, fg_g, fg_b)
            } else {
                (bg_r, bg_g, bg_b)
            };
            unsafe {
                fb.write_pixel(x_base + glyph_col, y_base + glyph_row, r, g, b);
            }
        }
    }
}

/// Scroll the EFI console area up by one line
fn fb_scroll_up(fb: &FramebufferInfo, start_row: u32, total_rows: u32) {
    let row_stride = fb.bytes_per_line as usize;

    // Copy each row up
    for row in start_row..(total_rows - 1) {
        let src_y = (row + 1) * CHAR_HEIGHT;
        let dst_y = row * CHAR_HEIGHT;

        for line in 0..CHAR_HEIGHT {
            let src_offset = ((src_y + line) as usize) * row_stride;
            let dst_offset = ((dst_y + line) as usize) * row_stride;

            unsafe {
                let src = (fb.physical_address as *const u8).add(src_offset);
                let dst = (fb.physical_address as *mut u8).add(dst_offset);
                core::ptr::copy(src, dst, row_stride);
            }
        }
    }

    // Clear the last row
    let last_row_y = (total_rows - 1) * CHAR_HEIGHT;
    for line in 0..CHAR_HEIGHT {
        let offset = ((last_row_y + line) as usize) * row_stride;
        unsafe {
            let dst = (fb.physical_address as *mut u8).add(offset);
            core::slice::from_raw_parts_mut(dst, row_stride).fill(0);
        }
    }
}

/// Simple Text Input Protocol GUID
pub const SIMPLE_TEXT_INPUT_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x387477c1,
    0x69c7,
    0x11d2,
    0x8e,
    0x39,
    &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);

/// Simple Text Output Protocol GUID
pub const SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x387477c2,
    0x69c7,
    0x11d2,
    0x8e,
    0x39,
    &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);

// ============================================================================
// EFI Scan Codes
// ============================================================================

/// EFI Scan codes for special keys
#[allow(dead_code)]
mod scan_codes {
    pub const SCAN_NULL: u16 = 0x0000;
    pub const SCAN_UP: u16 = 0x0001;
    pub const SCAN_DOWN: u16 = 0x0002;
    pub const SCAN_RIGHT: u16 = 0x0003;
    pub const SCAN_LEFT: u16 = 0x0004;
    pub const SCAN_HOME: u16 = 0x0005;
    pub const SCAN_END: u16 = 0x0006;
    pub const SCAN_INSERT: u16 = 0x0007;
    pub const SCAN_DELETE: u16 = 0x0008;
    pub const SCAN_PAGE_UP: u16 = 0x0009;
    pub const SCAN_PAGE_DOWN: u16 = 0x000A;
    pub const SCAN_F1: u16 = 0x000B;
    pub const SCAN_F2: u16 = 0x000C;
    pub const SCAN_F3: u16 = 0x000D;
    pub const SCAN_F4: u16 = 0x000E;
    pub const SCAN_F5: u16 = 0x000F;
    pub const SCAN_F6: u16 = 0x0010;
    pub const SCAN_F7: u16 = 0x0011;
    pub const SCAN_F8: u16 = 0x0012;
    pub const SCAN_F9: u16 = 0x0013;
    pub const SCAN_F10: u16 = 0x0014;
    pub const SCAN_F11: u16 = 0x0015;
    pub const SCAN_F12: u16 = 0x0016;
    pub const SCAN_ESC: u16 = 0x0017;
}

// ============================================================================
// Input Buffer for Escape Sequence Parsing (stored in state::ConsoleState.input)
// ============================================================================

/// Console output mode
static mut CONSOLE_MODE: SimpleTextOutputMode = SimpleTextOutputMode {
    max_mode: 1,
    mode: 0,
    attribute: 0x07, // Light gray on black
    cursor_column: 0,
    cursor_row: 0,
    cursor_visible: Boolean::TRUE,
};

/// Static text input protocol
/// Note: wait_for_key is set to KEYBOARD_EVENT_ID which is the special event
/// used for keyboard input polling
static mut TEXT_INPUT_PROTOCOL: SimpleTextInputProtocol = SimpleTextInputProtocol {
    reset: text_input_reset,
    read_key_stroke: text_input_read_key_stroke,
    wait_for_key: KEYBOARD_EVENT_ID as *mut c_void as Event,
};

/// Static text output protocol
static mut TEXT_OUTPUT_PROTOCOL: SimpleTextOutputProtocol = SimpleTextOutputProtocol {
    reset: text_output_reset,
    output_string: text_output_string,
    test_string: text_output_test_string,
    query_mode: text_output_query_mode,
    set_mode: text_output_set_mode,
    set_attribute: text_output_set_attribute,
    clear_screen: text_output_clear_screen,
    set_cursor_position: text_output_set_cursor_position,
    enable_cursor: text_output_enable_cursor,
    mode: core::ptr::null_mut(),
};

/// Get the text input protocol
pub fn get_text_input_protocol() -> *mut SimpleTextInputProtocol {
    &raw mut TEXT_INPUT_PROTOCOL
}

/// Get the text output protocol
pub fn get_text_output_protocol() -> *mut SimpleTextOutputProtocol {
    unsafe {
        TEXT_OUTPUT_PROTOCOL.mode = &raw mut CONSOLE_MODE;
        &raw mut TEXT_OUTPUT_PROTOCOL
    }
}

// ============================================================================
// Simple Text Input Protocol Implementation
// ============================================================================

extern "efiapi" fn text_input_reset(
    _this: *mut SimpleTextInputProtocol,
    _extended_verification: Boolean,
) -> Status {
    // Nothing to reset for serial input
    Status::SUCCESS
}

extern "efiapi" fn text_input_read_key_stroke(
    _this: *mut SimpleTextInputProtocol,
    key: *mut InputKey,
) -> Status {
    if key.is_null() {
        return Status::INVALID_PARAMETER;
    }

    state::with_console_mut(|console| {
        let input_state = &mut console.input;

        // First check if we have a queued key from previous escape sequence parsing
        if let Some((scan_code, unicode_char)) = input_state.queued_key.take() {
            unsafe {
                (*key).scan_code = scan_code;
                (*key).unicode_char = unicode_char;
            }
            log::trace!(
                "ConIn.ReadKeyStroke: queued key -> scan={:#x}, unicode={:#x}",
                scan_code,
                unicode_char
            );
            return Status::SUCCESS;
        }

        // Try to get a key from PS/2 keyboard first
        if let Some((scan_code, unicode_char)) = keyboard::try_read_key() {
            unsafe {
                (*key).scan_code = scan_code;
                (*key).unicode_char = unicode_char;
            }
            log::trace!(
                "ConIn.ReadKeyStroke: PS/2 -> scan={:#x}, unicode={:#x}",
                scan_code,
                unicode_char
            );
            return Status::SUCCESS;
        }

        // Try to read from serial port
        match serial::try_read() {
            Some(byte) => {
                // Handle escape sequence parsing
                let (scan_code, unicode_char) = process_serial_byte(input_state, byte);

                if scan_code == 0 && unicode_char == 0 {
                    // Still collecting escape sequence, no key ready yet
                    return Status::NOT_READY;
                }

                unsafe {
                    (*key).scan_code = scan_code;
                    (*key).unicode_char = unicode_char;
                }

                log::trace!(
                    "ConIn.ReadKeyStroke: serial byte={:#x} -> scan={:#x}, unicode={:#x}",
                    byte,
                    scan_code,
                    unicode_char
                );

                Status::SUCCESS
            }
            None => {
                // Check if we're in the middle of an escape sequence that timed out
                if input_state.in_escape && input_state.escape_len > 0 {
                    // Timeout: return what we have as individual characters
                    // This happens when user presses just ESC
                    let result = finalize_escape_sequence(input_state);
                    if let Some((scan_code, unicode_char)) = result {
                        unsafe {
                            (*key).scan_code = scan_code;
                            (*key).unicode_char = unicode_char;
                        }
                        return Status::SUCCESS;
                    }
                }

                // No key available
                Status::NOT_READY
            }
        }
    })
}

/// Process a serial byte, handling escape sequences
///
/// Returns (scan_code, unicode_char) if a key is ready, or (0, 0) if still collecting
/// an escape sequence.
fn process_serial_byte(input_state: &mut InputState, byte: u8) -> (u16, u16) {
    if input_state.in_escape {
        // We're collecting an escape sequence
        if input_state.escape_len < state::ESCAPE_BUF_SIZE {
            input_state.escape_buf[input_state.escape_len] = byte;
            input_state.escape_len += 1;
        }

        // Try to match the escape sequence
        if let Some(key) = match_escape_sequence(&input_state.escape_buf[..input_state.escape_len])
        {
            // Found a match
            input_state.in_escape = false;
            input_state.escape_len = 0;
            return key;
        }

        // Check if the sequence is definitely not going to match
        if input_state.escape_len >= 5
            || !could_be_escape_sequence(&input_state.escape_buf[..input_state.escape_len])
        {
            // Give up on this escape sequence, return ESC and queue the rest
            let result = finalize_escape_sequence(input_state);
            return result.unwrap_or((0, 0));
        }

        // Still collecting, no key ready yet
        return (0, 0);
    }

    // Not in an escape sequence - check if this starts one
    if byte == 0x1B {
        // Start of escape sequence
        input_state.in_escape = true;
        input_state.escape_len = 0;
        // Return (0, 0) to indicate we need more input
        // But first check if there's more data available immediately
        if !serial::has_input() {
            // No more data immediately available, this might be a standalone ESC
            // We'll let the next call to read_key_stroke handle the timeout
            return (0, 0);
        }
        return (0, 0);
    }

    // Regular character - convert directly
    convert_byte_to_efi_key(byte)
}

/// Convert a single byte to EFI key (non-escape sequence)
fn convert_byte_to_efi_key(byte: u8) -> (u16, u16) {
    match byte {
        // Enter key
        b'\r' | b'\n' => (0, 0x000D), // CHAR_CARRIAGE_RETURN

        // Backspace
        0x7F | 0x08 => (0, 0x0008), // CHAR_BACKSPACE

        // Tab
        b'\t' => (0, 0x0009), // CHAR_TAB

        // Regular printable ASCII
        0x20..=0x7E => (0, byte as u16),

        // Other control characters
        _ => (0, byte as u16),
    }
}

/// Try to match an escape sequence buffer to a known sequence
///
/// Returns Some((scan_code, unicode_char)) if matched, None if not yet matched
fn match_escape_sequence(buf: &[u8]) -> Option<(u16, u16)> {
    use scan_codes::*;

    // ANSI escape sequences (CSI sequences starting with ESC [)
    // Arrow keys: ESC [ A/B/C/D
    // Home/End: ESC [ H/F or ESC [ 1 ~/ESC [ 4 ~
    // Page Up/Down: ESC [ 5 ~/ESC [ 6 ~
    // Insert/Delete: ESC [ 2 ~/ESC [ 3 ~
    // Function keys: ESC O P/Q/R/S (F1-F4) or ESC [ 15 ~ etc.

    match buf {
        // Arrow keys
        [b'[', b'A'] => Some((SCAN_UP, 0)),
        [b'[', b'B'] => Some((SCAN_DOWN, 0)),
        [b'[', b'C'] => Some((SCAN_RIGHT, 0)),
        [b'[', b'D'] => Some((SCAN_LEFT, 0)),

        // Home/End (VT style)
        [b'[', b'H'] => Some((SCAN_HOME, 0)),
        [b'[', b'F'] => Some((SCAN_END, 0)),

        // Home/End (alternate style)
        [b'[', b'1', b'~'] => Some((SCAN_HOME, 0)),
        [b'[', b'4', b'~'] => Some((SCAN_END, 0)),

        // Insert/Delete
        [b'[', b'2', b'~'] => Some((SCAN_INSERT, 0)),
        [b'[', b'3', b'~'] => Some((SCAN_DELETE, 0)),

        // Page Up/Down
        [b'[', b'5', b'~'] => Some((SCAN_PAGE_UP, 0)),
        [b'[', b'6', b'~'] => Some((SCAN_PAGE_DOWN, 0)),

        // Function keys F1-F4 (VT style)
        [b'O', b'P'] => Some((SCAN_F1, 0)),
        [b'O', b'Q'] => Some((SCAN_F2, 0)),
        [b'O', b'R'] => Some((SCAN_F3, 0)),
        [b'O', b'S'] => Some((SCAN_F4, 0)),

        // Function keys F1-F4 (alternate xterm style)
        [b'[', b'[', b'A'] => Some((SCAN_F1, 0)),
        [b'[', b'[', b'B'] => Some((SCAN_F2, 0)),
        [b'[', b'[', b'C'] => Some((SCAN_F3, 0)),
        [b'[', b'[', b'D'] => Some((SCAN_F4, 0)),
        [b'[', b'[', b'E'] => Some((SCAN_F5, 0)),

        // Function keys F5-F12 (VT style)
        [b'[', b'1', b'5', b'~'] => Some((SCAN_F5, 0)),
        [b'[', b'1', b'7', b'~'] => Some((SCAN_F6, 0)),
        [b'[', b'1', b'8', b'~'] => Some((SCAN_F7, 0)),
        [b'[', b'1', b'9', b'~'] => Some((SCAN_F8, 0)),
        [b'[', b'2', b'0', b'~'] => Some((SCAN_F9, 0)),
        [b'[', b'2', b'1', b'~'] => Some((SCAN_F10, 0)),
        [b'[', b'2', b'3', b'~'] => Some((SCAN_F11, 0)),
        [b'[', b'2', b'4', b'~'] => Some((SCAN_F12, 0)),

        _ => None,
    }
}

/// Check if the buffer could potentially be a valid escape sequence prefix
fn could_be_escape_sequence(buf: &[u8]) -> bool {
    // All valid escape sequences start with '[' or 'O'
    if buf.is_empty() {
        return true;
    }

    matches!(buf[0], b'[' | b'O')
}

/// Finalize an incomplete escape sequence
///
/// Returns the ESC key and queues remaining bytes to be returned as separate keys
fn finalize_escape_sequence(input_state: &mut InputState) -> Option<(u16, u16)> {
    use scan_codes::*;

    input_state.in_escape = false;

    if input_state.escape_len == 0 {
        // Just ESC with no following characters
        input_state.escape_len = 0;
        return Some((SCAN_ESC, 0));
    }

    // We have bytes that didn't form a valid sequence
    // Return ESC and queue the first remaining byte
    // (Ideally we'd queue all of them, but for simplicity just queue one)
    if input_state.escape_len > 0 {
        let first_byte = input_state.escape_buf[0];
        input_state.queued_key = Some(convert_byte_to_efi_key(first_byte));
    }

    input_state.escape_len = 0;
    Some((SCAN_ESC, 0))
}

// ============================================================================
// Simple Text Output Protocol Implementation
// ============================================================================

extern "efiapi" fn text_output_reset(
    _this: *mut SimpleTextOutputProtocol,
    _extended_verification: Boolean,
) -> Status {
    // Reset console state
    unsafe {
        CONSOLE_MODE.cursor_column = 0;
        CONSOLE_MODE.cursor_row = 0;
        CONSOLE_MODE.attribute = 0x07;
    }

    // Send reset sequence to serial
    serial::write_str("\x1b[2J\x1b[H"); // Clear screen, home cursor

    Status::SUCCESS
}

extern "efiapi" fn text_output_string(
    _this: *mut SimpleTextOutputProtocol,
    string: *mut u16,
) -> Status {
    if string.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Convert UCS-2 to ASCII and output to both serial and framebuffer
    let mut ptr = string;
    unsafe {
        while *ptr != 0 {
            let ch = *ptr as u32;

            if ch < 128 {
                // ASCII character
                let byte = ch as u8;
                let c = byte as char;

                match byte {
                    b'\n' => {
                        serial::write_byte(b'\r');
                        serial::write_byte(b'\n');
                        fb_put_char('\n');
                        CONSOLE_MODE.cursor_column = 0;
                        CONSOLE_MODE.cursor_row += 1;
                    }
                    b'\r' => {
                        serial::write_byte(b'\r');
                        fb_put_char('\r');
                        CONSOLE_MODE.cursor_column = 0;
                    }
                    _ => {
                        serial::write_byte(byte);
                        fb_put_char(c);
                        CONSOLE_MODE.cursor_column += 1;
                    }
                }
            } else {
                // Non-ASCII: output '?'
                serial::write_byte(b'?');
                fb_put_char('?');
                CONSOLE_MODE.cursor_column += 1;
            }

            ptr = ptr.add(1);
        }
    }

    Status::SUCCESS
}

extern "efiapi" fn text_output_test_string(
    _this: *mut SimpleTextOutputProtocol,
    string: *mut u16,
) -> Status {
    if string.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Check if all characters can be displayed
    // For serial output, we support ASCII only
    let mut ptr = string;
    unsafe {
        while *ptr != 0 {
            let ch = *ptr as u32;
            if ch >= 128 {
                return Status::UNSUPPORTED;
            }
            ptr = ptr.add(1);
        }
    }

    Status::SUCCESS
}

extern "efiapi" fn text_output_query_mode(
    _this: *mut SimpleTextOutputProtocol,
    mode_number: usize,
    columns: *mut usize,
    rows: *mut usize,
) -> Status {
    if columns.is_null() || rows.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // We only support one mode: 80x25
    if mode_number != 0 {
        return Status::UNSUPPORTED;
    }

    unsafe {
        *columns = 80;
        *rows = 25;
    }

    Status::SUCCESS
}

extern "efiapi" fn text_output_set_mode(
    _this: *mut SimpleTextOutputProtocol,
    mode_number: usize,
) -> Status {
    if mode_number != 0 {
        return Status::UNSUPPORTED;
    }

    unsafe {
        CONSOLE_MODE.mode = mode_number as i32;
    }

    Status::SUCCESS
}

extern "efiapi" fn text_output_set_attribute(
    _this: *mut SimpleTextOutputProtocol,
    attribute: usize,
) -> Status {
    unsafe {
        CONSOLE_MODE.attribute = attribute as i32;
    }

    // Convert EFI attribute to ANSI escape sequence
    let fg = attribute & 0x0F;
    let bg = (attribute >> 4) & 0x0F;

    // Map EFI colors to ANSI
    let ansi_fg = match fg {
        0 => 30,  // Black
        1 => 34,  // Blue
        2 => 32,  // Green
        3 => 36,  // Cyan
        4 => 31,  // Red
        5 => 35,  // Magenta
        6 => 33,  // Brown/Yellow
        7 => 37,  // Light Gray
        8 => 90,  // Dark Gray
        9 => 94,  // Light Blue
        10 => 92, // Light Green
        11 => 96, // Light Cyan
        12 => 91, // Light Red
        13 => 95, // Light Magenta
        14 => 93, // Yellow
        15 => 97, // White
        _ => 37,
    };

    let ansi_bg = match bg {
        0 => 40,
        1 => 44,
        2 => 42,
        3 => 46,
        4 => 41,
        5 => 45,
        6 => 43,
        7 => 47,
        _ => 40,
    };

    // Send ANSI escape sequence
    let mut buf = [0u8; 16];
    let len = format_ansi_color(&mut buf, ansi_fg, ansi_bg);
    for &byte in buf.iter().take(len) {
        serial::write_byte(byte);
    }

    Status::SUCCESS
}

extern "efiapi" fn text_output_clear_screen(_this: *mut SimpleTextOutputProtocol) -> Status {
    serial::write_str("\x1b[2J\x1b[H");

    unsafe {
        CONSOLE_MODE.cursor_column = 0;
        CONSOLE_MODE.cursor_row = 0;
    }

    Status::SUCCESS
}

extern "efiapi" fn text_output_set_cursor_position(
    _this: *mut SimpleTextOutputProtocol,
    column: usize,
    row: usize,
) -> Status {
    // Send ANSI cursor position sequence
    // ESC [ row ; column H
    let mut buf = [0u8; 16];
    let len = format_cursor_pos(&mut buf, row + 1, column + 1);
    for &byte in buf.iter().take(len) {
        serial::write_byte(byte);
    }

    unsafe {
        CONSOLE_MODE.cursor_column = column as i32;
        CONSOLE_MODE.cursor_row = row as i32;
    }

    Status::SUCCESS
}

extern "efiapi" fn text_output_enable_cursor(
    _this: *mut SimpleTextOutputProtocol,
    visible: Boolean,
) -> Status {
    let is_visible: bool = visible.into();
    unsafe {
        CONSOLE_MODE.cursor_visible = visible;
    }

    if is_visible {
        serial::write_str("\x1b[?25h"); // Show cursor
    } else {
        serial::write_str("\x1b[?25l"); // Hide cursor
    }

    Status::SUCCESS
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Format ANSI color escape sequence
fn format_ansi_color(buf: &mut [u8], fg: u8, bg: u8) -> usize {
    // ESC [ fg ; bg m
    buf[0] = 0x1b;
    buf[1] = b'[';

    let mut pos = 2;

    // Foreground
    if fg >= 100 {
        buf[pos] = b'1';
        pos += 1;
    }
    if fg >= 10 {
        buf[pos] = b'0' + (fg / 10) % 10;
        pos += 1;
    }
    buf[pos] = b'0' + fg % 10;
    pos += 1;

    buf[pos] = b';';
    pos += 1;

    // Background
    if bg >= 10 {
        buf[pos] = b'0' + bg / 10;
        pos += 1;
    }
    buf[pos] = b'0' + bg % 10;
    pos += 1;

    buf[pos] = b'm';
    pos += 1;

    pos
}

/// Format ANSI cursor position escape sequence
fn format_cursor_pos(buf: &mut [u8], row: usize, col: usize) -> usize {
    // ESC [ row ; col H
    buf[0] = 0x1b;
    buf[1] = b'[';

    let mut pos = 2;

    // Row
    if row >= 10 {
        buf[pos] = b'0' + (row / 10) as u8;
        pos += 1;
    }
    buf[pos] = b'0' + (row % 10) as u8;
    pos += 1;

    buf[pos] = b';';
    pos += 1;

    // Column
    if col >= 10 {
        buf[pos] = b'0' + (col / 10) as u8;
        pos += 1;
    }
    buf[pos] = b'0' + (col % 10) as u8;
    pos += 1;

    buf[pos] = b'H';
    pos += 1;

    pos
}

/// Output a string to the console (helper for internal use)
pub fn console_print(s: &str) {
    for byte in s.bytes() {
        match byte {
            b'\n' => {
                serial::write_byte(b'\r');
                serial::write_byte(b'\n');
            }
            _ => {
                serial::write_byte(byte);
            }
        }
    }
}
