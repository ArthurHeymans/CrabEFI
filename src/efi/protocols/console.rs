//! EFI Console Protocols
//!
//! This module implements the Simple Text Input and Simple Text Output protocols
//! for console I/O.

use crate::drivers::serial;
use r_efi::efi::{Boolean, Guid, Status};
use r_efi::protocols::simple_text_input::{InputKey, Protocol as SimpleTextInputProtocol};
use r_efi::protocols::simple_text_output::{
    Mode as SimpleTextOutputMode, Protocol as SimpleTextOutputProtocol,
};

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
static mut TEXT_INPUT_PROTOCOL: SimpleTextInputProtocol = SimpleTextInputProtocol {
    reset: text_input_reset,
    read_key_stroke: text_input_read_key_stroke,
    wait_for_key: core::ptr::null_mut(),
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

    // Try to read from serial port
    // For now, we don't have async input, so this always returns NOT_READY
    // TODO: Implement keyboard polling

    Status::NOT_READY
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

    // Convert UCS-2 to ASCII and output
    let mut ptr = string;
    unsafe {
        while *ptr != 0 {
            let ch = *ptr as u32;

            if ch < 128 {
                // ASCII character
                let byte = ch as u8;

                match byte {
                    b'\n' => {
                        serial::write_byte(b'\r');
                        serial::write_byte(b'\n');
                        CONSOLE_MODE.cursor_column = 0;
                        CONSOLE_MODE.cursor_row += 1;
                    }
                    b'\r' => {
                        serial::write_byte(b'\r');
                        CONSOLE_MODE.cursor_column = 0;
                    }
                    _ => {
                        serial::write_byte(byte);
                        CONSOLE_MODE.cursor_column += 1;
                    }
                }
            } else {
                // Non-ASCII: output '?'
                serial::write_byte(b'?');
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
    for i in 0..len {
        serial::write_byte(buf[i]);
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
    for i in 0..len {
        serial::write_byte(buf[i]);
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
