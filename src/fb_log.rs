//! Framebuffer logging support
//!
//! This module provides logging output to the framebuffer. It is disabled by
//! default as it is very slow. Enable with the `fb-log` feature flag.

use core::fmt::Write;
use log::Level;
use spin::Mutex;

use crate::coreboot::FramebufferInfo;
use crate::framebuffer_console::{Color, CHAR_HEIGHT, CHAR_WIDTH, VGA_FONT_8X16};

/// Global framebuffer info for logging
static FB_INFO: Mutex<Option<FramebufferInfo>> = Mutex::new(None);

/// Cursor position for framebuffer logging (row, col)
static FB_CURSOR: Mutex<(u32, u32)> = Mutex::new((0, 0));

/// Set the framebuffer for logging output
///
/// Call this after parsing coreboot tables to enable framebuffer logging.
/// Clears the screen to remove any stale content from bootloader.
pub fn set_framebuffer(fb: FramebufferInfo) {
    // Clear the entire screen first
    unsafe {
        fb.clear(0, 0, 0); // Black background
    }
    *FB_INFO.lock() = Some(fb);
    // Reset cursor to top-left
    *FB_CURSOR.lock() = (0, 0);
}

/// Log a message to the framebuffer
pub fn log_to_framebuffer(level: Level, ts: u64, args: &core::fmt::Arguments) {
    let Some(ref fb_info) = *FB_INFO.lock() else {
        return;
    };

    // Level strings for framebuffer (no ANSI)
    let (level_str_fb, level_color) = match level {
        Level::Error => ("ERROR", Color::new(255, 64, 64)), // Red
        Level::Warn => ("WARN ", Color::new(255, 255, 0)),  // Yellow
        Level::Info => ("INFO ", Color::new(64, 255, 64)),  // Green
        Level::Debug => ("DEBUG", Color::new(128, 128, 255)), // Blue
        Level::Trace => ("TRACE", Color::new(192, 64, 192)), // Purple
    };

    // Get cursor position
    let (mut row, mut col) = *FB_CURSOR.lock();
    let cols = fb_info.x_resolution / CHAR_WIDTH;
    let rows = fb_info.y_resolution / CHAR_HEIGHT;

    // Format the message with timestamp
    let mut buf = FormattingBuffer::new();
    let _ = write!(buf, "{:>8} [{}] {}", ts, level_str_fb, args);

    // Draw each character
    let fg = Color::new(192, 192, 192); // Light gray for message
    let bg = Color::new(0, 0, 0); // Black background

    // Clear the current line first (remove stale content)
    clear_line(fb_info, row, cols, bg);

    // Draw timestamp (first 9 chars: "XXXXXXXX ")
    let timestamp_color = Color::new(128, 128, 128); // Gray for timestamp
    for (i, c) in buf.as_str().chars().take(9).enumerate() {
        if col < cols {
            draw_char_at(fb_info, c, col + i as u32, row, timestamp_color, bg);
        }
    }
    col += 9;

    // Draw level with color (skip the space after timestamp)
    for (i, c) in level_str_fb.chars().enumerate() {
        if col < cols {
            draw_char_at(fb_info, c, col + 1 + i as u32, row, level_color, bg);
        }
    }
    col += 7; // "[LEVEL]"

    // Draw the rest of the message (skip "XXXXXXXX [LEVEL]" = 17 chars)
    for c in buf.as_str().chars().skip(17) {
        // Skip "[LEVEL]" prefix
        if c == '\n' || col >= cols {
            col = 0;
            row += 1;
            if row >= rows {
                // Wrap around to top
                row = 0;
            }
            // Clear the new line before writing
            clear_line(fb_info, row, cols, bg);
            if c == '\n' {
                continue;
            }
        }
        draw_char_at(fb_info, c, col, row, fg, bg);
        col += 1;
    }

    // Move to next line
    col = 0;
    row += 1;
    if row >= rows {
        row = 0; // Wrap around
    }

    // Update cursor
    *FB_CURSOR.lock() = (row, col);
}

/// Clear a line on the framebuffer
fn clear_line(fb: &FramebufferInfo, row: u32, cols: u32, bg: Color) {
    let y_start = row * CHAR_HEIGHT;
    for y in y_start..(y_start + CHAR_HEIGHT) {
        for x in 0..(cols * CHAR_WIDTH) {
            unsafe {
                fb.write_pixel(x, y, bg.r, bg.g, bg.b);
            }
        }
    }
}

/// Draw a character at a specific position on the framebuffer
fn draw_char_at(fb: &FramebufferInfo, c: char, col: u32, row: u32, fg: Color, bg: Color) {
    let x_base = col * CHAR_WIDTH;
    let y_base = row * CHAR_HEIGHT;

    let glyph = get_glyph(c);

    for glyph_row in 0..CHAR_HEIGHT {
        let bits = glyph[glyph_row as usize];
        for glyph_col in 0..CHAR_WIDTH {
            let pixel_set = (bits >> (7 - glyph_col)) & 1 != 0;
            let (r, g, b) = if pixel_set {
                (fg.r, fg.g, fg.b)
            } else {
                (bg.r, bg.g, bg.b)
            };

            unsafe {
                fb.write_pixel(x_base + glyph_col, y_base + glyph_row, r, g, b);
            }
        }
    }
}

/// Get glyph data for a character (simplified - just use '?' for non-ASCII)
fn get_glyph(c: char) -> &'static [u8; 16] {
    let index = c as usize;
    if index < 256 {
        &VGA_FONT_8X16[index]
    } else {
        &VGA_FONT_8X16[b'?' as usize]
    }
}

/// Small formatting buffer for log messages
struct FormattingBuffer {
    buf: [u8; 512],
    len: usize,
}

impl FormattingBuffer {
    fn new() -> Self {
        Self {
            buf: [0; 512],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl Write for FormattingBuffer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len() - self.len;
        let to_copy = bytes.len().min(remaining);
        self.buf[self.len..self.len + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.len += to_copy;
        Ok(())
    }
}
