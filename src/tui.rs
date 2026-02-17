//! Ratatui backends for CrabEFI
//!
//! Provides custom [`Backend`] implementations for rendering ratatui UIs
//! to CrabEFI's serial console and framebuffer simultaneously.
//!
//! - [`SerialBackend`]: Renders via ANSI escape codes over the serial port
//! - [`FramebufferBackend`]: Renders to the coreboot framebuffer using the VGA font
//! - [`DualBackend`]: Renders to both serial and framebuffer at once

use crate::coreboot::framebuffer::FramebufferInfo;
use crate::drivers::serial as serial_driver;
use crate::framebuffer_console::{self, Color as FbColor, FramebufferConsole};
use core::fmt::Write;
use ratatui::backend::{Backend, ClearType, WindowSize};
use ratatui::buffer::Cell;
use ratatui::layout::{Position, Size};
use ratatui::style::Color;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Infallible error type for CrabEFI backends.
///
/// Our backends write directly to hardware registers / memory-mapped framebuffer
/// and cannot fail in a recoverable way, so we use an infallible error.
#[derive(Debug)]
pub enum BackendError {}

impl core::fmt::Display for BackendError {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {}
    }
}

impl core::error::Error for BackendError {}

// ---------------------------------------------------------------------------
// Color conversion
// ---------------------------------------------------------------------------

/// Convert a ratatui [`Color`] to a framebuffer [`FbColor`].
fn ratatui_color_to_fb(color: Color, default: FbColor) -> FbColor {
    match color {
        Color::Reset => default,
        Color::Black => FbColor::new(0, 0, 0),
        Color::Red => FbColor::new(170, 0, 0),
        Color::Green => FbColor::new(0, 170, 0),
        Color::Yellow => FbColor::new(170, 170, 0),
        Color::Blue => FbColor::new(0, 0, 170),
        Color::Magenta => FbColor::new(170, 0, 170),
        Color::Cyan => FbColor::new(0, 170, 170),
        Color::Gray => FbColor::new(170, 170, 170),
        Color::DarkGray => FbColor::new(85, 85, 85),
        Color::LightRed => FbColor::new(255, 85, 85),
        Color::LightGreen => FbColor::new(85, 255, 85),
        Color::LightYellow => FbColor::new(255, 255, 85),
        Color::LightBlue => FbColor::new(85, 85, 255),
        Color::LightMagenta => FbColor::new(255, 85, 255),
        Color::LightCyan => FbColor::new(85, 255, 255),
        Color::White => FbColor::new(255, 255, 255),
        Color::Rgb(r, g, b) => FbColor::new(r, g, b),
        Color::Indexed(idx) => ansi256_to_fb(idx),
    }
}

/// Map an 8-bit ANSI color index to an RGB [`FbColor`].
fn ansi256_to_fb(idx: u8) -> FbColor {
    match idx {
        // Standard 16 colors
        0 => FbColor::new(0, 0, 0),
        1 => FbColor::new(170, 0, 0),
        2 => FbColor::new(0, 170, 0),
        3 => FbColor::new(170, 170, 0),
        4 => FbColor::new(0, 0, 170),
        5 => FbColor::new(170, 0, 170),
        6 => FbColor::new(0, 170, 170),
        7 => FbColor::new(170, 170, 170),
        8 => FbColor::new(85, 85, 85),
        9 => FbColor::new(255, 85, 85),
        10 => FbColor::new(85, 255, 85),
        11 => FbColor::new(255, 255, 85),
        12 => FbColor::new(85, 85, 255),
        13 => FbColor::new(255, 85, 255),
        14 => FbColor::new(85, 255, 255),
        15 => FbColor::new(255, 255, 255),
        // 216-color cube (indices 16..=231)
        16..=231 => {
            let idx = idx - 16;
            let r = (idx / 36) * 51;
            let g = ((idx % 36) / 6) * 51;
            let b = (idx % 6) * 51;
            FbColor::new(r, g, b)
        }
        // Grayscale ramp (indices 232..=255)
        232..=255 => {
            let v = 8 + (idx - 232) * 10;
            FbColor::new(v, v, v)
        }
    }
}

/// Write the ANSI SGR (Select Graphic Rendition) escape sequence for a cell's
/// foreground and background colors to the serial port.
fn write_serial_sgr(fg: Color, bg: Color) {
    // Reset first, then set colors
    serial_driver::write_str("\x1b[0");

    // Foreground
    match fg {
        Color::Reset => {}
        Color::Black => serial_driver::write_str(";30"),
        Color::Red => serial_driver::write_str(";31"),
        Color::Green => serial_driver::write_str(";32"),
        Color::Yellow => serial_driver::write_str(";33"),
        Color::Blue => serial_driver::write_str(";34"),
        Color::Magenta => serial_driver::write_str(";35"),
        Color::Cyan => serial_driver::write_str(";36"),
        Color::Gray => serial_driver::write_str(";37"),
        Color::DarkGray => serial_driver::write_str(";90"),
        Color::LightRed => serial_driver::write_str(";91"),
        Color::LightGreen => serial_driver::write_str(";92"),
        Color::LightYellow => serial_driver::write_str(";93"),
        Color::LightBlue => serial_driver::write_str(";94"),
        Color::LightMagenta => serial_driver::write_str(";95"),
        Color::LightCyan => serial_driver::write_str(";96"),
        Color::White => serial_driver::write_str(";97"),
        Color::Rgb(r, g, b) => {
            let mut buf = SerialBuf::new();
            let _ = write!(buf, ";38;2;{};{};{}", r, g, b);
            serial_driver::write_str(buf.as_str());
        }
        Color::Indexed(idx) => {
            let mut buf = SerialBuf::new();
            let _ = write!(buf, ";38;5;{}", idx);
            serial_driver::write_str(buf.as_str());
        }
    }

    // Background
    match bg {
        Color::Reset => {}
        Color::Black => serial_driver::write_str(";40"),
        Color::Red => serial_driver::write_str(";41"),
        Color::Green => serial_driver::write_str(";42"),
        Color::Yellow => serial_driver::write_str(";43"),
        Color::Blue => serial_driver::write_str(";44"),
        Color::Magenta => serial_driver::write_str(";45"),
        Color::Cyan => serial_driver::write_str(";46"),
        Color::Gray => serial_driver::write_str(";47"),
        Color::DarkGray => serial_driver::write_str(";100"),
        Color::LightRed => serial_driver::write_str(";101"),
        Color::LightGreen => serial_driver::write_str(";102"),
        Color::LightYellow => serial_driver::write_str(";103"),
        Color::LightBlue => serial_driver::write_str(";104"),
        Color::LightMagenta => serial_driver::write_str(";105"),
        Color::LightCyan => serial_driver::write_str(";106"),
        Color::White => serial_driver::write_str(";107"),
        Color::Rgb(r, g, b) => {
            let mut buf = SerialBuf::new();
            let _ = write!(buf, ";48;2;{};{};{}", r, g, b);
            serial_driver::write_str(buf.as_str());
        }
        Color::Indexed(idx) => {
            let mut buf = SerialBuf::new();
            let _ = write!(buf, ";48;5;{}", idx);
            serial_driver::write_str(buf.as_str());
        }
    }

    serial_driver::write_str("m");
}

/// Small stack buffer for formatting ANSI sequences without allocation.
struct SerialBuf {
    buf: [u8; 32],
    pos: usize,
}

impl SerialBuf {
    fn new() -> Self {
        Self {
            buf: [0; 32],
            pos: 0,
        }
    }

    fn as_str(&self) -> &str {
        // Safety: we only write ASCII via core::fmt::Write
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.pos]) }
    }
}

impl core::fmt::Write for SerialBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = &mut self.buf[self.pos..];
        if bytes.len() > remaining.len() {
            return Err(core::fmt::Error);
        }
        remaining[..bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }
}

// ===========================================================================
// SerialBackend
// ===========================================================================

/// Backend that renders to the serial console via ANSI escape codes.
pub struct SerialBackend {
    width: u16,
    height: u16,
    cursor: Position,
}

impl SerialBackend {
    /// Create a new serial backend with the given terminal dimensions.
    pub fn new(width: u16, height: u16) -> Self {
        Self {
            width,
            height,
            cursor: Position::ORIGIN,
        }
    }
}

impl Backend for SerialBackend {
    type Error = BackendError;

    fn draw<'a, I>(&mut self, content: I) -> Result<(), Self::Error>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        let mut last_fg = Color::Reset;
        let mut last_bg = Color::Reset;
        let mut last_pos: Option<(u16, u16)> = None;

        for (x, y, cell) in content {
            // Only reposition cursor if not contiguous with previous cell
            let need_move = match last_pos {
                Some((lx, ly)) => !(ly == y && lx + 1 == x),
                None => true,
            };
            if need_move {
                let mut buf = SerialBuf::new();
                // ANSI cursor position is 1-based
                let _ = write!(buf, "\x1b[{};{}H", y + 1, x + 1);
                serial_driver::write_str(buf.as_str());
            }

            // Only emit SGR if colors changed
            if cell.fg != last_fg || cell.bg != last_bg {
                write_serial_sgr(cell.fg, cell.bg);
                last_fg = cell.fg;
                last_bg = cell.bg;
            }

            serial_driver::write_str(cell.symbol());
            last_pos = Some((x, y));
        }

        // Reset attributes after drawing
        serial_driver::write_str("\x1b[0m");
        Ok(())
    }

    fn hide_cursor(&mut self) -> Result<(), Self::Error> {
        serial_driver::write_str("\x1b[?25l");
        Ok(())
    }

    fn show_cursor(&mut self) -> Result<(), Self::Error> {
        serial_driver::write_str("\x1b[?25h");
        Ok(())
    }

    fn get_cursor_position(&mut self) -> Result<Position, Self::Error> {
        Ok(self.cursor)
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> Result<(), Self::Error> {
        self.cursor = position.into();
        let mut buf = SerialBuf::new();
        let _ = write!(buf, "\x1b[{};{}H", self.cursor.y + 1, self.cursor.x + 1);
        serial_driver::write_str(buf.as_str());
        Ok(())
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        serial_driver::write_str("\x1b[2J\x1b[H");
        Ok(())
    }

    fn clear_region(&mut self, clear_type: ClearType) -> Result<(), Self::Error> {
        match clear_type {
            ClearType::All => serial_driver::write_str("\x1b[2J"),
            ClearType::AfterCursor => serial_driver::write_str("\x1b[J"),
            ClearType::BeforeCursor => serial_driver::write_str("\x1b[1J"),
            ClearType::CurrentLine => serial_driver::write_str("\x1b[2K"),
            ClearType::UntilNewLine => serial_driver::write_str("\x1b[K"),
        }
        Ok(())
    }

    fn size(&self) -> Result<Size, Self::Error> {
        Ok(Size::new(self.width, self.height))
    }

    fn window_size(&mut self) -> Result<WindowSize, Self::Error> {
        Ok(WindowSize {
            columns_rows: Size::new(self.width, self.height),
            pixels: Size::new(self.width * 8, self.height * 16),
        })
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ===========================================================================
// FramebufferBackend
// ===========================================================================

/// Backend that renders to the coreboot framebuffer using the VGA bitmap font.
pub struct FramebufferBackend<'a> {
    console: FramebufferConsole<'a>,
}

impl<'a> FramebufferBackend<'a> {
    /// Create a new framebuffer backend wrapping the given framebuffer info.
    pub fn new(fb: &'a FramebufferInfo) -> Self {
        Self {
            console: FramebufferConsole::new(fb),
        }
    }
}

impl Backend for FramebufferBackend<'_> {
    type Error = BackendError;

    fn draw<'a, I>(&mut self, content: I) -> Result<(), Self::Error>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        let default_fg = framebuffer_console::DEFAULT_FG;
        let default_bg = framebuffer_console::DEFAULT_BG;

        for (x, y, cell) in content {
            let fg = ratatui_color_to_fb(cell.fg, default_fg);
            let bg = ratatui_color_to_fb(cell.bg, default_bg);

            // Use the first char of the symbol (our VGA font is single-byte)
            let ch = cell.symbol().chars().next().unwrap_or(' ');
            self.console.draw_char_at(ch, x as u32, y as u32, fg, bg);
        }

        Ok(())
    }

    fn hide_cursor(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn show_cursor(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn get_cursor_position(&mut self) -> Result<Position, Self::Error> {
        let (col, row) = self.console.position();
        Ok(Position::new(col as u16, row as u16))
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> Result<(), Self::Error> {
        let pos = position.into();
        self.console.set_position(pos.x as u32, pos.y as u32);
        Ok(())
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        self.console.clear();
        Ok(())
    }

    fn clear_region(&mut self, clear_type: ClearType) -> Result<(), Self::Error> {
        match clear_type {
            ClearType::All => self.console.clear(),
            ClearType::CurrentLine => {
                let (_, row) = self.console.position();
                self.console.clear_line(row);
            }
            // For other clear types, fall back to full clear
            _ => self.console.clear(),
        }
        Ok(())
    }

    fn size(&self) -> Result<Size, Self::Error> {
        Ok(Size::new(
            self.console.cols() as u16,
            self.console.rows() as u16,
        ))
    }

    fn window_size(&mut self) -> Result<WindowSize, Self::Error> {
        let cols = self.console.cols() as u16;
        let rows = self.console.rows() as u16;
        Ok(WindowSize {
            columns_rows: Size::new(cols, rows),
            pixels: Size::new(
                cols * framebuffer_console::CHAR_WIDTH as u16,
                rows * framebuffer_console::CHAR_HEIGHT as u16,
            ),
        })
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ===========================================================================
// DualBackend
// ===========================================================================

/// Backend that renders to both serial and framebuffer simultaneously.
///
/// Uses the smaller of the two terminal sizes so widgets lay out correctly
/// on both outputs.
pub struct DualBackend<'a> {
    serial: SerialBackend,
    fb: Option<FramebufferBackend<'a>>,
}

impl<'a> DualBackend<'a> {
    /// Create a dual backend.
    ///
    /// If `fb_info` is `None`, this degrades to serial-only output.
    /// The serial dimensions are automatically matched to the framebuffer
    /// when available, or default to 80x25.
    pub fn new(fb_info: Option<&'a FramebufferInfo>) -> Self {
        match fb_info {
            Some(fb) => {
                let fb_backend = FramebufferBackend::new(fb);
                let cols = fb_backend.console.cols() as u16;
                let rows = fb_backend.console.rows() as u16;
                // Use the min of framebuffer and a generous serial assumption
                let width = cols.min(120);
                let height = rows.min(50);
                Self {
                    serial: SerialBackend::new(width, height),
                    fb: Some(fb_backend),
                }
            }
            None => Self {
                serial: SerialBackend::new(80, 25),
                fb: None,
            },
        }
    }
}

impl Backend for DualBackend<'_> {
    type Error = BackendError;

    fn draw<'a, I>(&mut self, content: I) -> Result<(), Self::Error>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        // Collect into a Vec so we can iterate twice (once per backend).
        // This is acceptable because draw() is only called with the diff
        // between frames, which is typically small.
        let cells: alloc::vec::Vec<(u16, u16, Cell)> =
            content.map(|(x, y, c)| (x, y, c.clone())).collect();

        self.serial
            .draw(cells.iter().map(|(x, y, c)| (*x, *y, c)))?;

        if let Some(fb) = &mut self.fb {
            fb.draw(cells.iter().map(|(x, y, c)| (*x, *y, c)))?;
        }

        Ok(())
    }

    fn hide_cursor(&mut self) -> Result<(), Self::Error> {
        self.serial.hide_cursor()?;
        if let Some(fb) = &mut self.fb {
            fb.hide_cursor()?;
        }
        Ok(())
    }

    fn show_cursor(&mut self) -> Result<(), Self::Error> {
        self.serial.show_cursor()?;
        if let Some(fb) = &mut self.fb {
            fb.show_cursor()?;
        }
        Ok(())
    }

    fn get_cursor_position(&mut self) -> Result<Position, Self::Error> {
        self.serial.get_cursor_position()
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> Result<(), Self::Error> {
        let pos: Position = position.into();
        self.serial.set_cursor_position(pos)?;
        if let Some(fb) = &mut self.fb {
            fb.set_cursor_position(pos)?;
        }
        Ok(())
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        self.serial.clear()?;
        if let Some(fb) = &mut self.fb {
            fb.clear()?;
        }
        Ok(())
    }

    fn clear_region(&mut self, clear_type: ClearType) -> Result<(), Self::Error> {
        self.serial.clear_region(clear_type)?;
        if let Some(fb) = &mut self.fb {
            fb.clear_region(clear_type)?;
        }
        Ok(())
    }

    fn size(&self) -> Result<Size, Self::Error> {
        self.serial.size()
    }

    fn window_size(&mut self) -> Result<WindowSize, Self::Error> {
        self.serial.window_size()
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.serial.flush()?;
        if let Some(fb) = &mut self.fb {
            fb.flush()?;
        }
        Ok(())
    }
}
