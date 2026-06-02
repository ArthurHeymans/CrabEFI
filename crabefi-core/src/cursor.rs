//! Mouse Cursor Sprite Rendering
//!
//! Renders a mouse cursor sprite on the framebuffer with save-under
//! compositing: the framebuffer contents beneath the cursor are saved
//! before drawing and restored when the cursor moves.
//!
//! The cursor is a 12x19 pixel arrow pointer, similar to the classic
//! Windows/X11 cursor shape. It uses XOR-like compositing (black outline
//! with white fill) so it is visible on any background.

use crate::FramebufferConfig as FramebufferInfo;

/// Cursor width in pixels
pub const CURSOR_W: usize = 12;

/// Cursor height in pixels
pub const CURSOR_H: usize = 19;

/// Cursor hot spot X offset (tip of the arrow)
pub const HOTSPOT_X: i32 = 0;

/// Cursor hot spot Y offset
pub const HOTSPOT_Y: i32 = 0;

/// Cursor sprite bitmap.
///
/// 0 = transparent, 1 = black (outline), 2 = white (fill)
#[rustfmt::skip]
static CURSOR_BITMAP: [[u8; CURSOR_W]; CURSOR_H] = [
    [1,0,0,0,0,0,0,0,0,0,0,0],
    [1,1,0,0,0,0,0,0,0,0,0,0],
    [1,2,1,0,0,0,0,0,0,0,0,0],
    [1,2,2,1,0,0,0,0,0,0,0,0],
    [1,2,2,2,1,0,0,0,0,0,0,0],
    [1,2,2,2,2,1,0,0,0,0,0,0],
    [1,2,2,2,2,2,1,0,0,0,0,0],
    [1,2,2,2,2,2,2,1,0,0,0,0],
    [1,2,2,2,2,2,2,2,1,0,0,0],
    [1,2,2,2,2,2,2,2,2,1,0,0],
    [1,2,2,2,2,2,2,2,2,2,1,0],
    [1,2,2,2,2,2,2,1,1,1,1,1],
    [1,2,2,2,1,2,2,1,0,0,0,0],
    [1,2,2,1,0,1,2,2,1,0,0,0],
    [1,2,1,0,0,1,2,2,1,0,0,0],
    [1,1,0,0,0,0,1,2,2,1,0,0],
    [1,0,0,0,0,0,1,2,2,1,0,0],
    [0,0,0,0,0,0,0,1,2,1,0,0],
    [0,0,0,0,0,0,0,1,1,0,0,0],
];

/// Cursor rendering state
pub struct CursorRenderer {
    /// Whether cursor is currently drawn on screen
    visible: bool,
    /// Last drawn X position
    last_x: i32,
    /// Last drawn Y position
    last_y: i32,
    /// Save-under buffer (CURSOR_W * CURSOR_H pixels, stored as packed RGB)
    save_buffer: [[u32; CURSOR_W]; CURSOR_H],
    /// Which pixels were actually drawn (within screen bounds)
    save_valid: [[bool; CURSOR_W]; CURSOR_H],
}

impl Default for CursorRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl CursorRenderer {
    /// Create a new cursor renderer.
    pub const fn new() -> Self {
        Self {
            visible: false,
            last_x: 0,
            last_y: 0,
            save_buffer: [[0; CURSOR_W]; CURSOR_H],
            save_valid: [[false; CURSOR_W]; CURSOR_H],
        }
    }

    /// Erase the cursor from the framebuffer by restoring saved pixels.
    fn erase(&mut self, fb: &FramebufferInfo) {
        if !self.visible {
            return;
        }

        for row in 0..CURSOR_H {
            for col in 0..CURSOR_W {
                if self.save_valid[row][col] {
                    let px = self.last_x + col as i32;
                    let py = self.last_y + row as i32;
                    let saved = self.save_buffer[row][col];
                    let r = ((saved >> 16) & 0xFF) as u8;
                    let g = ((saved >> 8) & 0xFF) as u8;
                    let b = (saved & 0xFF) as u8;
                    // SAFETY: x,y bounds are validated; framebuffer is memory-mapped
                    unsafe { fb.write_pixel(px as u32, py as u32, r, g, b) };
                }
            }
        }

        self.visible = false;
    }

    /// Draw the cursor at the given position, saving the pixels underneath.
    fn draw(&mut self, fb: &FramebufferInfo, x: i32, y: i32) {
        // Reset save validity
        for row in &mut self.save_valid {
            row.fill(false);
        }

        for (row, bitmap_row) in CURSOR_BITMAP.iter().enumerate() {
            for (col, &pixel) in bitmap_row.iter().enumerate() {
                if pixel == 0 {
                    continue; // Transparent
                }

                let px = x + col as i32;
                let py = y + row as i32;

                // Bounds check
                if px < 0 || py < 0 || px >= fb.width as i32 || py >= fb.height as i32 {
                    continue;
                }

                // Save the pixel underneath
                self.save_buffer[row][col] = read_pixel(fb, px as u32, py as u32);
                self.save_valid[row][col] = true;

                // Draw cursor pixel
                let (r, g, b) = match pixel {
                    1 => (0, 0, 0),       // Black outline
                    2 => (255, 255, 255), // White fill
                    _ => continue,
                };
                // SAFETY: x,y bounds are checked above; framebuffer is memory-mapped
                unsafe { fb.write_pixel(px as u32, py as u32, r, g, b) };
            }
        }

        self.last_x = x;
        self.last_y = y;
        self.visible = true;
    }

    /// Update the cursor position on the framebuffer.
    ///
    /// Erases the old cursor, then draws at the new position.
    pub fn update(&mut self, fb: &FramebufferInfo, x: i32, y: i32) {
        // Skip if position hasn't changed and cursor is already drawn
        if self.visible && x == self.last_x && y == self.last_y {
            return;
        }

        self.erase(fb);
        self.draw(fb, x, y);
    }

    /// Hide the cursor (erase without redrawing).
    pub fn hide(&mut self, fb: &FramebufferInfo) {
        self.erase(fb);
    }

    /// Show the cursor at the current position.
    pub fn show(&mut self, fb: &FramebufferInfo, x: i32, y: i32) {
        if !self.visible {
            self.draw(fb, x, y);
        }
    }

    /// Check if the cursor is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }
}

/// Read a pixel from the framebuffer as packed RGB (0x00RRGGBB).
///
/// This reads raw bytes from the framebuffer and converts to a canonical
/// format for save-under buffering.
fn read_pixel(fb: &FramebufferInfo, x: u32, y: u32) -> u32 {
    let offset = fb.pixel_offset(x, y);

    // SAFETY: The framebuffer address and dimensions have been validated.
    // x,y are bounds-checked by the caller.
    unsafe {
        let base = fb.as_ptr() as *const u8;
        match fb.bits_per_pixel {
            32 => {
                let ptr = base.add(offset);
                let b = ptr.read_volatile();
                let g = ptr.add(1).read_volatile();
                let r = ptr.add(2).read_volatile();
                ((r as u32) << 16) | ((g as u32) << 8) | b as u32
            }
            24 => {
                let ptr = base.add(offset);
                let b = ptr.read_volatile();
                let g = ptr.add(1).read_volatile();
                let r = ptr.add(2).read_volatile();
                ((r as u32) << 16) | ((g as u32) << 8) | b as u32
            }
            16 => {
                let ptr = base.add(offset) as *const u16;
                let pixel = ptr.read_volatile();
                // RGB565: RRRRRGGGGGGBBBBB
                let r = ((pixel >> 11) & 0x1F) as u32;
                let g = ((pixel >> 5) & 0x3F) as u32;
                let b = (pixel & 0x1F) as u32;
                // Expand to 8-bit
                ((r << 19) | (r << 14)) | ((g << 10) | (g << 4)) | ((b << 3) | (b >> 2))
            }
            _ => 0,
        }
    }
}
