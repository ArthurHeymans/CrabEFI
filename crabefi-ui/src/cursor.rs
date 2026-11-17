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
    /// Save-under buffer (CURSOR_W * CURSOR_H native framebuffer pixels)
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
                    // SAFETY: x,y were bounds-checked when saved; framebuffer is memory-mapped
                    unsafe { fb.write_raw(px as u32, py as u32, self.save_buffer[row][col]) };
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

                // Save the native pixel underneath; restoring it needs no decoding.
                // SAFETY: x,y bounds are checked above; framebuffer is memory-mapped
                self.save_buffer[row][col] = unsafe { fb.read_raw(px as u32, py as u32) };
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

    /// Run `paint` with the cursor removed from the framebuffer, then put it
    /// back where it was.
    ///
    /// Any drawing that may touch pixels under the cursor must go through this:
    /// otherwise the sprite is overwritten and the save-under buffer goes stale,
    /// so the next move "restores" old pixels and leaves artifacts.
    pub fn while_hidden<R>(&mut self, fb: &FramebufferInfo, paint: impl FnOnce() -> R) -> R {
        let was_visible = self.visible;
        self.erase(fb);
        let result = paint();
        if was_visible {
            self.draw(fb, self.last_x, self.last_y);
        }
        result
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hiding_restores_the_exact_pixels_on_rgbx() {
        let mut mem = [0u32; 32 * 32];
        for (i, pixel) in mem.iter_mut().enumerate() {
            *pixel = 0x0001_0203u32.wrapping_mul(i as u32 + 1);
        }
        let before = mem;
        let fb = FramebufferInfo {
            physical_address: mem.as_mut_ptr() as u64,
            width: 32,
            height: 32,
            stride: 32,
            bits_per_pixel: 32,
            red_mask_pos: 0,
            red_mask_size: 8,
            green_mask_pos: 8,
            green_mask_size: 8,
            blue_mask_pos: 16,
            blue_mask_size: 8,
        };
        let mut cursor = CursorRenderer::new();
        cursor.update(&fb, 4, 4);
        cursor.update(&fb, 9, 7);
        cursor.hide(&fb);
        assert_eq!(mem, before);
    }
}
