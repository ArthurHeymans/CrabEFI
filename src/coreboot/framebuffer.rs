//! Framebuffer information from coreboot
//!
//! This module handles framebuffer information extracted from coreboot tables.

/// Framebuffer information
#[derive(Debug, Clone)]
pub struct FramebufferInfo {
    /// Physical address of the framebuffer
    pub physical_address: u64,
    /// Horizontal resolution in pixels
    pub x_resolution: u32,
    /// Vertical resolution in pixels
    pub y_resolution: u32,
    /// Bytes per scanline
    pub bytes_per_line: u32,
    /// Bits per pixel
    pub bits_per_pixel: u8,
    /// Red mask position (bit offset)
    pub red_mask_pos: u8,
    /// Red mask size (number of bits)
    pub red_mask_size: u8,
    /// Green mask position
    pub green_mask_pos: u8,
    /// Green mask size
    pub green_mask_size: u8,
    /// Blue mask position
    pub blue_mask_pos: u8,
    /// Blue mask size
    pub blue_mask_size: u8,
}

impl FramebufferInfo {
    /// Get the size of the framebuffer in bytes
    pub fn size(&self) -> u64 {
        self.bytes_per_line as u64 * self.y_resolution as u64
    }

    /// Get a pointer to the framebuffer (requires identity mapping)
    pub fn as_ptr(&self) -> *mut u8 {
        self.physical_address as *mut u8
    }

    /// Get a mutable slice to the framebuffer
    ///
    /// # Safety
    ///
    /// The framebuffer must be identity-mapped and accessible.
    pub unsafe fn as_slice_mut(&mut self) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.as_ptr(), self.size() as usize)
    }

    /// Calculate the byte offset for a pixel at (x, y)
    pub fn pixel_offset(&self, x: u32, y: u32) -> usize {
        (y * self.bytes_per_line + x * (self.bits_per_pixel as u32 / 8)) as usize
    }

    /// Write a pixel at (x, y) with the given RGB color
    ///
    /// # Safety
    ///
    /// The framebuffer must be accessible and (x, y) must be in bounds.
    pub unsafe fn write_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8) {
        if x >= self.x_resolution || y >= self.y_resolution {
            return;
        }

        let offset = self.pixel_offset(x, y);
        let fb = self.as_ptr();

        match self.bits_per_pixel {
            32 => {
                // BGRA or RGBA format
                let pixel = self.encode_pixel_32(r, g, b);
                let ptr = fb.add(offset) as *mut u32;
                ptr.write_volatile(pixel);
            }
            24 => {
                // BGR or RGB format
                let ptr = fb.add(offset);
                if self.blue_mask_pos < self.red_mask_pos {
                    // BGR
                    ptr.write_volatile(b);
                    ptr.add(1).write_volatile(g);
                    ptr.add(2).write_volatile(r);
                } else {
                    // RGB
                    ptr.write_volatile(r);
                    ptr.add(1).write_volatile(g);
                    ptr.add(2).write_volatile(b);
                }
            }
            16 => {
                // RGB565 or similar
                let pixel = self.encode_pixel_16(r, g, b);
                let ptr = fb.add(offset) as *mut u16;
                ptr.write_volatile(pixel);
            }
            _ => {
                // Unsupported format
            }
        }
    }

    /// Encode a 32-bit pixel value
    fn encode_pixel_32(&self, r: u8, g: u8, b: u8) -> u32 {
        let r = (r as u32) << self.red_mask_pos;
        let g = (g as u32) << self.green_mask_pos;
        let b = (b as u32) << self.blue_mask_pos;
        r | g | b
    }

    /// Encode a 16-bit pixel value
    fn encode_pixel_16(&self, r: u8, g: u8, b: u8) -> u16 {
        // Scale down to the mask size
        let r = ((r as u16) >> (8 - self.red_mask_size)) << self.red_mask_pos;
        let g = ((g as u16) >> (8 - self.green_mask_size)) << self.green_mask_pos;
        let b = ((b as u16) >> (8 - self.blue_mask_size)) << self.blue_mask_pos;
        r | g | b
    }

    /// Clear the framebuffer with a solid color
    ///
    /// # Safety
    ///
    /// The framebuffer must be accessible.
    pub unsafe fn clear(&self, r: u8, g: u8, b: u8) {
        for y in 0..self.y_resolution {
            for x in 0..self.x_resolution {
                self.write_pixel(x, y, r, g, b);
            }
        }
    }
}
