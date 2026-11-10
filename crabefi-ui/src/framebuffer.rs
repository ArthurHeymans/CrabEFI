/// Framebuffer configuration for the Graphics Output Protocol.
///
/// The platform provides this when a framebuffer is available. CrabEFI uses
/// it for the EFI GOP protocol and the text-mode boot menu.
#[derive(Debug, Clone, Copy)]
pub struct FramebufferConfig {
    /// Physical address of the framebuffer memory.
    pub physical_address: u64,
    /// Horizontal resolution in pixels.
    pub width: u32,
    /// Vertical resolution in pixels.
    pub height: u32,
    /// Pixels per scanline (may be wider than `width` due to alignment).
    ///
    /// To get bytes per scanline, multiply by `bits_per_pixel / 8`.
    pub stride: u32,
    /// Bits per pixel (typically 32).
    pub bits_per_pixel: u8,
    /// Bit position of the red channel.
    pub red_mask_pos: u8,
    /// Number of bits in the red channel.
    pub red_mask_size: u8,
    /// Bit position of the green channel.
    pub green_mask_pos: u8,
    /// Number of bits in the green channel.
    pub green_mask_size: u8,
    /// Bit position of the blue channel.
    pub blue_mask_pos: u8,
    /// Number of bits in the blue channel.
    pub blue_mask_size: u8,
}

impl FramebufferConfig {
    /// Framebuffer size in bytes.
    pub fn size(&self) -> u64 {
        self.bytes_per_line() as u64 * self.height as u64
    }

    /// Bytes per scanline (`stride * bytes_per_pixel`).
    pub fn bytes_per_line(&self) -> u32 {
        self.stride * (self.bits_per_pixel as u32 / 8)
    }

    /// Raw pointer to the framebuffer.
    pub fn as_ptr(&self) -> *mut u8 {
        core::ptr::with_exposed_provenance_mut(self.physical_address as usize)
    }

    /// Byte offset for a pixel at coordinates (x, y).
    ///
    /// Uses `u64` intermediates to avoid overflow on large framebuffers.
    pub fn pixel_offset(&self, x: u32, y: u32) -> usize {
        let bpp = self.bits_per_pixel as u64 / 8;
        (y as u64 * self.stride as u64 * bpp + x as u64 * bpp) as usize
    }

    /// Encode a pixel value for the framebuffer's native format.
    ///
    /// For 32bpp, returns the native pixel encoding.
    /// For 16bpp, returns the 16-bit pixel zero-extended to u32.
    /// For other bpp, returns 0.
    pub fn encode_pixel(&self, r: u8, g: u8, b: u8) -> u32 {
        match self.bits_per_pixel {
            32 => self.encode_pixel_32(r, g, b),
            16 => self.encode_pixel_16(r, g, b) as u32,
            _ => 0,
        }
    }

    /// Read the native pixel value at (x, y), zero-extended to `u32`.
    ///
    /// # Safety
    ///
    /// The framebuffer must be accessible and (x, y) must be in bounds.
    pub unsafe fn read_raw(&self, x: u32, y: u32) -> u32 {
        // SAFETY: the caller guarantees the pixel is inside the mapped framebuffer.
        unsafe {
            let ptr = self.as_ptr().add(self.pixel_offset(x, y));
            match self.bits_per_pixel {
                32 => (ptr as *const u32).read_volatile(),
                24 => {
                    u32::from(ptr.read_volatile())
                        | u32::from(ptr.add(1).read_volatile()) << 8
                        | u32::from(ptr.add(2).read_volatile()) << 16
                }
                16 => u32::from((ptr as *const u16).read_volatile()),
                _ => 0,
            }
        }
    }

    /// Write a native pixel value previously returned by [`Self::read_raw`].
    ///
    /// # Safety
    ///
    /// The framebuffer must be accessible and (x, y) must be in bounds.
    pub unsafe fn write_raw(&self, x: u32, y: u32, value: u32) {
        // SAFETY: the caller guarantees the pixel is inside the mapped framebuffer.
        unsafe {
            let ptr = self.as_ptr().add(self.pixel_offset(x, y));
            match self.bits_per_pixel {
                32 => (ptr as *mut u32).write_volatile(value),
                24 => {
                    ptr.write_volatile(value as u8);
                    ptr.add(1).write_volatile((value >> 8) as u8);
                    ptr.add(2).write_volatile((value >> 16) as u8);
                }
                16 => (ptr as *mut u16).write_volatile(value as u16),
                _ => {}
            }
        }
    }

    /// Decode a native pixel value to 8-bit RGB using the channel masks.
    pub fn decode_pixel(&self, value: u32) -> (u8, u8, u8) {
        let channel = |pos: u8, size: u8| {
            if size == 0 || pos >= 32 {
                return 0;
            }
            let max = (1u64 << size.min(32)) - 1;
            (((u64::from(value) >> pos) & max) * 255 / max) as u8
        };
        (
            channel(self.red_mask_pos, self.red_mask_size),
            channel(self.green_mask_pos, self.green_mask_size),
            channel(self.blue_mask_pos, self.blue_mask_size),
        )
    }

    /// Write a pixel at (x, y) with the given RGB color.
    ///
    /// # Safety
    ///
    /// The framebuffer must be accessible and (x, y) must be in bounds.
    pub unsafe fn write_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8) {
        if x >= self.width || y >= self.height {
            return;
        }
        let offset = self.pixel_offset(x, y);
        let fb = self.as_ptr();
        unsafe {
            match self.bits_per_pixel {
                32 => {
                    let pixel = self.encode_pixel_32(r, g, b);
                    (fb.add(offset) as *mut u32).write_volatile(pixel);
                }
                24 => {
                    let ptr = fb.add(offset);
                    if self.blue_mask_pos < self.red_mask_pos {
                        ptr.write_volatile(b);
                        ptr.add(1).write_volatile(g);
                        ptr.add(2).write_volatile(r);
                    } else {
                        ptr.write_volatile(r);
                        ptr.add(1).write_volatile(g);
                        ptr.add(2).write_volatile(b);
                    }
                }
                16 => {
                    let pixel = self.encode_pixel_16(r, g, b);
                    (fb.add(offset) as *mut u16).write_volatile(pixel);
                }
                _ => {}
            }
        }
    }

    /// Fill a framebuffer region with a solid color.
    ///
    /// # Safety
    ///
    /// `dst` must point to `pixel_count * (bits_per_pixel/8)` writable bytes
    /// within the framebuffer.
    pub unsafe fn fill_pixels(&self, dst: *mut u8, pixel_count: usize, r: u8, g: u8, b: u8) {
        unsafe {
            match self.bits_per_pixel {
                32 => {
                    let pixel = self.encode_pixel_32(r, g, b);
                    let ptr = dst as *mut u32;
                    for i in 0..pixel_count {
                        ptr.add(i).write_volatile(pixel);
                    }
                }
                24 => {
                    let bytes = if self.blue_mask_pos < self.red_mask_pos {
                        [b, g, r]
                    } else {
                        [r, g, b]
                    };
                    for i in 0..pixel_count {
                        let ptr = dst.add(i * 3);
                        ptr.write_volatile(bytes[0]);
                        ptr.add(1).write_volatile(bytes[1]);
                        ptr.add(2).write_volatile(bytes[2]);
                    }
                }
                16 => {
                    let pixel = self.encode_pixel_16(r, g, b);
                    let ptr = dst as *mut u16;
                    for i in 0..pixel_count {
                        ptr.add(i).write_volatile(pixel);
                    }
                }
                _ => {
                    core::slice::from_raw_parts_mut(
                        dst,
                        pixel_count * (self.bits_per_pixel as usize / 8),
                    )
                    .fill(0);
                }
            }
        }
    }

    /// Fill the entire framebuffer with a solid color.
    ///
    /// # Safety
    ///
    /// The framebuffer must be accessible.
    pub unsafe fn fill_solid(&self, r: u8, g: u8, b: u8) {
        let bpl = self.bytes_per_line() as usize;
        let row_pixels = self.width as usize;
        let packed = bpl == row_pixels * (self.bits_per_pixel as usize / 8);
        // SAFETY: caller guarantees the framebuffer is identity-mapped.
        unsafe {
            let fb = self.as_ptr();
            if packed {
                let total = row_pixels * self.height as usize;
                self.fill_pixels(fb, total, r, g, b);
            } else {
                for y in 0..self.height {
                    let offset = (y as usize) * bpl;
                    self.fill_pixels(fb.add(offset), row_pixels, r, g, b);
                }
            }
        }
    }

    /// Clear the entire framebuffer.
    ///
    /// # Safety
    ///
    /// The framebuffer must be accessible.
    pub unsafe fn clear(&self, r: u8, g: u8, b: u8) {
        let fb = self.as_ptr();
        let bpl = self.bytes_per_line() as usize;
        unsafe {
            match self.bits_per_pixel {
                32 => {
                    let pixel = self.encode_pixel_32(r, g, b);
                    for y in 0..self.height as usize {
                        let row = fb.add(y * bpl);
                        for x in 0..self.width as usize {
                            (row.add(x * 4) as *mut u32).write_volatile(pixel);
                        }
                    }
                }
                _ => {
                    for y in 0..self.height {
                        for x in 0..self.width {
                            self.write_pixel(x, y, r, g, b);
                        }
                    }
                }
            }
        }
    }

    fn encode_pixel_32(&self, r: u8, g: u8, b: u8) -> u32 {
        let r = ((r as u32) >> 8u32.saturating_sub(self.red_mask_size as u32)) << self.red_mask_pos;
        let g =
            ((g as u32) >> 8u32.saturating_sub(self.green_mask_size as u32)) << self.green_mask_pos;
        let b =
            ((b as u32) >> 8u32.saturating_sub(self.blue_mask_size as u32)) << self.blue_mask_pos;
        r | g | b
    }

    fn encode_pixel_16(&self, r: u8, g: u8, b: u8) -> u16 {
        let r = ((r as u16) >> 8u16.saturating_sub(self.red_mask_size as u16)) << self.red_mask_pos;
        let g =
            ((g as u16) >> 8u16.saturating_sub(self.green_mask_size as u16)) << self.green_mask_pos;
        let b =
            ((b as u16) >> 8u16.saturating_sub(self.blue_mask_size as u16)) << self.blue_mask_pos;
        r | g | b
    }
}

#[cfg(test)]
mod tests {
    use super::FramebufferConfig;

    fn config(mem: &mut [u8], bpp: u8, red: u8, blue: u8) -> FramebufferConfig {
        FramebufferConfig {
            physical_address: mem.as_mut_ptr() as u64,
            width: 4,
            height: 1,
            stride: 4,
            bits_per_pixel: bpp,
            red_mask_pos: red,
            red_mask_size: 8,
            green_mask_pos: 8,
            green_mask_size: 8,
            blue_mask_pos: blue,
            blue_mask_size: 8,
        }
    }

    #[test]
    fn fill_writes_the_colour_on_24_bpp() {
        for (red, blue, bytes) in [(16, 0, [3, 2, 1]), (0, 16, [1, 2, 3])] {
            let mut mem = [0u8; 12];
            let fb = config(&mut mem, 24, red, blue);
            // SAFETY: `mem` holds the whole 4x1 framebuffer.
            unsafe { fb.fill_solid(1, 2, 3) };
            assert!(mem.chunks(3).all(|pixel| pixel == bytes));
        }
    }

    #[test]
    fn raw_pixels_round_trip_and_decode_with_the_masks() {
        for bpp in [24, 32] {
            let mut mem = [0u8; 16];
            let fb = config(&mut mem, bpp, 0, 16); // RGBX: red in the low byte
            // SAFETY: (1, 0) lies inside the 4x1 framebuffer.
            unsafe {
                fb.write_pixel(1, 0, 10, 20, 30);
                let raw = fb.read_raw(1, 0);
                assert_eq!(fb.decode_pixel(raw), (10, 20, 30));
                fb.write_raw(2, 0, raw);
                assert_eq!(fb.decode_pixel(fb.read_raw(2, 0)), (10, 20, 30));
            }
        }
    }
}
