//! Low-level framebuffer drawing primitives.
//!
//! Provides filled rectangles, gradients, rounded rectangles, glow effects,
//! progress bars, pill badges, toggle switches, and multi-size anti-aliased
//! text rendering using the Noto Sans Mono bitmap font.

use crate::FramebufferConfig as FramebufferInfo;
use noto_sans_mono_bitmap::{FontWeight, RasterHeight, get_raster, get_raster_width};

/// RGB color triple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Linearly interpolate between `self` and `other` by `t` (0..=255).
    pub const fn lerp(self, other: Self, t: u8) -> Self {
        let t16 = t as u16;
        let inv = 255 - t16;
        Self {
            r: ((self.r as u16 * inv + other.r as u16 * t16) / 255) as u8,
            g: ((self.g as u16 * inv + other.g as u16 * t16) / 255) as u8,
            b: ((self.b as u16 * inv + other.b as u16 * t16) / 255) as u8,
        }
    }

    /// Brighten by `amount` (0..=255).
    pub const fn brighten(self, amount: u8) -> Self {
        let a = amount as u16;
        Self {
            r: (self.r as u16 + (255 - self.r as u16) * a / 255) as u8,
            g: (self.g as u16 + (255 - self.g as u16) * a / 255) as u8,
            b: (self.b as u16 + (255 - self.b as u16) * a / 255) as u8,
        }
    }

    /// Darken by `amount` (0..=255).
    pub const fn darken(self, amount: u8) -> Self {
        let inv = 255 - amount as u16;
        Self {
            r: (self.r as u16 * inv / 255) as u8,
            g: (self.g as u16 * inv / 255) as u8,
            b: (self.b as u16 * inv / 255) as u8,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Font sizes
// ═══════════════════════════════════════════════════════════════════════

/// Available font sizes for text rendering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FontSize {
    /// 16px — labels, pills, footer, secondary text
    Small,
    /// 20px — body text, card content, sidebar items
    Normal,
    /// 24px — section subheadings, card titles
    Heading,
    /// 32px — page titles, hero text
    Display,
}

impl FontSize {
    fn raster_height(self) -> RasterHeight {
        match self {
            FontSize::Small => RasterHeight::Size16,
            FontSize::Normal => RasterHeight::Size20,
            FontSize::Heading => RasterHeight::Size24,
            FontSize::Display => RasterHeight::Size32,
        }
    }
}

/// Height of a font in pixels.
pub fn font_height(size: FontSize) -> u32 {
    size.raster_height().val() as u32
}

/// Width of a single glyph in pixels (monospace — same for all chars).
pub fn font_width(size: FontSize) -> u32 {
    get_raster_width(FontWeight::Regular, size.raster_height()) as u32
}

/// Pixel width of a string at the given size.
pub fn text_width(s: &str, size: FontSize) -> u32 {
    s.len() as u32 * font_width(size)
}

// ═══════════════════════════════════════════════════════════════════════
//  Rectangles
// ═══════════════════════════════════════════════════════════════════════

/// Fill a rectangle with a solid color (bounds-clipped).
pub fn fill_rect(fb: &FramebufferInfo, x: i32, y: i32, w: u32, h: u32, c: Rgb) {
    let x0 = x.max(0) as u32;
    let y0 = y.max(0) as u32;
    let x1 = ((x as i64 + w as i64) as u32).min(fb.width);
    let y1 = ((y as i64 + h as i64) as u32).min(fb.height);
    if x0 >= x1 || y0 >= y1 {
        return;
    }
    let rpx = (x1 - x0) as usize;
    for row in y0..y1 {
        let off = fb.pixel_offset(x0, row);
        // SAFETY: coordinates clipped to framebuffer bounds.
        unsafe { fb.fill_pixels(fb.as_ptr().add(off), rpx, c.r, c.g, c.b) };
    }
}

/// Fill a rectangle with a vertical gradient from `top` to `bottom`.
pub fn fill_gradient_v(fb: &FramebufferInfo, x: i32, y: i32, w: u32, h: u32, top: Rgb, bot: Rgb) {
    if h == 0 {
        return;
    }
    for r in 0..h {
        let t = ((r * 255) / (h - 1).max(1)) as u8;
        fill_rect(fb, x, y + r as i32, w, 1, top.lerp(bot, t));
    }
}

/// Fill with a horizontal gradient.
pub fn fill_gradient_h(
    fb: &FramebufferInfo,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    left: Rgb,
    right: Rgb,
) {
    if w == 0 {
        return;
    }
    for c in 0..w {
        let t = ((c * 255) / (w - 1).max(1)) as u8;
        fill_rect(fb, x + c as i32, y, 1, h, left.lerp(right, t));
    }
}

/// Draw a 1-pixel border.
pub fn draw_border(fb: &FramebufferInfo, x: i32, y: i32, w: u32, h: u32, c: Rgb) {
    fill_rect(fb, x, y, w, 1, c);
    fill_rect(fb, x, y + h as i32 - 1, w, 1, c);
    fill_rect(fb, x, y, 1, h, c);
    fill_rect(fb, x + w as i32 - 1, y, 1, h, c);
}

/// Draw a border with a given thickness.
pub fn draw_thick_border(fb: &FramebufferInfo, x: i32, y: i32, w: u32, h: u32, t: u32, c: Rgb) {
    fill_rect(fb, x, y, w, t, c);
    fill_rect(fb, x, y + h as i32 - t as i32, w, t, c);
    fill_rect(fb, x, y, t, h, c);
    fill_rect(fb, x + w as i32 - t as i32, y, t, h, c);
}

// ═══════════════════════════════════════════════════════════════════════
//  Rounded rectangles
// ═══════════════════════════════════════════════════════════════════════

/// Integer square root.
fn isqrt(n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Filled rounded rectangle.
pub fn fill_rounded_rect(fb: &FramebufferInfo, x: i32, y: i32, w: u32, h: u32, r: u32, c: Rgb) {
    if r == 0 || w < r * 2 || h < r * 2 {
        fill_rect(fb, x, y, w, h, c);
        return;
    }
    fill_rect(fb, x, y + r as i32, w, h - r * 2, c);
    for dy in 0..r {
        let ry = r - dy - 1;
        let inset = r - isqrt(r * r - ry * ry);
        let sx = x + inset as i32;
        let sw = w - inset * 2;
        fill_rect(fb, sx, y + dy as i32, sw, 1, c);
        fill_rect(fb, sx, y + (h - 1 - dy) as i32, sw, 1, c);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Effects
// ═══════════════════════════════════════════════════════════════════════

/// Draw a soft glow border around a rounded rectangle.
pub fn draw_glow(
    fb: &FramebufferInfo,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    radius: u32,
    spread: u32,
    glow_color: Rgb,
    bg: Rgb,
) {
    for s in 1..=spread {
        let alpha = ((spread - s) * 180 / spread) as u8;
        let c = bg.lerp(glow_color, alpha);
        let r = radius + s;
        let gx = x - s as i32;
        let gy = y - s as i32;
        let gw = w + s * 2;
        let gh = h + s * 2;

        // Top and bottom edges
        for dy in 0..r.min(gh) {
            let ry = r.saturating_sub(dy).saturating_sub(1);
            let inset = r - isqrt(r * r - ry.min(r) * ry.min(r));
            let sx = gx + inset as i32;
            let ew = gw.saturating_sub(inset * 2);
            if ew > 0 {
                fill_rect(fb, sx, gy + dy as i32, ew, 1, c);
                fill_rect(
                    fb,
                    sx,
                    gy + (gh.saturating_sub(1).saturating_sub(dy)) as i32,
                    ew,
                    1,
                    c,
                );
            }
        }
        // Left and right strips (excluding corners)
        if gh > r * 2 {
            fill_rect(fb, gx, gy + r as i32, 1, gh - r * 2, c);
            fill_rect(fb, gx + gw as i32 - 1, gy + r as i32, 1, gh - r * 2, c);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Widgets
// ═══════════════════════════════════════════════════════════════════════

/// Draw a horizontal progress bar.
pub fn draw_progress_bar(
    fb: &FramebufferInfo,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    fraction: f32,
    bar_color: Rgb,
    track_color: Rgb,
    radius: u32,
) {
    // Track
    fill_rounded_rect(fb, x, y, w, h, radius, track_color);
    // Filled portion
    let filled_w = ((w as f32 * fraction.clamp(0.0, 1.0)) as u32).max(if fraction > 0.0 {
        radius * 2
    } else {
        0
    });
    if filled_w > 0 {
        fill_rounded_rect(fb, x, y, filled_w, h, radius, bar_color);
    }
}

/// Draw a pill-shaped badge with text.
pub fn draw_pill(fb: &FramebufferInfo, x: i32, y: i32, label: &str, fg: Rgb, bg: Rgb) {
    let size = FontSize::Small;
    let tw = text_width(label, size);
    let pad = 8u32;
    let h = font_height(size) + 6;
    let w = tw + pad * 2;
    let r = h / 2;
    fill_rounded_rect(fb, x, y, w, h, r, bg);
    draw_text(fb, x + pad as i32, y + 3, label, size, fg, Some(bg));
}

/// Draw a toggle switch (on/off).
pub fn draw_toggle(fb: &FramebufferInfo, x: i32, y: i32, on: bool, accent: Rgb) {
    let w = 36u32;
    let h = 18u32;
    let r = h / 2;
    let track_color = if on { accent } else { Rgb::new(60, 60, 80) };

    fill_rounded_rect(fb, x, y, w, h, r, track_color);
    draw_border(fb, x, y, w, h, track_color.brighten(40));

    // Knob
    let knob_r = 6u32;
    let knob_y = y + (h as i32 / 2) - knob_r as i32;
    let knob_x = if on {
        x + w as i32 - knob_r as i32 * 2 - 3
    } else {
        x + 3
    };
    fill_rounded_rect(
        fb,
        knob_x,
        knob_y,
        knob_r * 2,
        knob_r * 2,
        knob_r,
        Rgb::new(240, 240, 250),
    );
}

/// Draw a small filled circle (dot indicator).
pub fn draw_dot(fb: &FramebufferInfo, cx: i32, cy: i32, r: u32, c: Rgb) {
    let r2 = (r * r) as i32;
    for dy in -(r as i32)..=(r as i32) {
        for dx in -(r as i32)..=(r as i32) {
            if dx * dx + dy * dy <= r2 {
                let px = cx + dx;
                let py = cy + dy;
                if px >= 0 && py >= 0 && px < fb.width as i32 && py < fb.height as i32 {
                    // SAFETY: bounds checked
                    unsafe { fb.write_pixel(px as u32, py as u32, c.r, c.g, c.b) };
                }
            }
        }
    }
}

/// Draw a thin horizontal separator with a gradient fade.
pub fn draw_separator(fb: &FramebufferInfo, x: i32, y: i32, w: u32, c: Rgb, bg: Rgb) {
    let fade = w / 6;
    fill_gradient_h(fb, x, y, fade, 1, bg, c);
    fill_rect(fb, x + fade as i32, y, w - fade * 2, 1, c);
    fill_gradient_h(fb, x + (w - fade) as i32, y, fade, 1, c, bg);
}

// ═══════════════════════════════════════════════════════════════════════
//  Text rendering (Noto Sans Mono with alpha blending)
// ═══════════════════════════════════════════════════════════════════════

/// Read a framebuffer pixel as RGB (for alpha blending on unknown backgrounds).
fn read_fb_pixel(fb: &FramebufferInfo, x: u32, y: u32) -> Rgb {
    let off = fb.pixel_offset(x, y);
    // SAFETY: caller ensures x,y are within bounds.
    unsafe {
        let ptr = fb.as_ptr().add(off);
        match fb.bits_per_pixel {
            32 => {
                let b = ptr.read_volatile();
                let g = ptr.add(1).read_volatile();
                let r = ptr.add(2).read_volatile();
                Rgb::new(r, g, b)
            }
            24 => {
                let b = ptr.read_volatile();
                let g = ptr.add(1).read_volatile();
                let r = ptr.add(2).read_volatile();
                Rgb::new(r, g, b)
            }
            16 => {
                let lo = ptr.read_volatile() as u16;
                let hi = ptr.add(1).read_volatile() as u16;
                let v = lo | (hi << 8);
                let r = ((v >> 11) & 0x1F) as u8;
                let g = ((v >> 5) & 0x3F) as u8;
                let b = (v & 0x1F) as u8;
                Rgb::new(
                    (r << 3) | (r >> 2),
                    (g << 2) | (g >> 4),
                    (b << 3) | (b >> 2),
                )
            }
            _ => Rgb::new(0, 0, 0),
        }
    }
}

/// Draw a single character with anti-aliased alpha blending.
///
/// If `bg` is `Some(color)`, blends against that color (fast, no FB reads).
/// If `bg` is `None`, reads the framebuffer pixel to blend against (correct on gradients).
pub fn draw_char(
    fb: &FramebufferInfo,
    px: i32,
    py: i32,
    ch: char,
    size: FontSize,
    fg: Rgb,
    bg: Option<Rgb>,
) {
    let raster = match get_raster(ch, FontWeight::Regular, size.raster_height()) {
        Some(r) => r,
        None => match get_raster('?', FontWeight::Regular, size.raster_height()) {
            Some(r) => r,
            None => return,
        },
    };

    let rows = raster.raster();
    let w = raster.width();
    let h = raster.height();

    for (row, raster_row) in rows.iter().enumerate().take(h) {
        for (col, &alpha) in raster_row.iter().enumerate().take(w) {
            let sx = px + col as i32;
            let sy = py + row as i32;
            if sx < 0 || sy < 0 || sx >= fb.width as i32 || sy >= fb.height as i32 {
                continue;
            }
            if alpha == 0 {
                // Fully transparent — write bg if given, skip otherwise.
                if let Some(b) = bg {
                    unsafe { fb.write_pixel(sx as u32, sy as u32, b.r, b.g, b.b) };
                }
                continue;
            }
            if alpha == 255 {
                // Fully opaque — just write fg.
                unsafe { fb.write_pixel(sx as u32, sy as u32, fg.r, fg.g, fg.b) };
                continue;
            }

            // Partial transparency — alpha blend.
            let bg_color = match bg {
                Some(b) => b,
                None => read_fb_pixel(fb, sx as u32, sy as u32),
            };
            let a = alpha as u16;
            let inv = 255 - a;
            let r = ((fg.r as u16 * a + bg_color.r as u16 * inv) / 255) as u8;
            let g = ((fg.g as u16 * a + bg_color.g as u16 * inv) / 255) as u8;
            let b = ((fg.b as u16 * a + bg_color.b as u16 * inv) / 255) as u8;
            unsafe { fb.write_pixel(sx as u32, sy as u32, r, g, b) };
        }
    }
}

/// Draw a string. Returns pixel width.
pub fn draw_text(
    fb: &FramebufferInfo,
    px: i32,
    py: i32,
    s: &str,
    size: FontSize,
    fg: Rgb,
    bg: Option<Rgb>,
) -> u32 {
    let gw = font_width(size) as i32;
    let mut x = px;
    for ch in s.chars() {
        draw_char(fb, x, py, ch, size, fg, bg);
        x += gw;
    }
    s.len() as u32 * gw as u32
}

/// Draw text with extra letter-spacing (for "tracking-widest" labels).
pub fn draw_text_spaced(
    fb: &FramebufferInfo,
    px: i32,
    py: i32,
    s: &str,
    size: FontSize,
    spacing: i32,
    fg: Rgb,
    bg: Option<Rgb>,
) -> u32 {
    let gw = font_width(size) as i32 + spacing;
    let mut x = px;
    for ch in s.chars() {
        draw_char(fb, x, py, ch, size, fg, bg);
        x += gw;
    }
    s.len() as u32 * gw as u32
}

/// Pixel width of spaced text.
pub fn text_width_spaced(s: &str, size: FontSize, spacing: i32) -> u32 {
    s.len() as u32 * (font_width(size) as i32 + spacing) as u32
}

/// Draw text right-aligned ending at `rx + rw`.
pub fn draw_text_right(
    fb: &FramebufferInfo,
    rx: i32,
    ry: i32,
    rw: u32,
    s: &str,
    size: FontSize,
    fg: Rgb,
    bg: Option<Rgb>,
) {
    let tw = text_width(s, size);
    let x = rx + rw as i32 - tw as i32;
    draw_text(fb, x, ry, s, size, fg, bg);
}

/// Draw text centered horizontally within `[rx, rx+rw)`.
pub fn draw_text_centered(
    fb: &FramebufferInfo,
    rx: i32,
    ry: i32,
    rw: u32,
    s: &str,
    size: FontSize,
    fg: Rgb,
    bg: Option<Rgb>,
) {
    let tw = text_width(s, size);
    let x = rx + (rw as i32 - tw as i32) / 2;
    draw_text(fb, x, ry, s, size, fg, bg);
}
