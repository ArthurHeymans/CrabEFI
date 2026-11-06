//! Shared physical geometry and typography. No display-DPI assumptions.

use super::render::FontSize;
use crate::FramebufferConfig;
use core::sync::atomic::{AtomicU8, Ordering};

/// 0: resolution-aware default; 1: large; 2: compact. Session-only preference.
static TEXT_SIZE: AtomicU8 = AtomicU8::new(0);

#[derive(Clone, Copy, Debug)]
pub struct Metrics {
    pub small: FontSize,
    pub body: FontSize,
    pub title: FontSize,
    pub pad: u32,
    pub header: u32,
    pub footer: u32,
    pub row: u32,
    pub entry: u32,
    pub button: u32,
    pub line: u32,
}

impl Metrics {
    pub fn for_fb(fb: &FramebufferConfig) -> Self {
        let large = match TEXT_SIZE.load(Ordering::Relaxed) {
            1 => true,
            2 => false,
            _ => fb.height >= 900,
        };
        Self::new(large)
    }

    pub const fn new(large: bool) -> Self {
        if large {
            Self {
                small: FontSize::Normal,
                body: FontSize::Heading,
                title: FontSize::Display,
                pad: 20,
                header: 112,
                footer: 36,
                row: 52,
                entry: 64,
                button: 48,
                line: 26,
            }
        } else {
            Self {
                small: FontSize::Small,
                body: FontSize::Normal,
                title: FontSize::Heading,
                pad: 16,
                header: 92,
                footer: 28,
                row: 44,
                entry: 56,
                button: 40,
                line: 22,
            }
        }
    }

    pub fn canvas(self, fb: &FramebufferConfig) -> (i32, i32, u32, u32) {
        let w = fb.width.saturating_sub(self.pad * 2).min(1200);
        (
            (fb.width.saturating_sub(w) / 2) as i32,
            (self.header + self.pad) as i32,
            w,
            fb.height
                .saturating_sub(self.header + self.footer + self.pad * 2),
        )
    }
}

pub fn toggle_text_size(fb: &FramebufferConfig) {
    let large = Metrics::for_fb(fb).body == FontSize::Heading;
    TEXT_SIZE.store(if large { 2 } else { 1 }, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_typography_modes_fit_small_and_native_large_displays() {
        for (width, height) in [(640, 400), (640, 480), (800, 600), (1920, 1080)] {
            for large in [false, true] {
                let fb = FramebufferConfig {
                    physical_address: 0,
                    width,
                    height,
                    stride: width,
                    bits_per_pixel: 32,
                    red_mask_pos: 16,
                    red_mask_size: 8,
                    green_mask_pos: 8,
                    green_mask_size: 8,
                    blue_mask_pos: 0,
                    blue_mask_size: 8,
                };
                let m = Metrics::new(large);
                let (x, y, w, h) = m.canvas(&fb);
                assert!(x >= 0 && y >= 0 && w <= 1200);
                assert!(x as u32 + w <= width && y as u32 + h <= height - m.footer);
                assert!(h >= m.row + m.button + m.line * 2);
            }
        }
    }
}
