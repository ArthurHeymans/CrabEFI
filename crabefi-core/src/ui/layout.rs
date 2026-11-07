//! Shared physical geometry and typography. No display-DPI assumptions.
//!
//! Two typographic modes exist: compact (designed for 1024x768, e.g. a
//! ThinkPad X61) and large (1080p and up). F8 switches for the session.

use super::render::FontSize;
use crate::FramebufferConfig;
use core::sync::atomic::{AtomicU8, Ordering};

/// 0: resolution-aware default; 1: large; 2: compact. Session-only preference.
static TEXT_SIZE: AtomicU8 = AtomicU8::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metrics {
    pub large: bool,
    /// Labels, key legend, table headings.
    pub small: FontSize,
    /// Rows, values and prose.
    pub body: FontSize,
    /// Pane titles (drawn bold).
    pub title: FontSize,
    /// Brand and status headline (drawn bold).
    pub big: FontSize,
    /// Outer horizontal margin.
    pub pad: u32,
    /// Vertical rhythm between blocks.
    pub gap: u32,
    pub header: u32,
    pub tab: u32,
    pub footer: u32,
    pub row: u32,
    pub button: u32,
    /// Prose line advance for `body`.
    pub line: u32,
    /// Prose line advance for `small`.
    pub small_line: u32,
    /// Key column of label/value fact sheets.
    pub key_col: u32,
    /// Brand mark pixel size.
    pub crab: u32,
}

/// Canvas height the tallest fixed page needs in large metrics (Security:
/// title + six action rows + separators + action bar). Below it those rows
/// would spill over the bar and into the footer legend while staying
/// clickable, so a large request (F8) falls back to compact instead.
const LARGE_MIN_CANVAS_H: u32 = 372;

fn effective_large(requested: bool, fb: &FramebufferConfig) -> bool {
    requested && Metrics::new(true).canvas(fb).3 >= LARGE_MIN_CANVAS_H
}

impl Metrics {
    pub fn for_fb(fb: &FramebufferConfig) -> Self {
        let large = match TEXT_SIZE.load(Ordering::Relaxed) {
            1 => true,
            2 => false,
            _ => fb.height >= 900 && fb.width >= 1400,
        };
        Self::new(effective_large(large, fb))
    }

    pub const fn new(large: bool) -> Self {
        if large {
            Self {
                large,
                small: FontSize::Small,
                body: FontSize::Normal,
                title: FontSize::Heading,
                big: FontSize::Display,
                pad: 40,
                gap: 24,
                header: 64,
                tab: 48,
                footer: 44,
                row: 44,
                button: 44,
                line: 26,
                small_line: 20,
                key_col: 130,
                crab: 3,
            }
        } else {
            Self {
                large,
                small: FontSize::Small,
                body: FontSize::Normal,
                title: FontSize::Normal,
                big: FontSize::Heading,
                pad: 20,
                gap: 14,
                header: 48,
                tab: 38,
                footer: 34,
                row: 34,
                button: 36,
                line: 22,
                small_line: 18,
                key_col: 80,
                crab: 2,
            }
        }
    }

    /// Working area between header and key legend.
    pub fn canvas(self, fb: &FramebufferConfig) -> (i32, i32, u32, u32) {
        let w = fb.width.saturating_sub(self.pad * 2).min(1840);
        (
            (fb.width.saturating_sub(w) / 2) as i32,
            (self.header + self.gap) as i32,
            w,
            fb.height
                .saturating_sub(self.header + self.footer + self.gap * 2),
        )
    }

    /// Details pane width beside a list, or `None` when the list needs the room.
    pub fn side_width(self, canvas_w: u32) -> Option<u32> {
        if canvas_w < 860 {
            return None;
        }
        Some(if self.large {
            (canvas_w * 30 / 100).clamp(420, 640)
        } else {
            (canvas_w * 39 / 100).clamp(300, 420)
        })
    }

    /// Settings sections column.
    pub fn sections_width(self, canvas_w: u32) -> u32 {
        if self.large {
            320
        } else if canvas_w < 860 {
            160
        } else {
            190
        }
    }

    /// Settings help pane, or `None` on narrow screens.
    pub fn help_width(self, canvas_w: u32) -> Option<u32> {
        let help = if self.large {
            (canvas_w * 32 / 100).clamp(420, 640)
        } else {
            (canvas_w * 28 / 100).clamp(260, 340)
        };
        (canvas_w >= 860 && self.sections_width(canvas_w) + help + 300 <= canvas_w).then_some(help)
    }
}

pub fn toggle_text_size(fb: &FramebufferConfig) {
    let large = Metrics::for_fb(fb).large;
    TEXT_SIZE.store(if large { 2 } else { 1 }, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_typography_modes_fit_small_and_native_large_displays() {
        for (width, height) in [
            (640, 400),
            (640, 480),
            (800, 600),
            (1024, 768),
            (1280, 800),
            (1920, 1080),
        ] {
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
                assert!(x >= 0 && y >= 0);
                assert!(x as u32 + w <= width && y as u32 + h <= height - m.footer);
                assert!(h >= m.row * 4 + m.button);
                if let Some(side) = m.side_width(w) {
                    assert!(side + 300 <= w, "{width}x{height}");
                }
                if let Some(help) = m.help_width(w) {
                    assert!(m.sections_width(w) + help + 300 <= w, "{width}x{height}");
                }
            }
        }
    }

    #[test]
    fn large_falls_back_to_compact_when_the_display_cannot_hold_it() {
        let fb = |width, height| FramebufferConfig {
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
        assert!(!effective_large(true, &fb(640, 400)));
        assert!(!effective_large(true, &fb(640, 480)));
        assert!(effective_large(true, &fb(800, 600)));
        assert!(effective_large(true, &fb(1920, 1080)));
        assert!(!effective_large(false, &fb(1920, 1080)));
    }

    #[test]
    fn x61_is_compact_and_full_hd_is_large_by_default() {
        let fb = |width, height| FramebufferConfig {
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
        assert!(!Metrics::for_fb(&fb(1024, 768)).large);
        assert!(!Metrics::for_fb(&fb(1280, 800)).large);
        assert!(Metrics::for_fb(&fb(1920, 1080)).large);
        let m = Metrics::for_fb(&fb(1024, 768));
        let (_, _, w, _) = m.canvas(&fb(1024, 768));
        assert!(m.side_width(w).is_some() && m.help_width(w).is_some());
    }
}
