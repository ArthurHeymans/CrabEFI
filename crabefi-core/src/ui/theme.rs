//! "Ledger" palette: warm paper, ink text and one muted green action colour.
//! Focus, selection, unsaved drafts and danger each have a non-colour cue too
//! (outline, left bar plus bold, `*`, explicit wording).

use super::render::Rgb;
use core::sync::atomic::{AtomicBool, Ordering};

/// Window and header band behind the working sheet.
pub const PAPER: Rgb = Rgb::new(0xef, 0xea, 0xe0);
/// Main working surface.
pub const SHEET: Rgb = Rgb::new(0xfa, 0xf8, 0xf3);
/// Details panes and status cards.
pub const SIDE: Rgb = Rgb::new(0xf4, 0xf0, 0xe7);
/// Header and key-legend bands.
pub const BAND: Rgb = Rgb::new(0xe7, 0xe1, 0xd3);
/// Pointer hover on a list row.
pub const HOVER: Rgb = Rgb::new(0xf1, 0xed, 0xe4);
/// Hairline row separators.
pub const RULE: Rgb = Rgb::new(0xdb, 0xd3, 0xc3);
/// Control borders and inactive tab outlines (>= 3:1 against SHEET is not
/// required for decoration; interactive boundaries also carry text).
pub const RULE_STRONG: Rgb = Rgb::new(0xa8, 0x9d, 0x86);
/// Primary text.
pub const INK: Rgb = Rgb::new(0x23, 0x26, 0x2a);
/// Secondary text.
pub const INK2: Rgb = Rgb::new(0x4f, 0x4d, 0x47);
/// Labels and hints; still >= 4.5:1 on every light surface.
pub const INK3: Rgb = Rgb::new(0x63, 0x5f, 0x56);
/// The only filled-action colour.
pub const ACCENT: Rgb = Rgb::new(0x2d, 0x5b, 0x4c);
/// Primary button under the pointer.
pub const ACCENT_HOVER: Rgb = Rgb::new(0x24, 0x4a, 0x3e);
/// Selected row tint.
pub const SELECTED: Rgb = Rgb::new(0xdd, 0xe7, 0xde);
pub const ON_ACCENT: Rgb = Rgb::new(0xf7, 0xf4, 0xec);
pub const ON_ACCENT_DIM: Rgb = Rgb::new(0x9f, 0xbc, 0xb0);
/// Unsaved drafts, countdowns and weakening actions.
pub const WARN: Rgb = Rgb::new(0x7a, 0x50, 0x0f);
pub const WARN_TINT: Rgb = Rgb::new(0xf3, 0xe8, 0xcc);
pub const WARN_RULE: Rgb = Rgb::new(0xd9, 0xc0, 0x8a);
/// Destructive operations and failures.
pub const BAD: Rgb = Rgb::new(0x96, 0x30, 0x21);
pub const BAD_TINT: Rgb = Rgb::new(0xf4, 0xde, 0xd7);
/// Brand mark only.
pub const CRAB: Rgb = Rgb::new(0xb4, 0x5f, 0x3e);

// Compatibility aliases for platform integrations.
pub const BG: Rgb = SHEET;
pub const TEXT: Rgb = INK;
pub const TEXT_DIM: Rgb = INK2;
pub const PRIMARY: Rgb = ACCENT;
pub const ERROR: Rgb = BAD;
pub const GREEN: Rgb = ACCENT;
pub const ORANGE: Rgb = WARN;
pub const BORDER: Rgb = RULE_STRONG;

const DIM_TARGET: Rgb = Rgb::new(30, 32, 35);
const DIM_AMOUNT: u8 = 107; // ~42%
#[cfg(not(test))]
static DIM: AtomicBool = AtomicBool::new(false);
// Unit tests paint concurrently; firmware has one UI thread.
#[cfg(test)]
std::thread_local! {
    static DIM: AtomicBool = const { AtomicBool::new(false) };
}
#[cfg(not(test))]
fn dim_flag<R>(f: impl FnOnce(&AtomicBool) -> R) -> R {
    f(&DIM)
}
#[cfg(test)]
fn dim_flag<R>(f: impl FnOnce(&AtomicBool) -> R) -> R {
    DIM.with(f)
}

/// Colours are mapped here, at the primitive level. A modal backdrop is the
/// invoking screen repainted with a darker solid palette: no framebuffer
/// read-back or per-pixel blending is involved.
pub fn tone(c: Rgb) -> Rgb {
    if dim_flag(|d| d.load(Ordering::Relaxed)) {
        c.lerp(DIM_TARGET, DIM_AMOUNT)
    } else {
        c
    }
}

/// Whether painting currently targets a dimmed modal backdrop.
pub fn is_dimmed() -> bool {
    dim_flag(|d| d.load(Ordering::Relaxed))
}

/// Paint `f` with the dimmed palette.
pub fn dimmed<R>(f: impl FnOnce() -> R) -> R {
    let previous = dim_flag(|d| d.swap(true, Ordering::Relaxed));
    let result = f();
    dim_flag(|d| d.store(previous, Ordering::Relaxed));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn luminance(c: Rgb) -> f64 {
        let linear = |v: u8| {
            let x = f64::from(v) / 255.0;
            if x <= 0.04045 {
                x / 12.92
            } else {
                ((x + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * linear(c.r) + 0.7152 * linear(c.g) + 0.0722 * linear(c.b)
    }
    fn contrast(a: Rgb, b: Rgb) -> f64 {
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    #[test]
    fn text_and_state_pairs_have_readable_contrast() {
        for bg in [PAPER, SHEET, SIDE, BAND, HOVER, SELECTED] {
            assert!(contrast(INK, bg) >= 7.0, "INK on {bg:?}");
            assert!(contrast(INK2, bg) >= 4.5, "INK2 on {bg:?}");
            assert!(contrast(INK3, bg) >= 4.5, "INK3 on {bg:?}");
            assert!(contrast(ACCENT, bg) >= 4.5, "ACCENT on {bg:?}");
            assert!(contrast(BAD, bg) >= 4.5, "BAD on {bg:?}");
            assert!(contrast(WARN, bg) >= 4.5, "WARN on {bg:?}");
        }
        assert!(contrast(WARN, WARN_TINT) >= 4.5);
        assert!(contrast(INK2, WARN_TINT) >= 4.5);
        assert!(contrast(BAD, BAD_TINT) >= 4.5);
        assert!(contrast(ON_ACCENT, ACCENT) >= 4.5);
        // Focus outline and selection bar are distinguishable from surfaces.
        assert!(contrast(INK, SELECTED) >= 3.0);
        assert!(contrast(ACCENT, SELECTED) >= 3.0);
    }

    #[test]
    fn dimming_is_solid_scoped_and_restored() {
        assert_eq!(tone(SHEET), SHEET);
        let dim = dimmed(|| tone(SHEET));
        assert_ne!(dim, SHEET);
        assert!(luminance(dim) < luminance(SHEET));
        assert_eq!(tone(SHEET), SHEET);
    }
}
