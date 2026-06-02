//! Kinetic Command design system — palette and layout tokens.
//!
//! Ported from the "Ethereal Machine" design spec (DESIGN.md).
//! Hex values match the Tailwind config in the reference HTML.

use super::render::Rgb;

// ── Surface hierarchy (tonal layering — the "No-Line" rule) ─────────────

pub const BG: Rgb = Rgb::new(0x0c, 0x0e, 0x12); // #0c0e12  void
pub const SIDE: Rgb = Rgb::new(0x11, 0x13, 0x18); // #111318  sidebar
pub const CONTAINER: Rgb = Rgb::new(0x17, 0x1a, 0x1f); // #171a1f  content
pub const CONT_LOW: Rgb = Rgb::new(0x11, 0x13, 0x18); // #111318  recessed
pub const CONT_HIGH: Rgb = Rgb::new(0x1d, 0x20, 0x25); // #1d2025  elevated
pub const SURFACE_HI: Rgb = Rgb::new(0x23, 0x26, 0x2c); // #23262c  hover
pub const BRIGHT: Rgb = Rgb::new(0x29, 0x2c, 0x33); // #292c33  focus

// ── Accent colors ───────────────────────────────────────────────────────

pub const PRIMARY: Rgb = Rgb::new(0x8f, 0xf5, 0xff); // #8ff5ff  electric cyan
pub const PRIMARY_C: Rgb = Rgb::new(0x00, 0xee, 0xfc); // #00eefc  gradient end
pub const SECONDARY: Rgb = Rgb::new(0x00, 0xdc, 0xfc); // #00dcfc
pub const TERTIARY: Rgb = Rgb::new(0x65, 0xaf, 0xff); // #65afff  data blue
pub const ERROR: Rgb = Rgb::new(0xff, 0x71, 0x6c); // #ff716c

// ── Text ────────────────────────────────────────────────────────────────

pub const TEXT: Rgb = Rgb::new(0xf6, 0xf6, 0xfc); // #f6f6fc  NOT pure white
pub const TEXT_DIM: Rgb = Rgb::new(0xaa, 0xab, 0xb0); // #aaabb0  on-surface-variant
pub const OUTLINE: Rgb = Rgb::new(0x74, 0x75, 0x7a); // #74757a
pub const ON_PRIMARY: Rgb = Rgb::new(0x00, 0x5d, 0x63); // #005d63
pub const GHOST: Rgb = Rgb::new(0x46, 0x48, 0x4d); // #46484d  ghost border

// ── Back-compat aliases used by existing code ───────────────────────────

pub const ACCENT: Rgb = PRIMARY;
pub const ACCENT_DIM: Rgb = Rgb::new(0x00, 0x6a, 0x71);
pub const TEXT_SECONDARY: Rgb = TEXT_DIM;
pub const TEXT_ON_ACCENT: Rgb = Rgb::new(0xff, 0xff, 0xff);
pub const TEXT_DISABLED: Rgb = GHOST;
pub const TIMER: Rgb = PRIMARY;
pub const RED: Rgb = ERROR;
pub const GREEN: Rgb = Rgb::new(0x3f, 0xb9, 0x50); // #3FB950
pub const ORANGE: Rgb = Rgb::new(0xd2, 0x99, 0x22); // #D29922
pub const BORDER: Rgb = GHOST;
pub const BORDER_SEL: Rgb = PRIMARY;
pub const BAR_BG: Rgb = SIDE;
pub const BAR_TOP: Rgb = Rgb::new(0x14, 0x17, 0x1c);
pub const SURFACE_SEL: Rgb = Rgb::new(0x17, 0x22, 0x2c);

pub const BADGE_UEFI: Rgb = Rgb::new(0x00, 0x6a, 0x71);
pub const BADGE_LINUX: Rgb = Rgb::new(0x1a, 0x5e, 0x2a);
pub const BADGE_GRUB: Rgb = Rgb::new(0x6a, 0x40, 0x10);
pub const BADGE_PAYLOAD: Rgb = Rgb::new(0x40, 0x30, 0x6a);

pub const SB_ENABLED: Rgb = SECONDARY;
pub const SB_DISABLED: Rgb = ERROR;
pub const SB_SETUP: Rgb = ORANGE;

// ── Layout (pixels, 800×600) ────────────────────────────────────────────
//
// Proportions tuned for breathing room per the design spec:
// "Prioritize Breathing Room — spacing-10 and spacing-12 for section margins."

pub const SIDEBAR_W: u32 = 168;
pub const HEADER_H: u32 = 52;
pub const FOOTER_H: u32 = 28;
pub const PAD: u32 = 16;
pub const RADIUS: u32 = 6;
pub const GAP: u32 = 8;
pub const ACCENT_BAR: u32 = 3;

// ── Sidebar navigation ─────────────────────────────────────────────────

/// Height of each sidebar navigation item.
pub const NAV_ITEM_H: u32 = 36;
/// Vertical stride between sidebar items.
pub const NAV_ITEM_STRIDE: u32 = 4;
/// Vertical offset from sidebar top to first nav item.
pub const NAV_TOP_PAD: u32 = 48;

// ── Boot cards ──────────────────────────────────────────────────────────

pub const CARD_H: u32 = 68;
pub const CARD_GAP: u32 = GAP;
pub const CARD_PAD_X: u32 = 16;
pub const CARD_PAD_Y: u32 = 10;
pub const CARD_RADIUS: u32 = RADIUS;
pub const GLOW_SPREAD: u32 = 4;
pub const INDICATOR_W: u32 = ACCENT_BAR;

// ── Footer / progress ───────────────────────────────────────────────────

pub const PROGRESS_H: u32 = 4;
pub const PROGRESS_RADIUS: u32 = 2;

// Back-compat layout aliases
pub const MARGIN: u32 = PAD;
