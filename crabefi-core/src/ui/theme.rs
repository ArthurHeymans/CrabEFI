//! Native setup palette. Focus, selection and actions are distinct contracts.
//! Required text and control boundaries must remain readable without color.

use super::render::Rgb;

pub const BG: Rgb = Rgb::new(0x10, 0x15, 0x1d);
pub const SIDE: Rgb = Rgb::new(0x17, 0x1f, 0x2a);
pub const CONTAINER: Rgb = Rgb::new(0x1b, 0x24, 0x30);
pub const CONT_LOW: Rgb = Rgb::new(0x14, 0x1b, 0x25);
pub const CONT_HIGH: Rgb = Rgb::new(0x23, 0x30, 0x40);
pub const SURFACE_HI: Rgb = Rgb::new(0x27, 0x35, 0x47);
pub const BRIGHT: Rgb = SURFACE_HI;
pub const PRIMARY: Rgb = Rgb::new(0xa1, 0xd7, 0xc5);
pub const PRIMARY_C: Rgb = PRIMARY;
pub const SECONDARY: Rgb = PRIMARY;
pub const TERTIARY: Rgb = Rgb::new(0xb1, 0xcb, 0xf2);
pub const ERROR: Rgb = Rgb::new(0xff, 0x94, 0x8d);
pub const TEXT: Rgb = Rgb::new(0xf1, 0xf5, 0xf9);
pub const TEXT_DIM: Rgb = Rgb::new(0xb5, 0xc0, 0xcc);
pub const OUTLINE: Rgb = Rgb::new(0xa3, 0xaf, 0xbe);
pub const ON_PRIMARY: Rgb = Rgb::new(0x0c, 0x26, 0x20);
pub const GHOST: Rgb = Rgb::new(0x67, 0x78, 0x8e);
pub const ACCENT: Rgb = PRIMARY;
pub const ACCENT_DIM: Rgb = Rgb::new(0x2c, 0x53, 0x48);
pub const TEXT_SECONDARY: Rgb = TEXT_DIM;
pub const TEXT_ON_ACCENT: Rgb = ON_PRIMARY;
pub const TEXT_DISABLED: Rgb = TEXT_DIM;
pub const TIMER: Rgb = PRIMARY;
pub const RED: Rgb = ERROR;
pub const GREEN: Rgb = PRIMARY;
pub const ORANGE: Rgb = Rgb::new(0xec, 0xc2, 0x8b);
pub const BORDER: Rgb = GHOST;
pub const BORDER_SEL: Rgb = TEXT;
pub const BAR_BG: Rgb = SIDE;
pub const BAR_TOP: Rgb = SIDE;
pub const SURFACE_SEL: Rgb = SURFACE_HI;
pub const BADGE_UEFI: Rgb = ACCENT_DIM;
pub const BADGE_LINUX: Rgb = ACCENT_DIM;
pub const BADGE_GRUB: Rgb = ACCENT_DIM;
pub const BADGE_PAYLOAD: Rgb = ACCENT_DIM;
pub const SB_ENABLED: Rgb = PRIMARY;
pub const SB_DISABLED: Rgb = ERROR;
pub const SB_SETUP: Rgb = ORANGE;

// Compatibility geometry for external render helpers. Screens use layout::Metrics.
pub const SIDEBAR_W: u32 = 0;
pub const HEADER_H: u32 = 92;
pub const FOOTER_H: u32 = 28;
pub const PAD: u32 = 16;
pub const RADIUS: u32 = 3;
pub const GAP: u32 = 6;
pub const ACCENT_BAR: u32 = 3;
pub const NAV_ITEM_H: u32 = 40;
pub const NAV_ITEM_STRIDE: u32 = 8;
pub const NAV_TOP_PAD: u32 = 40;
pub const CARD_H: u32 = 56;
pub const CARD_GAP: u32 = GAP;
pub const CARD_PAD_X: u32 = 16;
pub const CARD_PAD_Y: u32 = 8;
pub const CARD_RADIUS: u32 = RADIUS;
pub const GLOW_SPREAD: u32 = 0;
pub const INDICATOR_W: u32 = ACCENT_BAR;
pub const PROGRESS_H: u32 = 4;
pub const PROGRESS_RADIUS: u32 = 0;
pub const MARGIN: u32 = PAD;
