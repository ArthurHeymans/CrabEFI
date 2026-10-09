//! Kinetic Command graphical UI.
//!
//! Implements the "Ethereal Machine" design system from the reference mockups:
//! left sidebar navigation, tonal surface hierarchy, electric-cyan accents,
//! hero cards, and a divider-free layout.  Multi-size anti-aliased Noto Sans
//! Mono font for modern typography hierarchy.

pub mod firmware_settings;
pub mod render;
#[cfg(feature = "secure-boot")]
pub mod secure_boot;
pub mod theme;

use crate::FramebufferConfig as FramebufferInfo;
use crate::cursor::CursorRenderer;
use crate::drivers::mouse_cursor;
use crate::menu::{BootCategory, BootMenu};
use crate::menu_common::{self, KeyPress};
use crate::time::{Timeout, delay_ms};
use render::{FontSize, Rgb};

// ═══════════════════════════════════════════════════════════════════════
//  Navigation types
// ═══════════════════════════════════════════════════════════════════════

/// Which nav item is active.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NavItem {
    Boot,
    #[cfg(feature = "secure-boot")]
    Security,
    Firmware,
}

/// Navigation result from any sub-screen.
pub enum ScreenNav {
    /// Go back (Esc or "Back" action).
    Back,
    /// Navigate to a different screen.
    Nav(NavItem),
}

/// Result from the boot selection screen.
enum BootResult {
    /// User selected a boot entry.
    Selected(usize),
    /// Navigate to a different screen.
    Nav(NavItem),
}

const NAV_ITEMS: &[(NavItem, &str)] = &[
    (NavItem::Boot, "BOOT"),
    #[cfg(feature = "secure-boot")]
    (NavItem::Security, "SECURITY"),
    (NavItem::Firmware, "FIRMWARE"),
];

fn nav_item_index(item: NavItem) -> usize {
    match item {
        NavItem::Boot => 0,
        #[cfg(feature = "secure-boot")]
        NavItem::Security => 1,
        NavItem::Firmware => 1 + cfg!(feature = "secure-boot") as usize,
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Shared chrome (sidebar, header, footer) — used by every screen
// ═══════════════════════════════════════════════════════════════════════

pub fn clear(fb: &FramebufferInfo) {
    unsafe { fb.clear(theme::BG.r, theme::BG.g, theme::BG.b) };
}

/// Draw the top header bar (branding + version).
pub fn draw_header(fb: &FramebufferInfo) {
    let w = fb.width;
    render::fill_gradient_v(
        fb,
        0,
        0,
        w,
        theme::HEADER_H,
        Rgb::new(0x14, 0x17, 0x1c),
        theme::BG,
    );

    let brand_y = (theme::HEADER_H as i32 - render::font_height(FontSize::Heading) as i32) / 2;
    render::draw_text(
        fb,
        14,
        brand_y,
        "CRABEFI",
        FontSize::Heading,
        theme::PRIMARY,
        None,
    );
    let vx = 14 + render::text_width("CRABEFI", FontSize::Heading) as i32 + 12;
    let vy = (theme::HEADER_H as i32 - render::font_height(FontSize::Small) as i32) / 2;
    render::draw_text(fb, vx, vy, "v0.1.0", FontSize::Small, theme::OUTLINE, None);
}

/// Draw the left sidebar with navigation items.
pub fn draw_sidebar(fb: &FramebufferInfo, active: NavItem, hovered: Option<NavItem>) {
    let sw = theme::SIDEBAR_W;
    let sy = theme::HEADER_H;
    let sh = fb.height - theme::HEADER_H - theme::FOOTER_H;

    render::fill_rect(fb, 0, sy as i32, sw, sh, theme::SIDE);

    // Title with letter-spacing
    let title_y = (sy + 14) as i32;
    render::draw_text_spaced(
        fb,
        14,
        title_y,
        "MAIN MENU",
        FontSize::Small,
        2,
        theme::TEXT,
        Some(theme::SIDE),
    );

    // Nav items
    for (i, (item, label)) in NAV_ITEMS.iter().enumerate() {
        paint_sidebar_item(fb, i, *item, label, active, hovered == Some(*item));
    }
}

fn paint_sidebar_item(
    fb: &FramebufferInfo,
    idx: usize,
    item: NavItem,
    label: &str,
    active: NavItem,
    is_hov: bool,
) {
    let y = sidebar_item_y(idx);
    let is_active = item == active;

    let bg = if is_active {
        theme::CONTAINER
    } else if is_hov {
        theme::CONT_HIGH
    } else {
        theme::SIDE
    };
    let fg = if is_active {
        theme::PRIMARY
    } else if is_hov {
        theme::TEXT
    } else {
        theme::TEXT_DIM
    };

    render::fill_rect(fb, 0, y, theme::SIDEBAR_W, theme::NAV_ITEM_H, bg);
    let text_y =
        y + ((theme::NAV_ITEM_H as i32 - render::font_height(FontSize::Normal) as i32) / 2);
    render::draw_text(fb, 16, text_y, label, FontSize::Normal, fg, Some(bg));

    // Active indicator — right-edge accent bar
    if is_active {
        render::fill_rect(
            fb,
            (theme::SIDEBAR_W - theme::ACCENT_BAR) as i32,
            y,
            theme::ACCENT_BAR,
            theme::NAV_ITEM_H,
            theme::PRIMARY,
        );
    }
}

/// Draw the bottom footer bar.
pub fn draw_footer(fb: &FramebufferInfo, hint: &str) {
    let w = fb.width;
    let fy = fb.height - theme::FOOTER_H;
    render::fill_rect(fb, 0, fy as i32, w, theme::FOOTER_H, theme::BG);
    let text_y =
        (fy as i32) + ((theme::FOOTER_H as i32 - render::font_height(FontSize::Small) as i32) / 2);
    render::draw_text_centered(
        fb,
        0,
        text_y,
        w,
        hint,
        FontSize::Small,
        theme::OUTLINE,
        None,
    );
}

pub fn poll_and_render_cursor(fb: &FramebufferInfo, cursor: &mut CursorRenderer) {
    mouse_cursor::poll();
    let (mx, my) = mouse_cursor::position();
    cursor.update(fb, mx, my);
}

/// Main canvas origin (x, y) and size (w, h) — right of sidebar, below header, above footer.
fn canvas(fb: &FramebufferInfo) -> (i32, i32, u32, u32) {
    let x = theme::SIDEBAR_W as i32 + theme::PAD as i32;
    let y = (theme::HEADER_H + theme::PAD) as i32;
    let w = fb.width - theme::SIDEBAR_W - theme::PAD * 2;
    let h = fb.height - theme::HEADER_H - theme::FOOTER_H - theme::PAD * 2;
    (x, y, w, h)
}

/// Y coordinate of the i-th sidebar nav item (0-indexed).
fn sidebar_item_y(i: usize) -> i32 {
    (theme::HEADER_H + theme::NAV_TOP_PAD) as i32
        + (i as i32 * (theme::NAV_ITEM_H + theme::NAV_ITEM_STRIDE) as i32)
}

/// Update sidebar hover state.  Repaints only the changed items.
/// Returns `true` if the hover state changed.
pub fn update_sidebar_hover(
    fb: &FramebufferInfo,
    cursor: &mut CursorRenderer,
    sidebar_hov: &mut Option<NavItem>,
    active: NavItem,
) -> bool {
    let new = sidebar_hit();
    if new == *sidebar_hov {
        return false;
    }
    let old = *sidebar_hov;
    *sidebar_hov = new;
    cursor.while_hidden(fb, || {
        if let Some(o) = old {
            let idx = nav_item_index(o);
            paint_sidebar_item(fb, idx, o, NAV_ITEMS[idx].1, active, false);
        }
        if let Some(n) = new {
            let idx = nav_item_index(n);
            paint_sidebar_item(fb, idx, n, NAV_ITEMS[idx].1, active, true);
        }
    });
    true
}

/// Hit-test sidebar: which nav item is the mouse over?
fn sidebar_hit() -> Option<NavItem> {
    let (mx, my) = mouse_cursor::position();
    if mx < 0 || mx >= theme::SIDEBAR_W as i32 {
        return None;
    }
    for (i, (item, _)) in NAV_ITEMS.iter().enumerate() {
        let iy = sidebar_item_y(i);
        if my >= iy && my < iy + theme::NAV_ITEM_H as i32 {
            return Some(*item);
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════
//  Public entry points (state machine for screen navigation)
// ═══════════════════════════════════════════════════════════════════════

pub fn show_graphical_menu(menu: &mut BootMenu) -> Option<usize> {
    let fb = crate::handoff::framebuffer()?;
    let mut screen = NavItem::Boot;

    loop {
        match screen {
            NavItem::Boot => match run_boot(&fb, menu) {
                BootResult::Selected(idx) => return Some(idx),
                BootResult::Nav(nav) => screen = nav,
            },
            #[cfg(feature = "secure-boot")]
            NavItem::Security => match secure_boot::show(&fb) {
                ScreenNav::Nav(nav) => screen = nav,
                ScreenNav::Back => screen = NavItem::Boot,
            },
            NavItem::Firmware => match firmware_settings::show(&fb) {
                ScreenNav::Nav(nav) => screen = nav,
                ScreenNav::Back => screen = NavItem::Boot,
            },
        }
    }
}

pub fn show_no_media_screen() {
    let fb = match crate::handoff::framebuffer() {
        Some(f) => f,
        None => return,
    };
    let mut screen = NavItem::Boot;

    loop {
        match screen {
            NavItem::Boot => match run_no_media(&fb) {
                ScreenNav::Nav(nav) => screen = nav,
                ScreenNav::Back => return,
            },
            #[cfg(feature = "secure-boot")]
            NavItem::Security => match secure_boot::show(&fb) {
                ScreenNav::Nav(nav) => screen = nav,
                ScreenNav::Back => screen = NavItem::Boot,
            },
            NavItem::Firmware => match firmware_settings::show(&fb) {
                ScreenNav::Nav(nav) => screen = nav,
                ScreenNav::Back => screen = NavItem::Boot,
            },
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Boot Selection screen
// ═══════════════════════════════════════════════════════════════════════

struct BState {
    sel: usize,
    hovered: Option<usize>,
    sidebar_hov: Option<NavItem>,
    scroll_offset: usize,
    countdown: u32,
    init_timeout: u32,
    tick: Timeout,
    count: usize,
}

impl BState {
    fn new(count: usize, sel: usize, timeout: u32) -> Self {
        Self {
            sel,
            hovered: None,
            sidebar_hov: None,
            scroll_offset: 0,
            countdown: timeout,
            init_timeout: timeout,
            tick: Timeout::from_ms(1000),
            count,
        }
    }
    fn sel_next(&mut self) {
        if self.count > 0 && self.sel < self.count - 1 {
            self.sel += 1;
        }
    }
    fn sel_prev(&mut self) {
        if self.sel > 0 {
            self.sel -= 1;
        }
    }
}

pub fn draw_scrollbar(
    fb: &FramebufferInfo,
    x: i32,
    y: i32,
    h: u32,
    total_items: usize,
    scroll_offset: usize,
    visible_items: usize,
) {
    if total_items <= visible_items || visible_items == 0 || h == 0 {
        return;
    }

    let track_w = 4;
    render::fill_rounded_rect(fb, x, y, track_w, h, 2, theme::SIDE);

    let thumb_h = ((h as usize * visible_items) / total_items)
        .max(24)
        .min(h as usize) as u32;
    let max_offset = total_items.saturating_sub(visible_items).max(1);
    let thumb_y = y + ((h - thumb_h) as usize * scroll_offset / max_offset) as i32;
    render::fill_rounded_rect(fb, x, thumb_y, track_w, thumb_h, 2, theme::PRIMARY);
}

fn run_boot(fb: &FramebufferInfo, menu: &mut BootMenu) -> BootResult {
    let mut cursor = CursorRenderer::new();
    let mut st = BState::new(menu.entry_count(), menu.selected, menu.timeout_seconds);
    keep_boot_selection_visible(fb, &mut st);

    paint_boot(fb, menu, &st);

    loop {
        poll_and_render_cursor(fb, &mut cursor);

        update_sidebar_hover(fb, &mut cursor, &mut st.sidebar_hov, NavItem::Boot);

        // ── Card hover ──
        let hov = boot_hit(fb, menu, &st);
        if hov != st.hovered {
            let prev = st.hovered;
            st.hovered = hov;
            cursor.while_hidden(fb, || {
                prev.into_iter()
                    .chain(hov)
                    .for_each(|i| paint_boot_card(fb, menu, &st, i));
                paint_boot_scrollbar(fb, menu, &st);
            });
        }

        if let Some(key) = menu_common::read_key() {
            if st.countdown > 0 {
                st.countdown = 0;
                cursor.while_hidden(fb, || paint_boot_footer(fb, &st));
            }

            match key {
                KeyPress::Up | KeyPress::Char('k') => {
                    let before = (st.sel, st.scroll_offset);
                    st.sel_prev();
                    select_boot(fb, menu, &mut st, &mut cursor, before);
                }
                KeyPress::Down | KeyPress::Char('j') => {
                    let before = (st.sel, st.scroll_offset);
                    st.sel_next();
                    select_boot(fb, menu, &mut st, &mut cursor, before);
                }
                KeyPress::Enter => {
                    cursor.hide(fb);
                    return BootResult::Selected(st.sel);
                }
                #[cfg(feature = "secure-boot")]
                KeyPress::Char('s') | KeyPress::Char('S') => {
                    cursor.hide(fb);
                    return BootResult::Nav(NavItem::Security);
                }
                KeyPress::Char('f') | KeyPress::Char('F') => {
                    cursor.hide(fb);
                    return BootResult::Nav(NavItem::Firmware);
                }
                KeyPress::Char('r') | KeyPress::Char('R') => {
                    crate::reset_system();
                }
                #[cfg(feature = "ui")]
                KeyPress::MouseClick { .. } => {
                    // Check sidebar clicks first
                    if let Some(nav) = st.sidebar_hov
                        && nav != NavItem::Boot
                    {
                        cursor.hide(fb);
                        return BootResult::Nav(nav);
                    }
                    // Then card clicks
                    if let Some(idx) = st.hovered {
                        if idx == st.sel {
                            cursor.hide(fb);
                            return BootResult::Selected(idx);
                        }
                        let before = (st.sel, st.scroll_offset);
                        st.sel = idx;
                        select_boot(fb, menu, &mut st, &mut cursor, before);
                    }
                }
                #[cfg(feature = "ui")]
                KeyPress::MouseScroll(dz) => {
                    let before = (st.sel, st.scroll_offset);
                    if dz > 0 {
                        st.sel_next();
                    } else {
                        st.sel_prev();
                    }
                    select_boot(fb, menu, &mut st, &mut cursor, before);
                }
                _ => {}
            }
        }

        if st.countdown > 0 && st.tick.is_expired() {
            st.countdown -= 1;
            st.tick = Timeout::from_ms(1000);
            cursor.while_hidden(fb, || paint_boot_footer(fb, &st));
            if st.countdown == 0 {
                cursor.hide(fb);
                return BootResult::Selected(st.sel);
            }
        }
        delay_ms(8);
    }
}

fn run_no_media(fb: &FramebufferInfo) -> ScreenNav {
    let mut cursor = CursorRenderer::new();
    let mut sidebar_hov: Option<NavItem> = None;

    clear(fb);
    draw_header(fb);
    draw_sidebar(fb, NavItem::Boot, None);

    let (cx, cy, cw, ch) = canvas(fb);

    // Section label
    let mut y = cy;
    render::draw_text_spaced(
        fb,
        cx,
        y,
        "PRIORITY SEQUENCE",
        FontSize::Small,
        3,
        theme::PRIMARY.darken(80),
        None,
    );
    y += render::font_height(FontSize::Small) as i32 + 4;
    render::draw_text(
        fb,
        cx,
        y,
        "Boot Selection",
        FontSize::Display,
        theme::TEXT,
        None,
    );

    let mid_y = cy + ch as i32 / 2 - 30;
    render::draw_dot(fb, cx + cw as i32 / 2, mid_y - 16, 6, theme::ERROR);
    render::draw_text_centered(
        fb,
        cx,
        mid_y + 4,
        cw,
        "No bootable media found",
        FontSize::Normal,
        theme::TEXT,
        None,
    );
    render::draw_text_centered(
        fb,
        cx,
        mid_y + 28,
        cw,
        "Connect a USB drive, then press R to restart",
        FontSize::Small,
        theme::TEXT_DIM,
        None,
    );
    render::draw_separator(fb, cx + 40, mid_y + 56, cw - 80, theme::GHOST, theme::BG);
    render::draw_text_centered(
        fb,
        cx,
        mid_y + 72,
        cw,
        "Mouse active -- move to test tracking",
        FontSize::Small,
        theme::OUTLINE,
        None,
    );

    draw_footer(
        fb,
        if cfg!(feature = "secure-boot") {
            "S: Security  F: Firmware  R: Reset  Esc: Halt"
        } else {
            "F: Firmware  R: Reset  Esc: Halt"
        },
    );

    loop {
        poll_and_render_cursor(fb, &mut cursor);

        update_sidebar_hover(fb, &mut cursor, &mut sidebar_hov, NavItem::Boot);

        if let Some(key) = menu_common::read_key() {
            match key {
                KeyPress::Char('r') | KeyPress::Char('R') => {
                    crate::reset_system();
                }
                #[cfg(feature = "secure-boot")]
                KeyPress::Char('s') | KeyPress::Char('S') => {
                    cursor.hide(fb);
                    return ScreenNav::Nav(NavItem::Security);
                }
                KeyPress::Char('f') | KeyPress::Char('F') => {
                    cursor.hide(fb);
                    return ScreenNav::Nav(NavItem::Firmware);
                }
                KeyPress::Escape => return ScreenNav::Back,
                #[cfg(feature = "ui")]
                KeyPress::MouseClick { .. } => {
                    if let Some(nav) = sidebar_hov
                        && nav != NavItem::Boot
                    {
                        cursor.hide(fb);
                        return ScreenNav::Nav(nav);
                    }
                }
                _ => {}
            }
        }
        delay_ms(8);
    }
}

// ── Boot internals ──────────────────────────────────────────────────────

fn boot_list_area(fb: &FramebufferInfo) -> (i32, i32, u32, u32) {
    let (cx, cy, cw, ch) = canvas(fb);
    let header_h =
        render::font_height(FontSize::Small) + 4 + render::font_height(FontSize::Display) + 12;
    let y = cy + header_h as i32;
    (cx, y, cw, ch.saturating_sub(header_h))
}

fn boot_visible_slots(fb: &FramebufferInfo) -> usize {
    let (_, _, _, h) = boot_list_area(fb);
    if h < theme::CARD_H {
        1
    } else {
        ((h + theme::GAP) / (theme::CARD_H + theme::GAP)).max(1) as usize
    }
}

fn keep_boot_selection_visible(fb: &FramebufferInfo, st: &mut BState) {
    let slots = boot_visible_slots(fb);
    if st.sel < st.scroll_offset {
        st.scroll_offset = st.sel;
    } else if st.sel >= st.scroll_offset + slots {
        st.scroll_offset = st.sel - slots + 1;
    }
}

fn card_rect(fb: &FramebufferInfo, st: &BState, idx: usize) -> Option<(i32, i32, u32, u32)> {
    if idx < st.scroll_offset || idx >= st.scroll_offset + boot_visible_slots(fb) {
        return None;
    }
    let (cx, list_y, cw, _) = boot_list_area(fb);
    let slot = idx - st.scroll_offset;
    let y = list_y + (slot as i32 * (theme::CARD_H + theme::GAP) as i32);
    Some((cx, y, cw, theme::CARD_H))
}

fn boot_hit(fb: &FramebufferInfo, menu: &BootMenu, st: &BState) -> Option<usize> {
    let (mx, my) = mouse_cursor::position();
    let end = (st.scroll_offset + boot_visible_slots(fb)).min(menu.entry_count());
    for i in st.scroll_offset..end {
        let Some((cx, cy, cw, ch)) = card_rect(fb, st, i) else {
            continue;
        };
        if mx >= cx && mx < cx + cw as i32 && my >= cy && my < cy + ch as i32 {
            return Some(i);
        }
    }
    None
}

fn paint_boot(fb: &FramebufferInfo, menu: &BootMenu, st: &BState) {
    clear(fb);
    draw_header(fb);
    draw_sidebar(fb, NavItem::Boot, st.sidebar_hov);

    let (cx, cy, _cw, _) = canvas(fb);

    // Section label with letter-spacing
    let mut y = cy;
    render::draw_text_spaced(
        fb,
        cx,
        y,
        "PRIORITY SEQUENCE",
        FontSize::Small,
        3,
        theme::PRIMARY.darken(80),
        None,
    );
    y += render::font_height(FontSize::Small) as i32 + 4;
    render::draw_text(
        fb,
        cx,
        y,
        "Boot Selection",
        FontSize::Display,
        theme::TEXT,
        None,
    );

    let end = (st.scroll_offset + boot_visible_slots(fb)).min(menu.entry_count());
    for i in st.scroll_offset..end {
        paint_boot_card(fb, menu, st, i);
    }

    paint_boot_scrollbar(fb, menu, st);

    paint_boot_footer(fb, st);
}

/// Repaint the boot list after `st.sel` changed from `before` (selection, scroll offset).
///
/// Only the two cards whose look changed are redrawn, or the visible cards when the list
/// scrolled; header, sidebar and footer are left alone.
fn select_boot(
    fb: &FramebufferInfo,
    menu: &mut BootMenu,
    st: &mut BState,
    cursor: &mut CursorRenderer,
    before: (usize, usize),
) {
    let (old_sel, old_scroll) = before;
    menu.selected = st.sel;
    keep_boot_selection_visible(fb, st);
    if (st.sel, st.scroll_offset) == before {
        return;
    }
    cursor.while_hidden(fb, || {
        if st.scroll_offset == old_scroll {
            [old_sel, st.sel]
                .into_iter()
                .for_each(|i| paint_boot_card(fb, menu, st, i));
        } else {
            let end = (st.scroll_offset + boot_visible_slots(fb)).min(menu.entry_count());
            (st.scroll_offset..end).for_each(|i| paint_boot_card(fb, menu, st, i));
        }
        paint_boot_scrollbar(fb, menu, st);
    });
}

fn paint_boot_scrollbar(fb: &FramebufferInfo, menu: &BootMenu, st: &BState) {
    let (list_x, list_y, list_w, list_h) = boot_list_area(fb);
    draw_scrollbar(
        fb,
        list_x + list_w as i32 - 4,
        list_y,
        list_h,
        menu.entry_count(),
        st.scroll_offset,
        boot_visible_slots(fb),
    );
}

fn paint_boot_card(fb: &FramebufferInfo, menu: &BootMenu, st: &BState, idx: usize) {
    let Some((cx, cy, cw, ch)) = card_rect(fb, st, idx) else {
        return;
    };
    let is_sel = idx == st.sel;
    let is_hov = st.hovered == Some(idx);

    // Background: tonal shift per design ("No-Line" rule)
    let bg = if is_sel {
        theme::SURFACE_HI
    } else if is_hov {
        theme::CONT_HIGH
    } else {
        theme::CONT_LOW
    };

    // Erase the glow ring around the card, including the corners of the card rect that the
    // rounded body does not cover.  The rest of the body is overpainted below, and leaving
    // it alone avoids flashing the card blank between repaints.
    let gm = theme::GLOW_SPREAD + 1;
    let (gx, gy) = (cx - gm as i32, cy - gm as i32);
    let full_w = cw + gm * 2;
    let (right, bottom) = (cx + cw as i32, cy + ch as i32);
    let r = theme::RADIUS;
    [
        (gx, gy, full_w, gm),
        (gx, bottom, full_w, gm),
        (gx, cy, gm, ch),
        (right, cy, gm, ch),
        (cx, cy, r, r),
        (right - r as i32, cy, r, r),
        (cx, bottom - r as i32, r, r),
        (right - r as i32, bottom - r as i32, r, r),
    ]
    .into_iter()
    .for_each(|(x, y, w, h)| render::fill_rect(fb, x, y, w, h, theme::BG));

    if is_sel {
        render::draw_glow(
            fb,
            cx,
            cy,
            cw,
            ch,
            theme::RADIUS,
            theme::GLOW_SPREAD,
            theme::PRIMARY.darken(180),
            theme::BG,
        );
    }

    render::fill_rounded_rect(fb, cx, cy, cw, ch, theme::RADIUS, bg);

    // Left accent bar for selected
    if is_sel {
        render::fill_rect(fb, cx, cy + 2, theme::ACCENT_BAR, ch - 4, theme::PRIMARY);
    }

    let Some(entry) = menu.entries.get(idx) else {
        return;
    };
    let tx = cx
        + theme::CARD_PAD_X as i32
        + if is_sel {
            theme::ACCENT_BAR as i32 + 4
        } else {
            0
        };
    let ty = cy + theme::CARD_PAD_Y as i32;

    // Entry name
    render::draw_text(
        fb,
        tx,
        ty,
        &entry.name,
        FontSize::Normal,
        theme::TEXT,
        Some(bg),
    );

    // Second row: badge + path
    let row2 = ty + render::font_height(FontSize::Normal) as i32 + 4;
    let (badge_label, badge_bg) = match entry.category {
        BootCategory::Uefi => ("UEFI", theme::BADGE_UEFI),
        BootCategory::Bls => ("LINUX", theme::BADGE_LINUX),
        BootCategory::Grub => ("GRUB", theme::BADGE_GRUB),
        BootCategory::Payload => ("PAYLOAD", theme::BADGE_PAYLOAD),
    };
    render::draw_pill(fb, tx, row2, badge_label, theme::TEXT, badge_bg);

    let info_x = tx + (render::text_width(badge_label, FontSize::Small) + 24) as i32;
    render::draw_text(
        fb,
        info_x,
        row2 + 3,
        &entry.path,
        FontSize::Small,
        theme::TEXT_DIM,
        Some(bg),
    );

    // Right side hint for selected
    if is_sel {
        let label = "SELECT >";
        let lw = render::text_width(label, FontSize::Small);
        render::draw_text(
            fb,
            cx + cw as i32 - lw as i32 - theme::PAD as i32,
            ty + 4,
            label,
            FontSize::Small,
            theme::PRIMARY,
            Some(bg),
        );
    }
}

fn paint_boot_footer(fb: &FramebufferInfo, st: &BState) {
    let w = fb.width;
    let fy = fb.height - theme::FOOTER_H;
    render::fill_rect(fb, 0, fy as i32, w, theme::FOOTER_H, theme::BG);

    if st.countdown > 0 && st.init_timeout > 0 {
        let bar_x = (theme::SIDEBAR_W + theme::PAD) as i32;
        let bar_w = w - theme::SIDEBAR_W - theme::PAD * 2 - 120;
        let frac = st.countdown as f32 / st.init_timeout as f32;
        let bar_y = fy as i32 + (theme::FOOTER_H as i32 - theme::PROGRESS_H as i32) / 2;
        render::draw_progress_bar(
            fb,
            bar_x,
            bar_y,
            bar_w,
            theme::PROGRESS_H,
            frac,
            theme::PRIMARY,
            theme::CONT_HIGH,
            theme::PROGRESS_RADIUS,
        );

        let mut buf = [0u8; 16];
        let s = fmt_cd(st.countdown, &mut buf);
        let text_y =
            fy as i32 + (theme::FOOTER_H as i32 - render::font_height(FontSize::Small) as i32) / 2;
        render::draw_text(
            fb,
            bar_x + bar_w as i32 + 12,
            text_y,
            s,
            FontSize::Small,
            theme::PRIMARY,
            None,
        );
    } else {
        draw_footer(
            fb,
            if cfg!(feature = "secure-boot") {
                "Up/Down Navigate  Enter Boot  S Security  F Firmware  R Reset"
            } else {
                "Up/Down Navigate  Enter Boot  F Firmware  R Reset"
            },
        );
    }
}

fn fmt_cd(secs: u32, buf: &mut [u8; 16]) -> &str {
    let mut p = 0;
    for &b in b"Boot " {
        buf[p] = b;
        p += 1;
    }
    p += fmt_u32(secs, &mut buf[p..]);
    buf[p] = b's';
    p += 1;
    core::str::from_utf8(&buf[..p]).unwrap_or("??")
}

/// Write decimal digits of `n` into `out`, returning the number of bytes written.
pub(super) fn fmt_u32(n: u32, out: &mut [u8]) -> usize {
    if n == 0 {
        out[0] = b'0';
        return 1;
    }
    // Find digit count (max 10 for u32)
    let mut digits = 0u32;
    let mut tmp = n;
    while tmp > 0 {
        digits += 1;
        tmp /= 10;
    }
    let len = digits as usize;
    let mut i = len;
    let mut v = n;
    while v > 0 {
        i -= 1;
        out[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::storage::StorageId;
    use crate::fs::gpt::Partition;
    use crate::menu::{BootCategory, BootEntry, BootEntryKind};
    use std::vec::Vec;

    const W: u32 = 1024;
    const H: u32 = 768;

    /// A 32bpp framebuffer backed by host memory.
    fn framebuffer(mem: &mut [u32]) -> FramebufferInfo {
        FramebufferInfo {
            physical_address: mem.as_mut_ptr() as u64,
            width: W,
            height: H,
            stride: W,
            bits_per_pixel: 32,
            red_mask_pos: 16,
            red_mask_size: 8,
            green_mask_pos: 8,
            green_mask_size: 8,
            blue_mask_pos: 0,
            blue_mask_size: 8,
        }
    }

    fn pixels(fb: &FramebufferInfo) -> Vec<u32> {
        // SAFETY: `fb` points at a live `W * H` buffer of u32.
        unsafe { core::slice::from_raw_parts(fb.as_ptr() as *const u32, (W * H) as usize) }.to_vec()
    }

    /// Assert equality, reporting the bounding box of the differing pixels instead of a dump.
    fn assert_same(got: &[u32], want: &[u32], sel: usize) {
        let diff: Vec<(u32, u32)> = got
            .iter()
            .zip(want)
            .enumerate()
            .filter(|(_, (g, w))| g != w)
            .map(|(i, _)| (i as u32 % W, i as u32 / W))
            .collect();
        let bbox = |f: fn(&(u32, u32)) -> u32| {
            (
                diff.iter().map(f).min().unwrap_or(0),
                diff.iter().map(f).max().unwrap_or(0),
            )
        };
        assert!(
            diff.is_empty(),
            "sel={sel}: {} pixels differ, x {:?} y {:?}",
            diff.len(),
            bbox(|p| p.0),
            bbox(|p| p.1)
        );
    }

    fn boot_menu(count: usize) -> BootMenu {
        let mut menu = BootMenu::new();
        (0..count).for_each(|i| {
            let mut name = heapless::String::<64>::new();
            let _ = core::fmt::write(&mut name, format_args!("Entry {i}"));
            menu.add_entry(BootEntry {
                name,
                path: heapless::String::new(),
                storage: StorageId::Nvme {
                    controller_id: 0,
                    nsid: 1,
                },
                pci: None,
                partition_num: 1,
                partition: Partition {
                    type_guid: [0; 16],
                    partition_guid: [0; 16],
                    first_lba: 0,
                    last_lba: 0,
                    attributes: 0,
                    is_esp: true,
                    block_size: 512,
                },
                kind: BootEntryKind::Uefi,
                category: BootCategory::Uefi,
            });
        });
        menu
    }

    /// Stepping through the boot list with partial repaints, with the mouse cursor sitting
    /// on top of the cards, must leave exactly the pixels of a full repaint and no cursor
    /// residue.
    #[test]
    fn boot_selection_repaint_matches_full_repaint() {
        const COUNT: usize = 12;
        let mut menu = boot_menu(COUNT);
        let mut inc_mem = std::vec![0u32; (W * H) as usize];
        let mut ref_mem = std::vec![0u32; (W * H) as usize];
        let (inc, full) = (framebuffer(&mut inc_mem), framebuffer(&mut ref_mem));

        let mut st = BState::new(COUNT, 0, 0);
        keep_boot_selection_visible(&inc, &mut st);
        paint_boot(&inc, &menu, &st);
        let mut cursor = CursorRenderer::new();
        let (cx, cy) = (300, 200);
        cursor.update(&inc, cx, cy);

        let scrolled = (0..COUNT - 1)
            .map(|_| {
                let before = (st.sel, st.scroll_offset);
                st.sel_next();
                select_boot(&inc, &mut menu, &mut st, &mut cursor, before);

                let mut expected = BState::new(COUNT, st.sel, 0);
                expected.scroll_offset = st.scroll_offset;
                paint_boot(&full, &menu, &expected);

                cursor.hide(&inc);
                assert_same(&pixels(&inc), &pixels(&full), st.sel);
                cursor.update(&inc, cx, cy);
                st.scroll_offset != before.1
            })
            .filter(|&scrolled| scrolled)
            .count();
        assert!(scrolled > 0, "test never exercised the scrolling path");
    }
}
