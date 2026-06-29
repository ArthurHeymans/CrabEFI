//! Graphical Secure Boot screen — Kinetic Command design.

use super::{
    NavItem, ScreenNav, canvas, clear, draw_footer, draw_header, draw_scrollbar, draw_sidebar,
    poll_and_render_cursor, render, theme, update_sidebar_hover,
};
use crate::FramebufferConfig as FramebufferInfo;
use crate::cursor::CursorRenderer;
use crate::menu_common::{self, KeyPress};
use crate::time::delay_ms;
use render::FontSize;

const ACTION_COUNT: usize = 6;
/// Index of the "Back to Boot Menu" action (last item).
const ACTION_BACK: usize = ACTION_COUNT - 1;

pub fn show(fb: &FramebufferInfo) -> ScreenNav {
    let mut cursor = CursorRenderer::new();
    let mut selected: usize = 0;
    let mut hovered: Option<usize> = None;
    let mut sidebar_hov: Option<NavItem> = None;
    let mut scroll_offset: usize = 0;
    let mut status: Option<(&str, bool)> = None;

    draw_screen(fb, selected, hovered, sidebar_hov, scroll_offset, status);

    loop {
        poll_and_render_cursor(fb, &mut cursor);

        update_sidebar_hover(fb, &mut sidebar_hov, NavItem::Security);

        // ── Card hover ──
        let new_hov = action_hit(fb, scroll_offset);
        if new_hov != hovered {
            hovered = new_hov;
            draw_screen(fb, selected, hovered, sidebar_hov, scroll_offset, status);
        }

        if let Some(key) = menu_common::read_key() {
            status = None;
            match key {
                KeyPress::Up | KeyPress::Char('k') => {
                    selected = selected.saturating_sub(1);
                    keep_action_visible(fb, selected, &mut scroll_offset);
                    draw_screen(fb, selected, hovered, sidebar_hov, scroll_offset, status);
                }
                KeyPress::Down | KeyPress::Char('j') => {
                    if selected < ACTION_COUNT - 1 {
                        selected += 1;
                    }
                    keep_action_visible(fb, selected, &mut scroll_offset);
                    draw_screen(fb, selected, hovered, sidebar_hov, scroll_offset, status);
                }
                KeyPress::Char('s') | KeyPress::Char('S') => {}
                KeyPress::Char('f') | KeyPress::Char('F') => {
                    cursor.hide(fb);
                    return ScreenNav::Nav(NavItem::Firmware);
                }
                KeyPress::Char('r') | KeyPress::Char('R') => {
                    crate::reset_system();
                }
                KeyPress::Escape | KeyPress::Char('q') | KeyPress::Char('Q') => {
                    return ScreenNav::Back;
                }
                KeyPress::Enter => {
                    status = handle_action(selected);
                    if selected == ACTION_BACK {
                        return ScreenNav::Back;
                    }
                    draw_screen(fb, selected, hovered, sidebar_hov, scroll_offset, status);
                }
                #[cfg(feature = "ui")]
                KeyPress::MouseClick { .. } => {
                    // Sidebar click
                    if let Some(nav) = sidebar_hov
                        && nav != NavItem::Security
                    {
                        cursor.hide(fb);
                        return ScreenNav::Nav(nav);
                    }
                    // Card click
                    if let Some(idx) = hovered {
                        if idx == selected {
                            status = handle_action(selected);
                            if selected == ACTION_BACK {
                                return ScreenNav::Back;
                            }
                        } else {
                            selected = idx;
                            keep_action_visible(fb, selected, &mut scroll_offset);
                        }
                        draw_screen(fb, selected, hovered, sidebar_hov, scroll_offset, status);
                    }
                }
                #[cfg(feature = "ui")]
                KeyPress::MouseScroll(dz) => {
                    if dz > 0 && selected < ACTION_COUNT - 1 {
                        selected += 1;
                    } else if dz < 0 && selected > 0 {
                        selected -= 1;
                    }
                    keep_action_visible(fb, selected, &mut scroll_offset);
                    draw_screen(fb, selected, hovered, sidebar_hov, scroll_offset, status);
                }
                _ => {}
            }
        }
        delay_ms(8);
    }
}

fn handle_action(idx: usize) -> Option<(&'static str, bool)> {
    use crate::efi::auth;
    match idx {
        0 => {
            if auth::is_secure_boot_enabled() {
                auth::disable_secure_boot();
                Some(("Secure Boot disabled", true))
            } else {
                auth::enable_secure_boot();
                if auth::is_secure_boot_enabled() {
                    Some(("Secure Boot enabled", true))
                } else {
                    Some(("Cannot enable: no PK enrolled", false))
                }
            }
        }
        1 => match auth::enrollment::enroll_default_keys() {
            Ok(_) => Some(("Default keys enrolled", true)),
            Err(_) => Some(("Failed to enroll keys", false)),
        },
        4 => match auth::boot::clear_all_keys() {
            Ok(_) => Some(("All keys cleared", true)),
            Err(_) => Some(("Failed to clear keys", false)),
        },
        ACTION_BACK => None,
        _ => Some(("Not implemented", false)),
    }
}

/// Hit-test action cards.
fn action_hit(fb: &FramebufferInfo, scroll_offset: usize) -> Option<usize> {
    let (mx, my) = crate::drivers::mouse_cursor::position();
    let end = (scroll_offset + action_visible_slots(fb)).min(ACTION_COUNT);
    for i in scroll_offset..end {
        let Some((ax, ay, aw, ah)) = action_card_rect(fb, scroll_offset, i) else {
            continue;
        };
        if mx >= ax && mx < ax + aw as i32 && my >= ay && my < ay + ah as i32 {
            return Some(i);
        }
    }
    None
}

const ACTION_ITEMS: [(&str, &str); ACTION_COUNT] = [
    (
        "Toggle Secure Boot",
        "Enable or disable signature verification",
    ),
    (
        "Enroll Default Keys",
        "Install Microsoft UEFI CA certificates",
    ),
    ("Enroll Custom PK", "Load PK from EFI\\keys\\PK.cer on ESP"),
    ("Import dbx Update", "Load dbx revocation list from ESP"),
    ("Clear All Keys", "Remove all keys, return to Setup Mode"),
    ("Back to Boot Menu", "Return to boot entry selection"),
];

fn action_list_area(fb: &FramebufferInfo) -> (i32, i32, u32, u32) {
    let (cx, cy, cw, ch) = canvas(fb);
    // Section header + hero card + gap
    let hero_h = 56u32;
    let header_h =
        render::font_height(FontSize::Small) + 4 + render::font_height(FontSize::Display) + 16;
    let used_h = header_h + hero_h + 16;
    let base_y = cy + used_h as i32;
    (cx, base_y, cw, ch.saturating_sub(used_h))
}

fn action_visible_slots(fb: &FramebufferInfo) -> usize {
    let (_, _, _, h) = action_list_area(fb);
    let card_h = 44u32;
    if h < card_h {
        1
    } else {
        ((h + theme::GAP) / (card_h + theme::GAP)).max(1) as usize
    }
}

fn keep_action_visible(fb: &FramebufferInfo, selected: usize, scroll_offset: &mut usize) {
    let slots = action_visible_slots(fb);
    if selected < *scroll_offset {
        *scroll_offset = selected;
    } else if selected >= *scroll_offset + slots {
        *scroll_offset = selected - slots + 1;
    }
}

/// Rect for the i-th action card.
fn action_card_rect(
    fb: &FramebufferInfo,
    scroll_offset: usize,
    i: usize,
) -> Option<(i32, i32, u32, u32)> {
    if i < scroll_offset || i >= scroll_offset + action_visible_slots(fb) {
        return None;
    }
    let (cx, base_y, cw, _) = action_list_area(fb);
    let card_h = 44u32;
    let slot = i - scroll_offset;
    let y = base_y + (slot as i32 * (card_h as i32 + theme::GAP as i32));
    Some((cx, y, cw, card_h))
}

/// Repaint a single action card (avoids full-screen redraw on hover changes).
fn paint_action_card(
    fb: &FramebufferInfo,
    i: usize,
    selected: usize,
    hovered: Option<usize>,
    scroll_offset: usize,
) {
    let Some((cx, y, cw, card_h)) = action_card_rect(fb, scroll_offset, i) else {
        return;
    };
    let (title, desc) = ACTION_ITEMS[i];
    let is_sel = i == selected;
    let is_hov = hovered == Some(i) && !is_sel;

    let bg = if is_sel {
        theme::SURFACE_HI
    } else if is_hov {
        theme::CONT_HIGH
    } else {
        theme::CONTAINER
    };
    render::fill_rounded_rect(fb, cx, y, cw, card_h, theme::RADIUS, bg);

    if is_sel {
        render::fill_rect(fb, cx, y + 2, theme::ACCENT_BAR, card_h - 4, theme::PRIMARY);
    }

    let tx = cx
        + theme::PAD as i32
        + if is_sel {
            theme::ACCENT_BAR as i32 + 4
        } else {
            0
        };
    render::draw_text(
        fb,
        tx,
        y + 4,
        title,
        FontSize::Normal,
        theme::TEXT,
        Some(bg),
    );
    render::draw_text(
        fb,
        tx,
        y + 4 + render::font_height(FontSize::Normal) as i32 + 2,
        desc,
        FontSize::Small,
        theme::TEXT_DIM,
        Some(bg),
    );

    if is_sel {
        render::draw_text(
            fb,
            cx + cw as i32 - 28,
            y + 12,
            ">",
            FontSize::Normal,
            theme::PRIMARY,
            Some(bg),
        );
    }
}

fn draw_screen(
    fb: &FramebufferInfo,
    selected: usize,
    hovered: Option<usize>,
    sidebar_hov: Option<NavItem>,
    scroll_offset: usize,
    status: Option<(&str, bool)>,
) {
    clear(fb);
    draw_header(fb);
    draw_sidebar(fb, NavItem::Security, sidebar_hov);
    draw_footer(
        fb,
        "Up/Down Navigate  Enter Select  S Security  F Firmware  R Reset  Esc Back",
    );

    let (cx, cy, cw, _ch) = canvas(fb);
    let mut y = cy;

    // ── Section label ──
    render::draw_text_spaced(
        fb,
        cx,
        y,
        "SECURITY CONFIGURATION",
        FontSize::Small,
        2,
        theme::PRIMARY.darken(80),
        None,
    );
    y += render::font_height(FontSize::Small) as i32 + 4;
    render::draw_text(
        fb,
        cx,
        y,
        "Secure Boot",
        FontSize::Display,
        theme::TEXT,
        None,
    );
    y += render::font_height(FontSize::Display) as i32 + 16;

    // ── Hero state card ──
    let sb_on = crate::efi::auth::is_secure_boot_enabled();
    let setup_mode = crate::efi::auth::is_setup_mode();
    let enroll = crate::efi::auth::enrollment::get_enrollment_status();

    let state_h = 56u32;
    render::fill_rounded_rect(fb, cx, y, cw, state_h, theme::RADIUS, theme::CONT_LOW);

    let state_color = if sb_on {
        theme::SECONDARY
    } else {
        theme::ERROR
    };
    render::fill_rect(fb, cx, y, theme::ACCENT_BAR, state_h, state_color);

    let state_label = if sb_on { "ACTIVE" } else { "INACTIVE" };
    render::draw_text_spaced(
        fb,
        cx + 16,
        y + 6,
        "CURRENT STATE",
        FontSize::Small,
        1,
        theme::OUTLINE,
        Some(theme::CONT_LOW),
    );
    render::draw_text(
        fb,
        cx + 16,
        y + 6 + render::font_height(FontSize::Small) as i32 + 4,
        state_label,
        FontSize::Heading,
        state_color,
        Some(theme::CONT_LOW),
    );

    // Right side: mode + key summary
    let mode_label = if setup_mode {
        "SETUP MODE"
    } else {
        "USER MODE"
    };
    let mode_color = if setup_mode {
        theme::ORANGE
    } else {
        theme::GREEN
    };
    let right_x = cx + cw as i32 / 2;
    render::draw_text(
        fb,
        right_x,
        y + 6,
        mode_label,
        FontSize::Small,
        mode_color,
        Some(theme::CONT_LOW),
    );

    let mut kx = right_x;
    let ky = y + 6 + render::font_height(FontSize::Small) as i32 + 6;
    let keys: [(&str, usize); 4] = [
        ("PK", enroll.pk_count),
        ("KEK", enroll.kek_count),
        ("db", enroll.db_count),
        ("dbx", enroll.dbx_count),
    ];
    for (name, count) in &keys {
        let mut buf = [0u8; 16];
        let s = fmt_kc(name, *count as u32, &mut buf);
        let pbg = if *count > 0 {
            theme::ACCENT_DIM
        } else {
            theme::GHOST
        };
        render::draw_pill(fb, kx, ky, s, theme::TEXT, pbg);
        kx += (render::text_width(s, FontSize::Small) + 24) as i32;
    }

    let _ = y; // y was used to position hero card; action cards use action_card_rect()

    // ── Action cards ──
    let end = (scroll_offset + action_visible_slots(fb)).min(ACTION_COUNT);
    for i in scroll_offset..end {
        paint_action_card(fb, i, selected, hovered, scroll_offset);
    }

    let (list_x, list_y, list_w, list_h) = action_list_area(fb);
    draw_scrollbar(
        fb,
        list_x + list_w as i32 - 4,
        list_y,
        list_h,
        ACTION_COUNT,
        scroll_offset,
        action_visible_slots(fb),
    );

    // Status toast
    if let Some((msg, ok)) = status {
        let msg_y = fb.height as i32 - theme::FOOTER_H as i32 - 24;
        let color = if ok { theme::SECONDARY } else { theme::ERROR };
        render::draw_text_centered(fb, 0, msg_y, fb.width, msg, FontSize::Normal, color, None);
    }
}

fn fmt_kc<'a>(name: &str, count: u32, buf: &'a mut [u8; 16]) -> &'a str {
    let mut p = 0;
    for &b in name.as_bytes() {
        if p >= buf.len() - 6 {
            break; // leave room for ':' + digits
        }
        buf[p] = b;
        p += 1;
    }
    buf[p] = b':';
    p += 1;
    p += super::fmt_u32(count, &mut buf[p..]);
    core::str::from_utf8(&buf[..p]).unwrap_or("??")
}
