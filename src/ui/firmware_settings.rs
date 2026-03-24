//! Graphical Firmware Settings (CFR) screen — Kinetic Command design.

use super::{
    NavItem, ScreenNav, canvas, clear, draw_footer, draw_header, draw_sidebar,
    poll_and_render_cursor, render, theme, update_sidebar_hover,
};
use crate::FramebufferConfig as FramebufferInfo;
use crate::cursor::CursorRenderer;
use crate::menu_common::{self, KeyPress};
use crate::time::delay_ms;
use render::FontSize;

pub fn show(fb: &FramebufferInfo) -> ScreenNav {
    let cfr = match crate::coreboot::get_cfr() {
        Some(c) => c,
        None => return show_no_cfr(fb),
    };

    let mut cursor = CursorRenderer::new();
    let mut selected: usize = 0;
    let mut hovered: Option<usize> = None;
    let mut sidebar_hov: Option<NavItem> = None;
    let mut scroll: usize = 0;
    let form_count = cfr.forms.len();

    draw_settings(fb, cfr, selected, hovered, scroll);

    loop {
        poll_and_render_cursor(fb, &mut cursor);

        update_sidebar_hover(fb, &mut sidebar_hov, NavItem::Firmware);

        // ── Card hover ──
        let new_hov = form_hit(fb, cfr, scroll);
        if new_hov != hovered {
            let old = hovered;
            hovered = new_hov;
            // Repaint only the changed cards
            if let Some(i) = old {
                paint_form_card(fb, cfr, i, selected, hovered, scroll);
            }
            if let Some(i) = new_hov {
                paint_form_card(fb, cfr, i, selected, hovered, scroll);
            }
        }

        if let Some(key) = menu_common::read_key() {
            match key {
                KeyPress::Up | KeyPress::Char('k') => {
                    selected = selected.saturating_sub(1);
                    if selected < scroll {
                        scroll = selected;
                    }
                    draw_settings(fb, cfr, selected, hovered, scroll);
                }
                KeyPress::Down | KeyPress::Char('j') => {
                    if selected + 1 < form_count {
                        selected += 1;
                    }
                    let mv = max_vis(fb);
                    if selected >= scroll + mv {
                        scroll = selected - mv + 1;
                    }
                    draw_settings(fb, cfr, selected, hovered, scroll);
                }
                KeyPress::Enter => {
                    cursor.hide(fb);
                    crate::cfr_menu::show_cfr_menu();
                    draw_settings(fb, cfr, selected, hovered, scroll);
                }
                KeyPress::Escape | KeyPress::Char('q') | KeyPress::Char('Q') => {
                    return ScreenNav::Back;
                }
                #[cfg(feature = "ui")]
                KeyPress::MouseClick { .. } => {
                    // Sidebar click
                    if let Some(nav) = sidebar_hov
                        && nav != NavItem::Firmware
                    {
                        cursor.hide(fb);
                        return ScreenNav::Nav(nav);
                    }
                    // Card click
                    if let Some(idx) = hovered {
                        if idx == selected {
                            cursor.hide(fb);
                            crate::cfr_menu::show_cfr_menu();
                        } else {
                            selected = idx;
                        }
                        draw_settings(fb, cfr, selected, hovered, scroll);
                    }
                }
                #[cfg(feature = "ui")]
                KeyPress::MouseScroll(dz) => {
                    if dz > 0 && selected + 1 < form_count {
                        selected += 1;
                        let mv = max_vis(fb);
                        if selected >= scroll + mv {
                            scroll = selected - mv + 1;
                        }
                    } else if dz < 0 && selected > 0 {
                        selected -= 1;
                        if selected < scroll {
                            scroll = selected;
                        }
                    }
                    draw_settings(fb, cfr, selected, hovered, scroll);
                }
                _ => {}
            }
        }
        delay_ms(8);
    }
}

fn max_vis(fb: &FramebufferInfo) -> usize {
    let (_, _, _, ch) = canvas(fb);
    let header_h =
        render::font_height(FontSize::Small) + 4 + render::font_height(FontSize::Display) + 16;
    let avail = ch.saturating_sub(header_h);
    (avail / (FORM_CARD_H + theme::GAP)) as usize
}

const FORM_CARD_H: u32 = 48;

fn form_card_base_y(fb: &FramebufferInfo) -> i32 {
    let (_, cy, _, _) = canvas(fb);
    let header_h =
        render::font_height(FontSize::Small) + 4 + render::font_height(FontSize::Display) + 16;
    cy + header_h as i32
}

/// Repaint a single form card (avoids full-screen redraw on hover changes).
fn paint_form_card(
    fb: &FramebufferInfo,
    cfr: &crate::coreboot::CfrInfo,
    idx: usize,
    selected: usize,
    hovered: Option<usize>,
    scroll: usize,
) {
    let mv = max_vis(fb);
    // Only repaint if the card is currently visible
    if idx < scroll || idx >= scroll + mv || idx >= cfr.forms.len() {
        return;
    }
    let vi = idx - scroll;
    let (cx, _, cw, _) = canvas(fb);
    let base_y = form_card_base_y(fb);
    let y = base_y + (vi as i32 * (FORM_CARD_H as i32 + theme::GAP as i32));

    let form = &cfr.forms[idx];
    let is_sel = idx == selected;
    let is_hov = hovered == Some(idx) && !is_sel;

    let bg = if is_sel {
        theme::SURFACE_HI
    } else if is_hov {
        theme::CONT_HIGH
    } else {
        theme::CONT_LOW
    };
    render::fill_rounded_rect(fb, cx, y, cw, FORM_CARD_H, theme::RADIUS, bg);

    if is_sel {
        render::fill_rect(
            fb,
            cx,
            y + 2,
            theme::ACCENT_BAR,
            FORM_CARD_H - 4,
            theme::PRIMARY,
        );
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
        y + 6,
        &form.ui_name,
        FontSize::Normal,
        theme::TEXT,
        Some(bg),
    );

    let opt_count = form.options.len();
    let mut buf = [0u8; 16];
    let cs = fmt_opts(opt_count as u32, &mut buf);
    render::draw_text_right(
        fb,
        cx,
        y + 6,
        cw - theme::PAD,
        cs,
        FontSize::Small,
        theme::OUTLINE,
        Some(bg),
    );

    let desc = if opt_count == 1 { "1 setting" } else { cs };
    render::draw_text(
        fb,
        tx,
        y + 6 + render::font_height(FontSize::Normal) as i32 + 2,
        desc,
        FontSize::Small,
        theme::TEXT_DIM,
        Some(bg),
    );

    if is_sel {
        render::draw_text(
            fb,
            cx + cw as i32 - 28,
            y + (FORM_CARD_H as i32 - render::font_height(FontSize::Normal) as i32) / 2,
            ">",
            FontSize::Normal,
            theme::PRIMARY,
            Some(bg),
        );
    }
}

/// Hit-test form cards.
fn form_hit(fb: &FramebufferInfo, cfr: &crate::coreboot::CfrInfo, scroll: usize) -> Option<usize> {
    let (mx, my) = crate::drivers::mouse_cursor::position();
    let (cx, _, cw, _) = canvas(fb);
    let base_y = form_card_base_y(fb);
    let mv = max_vis(fb);

    for vi in 0..mv {
        let idx = scroll + vi;
        if idx >= cfr.forms.len() {
            break;
        }
        let card_y = base_y + (vi as i32 * (FORM_CARD_H as i32 + theme::GAP as i32));
        if mx >= cx && mx < cx + cw as i32 && my >= card_y && my < card_y + FORM_CARD_H as i32 {
            return Some(idx);
        }
    }
    None
}

fn draw_settings(
    fb: &FramebufferInfo,
    cfr: &crate::coreboot::CfrInfo,
    selected: usize,
    hovered: Option<usize>,
    scroll: usize,
) {
    clear(fb);
    draw_header(fb);
    draw_sidebar(fb, NavItem::Firmware, None);
    draw_footer(fb, "Up/Down Navigate   Enter Edit   Esc Back");

    let (cx, cy, cw, _) = canvas(fb);
    let mut y = cy;

    // Section label
    render::draw_text_spaced(
        fb,
        cx,
        y,
        "HARDWARE CONFIGURATION",
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
        "Firmware Settings",
        FontSize::Display,
        theme::TEXT,
        None,
    );
    let _ = y; // y was used to lay out the header; cards use form_card_base_y()

    let mv = max_vis(fb);
    for vi in 0..mv {
        let idx = scroll + vi;
        if idx >= cfr.forms.len() {
            break;
        }
        paint_form_card(fb, cfr, idx, selected, hovered, scroll);
    }

    // Scroll indicators
    let header_h =
        render::font_height(FontSize::Small) + 4 + render::font_height(FontSize::Display) + 16;
    if scroll > 0 {
        render::draw_text_centered(
            fb,
            cx,
            cy + header_h as i32 - 18,
            cw,
            "^",
            FontSize::Small,
            theme::PRIMARY,
            None,
        );
    }
    if scroll + mv < cfr.forms.len() {
        let ay = fb.height as i32 - theme::FOOTER_H as i32 - 20;
        render::draw_text_centered(fb, cx, ay, cw, "v", FontSize::Small, theme::PRIMARY, None);
    }
}

fn show_no_cfr(fb: &FramebufferInfo) -> ScreenNav {
    let mut cursor = CursorRenderer::new();
    let mut sidebar_hov: Option<NavItem> = None;

    clear(fb);
    draw_header(fb);
    draw_sidebar(fb, NavItem::Firmware, None);

    let (cx, cy, cw, ch) = canvas(fb);
    let mid = cy + ch as i32 / 2 - 20;
    render::draw_dot(fb, cx + cw as i32 / 2, mid - 12, 6, theme::ORANGE);
    render::draw_text_centered(
        fb,
        cx,
        mid + 6,
        cw,
        "No firmware configuration available",
        FontSize::Normal,
        theme::TEXT,
        None,
    );
    render::draw_text_centered(
        fb,
        cx,
        mid + 30,
        cw,
        "CFR tables not found in coreboot",
        FontSize::Small,
        theme::TEXT_DIM,
        None,
    );

    draw_footer(fb, "Esc: Back");

    loop {
        poll_and_render_cursor(fb, &mut cursor);

        update_sidebar_hover(fb, &mut sidebar_hov, NavItem::Firmware);

        if let Some(key) = menu_common::read_key() {
            match key {
                KeyPress::Escape | KeyPress::Char('q') => return ScreenNav::Back,
                #[cfg(feature = "ui")]
                KeyPress::MouseClick { .. } => {
                    if let Some(nav) = sidebar_hov
                        && nav != NavItem::Firmware
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

fn fmt_opts(n: u32, buf: &mut [u8; 16]) -> &str {
    let mut p = 0;
    p += super::fmt_u32(n, &mut buf[p..]);
    for &b in b" opts" {
        buf[p] = b;
        p += 1;
    }
    core::str::from_utf8(&buf[..p]).unwrap_or("??")
}
