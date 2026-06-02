//! Graphical Firmware Settings screen — Kinetic Command design.

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
    let Some(hooks) = crate::state::drivers().platform.hooks else {
        return show_no_settings(fb);
    };

    if !hooks.firmware_settings_available() {
        return show_no_settings(fb);
    }

    let mut cursor = CursorRenderer::new();
    let mut sidebar_hov: Option<NavItem> = None;
    let mut hovered = false;

    draw_settings(fb, hovered);

    loop {
        poll_and_render_cursor(fb, &mut cursor);
        update_sidebar_hover(fb, &mut sidebar_hov, NavItem::Firmware);

        let new_hovered = card_hit(fb);
        if new_hovered != hovered {
            hovered = new_hovered;
            draw_settings(fb, hovered);
        }

        if let Some(key) = menu_common::read_key() {
            match key {
                KeyPress::Enter => {
                    cursor.hide(fb);
                    hooks.show_firmware_settings();
                    draw_settings(fb, hovered);
                }
                KeyPress::Escape | KeyPress::Char('q') | KeyPress::Char('Q') => {
                    return ScreenNav::Back;
                }
                #[cfg(feature = "ui")]
                KeyPress::MouseClick { .. } => {
                    if let Some(nav) = sidebar_hov
                        && nav != NavItem::Firmware
                    {
                        cursor.hide(fb);
                        return ScreenNav::Nav(nav);
                    }
                    if hovered {
                        cursor.hide(fb);
                        hooks.show_firmware_settings();
                        draw_settings(fb, hovered);
                    }
                }
                _ => {}
            }
        }
        delay_ms(8);
    }
}

const CARD_H: u32 = 72;

fn card_base_y(fb: &FramebufferInfo) -> i32 {
    let (_, cy, _, _) = canvas(fb);
    let header_h =
        render::font_height(FontSize::Small) + 4 + render::font_height(FontSize::Display) + 16;
    cy + header_h as i32
}

fn card_hit(fb: &FramebufferInfo) -> bool {
    let (mx, my) = crate::drivers::mouse_cursor::position();
    let (cx, _, cw, _) = canvas(fb);
    let y = card_base_y(fb);
    mx >= cx && mx < cx + cw as i32 && my >= y && my < y + CARD_H as i32
}

fn draw_settings(fb: &FramebufferInfo, hovered: bool) {
    clear(fb);
    draw_header(fb);
    draw_sidebar(fb, NavItem::Firmware, None);
    draw_footer(fb, "Enter Open   Esc Back");

    let (cx, cy, cw, _) = canvas(fb);
    let mut y = cy;

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

    let card_y = card_base_y(fb);
    let bg = if hovered {
        theme::CONT_HIGH
    } else {
        theme::SURFACE_HI
    };
    render::fill_rounded_rect(fb, cx, card_y, cw, CARD_H, theme::RADIUS, bg);
    render::fill_rect(
        fb,
        cx,
        card_y + 2,
        theme::ACCENT_BAR,
        CARD_H - 4,
        theme::PRIMARY,
    );

    let tx = cx + theme::PAD as i32 + theme::ACCENT_BAR as i32 + 4;
    render::draw_text(
        fb,
        tx,
        card_y + 8,
        "Platform firmware settings",
        FontSize::Normal,
        theme::TEXT,
        Some(bg),
    );
    render::draw_text(
        fb,
        tx,
        card_y + 8 + render::font_height(FontSize::Normal) as i32 + 4,
        "Open the platform-provided setup interface",
        FontSize::Small,
        theme::TEXT_DIM,
        Some(bg),
    );
    render::draw_text(
        fb,
        cx + cw as i32 - 28,
        card_y + (CARD_H as i32 - render::font_height(FontSize::Normal) as i32) / 2,
        ">",
        FontSize::Normal,
        theme::PRIMARY,
        Some(bg),
    );
}

fn show_no_settings(fb: &FramebufferInfo) -> ScreenNav {
    let mut cursor = CursorRenderer::new();
    let mut sidebar_hov: Option<NavItem> = None;

    clear(fb);
    draw_header(fb);
    draw_sidebar(fb, NavItem::Firmware, None);

    let (cx, cy, cw, ch) = canvas(fb);
    let mid = cy + ch as i32 / 2 - 20;
    render::draw_text_centered(
        fb,
        cx,
        mid,
        cw,
        "No firmware settings available",
        FontSize::Normal,
        theme::TEXT_DIM,
        None,
    );
    draw_footer(fb, "Esc Back");

    loop {
        poll_and_render_cursor(fb, &mut cursor);
        update_sidebar_hover(fb, &mut sidebar_hov, NavItem::Firmware);

        if let Some(key) = menu_common::read_key() {
            match key {
                KeyPress::Escape | KeyPress::Char('q') | KeyPress::Char('Q') => {
                    return ScreenNav::Back;
                }
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
