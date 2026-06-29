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

    hooks.show_firmware_settings();
    ScreenNav::Back
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
    draw_footer(fb, "S Security  F Firmware  R Reset  Esc Back");

    loop {
        poll_and_render_cursor(fb, &mut cursor);
        update_sidebar_hover(fb, &mut sidebar_hov, NavItem::Firmware);

        if let Some(key) = menu_common::read_key() {
            match key {
                KeyPress::Char('s') | KeyPress::Char('S') => {
                    cursor.hide(fb);
                    return ScreenNav::Nav(NavItem::Security);
                }
                KeyPress::Char('f') | KeyPress::Char('F') => {}
                KeyPress::Char('r') | KeyPress::Char('R') => {
                    crate::reset_system();
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
                }
                _ => {}
            }
        }
        delay_ms(8);
    }
}
