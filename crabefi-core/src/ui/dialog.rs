//! Shared, keyboard- and pointer-accessible dialogs. Escape never commits changes.

use super::{NavItem, canvas, clear, draw_footer, draw_header, draw_sidebar, render, theme};
use crate::FramebufferConfig;
use crate::cursor::CursorRenderer;
use crate::menu_common::{self, KeyPress};
use crate::time::delay_ms;
use alloc::string::String;
use render::FontSize;

pub type Rect = (i32, i32, u32, u32);

pub fn contains(rect: Rect, x: i32, y: i32) -> bool {
    x >= rect.0 && x < rect.0 + rect.2 as i32 && y >= rect.1 && y < rect.1 + rect.3 as i32
}

pub fn button(fb: &FramebufferConfig, rect: Rect, label: &str, focused: bool) {
    let (x, y, w, h) = rect;
    let bg = if focused {
        theme::PRIMARY
    } else {
        theme::CONT_HIGH
    };
    let fg = if focused {
        theme::ON_PRIMARY
    } else {
        theme::TEXT
    };
    render::fill_rounded_rect(fb, x, y, w, h, theme::RADIUS, bg);
    render::draw_text_centered(
        fb,
        x,
        y + (h - 16) as i32 / 2,
        w,
        label,
        FontSize::Small,
        fg,
        Some(bg),
    );
}

/// Dialog content is bounded to the canvas even on 640x480 displays.
fn surface(fb: &FramebufferConfig, nav: NavItem, title: &str, message: &str, extra: u32) -> Rect {
    clear(fb);
    draw_header(fb);
    draw_sidebar(fb, nav, None);
    draw_footer(fb, "Arrows / Tab Choose   Enter Confirm   Esc Cancel");
    let (cx, cy, cw, ch) = canvas(fb);
    let w = cw.min(600);
    let message_h =
        message_height(message, w.saturating_sub(40)).min(ch.saturating_sub(132 + extra));
    let h = (132 + message_h + extra).min(ch);
    let x = cx + (cw - w) as i32 / 2;
    let y = cy + (ch - h) as i32 / 2;
    render::fill_rounded_rect(fb, x, y, w, h, theme::RADIUS, theme::CONTAINER);
    render::draw_text(
        fb,
        x + 20,
        y + 16,
        &render::ellipsize(title, w.saturating_sub(40), FontSize::Heading),
        FontSize::Heading,
        theme::TEXT,
        None,
    );
    wrapped(
        fb,
        (x + 20, y + 58, w.saturating_sub(40), message_h),
        message,
        theme::TEXT_DIM,
    );
    (x, y, w, h)
}

fn message_height(message: &str, width: u32) -> u32 {
    wrap_lines(
        message,
        (width / render::font_width(FontSize::Small)) as usize,
    )
    .len()
    .max(1) as u32
        * 20
}

/// Word wrap without overflowing on long words or Unicode. Returns complete lines.
pub fn wrap_lines(text: &str, columns: usize) -> alloc::vec::Vec<String> {
    let columns = columns.max(1);
    let mut lines = alloc::vec::Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let word_len = word.chars().count();
        if !line.is_empty() && line.chars().count() + 1 + word_len > columns {
            lines.push(core::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        for ch in word.chars() {
            if line.chars().count() == columns {
                lines.push(core::mem::take(&mut line));
            }
            line.push(ch);
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

pub fn wrapped(fb: &FramebufferConfig, rect: Rect, text: &str, color: render::Rgb) {
    let (x, y, w, h) = rect;
    let line_h = render::font_height(FontSize::Small) + 4;
    let lines = wrap_lines(text, (w / render::font_width(FontSize::Small)) as usize);
    let slots = (h / line_h) as usize;
    for (i, line) in lines.iter().take(slots).enumerate() {
        let label = if i + 1 == slots && lines.len() > slots {
            render::ellipsize(&alloc::format!("{line} ..."), w, FontSize::Small)
        } else {
            render::ellipsize(line, w, FontSize::Small)
        };
        render::draw_text(
            fb,
            x,
            y + (i as u32 * line_h) as i32,
            &label,
            FontSize::Small,
            color,
            None,
        );
    }
}

/// Choice 0 must be the non-destructive default. Escape always returns 0.
pub fn choose(
    fb: &FramebufferConfig,
    nav: NavItem,
    title: &str,
    message: &str,
    labels: &[&str],
) -> usize {
    assert!(!labels.is_empty() && labels.len() <= 3);
    let mut cursor = CursorRenderer::new();
    let mut selected = 0;
    loop {
        cursor.hide(fb);
        let (x, y, w, h) = surface(fb, nav, title, message, 0);
        let bw = (w - 40 - (labels.len() as u32 - 1) * 8) / labels.len() as u32;
        let rects: alloc::vec::Vec<_> = labels
            .iter()
            .enumerate()
            .map(|(i, label)| {
                let rect = (
                    x + 20 + (i as u32 * (bw + 8)) as i32,
                    y + h as i32 - 58,
                    bw,
                    38,
                );
                button(fb, rect, label, i == selected);
                rect
            })
            .collect();
        loop {
            super::poll_and_render_cursor(fb, &mut cursor);
            if let Some(key) = menu_common::read_key() {
                match key {
                    KeyPress::Escape => {
                        cursor.hide(fb);
                        return 0;
                    }
                    KeyPress::Enter => {
                        cursor.hide(fb);
                        return selected;
                    }
                    KeyPress::Left | KeyPress::Up => {
                        selected = (selected + labels.len() - 1) % labels.len();
                        break;
                    }
                    KeyPress::Right | KeyPress::Down | KeyPress::Char('\t') => {
                        selected = (selected + 1) % labels.len();
                        break;
                    }
                    KeyPress::MouseClick { x, y } => {
                        if let Some(i) = rects.iter().position(|r| contains(*r, x as i32, y as i32))
                        {
                            cursor.hide(fb);
                            return i;
                        }
                    }
                    _ => {}
                }
            }
            delay_ms(8);
        }
    }
}

/// Choose from all enum values, with scrolling and no implicit change on Escape.
pub fn select(
    fb: &FramebufferConfig,
    title: &str,
    labels: &[&str],
    initial: usize,
) -> Option<usize> {
    if labels.is_empty() {
        return None;
    }
    let mut selected = initial.min(labels.len() - 1);
    let mut cursor = CursorRenderer::new();
    loop {
        cursor.hide(fb);
        clear(fb);
        draw_header(fb);
        draw_sidebar(fb, NavItem::Firmware, None);
        draw_footer(
            fb,
            "Pg/Home/End Choose   Enter / Click Apply draft   Esc Cancel",
        );
        let (x, y, w, h) = canvas(fb);
        render::draw_text(
            fb,
            x,
            y,
            &render::ellipsize(title, w, FontSize::Heading),
            FontSize::Heading,
            theme::TEXT,
            None,
        );
        render::draw_text(
            fb,
            x,
            y + 30,
            &render::ellipsize(
                &alloc::format!("Current: {}", labels[initial.min(labels.len() - 1)]),
                w,
                FontSize::Small,
            ),
            FontSize::Small,
            theme::TEXT_DIM,
            None,
        );
        let slots = (h.saturating_sub(110) / 44).max(1) as usize;
        let offset = selected.saturating_sub(slots - 1);
        for (i, label) in labels.iter().enumerate().skip(offset).take(slots) {
            button(
                fb,
                (
                    x,
                    y + 64 + ((i - offset) * 44) as i32,
                    w.saturating_sub(12),
                    36,
                ),
                &render::ellipsize(
                    &alloc::format!("{}{}", if i == initial { "[current] " } else { "" }, label),
                    w.saturating_sub(36),
                    FontSize::Small,
                ),
                i == selected,
            );
        }
        super::draw_scrollbar(
            fb,
            x + w as i32 - 4,
            y + 64,
            (slots * 44) as u32,
            labels.len(),
            offset,
            slots,
        );
        let cancel = (x, y + h as i32 - 38, w, 38);
        button(fb, cancel, "Cancel", false);
        loop {
            super::poll_and_render_cursor(fb, &mut cursor);
            if let Some(key) = menu_common::read_key() {
                match key {
                    KeyPress::Escape => {
                        cursor.hide(fb);
                        return None;
                    }
                    KeyPress::Enter => {
                        cursor.hide(fb);
                        return Some(selected);
                    }
                    KeyPress::Up => {
                        selected = selected.saturating_sub(1);
                        break;
                    }
                    KeyPress::Down => {
                        selected = (selected + 1).min(labels.len() - 1);
                        break;
                    }
                    key @ (KeyPress::Home
                    | KeyPress::End
                    | KeyPress::PageUp
                    | KeyPress::PageDown) => {
                        selected = super::page_selection(key, selected, labels.len(), slots)
                            .unwrap_or(selected);
                        break;
                    }
                    KeyPress::MouseScroll(dz) => {
                        selected = if dz > 0 {
                            (selected + 1).min(labels.len() - 1)
                        } else {
                            selected.saturating_sub(1)
                        };
                        break;
                    }
                    KeyPress::MouseClick { x: mx, y: my } => {
                        if contains(cancel, mx as i32, my as i32) {
                            cursor.hide(fb);
                            return None;
                        }
                        for i in offset..(offset + slots).min(labels.len()) {
                            if contains(
                                (
                                    x,
                                    y + 64 + ((i - offset) * 44) as i32,
                                    w.saturating_sub(12),
                                    36,
                                ),
                                mx as i32,
                                my as i32,
                            ) {
                                cursor.hide(fb);
                                return Some(i);
                            }
                        }
                    }
                    _ => {}
                }
            }
            delay_ms(8);
        }
    }
}

/// An append/backspace editor; validation errors keep the draft and dialog open.
pub fn input(
    fb: &FramebufferConfig,
    title: &str,
    hint: &str,
    initial: &str,
    validate: impl Fn(&str) -> Result<(), &'static str>,
) -> Option<String> {
    let mut value = String::from(initial);
    let mut error = None;
    let mut cursor = CursorRenderer::new();
    loop {
        cursor.hide(fb);
        let (x, y, w, h) = surface(fb, NavItem::Firmware, title, hint, 96);
        let hint_h = message_height(hint, w.saturating_sub(40)).min(h.saturating_sub(228));
        let field = (x + 20, y + 70 + hint_h as i32, w - 40, 36);
        render::fill_rounded_rect(fb, field.0, field.1, field.2, field.3, 4, theme::CONT_LOW);
        let columns = (field.2.saturating_sub(24) / render::font_width(FontSize::Normal)) as usize;
        let start = value
            .char_indices()
            .rev()
            .nth(columns.saturating_sub(2))
            .map_or(0, |(i, _)| i);
        let label = alloc::format!("{}{}|", if start > 0 { "~" } else { "" }, &value[start..]);
        render::draw_text(
            fb,
            field.0 + 8,
            field.1 + 8,
            &label,
            FontSize::Normal,
            theme::TEXT,
            None,
        );
        if let Some(msg) = error {
            wrapped(fb, (x + 20, field.1 + 44, w - 40, 40), msg, theme::ERROR);
        }
        let cancel = (x + 20, y + h as i32 - 58, (w - 48) / 2, 38);
        let apply = (x + 28 + cancel.2 as i32, cancel.1, cancel.2, 38);
        button(fb, cancel, "Cancel", false);
        button(fb, apply, "Apply draft", true);
        draw_footer(
            fb,
            "Type value   Backspace Delete   Ctrl+U Clear   Enter Apply   Esc Cancel",
        );
        loop {
            super::poll_and_render_cursor(fb, &mut cursor);
            if let Some(key) = menu_common::read_key() {
                let apply_value = match key {
                    KeyPress::Escape => {
                        cursor.hide(fb);
                        return None;
                    }
                    KeyPress::Enter => true,
                    KeyPress::MouseClick { x, y } => {
                        if contains(cancel, x as i32, y as i32) {
                            cursor.hide(fb);
                            return None;
                        }
                        contains(apply, x as i32, y as i32)
                    }
                    KeyPress::Char('\u{8}' | '\u{7f}') => {
                        value.pop();
                        error = None;
                        break;
                    }
                    KeyPress::Char('\u{15}') => {
                        value.clear();
                        error = None;
                        break;
                    }
                    KeyPress::Char(ch) if !ch.is_control() && ch.is_ascii() => {
                        if value.len() < 255 {
                            value.push(ch);
                            error = None;
                        } else {
                            error = Some("Maximum 255 bytes; delete text before adding more.");
                        }
                        break;
                    }
                    _ => false,
                };
                if apply_value {
                    match validate(&value) {
                        Ok(()) => {
                            cursor.hide(fb);
                            return Some(value);
                        }
                        Err(msg) => {
                            error = Some(msg);
                            break;
                        }
                    }
                }
            }
            delay_ms(8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_bounds_long_words_and_unicode() {
        let lines = wrap_lines("hello extraordinarilylong éééééé end", 5);
        assert!(lines.iter().all(|s| s.chars().count() <= 5));
        assert_eq!(
            lines.concat().replace(' ', ""),
            "helloextraordinarilylongééééééend"
        );
    }
}
