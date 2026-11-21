//! Modal focus scopes, structured trust review, anchored pickers and caret-aware
//! field editing. Escape never commits; every visible action is reachable in
//! both directions. Modals repaint the invoking screen with a dimmed solid
//! palette as their backdrop; popovers keep it at full strength.

mod content;
mod editor;
mod modal;
mod pagination;
mod picker;
mod review;

pub use content::{Block, Choice};
pub use editor::{EditEvent, Editor, input, input_with};
pub use modal::{choose, modal};
pub use pagination::{LineKind, ReviewLine, ReviewSection};
pub use picker::select;
pub use review::review;

use crate::Surface;
use crate::screens::layout::Metrics;
use crate::screens::render::Rgb;
use crate::screens::{controls, kit, render, theme};
use alloc::string::String;
use alloc::vec::Vec;

pub type Rect = (i32, i32, u32, u32);
/// Repaints the invoking screen (without cursor handling).
pub type Backdrop<'a> = &'a dyn Fn();

pub fn contains(rect: Rect, x: i32, y: i32) -> bool {
    x >= rect.0 && y >= rect.1 && x < rect.0 + rect.2 as i32 && y < rect.1 + rect.3 as i32
}

/// Paragraph boundaries are meaningful, including in machine-identity details.
pub fn wrap_lines(text: &str, columns: usize) -> Vec<String> {
    let columns = columns.max(1);
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut line = String::new();
        for word in paragraph.split_whitespace() {
            if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > columns {
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
        lines.push(line);
    }
    lines
}
/// Compatibility: wrapped small text clipped to `rect`.
pub fn wrapped(fb: &Surface, rect: Rect, text: &str, color: Rgb) {
    let m = Metrics::for_fb(fb);
    let lines = (rect.3 / m.small_line).max(1) as usize;
    kit::prose(fb, rect.0, rect.1, rect.2, text, m.small, color, lines);
}

fn modal_width(fb: &Surface, preferred: u32) -> u32 {
    let m = Metrics::for_fb(fb);
    fb.width.saturating_sub(m.pad * 2).min(preferred)
}
fn center_modal(fb: &Surface, w: u32, h: u32) -> Rect {
    let m = Metrics::for_fb(fb);
    let avail = fb.height.saturating_sub(m.header + m.footer);
    let h = h.min(avail.saturating_sub(16));
    (
        ((fb.width - w) / 2) as i32,
        (m.header + avail.saturating_sub(h) / 2) as i32,
        w,
        h,
    )
}

fn modal_backdrop(fb: &Surface, backdrop: Backdrop<'_>) {
    fb.dimmed(backdrop);
    // Platform backdrops need not use draw_shell, so they need not reset the
    // registry. Only the new modal surface may participate in hover tracking.
    controls::clear_buttons(fb);
}

fn modal_keys(fb: &Surface, esc: &str, extra: &[(&str, &str)]) {
    let mut keys: Vec<(&str, &str)> =
        alloc::vec![("Tab Left Right", "Move"), ("Enter", "Activate")];
    keys.extend_from_slice(extra);
    keys.push(("Esc", esc));
    kit::draw_keys(fb, &keys, false);
}

/// Below the anchor's value side, flipped above when there is no room.
fn popover_rect(fb: &Surface, anchor: Option<Rect>, w: u32, h: u32) -> Rect {
    let m = Metrics::for_fb(fb);
    let top_limit = m.header as i32 + 4;
    let bottom_limit = (fb.height - m.footer) as i32 - 4;
    let h = h.min((bottom_limit - top_limit) as u32);
    let Some((ax, ay, aw, ah)) = anchor else {
        let (x, y, w, h) = center_modal(fb, w, h);
        return (x, y, w, h);
    };
    let x = (ax + aw as i32 - w as i32).clamp(m.pad as i32, (fb.width - w - m.pad) as i32);
    let below = ay + ah as i32 - 1;
    let y = if below + h as i32 <= bottom_limit {
        below
    } else if ay + 1 - (h as i32) >= top_limit {
        ay + 1 - h as i32
    } else {
        bottom_limit - h as i32
    };
    (x, y, w, h)
}

fn popover_frame(fb: &Surface, rect: Rect, title: &str) -> i32 {
    let m = Metrics::for_fb(fb);
    let (x, y, w, h) = rect;
    render::fill_rect(fb, x, y, w, h, theme::SHEET);
    render::draw_thick_border(fb, x, y, w, h, 2, theme::INK);
    let th = m.small_line + 12;
    render::draw_text(
        fb,
        x + 12,
        y + 7,
        &render::ellipsize(title, w - 24, m.small),
        m.small,
        theme::INK3,
        None,
    );
    render::fill_rect(fb, x + 2, y + th as i32, w - 4, 1, theme::RULE);
    y + th as i32 + 1
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
        assert_eq!(wrap_lines("A\n\nB", 40), ["A", "", "B"]);
    }
}
