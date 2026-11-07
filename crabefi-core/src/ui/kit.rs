//! "Ledger" chrome: header with folder tabs, key legend, notice strips,
//! pane titles, fact sheets and modal frames. Solid fills and text only.

use super::{
    controls::{self, ButtonKind, Control, Role},
    dialog::{Rect, wrap_lines},
    layout::Metrics,
    render::{self, FontSize, Rgb},
    theme,
};
use crate::FramebufferConfig;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Warn,
    Ok,
    Bad,
}
impl Tone {
    /// (fill, border, headline)
    pub const fn colors(self) -> (Rgb, Rgb, Rgb) {
        match self {
            Tone::Neutral => (theme::SIDE, theme::RULE, theme::INK),
            Tone::Warn => (theme::WARN_TINT, theme::WARN_RULE, theme::WARN),
            Tone::Ok => (theme::SELECTED, theme::ACCENT, theme::ACCENT),
            Tone::Bad => (theme::BAD_TINT, theme::BAD, theme::BAD),
        }
    }
}

// ─── Brand ──────────────────────────────────────────────────────────────

const CRAB: [&[u8; 11]; 8] = [
    b"X.........X",
    b"XX.......XX",
    b".X.......X.",
    b"..XXXXXXX..",
    b"XXXXXXXXXXX",
    b"..XXXXXXX..",
    b".X.X...X.X.",
    b"X.........X",
];
pub fn crab(fb: &FramebufferConfig, x: i32, y: i32, px: u32) -> (u32, u32) {
    for (row, bits) in CRAB.iter().enumerate() {
        for (col, bit) in bits.iter().enumerate() {
            if *bit == b'X' {
                render::fill_rect(
                    fb,
                    x + (col as u32 * px) as i32,
                    y + (row as u32 * px) as i32,
                    px,
                    px,
                    theme::CRAB,
                );
            }
        }
    }
    (11 * px, 8 * px)
}

// ─── Header with folder tabs ────────────────────────────────────────────

fn brand_width(fb: &FramebufferConfig) -> u32 {
    let m = Metrics::for_fb(fb);
    11 * m.crab + m.pad / 2 + render::text_width("CrabEFI", m.big) + m.pad + m.pad / 2
}

/// Tab rectangles in header coordinates.
pub fn tab_rects(fb: &FramebufferConfig, labels: &[&str]) -> Vec<Rect> {
    let m = Metrics::for_fb(fb);
    let (cx, _, _, _) = m.canvas(fb);
    let mut x = cx + brand_width(fb) as i32;
    let pad = m.pad * 4 / 5;
    labels
        .iter()
        .map(|label| {
            // Reserve room for an unsaved marker so tabs never shift.
            let w =
                render::text_width(label, m.title) + render::text_width(" *", m.title) + pad * 2;
            let rect = (x, (m.header - m.tab) as i32, w, m.tab);
            x += w as i32 + 6;
            rect
        })
        .collect()
}

pub struct Tab<'a> {
    pub label: &'a str,
    pub active: bool,
    pub focused: bool,
    pub hovered: bool,
    pub dirty: bool,
}

pub fn draw_tabs(fb: &FramebufferConfig, tabs: &[Tab<'_>]) {
    let m = Metrics::for_fb(fb);
    let labels: Vec<&str> = tabs.iter().map(|t| t.label).collect();
    let pad = m.pad * 4 / 5;
    for (tab, rect) in tabs.iter().zip(tab_rects(fb, &labels)) {
        let (x, y, w, h) = rect;
        let bg = if tab.active {
            theme::SHEET
        } else if tab.hovered {
            theme::HOVER
        } else {
            theme::BAND
        };
        render::fill_rect(fb, x, y, w, h, bg);
        if tab.active {
            render::fill_rect(fb, x, y, w, 1, theme::RULE_STRONG);
            render::fill_rect(fb, x, y, 1, h, theme::RULE_STRONG);
            render::fill_rect(fb, x + w as i32 - 1, y, 1, h, theme::RULE_STRONG);
            render::fill_rect(fb, x, y, w, 3, theme::ACCENT);
        } else {
            render::fill_rect(fb, x, y + h as i32 - 1, w, 1, theme::RULE_STRONG);
        }
        if tab.focused {
            render::draw_thick_border(fb, x + 3, y + 5, w - 6, h - 8, 2, theme::INK);
        }
        let fg = if tab.active || tab.hovered {
            theme::INK
        } else {
            theme::INK2
        };
        let th = render::font_height(m.title);
        let ty = y + 2 + (h.saturating_sub(th + 2) / 2) as i32;
        let tx = x + pad as i32;
        let tw = render::draw_text_weight(fb, tx, ty, tab.label, m.title, tab.active, fg, Some(bg));
        // Mnemonic: the first letter is the page shortcut.
        render::fill_rect(
            fb,
            tx,
            ty + th as i32 - 2,
            render::font_width(m.title),
            2,
            fg,
        );
        if tab.dirty {
            render::draw_text_bold(fb, tx + tw as i32, ty, " *", m.title, theme::WARN, Some(bg));
        }
    }
}

/// Header band, brand and an optional status chip at the right.
/// The chip is omitted when it would collide with the tabs ending at `tabs_end`.
pub fn draw_header(fb: &FramebufferConfig, chip: Option<(&str, Rgb)>, tabs_end: i32) {
    let m = Metrics::for_fb(fb);
    let (cx, _, cw, _) = m.canvas(fb);
    render::fill_rect(fb, 0, 0, fb.width, m.header, theme::BAND);
    render::fill_rect(fb, 0, m.header as i32 - 1, fb.width, 1, theme::RULE_STRONG);
    let row_y = (m.header - m.tab) as i32;
    let crab_h = 8 * m.crab;
    let (cw_px, _) = crab(fb, cx, row_y + ((m.tab - crab_h) / 2) as i32, m.crab);
    let bh = render::font_height(m.big);
    render::draw_text_bold(
        fb,
        cx + (cw_px + m.pad / 2) as i32,
        row_y + (m.tab.saturating_sub(bh) / 2) as i32,
        "CrabEFI",
        m.big,
        theme::INK,
        Some(theme::BAND),
    );
    if let Some((label, dot)) = chip {
        let tw = render::text_width(label, m.body);
        let h = render::font_height(m.body) + 8;
        let w = tw + 34;
        let x = cx + cw as i32 - w as i32;
        let y = row_y + (m.tab.saturating_sub(h) / 2) as i32;
        if x < tabs_end + 12 {
            return;
        }
        render::fill_rect(fb, x, y, w, h, theme::SHEET);
        render::draw_border(fb, x, y, w, h, theme::RULE_STRONG);
        render::draw_dot(fb, x + 13, y + h as i32 / 2, 4, dot);
        render::draw_text(
            fb,
            x + 24,
            y + 4,
            label,
            m.body,
            theme::INK,
            Some(theme::SHEET),
        );
    }
}

// ─── Key legend ─────────────────────────────────────────────────────────

fn keys_width(fb: &FramebufferConfig, items: &[(&str, &str)]) -> u32 {
    let m = Metrics::for_fb(fb);
    let gap = m.pad * 3 / 4;
    items
        .iter()
        .map(|(keys, label)| {
            keys.split(' ')
                .map(|k| controls::keycap_width(fb, k) + 4)
                .sum::<u32>()
                + 4
                + render::text_width(label, m.small)
                + gap
        })
        .sum()
}
fn draw_key_items(fb: &FramebufferConfig, mut x: i32, y: i32, items: &[(&str, &str)]) {
    let m = Metrics::for_fb(fb);
    let gap = m.pad * 3 / 4;
    for (keys, label) in items {
        for k in keys.split(' ') {
            x += controls::keycap(fb, x, y, k, false) as i32 + 4;
        }
        x += 4;
        x += render::draw_text(fb, x, y + 2, label, m.small, theme::INK2, Some(theme::BAND)) as i32;
        x += gap as i32;
    }
}

/// Footer: local keys on the left, the fixed global group on the right.
pub fn draw_keys(fb: &FramebufferConfig, local: &[(&str, &str)], global: bool) {
    let m = Metrics::for_fb(fb);
    let y = fb.height.saturating_sub(m.footer) as i32;
    let (cx, _, cw, _) = m.canvas(fb);
    render::fill_rect(fb, 0, y, fb.width, m.footer, theme::BAND);
    render::fill_rect(fb, 0, y, fb.width, 1, theme::RULE_STRONG);
    let ky = y + ((m.footer - render::font_height(m.small) - 4) / 2) as i32;
    let full: &[(&str, &str)] = &[("B S F", "Pages"), ("F8", "Text size"), ("R", "Restart")];
    let short: &[(&str, &str)] = &[("B S F", "Pages"), ("R", "Restart")];
    let mut right: &[(&str, &str)] = if global { full } else { &[] };
    let mut left = local.len();
    loop {
        let need = keys_width(fb, &local[..left]) + keys_width(fb, right) + 24;
        if need <= cw || (left == 0 && right.is_empty()) {
            break;
        }
        if right.len() == 3 {
            right = short;
        } else if left > 0 {
            left -= 1;
        } else {
            right = &[];
        }
    }
    draw_key_items(fb, cx, ky, &local[..left]);
    if !right.is_empty() {
        let rw = keys_width(fb, right) - m.pad * 3 / 4;
        let rx = cx + cw as i32 - rw as i32;
        render::fill_rect(fb, rx - 14, y + 8, 1, m.footer - 16, theme::RULE_STRONG);
        draw_key_items(fb, rx, ky, right);
    }
}

// ─── Notice strip ───────────────────────────────────────────────────────

pub struct StripButton<'a> {
    pub label: &'a str,
    pub key: Option<&'a str>,
    pub kind: ButtonKind,
    pub focused: bool,
}

pub fn strip_height(fb: &FramebufferConfig) -> u32 {
    Metrics::for_fb(fb).row + 8
}

/// Full-width state line: bold headline, quieter detail, right-aligned
/// buttons and an optional progress rule. Returns the button rectangles.
#[allow(clippy::too_many_arguments)]
pub fn strip(
    fb: &FramebufferConfig,
    rect: Rect,
    tone: Tone,
    headline: &str,
    detail: &str,
    buttons: &[StripButton<'_>],
    progress: Option<(u32, u32)>,
) -> Vec<Rect> {
    let m = Metrics::for_fb(fb);
    let (x, y, w, h) = rect;
    let (bg, border, head) = tone.colors();
    render::fill_rect(fb, x, y, w, h, bg);
    render::draw_border(fb, x, y, w, h, border);
    let bh = m.button.min(h.saturating_sub(8));
    let mut rects = Vec::new();
    let mut bx = x + w as i32 - 8;
    for b in buttons.iter().rev() {
        let bw = controls::button_width(fb, b.label, b.key);
        bx -= bw as i32;
        rects.push((bx, y + ((h - bh) / 2) as i32, bw, bh));
        bx -= 12;
    }
    rects.reverse();
    let text_right = if buttons.is_empty() {
        x + w as i32 - 14
    } else {
        bx
    };
    let ty = y + (h.saturating_sub(render::font_height(m.body)) / 2) as i32;
    let avail = (text_right - x - 14).max(0) as u32;
    let headline = render::ellipsize(headline, avail, m.body);
    let hw = render::draw_text_bold(fb, x + 14, ty, &headline, m.body, head, Some(bg));
    let rest = avail.saturating_sub(hw + 14);
    if !detail.is_empty() && rest > render::font_width(m.body) * 4 {
        render::draw_text(
            fb,
            x + 14 + (hw + 14) as i32,
            ty,
            &render::ellipsize(detail, rest, m.body),
            m.body,
            theme::INK2,
            Some(bg),
        );
    }
    for (b, r) in buttons.iter().zip(&rects) {
        let mut c = Control::new(0, Role::Button, b.label);
        c.focused = b.focused;
        controls::button_with_key(fb, *r, &c, b.kind, b.key);
    }
    if let Some((done, total)) = progress
        && total > 0
    {
        let filled = (w as u64 * done.min(total) as u64 / total as u64) as u32;
        render::fill_rect(fb, x, y + h as i32 - 3, filled, 3, theme::WARN);
    }
    rects
}

// ─── Panes ──────────────────────────────────────────────────────────────

/// Bold pane title with a right-aligned note and a rule. Returns its height.
pub fn pane_title(
    fb: &FramebufferConfig,
    x: i32,
    y: i32,
    w: u32,
    title: &str,
    note: &str,
    strong: bool,
) -> u32 {
    let m = Metrics::for_fb(fb);
    let th = render::font_height(m.title);
    let nw = render::text_width(note, m.small).min(w / 2);
    render::draw_text_bold(
        fb,
        x + 2,
        y,
        &render::ellipsize(title, w.saturating_sub(nw + 16), m.title),
        m.title,
        theme::INK,
        None,
    );
    if !note.is_empty() {
        render::draw_text_right(
            fb,
            x,
            y + (th - render::font_height(m.small)) as i32,
            w - 2,
            &render::ellipsize(note, w / 2, m.small),
            m.small,
            theme::INK3,
            None,
        );
    }
    let ry = y + th as i32 + 6;
    render::fill_rect(
        fb,
        x,
        ry,
        w,
        2,
        if strong {
            theme::INK
        } else {
            theme::RULE_STRONG
        },
    );
    th + 8
}

/// Small column headings over a ledger table. Returns its height.
pub fn table_head(fb: &FramebufferConfig, x: i32, y: i32, w: u32, cols: &[(&str, i32)]) -> u32 {
    let m = Metrics::for_fb(fb);
    let h = render::font_height(m.small) + 12;
    for (label, dx) in cols {
        render::draw_text(fb, x + dx, y + 6, label, m.small, theme::INK3, None);
    }
    render::fill_rect(fb, x, y + h as i32 - 1, w, 1, theme::RULE);
    h
}

/// Details pane surface.
pub fn side(fb: &FramebufferConfig, rect: Rect) {
    render::fill_rect(fb, rect.0, rect.1, rect.2, rect.3, theme::SIDE);
    render::draw_border(fb, rect.0, rect.1, rect.2, rect.3, theme::RULE);
}

/// Small label above a bold title. Returns the next y.
pub fn caption_title(
    fb: &FramebufferConfig,
    x: i32,
    y: i32,
    w: u32,
    caption: &str,
    title: &str,
) -> i32 {
    let m = Metrics::for_fb(fb);
    render::draw_text(fb, x, y, caption, m.small, theme::INK3, None);
    let y = y + m.small_line as i32;
    let mut y = y;
    for line in wrap_lines(title, (w / render::font_width(m.title)) as usize)
        .iter()
        .take(2)
    {
        render::draw_text_bold(fb, x, y, line, m.title, theme::INK, None);
        y += render::font_height(m.title) as i32 + 2;
    }
    y + 6
}

/// Wrapped prose. Returns the next y. A clipped paragraph ends in "...".
#[allow(clippy::too_many_arguments)]
pub fn prose(
    fb: &FramebufferConfig,
    x: i32,
    y: i32,
    w: u32,
    text: &str,
    size: FontSize,
    color: Rgb,
    max_lines: usize,
) -> i32 {
    let m = Metrics::for_fb(fb);
    let advance = if size == m.small {
        m.small_line
    } else {
        m.line
    };
    let lines = wrap_lines(text, (w / render::font_width(size)).max(1) as usize);
    let mut y = y;
    for (i, line) in lines.iter().take(max_lines).enumerate() {
        let shown = if i + 1 == max_lines && lines.len() > max_lines {
            alloc::format!("{line}...")
        } else {
            line.clone()
        };
        render::draw_text(
            fb,
            x,
            y,
            &render::ellipsize(&shown, w, size),
            size,
            color,
            None,
        );
        y += advance as i32;
    }
    y
}

pub struct Fact<'a> {
    pub key: &'a str,
    pub value: &'a str,
    pub color: Rgb,
    pub bold: bool,
}
impl<'a> Fact<'a> {
    pub const fn new(key: &'a str, value: &'a str) -> Self {
        Self {
            key,
            value,
            color: theme::INK,
            bold: false,
        }
    }
    pub const fn strong(key: &'a str, value: &'a str, color: Rgb) -> Self {
        Self {
            key,
            value,
            color,
            bold: true,
        }
    }
}

/// Key/value fact sheet; values wrap under themselves. Returns the next y.
pub fn facts(fb: &FramebufferConfig, x: i32, y: i32, w: u32, rows: &[Fact<'_>], max_y: i32) -> i32 {
    let m = Metrics::for_fb(fb);
    let key_w = rows
        .iter()
        .map(|r| render::text_width(r.key, m.body))
        .max()
        .unwrap_or(0)
        .max(m.key_col.min(w / 3))
        + 12;
    let value_w = w.saturating_sub(key_w);
    let cols = (value_w / render::font_width(m.body)).max(1) as usize;
    let mut y = y;
    for row in rows {
        if y + m.line as i32 > max_y {
            break;
        }
        render::draw_text(fb, x, y, row.key, m.body, theme::INK3, None);
        for line in wrap_lines(row.value, cols).iter().take(5) {
            if y + m.line as i32 > max_y {
                break;
            }
            render::draw_text_weight(
                fb,
                x + key_w as i32,
                y,
                line,
                m.body,
                row.bold,
                row.color,
                None,
            );
            y += m.line as i32;
        }
        y += 4;
    }
    y
}

/// Vertical stack of full-width buttons. Returns their rectangles.
pub fn button_stack(
    fb: &FramebufferConfig,
    x: i32,
    y: i32,
    w: u32,
    buttons: &[StripButton<'_>],
) -> Vec<Rect> {
    let m = Metrics::for_fb(fb);
    let mut rects = Vec::new();
    let mut y = y;
    for b in buttons {
        let rect = (x, y, w, m.button);
        let mut c = Control::new(0, Role::Button, b.label);
        c.focused = b.focused;
        controls::button_with_key(fb, rect, &c, b.kind, b.key);
        rects.push(rect);
        y += m.button as i32 + 10;
    }
    rects
}

// ─── Modal frame ────────────────────────────────────────────────────────

/// Panel with a 2px ink border and a tinted title band. Returns the body rect.
pub fn modal_frame(fb: &FramebufferConfig, rect: Rect, tone: Tone, title: &str) -> Rect {
    let m = Metrics::for_fb(fb);
    let (x, y, w, h) = rect;
    render::fill_rect(fb, x, y, w, h, theme::SHEET);
    render::draw_thick_border(fb, x, y, w, h, 2, theme::INK);
    let head_h = m.row + 10;
    let (bg, border, fg) = match tone {
        Tone::Neutral => (theme::SIDE, theme::RULE_STRONG, theme::INK),
        tone => {
            let (bg, _, fg) = tone.colors();
            (bg, theme::RULE_STRONG, fg)
        }
    };
    render::fill_rect(fb, x + 2, y + 2, w - 4, head_h - 2, bg);
    render::fill_rect(fb, x + 2, y + head_h as i32, w - 4, 1, border);
    let th = render::font_height(m.title);
    let ty = y + ((head_h - th) / 2) as i32 + 1;
    render::draw_dot(fb, x + m.pad as i32 + 5, ty + th as i32 / 2, 5, fg);
    render::draw_text_bold(
        fb,
        x + m.pad as i32 + 20,
        ty,
        &render::ellipsize(title, w.saturating_sub(m.pad * 2 + 24), m.title),
        m.title,
        fg,
        Some(bg),
    );
    (
        x + m.pad as i32,
        y + head_h as i32 + m.gap as i32,
        w.saturating_sub(m.pad * 2),
        h.saturating_sub(head_h + m.gap + 2),
    )
}

pub fn modal_head_height(fb: &FramebufferConfig) -> u32 {
    Metrics::for_fb(fb).row + 10
}
