//! Modal focus scopes, structured trust review, anchored pickers and caret-aware
//! field editing. Escape never commits; every visible action is reachable in
//! both directions. Modals repaint the invoking screen with a dimmed solid
//! palette as their backdrop; popovers keep it at full strength.

use super::{
    controls::{self, ButtonKind, Control, Role},
    kit::{self, Tone},
    layout::{self, Metrics},
    render::{self, Rgb},
    theme,
};
use crate::{
    FramebufferConfig,
    cursor::CursorRenderer,
    menu_common::{self, KeyPress},
    time::delay_ms,
};
use alloc::{string::String, vec::Vec};

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
pub fn wrapped(fb: &FramebufferConfig, rect: Rect, text: &str, color: Rgb) {
    let m = Metrics::for_fb(fb);
    let lines = (rect.3 / m.small_line).max(1) as usize;
    kit::prose(fb, rect.0, rect.1, rect.2, text, m.small, color, lines);
}

// ─── Modal content ──────────────────────────────────────────────────────

pub enum Block {
    Text(String),
    Muted(String),
    Fact {
        key: String,
        value: String,
        color: Rgb,
        bold: bool,
    },
    /// "name   from -> to", the new value emphasised as an unsaved draft.
    Change {
        name: String,
        from: String,
        to: String,
    },
}
impl Block {
    pub fn text(text: &str) -> Self {
        Self::Text(String::from(text))
    }
    pub fn muted(text: &str) -> Self {
        Self::Muted(String::from(text))
    }
    pub fn fact(key: &str, value: &str) -> Self {
        Self::Fact {
            key: String::from(key),
            value: String::from(value),
            color: theme::INK2,
            bold: false,
        }
    }
    pub fn strong_fact(key: &str, value: &str) -> Self {
        Self::Fact {
            key: String::from(key),
            value: String::from(value),
            color: theme::INK,
            bold: true,
        }
    }
    pub fn change(name: &str, from: &str, to: &str) -> Self {
        Self::Change {
            name: String::from(name),
            from: String::from(from),
            to: String::from(to),
        }
    }
}

pub struct Choice<'a> {
    pub label: &'a str,
    pub key: Option<&'a str>,
    pub kind: ButtonKind,
}
impl<'a> Choice<'a> {
    pub const fn new(label: &'a str, key: Option<&'a str>, kind: ButtonKind) -> Self {
        Self { label, key, kind }
    }
}

fn block_key_width(fb: &FramebufferConfig, blocks: &[Block]) -> u32 {
    let m = Metrics::for_fb(fb);
    blocks
        .iter()
        .filter_map(|b| match b {
            Block::Fact { key, .. } => Some(render::text_width(key, m.body)),
            Block::Change { name, .. } => Some(render::text_width(name, m.body)),
            _ => None,
        })
        .max()
        .map_or(0, |w| w + 16)
}

/// Lays out blocks, optionally painting. Returns the height used.
fn blocks(fb: &FramebufferConfig, x: i32, y: i32, w: u32, blocks: &[Block], paint: bool) -> u32 {
    let m = Metrics::for_fb(fb);
    let cols = (w / render::font_width(m.body)).max(1) as usize;
    let key_w = block_key_width(fb, blocks).min(w / 2);
    let value_cols = ((w - key_w) / render::font_width(m.body)).max(1) as usize;
    let mut cy = y;
    let mut previous_fact = false;
    for (i, block) in blocks.iter().enumerate() {
        let fact = matches!(block, Block::Fact { .. } | Block::Change { .. });
        if i > 0 && !(fact && previous_fact) {
            cy += (m.gap / 2) as i32;
        }
        previous_fact = fact;
        match block {
            Block::Text(text) | Block::Muted(text) => {
                let color = if matches!(block, Block::Text(_)) {
                    theme::INK
                } else {
                    theme::INK2
                };
                for line in wrap_lines(text, cols) {
                    if paint {
                        render::draw_text(fb, x, cy, &line, m.body, color, None);
                    }
                    cy += m.line as i32;
                }
            }
            Block::Fact {
                key,
                value,
                color,
                bold,
            } => {
                if paint {
                    render::draw_text_bold(fb, x, cy, key, m.body, theme::INK, None);
                }
                for line in wrap_lines(value, value_cols) {
                    if paint {
                        render::draw_text_weight(
                            fb,
                            x + key_w as i32,
                            cy,
                            &line,
                            m.body,
                            *bold,
                            *color,
                            None,
                        );
                    }
                    cy += m.line as i32;
                }
            }
            Block::Change { name, from, to } => {
                if paint {
                    render::draw_text(fb, x, cy, name, m.body, theme::INK, None);
                    let vx = x + key_w as i32;
                    let lead = alloc::format!("{from} -> ");
                    let lw = render::draw_text(
                        fb,
                        vx,
                        cy,
                        &render::ellipsize(&lead, w - key_w, m.body),
                        m.body,
                        theme::INK3,
                        None,
                    );
                    render::draw_text_bold(
                        fb,
                        vx + lw as i32,
                        cy,
                        &render::ellipsize(to, (w - key_w).saturating_sub(lw), m.body),
                        m.body,
                        theme::WARN,
                        None,
                    );
                }
                cy += m.line as i32;
            }
        }
    }
    (cy - y) as u32
}

fn modal_width(fb: &FramebufferConfig, preferred: u32) -> u32 {
    let m = Metrics::for_fb(fb);
    fb.width.saturating_sub(m.pad * 2).min(preferred)
}
fn center_modal(fb: &FramebufferConfig, w: u32, h: u32) -> Rect {
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

/// Right-aligned button row. Returns rectangles in choice order.
fn choice_row(
    fb: &FramebufferConfig,
    right: i32,
    y: i32,
    choices: &[Choice<'_>],
    focused: Option<usize>,
    enabled: &[bool],
) -> Vec<Rect> {
    let m = Metrics::for_fb(fb);
    let widths: Vec<u32> = choices
        .iter()
        .map(|c| controls::button_width(fb, c.label, c.key).max(if m.large { 180 } else { 140 }))
        .collect();
    let total: u32 = widths.iter().sum::<u32>() + 12 * widths.len().saturating_sub(1) as u32;
    let mut x = right - total as i32;
    let mut rects = Vec::new();
    for (i, (choice, w)) in choices.iter().zip(&widths).enumerate() {
        let rect = (x, y, *w, m.button);
        let mut c = Control::new(i as u64, Role::Button, choice.label);
        c.focused = focused == Some(i);
        c.enabled = enabled.get(i).copied().unwrap_or(true);
        controls::button_with_key(fb, rect, &c, choice.kind, choice.key);
        rects.push(rect);
        x += *w as i32 + 12;
    }
    rects
}

fn modal_keys(fb: &FramebufferConfig, esc: &str, extra: &[(&str, &str)]) {
    let mut keys: Vec<(&str, &str)> =
        alloc::vec![("Tab Left Right", "Move"), ("Enter", "Activate")];
    keys.extend_from_slice(extra);
    keys.push(("Esc", esc));
    kit::draw_keys(fb, &keys, false);
}

/// Focus starts on, and Escape returns, choice 0: callers put the safe
/// option first.
pub fn modal(
    fb: &FramebufferConfig,
    backdrop: Backdrop<'_>,
    tone: Tone,
    title: &str,
    content: &[Block],
    choices: &[Choice<'_>],
) -> usize {
    assert!(!choices.is_empty() && choices.len() <= 3);
    let mut cursor = CursorRenderer::new();
    let mut focused = 0usize;
    loop {
        cursor.hide(fb);
        let m = Metrics::for_fb(fb);
        let w = modal_width(fb, if m.large { 820 } else { 720 });
        let inner = w - m.pad * 2;
        let body_h = blocks(fb, 0, 0, inner, content, false);
        let h = kit::modal_head_height(fb) + m.gap * 3 + body_h + m.button + 4;
        let rect = center_modal(fb, w, h);
        theme::dimmed(backdrop);
        let body = kit::modal_frame(fb, rect, tone, title);
        blocks(fb, body.0, body.1, body.2, content, true);
        let by = rect.1 + rect.3 as i32 - m.button as i32 - m.gap as i32;
        let rects = choice_row(fb, body.0 + body.2 as i32, by, choices, Some(focused), &[]);
        modal_keys(fb, choices[0].label, &[]);
        let mut hover = super::Hover::default();
        loop {
            super::poll_and_render_cursor(fb, &mut cursor);
            super::track_hover(fb, &mut cursor, &mut hover, None);
            if let Some(key) = menu_common::read_key() {
                let activation = match key {
                    KeyPress::Escape => {
                        cursor.hide(fb);
                        return 0;
                    }
                    KeyPress::F8 => {
                        layout::toggle_text_size(fb);
                        break;
                    }
                    KeyPress::Tab | KeyPress::Right | KeyPress::Down => {
                        focused = (focused + 1) % choices.len();
                        break;
                    }
                    KeyPress::BackTab | KeyPress::Left | KeyPress::Up => {
                        focused = (focused + choices.len() - 1) % choices.len();
                        break;
                    }
                    KeyPress::Enter | KeyPress::Char(' ') => Some(focused),
                    KeyPress::MouseClick { x, y } => {
                        rects.iter().position(|r| contains(*r, x as i32, y as i32))
                    }
                    _ => None,
                };
                if let Some(i) = activation {
                    cursor.hide(fb);
                    return i;
                }
            }
            delay_ms(8);
        }
    }
}

fn choice_kind(label: &str, index: usize) -> ButtonKind {
    if index == 0 {
        ButtonKind::Neutral
    } else if matches!(
        label,
        "Discard" | "Clear keys" | "Clear all keys" | "Disable"
    ) {
        ButtonKind::Danger
    } else if matches!(label, "Enroll" | "Import") {
        ButtonKind::Accent
    } else {
        ButtonKind::Primary
    }
}

/// Compatibility choice API: one paragraph, safe choice first.
pub fn choose(
    fb: &FramebufferConfig,
    backdrop: Backdrop<'_>,
    title: &str,
    message: &str,
    labels: &[&str],
) -> usize {
    let choices: Vec<Choice<'_>> = labels
        .iter()
        .enumerate()
        .map(|(i, l)| Choice::new(l, (i == 0).then_some("Esc"), choice_kind(l, i)))
        .collect();
    let content: Vec<Block> = message.split("\n\n").map(Block::text).collect();
    modal(fb, backdrop, Tone::Neutral, title, &content, &choices)
}

// ─── Trust review ───────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineKind {
    Body,
    /// "SHA-256 <hex groups>", prefix drawn quieter.
    Fingerprint,
    Note,
    Warn,
}
pub struct ReviewLine {
    pub kind: LineKind,
    pub text: String,
}
/// One identity or fact group; always shown whole, never split across pages.
pub struct ReviewSection {
    pub label: String,
    pub lines: Vec<ReviewLine>,
}
impl ReviewSection {
    pub fn new(label: &str, text: &str) -> Self {
        Self {
            label: String::from(label),
            lines: alloc::vec![ReviewLine {
                kind: LineKind::Body,
                text: String::from(text),
            }],
        }
    }
    pub fn labelled(label: &str) -> Self {
        Self {
            label: String::from(label),
            lines: Vec::new(),
        }
    }
    pub fn line(mut self, kind: LineKind, text: &str) -> Self {
        self.lines.push(ReviewLine {
            kind,
            text: String::from(text),
        });
        self
    }
    /// Text of the section, for tests and serial logs.
    pub fn text(&self) -> String {
        let mut s = String::new();
        for line in &self.lines {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(&line.text);
        }
        s
    }
}

fn section_label_width(fb: &FramebufferConfig, sections: &[ReviewSection]) -> u32 {
    let m = Metrics::for_fb(fb);
    sections
        .iter()
        .map(|s| render::text_width(&s.label, m.body))
        .max()
        .unwrap_or(0)
        .max(if m.large { 70 } else { 40 })
        + 14
}

/// Lays out one section, optionally painting. Returns its height.
fn review_section(
    fb: &FramebufferConfig,
    x: i32,
    y: i32,
    w: u32,
    label_w: u32,
    section: &ReviewSection,
    paint: bool,
) -> u32 {
    let m = Metrics::for_fb(fb);
    let tx = x + label_w as i32;
    let tw = w.saturating_sub(label_w);
    if paint {
        render::fill_rect(fb, x, y, w, 1, theme::RULE);
        render::draw_text_bold(fb, x, y + 8, &section.label, m.body, theme::INK, None);
    }
    let mut cy = y + 8;
    for (i, line) in section.lines.iter().enumerate() {
        let (size, advance) = if line.kind == LineKind::Note {
            (m.small, m.small_line)
        } else {
            (m.body, m.line)
        };
        let cols = (tw / render::font_width(size)).max(1) as usize;
        if i > 0 && line.kind == LineKind::Body {
            cy += 4;
        }
        for (j, text) in wrap_lines(&line.text, cols).iter().enumerate() {
            if paint {
                match line.kind {
                    LineKind::Fingerprint if j == 0 && text.starts_with("SHA-256 ") => {
                        let pw = render::draw_text(fb, tx, cy, "SHA-256 ", size, theme::INK3, None);
                        render::draw_text(
                            fb,
                            tx + pw as i32,
                            cy,
                            &text[8..],
                            size,
                            theme::INK,
                            None,
                        );
                    }
                    LineKind::Note => {
                        render::draw_text(fb, tx, cy, text, size, theme::INK3, None);
                    }
                    LineKind::Warn => {
                        render::draw_text_bold(fb, tx, cy, text, size, theme::WARN, None);
                    }
                    _ => {
                        render::draw_text(fb, tx, cy, text, size, theme::INK, None);
                    }
                }
            }
            cy += advance as i32;
        }
    }
    (cy - y) as u32 + 6
}

/// Greedy whole-section pages. A section taller than a page gets one alone.
fn paginate(heights: &[u32], room: u32) -> Vec<(usize, usize)> {
    let mut pages = Vec::new();
    let mut start = 0;
    while start < heights.len() {
        let mut used = 0;
        let mut end = start;
        while end < heights.len() && (end == start || used + heights[end] <= room) {
            used += heights[end];
            end += 1;
        }
        pages.push((start, end));
        start = end;
    }
    if pages.is_empty() {
        pages.push((0, 0));
    }
    pages
}

/// Identity-before-consent review. `intro`/`outro` stay fixed; sections page
/// by whole blocks. Confirm stays unavailable until every page was shown.
pub fn review(
    fb: &FramebufferConfig,
    backdrop: Backdrop<'_>,
    title: &str,
    intro: &[Block],
    sections: &[ReviewSection],
    outro: &[Block],
    confirm: Option<&str>,
) -> bool {
    let mut cursor = CursorRenderer::new();
    let mut page = 0usize;
    let mut seen = 0usize;
    let mut focused = 0usize;
    loop {
        cursor.hide(fb);
        let m = Metrics::for_fb(fb);
        let w = modal_width(fb, if m.large { 1000 } else { 984 });
        let inner = w - m.pad * 2;
        let label_w = section_label_width(fb, sections);
        let measure = |w| -> Vec<u32> {
            sections
                .iter()
                .map(|s| review_section(fb, 0, 0, w, label_w, s, false))
                .collect()
        };
        // Reserve the scroll gutter only when the list actually pages.
        let mut list_w = inner;
        let mut heights = measure(list_w);
        let intro_h = blocks(fb, 0, 0, inner, intro, false);
        let outro_h = blocks(fb, 0, 0, inner, outro, false);
        let counter_h = m.small_line + 8;
        let fixed =
            kit::modal_head_height(fb) + m.gap * 5 + intro_h + outro_h + m.button + counter_h;
        let avail = fb.height.saturating_sub(m.header + m.footer + 16);
        let natural: u32 = heights.iter().sum();
        let room = avail.saturating_sub(fixed).max(m.line * 3);
        if natural > room {
            list_w = inner - controls::SCROLL_GUTTER;
            heights = measure(list_w);
        }
        let natural: u32 = heights.iter().sum();
        let pages = paginate(&heights, room);
        page = page.min(pages.len() - 1);
        seen = seen.max(page);
        let all_seen = seen + 1 >= pages.len();
        let list_h = if pages.len() == 1 { natural } else { room };
        let h = fixed + list_h;
        let rect = center_modal(fb, w, h);
        theme::dimmed(backdrop);
        let body = kit::modal_frame(fb, rect, Tone::Ok, title);
        let mut y = body.1;
        blocks(fb, body.0, y, inner, intro, true);
        y += (intro_h + m.gap) as i32;
        let list_top = y;
        let (first, last) = pages[page];
        for section in &sections[first..last] {
            y += review_section(fb, body.0, y, list_w, label_w, section, true) as i32;
        }
        let list = (body.0, list_top, inner, list_h);
        controls::scrollbar(fb, list, pages.len(), page, 1);
        y = list_top + list_h as i32 + 4;
        render::fill_rect(fb, body.0, y - 4, inner, 1, theme::RULE);
        let counter = alloc::format!(
            "{} {} to {} of {}",
            if sections.len() == 1 { "Item" } else { "Items" },
            first + usize::from(last > first),
            last,
            sections.len()
        );
        render::draw_text(fb, body.0, y + 2, &counter, m.small, theme::INK2, None);
        if pages.len() > 1 {
            let hint = if page + 1 < pages.len() {
                alloc::format!(
                    "PgDn shows the next {}",
                    if pages.len() - page - 1 == 1 {
                        "page"
                    } else {
                        "pages"
                    }
                )
            } else {
                String::from("PgUp shows earlier items")
            };
            render::draw_text_right(fb, body.0, y + 2, inner, &hint, m.small, theme::INK3, None);
        }
        y += counter_h as i32 + m.gap as i32 / 2;
        blocks(fb, body.0, y, inner, outro, true);
        let by = rect.1 + rect.3 as i32 - m.button as i32 - m.gap as i32;
        let choices = match confirm {
            Some(confirm) => alloc::vec![
                Choice::new("Cancel", Some("Esc"), ButtonKind::Neutral),
                Choice::new(confirm, None, ButtonKind::Accent),
            ],
            None => alloc::vec![Choice::new("Close", Some("Esc"), ButtonKind::Neutral)],
        };
        focused = focused.min(choices.len() - 1);
        let rects = choice_row(
            fb,
            body.0 + inner as i32,
            by,
            &choices,
            Some(focused),
            &[true, all_seen],
        );
        if !all_seen && confirm.is_some() {
            let note = alloc::format!(
                "Review {} more {} first",
                pages.len() - seen - 1,
                if pages.len() - seen - 1 == 1 {
                    "page"
                } else {
                    "pages"
                }
            );
            render::draw_text_right(
                fb,
                body.0,
                by + ((m.button - render::font_height(m.small)) / 2) as i32,
                inner - rects.iter().map(|r| r.2 + 12).sum::<u32>() - 8,
                &note,
                m.small,
                theme::WARN,
                None,
            );
        }
        modal_keys(
            fb,
            if confirm.is_some() { "Cancel" } else { "Close" },
            if pages.len() > 1 {
                &[("PgUp PgDn", "Scroll")]
            } else {
                &[]
            },
        );
        let mut hover = super::Hover::default();
        loop {
            super::track_hover(fb, &mut cursor, &mut hover, None);
            super::poll_and_render_cursor(fb, &mut cursor);
            if let Some(key) = menu_common::read_key() {
                let activation = match key {
                    KeyPress::Escape => {
                        cursor.hide(fb);
                        return false;
                    }
                    KeyPress::F8 => {
                        layout::toggle_text_size(fb);
                        break;
                    }
                    KeyPress::Tab | KeyPress::Right | KeyPress::BackTab | KeyPress::Left => {
                        focused = (focused + 1) % choices.len();
                        break;
                    }
                    KeyPress::PageDown | KeyPress::Down => {
                        page = (page + 1).min(pages.len() - 1);
                        break;
                    }
                    KeyPress::PageUp | KeyPress::Up => {
                        page = page.saturating_sub(1);
                        break;
                    }
                    KeyPress::End => {
                        page = pages.len() - 1;
                        break;
                    }
                    KeyPress::Home => {
                        page = 0;
                        break;
                    }
                    KeyPress::MouseScroll(dz) => {
                        controls::scroll(&mut page, dz, pages.len(), 1);
                        break;
                    }
                    KeyPress::Enter | KeyPress::Char(' ') => Some(focused),
                    KeyPress::MouseClick { x, y } => {
                        if controls::scroll_track(
                            &mut page,
                            list,
                            (x as i32, y as i32),
                            pages.len(),
                            1,
                        ) {
                            break;
                        }
                        rects.iter().position(|r| contains(*r, x as i32, y as i32))
                    }
                    _ => None,
                };
                match activation {
                    Some(0) => {
                        cursor.hide(fb);
                        return false;
                    }
                    // Unseen identities: confirm advances instead of committing.
                    Some(_) if !all_seen => {
                        page = (page + 1).min(pages.len() - 1);
                        break;
                    }
                    Some(_) => {
                        cursor.hide(fb);
                        return true;
                    }
                    None => {}
                }
            }
            delay_ms(8);
        }
    }
}

// ─── Anchored popovers ──────────────────────────────────────────────────

/// Below the anchor's value side, flipped above when there is no room.
fn popover_rect(fb: &FramebufferConfig, anchor: Option<Rect>, w: u32, h: u32) -> Rect {
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

fn popover_frame(fb: &FramebufferConfig, rect: Rect, title: &str) -> i32 {
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

fn radio(fb: &FramebufferConfig, cx: i32, cy: i32, on: bool, bg: Rgb) {
    render::draw_dot(fb, cx, cy, 7, theme::INK2);
    render::draw_dot(fb, cx, cy, 5, bg);
    if on {
        render::draw_dot(fb, cx, cy, 3, theme::INK);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ChoiceAction {
    Apply(usize),
    Cancel,
}
fn choice_action(focus: usize, selected: usize) -> ChoiceAction {
    match focus {
        1 => ChoiceAction::Cancel,
        _ => ChoiceAction::Apply(selected),
    }
}
fn choice_pointer_action(
    buttons: &[Rect; 2],
    x: i32,
    y: i32,
    selected: usize,
) -> Option<ChoiceAction> {
    buttons
        .iter()
        .position(|r| contains(*r, x, y))
        .map(|i| choice_action(i + 1, selected))
}
fn reconcile_choice_view(
    offset: &mut usize,
    selected: usize,
    total: usize,
    slots: usize,
    reveal: &mut bool,
) {
    if *reveal {
        controls::ensure_visible(offset, selected, total, slots);
        *reveal = false;
    } else {
        *offset = (*offset).min(total.saturating_sub(slots));
    }
}

struct ChoiceRow<'a> {
    rect: Rect,
    label: &'a str,
    selected: bool,
    focused: bool,
    current: bool,
    tag: Option<&'a str>,
    text_w: u32,
    hovered: bool,
}

fn paint_choice_row(fb: &FramebufferConfig, r: &ChoiceRow<'_>) {
    let m = Metrics::for_fb(fb);
    let row = r.rect;
    let mut c = Control::new(0, Role::Option, r.label);
    c.selected = r.selected;
    c.focused = r.focused;
    let bg = controls::row(fb, row, &c, r.hovered);
    let ty = row.1 + ((m.row - render::font_height(m.body)) / 2) as i32;
    radio(fb, row.0 + 18, row.1 + m.row as i32 / 2, r.current, bg);
    render::draw_text_weight(
        fb,
        row.0 + 34,
        ty,
        &render::ellipsize(r.label, r.text_w, m.body),
        m.body,
        r.selected,
        theme::INK,
        Some(bg),
    );
    if let Some(tag) = r.tag {
        render::draw_text_right(
            fb,
            row.0,
            ty + 2,
            row.2 - 10,
            tag,
            m.small,
            if tag == "unsaved" {
                theme::WARN
            } else {
                theme::INK3
            },
            Some(bg),
        );
    }
}

/// Enum picker anchored to the setting row. Keyboard focus (outline) and the
/// current value (filled radio) are distinct. A row click only moves focus;
/// "Use value" or Enter applies, Escape or Cancel leaves the value alone.
#[allow(clippy::too_many_arguments)]
pub fn select(
    fb: &FramebufferConfig,
    backdrop: Backdrop<'_>,
    anchor: Option<Rect>,
    title: &str,
    labels: &[&str],
    initial: usize,
    tags: &[(usize, &str)],
) -> Option<usize> {
    if labels.is_empty() {
        return None;
    }
    let initial = initial.min(labels.len() - 1);
    let mut selected = initial;
    let mut offset = 0;
    let mut focus = 0usize; // list, Cancel, Use value
    let mut reveal_selection = true;
    let mut cursor = CursorRenderer::new();
    loop {
        cursor.hide(fb);
        let m = Metrics::for_fb(fb);
        let tag_w = tags
            .iter()
            .map(|(_, t)| render::text_width(t, m.small))
            .max()
            .unwrap_or(0);
        let label_w = labels
            .iter()
            .map(|l| render::text_width(l, m.body))
            .max()
            .unwrap_or(0);
        let base = if m.large { 460 } else { 400 };
        let gutter_w = controls::SCROLL_GUTTER;
        let w = (label_w + tag_w + 80 + gutter_w)
            .clamp(base, fb.width.saturating_sub(m.pad * 2).min(680));
        let text_w = w - 60 - tag_w - gutter_w;
        let long = render::text_width(labels[selected], m.body) > text_w;
        let detail_h = if long { m.line * 3 + 12 } else { 0 };
        let chrome = m.small_line + 13 + detail_h + m.button + 28;
        let max_h = fb.height.saturating_sub(m.header + m.footer + 8);
        let slots = ((max_h.saturating_sub(chrome)) / m.row).clamp(1, labels.len() as u32) as usize;
        let rect = popover_rect(fb, anchor, w, chrome + slots as u32 * m.row);
        let slots = ((rect.3.saturating_sub(chrome)) / m.row).max(1) as usize;
        reconcile_choice_view(
            &mut offset,
            selected,
            labels.len(),
            slots,
            &mut reveal_selection,
        );
        backdrop();
        // The page behind a popover is visible but not clickable.
        controls::clear_buttons();
        let top = popover_frame(fb, rect, title);
        let list = (rect.0 + 2, top, rect.2 - 4, slots as u32 * m.row);
        let gutter = if labels.len() > slots {
            controls::SCROLL_GUTTER
        } else {
            0
        };
        // Snapshot of this paint: any change below breaks out and repaints.
        let (offset_now, selected_now, focus_now) = (offset, selected, focus);
        let row_rect = move |i: usize| {
            (
                list.0,
                list.1 + ((i - offset_now) as u32 * m.row) as i32,
                list.2 - gutter,
                m.row,
            )
        };
        let choice_row = |i: usize, hovered: bool| ChoiceRow {
            rect: row_rect(i),
            label: labels[i],
            selected: i == selected_now,
            focused: focus_now == 0 && i == selected_now,
            current: i == initial,
            tag: tags.iter().find(|(j, _)| *j == i).map(|(_, t)| *t),
            text_w,
            hovered,
        };
        for i in (offset..labels.len()).take(slots) {
            paint_choice_row(fb, &choice_row(i, false));
        }
        controls::scrollbar(fb, list, labels.len(), offset, slots);
        controls::viewport_focus(fb, list, focus == 0, selected, offset, slots);
        let mut y = list.1 + list.3 as i32 + 6;
        if long {
            kit::prose(
                fb,
                rect.0 + 12,
                y,
                rect.2 - 24,
                labels[selected],
                m.body,
                theme::INK2,
                3,
            );
            y += detail_h as i32;
        }
        let bw = (rect.2 - 36) / 2;
        let cancel = (rect.0 + 12, y + 4, bw, m.button);
        let apply = (cancel.0 + bw as i32 + 12, cancel.1, bw, m.button);
        let mut c = Control::new(u64::MAX, Role::Button, "Cancel");
        c.focused = focus == 1;
        controls::button_with_key(fb, cancel, &c, ButtonKind::Neutral, Some("Esc"));
        let mut c = Control::new(u64::MAX - 1, Role::Button, "Use value");
        c.focused = focus == 2;
        controls::button_with_key(fb, apply, &c, ButtonKind::Primary, Some("Enter"));
        let buttons = [cancel, apply];
        kit::draw_keys(
            fb,
            &[
                ("Up Down", "Choose"),
                ("Enter", "Use value"),
                ("Tab", "Buttons"),
                ("Esc", "Cancel"),
            ],
            false,
        );
        let mut hover = super::Hover::default();
        let mut hovered_row: Option<usize> = None;
        loop {
            super::poll_and_render_cursor(fb, &mut cursor);
            super::track_hover(fb, &mut cursor, &mut hover, None);
            let (mx, my) = crate::drivers::mouse_cursor::position();
            let under = contains((list.0, list.1, list.2 - gutter, list.3), mx, my)
                .then(|| offset + ((my - list.1) as u32 / m.row) as usize)
                .filter(|i| *i < labels.len() && *i < offset + slots);
            if under != hovered_row {
                let previous = core::mem::replace(&mut hovered_row, under);
                cursor.while_hidden(fb, || {
                    for (i, on) in previous
                        .map(|i| (i, false))
                        .into_iter()
                        .chain(under.map(|i| (i, true)))
                    {
                        paint_choice_row(fb, &choice_row(i, on));
                    }
                    controls::viewport_focus(
                        fb,
                        list,
                        focus_now == 0,
                        selected_now,
                        offset_now,
                        slots,
                    );
                });
            }
            if let Some(key) = menu_common::read_key() {
                match key {
                    KeyPress::Escape => {
                        cursor.hide(fb);
                        return None;
                    }
                    KeyPress::Enter | KeyPress::Char(' ') => {
                        cursor.hide(fb);
                        return match choice_action(focus, selected) {
                            ChoiceAction::Apply(v) => Some(v),
                            ChoiceAction::Cancel => None,
                        };
                    }
                    KeyPress::Tab | KeyPress::BackTab => {
                        focus = (focus + if key == KeyPress::BackTab { 2 } else { 1 }) % 3;
                        if focus == 0 {
                            controls::ensure_visible(&mut offset, selected, labels.len(), slots);
                        }
                        break;
                    }
                    KeyPress::F8 => {
                        layout::toggle_text_size(fb);
                        reveal_selection = true; // Reconcile only after computing the new slots.
                        break;
                    }
                    KeyPress::Up if focus == 0 => {
                        selected = selected.saturating_sub(1);
                        controls::ensure_visible(&mut offset, selected, labels.len(), slots);
                        break;
                    }
                    KeyPress::Down if focus == 0 => {
                        selected = (selected + 1).min(labels.len() - 1);
                        controls::ensure_visible(&mut offset, selected, labels.len(), slots);
                        break;
                    }
                    KeyPress::Left | KeyPress::Right if focus != 0 => {
                        focus = if focus == 1 { 2 } else { 1 };
                        break;
                    }
                    KeyPress::Home | KeyPress::End | KeyPress::PageUp | KeyPress::PageDown
                        if focus == 0 =>
                    {
                        selected = super::page_selection(key, selected, labels.len(), slots)
                            .unwrap_or(selected);
                        controls::ensure_visible(&mut offset, selected, labels.len(), slots);
                        break;
                    }
                    KeyPress::MouseScroll(dz) => {
                        controls::scroll(&mut offset, dz, labels.len(), slots);
                        break;
                    }
                    KeyPress::MouseClick { x, y } => {
                        if let Some(action) =
                            choice_pointer_action(&buttons, x as i32, y as i32, selected)
                        {
                            cursor.hide(fb);
                            return match action {
                                ChoiceAction::Apply(v) => Some(v),
                                ChoiceAction::Cancel => None,
                            };
                        }
                        if controls::scroll_track(
                            &mut offset,
                            list,
                            (x as i32, y as i32),
                            labels.len(),
                            slots,
                        ) {
                            break;
                        }
                        if contains(
                            (list.0, list.1, list.2 - gutter, list.3),
                            x as i32,
                            y as i32,
                        ) {
                            let i = offset + ((y as i32 - list.1) as u32 / m.row) as usize;
                            if i < labels.len() {
                                selected = i;
                                focus = 0;
                            }
                            break;
                        }
                    }
                    _ => {}
                }
            }
            delay_ms(8);
        }
    }
}

// ─── Field editor ───────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum EditEvent {
    Changed,
    Apply,
    Cancel,
}
/// Caret editor model. Focus stops: 0 field, 1 Cancel, 2 Apply.
pub struct Editor {
    pub value: String,
    pub caret: usize,
    pub focus: usize,
    pub error: Option<&'static str>,
    limit: usize,
}
impl Editor {
    pub fn new(initial: &str) -> Self {
        Self::with_limit(initial, 255)
    }
    pub fn with_limit(initial: &str, limit: usize) -> Self {
        Self {
            value: String::from(initial),
            caret: initial.len(),
            focus: 0,
            error: None,
            limit,
        }
    }
    fn control<'a>(&'a self, index: usize, title: &'a str) -> Control<'a> {
        let mut c = Control::new(
            index as u64,
            if index == 0 {
                Role::TextField
            } else {
                Role::Button
            },
            match index {
                0 => title,
                1 => "Cancel",
                _ => "Set",
            },
        );
        c.focused = self.focus == index;
        c.invalid = index == 0 && self.error.is_some();
        if index == 0 {
            c.value = Some(&self.value);
        }
        c
    }
    pub fn key(&mut self, key: KeyPress) -> EditEvent {
        match key {
            KeyPress::Escape => return EditEvent::Cancel,
            KeyPress::Tab => self.focus = (self.focus + 1) % 3,
            KeyPress::BackTab => self.focus = (self.focus + 2) % 3,
            KeyPress::Enter => {
                return if self.focus == 1 {
                    EditEvent::Cancel
                } else {
                    EditEvent::Apply
                };
            }
            KeyPress::Char(' ') if self.focus != 0 => {
                return if self.focus == 1 {
                    EditEvent::Cancel
                } else {
                    EditEvent::Apply
                };
            }
            _ if self.focus != 0 => {}
            KeyPress::Home | KeyPress::Char('\x01') => self.caret = 0,
            KeyPress::End | KeyPress::Char('\x05') => self.caret = self.value.len(),
            KeyPress::Left => {
                self.caret = self.value[..self.caret]
                    .char_indices()
                    .next_back()
                    .map_or(0, |(i, _)| i)
            }
            KeyPress::Right => {
                if let Some(c) = self.value[self.caret..].chars().next() {
                    self.caret += c.len_utf8();
                }
            }
            KeyPress::Delete => {
                if self.caret < self.value.len() {
                    self.value.remove(self.caret);
                    self.error = None;
                }
            }
            KeyPress::Char('\x08' | '\x7f') => {
                if self.caret > 0 {
                    let previous = self.value[..self.caret]
                        .char_indices()
                        .next_back()
                        .map_or(0, |(i, _)| i);
                    self.value.drain(previous..self.caret);
                    self.caret = previous;
                    self.error = None;
                }
            }
            KeyPress::Char('\x15') => {
                self.value.clear();
                self.caret = 0;
                self.error = None;
            }
            KeyPress::Char(ch) if ch.is_ascii() && !ch.is_control() => {
                if self.value.len() < self.limit {
                    self.value.insert(self.caret, ch);
                    self.caret += 1;
                    self.error = None;
                } else {
                    self.error = Some("Maximum length reached. Delete text before adding more.");
                }
            }
            _ => {}
        }
        EditEvent::Changed
    }
}

/// Single-line field editor. With an anchor it is a popover on the row;
/// without one it is a modal over the dimmed screen.
#[allow(clippy::too_many_arguments)]
pub fn input(
    fb: &FramebufferConfig,
    backdrop: Backdrop<'_>,
    anchor: Option<Rect>,
    title: &str,
    hint: &str,
    initial: &str,
    limit: usize,
    validate: impl Fn(&str) -> Result<(), &'static str>,
) -> Option<String> {
    let mut editor = Editor::with_limit(initial, limit);
    let mut cursor = CursorRenderer::new();
    loop {
        cursor.hide(fb);
        let m = Metrics::for_fb(fb);
        let w = if anchor.is_some() {
            if m.large { 520 } else { 400 }
        } else {
            modal_width(fb, if m.large { 820 } else { 720 })
        };
        let field_h = render::font_height(m.body) + 16;
        let message_h = m.small_line * 2 + 8;
        let (inner_x, mut y, inner_w, rect) = if anchor.is_some() {
            let h = m.small_line + 13 + field_h + message_h + m.button + 36;
            let rect = popover_rect(fb, anchor, w, h);
            backdrop();
            // The page behind a popover is visible but not clickable.
            controls::clear_buttons();
            let top = popover_frame(fb, rect, title);
            (rect.0 + 12, top + 10, rect.2 - 24, rect)
        } else {
            let h = kit::modal_head_height(fb) + m.gap * 3 + field_h + message_h + m.button + 12;
            let rect = center_modal(fb, w, h);
            theme::dimmed(backdrop);
            let body = kit::modal_frame(fb, rect, Tone::Neutral, title);
            (body.0, body.1, body.2, rect)
        };
        let field = (inner_x, y, inner_w, field_h);
        let c = editor.control(0, title);
        render::fill_rect(fb, field.0, field.1, field.2, field.3, theme::SHEET);
        render::draw_thick_border(
            fb,
            field.0,
            field.1,
            field.2,
            field.3,
            2,
            if c.invalid {
                theme::BAD
            } else if c.focused {
                theme::INK
            } else {
                theme::RULE_STRONG
            },
        );
        let fw = render::font_width(m.body);
        let columns = (field.2.saturating_sub(20) / fw).max(2) as usize;
        let before = editor.value[..editor.caret].chars().count();
        let start = before.saturating_sub(columns - 1);
        let shown: String = editor.value.chars().skip(start).take(columns).collect();
        let ty = field.1 + 8;
        render::draw_text(
            fb,
            field.0 + 10,
            ty,
            &shown,
            m.body,
            theme::INK,
            Some(theme::SHEET),
        );
        if editor.focus == 0 {
            let cx = field.0 + 10 + ((before - start) as u32 * fw) as i32;
            render::fill_rect(fb, cx, ty, fw, render::font_height(m.body), theme::INK);
            if let Some(ch) = editor.value[editor.caret..].chars().next() {
                render::draw_char(fb, cx, ty, ch, m.body, theme::SHEET, Some(theme::INK));
            }
        }
        y += field_h as i32 + 6;
        if let Some(error) = editor.error {
            kit::prose(
                fb,
                inner_x,
                y,
                inner_w,
                &alloc::format!("Error: {error}"),
                m.small,
                theme::BAD,
                2,
            );
        } else {
            kit::prose(fb, inner_x, y, inner_w, hint, m.small, theme::INK2, 2);
        }
        let by = rect.1 + rect.3 as i32 - m.button as i32 - 12;
        let bw = (inner_w - 12) / 2;
        let cancel = (inner_x, by, bw, m.button);
        let apply = (inner_x + bw as i32 + 12, by, bw, m.button);
        controls::button_with_key(
            fb,
            cancel,
            &editor.control(1, title),
            ButtonKind::Neutral,
            Some("Esc"),
        );
        controls::button_with_key(
            fb,
            apply,
            &editor.control(2, title),
            ButtonKind::Primary,
            Some("Enter"),
        );
        kit::draw_keys(
            fb,
            &[
                ("Left Right", "Move"),
                ("Home End", "Jump"),
                ("Tab", "Buttons"),
                ("Enter", "Set"),
                ("Esc", "Cancel"),
            ],
            false,
        );
        let mut hover = super::Hover::default();
        loop {
            super::track_hover(fb, &mut cursor, &mut hover, None);
            super::poll_and_render_cursor(fb, &mut cursor);
            if let Some(key) = menu_common::read_key() {
                if key == KeyPress::F8 {
                    layout::toggle_text_size(fb);
                    break;
                }
                let event = if let KeyPress::MouseClick { x, y } = key {
                    if contains(cancel, x as i32, y as i32) {
                        EditEvent::Cancel
                    } else if contains(apply, x as i32, y as i32) {
                        EditEvent::Apply
                    } else if contains(field, x as i32, y as i32) {
                        editor.focus = 0;
                        let index = start + ((x as i32 - field.0 - 10).max(0) as u32 / fw) as usize;
                        editor.caret = editor
                            .value
                            .char_indices()
                            .nth(index)
                            .map_or(editor.value.len(), |(i, _)| i);
                        EditEvent::Changed
                    } else {
                        EditEvent::Changed
                    }
                } else {
                    editor.key(key)
                };
                match event {
                    EditEvent::Cancel => {
                        cursor.hide(fb);
                        return None;
                    }
                    EditEvent::Apply => match validate(&editor.value) {
                        Ok(()) => {
                            cursor.hide(fb);
                            return Some(editor.value);
                        }
                        Err(error) => {
                            editor.error = Some(error);
                            editor.focus = 0;
                        }
                    },
                    EditEvent::Changed => {}
                }
                break;
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
        assert_eq!(wrap_lines("A\n\nB", 40), ["A", "", "B"]);
    }
    #[test]
    fn identities_page_as_whole_blocks() {
        // Heights of six identity blocks; a page holds about two and a half.
        let heights = [80, 80, 40, 80, 80, 200];
        let pages = paginate(&heights, 190);
        assert_eq!(pages, [(0, 2), (2, 4), (4, 5), (5, 6)]);
        for (a, b) in &pages {
            assert!(b > a, "every page shows at least one whole block");
        }
        assert_eq!(paginate(&heights, 10_000), [(0, 6)]);
        assert_eq!(paginate(&[], 100), [(0, 0)]);
    }
    #[test]
    fn editor_focus_describes_the_actual_field_and_actions() {
        let mut e = Editor::new("25");
        assert!(e.control(0, "Delay").focused);
        assert!(!e.control(2, "Delay").focused);
        assert_eq!(e.control(0, "Delay").value, Some("25"));
        e.key(KeyPress::Tab);
        assert!(e.control(1, "Delay").focused);
        e.key(KeyPress::Tab);
        assert!(e.control(2, "Delay").focused);
        e.key(KeyPress::BackTab);
        assert!(e.control(1, "Delay").focused);
        assert_eq!(e.key(KeyPress::Enter), EditEvent::Cancel);
    }
    #[test]
    fn enum_pointer_buttons_can_apply_the_selected_draft() {
        let buttons = [(0, 0, 100, 40), (108, 0, 100, 40)];
        assert_eq!(
            choice_pointer_action(&buttons, 120, 10, 17),
            Some(ChoiceAction::Apply(17))
        );
        assert_eq!(
            choice_pointer_action(&buttons, 10, 10, 17),
            Some(ChoiceAction::Cancel)
        );
        assert_eq!(choice_pointer_action(&buttons, 104, 10, 17), None);
        assert_eq!(choice_action(0, 17), choice_action(2, 17));
    }

    #[test]
    fn enum_initial_and_resized_viewports_reveal_the_selected_choice() {
        let mut offset = 0;
        let mut reveal = true;
        reconcile_choice_view(&mut offset, 31, 32, 8, &mut reveal);
        assert_eq!(offset, 24);
        reveal = true;
        reconcile_choice_view(&mut offset, 31, 32, 3, &mut reveal);
        assert_eq!(offset, 29);
        controls::scroll(&mut offset, -20, 32, 3);
        let scrolled = offset;
        reconcile_choice_view(&mut offset, 31, 32, 3, &mut reveal);
        assert_eq!(
            offset, scrolled,
            "ordinary repaint must not undo wheel scrolling"
        );
    }

    #[test]
    fn caret_edits_do_not_dispatch_global_shortcuts() {
        let mut e = Editor::new("120");
        e.key(KeyPress::Home);
        e.key(KeyPress::Right);
        e.key(KeyPress::Delete);
        assert_eq!(e.value, "10");
        e.key(KeyPress::Char('5'));
        assert_eq!(e.value, "150");
        for c in ['b', 's', 'f', 'r'] {
            e.key(KeyPress::Char(c));
        }
        assert_eq!(e.value, "15bsfr0");
        assert_eq!(e.key(KeyPress::Escape), EditEvent::Cancel);
    }
    #[test]
    fn unicode_initial_values_keep_valid_caret_boundaries() {
        let mut e = Editor::new("éx");
        e.key(KeyPress::Home);
        e.key(KeyPress::Right);
        e.key(KeyPress::Char('\x08'));
        assert_eq!(e.value, "x");
        assert_eq!(e.caret, 0);
        let mut e = Editor::new(&"x".repeat(255));
        e.key(KeyPress::Char('y'));
        assert_eq!(e.value.len(), 255);
        assert!(e.error.is_some());
        let mut e = Editor::with_limit(&"x".repeat(300), 511);
        e.key(KeyPress::Char('y'));
        assert_eq!(e.value.len(), 301);
    }
}
