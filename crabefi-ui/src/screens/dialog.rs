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
use crate::{KeyPress, Surface, cursor::CursorRenderer};
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
pub fn wrapped(fb: &Surface, rect: Rect, text: &str, color: Rgb) {
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

fn block_key_width(fb: &Surface, blocks: &[Block]) -> u32 {
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
fn blocks(fb: &Surface, x: i32, y: i32, w: u32, blocks: &[Block], paint: bool) -> u32 {
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
                    let lead = change_lead(from, w - key_w, m.body);
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

fn change_lead(from: &str, width: u32, font: render::FontSize) -> String {
    let reserved = render::text_width(" -> ", font);
    alloc::format!(
        "{} -> ",
        render::ellipsize(from, width.saturating_sub(reserved) / 2, font)
    )
}

fn choice_widths(fb: &Surface, choices: &[Choice<'_>]) -> Vec<u32> {
    let m = Metrics::for_fb(fb);
    choices
        .iter()
        .map(|c| controls::button_width(fb, c.label, c.key).max(if m.large { 180 } else { 140 }))
        .collect()
}

fn choice_height(fb: &Surface, width: u32, choices: &[Choice<'_>]) -> u32 {
    let widths = choice_widths(fb, choices);
    let total = widths.iter().sum::<u32>() + 12 * widths.len().saturating_sub(1) as u32;
    let m = Metrics::for_fb(fb);
    if total <= width {
        m.button
    } else {
        choices.len() as u32 * (m.button + 8) - 8
    }
}

/// Right-aligned choices, stacked when a complete row will not fit.
fn choice_row(
    fb: &Surface,
    right: i32,
    y: i32,
    available: u32,
    choices: &[Choice<'_>],
    focused: Option<usize>,
    enabled: &[bool],
) -> Vec<Rect> {
    let m = Metrics::for_fb(fb);
    let widths = choice_widths(fb, choices);
    let total: u32 = widths.iter().sum::<u32>() + 12 * widths.len().saturating_sub(1) as u32;
    let stacked = total > available;
    let mut x = right - total as i32;
    let mut rects = Vec::new();
    for (i, (choice, w)) in choices.iter().zip(&widths).enumerate() {
        let rect = if stacked {
            let w = (*w).min(available);
            (
                right - w as i32,
                y + i as i32 * (m.button + 8) as i32,
                w,
                m.button,
            )
        } else {
            (x, y, *w, m.button)
        };
        let mut c = Control::new(i as u64, Role::Button, choice.label);
        c.focused = focused == Some(i);
        c.enabled = enabled.get(i).copied().unwrap_or(true);
        controls::button_with_key(fb, rect, &c, choice.kind, choice.key);
        rects.push(rect);
        x += *w as i32 + 12;
    }
    rects
}

fn modal_backdrop(fb: &Surface, backdrop: Backdrop<'_>) {
    fb.dimmed(backdrop);
    // Platform backdrops need not use draw_shell, so they need not reset the
    // registry. Only the new modal surface may participate in hover tracking.
    controls::clear_buttons(fb);
}

fn shortcut_choice(choices: &[Choice<'_>], key: KeyPress) -> Option<usize> {
    (key == KeyPress::F10)
        .then(|| choices.iter().position(|choice| choice.key == Some("F10")))
        .flatten()
}

fn modal_keys(fb: &Surface, esc: &str, extra: &[(&str, &str)]) {
    let mut keys: Vec<(&str, &str)> =
        alloc::vec![("Tab Left Right", "Move"), ("Enter", "Activate")];
    keys.extend_from_slice(extra);
    keys.push(("Esc", esc));
    kit::draw_keys(fb, &keys, false);
}

/// Focus starts on, and Escape returns, choice 0: callers put the safe
/// option first.
pub async fn modal(
    fb: &crate::Surface,
    backdrop: Backdrop<'_>,
    tone: Tone,
    title: &str,
    content: &[Block],
    choices: &[Choice<'_>],
) -> usize {
    let _scope = fb.dialog_scope(title);
    assert!(!choices.is_empty() && choices.len() <= 3);
    let mut cursor = CursorRenderer::new();
    let mut focused = 0usize;
    let mut page = 0usize;
    loop {
        cursor.hide(fb);
        let m = Metrics::for_fb(fb);
        let w = modal_width(fb, if m.large { 820 } else { 720 });
        let inner = w - m.pad * 2;
        let body_h = blocks(fb, 0, 0, inner, content, false);
        let buttons_h = choice_height(fb, inner, choices);
        let chrome = kit::modal_head_height(fb) + m.gap * 3 + buttons_h + 4;
        let room = fb.height.saturating_sub(m.header + m.footer + 16 + chrome);
        // Stacking choices must not merely move clipping into the body. Page
        // long confirmations/results on short displays, like trust reviews.
        let sections = block_sections(content);
        let label_w = section_label_width(fb, &sections);
        let lines: Vec<_> = sections
            .iter()
            .map(|section| layout_section(fb, inner, label_w, section))
            .collect();
        let overflow = body_h > room;
        let pages = paginate(&lines, room);
        let page_count = if overflow { pages.len() } else { 1 };
        page = page.min(page_count - 1);
        let title = if page_count > 1 {
            alloc::format!("{title} ({}/{page_count})", page + 1)
        } else {
            String::from(title)
        };
        let h = chrome + body_h.min(room);
        let rect = center_modal(fb, w, h);
        modal_backdrop(fb, backdrop);
        let body = kit::modal_frame(fb, rect, tone, &title);
        if overflow {
            let mut y = body.1;
            for (s, range) in &pages[page] {
                y += paint_vlines(
                    fb,
                    body.0,
                    y,
                    inner,
                    label_w,
                    &sections[*s].label,
                    &lines[*s][range.clone()],
                ) as i32;
            }
        } else {
            blocks(fb, body.0, body.1, body.2, content, true);
        }
        let by = rect.1 + rect.3 as i32 - buttons_h as i32 - m.gap as i32;
        let rects = choice_row(
            fb,
            body.0 + body.2 as i32,
            by,
            inner,
            choices,
            Some(focused),
            &[],
        );
        modal_keys(
            fb,
            choices[0].label,
            if page_count > 1 {
                &[("PgUp PgDn", "Details")]
            } else {
                &[]
            },
        );
        let mut hover = super::Hover::default();
        loop {
            super::poll_and_render_cursor(fb, &mut cursor);
            super::track_hover(fb, &mut cursor, &mut hover, None);
            if let Some(key) = fb.key() {
                let activation = match key {
                    KeyPress::Escape => {
                        cursor.hide(fb);
                        return 0;
                    }
                    KeyPress::F8 => {
                        layout::toggle_text_size(fb);
                        page = 0;
                        break;
                    }
                    KeyPress::PageUp | KeyPress::PageDown | KeyPress::MouseScroll(_) => {
                        if key == KeyPress::PageUp
                            || matches!(key, KeyPress::MouseScroll(z) if z > 0)
                        {
                            page = page.saturating_sub(1);
                        } else {
                            page = (page + 1).min(page_count - 1);
                        }
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
                    KeyPress::F10 => shortcut_choice(choices, key),
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
            fb.wait_for_frame().await;
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
pub async fn choose(
    fb: &crate::Surface,
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
    modal(fb, backdrop, Tone::Neutral, title, &content, &choices).await
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
#[derive(Clone)]
pub struct ReviewLine {
    pub kind: LineKind,
    pub text: String,
}
/// One identity or fact group; kept whole on a page whenever it fits.
#[derive(Clone)]
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

fn section_label_width(fb: &Surface, sections: &[ReviewSection]) -> u32 {
    let m = Metrics::for_fb(fb);
    sections
        .iter()
        .map(|s| render::text_width(&s.label, m.body))
        .max()
        .unwrap_or(0)
        .max(if m.large { 70 } else { 40 })
        + 14
}

/// One painted line of a review section.
struct VLine {
    kind: LineKind,
    text: String,
    /// Space above this line (paragraph spacing inside a section).
    gap: u32,
    advance: u32,
    /// First wrapped line of a fingerprint keeps its quieter "SHA-256" prefix.
    first: bool,
}

/// Section chrome around its lines: rule plus padding above, padding below.
const SECTION_TOP: u32 = 8;
const SECTION_BOTTOM: u32 = 6;

fn layout_section(fb: &Surface, w: u32, label_w: u32, section: &ReviewSection) -> Vec<VLine> {
    let m = Metrics::for_fb(fb);
    let tw = w.saturating_sub(label_w);
    let mut out = Vec::new();
    for (i, line) in section.lines.iter().enumerate() {
        let (size, advance) = if line.kind == LineKind::Note {
            (m.small, m.small_line)
        } else {
            (m.body, m.line)
        };
        let cols = (tw / render::font_width(size)).max(1) as usize;
        for (j, text) in wrap_lines(&line.text, cols).into_iter().enumerate() {
            out.push(VLine {
                kind: line.kind,
                text,
                gap: if i > 0 && j == 0 && line.kind == LineKind::Body {
                    4
                } else {
                    0
                },
                advance,
                first: j == 0,
            });
        }
    }
    out
}

fn vlines_height(lines: &[VLine]) -> u32 {
    lines.iter().map(|l| l.gap + l.advance).sum::<u32>() + SECTION_TOP + SECTION_BOTTOM
}

fn paint_vlines(
    fb: &Surface,
    x: i32,
    y: i32,
    w: u32,
    label_w: u32,
    label: &str,
    lines: &[VLine],
) -> u32 {
    let m = Metrics::for_fb(fb);
    let tx = x + label_w as i32;
    render::fill_rect(fb, x, y, w, 1, theme::RULE);
    render::draw_text_bold(
        fb,
        x,
        y + SECTION_TOP as i32,
        label,
        m.body,
        theme::INK,
        None,
    );
    let mut cy = y + SECTION_TOP as i32;
    for line in lines {
        cy += line.gap as i32;
        let size = if line.kind == LineKind::Note {
            m.small
        } else {
            m.body
        };
        match line.kind {
            LineKind::Fingerprint if line.first && line.text.starts_with("SHA-256 ") => {
                let pw = render::draw_text(fb, tx, cy, "SHA-256 ", size, theme::INK3, None);
                render::draw_text(
                    fb,
                    tx + pw as i32,
                    cy,
                    &line.text[8..],
                    size,
                    theme::INK,
                    None,
                );
            }
            LineKind::Note => {
                render::draw_text(fb, tx, cy, &line.text, size, theme::INK3, None);
            }
            LineKind::Warn => {
                render::draw_text_bold(fb, tx, cy, &line.text, size, theme::WARN, None);
            }
            _ => {
                render::draw_text(fb, tx, cy, &line.text, size, theme::INK, None);
            }
        }
        cy += line.advance as i32;
    }
    (cy - y) as u32 + SECTION_BOTTOM
}

/// A page shows, for each listed section, a range of its visual lines.
type Page = Vec<(usize, core::ops::Range<usize>)>;

/// Whole sections per page where they fit. A section taller than a page is
/// split between its lines, preferring line-group (fingerprint) boundaries,
/// so nothing is ever painted outside the list area.
fn paginate(sections: &[Vec<VLine>], room: u32) -> Vec<Page> {
    let mut pages: Vec<Page> = Vec::new();
    let mut page: Page = Vec::new();
    let mut used = 0;
    let body_room = room.saturating_sub(SECTION_TOP + SECTION_BOTTOM).max(1);
    for (s, lines) in sections.iter().enumerate() {
        let h = vlines_height(lines);
        if h <= room {
            if used + h > room && !page.is_empty() {
                pages.push(core::mem::take(&mut page));
                used = 0;
            }
            page.push((s, 0..lines.len()));
            used += h;
            continue;
        }
        if !page.is_empty() {
            pages.push(core::mem::take(&mut page));
            used = 0;
        }
        let mut start = 0;
        while start < lines.len() {
            let mut end = start;
            let mut acc = 0;
            while end < lines.len() {
                let line_h = lines[end].gap + lines[end].advance;
                if end > start && acc + line_h > body_room {
                    // Prefer not to split a wrapped line group across pages.
                    let group_start = (start..=end).rev().find(|i| lines[*i].first).unwrap_or(end);
                    if group_start > start {
                        end = group_start;
                    }
                    break;
                }
                acc += line_h;
                end += 1;
            }
            pages.push(alloc::vec![(s, start..end)]);
            start = end;
        }
    }
    if !page.is_empty() || pages.is_empty() {
        pages.push(page);
    }
    pages
}

fn mark_shown(shown: &mut [Vec<bool>], page: &Page) {
    for (s, range) in page {
        shown[*s][range.clone()].fill(true);
    }
}

/// Indices of pages that still hold a line the user has not seen.
fn unseen_pages<'a>(pages: &'a [Page], shown: &'a [Vec<bool>]) -> impl Iterator<Item = usize> + 'a {
    pages
        .iter()
        .enumerate()
        .filter(|(_, p)| p.iter().any(|(s, r)| shown[*s][r.clone()].contains(&false)))
        .map(|(i, _)| i)
}

fn block_sections(blocks: &[Block]) -> Vec<ReviewSection> {
    blocks
        .iter()
        .map(|b| match b {
            Block::Text(t) => ReviewSection::labelled("").line(LineKind::Body, t),
            Block::Muted(t) => ReviewSection::labelled("").line(LineKind::Body, t),
            Block::Fact { key, value, .. } => {
                ReviewSection::labelled(key).line(LineKind::Body, value)
            }
            Block::Change { name, from, to } => ReviewSection::labelled(name)
                .line(LineKind::Body, &alloc::format!("{from} -> {to}")),
        })
        .collect()
}

/// Identity-before-consent review. Normally `intro`/`outro` stay fixed and
/// sections page by whole blocks; on short screens they join the pages.
/// Confirm stays unavailable until every line was actually on screen.
pub async fn review(
    fb: &crate::Surface,
    backdrop: Backdrop<'_>,
    title: &str,
    intro: &[Block],
    sections: &[ReviewSection],
    outro: &[Block],
    confirm: Option<&str>,
) -> bool {
    let _scope = fb.dialog_scope(title);
    let mut cursor = CursorRenderer::new();
    let mut page = 0usize;
    let mut focused = 0usize;
    // Shown lines per (paged entry, visual line); reset when the layout changes.
    let mut shown: Vec<Vec<bool>> = Vec::new();
    let mut layout_key = None;
    loop {
        cursor.hide(fb);
        let m = Metrics::for_fb(fb);
        let w = modal_width(fb, if m.large { 1000 } else { 984 });
        let inner = w - m.pad * 2;
        let counter_h = m.small_line + 8;
        let avail = fb.height.saturating_sub(m.header + m.footer + 16);
        let intro_h = blocks(fb, 0, 0, inner, intro, false);
        let outro_h = blocks(fb, 0, 0, inner, outro, false);
        let choices = match confirm {
            Some(confirm) => alloc::vec![
                Choice::new("Cancel", Some("Esc"), ButtonKind::Neutral),
                Choice::new(confirm, None, ButtonKind::Accent),
            ],
            None => alloc::vec![Choice::new("Close", Some("Esc"), ButtonKind::Neutral)],
        };
        let buttons_h = choice_height(fb, inner, &choices);
        let base = kit::modal_head_height(fb) + m.gap * 3 + buttons_h + counter_h;
        let normal_fixed = base + m.gap * 2 + intro_h + outro_h;
        let label_w_of = |entries: &[ReviewSection]| section_label_width(fb, entries);
        let tallest = {
            let lw = label_w_of(sections);
            sections
                .iter()
                .map(|s| vlines_height(&layout_section(fb, inner - controls::SCROLL_GUTTER, lw, s)))
                .max()
                .unwrap_or(0)
        };
        // Short screens: page the summary too, rather than squeeze identities.
        let compact = avail.saturating_sub(normal_fixed) < tallest.max(m.line * 3);
        let entries: Vec<ReviewSection> = if compact {
            let mut all = block_sections(intro);
            all.extend(sections.iter().cloned());
            all.extend(block_sections(outro));
            all
        } else {
            sections.to_vec()
        };
        let fixed = if compact { base } else { normal_fixed };
        let room = avail.saturating_sub(fixed).max(m.line * 3);
        let label_w = label_w_of(&entries);
        let lay = |w| -> Vec<Vec<VLine>> {
            entries
                .iter()
                .map(|s| layout_section(fb, w, label_w, s))
                .collect()
        };
        let mut list_w = inner;
        let mut lines = lay(list_w);
        let natural: u32 = lines.iter().map(|l| vlines_height(l)).sum();
        if natural > room {
            list_w = inner - controls::SCROLL_GUTTER;
            lines = lay(list_w);
        }
        let natural: u32 = lines.iter().map(|l| vlines_height(l)).sum();
        let pages = paginate(&lines, room);
        if layout_key != Some((m.large, w, compact)) {
            layout_key = Some((m.large, w, compact));
            shown = lines.iter().map(|l| alloc::vec![false; l.len()]).collect();
            page = 0;
        }
        page = page.min(pages.len() - 1);
        mark_shown(&mut shown, &pages[page]);
        let unseen = unseen_pages(&pages, &shown).count();
        let all_seen = unseen == 0;
        let list_h = if pages.len() == 1 { natural } else { room };
        let h = fixed + list_h;
        let rect = center_modal(fb, w, h);
        modal_backdrop(fb, backdrop);
        let body = kit::modal_frame(fb, rect, Tone::Ok, title);
        let mut y = body.1;
        if !compact {
            blocks(fb, body.0, y, inner, intro, true);
            y += (intro_h + m.gap) as i32;
        }
        let list_top = y;
        for (s, range) in &pages[page] {
            y += paint_vlines(
                fb,
                body.0,
                y,
                list_w,
                label_w,
                &entries[*s].label,
                &lines[*s][range.clone()],
            ) as i32;
        }
        let list = (body.0, list_top, inner, list_h);
        controls::scrollbar(fb, list, pages.len(), page, 1);
        y = list_top + list_h as i32 + 4;
        render::fill_rect(fb, body.0, y - 4, inner, 1, theme::RULE);
        let counter = if pages.len() > 1 {
            alloc::format!("Page {} of {}", page + 1, pages.len())
        } else {
            alloc::format!(
                "All {} {} shown",
                entries.len(),
                if entries.len() == 1 { "item" } else { "items" }
            )
        };
        render::draw_text(fb, body.0, y + 2, &counter, m.small, theme::INK2, None);
        if pages.len() > 1 {
            let hint = if page + 1 < pages.len() {
                String::from("PgDn shows the next page")
            } else {
                String::from("PgUp shows earlier pages")
            };
            render::draw_text_right(fb, body.0, y + 2, inner, &hint, m.small, theme::INK3, None);
        }
        y += counter_h as i32 + m.gap as i32 / 2;
        if !compact {
            blocks(fb, body.0, y, inner, outro, true);
        }
        let by = rect.1 + rect.3 as i32 - buttons_h as i32 - m.gap as i32;
        focused = focused.min(choices.len() - 1);
        let rects = choice_row(
            fb,
            body.0 + inner as i32,
            by,
            inner,
            &choices,
            Some(focused),
            &[true, all_seen],
        );
        if !all_seen && confirm.is_some() {
            let note = alloc::format!(
                "Review {} more {} first",
                unseen,
                if unseen == 1 { "page" } else { "pages" }
            );
            render::draw_text_right(
                fb,
                body.0,
                by + ((m.button - render::font_height(m.small)) / 2) as i32,
                inner
                    .saturating_sub(rects.iter().map(|r| r.2 + 12).sum::<u32>())
                    .saturating_sub(8),
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
            super::poll_and_render_cursor(fb, &mut cursor);
            super::track_hover(fb, &mut cursor, &mut hover, None);
            if let Some(key) = fb.key() {
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
                    // Unseen identities: confirm moves to the first page that
                    // still has unseen lines instead of committing.
                    Some(_) if !all_seen => {
                        page = unseen_pages(&pages, &shown).next().unwrap_or(page);
                        break;
                    }
                    Some(_) => {
                        cursor.hide(fb);
                        return true;
                    }
                    None => {}
                }
            }
            fb.wait_for_frame().await;
        }
    }
}

// ─── Anchored popovers ──────────────────────────────────────────────────

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

fn radio(fb: &Surface, cx: i32, cy: i32, on: bool, bg: Rgb) {
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

fn paint_choice_row(fb: &Surface, r: &ChoiceRow<'_>) {
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
pub async fn select(
    fb: &crate::Surface,
    backdrop: Backdrop<'_>,
    anchor: Option<Rect>,
    title: &str,
    labels: &[&str],
    initial: usize,
    tags: &[(usize, &str)],
) -> Option<usize> {
    let _scope = fb.dialog_scope(title);
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
        controls::clear_buttons(fb);
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
            let (mx, my) = fb.position();
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
            if let Some(key) = fb.key() {
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
            fb.wait_for_frame().await;
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
    /// Whether Space on the Apply button commits. Off when Apply boots:
    /// Space never boots.
    pub space_commits: bool,
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
            space_commits: true,
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
                } else if self.space_commits {
                    EditEvent::Apply
                } else {
                    EditEvent::Changed
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
pub async fn input(
    fb: &crate::Surface,
    backdrop: Backdrop<'_>,
    anchor: Option<Rect>,
    title: &str,
    hint: &str,
    initial: &str,
    limit: usize,
    validate: impl Fn(&str) -> Result<(), &'static str>,
) -> Option<String> {
    input_with(
        fb, backdrop, anchor, title, hint, initial, limit, true, validate,
    )
    .await
}

/// `input`, choosing whether Space on the Apply button commits.
#[allow(clippy::too_many_arguments)]
pub async fn input_with(
    fb: &crate::Surface,
    backdrop: Backdrop<'_>,
    anchor: Option<Rect>,
    title: &str,
    hint: &str,
    initial: &str,
    limit: usize,
    space_commits: bool,
    validate: impl Fn(&str) -> Result<(), &'static str>,
) -> Option<String> {
    let _scope = fb.dialog_scope(title);
    let mut editor = Editor::with_limit(initial, limit);
    editor.space_commits = space_commits;
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
            controls::clear_buttons(fb);
            let top = popover_frame(fb, rect, title);
            (rect.0 + 12, top + 10, rect.2 - 24, rect)
        } else {
            let h = kit::modal_head_height(fb) + m.gap * 3 + field_h + message_h + m.button + 12;
            let rect = center_modal(fb, w, h);
            modal_backdrop(fb, backdrop);
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
            if let Some(key) = fb.key() {
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
            fb.wait_for_frame().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn narrow_modal_choices_fit_and_repaints_replace_the_hover_registry() {
        let mut pixels = std::vec![0u32; 640 * 480];
        let fb = crate::test_surface(crate::FramebufferConfig {
            physical_address: pixels.as_mut_ptr() as u64,
            width: 640,
            height: 480,
            stride: 640,
            bits_per_pixel: 32,
            red_mask_pos: 16,
            red_mask_size: 8,
            green_mask_pos: 8,
            green_mask_size: 8,
            blue_mask_pos: 0,
            blue_mask_size: 8,
        });
        let choices = [
            Choice::new("Keep editing", Some("Esc"), ButtonKind::Neutral),
            Choice::new("Discard and restart", None, ButtonKind::Danger),
            Choice::new("Save and restart", Some("F10"), ButtonKind::Primary),
        ];
        let w = 520;
        let h = choice_height(&fb, w, &choices);
        assert!(h > Metrics::for_fb(&fb).button);
        for _ in 0..3 {
            modal_backdrop(&fb, &|| {});
            let rects = choice_row(&fb, 580, 100, w, &choices, Some(0), &[]);
            for r in &rects {
                assert!(r.0 >= 60 && r.0 + r.2 as i32 <= 580);
                assert!(r.1 + r.3 as i32 <= 100 + h as i32);
            }
            assert_eq!(
                controls::button_at(&fb, rects[0].0 + 5, rects[0].1 + 5),
                Some(0)
            );
        }
        assert_eq!(shortcut_choice(&choices, KeyPress::F10), Some(2));
        assert_eq!(shortcut_choice(&choices, KeyPress::Enter), None);
    }

    #[test]
    fn long_saved_values_leave_space_for_the_proposed_value() {
        let width = 240;
        let font = render::FontSize::Normal;
        let lead = change_lead(&"old value".repeat(40), width, font);
        let remaining = width - render::text_width(&lead, font);
        assert!(remaining >= (width - render::text_width(" -> ", font)) / 2);
        assert!(!render::ellipsize("new value", remaining, font).is_empty());
    }

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
    /// A section of `groups` line groups, each `per` wrapped lines of 20 px.
    fn section(groups: usize, per: usize) -> Vec<VLine> {
        (0..groups)
            .flat_map(|_g| {
                (0..per).map(move |j| VLine {
                    kind: LineKind::Body,
                    text: String::new(),
                    gap: 0,
                    advance: 20,
                    first: j == 0,
                })
            })
            .collect()
    }
    fn page_height(sections: &[Vec<VLine>], page: &Page) -> u32 {
        page.iter()
            .map(|(s, r)| vlines_height(&sections[*s][r.clone()]))
            .sum()
    }

    #[test]
    fn identities_page_as_whole_blocks() {
        // Section heights: 3 lines = 74 px, 1 line = 34 px.
        let sections = [section(3, 1), section(3, 1), section(1, 1), section(3, 1)];
        let pages = paginate(&sections, 190);
        assert_eq!(pages.len(), 2);
        for page in &pages {
            for (s, r) in page {
                assert_eq!(
                    r.clone(),
                    0..sections[*s].len(),
                    "whole blocks when they fit"
                );
            }
            assert!(page_height(&sections, page) <= 190);
        }
        assert_eq!(paginate(&sections, 10_000).len(), 1);
        assert_eq!(paginate(&[], 100).len(), 1);
    }

    #[test]
    fn oversized_blocks_split_between_lines_and_never_overflow() {
        // A 2-line fingerprint group must not be split when the page can hold it.
        let sections = [section(1, 1), section(6, 2)];
        let room = 110;
        let pages = paginate(&sections, room);
        let mut covered = std::vec![std::vec![0; 1], std::vec![0; 12]];
        for page in &pages {
            assert!(
                page_height(&sections, page) <= room,
                "nothing painted outside"
            );
            for (s, r) in page {
                for i in r.clone() {
                    covered[*s][i] += 1;
                }
                if *s == 1 {
                    assert!(
                        sections[1][r.start].first,
                        "pages start at a group boundary"
                    );
                }
            }
        }
        assert!(
            covered.iter().flatten().all(|n| *n == 1),
            "every line exactly once"
        );
    }

    #[test]
    fn jumping_to_the_last_page_does_not_count_as_review() {
        let sections = [section(4, 1), section(4, 1), section(4, 1)];
        let pages = paginate(&sections, 100);
        assert_eq!(pages.len(), 3);
        let mut shown: Vec<Vec<bool>> =
            sections.iter().map(|s| std::vec![false; s.len()]).collect();
        mark_shown(&mut shown, &pages[0]);
        mark_shown(&mut shown, &pages[2]); // End
        assert_eq!(unseen_pages(&pages, &shown).collect::<Vec<_>>(), [1]);
        mark_shown(&mut shown, &pages[1]);
        assert_eq!(unseen_pages(&pages, &shown).count(), 0);
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
    fn space_does_not_commit_when_apply_boots() {
        let mut e = Editor::new("quiet");
        e.space_commits = false;
        e.key(KeyPress::Tab);
        e.key(KeyPress::Tab);
        assert_eq!(e.focus, 2);
        assert_eq!(e.key(KeyPress::Char(' ')), EditEvent::Changed);
        assert_eq!(e.key(KeyPress::Enter), EditEvent::Apply);
        e.key(KeyPress::BackTab);
        assert_eq!(e.key(KeyPress::Char(' ')), EditEvent::Cancel);
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
