//! Modal focus scopes, structured trust review and caret-aware field editing.
//! Escape never commits; every visible action is reachable in both directions.

use super::{
    NavItem,
    controls::{self, ButtonKind, Control, Role},
    layout::{self, Metrics},
    render, theme,
};
use crate::{
    FramebufferConfig,
    cursor::CursorRenderer,
    menu_common::{self, KeyPress},
    time::delay_ms,
};
use alloc::{string::String, vec::Vec};

pub type Rect = (i32, i32, u32, u32);
pub fn contains(rect: Rect, x: i32, y: i32) -> bool {
    x >= rect.0 && y >= rect.1 && x < rect.0 + rect.2 as i32 && y < rect.1 + rect.3 as i32
}
pub fn button(fb: &FramebufferConfig, rect: Rect, label: &str, focused: bool) {
    let mut c = Control::new(0, Role::Button, label);
    c.focused = focused;
    controls::button(fb, rect, &c, ButtonKind::Neutral);
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
pub fn wrapped(fb: &FramebufferConfig, rect: Rect, text: &str, color: render::Rgb) {
    let m = Metrics::for_fb(fb);
    let lines = wrap_lines(text, (rect.2 / render::font_width(m.small)) as usize);
    let slots = (rect.3 / m.line) as usize;
    for (i, line) in lines.iter().take(slots).enumerate() {
        let label = if i + 1 == slots && lines.len() > slots {
            alloc::format!("{line} ...")
        } else {
            line.clone()
        };
        render::draw_text(
            fb,
            rect.0,
            rect.1 + (i as u32 * m.line) as i32,
            &render::ellipsize(&label, rect.2, m.small),
            m.small,
            color,
            None,
        );
    }
}

fn modal_rect(fb: &FramebufferConfig) -> Rect {
    modal_rect_with_height(fb, 720)
}
fn modal_rect_with_height(fb: &FramebufferConfig, preferred: u32) -> Rect {
    let m = Metrics::for_fb(fb);
    let w = fb.width.saturating_sub(32).min(760);
    let h = fb.height.saturating_sub(m.footer + 32).min(preferred);
    (
        ((fb.width - w) / 2) as i32,
        ((fb.height - m.footer - h) / 2) as i32,
        w,
        h,
    )
}
fn surface(fb: &FramebufferConfig, title: &str, rect: Rect) -> Rect {
    let m = Metrics::for_fb(fb);
    // Do not paint bright, apparently interactive navigation behind a modal.
    render::fill_rect(fb, 0, 0, fb.width, fb.height, theme::CONT_LOW);
    render::fill_rect(fb, rect.0, rect.1, rect.2, rect.3, theme::CONTAINER);
    render::draw_thick_border(fb, rect.0, rect.1, rect.2, rect.3, 2, theme::BORDER);
    render::draw_text(
        fb,
        rect.0 + 20,
        rect.1 + 16,
        &render::ellipsize(title, rect.2 - 40, m.title),
        m.title,
        theme::TEXT,
        Some(theme::CONTAINER),
    );
    rect
}

pub struct ReviewSection {
    pub label: String,
    pub text: String,
}
impl ReviewSection {
    pub fn new(label: &str, text: &str) -> Self {
        Self {
            label: String::from(label),
            text: String::from(text),
        }
    }
}

/// Pack logical blocks, not arbitrary prose slices. A fingerprint block fits
/// whole at the minimum viewport. Oversized non-identity prose repeats its label.
fn review_pages(sections: &[ReviewSection], columns: usize, slots: usize) -> Vec<Vec<String>> {
    let slots = slots.max(3);
    let mut pages = Vec::new();
    let mut page = Vec::new();
    for section in sections {
        let body = wrap_lines(&section.text, columns);
        let mut label = wrap_lines(&section.label, columns);
        if section.label.is_empty() {
            label.clear();
        }
        if label.len() + body.len() <= slots {
            let needed = label.len() + body.len() + usize::from(!page.is_empty());
            if page.len() + needed > slots && !page.is_empty() {
                pages.push(core::mem::take(&mut page));
            }
            if !page.is_empty() {
                page.push(String::new());
            }
            page.extend(label);
            page.extend(body);
        } else {
            if !page.is_empty() {
                pages.push(core::mem::take(&mut page));
            }
            let heading = if section.label.is_empty() {
                "Details"
            } else {
                &section.label
            };
            // One bounded heading line is repeated on every continuation page.
            for (i, chunk) in body.chunks(slots - 1).enumerate() {
                let mut next = alloc::vec![if i == 0 {
                    String::from(heading)
                } else {
                    alloc::format!("{heading} (continued)")
                }];
                next.extend_from_slice(chunk);
                pages.push(next);
            }
        }
    }
    if !page.is_empty() {
        pages.push(page);
    }
    if pages.is_empty() {
        pages.push(Vec::new());
    }
    pages
}
fn review_geometry(fb: &FramebufferConfig, rect: Rect) -> (Rect, Rect, Rect, usize, usize) {
    let m = Metrics::for_fb(fb);
    let (x, y, w, h) = rect;
    let buttons = (
        x + 20,
        y + h as i32 - m.button as i32 - 16,
        w - 40,
        m.button,
    );
    let pages = (x + 20, buttons.1 - m.button as i32 - 8, w - 40, m.button);
    let content = (
        x + 20,
        y + 28 + render::font_height(m.title) as i32,
        w - 40,
        (pages.1 - y - 40 - render::font_height(m.title) as i32).max(0) as u32,
    );
    (
        content,
        pages,
        buttons,
        (content.2 / render::font_width(m.small)) as usize,
        (content.3 / m.line) as usize,
    )
}
fn cycle_focus(current: usize, enabled: &[usize], backwards: bool) -> usize {
    let index = enabled.iter().position(|id| *id == current).unwrap_or(0);
    enabled[(index + if backwards { enabled.len() - 1 } else { 1 }) % enabled.len()]
}
fn choice_kind(label: &str, index: usize) -> ButtonKind {
    if index == 0 {
        ButtonKind::Neutral
    } else if matches!(
        label,
        "Restart" | "Discard" | "Clear keys" | "Disable" | "Enroll" | "Import"
    ) {
        ButtonKind::Danger
    } else {
        ButtonKind::Primary
    }
}

/// Compatibility choice API; trust imports use labeled sections directly.
pub fn choose(
    fb: &FramebufferConfig,
    nav: NavItem,
    title: &str,
    message: &str,
    labels: &[&str],
) -> usize {
    review_choice(fb, nav, title, &[ReviewSection::new("", message)], labels)
}
pub fn review(
    fb: &FramebufferConfig,
    nav: NavItem,
    title: &str,
    sections: &[ReviewSection],
    confirm: &str,
) -> bool {
    review_choice(fb, nav, title, sections, &["Cancel", confirm]) == 1
}
fn review_choice(
    fb: &FramebufferConfig,
    _nav: NavItem,
    title: &str,
    sections: &[ReviewSection],
    labels: &[&str],
) -> usize {
    assert!(!labels.is_empty() && labels.len() <= 3);
    let mut cursor = CursorRenderer::new();
    let mut page = 0usize;
    let mut focused = 2usize; // Stable ID 2 is always the safe first action.
    loop {
        cursor.hide(fb);
        let m = Metrics::for_fb(fb);
        let width = modal_rect(fb).2;
        let columns = ((width - 40) / render::font_width(m.small)) as usize;
        let needed = sections
            .iter()
            .map(|s| {
                wrap_lines(&s.text, columns).len()
                    + if s.label.is_empty() {
                        0
                    } else {
                        wrap_lines(&s.label, columns).len()
                    }
                    + 1
            })
            .sum::<usize>();
        let preferred = render::font_height(m.title)
            + (needed as u32).saturating_mul(m.line)
            + m.button * 2
            + 80;
        let rect = surface(fb, title, modal_rect_with_height(fb, preferred));
        let (content, pager, actions, columns, slots) = review_geometry(fb, rect);
        let pages = review_pages(sections, columns, slots);
        page = page.min(pages.len() - 1);
        for (i, line) in pages[page].iter().enumerate() {
            render::draw_text(
                fb,
                content.0,
                content.1 + (i as u32 * m.line) as i32,
                &render::ellipsize(line, content.2, m.small),
                m.small,
                theme::TEXT_DIM,
                None,
            );
        }
        let mut rects = Vec::new();
        let mut enabled = Vec::new();
        if pages.len() > 1 {
            let bw = (pager.2 - 12) / 3;
            for (i, label) in ["Previous", "Next"].iter().enumerate() {
                let rect = (pager.0 + (i as u32 * (bw + 6)) as i32, pager.1, bw, pager.3);
                let mut c = Control::new(i as u64, Role::Button, label);
                c.enabled = if i == 0 {
                    page > 0
                } else {
                    page + 1 < pages.len()
                };
                c.focused = focused == i;
                controls::button(fb, rect, &c, ButtonKind::Neutral);
                if c.enabled {
                    enabled.push(i);
                }
                rects.push((i, rect, c.enabled));
            }
            render::draw_text(
                fb,
                pager.0 + (2 * (bw + 6)) as i32,
                pager.1 + 10,
                &alloc::format!("{} / {}", page + 1, pages.len()),
                m.small,
                theme::TEXT_DIM,
                None,
            );
        }
        let bw = (actions.2 - (labels.len() as u32 - 1) * 8) / labels.len() as u32;
        for (i, label) in labels.iter().enumerate() {
            let id = i + 2;
            let rect = (
                actions.0 + (i as u32 * (bw + 8)) as i32,
                actions.1,
                bw,
                actions.3,
            );
            let mut c = Control::new(id as u64, Role::Button, label);
            c.focused = focused == id;
            controls::button(fb, rect, &c, choice_kind(label, i));
            enabled.push(id);
            rects.push((id, rect, true));
        }
        super::draw_footer(fb, "PgUp/PgDn Read   Tab Focus   Enter Choose   Esc Cancel");
        loop {
            super::poll_and_render_cursor(fb, &mut cursor);
            if let Some(key) = menu_common::read_key() {
                let activation = match key {
                    KeyPress::Escape => {
                        cursor.hide(fb);
                        return 0;
                    }
                    KeyPress::F8 => {
                        layout::toggle_text_size(fb);
                        focused = 2;
                        break;
                    }
                    KeyPress::Tab | KeyPress::Right | KeyPress::Down => {
                        focused = cycle_focus(focused, &enabled, false);
                        break;
                    }
                    KeyPress::BackTab | KeyPress::Left | KeyPress::Up => {
                        focused = cycle_focus(focused, &enabled, true);
                        break;
                    }
                    KeyPress::PageDown | KeyPress::End => {
                        page = if key == KeyPress::End {
                            pages.len() - 1
                        } else {
                            (page + 1).min(pages.len() - 1)
                        };
                        focused = 2;
                        break;
                    }
                    KeyPress::PageUp | KeyPress::Home => {
                        page = if key == KeyPress::Home {
                            0
                        } else {
                            page.saturating_sub(1)
                        };
                        focused = 2;
                        break;
                    }
                    KeyPress::MouseScroll(dz) => {
                        controls::scroll(&mut page, dz, pages.len(), 1);
                        focused = 2;
                        break;
                    }
                    KeyPress::Enter | KeyPress::Char(' ') => Some(focused),
                    KeyPress::MouseClick { x, y } => rects
                        .iter()
                        .find(|(_, r, on)| *on && contains(*r, x as i32, y as i32))
                        .map(|(id, _, _)| *id),
                    _ => None,
                };
                if let Some(id) = activation {
                    if id < 2 {
                        page = if id == 0 {
                            page.saturating_sub(1)
                        } else {
                            (page + 1).min(pages.len() - 1)
                        };
                        focused = if (id == 0 && page > 0) || (id == 1 && page + 1 < pages.len()) {
                            id
                        } else {
                            2
                        };
                        break;
                    }
                    cursor.hide(fb);
                    return id - 2;
                }
            }
            delay_ms(8);
        }
    }
}

/// Enum list selection and Cancel have independent keyboard focus. Current
/// value is labeled independently of the focused draft choice.
pub fn select(
    fb: &FramebufferConfig,
    title: &str,
    labels: &[&str],
    initial: usize,
) -> Option<usize> {
    if labels.is_empty() {
        return None;
    }
    let initial = initial.min(labels.len() - 1);
    let mut selected = initial;
    let mut offset = 0;
    let mut focus = 0usize; // list, Cancel, full choice details, Apply draft
    let mut reveal_selection = true;
    let mut cursor = CursorRenderer::new();
    loop {
        cursor.hide(fb);
        let m = Metrics::for_fb(fb);
        let height = (labels.len() as u32)
            .saturating_mul(m.row + 4)
            .saturating_add(render::font_height(m.title) + m.button + m.line + 88);
        let rect = surface(fb, title, modal_rect_with_height(fb, height));
        let cancel = (
            rect.0 + 20,
            rect.1 + rect.3 as i32 - m.button as i32 - 16,
            (rect.2 - 56) / 3,
            m.button,
        );
        let details = (cancel.0 + cancel.2 as i32 + 8, cancel.1, cancel.2, cancel.3);
        let apply = (
            details.0 + details.2 as i32 + 8,
            details.1,
            details.2,
            details.3,
        );
        let buttons = [cancel, details, apply];
        let top = rect.1 + render::font_height(m.title) as i32 + 40 + m.line as i32;
        let slots = ((cancel.1 - top - 12).max(0) as u32 / (m.row + 4)).max(1) as usize;
        let list = (rect.0 + 20, top, rect.2 - 40, (slots as u32) * (m.row + 4));
        reconcile_choice_view(
            &mut offset,
            selected,
            labels.len(),
            slots,
            &mut reveal_selection,
        );
        render::draw_text(
            fb,
            rect.0 + 20,
            rect.1 + render::font_height(m.title) as i32 + 24,
            &render::ellipsize(
                &alloc::format!("Selected: {}", labels[selected]),
                rect.2 - 40,
                m.small,
            ),
            m.small,
            theme::TEXT_DIM,
            None,
        );
        for (i, choice) in labels.iter().enumerate().skip(offset).take(slots) {
            let row = (
                list.0,
                list.1 + ((i - offset) as u32 * (m.row + 4)) as i32,
                list.2 - controls::SCROLL_GUTTER,
                m.row,
            );
            let mut c = Control::new(i as u64, Role::Option, choice);
            c.focused = focus == 0 && i == selected;
            c.selected = i == initial;
            let bg = controls::frame(fb, row, &c, false);
            let label = alloc::format!(
                "{} {} {}",
                if i == selected { ">" } else { " " },
                if i == initial {
                    "[current]"
                } else {
                    "         "
                },
                choice
            );
            render::draw_text(
                fb,
                row.0 + 14,
                row.1 + 10,
                &render::ellipsize(&label, row.2 - 28, m.small),
                m.small,
                theme::TEXT,
                Some(bg),
            );
        }
        super::draw_scrollbar(
            fb,
            list.0 + list.2 as i32 - 22,
            list.1,
            list.3,
            labels.len(),
            offset,
            slots,
        );
        controls::viewport_focus(fb, list, focus == 0, selected, offset, slots);
        let mut c = Control::new(u64::MAX, Role::Button, "Cancel");
        c.focused = focus == 1;
        controls::button(fb, cancel, &c, ButtonKind::Neutral);
        let mut c = Control::new(u64::MAX - 1, Role::Button, "Choice details");
        c.focused = focus == 2;
        controls::button(fb, details, &c, ButtonKind::Neutral);
        let mut c = Control::new(u64::MAX - 2, Role::Button, "Apply draft");
        c.focused = focus == 3;
        controls::button(fb, apply, &c, ButtonKind::Primary);
        super::draw_footer(
            fb,
            "Tab Focus   Arrows Choose   Enter Apply draft   ? Details   Esc Cancel",
        );
        loop {
            super::poll_and_render_cursor(fb, &mut cursor);
            if let Some(key) = menu_common::read_key() {
                match key {
                    KeyPress::Escape => {
                        cursor.hide(fb);
                        return None;
                    }
                    KeyPress::Enter | KeyPress::Char(' ') => {
                        cursor.hide(fb);
                        if matches!(choice_action(focus, selected), ChoiceAction::Apply(_)) {
                            return Some(selected);
                        }
                        if focus == 1 {
                            return None;
                        }
                        choice_details(fb, labels[selected], selected == initial);
                        break;
                    }
                    KeyPress::Char('?') => {
                        cursor.hide(fb);
                        choice_details(fb, labels[selected], selected == initial);
                        break;
                    }
                    KeyPress::Tab | KeyPress::BackTab => {
                        focus = (focus + if key == KeyPress::BackTab { 3 } else { 1 }) % 4;
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
                            match action {
                                ChoiceAction::Cancel => return None,
                                ChoiceAction::Apply(value) => return Some(value),
                                ChoiceAction::Details => {
                                    choice_details(fb, labels[selected], selected == initial);
                                    focus = 2;
                                    break;
                                }
                            }
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
                            (list.0, list.1, list.2 - controls::SCROLL_GUTTER, list.3),
                            x as i32,
                            y as i32,
                        ) && (y as i32 - list.1) as u32 % (m.row + 4) < m.row
                        {
                            let i = offset + ((y as i32 - list.1) as u32 / (m.row + 4)) as usize;
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

#[derive(Debug, PartialEq, Eq)]
enum ChoiceAction {
    Apply(usize),
    Cancel,
    Details,
}
fn choice_action(focus: usize, selected: usize) -> ChoiceAction {
    match focus {
        1 => ChoiceAction::Cancel,
        2 => ChoiceAction::Details,
        _ => ChoiceAction::Apply(selected),
    }
}
fn choice_pointer_action(
    buttons: &[Rect; 3],
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

fn choice_details(fb: &FramebufferConfig, label: &str, current: bool) {
    choose(
        fb,
        NavItem::Firmware,
        "Choice details",
        &alloc::format!(
            "{}\n\n{label}",
            if current {
                "Current value (unchanged)"
            } else {
                "Draft choice (not yet applied)"
            }
        ),
        &["Back"],
    );
}

#[derive(Debug, PartialEq, Eq)]
enum EditEvent {
    Changed,
    Apply,
    Cancel,
}
struct Editor {
    value: String,
    caret: usize,
    focus: usize,
    error: Option<&'static str>,
}
impl Editor {
    fn new(initial: &str) -> Self {
        Self {
            value: String::from(initial),
            caret: initial.len(),
            focus: 0,
            error: None,
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
                _ => "Apply draft",
            },
        );
        c.focused = self.focus == index;
        c.invalid = index == 0 && self.error.is_some();
        if index == 0 {
            c.value = Some(&self.value);
        }
        c
    }
    fn key(&mut self, key: KeyPress) -> EditEvent {
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
                if self.value.len() < 255 {
                    self.value.insert(self.caret, ch);
                    self.caret += 1;
                    self.error = None;
                } else {
                    self.error = Some("Maximum 255 bytes. Delete text before adding more.");
                }
            }
            _ => {}
        }
        EditEvent::Changed
    }
}

pub fn input(
    fb: &FramebufferConfig,
    title: &str,
    hint: &str,
    initial: &str,
    validate: impl Fn(&str) -> Result<(), &'static str>,
) -> Option<String> {
    let mut editor = Editor::new(initial);
    let mut cursor = CursorRenderer::new();
    loop {
        cursor.hide(fb);
        let m = Metrics::for_fb(fb);
        let height = render::font_height(m.title) + m.line * 5 + m.button * 2 + 72;
        let rect = surface(fb, title, modal_rect_with_height(fb, height));
        let hint_y = rect.1 + render::font_height(m.title) as i32 + 32;
        wrapped(
            fb,
            (rect.0 + 20, hint_y, rect.2 - 40, m.line * 3),
            hint,
            theme::TEXT_DIM,
        );
        let field = (
            rect.0 + 20,
            hint_y + (m.line * 3 + 8) as i32,
            rect.2 - 40,
            m.button + 4,
        );
        let c = editor.control(0, title);
        let bg = controls::frame(fb, field, &c, false);
        let columns = (field.2.saturating_sub(24) / render::font_width(m.body)).max(2) as usize;
        let before = editor.value[..editor.caret].chars().count();
        let start = before.saturating_sub(columns - 2);
        let shown: String = editor.value.chars().skip(start).take(columns - 1).collect();
        render::draw_text(
            fb,
            field.0 + 10,
            field.1 + 10,
            &shown,
            m.body,
            theme::TEXT,
            Some(bg),
        );
        if editor.focus == 0 {
            render::fill_rect(
                fb,
                field.0 + 10 + ((before - start) as u32 * render::font_width(m.body)) as i32,
                field.1 + 8,
                2,
                render::font_height(m.body) + 4,
                theme::TEXT,
            );
        }
        if let Some(error) = editor.error {
            wrapped(
                fb,
                (
                    rect.0 + 20,
                    field.1 + field.3 as i32 + 8,
                    rect.2 - 40,
                    m.line * 2,
                ),
                &alloc::format!("Error: {error}"),
                theme::ERROR,
            );
        }
        let cancel = (
            rect.0 + 20,
            rect.1 + rect.3 as i32 - m.button as i32 - 16,
            (rect.2 - 48) / 2,
            m.button,
        );
        let apply = (cancel.0 + cancel.2 as i32 + 8, cancel.1, cancel.2, cancel.3);
        controls::button(fb, cancel, &editor.control(1, title), ButtonKind::Neutral);
        controls::button(fb, apply, &editor.control(2, title), ButtonKind::Primary);
        super::draw_footer(
            fb,
            "Tab Focus   Arrows Edit   Del Delete   Enter Apply   Esc Cancel",
        );
        loop {
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
                        let index = start
                            + ((x as i32 - field.0 - 10).max(0) as u32 / render::font_width(m.body))
                                as usize;
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
    fn identities_are_whole_labeled_blocks_on_short_displays() {
        let hash = "00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617 18191a1b 1c1d1e1f";
        let sections = [
            ReviewSection::new("Consequences", &"Review carefully. ".repeat(20)),
            ReviewSection::new("PK SHA256", hash),
            ReviewSection::new("KEK SHA256", hash),
        ];
        for (columns, slots) in [(50, 6), (56, 4), (70, 12)] {
            let pages = review_pages(&sections, columns, slots);
            assert!(pages.iter().all(|p| p.len() <= slots));
            for label in ["PK SHA256", "KEK SHA256"] {
                let page = pages.iter().find(|p| p.iter().any(|s| s == label)).unwrap();
                let joined = page.join(" ");
                assert!(joined.contains("00010203 04050607"));
                assert!(joined.contains("18191a1b 1c1d1e1f"));
            }
        }
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
        let buttons = [(0, 0, 100, 40), (108, 0, 100, 40), (216, 0, 100, 40)];
        assert_eq!(
            choice_pointer_action(&buttons, 230, 10, 17),
            Some(ChoiceAction::Apply(17))
        );
        assert_eq!(
            choice_pointer_action(&buttons, 10, 10, 17),
            Some(ChoiceAction::Cancel)
        );
        assert_eq!(
            choice_pointer_action(&buttons, 120, 10, 17),
            Some(ChoiceAction::Details)
        );
        assert_eq!(choice_pointer_action(&buttons, 105, 10, 17), None);
        assert_eq!(choice_action(0, 17), choice_action(3, 17));
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
    }
}
