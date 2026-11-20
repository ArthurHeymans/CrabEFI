use super::{
    Backdrop, Rect, center_modal, contains, modal_backdrop, modal_width, popover_frame,
    popover_rect,
};
use crate::KeyPress;
use crate::cursor::CursorRenderer;
use crate::screens::controls::{ButtonKind, Control, Role};
use crate::screens::kit::Tone;
use crate::screens::layout::Metrics;
use crate::screens::{
    Hover, controls, kit, layout, poll_and_render_cursor, render, theme, track_hover,
};
use alloc::string::String;

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
        let mut hover = Hover::default();
        loop {
            track_hover(fb, &mut cursor, &mut hover, None);
            poll_and_render_cursor(fb, &mut cursor);
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
