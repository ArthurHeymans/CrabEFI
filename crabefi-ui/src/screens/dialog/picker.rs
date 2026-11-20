use super::{Backdrop, Rect, contains, popover_frame, popover_rect};
use crate::cursor::CursorRenderer;
use crate::screens::controls::{ButtonKind, Control, Role};
use crate::screens::layout::Metrics;
use crate::screens::render::Rgb;
use crate::screens::{
    Hover, controls, kit, layout, page_selection, poll_and_render_cursor, render, theme,
    track_hover,
};
use crate::{KeyPress, Surface};

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
        let mut hover = Hover::default();
        let mut hovered_row: Option<usize> = None;
        loop {
            poll_and_render_cursor(fb, &mut cursor);
            track_hover(fb, &mut cursor, &mut hover, None);
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
                        selected =
                            page_selection(key, selected, labels.len(), slots).unwrap_or(selected);
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
