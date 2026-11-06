//! Thin, immediate-mode control contracts shared by all graphical screens.
//! Descriptions borrow live state; they are not a second retained UI tree or an AT API.

use super::{dialog::Rect, layout::Metrics, render, theme};
use crate::{FramebufferConfig, menu_common::KeyPress};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    Navigation,
    Content,
    Actions,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FocusEvent {
    Moved,
    Navigate(usize),
    Action(usize),
}

#[derive(Clone, Copy, Debug)]
pub struct Focus {
    pub group: Group,
    pub navigation: usize,
    pub action: usize,
}
impl Focus {
    pub const fn new(navigation: usize) -> Self {
        Self {
            group: Group::Content,
            navigation,
            action: 0,
        }
    }
    /// Traversal never activates. Space activates buttons, not arbitrary lists.
    pub fn handle(
        &mut self,
        key: KeyPress,
        navigation: usize,
        actions: usize,
    ) -> Option<FocusEvent> {
        if matches!(key, KeyPress::Tab | KeyPress::BackTab) {
            let groups = [Group::Navigation, Group::Content, Group::Actions];
            let current = groups.iter().position(|g| *g == self.group).unwrap_or(1);
            self.group = groups[(current + if key == KeyPress::BackTab { 2 } else { 1 }) % 3];
            return Some(FocusEvent::Moved);
        }
        let (index, count) = match self.group {
            Group::Navigation => (&mut self.navigation, navigation),
            Group::Actions => (&mut self.action, actions),
            Group::Content => return None,
        };
        if count == 0 {
            return Some(FocusEvent::Moved);
        }
        *index = (*index).min(count - 1);
        match key {
            KeyPress::Left | KeyPress::Up => *index = (*index + count - 1) % count,
            KeyPress::Right | KeyPress::Down => *index = (*index + 1) % count,
            KeyPress::Home => *index = 0,
            KeyPress::End => *index = count - 1,
            KeyPress::Enter | KeyPress::Char(' ') => {
                return Some(if self.group == Group::Navigation {
                    FocusEvent::Navigate(*index)
                } else {
                    FocusEvent::Action(*index)
                });
            }
            _ => return None,
        }
        Some(FocusEvent::Moved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Button,
    Option,
    TextField,
}

/// The very descriptor used to paint the control is available to state tests.
#[derive(Clone, Copy, Debug)]
pub struct Control<'a> {
    pub id: u64,
    pub role: Role,
    pub label: &'a str,
    pub value: Option<&'a str>,
    pub focused: bool,
    pub selected: bool,
    pub enabled: bool,
    pub read_only: bool,
    pub changed: bool,
    pub invalid: bool,
}
impl<'a> Control<'a> {
    pub const fn new(id: u64, role: Role, label: &'a str) -> Self {
        Self {
            id,
            role,
            label,
            value: None,
            focused: false,
            selected: false,
            enabled: true,
            read_only: false,
            changed: false,
            invalid: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonKind {
    Neutral,
    Primary,
    Danger,
}

pub fn frame(
    fb: &FramebufferConfig,
    rect: Rect,
    control: &Control<'_>,
    hovered: bool,
) -> render::Rgb {
    let (x, y, w, h) = rect;
    let bg = if control.focused || control.selected {
        theme::BRIGHT
    } else if hovered {
        theme::CONT_HIGH
    } else {
        theme::CONTAINER
    };
    render::fill_rect(fb, x, y, w, h, bg);
    let border = if control.invalid {
        theme::ERROR
    } else if control.focused {
        theme::TEXT
    } else if hovered {
        theme::TEXT_DIM
    } else {
        theme::BORDER
    };
    render::draw_thick_border(fb, x, y, w, h, if control.focused { 3 } else { 1 }, border);
    if control.selected {
        render::fill_rect(fb, x + 4, y + 5, 3, h.saturating_sub(10), theme::PRIMARY);
    }
    bg
}

pub fn button(fb: &FramebufferConfig, rect: Rect, control: &Control<'_>, kind: ButtonKind) {
    let m = Metrics::for_fb(fb);
    let (x, y, w, h) = rect;
    let bg = match kind {
        ButtonKind::Primary if control.enabled => theme::PRIMARY,
        _ => theme::CONTAINER,
    };
    let fg = if !control.enabled {
        theme::TEXT_DIM
    } else if kind == ButtonKind::Primary {
        theme::ON_PRIMARY
    } else {
        theme::TEXT
    };
    render::fill_rect(fb, x, y, w, h, bg);
    let border = if control.focused {
        theme::TEXT
    } else if kind == ButtonKind::Danger {
        theme::ERROR
    } else {
        theme::BORDER
    };
    render::draw_thick_border(fb, x, y, w, h, if control.focused { 3 } else { 1 }, border);
    render::draw_text_centered(
        fb,
        x + 8,
        y + (h.saturating_sub(render::font_height(m.small)) / 2) as i32,
        w.saturating_sub(16),
        &render::ellipsize(control.label, w.saturating_sub(24), m.small),
        m.small,
        fg,
        Some(bg),
    );
}

/// Viewport movement is deliberately independent of the selected target.
pub fn scroll(offset: &mut usize, delta: i32, total: usize, slots: usize) {
    if delta > 0 {
        *offset = offset.saturating_add(delta as usize);
    } else {
        *offset = offset.saturating_sub(delta.unsigned_abs() as usize);
    }
    *offset = (*offset).min(total.saturating_sub(slots.max(1)));
}

/// Restore the region outline after partial row repaints too: a hovered row
/// must not erase keyboard focus when its selected target is off screen.
pub fn viewport_focus(
    fb: &FramebufferConfig,
    list: Rect,
    focused: bool,
    selected: usize,
    offset: usize,
    slots: usize,
) {
    if focused && (selected < offset || selected >= offset.saturating_add(slots)) {
        render::draw_thick_border(
            fb,
            list.0,
            list.1,
            list.2.saturating_sub(8),
            list.3,
            2,
            theme::TEXT,
        );
    }
}

/// A usable pointer target even when a boot-protocol mouse has no wheel.
pub const SCROLL_GUTTER: u32 = 32;

pub fn scrollbar_thumb(
    height: u32,
    total: usize,
    offset: usize,
    slots: usize,
) -> Option<(u32, u32)> {
    if height == 0 || slots == 0 || total <= slots {
        return None;
    }
    let thumb = ((height as u128 * slots as u128 / total as u128) as u32)
        .max(24)
        .min(height);
    let maximum = total - slots;
    let top = ((height - thumb) as u128 * offset.min(maximum) as u128 / maximum as u128) as u32;
    Some((top, thumb))
}

/// Track clicks page the viewport without changing focus or selecting a row.
/// Thumb clicks are consumed too: they must never fall through to activation.
pub fn scroll_track(
    offset: &mut usize,
    list: Rect,
    point: (i32, i32),
    total: usize,
    slots: usize,
) -> bool {
    let Some((top, thumb)) = scrollbar_thumb(list.3, total, *offset, slots) else {
        return false;
    };
    let target = (
        list.0 + list.2.saturating_sub(SCROLL_GUTTER) as i32,
        list.1,
        list.2.min(SCROLL_GUTTER),
        list.3,
    );
    if !super::dialog::contains(target, point.0, point.1) {
        return false;
    }
    let y = (point.1 - list.1) as u32;
    let step = slots.min(i32::MAX as usize) as i32;
    if y < top {
        scroll(offset, -step, total, slots);
    } else if y >= top + thumb {
        scroll(offset, step, total, slots);
    }
    true
}

pub fn ensure_visible(offset: &mut usize, selected: usize, total: usize, slots: usize) {
    let slots = slots.max(1);
    if selected < *offset {
        *offset = selected;
    } else if selected >= offset.saturating_add(slots) {
        *offset = selected + 1 - slots;
    }
    *offset = (*offset).min(total.saturating_sub(slots));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forward_and_backward_group_traversal_never_activate() {
        let mut f = Focus::new(0);
        for expected in [Group::Actions, Group::Navigation, Group::Content] {
            assert_eq!(f.handle(KeyPress::Tab, 3, 4), Some(FocusEvent::Moved));
            assert_eq!(f.group, expected);
        }
        assert_eq!(f.handle(KeyPress::Char(' '), 3, 4), None);
        for expected in [Group::Navigation, Group::Actions, Group::Content] {
            assert_eq!(f.handle(KeyPress::BackTab, 3, 4), Some(FocusEvent::Moved));
            assert_eq!(f.group, expected);
        }
    }
    #[test]
    fn action_focus_and_navigation_are_independent() {
        let mut f = Focus::new(1);
        f.group = Group::Actions;
        f.handle(KeyPress::Right, 3, 4);
        assert_eq!(f.handle(KeyPress::Enter, 3, 4), Some(FocusEvent::Action(1)));
        assert_eq!(f.navigation, 1);
    }
    #[test]
    fn required_palette_pairs_have_readable_contrast() {
        fn luminance(c: render::Rgb) -> f64 {
            let linear = |v: u8| {
                let x = f64::from(v) / 255.0;
                if x <= 0.04045 {
                    x / 12.92
                } else {
                    ((x + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * linear(c.r) + 0.7152 * linear(c.g) + 0.0722 * linear(c.b)
        }
        for (fg, bg, minimum) in [
            (theme::TEXT, theme::CONTAINER, 4.5),
            (theme::TEXT_DIM, theme::CONTAINER, 4.5),
            (theme::OUTLINE, theme::CONTAINER, 4.5),
            (theme::ON_PRIMARY, theme::PRIMARY, 4.5),
            (theme::TEXT, theme::BRIGHT, 4.5),
            (theme::BORDER, theme::CONTAINER, 3.0),
            (theme::ERROR, theme::CONTAINER, 4.5),
        ] {
            let a = luminance(fg);
            let b = luminance(bg);
            assert!(
                (a.max(b) + 0.05) / (a.min(b) + 0.05) >= minimum,
                "{fg:?} on {bg:?}"
            );
        }
    }

    #[test]
    fn basic_mouse_can_page_to_every_row_without_a_wheel() {
        let list = (10, 20, 200, 100);
        let mut offset = 0;
        assert!(!scroll_track(&mut offset, list, (20, 110), 13, 4));
        for _ in 0..4 {
            assert!(scroll_track(&mut offset, list, (200, 119), 13, 4));
        }
        assert_eq!(offset, 9);
        assert!(scroll_track(&mut offset, list, (200, 21), 13, 4));
        assert_eq!(offset, 5);
        let (top, _) = scrollbar_thumb(100, 13, offset, 4).unwrap();
        assert!(scroll_track(
            &mut offset,
            list,
            (200, 21 + top as i32),
            13,
            4
        ));
        assert_eq!(offset, 5, "a thumb click must not fall through to a row");
        assert_eq!(scrollbar_thumb(0, 13, 0, 4), None);
        assert_eq!(scrollbar_thumb(100, 4, 0, 4), None);
    }

    #[test]
    fn scrolling_does_not_retarget_a_selection() {
        let selected = 2;
        let mut offset = 0;
        scroll(&mut offset, 5, 12, 4);
        assert_eq!((offset, selected), (5, 2));
        ensure_visible(&mut offset, selected, 12, 4);
        assert_eq!(offset, 2);
    }
}
