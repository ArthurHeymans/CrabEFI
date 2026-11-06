//! Thin, immediate-mode control contracts shared by all graphical screens.
//! Descriptions borrow live state; they are not a second retained UI tree or an AT API.

use super::{dialog::Rect, layout::Metrics, render, theme};
use crate::{FramebufferConfig, menu_common::KeyPress};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    Navigation,
    /// Settings section list (Firmware page only).
    Sections,
    Content,
    Actions,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FocusEvent {
    Moved,
    Navigate(usize),
    Action(usize),
}

pub const DEFAULT_ORDER: &[Group] = &[Group::Navigation, Group::Content, Group::Actions];
pub const SECTIONED_ORDER: &[Group] = &[
    Group::Navigation,
    Group::Sections,
    Group::Content,
    Group::Actions,
];

#[derive(Clone, Copy, Debug)]
pub struct Focus {
    pub group: Group,
    pub navigation: usize,
    pub action: usize,
    pub order: &'static [Group],
}
impl Focus {
    pub const fn new(navigation: usize) -> Self {
        Self {
            group: Group::Content,
            navigation,
            action: 0,
            order: DEFAULT_ORDER,
        }
    }
    /// Traversal never activates. Space activates buttons, not arbitrary lists.
    /// Content and Sections are owned by the screen and return `None`.
    pub fn handle(
        &mut self,
        key: KeyPress,
        navigation: usize,
        actions: usize,
    ) -> Option<FocusEvent> {
        if matches!(key, KeyPress::Tab | KeyPress::BackTab) {
            let n = self.order.len();
            let current = self
                .order
                .iter()
                .position(|g| *g == self.group)
                .unwrap_or(1);
            let mut next = current;
            // Skip an empty action group rather than parking focus nowhere.
            for _ in 0..n {
                next = (next + if key == KeyPress::BackTab { n - 1 } else { 1 }) % n;
                if self.order[next] != Group::Actions || actions > 0 {
                    break;
                }
            }
            self.group = self.order[next];
            return Some(FocusEvent::Moved);
        }
        let (index, count) = match self.group {
            Group::Navigation => (&mut self.navigation, navigation),
            Group::Actions => (&mut self.action, actions),
            Group::Content | Group::Sections => return None,
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
    /// Bordered, ink text.
    Neutral,
    /// The one filled action on a surface.
    Primary,
    /// Destructive: red outline, never filled.
    Danger,
    /// Consequential but constructive (enroll, import): green outline.
    Accent,
}

/// List row: tint for selection, a left bar and bold label (drawn by the
/// caller), and an inset ink outline for keyboard focus. Returns the fill.
pub fn row(
    fb: &FramebufferConfig,
    rect: Rect,
    control: &Control<'_>,
    hovered: bool,
) -> render::Rgb {
    let (x, y, w, h) = rect;
    let bg = if control.selected {
        theme::SELECTED
    } else if hovered {
        theme::HOVER
    } else {
        theme::SHEET
    };
    render::fill_rect(fb, x, y, w, h.saturating_sub(1), bg);
    render::fill_rect(fb, x, y + h as i32 - 1, w, 1, theme::RULE);
    if control.selected {
        render::fill_rect(fb, x, y, 4, h.saturating_sub(1), theme::ACCENT);
    }
    if control.focused {
        render::draw_thick_border(fb, x, y, w, h, 2, theme::INK);
    }
    if control.invalid {
        render::draw_thick_border(fb, x, y, w, h, 2, theme::BAD);
    }
    bg
}

/// Compatibility name: a bordered surface used by platform integrations.
pub fn frame(
    fb: &FramebufferConfig,
    rect: Rect,
    control: &Control<'_>,
    hovered: bool,
) -> render::Rgb {
    row(fb, rect, control, hovered)
}

/// Bordered key cap such as `[F10]`. Returns its width.
pub fn keycap(fb: &FramebufferConfig, x: i32, y: i32, label: &str, on_accent: bool) -> u32 {
    let m = Metrics::for_fb(fb);
    let w = render::text_width(label, m.small) + 10;
    let h = render::font_height(m.small) + 4;
    let (bg, border, fg) = if on_accent {
        (theme::ACCENT, theme::ON_ACCENT_DIM, theme::ON_ACCENT)
    } else {
        (theme::SHEET, theme::RULE_STRONG, theme::INK)
    };
    render::fill_rect(fb, x, y, w, h, bg);
    render::draw_border(fb, x, y, w, h, border);
    render::draw_text_bold(fb, x + 5, y + 2, label, m.small, fg, Some(bg));
    w
}
pub fn keycap_width(fb: &FramebufferConfig, label: &str) -> u32 {
    render::text_width(label, Metrics::for_fb(fb).small) + 10
}

pub fn button(fb: &FramebufferConfig, rect: Rect, control: &Control<'_>, kind: ButtonKind) {
    button_with_key(fb, rect, control, kind, None);
}

/// Left-aligned label, optional key cap at the right. Focus is a 2px ink
/// ring outside the button, independent of the Primary fill.
pub fn button_with_key(
    fb: &FramebufferConfig,
    rect: Rect,
    control: &Control<'_>,
    kind: ButtonKind,
    key: Option<&str>,
) {
    let m = Metrics::for_fb(fb);
    let (x, y, w, h) = rect;
    let primary = kind == ButtonKind::Primary && control.enabled;
    let bg = if primary { theme::ACCENT } else { theme::SHEET };
    let fg = if !control.enabled {
        theme::INK3
    } else {
        match kind {
            ButtonKind::Primary => theme::ON_ACCENT,
            ButtonKind::Danger => theme::BAD,
            ButtonKind::Accent => theme::ACCENT,
            ButtonKind::Neutral => theme::INK,
        }
    };
    render::fill_rect(fb, x, y, w, h, bg);
    match kind {
        _ if !control.enabled => render::draw_border(fb, x, y, w, h, theme::RULE),
        ButtonKind::Danger => render::draw_thick_border(fb, x, y, w, h, 2, theme::BAD),
        ButtonKind::Accent => render::draw_thick_border(fb, x, y, w, h, 2, theme::ACCENT),
        ButtonKind::Primary => render::draw_border(fb, x, y, w, h, theme::ACCENT),
        ButtonKind::Neutral => render::draw_border(fb, x, y, w, h, theme::RULE_STRONG),
    }
    if control.focused {
        render::draw_thick_border(fb, x - 4, y - 4, w + 8, h + 8, 2, theme::INK);
    }
    let key_w = key.map_or(0, |k| keycap_width(fb, k) + 10);
    let text_h = render::font_height(m.body);
    let ty = y + (h.saturating_sub(text_h) / 2) as i32;
    let bold = kind != ButtonKind::Neutral || control.focused;
    let label = render::ellipsize(control.label, w.saturating_sub(28 + key_w), m.body);
    render::draw_text_weight(fb, x + 14, ty, &label, m.body, bold, fg, Some(bg));
    if let Some(k) = key {
        let kh = render::font_height(m.small) + 4;
        keycap(
            fb,
            x + w as i32 - key_w as i32 - 4,
            y + (h.saturating_sub(kh) / 2) as i32,
            k,
            primary,
        );
    }
}

/// Natural width of a button for its label and key cap.
pub fn button_width(fb: &FramebufferConfig, label: &str, key: Option<&str>) -> u32 {
    let m = Metrics::for_fb(fb);
    render::text_width(label, m.body) + 28 + key.map_or(0, |k| keycap_width(fb, k) + 14)
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
            list.2.saturating_sub(SCROLL_GUTTER),
            list.3,
            2,
            theme::INK,
        );
    }
}

/// A usable pointer target even when a boot-protocol mouse has no wheel.
pub const SCROLL_GUTTER: u32 = 24;

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

/// Thin track at the right edge of `list`, inside the scroll gutter.
pub fn scrollbar(fb: &FramebufferConfig, list: Rect, total: usize, offset: usize, slots: usize) {
    let Some((top, thumb)) = scrollbar_thumb(list.3, total, offset, slots) else {
        return;
    };
    let x = list.0 + list.2 as i32 - 8;
    render::fill_rect(fb, x, list.1, 6, list.3, theme::BAND);
    render::fill_rect(fb, x, list.1 + top as i32, 6, thumb, theme::INK3);
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
    fn sectioned_order_visits_sections_and_skips_empty_actions() {
        let mut f = Focus::new(0);
        f.order = SECTIONED_ORDER;
        f.group = Group::Navigation;
        for expected in [Group::Sections, Group::Content, Group::Navigation] {
            f.handle(KeyPress::Tab, 3, 0);
            assert_eq!(f.group, expected);
        }
        f.handle(KeyPress::BackTab, 3, 0);
        assert_eq!(f.group, Group::Content);
        assert_eq!(f.handle(KeyPress::Down, 3, 0), None);
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
