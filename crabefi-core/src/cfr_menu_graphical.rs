//! Graphical Firmware page ("Ledger"): sections | options | help pane.
//!
//! Drafts, dependency evaluation and persistence are the parent module's; this
//! file owns layout, focus and pointer handling only.

use super::*;
use crate::ui::{
    controls::{self, ButtonKind, Control, Focus, FocusEvent, Group, Role},
    dialog::{Block, Choice},
    kit::{self, Fact, StripButton, Tone},
    layout::Metrics,
};

pub(super) struct GraphicalState {
    pub(super) focus: Focus,
    /// Item index of the current section's FormHeader.
    pub(super) section: usize,
    pub(super) selected: usize,
    pub(super) hovered: Option<usize>,
    pub(super) scroll_offset: usize,
    pub(super) status_message: Option<(&'static str, bool)>,
    pub(super) save_result: Option<(usize, usize)>,
}

impl GraphicalState {
    pub(super) fn new(selected: usize) -> Self {
        let mut focus = Focus::new(ui::nav_item_index(NavItem::Firmware));
        focus.order = controls::SECTIONED_ORDER;
        Self {
            focus,
            section: 0,
            selected,
            hovered: None,
            scroll_offset: 0,
            status_message: None,
            save_result: None,
        }
    }
}

// ─── Sections ───────────────────────────────────────────────────────────

fn visible_sections(cfr: &CfrInfo, items: &[MenuItem]) -> Vec<usize> {
    items
        .iter()
        .enumerate()
        .filter(|(_, item)| {
            matches!(item, MenuItem::FormHeader { .. }) && is_item_visible(cfr, items, item)
        })
        .map(|(i, _)| i)
        .collect()
}
fn section_end(items: &[MenuItem], header: usize) -> usize {
    items
        .iter()
        .enumerate()
        .skip(header + 1)
        .find(|(_, item)| matches!(item, MenuItem::FormHeader { .. }))
        .map_or(items.len(), |(i, _)| i)
}
fn section_of(items: &[MenuItem], index: usize) -> usize {
    (0..=index.min(items.len().saturating_sub(1)))
        .rev()
        .find(|i| matches!(items[*i], MenuItem::FormHeader { .. }))
        .unwrap_or(0)
}
/// Visible rows of a section (options, subform headings and comments).
fn section_rows(cfr: &CfrInfo, items: &[MenuItem], header: usize) -> Vec<usize> {
    let start = if matches!(items.get(header), Some(MenuItem::FormHeader { .. })) {
        header + 1
    } else {
        header
    };
    (start..section_end(items, header))
        .filter(|i| is_item_visible(cfr, items, &items[*i]))
        .collect()
}
fn section_name(items: &[MenuItem], header: usize) -> &str {
    match items.get(header) {
        Some(MenuItem::FormHeader { name }) => name,
        _ => "Settings",
    }
}
fn is_changed(item: &MenuItem) -> bool {
    match item {
        MenuItem::Option {
            current_value,
            original_value,
            ..
        } => current_value != original_value,
        MenuItem::CrabLogLevel {
            current_level,
            original_level,
        } => current_level != original_level,
        _ => false,
    }
}
fn first_selectable(items: &[MenuItem], rows: &[usize]) -> Option<usize> {
    rows.iter().copied().find(|i| is_selectable(&items[*i]))
}

/// Home/End/Page movement over the selectable rows of one section.
fn graphical_page_selection(
    items: &[MenuItem],
    rows: &[usize],
    current: usize,
    key: KeyPress,
    page: usize,
) -> usize {
    let selectable: Vec<usize> = rows
        .iter()
        .copied()
        .filter(|i| is_selectable(&items[*i]))
        .collect();
    let Some(pos) = selectable.iter().position(|i| *i == current) else {
        return selectable.first().copied().unwrap_or(current);
    };
    let last = selectable.len() - 1;
    let next = match key {
        KeyPress::Home => 0,
        KeyPress::End => last,
        KeyPress::PageUp => pos.saturating_sub(page.max(1)),
        KeyPress::PageDown => (pos + page.max(1)).min(last),
        KeyPress::Up => pos.saturating_sub(1),
        KeyPress::Down => (pos + 1).min(last),
        _ => pos,
    };
    selectable[next]
}

// ─── Layout ─────────────────────────────────────────────────────────────

struct FwLayout {
    strip: Rect,
    sections: Rect,
    sec_rows_y: i32,
    options: Rect,
    rows_y: i32,
    slots: usize,
    help: Option<Rect>,
    marker_w: u32,
    label_w: u32,
}
fn fw_layout(fb: &FramebufferInfo) -> FwLayout {
    let m = Metrics::for_fb(fb);
    let (cx, cy, cw, ch) = ui::canvas(fb);
    let bottom = cy + ch as i32;
    let strip = (cx, cy, cw, kit::strip_height(fb));
    let top = cy + (strip.3 + m.gap) as i32;
    let sw = m.sections_width(cw);
    let help_w = m.help_width(cw);
    let ow = cw - sw - m.gap - help_w.map_or(0, |h| h + m.gap);
    let title_h = render::font_height(m.title) + 8;
    let head_h = render::font_height(m.small) + 12;
    let ox = cx + (sw + m.gap) as i32;
    let rows_y = top + (title_h + head_h) as i32;
    let marker_w = render::font_width(m.body) * 2 + 8;
    let label_w = (ow * 55 / 100).min(if m.large { 440 } else { 270 });
    FwLayout {
        strip,
        sections: (cx, top, sw, (bottom - top) as u32),
        sec_rows_y: top + title_h as i32,
        options: (ox, top, ow, (bottom - top) as u32),
        rows_y,
        slots: (((bottom - rows_y).max(0) as u32) / m.row).max(1) as usize,
        help: help_w.map(|h| (ox + (ow + m.gap) as i32, top, h, (bottom - top) as u32)),
        marker_w,
        label_w,
    }
}

fn keep_graphical_selection_visible(
    cfr: &CfrInfo,
    items: &[MenuItem],
    state: &mut GraphicalState,
    fb: &FramebufferInfo,
) {
    let rows = section_rows(cfr, items, state.section);
    if (!rows.contains(&state.selected) || !is_selectable(&items[state.selected]))
        && let Some(first) = first_selectable(items, &rows)
    {
        state.selected = first;
    }
    let pos = rows.iter().position(|i| *i == state.selected).unwrap_or(0);
    controls::ensure_visible(
        &mut state.scroll_offset,
        pos,
        rows.len(),
        fw_layout(fb).slots,
    );
}

// ─── Values ─────────────────────────────────────────────────────────────

fn format_value(option: &CfrOption, value: &CfrValue) -> StackString<96> {
    let mut out = StackString::new();
    match (&option.option_type, value) {
        (CfrOptionType::Bool { .. }, CfrValue::Bool(b)) => {
            let _ = out.push_str(if *b { "Enabled" } else { "Disabled" });
        }
        (CfrOptionType::Enum { choices, .. }, CfrValue::Number(n)) => {
            if let Some(choice) = choices.iter().find(|c| c.value == *n) {
                push_truncated(&mut out, &choice.ui_name, 95);
            } else {
                let _ = write!(out, "{}", n);
            }
        }
        (CfrOptionType::Number { hex_display, .. }, CfrValue::Number(n)) => {
            if *hex_display {
                let _ = write!(out, "0x{:X}", n);
            } else {
                let _ = write!(out, "{}", n);
            }
        }
        (CfrOptionType::Varchar { .. }, CfrValue::Varchar(s)) => {
            push_truncated(&mut out, s, 95);
        }
        _ => {
            let _ = out.push('-');
        }
    }
    out
}

fn truncate_for_width(text: &str, max_width: u32, size: FontSize) -> StackString<256> {
    render::ellipsize(text, max_width, size)
}

fn full_value(option: &CfrOption, value: &CfrValue) -> String {
    match (&option.option_type, value) {
        (_, CfrValue::Varchar(text)) => text.clone(),
        (CfrOptionType::Enum { choices, .. }, CfrValue::Number(n)) => {
            choices.iter().find(|c| c.value == *n).map_or_else(
                || alloc::format!("Unlisted value {n}"),
                |c| c.ui_name.clone(),
            )
        }
        _ => String::from(format_value(option, value).as_str()),
    }
}

/// (label, shown value, saved value, editable, tag)
fn row_parts(
    cfr: &CfrInfo,
    item: &MenuItem,
) -> Option<(String, String, String, bool, Option<&'static str>)> {
    match item {
        MenuItem::Option {
            form_idx,
            option_idx,
            current_value,
            original_value,
        } => {
            let option = get_option(cfr, *form_idx, *option_idx)?;
            let tag = if option.flags & cfr::CFR_OPTFLAG_INACTIVE != 0 {
                Some("unavailable")
            } else if !option.is_editable() {
                Some("read-only")
            } else {
                None
            };
            Some((
                option.ui_name.clone(),
                String::from(format_value(option, current_value).as_str()),
                full_value(option, original_value),
                option.is_editable(),
                tag,
            ))
        }
        MenuItem::CrabLogLevel {
            current_level,
            original_level,
        } => Some((
            String::from("CrabEFI log level"),
            String::from(crate::logger::level_name(*current_level)),
            String::from(crate::logger::level_name(*original_level)),
            true,
            None,
        )),
        _ => None,
    }
}

fn changed_count(items: &[MenuItem]) -> usize {
    items.iter().filter(|item| is_changed(item)).count()
}

fn changed_items<'a>(cfr: &'a CfrInfo, items: &'a [MenuItem]) -> Vec<(String, String, String)> {
    items
        .iter()
        .filter(|item| is_changed(item))
        .filter_map(|item| match item {
            MenuItem::CrabLogLevel {
                current_level,
                original_level,
            } => Some((
                String::from("CrabEFI log level"),
                String::from(crate::logger::level_name(*original_level)),
                String::from(crate::logger::level_name(*current_level)),
            )),
            MenuItem::Option {
                form_idx,
                option_idx,
                current_value,
                original_value,
            } => get_option(cfr, *form_idx, *option_idx).map(|o| {
                (
                    o.ui_name.clone(),
                    full_value(o, original_value),
                    full_value(o, current_value),
                )
            }),
            _ => None,
        })
        .collect()
}

// ─── Actions ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FwAction {
    Edit,
    Default,
    Save,
    Discard,
    Restart,
}

fn edit_label(cfr: &CfrInfo, item: &MenuItem) -> &'static str {
    match item {
        MenuItem::Option {
            form_idx,
            option_idx,
            current_value,
            ..
        } => match (
            get_option(cfr, *form_idx, *option_idx).map(|o| &o.option_type),
            current_value,
        ) {
            (Some(CfrOptionType::Bool { .. }), CfrValue::Bool(true)) => "Turn off",
            (Some(CfrOptionType::Bool { .. }), _) => "Turn on",
            (Some(CfrOptionType::Enum { .. }), _) => "Choose value...",
            _ => "Edit value...",
        },
        _ => "Choose value...",
    }
}

fn strip_actions(items: &[MenuItem], state: &GraphicalState) -> Vec<FwAction> {
    match state.save_result {
        Some((_, failed)) if failed > 0 => alloc::vec![FwAction::Save, FwAction::Discard],
        Some(_) if !has_changes(items) => alloc::vec![FwAction::Restart],
        _ if has_changes(items) => alloc::vec![FwAction::Save, FwAction::Discard],
        _ => Vec::new(),
    }
}

/// Focus order: the selected option's actions, then the page-wide strip.
fn actions(
    cfr: &CfrInfo,
    items: &[MenuItem],
    state: &GraphicalState,
    fb: &FramebufferInfo,
) -> Vec<FwAction> {
    let mut list = Vec::new();
    if fw_layout(fb).help.is_some() && can_edit_item(cfr, items, state.selected) {
        list.push(FwAction::Edit);
        list.push(FwAction::Default);
    }
    list.extend(strip_actions(items, state));
    list
}

// ─── Painting ───────────────────────────────────────────────────────────

fn paint_section_row(
    fb: &FramebufferInfo,
    l: &FwLayout,
    cfr: &CfrInfo,
    items: &[MenuItem],
    state: &GraphicalState,
    pos: usize,
    header: usize,
) {
    let m = Metrics::for_fb(fb);
    let rect = (
        l.sections.0,
        l.sec_rows_y + (pos as u32 * m.row) as i32,
        l.sections.2,
        m.row,
    );
    if rect.1 + rect.3 as i32 > l.sections.1 + l.sections.3 as i32 {
        return;
    }
    let rows = section_rows(cfr, items, header);
    let count = rows.iter().filter(|i| is_selectable(&items[**i])).count();
    let dirty = rows.iter().any(|i| is_changed(&items[*i]));
    let mut c = Control::new(header as u64, Role::Option, section_name(items, header));
    c.selected = header == state.section;
    c.focused = c.selected && state.focus.group == Group::Sections;
    let bg = controls::row(fb, rect, &c, false);
    let ty = rect.1 + ((m.row - render::font_height(m.body)) / 2) as i32;
    if dirty {
        render::draw_text_bold(fb, rect.0 + 10, ty, "*", m.body, theme::WARN, Some(bg));
    }
    let count_text = alloc::format!("{count}");
    let cw = render::text_width(&count_text, m.small);
    render::draw_text(
        fb,
        rect.0 + rect.2 as i32 - cw as i32 - 10,
        ty + 2,
        &count_text,
        m.small,
        theme::INK3,
        Some(bg),
    );
    let nx = rect.0 + 10 + render::font_width(m.body) as i32 + 6;
    render::draw_text_weight(
        fb,
        nx,
        ty,
        &render::ellipsize(
            c.label,
            (rect.0 + rect.2 as i32 - nx - cw as i32 - 18).max(0) as u32,
            m.body,
        ),
        m.body,
        c.selected,
        theme::INK,
        Some(bg),
    );
}

#[allow(clippy::too_many_arguments)]
fn draw_setting_row(
    fb: &FramebufferInfo,
    l: &FwLayout,
    cfr: &CfrInfo,
    item: &MenuItem,
    rect: Rect,
    selected: bool,
    focused: bool,
    hovered: bool,
) {
    let m = Metrics::for_fb(fb);
    let ty = rect.1 + ((rect.3 - render::font_height(m.body)) / 2) as i32;
    match item {
        MenuItem::SubformHeader { name } => {
            render::fill_rect(fb, rect.0, rect.1, rect.2, rect.3, theme::SHEET);
            render::draw_text_bold(
                fb,
                rect.0 + 4,
                rect.1 + rect.3 as i32 - m.small_line as i32 - 4,
                &truncate_for_width(name, rect.2 - 8, m.small),
                m.small,
                theme::INK3,
                Some(theme::SHEET),
            );
            render::fill_rect(
                fb,
                rect.0,
                rect.1 + rect.3 as i32 - 1,
                rect.2,
                1,
                theme::RULE,
            );
            return;
        }
        MenuItem::Comment { text } => {
            render::fill_rect(fb, rect.0, rect.1, rect.2, rect.3, theme::SHEET);
            render::draw_text(
                fb,
                rect.0 + l.marker_w as i32,
                ty + 2,
                &truncate_for_width(text, rect.2 - l.marker_w - 8, m.small),
                m.small,
                theme::INK2,
                Some(theme::SHEET),
            );
            return;
        }
        MenuItem::FormHeader { .. } => return,
        _ => {}
    }
    let Some((label, value, saved, editable, tag)) = row_parts(cfr, item) else {
        return;
    };
    let changed = is_changed(item);
    let mut c = Control::new(0, Role::Option, &label);
    c.selected = selected;
    c.focused = focused;
    c.changed = changed;
    c.read_only = !editable;
    let bg = controls::row(fb, rect, &c, hovered);
    if changed {
        render::draw_text_bold(fb, rect.0 + 10, ty, "*", m.body, theme::WARN, Some(bg));
    }
    let lx = rect.0 + l.marker_w as i32;
    let value_x = lx + l.label_w as i32 + 10;
    let label_text = truncate_for_width(&label, l.label_w.saturating_sub(4), m.body);
    let lw = render::draw_text_weight(
        fb,
        lx,
        ty,
        &label_text,
        m.body,
        selected,
        if editable { theme::INK } else { theme::INK3 },
        Some(bg),
    );
    // Dot leaders guide the eye from label to value; at least three or none.
    let fw = render::font_width(m.body) as i32;
    let dots = ((value_x - 10 - (lx + lw as i32 + 10)) / fw).max(0) as usize;
    if dots >= 3 {
        let leader: String = core::iter::repeat_n('.', dots).collect();
        render::draw_text(
            fb,
            lx + lw as i32 + 10,
            ty,
            &leader,
            m.body,
            theme::RULE_STRONG,
            Some(bg),
        );
    }
    let right = rect.0 + rect.2 as i32 - 10;
    let mut x = value_x;
    let arrows = selected && editable;
    if arrows {
        x += render::draw_text(fb, x, ty, "< ", m.body, theme::INK3, Some(bg)) as i32;
    }
    let room = (right - x - if arrows { fw * 2 } else { 0 }).max(0) as u32;
    let shown = truncate_for_width(&value, room, m.body);
    x += render::draw_text_weight(
        fb,
        x,
        ty,
        &shown,
        m.body,
        changed,
        if changed {
            theme::WARN
        } else if editable {
            theme::INK
        } else {
            theme::INK3
        },
        Some(bg),
    ) as i32;
    if arrows {
        x += render::draw_text(fb, x, ty, " >", m.body, theme::INK3, Some(bg)) as i32;
    }
    // Read-only and unavailable tags follow the value and yield to it.
    if let Some(tag) = tag {
        let tw = render::text_width(tag, m.small) + 10;
        if x + 10 + tw as i32 <= right {
            let th = render::font_height(m.small) + 2;
            let tyy = rect.1 + ((rect.3 - th) / 2) as i32;
            render::draw_border(fb, x + 10, tyy, tw, th, theme::RULE_STRONG);
            render::draw_text(fb, x + 15, tyy + 1, tag, m.small, theme::INK2, Some(bg));
        }
    }
    if changed && m.large {
        let was = alloc::format!("was {saved}");
        let room = (right - x - 16).max(0) as u32;
        if room > render::text_width("was ...", m.small) {
            render::draw_text(
                fb,
                x + 16,
                ty + 2,
                &truncate_for_width(&was, room, m.small),
                m.small,
                theme::INK3,
                Some(bg),
            );
        }
    }
}

fn row_rect(
    l: &FwLayout,
    fb: &FramebufferInfo,
    pos: usize,
    offset: usize,
    total: usize,
) -> Option<Rect> {
    let m = Metrics::for_fb(fb);
    if pos < offset || pos >= offset + l.slots {
        return None;
    }
    let gutter = if total > l.slots {
        controls::SCROLL_GUTTER
    } else {
        0
    };
    Some((
        l.options.0,
        l.rows_y + ((pos - offset) as u32 * m.row) as i32,
        l.options.2 - gutter,
        m.row,
    ))
}

fn paint_option_row(
    fb: &FramebufferInfo,
    l: &FwLayout,
    cfr: &CfrInfo,
    items: &[MenuItem],
    state: &GraphicalState,
    rows: &[usize],
    pos: usize,
) {
    let Some(rect) = row_rect(l, fb, pos, state.scroll_offset, rows.len()) else {
        return;
    };
    let index = rows[pos];
    draw_setting_row(
        fb,
        l,
        cfr,
        &items[index],
        rect,
        index == state.selected,
        index == state.selected && state.focus.group == Group::Content,
        state.hovered == Some(index),
    );
    let m = Metrics::for_fb(fb);
    if let Some(sel) = rows.iter().position(|i| *i == state.selected) {
        controls::viewport_focus(
            fb,
            (l.options.0, l.rows_y, l.options.2, l.slots as u32 * m.row),
            state.focus.group == Group::Content,
            sel,
            state.scroll_offset,
            l.slots,
        );
    }
}

fn paint_strip(
    fb: &FramebufferInfo,
    l: &FwLayout,
    cfr: &CfrInfo,
    items: &[MenuItem],
    state: &GraphicalState,
    focused: Option<FwAction>,
) -> Vec<(FwAction, Rect)> {
    let changed = changed_count(items);
    let names: Vec<String> = changed_items(cfr, items)
        .into_iter()
        .map(|(n, _, _)| n)
        .collect();
    let mut names_text = names.join(", ");
    if !names_text.is_empty() {
        names_text.push('.');
    }
    let (tone, headline, detail): (Tone, String, String) =
        match (state.save_result, state.status_message) {
            (Some((saved, failed)), _) if failed > 0 => (
                Tone::Bad,
                if saved == 0 && failed == 1 {
                    String::from("Could not save the change.")
                } else if saved == 0 {
                    alloc::format!("Could not save {failed} changes.")
                } else {
                    alloc::format!("Could not save {failed} of {} changes.", saved + failed)
                },
                String::from("Your edits are kept (starred)."),
            ),
            (Some((saved, _)), _) => (
                Tone::Ok,
                alloc::format!(
                    "Saved {saved} {}.",
                    if saved == 1 { "change" } else { "changes" }
                ),
                String::from("They apply after restart."),
            ),
            (None, Some((message, ok))) => (
                if ok {
                    if changed > 0 { Tone::Warn } else { Tone::Ok }
                } else {
                    Tone::Bad
                },
                String::from(message),
                if changed > 0 {
                    alloc::format!("{changed} unsaved: {names_text}")
                } else {
                    String::new()
                },
            ),
            (None, None) if changed > 0 => (
                Tone::Warn,
                alloc::format!(
                    "{changed} unsaved {}",
                    if changed == 1 { "change" } else { "changes" }
                ),
                names_text,
            ),
            _ => (
                Tone::Neutral,
                String::from("No unsaved changes."),
                String::from("Saved settings apply after restart."),
            ),
        };
    let acts = strip_actions(items, state);
    let buttons: Vec<StripButton<'_>> = acts
        .iter()
        .map(|a| match a {
            FwAction::Save => StripButton {
                label: if state.save_result.is_some_and(|(_, f)| f > 0) {
                    "Try again"
                } else {
                    "Save changes"
                },
                key: Some("F10"),
                kind: ButtonKind::Primary,
                focused: focused == Some(*a),
            },
            FwAction::Discard => StripButton {
                label: "Discard...",
                key: None,
                kind: ButtonKind::Neutral,
                focused: focused == Some(*a),
            },
            _ => StripButton {
                label: "Restart now",
                key: Some("R"),
                kind: ButtonKind::Primary,
                focused: focused == Some(*a),
            },
        })
        .collect();
    let rects = kit::strip(fb, l.strip, tone, &headline, &detail, &buttons, None);
    acts.into_iter().zip(rects).collect()
}

/// Title, description, facts, read-only status and when changes apply.
type HelpContent<'a> = (
    String,
    String,
    Vec<(&'a str, String)>,
    Option<String>,
    &'static str,
);

fn paint_help(
    fb: &FramebufferInfo,
    l: &FwLayout,
    cfr: &CfrInfo,
    items: &[MenuItem],
    state: &GraphicalState,
    focused: Option<FwAction>,
) -> Vec<(FwAction, Rect)> {
    let Some(rect) = l.help else {
        return Vec::new();
    };
    let m = Metrics::for_fb(fb);
    kit::side(fb, rect);
    let (hx, hy, hw, hh) = rect;
    let x = hx + m.pad as i32;
    let w = hw - m.pad * 2;
    let max_y = hy + hh as i32 - m.pad as i32;
    let Some(item) = items.get(state.selected) else {
        return Vec::new();
    };
    let changed = is_changed(item);
    let (title, help, facts_owned, status, applies): HelpContent<'_> = match item {
        MenuItem::Option {
            form_idx,
            option_idx,
            current_value,
            original_value,
        } => {
            let Some(option) = get_option(cfr, *form_idx, *option_idx) else {
                return Vec::new();
            };
            let mut facts = Vec::new();
            if changed {
                facts.push(("Unsaved", full_value(option, current_value)));
            }
            facts.push(("Saved", full_value(option, original_value)));
            facts.push((
                "Default",
                full_value(option, &CfrValue::from_option_type(&option.option_type)),
            ));
            match &option.option_type {
                CfrOptionType::Enum { choices, .. } => {
                    let list: Vec<&str> = choices.iter().map(|c| c.ui_name.as_str()).collect();
                    facts.push(("Choices", list.join(", ")));
                }
                CfrOptionType::Number { min, max, step, .. } => {
                    facts.push(("Range", alloc::format!("{min} to {max}, step {step}")));
                }
                CfrOptionType::Varchar { .. } => {
                    facts.push(("Length", String::from("Up to 255 characters")));
                }
                _ => {}
            }
            let status = if option.flags & cfr::CFR_OPTFLAG_INACTIVE != 0 {
                Some(String::from(
                    "Unavailable: the platform reports this option as inactive.",
                ))
            } else if !option.is_editable() {
                Some(String::from(
                    "Read-only: this value is supplied by firmware.",
                ))
            } else {
                None
            };
            (
                option.ui_name.clone(),
                if option.ui_helptext.is_empty() {
                    String::from("No description supplied.")
                } else {
                    option.ui_helptext.clone()
                },
                facts,
                status,
                "After restart",
            )
        }
        MenuItem::CrabLogLevel {
            current_level,
            original_level,
        } => {
            let mut facts = Vec::new();
            if changed {
                facts.push((
                    "Unsaved",
                    String::from(crate::logger::level_name(*current_level)),
                ));
            }
            facts.push((
                "Saved",
                String::from(crate::logger::level_name(*original_level)),
            ));
            facts.push((
                "Default",
                String::from(crate::logger::level_name(crate::logger::DEFAULT_LEVEL)),
            ));
            let names: Vec<&str> = crate::logger::LEVEL_CHOICES
                .iter()
                .map(|l| crate::logger::level_name(*l))
                .collect();
            facts.push(("Choices", names.join(", ")));
            (
                String::from("CrabEFI log level"),
                String::from("How much CrabEFI writes to the serial console."),
                facts,
                None,
                "When saved",
            )
        }
        _ => return Vec::new(),
    };
    let mut y = kit::caption_title(fb, x, hy + m.pad as i32, w, "Option", &title);
    y = kit::prose(fb, x, y, w, &help, m.body, theme::INK, 5) + m.gap as i32 / 2;
    let mut facts: Vec<Fact<'_>> = facts_owned
        .iter()
        .map(|(k, v)| {
            if *k == "Unsaved" {
                Fact::strong(k, v, theme::WARN)
            } else {
                Fact::new(k, v)
            }
        })
        .collect();
    facts.push(Fact::new("Applies", applies));
    y = kit::facts(fb, x, y, w, &facts, max_y) + m.gap as i32 / 2;
    if let Some(status) = status {
        return {
            kit::prose(fb, x, y, w, &status, m.body, theme::WARN, 3);
            Vec::new()
        };
    }
    let buttons = [
        StripButton {
            label: edit_label(cfr, item),
            key: Some("Enter"),
            kind: ButtonKind::Neutral,
            focused: focused == Some(FwAction::Edit),
        },
        StripButton {
            label: "Reset to default",
            key: Some("D"),
            kind: ButtonKind::Neutral,
            focused: focused == Some(FwAction::Default),
        },
    ];
    let needed = 2 * (m.button as i32 + 10);
    let rects = kit::button_stack(fb, x, y.min(max_y - needed), w, &buttons);
    alloc::vec![(FwAction::Edit, rects[0]), (FwAction::Default, rects[1])]
}

/// Paints the page. Returns clickable actions with their rectangles.
fn draw_graphical_menu(
    cfr: &CfrInfo,
    items: &[MenuItem],
    state: &GraphicalState,
    fb: &FramebufferInfo,
) -> Vec<(FwAction, Rect)> {
    ui::set_firmware_dirty(has_changes(items));
    ui::draw_shell(fb, NavItem::Firmware, &state.focus, None);
    let m = Metrics::for_fb(fb);
    let l = fw_layout(fb);
    let acts = actions(cfr, items, state, fb);
    let focused = (state.focus.group == Group::Actions)
        .then(|| acts.get(state.focus.action).copied())
        .flatten();
    let mut clickable = paint_strip(fb, &l, cfr, items, state, focused);

    // Sections column.
    let (sx, sy, sw, _) = l.sections;
    kit::pane_title(fb, sx, sy, sw, "Sections", "", false);
    for (pos, header) in visible_sections(cfr, items).into_iter().enumerate() {
        paint_section_row(fb, &l, cfr, items, state, pos, header);
    }

    // Options ledger.
    let rows = section_rows(cfr, items, state.section);
    let count = rows.iter().filter(|i| is_selectable(&items[**i])).count();
    let (ox, oy, ow, _) = l.options;
    let note = alloc::format!("{count} {}", if count == 1 { "option" } else { "options" });
    let title_h = kit::pane_title(
        fb,
        ox,
        oy,
        ow,
        section_name(items, state.section),
        &note,
        true,
    );
    kit::table_head(
        fb,
        ox,
        oy + title_h as i32,
        ow,
        &[
            ("Option", l.marker_w as i32),
            ("Value", (l.marker_w + l.label_w + 10) as i32),
        ],
    );
    for pos in state.scroll_offset..(state.scroll_offset + l.slots).min(rows.len()) {
        paint_option_row(fb, &l, cfr, items, state, &rows, pos);
    }
    if rows.is_empty() {
        render::draw_text(
            fb,
            ox + 10,
            l.rows_y + 8,
            "No options in this section.",
            m.body,
            theme::INK2,
            None,
        );
    }
    let area = (ox, l.rows_y, ow, l.slots as u32 * m.row);
    controls::scrollbar(fb, area, rows.len(), state.scroll_offset, l.slots);

    clickable.extend(paint_help(fb, &l, cfr, items, state, focused));
    let failed = state.save_result.is_some_and(|(_, f)| f > 0);
    let save = if failed { "Retry save" } else { "Save" };
    let keys: Vec<(&str, &str)> = if state.focus.group == Group::Sections {
        alloc::vec![
            ("Up Down", "Section"),
            ("Enter", "Open"),
            ("F10", save),
            ("Tab", "Next pane"),
            ("Esc", "Back to Boot"),
        ]
    } else if m.large {
        alloc::vec![
            ("Up Down", "Select"),
            ("Left Right", "Change"),
            ("Enter", "Edit"),
            ("D", "Default"),
            ("F10", save),
            ("Tab", "Next pane"),
            ("Esc", "Back to Boot"),
        ]
    } else {
        alloc::vec![
            ("Up Down", "Select"),
            ("Left Right", "Change"),
            ("Enter", "Edit"),
            ("F10", save),
            ("Tab", "Pane"),
            ("Esc", "Back to Boot"),
        ]
    };
    kit::draw_keys(fb, &keys, true);
    clickable
}

// ─── Page loop ──────────────────────────────────────────────────────────

/// Graphical platform-hook entry point, preserving the requested destination.
pub fn show_graphical_firmware_settings() -> ui::ScreenNav {
    let Some(fb) = crate::handoff::framebuffer().filter(ui::supports_framebuffer) else {
        return ui::ScreenNav::Back;
    };
    let empty = CfrInfo::new();
    show_cfr_menu_graphical(cfr::get_cfr().unwrap_or(&empty), &fb)
}

/// Character accelerators and paging belong to the content group. Save (W,
/// F10) is page-wide and never dispatched inside an editor.
fn graphical_key_allowed(group: Group, key: KeyPress) -> bool {
    group == Group::Content
        || !matches!(
            key,
            KeyPress::Home
                | KeyPress::End
                | KeyPress::PageUp
                | KeyPress::PageDown
                | KeyPress::Left
                | KeyPress::Right
                | KeyPress::Char('j' | 'k' | '+' | '=' | '-' | 'd' | 'D')
        )
}

fn hovered_item(
    cfr: &CfrInfo,
    items: &[MenuItem],
    state: &GraphicalState,
    fb: &FramebufferInfo,
) -> Option<usize> {
    let (mx, my) = crate::drivers::mouse_cursor::position();
    let l = fw_layout(fb);
    let rows = section_rows(cfr, items, state.section);
    (state.scroll_offset..(state.scroll_offset + l.slots).min(rows.len()))
        .find(|pos| {
            row_rect(&l, fb, *pos, state.scroll_offset, rows.len())
                .is_some_and(|r| dialog::contains(r, mx, my))
        })
        .map(|pos| rows[pos])
        .filter(|i| is_selectable(&items[*i]))
}

fn section_hit(
    cfr: &CfrInfo,
    items: &[MenuItem],
    fb: &FramebufferInfo,
    x: i32,
    y: i32,
) -> Option<usize> {
    let m = Metrics::for_fb(fb);
    let l = fw_layout(fb);
    let (sx, _, sw, _) = l.sections;
    if x < sx || x >= sx + sw as i32 || y < l.sec_rows_y {
        return None;
    }
    visible_sections(cfr, items)
        .get(((y - l.sec_rows_y) as u32 / m.row) as usize)
        .copied()
}

fn open_section(cfr: &CfrInfo, items: &[MenuItem], state: &mut GraphicalState, header: usize) {
    if state.section != header {
        state.section = header;
        state.scroll_offset = 0;
        let rows = section_rows(cfr, items, header);
        state.selected = first_selectable(items, &rows).unwrap_or(header);
    }
}

pub(super) fn show_cfr_menu_graphical(cfr_info: &CfrInfo, fb: &FramebufferInfo) -> ui::ScreenNav {
    let mut items = build_menu_items(cfr_info);
    if items.is_empty() {
        return show_no_options_graphical(fb);
    }
    let mut cursor = crate::cursor::CursorRenderer::new();
    let first = find_first_selectable(cfr_info, &items, 0);
    let mut state = GraphicalState::new(first);
    state.section = section_of(&items, first);
    let mut tab_hover = None;
    let mut clickable = draw_graphical_menu(cfr_info, &items, &state, fb);

    loop {
        ui::poll_and_render_cursor(fb, &mut cursor);
        let (mx, my) = crate::drivers::mouse_cursor::position();
        let next_tab = ui::navigation_hit(fb, mx, my);
        if next_tab != tab_hover {
            tab_hover = next_tab;
            cursor.while_hidden(fb, || {
                ui::draw_navigation(
                    fb,
                    NavItem::Firmware,
                    (state.focus.group == Group::Navigation).then_some(state.focus.navigation),
                    tab_hover,
                )
            });
        }
        let hovered = hovered_item(cfr_info, &items, &state, fb);
        if hovered != state.hovered {
            let previous = core::mem::replace(&mut state.hovered, hovered);
            cursor.while_hidden(fb, || {
                let l = fw_layout(fb);
                let rows = section_rows(cfr_info, &items, state.section);
                for i in previous.into_iter().chain(hovered) {
                    if let Some(pos) = rows.iter().position(|r| *r == i) {
                        paint_option_row(fb, &l, cfr_info, &items, &state, &rows, pos);
                    }
                }
            });
        }

        if let Some(mut key) = menu_common::read_key() {
            let mut viewport_only = matches!(key, KeyPress::MouseScroll(_));
            let acts = actions(cfr_info, &items, &state, fb);
            let mut action = None;
            match ui::chrome_key(fb, key, &mut state.focus, NavItem::Firmware, acts.len()) {
                Some(FocusEvent::Navigate(i)) => {
                    cursor.hide(fb);
                    let nav = ui::nav_at(i);
                    if leave_graphical(cfr_info, &mut items, &mut state, fb, destination(nav)) {
                        return ui::ScreenNav::Nav(nav);
                    }
                    clickable = cursor
                        .while_hidden(fb, || draw_graphical_menu(cfr_info, &items, &state, fb));
                    continue;
                }
                Some(FocusEvent::Moved) => {
                    if state.focus.group == Group::Content {
                        keep_graphical_selection_visible(cfr_info, &items, &mut state, fb);
                    }
                    clickable = cursor
                        .while_hidden(fb, || draw_graphical_menu(cfr_info, &items, &state, fb));
                    continue;
                }
                Some(FocusEvent::Action(i)) => action = acts.get(i).copied(),
                None => {}
            }
            if !graphical_key_allowed(state.focus.group, key) {
                continue;
            }
            if action.is_none()
                && (matches!(
                    key,
                    KeyPress::Enter | KeyPress::Char(' ' | 'w' | 'W') | KeyPress::F10
                ) || (state.focus.group == Group::Content
                    && matches!(
                        key,
                        KeyPress::Left
                            | KeyPress::Right
                            | KeyPress::Char('+' | '=' | '-' | 'd' | 'D')
                    )))
            {
                state.status_message = None;
                if !matches!(key, KeyPress::F10 | KeyPress::Char('w' | 'W')) {
                    state.save_result = None;
                }
            }
            if state.focus.group == Group::Sections {
                let sections = visible_sections(cfr_info, &items);
                let pos = sections
                    .iter()
                    .position(|h| *h == state.section)
                    .unwrap_or(0);
                match key {
                    KeyPress::Up | KeyPress::Char('k') => {
                        let header = sections[pos.saturating_sub(1)];
                        open_section(cfr_info, &items, &mut state, header);
                        key = KeyPress::Char('\0');
                    }
                    KeyPress::Down | KeyPress::Char('j') => {
                        let header = sections[(pos + 1).min(sections.len() - 1)];
                        open_section(cfr_info, &items, &mut state, header);
                        key = KeyPress::Char('\0');
                    }
                    KeyPress::Enter | KeyPress::Char(' ') | KeyPress::Right => {
                        state.focus.group = Group::Content;
                        key = KeyPress::Char('\0');
                    }
                    _ => {}
                }
            }
            let mut activated = action;
            if let Some(action) = action {
                cursor.hide(fb);
                match action {
                    FwAction::Edit => edit_graphical_item(cfr_info, &mut items, &mut state, fb),
                    FwAction::Default => {
                        restore_graphical_default(cfr_info, &mut items, &mut state)
                    }
                    FwAction::Save => save_graphical_changes(cfr_info, &mut items, &mut state),
                    FwAction::Discard => discard_graphical(cfr_info, &mut items, &mut state, fb),
                    FwAction::Restart => {
                        let backdrop = || {
                            draw_graphical_menu(cfr_info, &items, &state, fb);
                        };
                        ui::confirm_reset(fb, &backdrop);
                    }
                }
                key = KeyPress::Char('\0');
            }
            let content = state.focus.group == Group::Content;
            match key {
                KeyPress::Up | KeyPress::Down | KeyPress::Char('j' | 'k') if content => {
                    let rows = section_rows(cfr_info, &items, state.section);
                    let k = if matches!(key, KeyPress::Up | KeyPress::Char('k')) {
                        KeyPress::Up
                    } else {
                        KeyPress::Down
                    };
                    state.selected = graphical_page_selection(&items, &rows, state.selected, k, 1);
                }
                key @ (KeyPress::Home | KeyPress::End | KeyPress::PageUp | KeyPress::PageDown)
                    if content =>
                {
                    let rows = section_rows(cfr_info, &items, state.section);
                    state.selected = graphical_page_selection(
                        &items,
                        &rows,
                        state.selected,
                        key,
                        fw_layout(fb).slots,
                    );
                }
                KeyPress::Enter | KeyPress::Char(' ') if content => {
                    cursor.hide(fb);
                    edit_graphical_item(cfr_info, &mut items, &mut state, fb);
                }
                KeyPress::Right | KeyPress::Char('+' | '=') if content => {
                    if !increment_option(cfr_info, &mut items, state.selected) {
                        state.status_message = Some(("This option cannot be changed.", false));
                    }
                }
                KeyPress::Left | KeyPress::Char('-') if content => {
                    if !decrement_option(cfr_info, &mut items, state.selected) {
                        state.status_message = Some(("This option cannot be changed.", false));
                    }
                }
                KeyPress::F10 | KeyPress::Char('w' | 'W') => {
                    save_graphical_changes(cfr_info, &mut items, &mut state);
                }
                #[cfg(feature = "secure-boot")]
                KeyPress::Char('s' | 'S') => {
                    cursor.hide(fb);
                    if leave_graphical(
                        cfr_info,
                        &mut items,
                        &mut state,
                        fb,
                        destination(NavItem::Security),
                    ) {
                        return ui::ScreenNav::Nav(NavItem::Security);
                    }
                }
                KeyPress::Char('f' | 'F') => {}
                KeyPress::Char('r' | 'R') => {
                    cursor.hide(fb);
                    if leave_graphical(cfr_info, &mut items, &mut state, fb, Destination::Restart) {
                        let backdrop = || {
                            draw_graphical_menu(cfr_info, &items, &state, fb);
                        };
                        ui::confirm_reset(fb, &backdrop);
                    }
                }
                KeyPress::Escape | KeyPress::Char('b' | 'B' | 'q' | 'Q') => {
                    cursor.hide(fb);
                    if leave_graphical(
                        cfr_info,
                        &mut items,
                        &mut state,
                        fb,
                        destination(NavItem::Boot),
                    ) {
                        return ui::ScreenNav::Back;
                    }
                }
                KeyPress::Char('?') => {
                    cursor.hide(fb);
                    help_graphical_item(cfr_info, &mut items, &mut state, fb);
                }
                KeyPress::Char('d' | 'D') if content => {
                    restore_graphical_default(cfr_info, &mut items, &mut state);
                }
                KeyPress::MouseClick { x, y } => {
                    cursor.hide(fb);
                    let (x, y) = (x as i32, y as i32);
                    let l = fw_layout(fb);
                    let rows = section_rows(cfr_info, &items, state.section);
                    let area = (
                        l.options.0,
                        l.rows_y,
                        l.options.2,
                        l.slots as u32 * Metrics::for_fb(fb).row,
                    );
                    if controls::scroll_track(
                        &mut state.scroll_offset,
                        area,
                        (x, y),
                        rows.len(),
                        l.slots,
                    ) {
                        viewport_only = true;
                    } else if let Some((action, _)) = clickable
                        .iter()
                        .find(|(_, r)| dialog::contains(*r, x, y))
                        .copied()
                    {
                        activated = Some(action);
                        let acts = actions(cfr_info, &items, &state, fb);
                        if let Some(i) = acts.iter().position(|a| *a == action) {
                            state.focus.group = Group::Actions;
                            state.focus.action = i;
                        }
                        state.status_message = None;
                        if action != FwAction::Save {
                            state.save_result = None;
                        }
                        match action {
                            FwAction::Edit => {
                                edit_graphical_item(cfr_info, &mut items, &mut state, fb)
                            }
                            FwAction::Default => {
                                restore_graphical_default(cfr_info, &mut items, &mut state)
                            }
                            FwAction::Save => {
                                save_graphical_changes(cfr_info, &mut items, &mut state)
                            }
                            FwAction::Discard => {
                                discard_graphical(cfr_info, &mut items, &mut state, fb)
                            }
                            FwAction::Restart => {
                                let backdrop = || {
                                    draw_graphical_menu(cfr_info, &items, &state, fb);
                                };
                                ui::confirm_reset(fb, &backdrop);
                            }
                        }
                    } else if let Some(header) = section_hit(cfr_info, &items, fb, x, y) {
                        open_section(cfr_info, &items, &mut state, header);
                        state.focus.group = Group::Sections;
                    } else if let Some(item_idx) = hovered_item(cfr_info, &items, &state, fb) {
                        state.selected = item_idx;
                        state.focus.group = Group::Content;
                    }
                }
                KeyPress::MouseScroll(dz) => {
                    let rows = section_rows(cfr_info, &items, state.section);
                    controls::scroll(
                        &mut state.scroll_offset,
                        dz,
                        rows.len(),
                        fw_layout(fb).slots,
                    );
                }
                _ => {}
            }
            // Dependencies may hide the section or the selected option.
            let sections = visible_sections(cfr_info, &items);
            if !sections.contains(&state.section)
                && let Some(first) = sections.first()
            {
                open_section(cfr_info, &items, &mut state, *first);
            }
            if !viewport_only {
                keep_graphical_selection_visible(cfr_info, &items, &mut state, fb);
            }
            let acts = actions(cfr_info, &items, &state, fb);
            // An action that replaced itself (Save -> Restart now) must not
            // hand its focus to a different, consequential button.
            if state.focus.group == Group::Actions
                && (acts.is_empty()
                    || activated.is_some_and(|a| acts.get(state.focus.action) != Some(&a)))
            {
                state.focus.group = Group::Content;
            }
            state.focus.action = state.focus.action.min(acts.len().saturating_sub(1));
            clickable =
                cursor.while_hidden(fb, || draw_graphical_menu(cfr_info, &items, &state, fb));
            tab_hover = None;
        }
        delay_ms(8);
    }
}

// ─── Operations ─────────────────────────────────────────────────────────

fn save_graphical_changes(cfr: &CfrInfo, items: &mut [MenuItem], state: &mut GraphicalState) {
    if !has_changes(items) {
        state.status_message = Some(("Nothing to save.", true));
        return;
    }
    state.save_result = Some(save_all_changes(cfr, items));
    state.status_message = None;
}

/// Restore only unsaved drafts; successful writes in a partial save remain saved.
fn discard_graphical_changes(items: &mut [MenuItem]) {
    for item in items {
        match item {
            MenuItem::Option {
                current_value,
                original_value,
                ..
            } => *current_value = original_value.clone(),
            MenuItem::CrabLogLevel {
                current_level,
                original_level,
            } => *current_level = *original_level,
            _ => {}
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Destination {
    Page(&'static str),
    Restart,
}
fn destination(nav: NavItem) -> Destination {
    Destination::Page(match nav {
        NavItem::Boot => "the Boot page",
        #[cfg(feature = "secure-boot")]
        NavItem::Security => "the Security page",
        NavItem::Firmware => "Firmware",
    })
}

/// Changes listed name by name, capped so instructions always stay visible.
fn change_blocks(cfr: &CfrInfo, items: &[MenuItem], cap: usize) -> Vec<Block> {
    let changes = changed_items(cfr, items);
    let mut blocks: Vec<Block> = changes
        .iter()
        .take(cap)
        .map(|(name, from, to)| Block::change(name, from, to))
        .collect();
    if changes.len() > cap {
        blocks.push(Block::muted(&alloc::format!(
            "and {} more",
            changes.len() - cap
        )));
    }
    blocks
}

fn leave_graphical(
    cfr: &CfrInfo,
    items: &mut [MenuItem],
    state: &mut GraphicalState,
    fb: &FramebufferInfo,
    to: Destination,
) -> bool {
    if !has_changes(items) {
        return true;
    }
    let n = changed_count(items);
    let noun = if n == 1 { "change" } else { "changes" };
    let (title, lead, discard, save) = match to {
        Destination::Page(page) => (
            alloc::format!("Leave Firmware with {n} unsaved {noun}?"),
            alloc::format!("You are going to {page}. These changes are not saved yet:"),
            "Discard changes",
            "Save and leave",
        ),
        Destination::Restart => (
            alloc::format!("Restart with {n} unsaved {noun}?"),
            String::from("You are restarting the computer. These changes are not saved yet:"),
            "Discard and restart",
            "Save and restart",
        ),
    };
    let mut content = alloc::vec![Block::text(&lead)];
    content.extend(change_blocks(
        cfr,
        items,
        if Metrics::for_fb(fb).large { 8 } else { 5 },
    ));
    content.push(Block::muted("Saved changes apply after restart."));
    let choice = {
        let snapshot: &[MenuItem] = items;
        let st: &GraphicalState = state;
        let backdrop = || {
            draw_graphical_menu(cfr, snapshot, st, fb);
        };
        dialog::modal(
            fb,
            &backdrop,
            Tone::Warn,
            &title,
            &content,
            &[
                Choice::new("Keep editing", Some("Esc"), ButtonKind::Neutral),
                Choice::new(discard, None, ButtonKind::Neutral),
                Choice::new(save, Some("F10"), ButtonKind::Primary),
            ],
        )
    };
    match choice {
        1 => {
            discard_graphical_changes(items);
            state.status_message = Some(("Unsaved changes discarded.", true));
            ui::set_firmware_dirty(false);
            true
        }
        2 => {
            save_graphical_changes(cfr, items, state);
            let done = !has_changes(items);
            ui::set_firmware_dirty(!done);
            done
        }
        _ => false,
    }
}

fn discard_graphical(
    cfr: &CfrInfo,
    items: &mut [MenuItem],
    state: &mut GraphicalState,
    fb: &FramebufferInfo,
) {
    let n = changed_count(items);
    if n == 0 {
        return;
    }
    let mut content = alloc::vec![Block::text(
        "These unsaved values return to their saved settings:"
    )];
    content.extend(change_blocks(cfr, items, 6));
    let choice = {
        let snapshot: &[MenuItem] = items;
        let st: &GraphicalState = state;
        let backdrop = || {
            draw_graphical_menu(cfr, snapshot, st, fb);
        };
        dialog::modal(
            fb,
            &backdrop,
            Tone::Warn,
            &alloc::format!(
                "Discard {n} unsaved {}?",
                if n == 1 { "change" } else { "changes" }
            ),
            &content,
            &[
                Choice::new("Cancel", Some("Esc"), ButtonKind::Neutral),
                Choice::new("Discard changes", None, ButtonKind::Danger),
            ],
        )
    };
    if choice == 1 {
        discard_graphical_changes(items);
        state.save_result = None;
        state.status_message = Some(("Unsaved changes discarded.", true));
    }
}

fn help_graphical_item(
    cfr: &CfrInfo,
    items: &mut [MenuItem],
    state: &mut GraphicalState,
    fb: &FramebufferInfo,
) {
    let Some(item) = items.get(state.selected) else {
        return;
    };
    let mut content = Vec::new();
    let title = match item {
        MenuItem::Option {
            form_idx,
            option_idx,
            current_value,
            original_value,
        } => {
            let Some(option) = get_option(cfr, *form_idx, *option_idx) else {
                return;
            };
            content.push(Block::text(if option.ui_helptext.is_empty() {
                "No description supplied."
            } else {
                &option.ui_helptext
            }));
            if is_changed(item) {
                content.push(Block::strong_fact(
                    "Unsaved",
                    &full_value(option, current_value),
                ));
            }
            content.push(Block::fact("Saved", &full_value(option, original_value)));
            content.push(Block::fact(
                "Default",
                &full_value(option, &CfrValue::from_option_type(&option.option_type)),
            ));
            if let CfrOptionType::Number { min, max, step, .. } = option.option_type {
                content.push(Block::fact(
                    "Range",
                    &alloc::format!("{min} to {max}, step {step}"),
                ));
            }
            if !option.is_editable() {
                content.push(Block::muted(
                    "Read-only: this value is supplied by firmware.",
                ));
            }
            option.ui_name.clone()
        }
        MenuItem::CrabLogLevel {
            current_level,
            original_level,
        } => {
            content.push(Block::text(
                "How much CrabEFI writes to the serial console. Applies when saved.",
            ));
            content.push(Block::fact(
                "Current",
                crate::logger::level_name(*current_level),
            ));
            content.push(Block::fact(
                "Saved",
                crate::logger::level_name(*original_level),
            ));
            content.push(Block::fact(
                "Default",
                crate::logger::level_name(crate::logger::DEFAULT_LEVEL),
            ));
            String::from("CrabEFI log level")
        }
        _ => return,
    };
    let editable = can_edit_item(cfr, items, state.selected);
    let choice = {
        let snapshot: &[MenuItem] = items;
        let st: &GraphicalState = state;
        let backdrop = || {
            draw_graphical_menu(cfr, snapshot, st, fb);
        };
        let close = [Choice::new("Close", Some("Esc"), ButtonKind::Neutral)];
        let with_default = [
            Choice::new("Close", Some("Esc"), ButtonKind::Neutral),
            Choice::new("Reset to default", None, ButtonKind::Neutral),
        ];
        dialog::modal(
            fb,
            &backdrop,
            Tone::Neutral,
            &title,
            &content,
            if editable { &with_default } else { &close },
        )
    };
    if choice == 1 {
        restore_graphical_default(cfr, items, state);
    }
}

fn restore_graphical_default(cfr: &CfrInfo, items: &mut [MenuItem], state: &mut GraphicalState) {
    state.save_result = None;
    if !can_edit_item(cfr, items, state.selected) {
        state.status_message = Some((
            "Read-only or unavailable; the default cannot be applied.",
            false,
        ));
        return;
    }
    match items.get_mut(state.selected) {
        Some(MenuItem::CrabLogLevel { current_level, .. }) => {
            *current_level = crate::logger::DEFAULT_LEVEL;
        }
        Some(MenuItem::Option {
            form_idx,
            option_idx,
            current_value,
            ..
        }) => {
            let Some(option) = get_option(cfr, *form_idx, *option_idx) else {
                return;
            };
            *current_value = CfrValue::from_option_type(&option.option_type);
        }
        _ => return,
    }
    state.status_message = Some(("Default value set; save to keep it.", true));
}

/// Numeric editors accept an explicit decimal or 0x-prefixed hexadecimal value.
fn parse_graphical_number(text: &str, min: u32, max: u32, step: u32) -> Result<u32, &'static str> {
    let text = text.trim();
    let n = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        text.parse::<u32>()
    }
    .map_err(|_| "Enter a decimal number or 0x-prefixed hexadecimal.")?;
    if n < min || n > max {
        return Err("Value is outside the allowed range.");
    }
    if step > 1 && !(n - min).is_multiple_of(step) {
        return Err("Value must match the step from the minimum.");
    }
    Ok(n)
}

/// The selected row, as the anchor for pickers and field editors.
fn selected_anchor(
    cfr: &CfrInfo,
    items: &[MenuItem],
    state: &GraphicalState,
    fb: &FramebufferInfo,
) -> Option<Rect> {
    let l = fw_layout(fb);
    let rows = section_rows(cfr, items, state.section);
    let pos = rows.iter().position(|i| *i == state.selected)?;
    row_rect(&l, fb, pos, state.scroll_offset, rows.len())
}

fn choice_tags(
    saved: Option<usize>,
    default: Option<usize>,
    current: usize,
) -> Vec<(usize, &'static str)> {
    let mut tags = Vec::new();
    match (saved, default) {
        (Some(s), Some(d)) if s == d => tags.push((s, "saved, default")),
        (s, d) => {
            if let Some(s) = s {
                tags.push((s, "saved"));
            }
            if let Some(d) = d {
                tags.push((d, "default"));
            }
        }
    }
    if saved != Some(current) && !tags.iter().any(|(i, _)| *i == current) {
        tags.push((current, "unsaved"));
    }
    tags
}

fn edit_graphical_item(
    cfr: &CfrInfo,
    items: &mut [MenuItem],
    state: &mut GraphicalState,
    fb: &FramebufferInfo,
) {
    if !can_edit_item(cfr, items, state.selected) {
        state.status_message = Some((
            "Read-only or unavailable; see the help pane for the reason.",
            false,
        ));
        return;
    }
    let anchor = selected_anchor(cfr, items, state, fb);
    // Painting the backdrop needs an immutable view; edit afterwards.
    let result: Option<EditResult> = {
        let snapshot: &[MenuItem] = items;
        let st: &GraphicalState = state;
        let backdrop = || {
            draw_graphical_menu(cfr, snapshot, st, fb);
        };
        match snapshot.get(st.selected) {
            Some(MenuItem::CrabLogLevel {
                current_level,
                original_level,
            }) => {
                let labels: Vec<&str> = crate::logger::LEVEL_CHOICES
                    .iter()
                    .map(|level| crate::logger::level_name(*level))
                    .collect();
                let current = crate::logger::level_index(*current_level);
                let tags = choice_tags(
                    Some(crate::logger::level_index(*original_level)),
                    Some(crate::logger::level_index(crate::logger::DEFAULT_LEVEL)),
                    current,
                );
                dialog::select(
                    fb,
                    &backdrop,
                    anchor,
                    "CrabEFI log level",
                    &labels,
                    current,
                    &tags,
                )
                .map(EditResult::Level)
            }
            Some(MenuItem::Option {
                form_idx,
                option_idx,
                current_value,
                original_value,
            }) => {
                let Some(option) = get_option(cfr, *form_idx, *option_idx) else {
                    return;
                };
                match (&option.option_type, current_value) {
                    (CfrOptionType::Bool { .. }, CfrValue::Bool(value)) => {
                        Some(EditResult::Bool(!*value))
                    }
                    (CfrOptionType::Enum { choices, .. }, CfrValue::Number(value)) => {
                        let current = choices.iter().position(|c| c.value == *value);
                        let unknown = alloc::format!("Unlisted value {value} (keep unchanged)");
                        let mut labels: Vec<&str> =
                            choices.iter().map(|c| c.ui_name.as_str()).collect();
                        let extra = usize::from(current.is_none());
                        if extra > 0 {
                            labels.insert(0, &unknown);
                        }
                        let saved = match original_value {
                            CfrValue::Number(n) => choices
                                .iter()
                                .position(|c| c.value == *n)
                                .map(|i| i + extra),
                            _ => None,
                        };
                        let default = match CfrValue::from_option_type(&option.option_type) {
                            CfrValue::Number(n) => {
                                choices.iter().position(|c| c.value == n).map(|i| i + extra)
                            }
                            _ => None,
                        };
                        let current_pos = current.map_or(0, |i| i + extra);
                        let tags = choice_tags(saved, default, current_pos);
                        dialog::select(
                            fb,
                            &backdrop,
                            anchor,
                            &option.ui_name,
                            &labels,
                            current_pos,
                            &tags,
                        )
                        .and_then(|i| i.checked_sub(extra))
                        .and_then(|i| choices.get(i))
                        .map(|c| EditResult::Number(c.value))
                    }
                    (CfrOptionType::Number { min, max, step, .. }, CfrValue::Number(value)) => {
                        let hint =
                            alloc::format!("Range {min} to {max}, step {step}. Decimal or 0x hex.");
                        dialog::input(
                            fb,
                            &backdrop,
                            anchor,
                            &option.ui_name,
                            &hint,
                            &alloc::format!("{value}"),
                            32,
                            |s| parse_graphical_number(s, *min, *max, *step).map(|_| ()),
                        )
                        .and_then(|text| parse_graphical_number(&text, *min, *max, *step).ok())
                        .map(EditResult::Number)
                    }
                    (CfrOptionType::Varchar { .. }, CfrValue::Varchar(value)) => dialog::input(
                        fb,
                        &backdrop,
                        anchor,
                        &option.ui_name,
                        "Text, up to 255 characters. Ctrl+U clears the field.",
                        value,
                        255,
                        |_| Ok(()),
                    )
                    .map(EditResult::Text),
                    _ => {
                        return;
                    }
                }
            }
            _ => None,
        }
    };
    let Some(result) = result else {
        return;
    };
    match (items.get_mut(state.selected), result) {
        (Some(MenuItem::CrabLogLevel { current_level, .. }), EditResult::Level(i)) => {
            *current_level = crate::logger::LEVEL_CHOICES[i];
        }
        (Some(MenuItem::Option { current_value, .. }), result) => match (current_value, result) {
            (CfrValue::Bool(v), EditResult::Bool(n)) => *v = n,
            (CfrValue::Number(v), EditResult::Number(n)) => *v = n,
            (CfrValue::Varchar(v), EditResult::Text(t)) => *v = t,
            _ => {}
        },
        _ => {}
    }
}

enum EditResult {
    Level(usize),
    Bool(bool),
    Number(u32),
    Text(String),
}

fn show_no_options_graphical(fb: &FramebufferInfo) -> ui::ScreenNav {
    ui::empty_screen(
        fb,
        NavItem::Firmware,
        "No settings available",
        "This platform did not supply configurable settings.",
    )
}

#[cfg(test)]
mod graphical_tests {
    use super::*;
    use crate::cfr::{CfrForm, OptionStore};
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn option(id: u64) -> CfrOption {
        CfrOption {
            object_id: id,
            dependency_id: 0,
            opt_name: alloc::format!("ui_regression_{id}"),
            ui_name: alloc::format!("Option {id}"),
            ui_helptext: String::new(),
            flags: 0,
            option_type: CfrOptionType::Bool { default: false },
            dep_values: Vec::new(),
        }
    }
    fn framebuffer(pixels: &mut [u32], width: u32, height: u32) -> FramebufferInfo {
        FramebufferInfo {
            physical_address: pixels.as_mut_ptr() as u64,
            width,
            height,
            stride: width,
            bits_per_pixel: 32,
            red_mask_pos: 16,
            red_mask_size: 8,
            green_mask_pos: 8,
            green_mask_size: 8,
            blue_mask_pos: 0,
            blue_mask_size: 8,
        }
    }

    #[test]
    fn changed_log_level_has_a_visible_dirty_marker_even_when_value_is_identical() {
        let mut clean_pixels = std::vec![0u32; 1024 * 768];
        let mut dirty_pixels = clean_pixels.clone();
        let clean = MenuItem::CrabLogLevel {
            current_level: log::LevelFilter::Info,
            original_level: log::LevelFilter::Info,
        };
        let dirty = MenuItem::CrabLogLevel {
            current_level: log::LevelFilter::Info,
            original_level: log::LevelFilter::Debug,
        };
        let cfr = CfrInfo::new();
        for (item, pixels) in [(&clean, &mut clean_pixels), (&dirty, &mut dirty_pixels)] {
            let fb = framebuffer(pixels, 1024, 768);
            let l = fw_layout(&fb);
            draw_setting_row(&fb, &l, &cfr, item, (240, 200, 460, 34), true, true, false);
        }
        assert_ne!(
            clean_pixels, dirty_pixels,
            "dirty marker must be rendered, independently of the displayed value"
        );
    }

    #[test]
    fn long_unsaved_lists_cannot_hide_the_decision() {
        let cfr = CfrInfo {
            version: 0,
            forms: alloc::vec![CfrForm {
                object_id: 10,
                dependency_id: 0,
                ui_name: String::from("Test"),
                flags: 0,
                options: (1..=30).map(option).collect(),
                dep_values: Vec::new(),
            }],
        };
        let items: Vec<_> = (0..30)
            .map(|i| MenuItem::Option {
                form_idx: 0,
                option_idx: i,
                current_value: CfrValue::Bool(true),
                original_value: CfrValue::Bool(false),
            })
            .collect();
        let blocks = change_blocks(&cfr, &items, 5);
        assert_eq!(blocks.len(), 6);
        assert!(matches!(&blocks[5], Block::Muted(text) if text == "and 25 more"));
    }

    #[test]
    fn paging_and_content_accelerators_cannot_retarget_other_focus_groups() {
        for group in [Group::Navigation, Group::Actions, Group::Sections] {
            for key in [
                KeyPress::Char('d'),
                KeyPress::Char('+'),
                KeyPress::PageDown,
                KeyPress::PageUp,
                KeyPress::Left,
            ] {
                assert!(!graphical_key_allowed(group, key));
                assert!(graphical_key_allowed(Group::Content, key));
            }
            assert!(graphical_key_allowed(group, KeyPress::Char('w')));
            assert!(graphical_key_allowed(group, KeyPress::F10));
        }
    }

    #[test]
    fn shortcuts_stay_on_the_editors_step_grid_without_overflow() {
        assert_eq!(stepped_number(10, 0, 12, 5, true), None);
        assert_eq!(stepped_number(12, 0, 12, 5, false), Some(10));
        assert_eq!(stepped_number(8, 2, 12, 5, true), Some(12));
        assert_eq!(stepped_number(8, 2, 12, 5, false), Some(7));
        assert_eq!(
            stepped_number(u32::MAX, u32::MAX - 1, u32::MAX, 5, false),
            Some(u32::MAX - 1)
        );
        assert_eq!(stepped_number(u32::MAX, 0, u32::MAX, 1, true), None);
        assert_eq!(stepped_number(0, 0, 12, 0, true), Some(1));
        for n in 0..=12 {
            for forward in [false, true] {
                if let Some(next) = stepped_number(n, 0, 12, 5, forward) {
                    assert!(parse_graphical_number(&alloc::format!("{next}"), 0, 12, 5).is_ok());
                }
            }
        }
    }

    #[test]
    fn long_help_text_is_capacity_aware_and_ascii_truncated() {
        let text = "Description ".repeat(30);
        let label = truncate_for_width(&text, 1800, FontSize::Small);
        assert!(label.starts_with("Description "));
        assert!(label.ends_with("..."));
        assert!(label.is_ascii() && label.len() <= 256);
    }

    #[test]
    fn log_level_default_updates_the_draft_and_feedback() {
        let cfr = CfrInfo::new();
        let mut items = alloc::vec![MenuItem::CrabLogLevel {
            current_level: log::LevelFilter::Trace,
            original_level: log::LevelFilter::Trace,
        }];
        let mut state = GraphicalState::new(0);
        restore_graphical_default(&cfr, &mut items, &mut state);
        assert!(
            matches!(items[0], MenuItem::CrabLogLevel { current_level, original_level }
            if current_level == crate::logger::DEFAULT_LEVEL && original_level == log::LevelFilter::Trace)
        );
        assert!(state.status_message.is_some_and(|(_, ok)| ok));
    }

    #[test]
    fn number_editor_validates_radix_bounds_step_and_overflow() {
        assert_eq!(parse_graphical_number("0x19", 0, 120, 5), Ok(25));
        assert_eq!(parse_graphical_number("25", 0, 120, 5), Ok(25));
        assert_eq!(parse_graphical_number("0XFF", 0, 255, 1), Ok(255));
        for text in ["", "-1", "999", "13", "4294967296", "abc"] {
            assert!(parse_graphical_number(text, 0, 120, 5).is_err(), "{text}");
        }
        assert_eq!(
            parse_graphical_number("4294967295", 0, u32::MAX, 1),
            Ok(u32::MAX)
        );
        assert_eq!(parse_graphical_number("7", 2, 12, 5), Ok(7));
    }

    #[test]
    fn discard_restores_unsaved_values_only() {
        let mut items = alloc::vec![
            MenuItem::Option {
                form_idx: 0,
                option_idx: 0,
                current_value: CfrValue::Bool(true),
                original_value: CfrValue::Bool(true)
            },
            MenuItem::Option {
                form_idx: 0,
                option_idx: 1,
                current_value: CfrValue::Bool(false),
                original_value: CfrValue::Bool(true)
            },
            MenuItem::CrabLogLevel {
                current_level: log::LevelFilter::Trace,
                original_level: log::LevelFilter::Info
            },
        ];
        discard_graphical_changes(&mut items);
        assert!(!has_changes(&items));
        assert!(matches!(
            items[1],
            MenuItem::Option {
                current_value: CfrValue::Bool(true),
                ..
            }
        ));
        assert!(matches!(
            items[2],
            MenuItem::CrabLogLevel {
                current_level: log::LevelFilter::Info,
                ..
            }
        ));
    }

    fn two_sections() -> (CfrInfo, Vec<MenuItem>) {
        let mut options: Vec<_> = (1..=40).map(option).collect();
        options[20].dependency_id = 1;
        let cfr = CfrInfo {
            version: 0,
            forms: alloc::vec![
                CfrForm {
                    object_id: 100,
                    dependency_id: 0,
                    ui_name: String::from("First"),
                    flags: 0,
                    options,
                    dep_values: Vec::new(),
                },
                CfrForm {
                    object_id: 101,
                    dependency_id: 0,
                    ui_name: String::from("Second"),
                    flags: 0,
                    options: alloc::vec![option(50)],
                    dep_values: Vec::new(),
                }
            ],
        };
        let mut items = alloc::vec![MenuItem::FormHeader {
            name: String::from("First")
        }];
        items.extend((0..40).map(|i| MenuItem::Option {
            form_idx: 0,
            option_idx: i,
            current_value: CfrValue::Bool(false),
            original_value: CfrValue::Bool(false),
        }));
        items.push(MenuItem::FormHeader {
            name: String::from("Second"),
        });
        items.push(MenuItem::Option {
            form_idx: 1,
            option_idx: 0,
            current_value: CfrValue::Bool(false),
            original_value: CfrValue::Bool(false),
        });
        (cfr, items)
    }

    #[test]
    fn page_navigation_stays_in_its_section_and_skips_hidden_dependencies() {
        let (cfr, items) = two_sections();
        let rows = section_rows(&cfr, &items, 0);
        assert!(
            !rows.contains(&21),
            "option 21 depends on disabled option 1"
        );
        assert!(
            !rows.contains(&42),
            "the next section is not part of this one"
        );
        assert_eq!(
            graphical_page_selection(&items, &rows, 30, KeyPress::Home, 5),
            1
        );
        assert_eq!(
            graphical_page_selection(&items, &rows, 1, KeyPress::End, 5),
            40
        );
        assert_eq!(
            graphical_page_selection(&items, &rows, 1, KeyPress::PageDown, 5),
            6
        );
        assert_eq!(
            graphical_page_selection(&items, &rows, 20, KeyPress::Down, 1),
            22
        );
        assert_eq!(
            graphical_page_selection(&items, &rows, 1, KeyPress::PageUp, 5),
            1
        );
        assert_eq!(visible_sections(&cfr, &items), [0, 41]);
        assert_eq!(section_of(&items, 42), 41);
    }

    #[test]
    fn x61_layout_fits_three_panes_and_rows() {
        let fb = framebuffer(&mut [], 1024, 768);
        let l = fw_layout(&fb);
        assert!(l.help.is_some());
        assert!(l.slots >= 12, "{}", l.slots);
        assert!(l.options.2 >= 400);
        let narrow = framebuffer(&mut [], 640, 480);
        assert!(fw_layout(&narrow).help.is_none());
    }

    #[test]
    fn hover_repaint_matches_full_repaint() {
        let (cfr, items) = two_sections();
        let (width, height) = (1024, 768);
        let mut pixels = std::vec![0; width as usize * height as usize];
        let fb = framebuffer(&mut pixels, width, height);
        let mut state = GraphicalState::new(3);
        draw_graphical_menu(&cfr, &items, &state, &fb);
        let l = fw_layout(&fb);
        let rows = section_rows(&cfr, &items, 0);
        state.hovered = Some(5);
        paint_option_row(&fb, &l, &cfr, &items, &state, &rows, 4);
        let mut expected = std::vec![0; pixels.len()];
        draw_graphical_menu(
            &cfr,
            &items,
            &state,
            &framebuffer(&mut expected, width, height),
        );
        assert!(pixels == expected);
    }

    #[test]
    fn hidden_dependencies_are_read_once_per_session_not_per_poll() {
        install_store();
        let mut hidden = option(900);
        hidden.opt_name = String::from("ui_hidden_900");
        hidden.flags = cfr::CFR_OPTFLAG_SUPPRESS;
        let mut dependent: Vec<_> = (1..=10).map(option).collect();
        for o in &mut dependent {
            o.dependency_id = 900;
        }
        let mut options = alloc::vec![hidden];
        options.extend(dependent);
        let cfr = CfrInfo {
            version: 0,
            forms: alloc::vec![CfrForm {
                object_id: 10,
                dependency_id: 0,
                ui_name: String::from("Test"),
                flags: 0,
                options,
                dep_values: Vec::new(),
            }],
        };
        let items = build_menu_items(&cfr);
        let header = visible_sections(&cfr, &items)[1];
        for _ in 0..50 {
            assert_eq!(section_rows(&cfr, &items, header).len(), 10);
        }
        assert_eq!(STORE.hidden_reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn picker_tags_distinguish_saved_default_and_unsaved() {
        assert_eq!(
            choice_tags(Some(1), Some(1), 2),
            [(1, "saved, default"), (2, "unsaved")]
        );
        assert_eq!(
            choice_tags(Some(0), Some(1), 0),
            [(0, "saved"), (1, "default")]
        );
    }

    /// One store per test process: `set_option_store` may run only once.
    struct TestStore {
        fail: AtomicBool,
        first_writes: AtomicUsize,
        second_writes: AtomicUsize,
        hidden_reads: AtomicUsize,
    }
    static STORE: TestStore = TestStore {
        fail: AtomicBool::new(true),
        first_writes: AtomicUsize::new(0),
        second_writes: AtomicUsize::new(0),
        hidden_reads: AtomicUsize::new(0),
    };
    fn install_store() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| cfr::set_option_store(&STORE));
    }
    impl OptionStore for TestStore {
        fn keeps(&self, option: &CfrOption) -> bool {
            option.opt_name.starts_with("ui_regression_")
                || option.opt_name.starts_with("ui_hidden_")
        }
        fn read(&self, option: &CfrOption) -> Option<CfrValue> {
            if option.opt_name.starts_with("ui_hidden_") {
                self.hidden_reads.fetch_add(1, Ordering::SeqCst);
                return Some(CfrValue::Bool(true));
            }
            None
        }
        fn write(&self, option: &CfrOption, _: &CfrValue) -> Result<(), &'static str> {
            if option.object_id == 1 {
                self.first_writes.fetch_add(1, Ordering::SeqCst);
            } else {
                self.second_writes.fetch_add(1, Ordering::SeqCst);
                if self.fail.load(Ordering::SeqCst) {
                    return Err("injected failure");
                }
            }
            Ok(())
        }
    }

    #[test]
    fn partial_save_preserves_failed_drafts_and_retries_only_unsaved_options() {
        install_store();
        let cfr = CfrInfo {
            version: 0,
            forms: alloc::vec![CfrForm {
                object_id: 10,
                dependency_id: 0,
                ui_name: String::from("Test"),
                flags: 0,
                options: alloc::vec![option(1), option(2)],
                dep_values: Vec::new(),
            }],
        };
        let mut items: Vec<_> = (0..2)
            .map(|i| MenuItem::Option {
                form_idx: 0,
                option_idx: i,
                current_value: CfrValue::Bool(true),
                original_value: CfrValue::Bool(false),
            })
            .collect();
        assert_eq!(save_all_changes(&cfr, &mut items), (1, 1));
        assert!(has_changes(&items));
        STORE.fail.store(false, Ordering::SeqCst);
        assert_eq!(save_all_changes(&cfr, &mut items), (1, 0));
        assert!(!has_changes(&items));
        assert_eq!(STORE.first_writes.load(Ordering::SeqCst), 1);
        assert_eq!(STORE.second_writes.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn defaults_stay_in_draft_and_readonly_values_are_not_edited() {
        let mut read_only = option(1);
        read_only.flags = cfr::CFR_OPTFLAG_READONLY;
        let cfr = CfrInfo {
            version: 0,
            forms: alloc::vec![CfrForm {
                object_id: 10,
                dependency_id: 0,
                ui_name: String::from("Test"),
                flags: 0,
                options: alloc::vec![read_only, option(2)],
                dep_values: Vec::new(),
            }],
        };
        let mut items: Vec<_> = (0..2)
            .map(|i| MenuItem::Option {
                form_idx: 0,
                option_idx: i,
                current_value: CfrValue::Bool(true),
                original_value: CfrValue::Bool(true),
            })
            .collect();
        let mut state = GraphicalState::new(0);
        restore_graphical_default(&cfr, &mut items, &mut state);
        assert!(!has_changes(&items));
        state.selected = 1;
        restore_graphical_default(&cfr, &mut items, &mut state);
        assert!(has_changes(&items));
    }
}
