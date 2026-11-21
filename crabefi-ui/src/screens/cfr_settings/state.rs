use super::geometry::fw_layout;
use super::{CfrInfo, FramebufferInfo, GraphicalState};
use crate::KeyPress;
use crate::cfr::{CfrOptionType, CfrValue};
use crate::screens::controls;
use crate::settings::{
    MenuItem, can_edit_item, get_option, has_changes, is_item_visible, is_selectable,
};
use alloc::vec::Vec;

// ─── Sections ───────────────────────────────────────────────────────────

pub(super) fn visible_sections(cfr: &CfrInfo<'_>, items: &[MenuItem]) -> Vec<usize> {
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
pub(super) fn section_of(items: &[MenuItem], index: usize) -> usize {
    (0..=index.min(items.len().saturating_sub(1)))
        .rev()
        .find(|i| matches!(items[*i], MenuItem::FormHeader { .. }))
        .unwrap_or(0)
}
/// Visible rows of a section (options, subform headings and comments).
pub(super) fn section_rows(cfr: &CfrInfo<'_>, items: &[MenuItem], header: usize) -> Vec<usize> {
    let start = if matches!(items.get(header), Some(MenuItem::FormHeader { .. })) {
        header + 1
    } else {
        header
    };
    (start..section_end(items, header))
        .filter(|i| is_item_visible(cfr, items, &items[*i]))
        .collect()
}
pub(super) fn section_name(items: &[MenuItem], header: usize) -> &str {
    match items.get(header) {
        Some(MenuItem::FormHeader { name, .. }) => name,
        _ => "Settings",
    }
}
pub(super) fn is_changed(item: &MenuItem) -> bool {
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
        MenuItem::CrabExternalBoot {
            current, original, ..
        } => current != original,
        _ => false,
    }
}
pub(super) fn first_selectable(items: &[MenuItem], rows: &[usize]) -> Option<usize> {
    rows.iter().copied().find(|i| is_selectable(&items[*i]))
}

/// Home/End/Page movement over the selectable rows of one section.
pub(super) fn graphical_page_selection(
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

pub(super) fn keep_graphical_selection_visible(
    cfr: &CfrInfo<'_>,
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
    let l = fw_layout(fb);
    let sections = visible_sections(cfr, items).len();
    state.section_offset = state
        .section_offset
        .min(sections.saturating_sub(l.sec_slots));
    let pos = rows.iter().position(|i| *i == state.selected).unwrap_or(0);
    controls::ensure_visible(
        &mut state.scroll_offset,
        pos,
        rows.len(),
        fw_layout(fb).slots,
    );
}

// ─── Actions ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FwAction {
    Edit,
    Default,
    Save,
    Discard,
    Restart,
}

pub(super) fn edit_label(cfr: &CfrInfo<'_>, item: &MenuItem) -> &'static str {
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

pub(super) fn strip_actions(items: &[MenuItem], state: &GraphicalState) -> Vec<FwAction> {
    match state.save_result {
        Some((_, failed)) if failed > 0 => alloc::vec![FwAction::Save, FwAction::Discard],
        Some(_) if !has_changes(items) => alloc::vec![FwAction::Restart],
        _ if has_changes(items) => alloc::vec![FwAction::Save, FwAction::Discard],
        _ => Vec::new(),
    }
}

/// Focus order: the selected option's actions, then the page-wide strip.
pub(super) fn actions(
    cfr: &CfrInfo<'_>,
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
