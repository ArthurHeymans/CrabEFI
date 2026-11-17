//! Shared CFR draft/dependency/save policy for the graphical settings UI.
use crate::cfr::{CfrOption, CfrOptionType, CfrValue, SettingsModel};
use crate::log_level::LevelFilter;
use alloc::{string::String, vec::Vec};
use core::cell::RefCell;
use heapless::String as StackString;
type CfrInfo<'a> = dyn SettingsModel + 'a;

/// One menu session over a settings model. Options outside the menu (for
/// example suppressed ones) cannot change while it is open, so their stored
/// values are read once: a variable-store read on every pointer poll made the
/// graphical loop too slow to see clicks. A write forgets them: platform
/// writes can change suppressed dependencies as a side effect, even when
/// only a prefix of a save succeeded.
pub struct Session<'a> {
    model: &'a CfrInfo<'a>,
    stored: RefCell<Vec<(u64, Option<u32>)>>,
}
impl<'a> Session<'a> {
    pub fn new(model: &'a CfrInfo<'a>) -> Self {
        Self {
            model,
            stored: RefCell::new(Vec::new()),
        }
    }
}
impl SettingsModel for Session<'_> {
    fn forms(&self) -> &[crate::cfr::CfrForm] {
        self.model.forms()
    }
    fn read_option_value(&self, option: &CfrOption) -> CfrValue {
        self.model.read_option_value(option)
    }
    fn write_option_value(&self, option: &CfrOption, value: &CfrValue) -> Result<(), &'static str> {
        self.stored.borrow_mut().clear();
        self.model.write_option_value(option, value)
    }
    fn configured_level(&self) -> LevelFilter {
        self.model.configured_level()
    }
    fn set_configured_level(&self, level: LevelFilter) -> Result<(), &'static str> {
        self.stored.borrow_mut().clear();
        self.model.set_configured_level(level)
    }
    fn find_numeric_value(&self, object_id: u64) -> Option<u32> {
        let mut stored = self.stored.borrow_mut();
        if let Some((_, value)) = stored.iter().find(|(id, _)| *id == object_id) {
            return *value;
        }
        let value = self.model.find_numeric_value(object_id);
        stored.push((object_id, value));
        value
    }
}
#[derive(Debug, Clone)]
pub enum MenuItem {
    /// Form header (category separator). `form_idx` is `None` for the
    /// built-in CrabEFI section, which no platform form can hide.
    FormHeader {
        name: String,
        form_idx: Option<usize>,
    },
    /// CrabEFI-owned log-level setting.
    CrabLogLevel {
        current_level: log::LevelFilter,
        /// Snapshot of the value when the menu was opened, used to detect changes.
        original_level: log::LevelFilter,
    },
    /// Editable option
    Option {
        form_idx: usize,
        option_idx: usize,
        current_value: CfrValue,
        /// Snapshot of the value when the menu was opened, used to detect changes
        original_value: CfrValue,
    },
    /// Informational comment
    Comment { text: String },
    /// Nested subform section header (indented)
    SubformHeader { name: String },
}

pub fn has_changes(items: &[MenuItem]) -> bool {
    items.iter().any(|item| {
        matches!(
            item,
            MenuItem::Option {
                current_value,
                original_value,
                ..
            } if current_value != original_value
        ) || matches!(
            item,
            MenuItem::CrabLogLevel {
                current_level,
                original_level,
            } if current_level != original_level
        )
    })
}

pub fn build_menu_items(cfr: &CfrInfo<'_>) -> Vec<MenuItem> {
    let mut items = Vec::new();

    items.push(MenuItem::FormHeader {
        name: String::from("CrabEFI"),
        form_idx: None,
    });
    let current_level = cfr.configured_level();
    items.push(MenuItem::CrabLogLevel {
        current_level,
        original_level: current_level,
    });

    for (form_idx, form) in cfr.forms().iter().enumerate() {
        if !form.is_visible() {
            continue;
        }

        items.push(MenuItem::FormHeader {
            name: form.ui_name.clone(),
            form_idx: Some(form_idx),
        });

        for (option_idx, option) in form.options.iter().enumerate() {
            if !option.is_visible() {
                continue;
            }

            match &option.option_type {
                CfrOptionType::Comment => {
                    // Check if this is a flattened subform header (has object_id, no opt_name)
                    let is_subform = option.opt_name.is_empty() && option.object_id != 0;
                    if is_subform {
                        items.push(MenuItem::SubformHeader {
                            name: option.ui_name.clone(),
                        });
                    } else {
                        items.push(MenuItem::Comment {
                            text: option.ui_name.clone(),
                        });
                    }
                }
                _ => {
                    let current_value = cfr.read_option_value(option);
                    items.push(MenuItem::Option {
                        form_idx,
                        option_idx,
                        original_value: current_value.clone(),
                        current_value,
                    });
                }
            }
        }
    }

    items
}

pub fn find_live_numeric_value(
    cfr: &CfrInfo<'_>,
    items: &[MenuItem],
    object_id: u64,
) -> Option<u32> {
    if object_id == 0 {
        return None;
    }
    // Search menu items for an option whose CfrOption::object_id matches
    for item in items {
        if let MenuItem::Option {
            form_idx,
            option_idx,
            current_value,
            ..
        } = item
            && let Some(option) = get_option(cfr, *form_idx, *option_idx)
            && option.object_id == object_id
        {
            return match current_value {
                CfrValue::Bool(b) => Some(if *b { 1 } else { 0 }),
                CfrValue::Number(n) => Some(*n),
                _ => None,
            };
        }
    }
    // Not a menu item: a menu session reads its stored value once.
    cfr.find_numeric_value(object_id)
}

pub fn is_dep_met_live(
    cfr: &CfrInfo<'_>,
    items: &[MenuItem],
    dependency_id: u64,
    dep_values: &[u32],
) -> bool {
    if dependency_id == 0 {
        return true;
    }
    match find_live_numeric_value(cfr, items, dependency_id) {
        Some(current) => {
            if dep_values.is_empty() {
                current != 0
            } else {
                dep_values.contains(&current)
            }
        }
        None => true,
    }
}

pub fn is_item_visible(cfr: &CfrInfo<'_>, items: &[MenuItem], item: &MenuItem) -> bool {
    match item {
        MenuItem::FormHeader { form_idx, .. } => form_idx
            .and_then(|index| cfr.forms().get(index))
            .is_none_or(|form| is_dep_met_live(cfr, items, form.dependency_id, &form.dep_values)),
        MenuItem::Option {
            form_idx,
            option_idx,
            ..
        } => {
            let form_ok = cfr.forms().get(*form_idx).is_none_or(|form| {
                is_dep_met_live(cfr, items, form.dependency_id, &form.dep_values)
            });
            let opt_ok = get_option(cfr, *form_idx, *option_idx)
                .is_none_or(|opt| is_dep_met_live(cfr, items, opt.dependency_id, &opt.dep_values));
            form_ok && opt_ok
        }
        MenuItem::CrabLogLevel { .. } => true,
        // Comments and subform headers don't carry their own indices, so
        // they stay visible (their parent form header hides the section).
        MenuItem::Comment { .. } | MenuItem::SubformHeader { .. } => true,
    }
}

pub fn get_option<'a>(
    cfr: &'a CfrInfo<'_>,
    form_idx: usize,
    option_idx: usize,
) -> Option<&'a CfrOption> {
    cfr.forms()
        .get(form_idx)
        .and_then(|f| f.options.get(option_idx))
}

pub fn find_first_selectable(cfr: &CfrInfo<'_>, items: &[MenuItem], start: usize) -> usize {
    for (i, item) in items.iter().enumerate().skip(start) {
        if is_selectable(item) && is_item_visible(cfr, items, item) {
            return i;
        }
    }
    for (i, item) in items.iter().enumerate().take(start) {
        if is_selectable(item) && is_item_visible(cfr, items, item) {
            return i;
        }
    }
    0
}

pub fn is_selectable(item: &MenuItem) -> bool {
    matches!(
        item,
        MenuItem::Option { .. } | MenuItem::CrabLogLevel { .. }
    )
}

pub fn can_edit_item(cfr: &CfrInfo<'_>, items: &[MenuItem], index: usize) -> bool {
    if matches!(items.get(index), Some(MenuItem::CrabLogLevel { .. })) {
        return true;
    }

    if let Some(
        item @ MenuItem::Option {
            form_idx,
            option_idx,
            ..
        },
    ) = items.get(index)
    {
        is_item_visible(cfr, items, item)
            && get_option(cfr, *form_idx, *option_idx).is_some_and(|o| o.is_editable())
    } else {
        false
    }
}

pub fn stepped_number(current: u32, min: u32, max: u32, step: u32, forward: bool) -> Option<u32> {
    if min > max {
        return None;
    }
    let step = step.max(1);
    if forward {
        if current < min {
            return Some(min);
        }
        let offset = (current - min) / step;
        min.checked_add(offset.checked_add(1)?.checked_mul(step)?)
            .filter(|next| *next <= max)
    } else if current > min {
        let bound = current.saturating_sub(1).min(max);
        Some(min + (bound - min) / step * step)
    } else {
        None
    }
}

pub fn increment_option(cfr: &CfrInfo<'_>, items: &mut [MenuItem], index: usize) -> bool {
    // Check editability with live dependencies before taking a mutable borrow
    if !can_edit_item(cfr, items, index) {
        return false;
    }

    if let Some(MenuItem::CrabLogLevel { current_level, .. }) = items.get_mut(index) {
        let current_idx = crate::cfr::level_index(*current_level);
        let next_idx = (current_idx + 1) % crate::cfr::LEVEL_CHOICES.len();
        *current_level = crate::cfr::LEVEL_CHOICES[next_idx];
        return true;
    }

    let Some(MenuItem::Option {
        form_idx,
        option_idx,
        current_value,
        ..
    }) = items.get_mut(index)
    else {
        return false;
    };
    let (fi, oi) = (*form_idx, *option_idx);
    let Some(option) = get_option(cfr, fi, oi) else {
        return false;
    };
    match (&option.option_type, current_value) {
        (CfrOptionType::Bool { .. }, CfrValue::Bool(b)) => {
            *b = !*b;
            true
        }
        (CfrOptionType::Enum { choices, .. }, CfrValue::Number(n)) => {
            if choices.is_empty() {
                return false;
            }
            let current_idx = choices.iter().position(|c| c.value == *n).unwrap_or(0);
            let next_idx = (current_idx + 1) % choices.len();
            if let Some(choice) = choices.get(next_idx) {
                *n = choice.value;
                true
            } else {
                false
            }
        }
        (CfrOptionType::Number { min, max, step, .. }, CfrValue::Number(n)) => {
            if let Some(next) = stepped_number(*n, *min, *max, *step, true) {
                *n = next;
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

pub fn decrement_option(cfr: &CfrInfo<'_>, items: &mut [MenuItem], index: usize) -> bool {
    // Check editability with live dependencies before taking a mutable borrow
    if !can_edit_item(cfr, items, index) {
        return false;
    }

    if let Some(MenuItem::CrabLogLevel { current_level, .. }) = items.get_mut(index) {
        let current_idx = crate::cfr::level_index(*current_level);
        let prev_idx = if current_idx == 0 {
            crate::cfr::LEVEL_CHOICES.len().saturating_sub(1)
        } else {
            current_idx - 1
        };
        *current_level = crate::cfr::LEVEL_CHOICES[prev_idx];
        return true;
    }

    let Some(MenuItem::Option {
        form_idx,
        option_idx,
        current_value,
        ..
    }) = items.get_mut(index)
    else {
        return false;
    };
    let (fi, oi) = (*form_idx, *option_idx);
    let Some(option) = get_option(cfr, fi, oi) else {
        return false;
    };
    match (&option.option_type, current_value) {
        (CfrOptionType::Bool { .. }, CfrValue::Bool(b)) => {
            *b = !*b;
            true
        }
        (CfrOptionType::Enum { choices, .. }, CfrValue::Number(n)) => {
            if choices.is_empty() {
                return false;
            }
            let current_idx = choices.iter().position(|c| c.value == *n).unwrap_or(0);
            let prev_idx = if current_idx == 0 {
                choices.len().saturating_sub(1)
            } else {
                current_idx - 1
            };
            if let Some(choice) = choices.get(prev_idx) {
                *n = choice.value;
                true
            } else {
                false
            }
        }
        (CfrOptionType::Number { min, max, step, .. }, CfrValue::Number(n)) => {
            if let Some(next) = stepped_number(*n, *min, *max, *step, false) {
                *n = next;
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

pub fn save_all_changes(cfr: &CfrInfo<'_>, items: &mut [MenuItem]) -> (usize, usize) {
    let mut saved = 0usize;
    let mut failed = 0usize;
    for item in items {
        match item {
            MenuItem::CrabLogLevel {
                current_level,
                original_level,
            } if current_level != original_level => {
                match cfr.set_configured_level(*current_level) {
                    Ok(()) => {
                        *original_level = *current_level;
                        saved += 1;
                    }
                    Err(e) => {
                        log::warn!("Failed to save CrabEFI log level: {:?}", e);
                        failed += 1;
                    }
                }
            }
            MenuItem::Option {
                form_idx,
                option_idx,
                current_value,
                original_value,
            } if current_value != original_value => {
                if let Some(option) = get_option(cfr, *form_idx, *option_idx) {
                    match cfr.write_option_value(option, current_value) {
                        Ok(()) => {
                            *original_value = current_value.clone();
                            saved += 1;
                        }
                        Err(e) => {
                            log::warn!("Failed to save '{}': {}", option.opt_name, e);
                            failed += 1;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    (saved, failed)
}

pub fn push_truncated<const N: usize>(out: &mut StackString<N>, text: &str, max_chars: usize) {
    if max_chars == 0 {
        return;
    }

    let mut chars = text.chars();
    for idx in 0..max_chars {
        let Some(ch) = chars.next() else {
            return;
        };
        if idx + 1 == max_chars && chars.next().is_some() {
            let _ = out.push('~');
            return;
        }
        if out.push(ch).is_err() {
            let _ = out.push('~');
            return;
        }
    }
}
/// Borrowed state from the real settings page, for host automation only.
pub struct FirmwareObservation<'a> {
    pub model: &'a CfrInfo<'a>,
    pub items: &'a [MenuItem],
    pub selected: usize,
    pub section: &'a str,
    pub dirty_count: usize,
    pub save_result: Option<(usize, usize)>,
    pub status: Option<(&'static str, bool)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfr::{CfrForm, CfrInfo};

    fn form(name: &str, dependency_id: u64, options: Vec<CfrOption>) -> CfrForm {
        CfrForm {
            object_id: 0,
            dependency_id,
            ui_name: String::from(name),
            flags: 0,
            options,
            dep_values: Vec::new(),
        }
    }

    #[test]
    fn a_session_reads_stored_dependencies_once_until_a_write() {
        struct Counting(core::cell::Cell<usize>);
        impl SettingsModel for Counting {
            fn forms(&self) -> &[CfrForm] {
                &[]
            }
            fn read_option_value(&self, _: &CfrOption) -> CfrValue {
                CfrValue::Bool(false)
            }
            fn write_option_value(&self, _: &CfrOption, _: &CfrValue) -> Result<(), &'static str> {
                Err("injected failure")
            }
            fn find_numeric_value(&self, _: u64) -> Option<u32> {
                self.0.set(self.0.get() + 1);
                Some(0)
            }
        }
        let model = Counting(core::cell::Cell::new(0));
        let session = Session::new(&model);
        session.find_numeric_value(900);
        session.find_numeric_value(900);
        assert_eq!(model.0.get(), 1);
        let option = CfrOption {
            object_id: 1,
            dependency_id: 0,
            opt_name: String::from("switch"),
            ui_name: String::from("Switch"),
            ui_helptext: String::new(),
            flags: 0,
            option_type: CfrOptionType::Bool { default: false },
            dep_values: Vec::new(),
        };
        // Even a failed write may have changed what the platform stores.
        assert!(
            session
                .write_option_value(&option, &CfrValue::Bool(true))
                .is_err()
        );
        session.find_numeric_value(900);
        assert_eq!(model.0.get(), 2);
    }

    #[test]
    fn form_headers_follow_their_own_form_not_its_title() {
        let switch = CfrOption {
            object_id: 1,
            dependency_id: 0,
            opt_name: String::from("switch"),
            ui_name: String::from("Switch"),
            ui_helptext: String::new(),
            flags: 0,
            option_type: CfrOptionType::Bool { default: false },
            dep_values: Vec::new(),
        };
        let cfr = CfrInfo {
            version: 0,
            forms: alloc::vec![
                form("Shared", 1, Vec::new()),
                form("Shared", 0, alloc::vec![switch]),
                form("CrabEFI", 1, Vec::new()),
            ],
        };
        let items = build_menu_items(&cfr);
        let headers: Vec<(Option<usize>, bool)> = items
            .iter()
            .filter_map(|item| match item {
                MenuItem::FormHeader { form_idx, .. } => {
                    Some((*form_idx, is_item_visible(&cfr, &items, item)))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            headers,
            [
                (None, true),
                (Some(0), false),
                (Some(1), true),
                (Some(2), false)
            ]
        );
    }
}
