//! Shared CFR draft/dependency/save policy for the graphical settings UI.
use crate::cfr::{CfrOption, CfrOptionType, CfrValue, EXTERNAL_BOOT_CHOICES, SettingsModel};
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
    fn configured_level(&self) -> Option<LevelFilter> {
        self.model.configured_level()
    }
    fn set_configured_level(&self, level: LevelFilter) -> Result<(), &'static str> {
        self.stored.borrow_mut().clear();
        self.model.set_configured_level(level)
    }
    fn external_boot(&self) -> Option<(usize, usize)> {
        self.model.external_boot()
    }
    fn set_external_boot(&self, choice: usize) -> Result<(), &'static str> {
        self.stored.borrow_mut().clear();
        self.model.set_external_boot(choice)
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
    /// CrabEFI-owned external-boot policy, as [`EXTERNAL_BOOT_CHOICES`]
    /// indices. Only `floor` (the build policy) and stricter are offered.
    CrabExternalBoot {
        current: usize,
        original: usize,
        floor: usize,
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
        ) || matches!(
            item,
            MenuItem::CrabExternalBoot {
                current,
                original,
                ..
            } if current != original
        )
    })
}

/// External-boot choices offered: the build policy and stricter ones.
pub fn external_boot_choices(floor: usize) -> core::ops::Range<usize> {
    floor..EXTERNAL_BOOT_CHOICES.len()
}

pub fn external_boot_name(choice: usize) -> &'static str {
    EXTERNAL_BOOT_CHOICES.get(choice).copied().unwrap_or("?")
}

/// Cycle through the offered external-boot choices.
pub fn step_external_boot(current: usize, floor: usize, forward: bool) -> usize {
    let choices = external_boot_choices(floor);
    match forward {
        true if current + 1 < choices.end => current + 1,
        true => choices.start,
        false if current > choices.start => current - 1,
        false => choices.end - 1,
    }
}

pub fn build_menu_items(cfr: &CfrInfo<'_>) -> Vec<MenuItem> {
    let mut items = Vec::new();

    let level = cfr.configured_level();
    let external_boot = cfr.external_boot();
    if level.is_some() || external_boot.is_some() {
        items.push(MenuItem::FormHeader {
            name: String::from("CrabEFI"),
            form_idx: None,
        });
    }
    if let Some(current_level) = level {
        items.push(MenuItem::CrabLogLevel {
            current_level,
            original_level: current_level,
        });
    }
    if let Some((floor, current)) = external_boot {
        items.push(MenuItem::CrabExternalBoot {
            current,
            original: current,
            floor,
        });
    }

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
        MenuItem::CrabLogLevel { .. } | MenuItem::CrabExternalBoot { .. } => true,
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
        MenuItem::Option { .. } | MenuItem::CrabLogLevel { .. } | MenuItem::CrabExternalBoot { .. }
    )
}

pub fn can_edit_item(cfr: &CfrInfo<'_>, items: &[MenuItem], index: usize) -> bool {
    if matches!(
        items.get(index),
        Some(MenuItem::CrabLogLevel { .. } | MenuItem::CrabExternalBoot { .. })
    ) {
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
        cfr.forms()
            .get(*form_idx)
            .is_some_and(|form| form.is_visible())
            && get_option(cfr, *form_idx, *option_idx)
                .is_some_and(|o| o.is_visible() && o.is_editable())
            && is_item_visible(cfr, items, item)
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

#[derive(Clone, Copy)]
pub enum StepDirection {
    Forward,
    Backward,
}

impl StepDirection {
    fn cycle_index(self, index: usize, len: usize) -> usize {
        match self {
            Self::Forward => (index + 1) % len,
            Self::Backward => index.checked_sub(1).unwrap_or(len - 1),
        }
    }
}

pub enum SettingEdit {
    /// Step a number without wrapping, or cycle a discrete choice.
    Step(StepDirection),
    /// Like a forward step, but wrap a number back to its minimum.
    Cycle,
    Set(CfrValue),
    SetLogLevel(LevelFilter),
    /// Select an [`EXTERNAL_BOOT_CHOICES`] index.
    SetExternalBoot(usize),
    RestoreDefault,
}

/// Apply an edit to the current value without writing it to the store.
/// `None` means no edit was possible; `Some` says whether the value changed.
pub fn apply_edit(
    cfr: &CfrInfo<'_>,
    items: &mut [MenuItem],
    index: usize,
    edit: SettingEdit,
) -> Option<bool> {
    if !can_edit_item(cfr, items, index) {
        return None;
    }
    fn replace<T: PartialEq>(current: &mut T, next: T) -> bool {
        let changed = *current != next;
        *current = next;
        changed
    }
    match items.get_mut(index)? {
        MenuItem::CrabLogLevel { current_level, .. } => {
            use crate::cfr::{DEFAULT_LEVEL, LEVEL_CHOICES, level_index};
            let next = match edit {
                SettingEdit::RestoreDefault => DEFAULT_LEVEL,
                SettingEdit::SetLogLevel(level) if LEVEL_CHOICES.contains(&level) => level,
                SettingEdit::Step(_) | SettingEdit::Cycle => {
                    let direction = match edit {
                        SettingEdit::Step(direction) => direction,
                        _ => StepDirection::Forward,
                    };
                    LEVEL_CHOICES
                        [direction.cycle_index(level_index(*current_level), LEVEL_CHOICES.len())]
                }
                _ => return None,
            };
            Some(replace(current_level, next))
        }
        MenuItem::CrabExternalBoot { current, floor, .. } => {
            let next = match edit {
                SettingEdit::RestoreDefault => *floor,
                SettingEdit::SetExternalBoot(choice)
                    if external_boot_choices(*floor).contains(&choice) =>
                {
                    choice
                }
                SettingEdit::Step(direction) => step_external_boot(
                    *current,
                    *floor,
                    matches!(direction, StepDirection::Forward),
                ),
                SettingEdit::Cycle => step_external_boot(*current, *floor, true),
                _ => return None,
            };
            Some(replace(current, next))
        }
        MenuItem::Option {
            form_idx,
            option_idx,
            current_value,
            ..
        } => {
            let kind = &get_option(cfr, *form_idx, *option_idx)?.option_type;
            let next = match edit {
                SettingEdit::RestoreDefault => CfrValue::from_option_type(kind),
                SettingEdit::Set(value) if accepts_value(kind, &value) => value,
                SettingEdit::Step(_) | SettingEdit::Cycle => {
                    stepped_value(kind, current_value, edit)?
                }
                _ => return None,
            };
            Some(replace(current_value, next))
        }
        _ => None,
    }
}

fn stepped_value(kind: &CfrOptionType, value: &CfrValue, edit: SettingEdit) -> Option<CfrValue> {
    let direction = match edit {
        SettingEdit::Cycle => StepDirection::Forward,
        SettingEdit::Step(direction) => direction,
        _ => return None,
    };
    match (kind, value) {
        (CfrOptionType::Bool { .. }, CfrValue::Bool(value)) => Some(CfrValue::Bool(!value)),
        (CfrOptionType::Enum { choices, .. }, CfrValue::Number(value)) if !choices.is_empty() => {
            let current = choices
                .iter()
                .position(|choice| choice.value == *value)
                .unwrap_or(0);
            Some(CfrValue::Number(
                choices[direction.cycle_index(current, choices.len())].value,
            ))
        }
        (CfrOptionType::Number { min, max, step, .. }, CfrValue::Number(value)) if min <= max => {
            stepped_number(
                *value,
                *min,
                *max,
                *step,
                matches!(direction, StepDirection::Forward),
            )
            .or_else(|| matches!(edit, SettingEdit::Cycle).then_some(*min))
            .map(CfrValue::Number)
        }
        _ => None,
    }
}

pub(crate) fn validate_number(
    value: u32,
    min: u32,
    max: u32,
    step: u32,
) -> Result<(), &'static str> {
    if !(min..=max).contains(&value) {
        return Err("Value is outside the allowed range.");
    }
    if !(value - min).is_multiple_of(step.max(1)) {
        return Err("Value must match the step from the minimum.");
    }
    Ok(())
}

fn accepts_value(kind: &CfrOptionType, value: &CfrValue) -> bool {
    match (kind, value) {
        (CfrOptionType::Bool { .. }, CfrValue::Bool(_)) => true,
        // The firmware store treats the first NUL as the end of the value.
        (CfrOptionType::Varchar { .. }, CfrValue::Varchar(text)) => !text.contains('\0'),
        (CfrOptionType::Enum { choices, .. }, CfrValue::Number(value)) => {
            choices.iter().any(|choice| choice.value == *value)
        }
        (CfrOptionType::Number { min, max, step, .. }, CfrValue::Number(value)) => {
            validate_number(*value, *min, *max, *step).is_ok()
        }
        _ => false,
    }
}

pub fn increment_option(cfr: &CfrInfo<'_>, items: &mut [MenuItem], index: usize) -> bool {
    apply_edit(cfr, items, index, SettingEdit::Step(StepDirection::Forward)).is_some()
}

pub fn decrement_option(cfr: &CfrInfo<'_>, items: &mut [MenuItem], index: usize) -> bool {
    apply_edit(
        cfr,
        items,
        index,
        SettingEdit::Step(StepDirection::Backward),
    )
    .is_some()
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
            MenuItem::CrabExternalBoot {
                current, original, ..
            } if current != original => match cfr.set_external_boot(*current) {
                Ok(()) => {
                    *original = *current;
                    saved += 1;
                }
                Err(e) => {
                    log::warn!("Failed to save external boot policy: {}", e);
                    failed += 1;
                }
            },
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
    fn numeric_steps_stop_at_the_bound_but_cycle_wraps() {
        let cfr = CfrInfo {
            version: 0,
            forms: alloc::vec![form(
                "Test",
                0,
                alloc::vec![CfrOption {
                    object_id: 1,
                    dependency_id: 0,
                    opt_name: String::from("number"),
                    ui_name: String::from("Number"),
                    ui_helptext: String::new(),
                    flags: 0,
                    option_type: CfrOptionType::Number {
                        default: 5,
                        min: 0,
                        max: 12,
                        step: 5,
                        hex_display: false,
                    },
                    dep_values: Vec::new(),
                }]
            )],
        };
        let mut items = [MenuItem::Option {
            form_idx: 0,
            option_idx: 0,
            current_value: CfrValue::Number(10),
            original_value: CfrValue::Number(10),
        }];
        assert!(!increment_option(&cfr, &mut items, 0));
        assert_eq!(
            apply_edit(&cfr, &mut items, 0, SettingEdit::Cycle),
            Some(true)
        );
        assert_eq!(
            apply_edit(&cfr, &mut items, 0, SettingEdit::Set(CfrValue::Number(0))),
            Some(false)
        );
        assert_eq!(
            apply_edit(&cfr, &mut items, 0, SettingEdit::Set(CfrValue::Number(12))),
            None
        );
        assert!(!decrement_option(&cfr, &mut items, 0));
        assert_eq!(
            apply_edit(&cfr, &mut items, 0, SettingEdit::RestoreDefault),
            Some(true)
        );
        assert!(matches!(
            items[0],
            MenuItem::Option {
                current_value: CfrValue::Number(5),
                original_value: CfrValue::Number(10),
                ..
            }
        ));
    }

    #[test]
    fn embedded_nul_is_rejected_without_changing_the_draft() {
        let cfr = CfrInfo {
            version: 0,
            forms: alloc::vec![form(
                "Test",
                0,
                alloc::vec![CfrOption {
                    object_id: 1,
                    dependency_id: 0,
                    opt_name: String::from("text"),
                    ui_name: String::from("Text"),
                    ui_helptext: String::new(),
                    flags: 0,
                    option_type: CfrOptionType::Varchar {
                        default: String::new()
                    },
                    dep_values: Vec::new(),
                }]
            )],
        };
        let mut items = [MenuItem::Option {
            form_idx: 0,
            option_idx: 0,
            current_value: CfrValue::Varchar(String::from("draft")),
            original_value: CfrValue::Varchar(String::new()),
        }];
        assert_eq!(
            apply_edit(
                &cfr,
                &mut items,
                0,
                SettingEdit::Set(CfrValue::Varchar(String::from("a\0b")))
            ),
            None
        );
        assert!(
            matches!(&items[0], MenuItem::Option { current_value: CfrValue::Varchar(text), .. } if text == "draft")
        );
        assert_eq!(
            apply_edit(
                &cfr,
                &mut items,
                0,
                SettingEdit::Set(CfrValue::Varchar(String::from("é")))
            ),
            Some(true)
        );
    }

    #[test]
    fn manually_supplied_suppressed_rows_cannot_be_edited() {
        let mut cfr = CfrInfo {
            version: 0,
            forms: alloc::vec![form(
                "Test",
                0,
                alloc::vec![CfrOption {
                    object_id: 1,
                    dependency_id: 0,
                    opt_name: String::from("switch"),
                    ui_name: String::from("Switch"),
                    ui_helptext: String::new(),
                    flags: crate::cfr::CFR_OPTFLAG_SUPPRESS,
                    option_type: CfrOptionType::Bool { default: false },
                    dep_values: Vec::new(),
                }]
            )],
        };
        let mut items = [MenuItem::Option {
            form_idx: 0,
            option_idx: 0,
            current_value: CfrValue::Bool(false),
            original_value: CfrValue::Bool(false),
        }];
        assert_eq!(apply_edit(&cfr, &mut items, 0, SettingEdit::Cycle), None);
        cfr.forms[0].options[0].flags = 0;
        cfr.forms[0].flags = crate::cfr::CFR_OPTFLAG_SUPPRESS;
        assert_eq!(apply_edit(&cfr, &mut items, 0, SettingEdit::Cycle), None);
        assert!(!has_changes(&items));
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
    fn external_boot_offers_only_the_build_policy_and_stricter() {
        assert_eq!(external_boot_choices(0), 0..3);
        assert_eq!(external_boot_choices(1), 1..3);
        assert_eq!(external_boot_choices(2), 2..3);
        for floor in 0..3 {
            for current in external_boot_choices(floor) {
                for forward in [true, false] {
                    let next = step_external_boot(current, floor, forward);
                    assert!(external_boot_choices(floor).contains(&next));
                }
            }
        }
        assert_eq!(step_external_boot(2, 1, true), 1);
        assert_eq!(step_external_boot(1, 1, false), 2);
        assert_eq!(step_external_boot(2, 2, true), 2);
    }

    #[test]
    fn a_platform_owned_log_level_is_not_offered() {
        struct Model;
        impl SettingsModel for Model {
            fn forms(&self) -> &[CfrForm] {
                &[]
            }
            fn read_option_value(&self, _: &CfrOption) -> CfrValue {
                CfrValue::Bool(false)
            }
            fn write_option_value(&self, _: &CfrOption, _: &CfrValue) -> Result<(), &'static str> {
                Ok(())
            }
            fn configured_level(&self) -> Option<LevelFilter> {
                None
            }
        }
        // Nothing of CrabEFI's own is left, not even its header.
        assert!(build_menu_items(&Session::new(&Model)).is_empty());
        assert!(
            build_menu_items(&CfrInfo::new())
                .iter()
                .any(|item| matches!(item, MenuItem::CrabLogLevel { .. }))
        );
    }

    #[test]
    fn external_boot_is_saved_through_the_session() {
        struct Model(core::cell::Cell<Option<usize>>);
        impl SettingsModel for Model {
            fn forms(&self) -> &[CfrForm] {
                &[]
            }
            fn read_option_value(&self, _: &CfrOption) -> CfrValue {
                CfrValue::Bool(false)
            }
            fn write_option_value(&self, _: &CfrOption, _: &CfrValue) -> Result<(), &'static str> {
                Ok(())
            }
            fn external_boot(&self) -> Option<(usize, usize)> {
                Some((1, 1))
            }
            fn set_external_boot(&self, choice: usize) -> Result<(), &'static str> {
                self.0.set(Some(choice));
                Ok(())
            }
        }
        let model = Model(core::cell::Cell::new(None));
        let session = Session::new(&model);
        let mut items = build_menu_items(&session);
        let index = items
            .iter()
            .position(|item| matches!(item, MenuItem::CrabExternalBoot { .. }))
            .unwrap();
        assert!(matches!(
            items[index],
            MenuItem::CrabExternalBoot {
                current: 1,
                original: 1,
                floor: 1
            }
        ));
        assert!(increment_option(&session, &mut items, index));
        assert!(has_changes(&items));
        assert_eq!(save_all_changes(&session, &mut items), (1, 0));
        assert_eq!(model.0.get(), Some(2));
        assert!(!has_changes(&items));
        // Without a model that stores it, the setting is not offered.
        assert!(
            !build_menu_items(&CfrInfo::new())
                .iter()
                .any(|item| matches!(item, MenuItem::CrabExternalBoot { .. }))
        );
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
