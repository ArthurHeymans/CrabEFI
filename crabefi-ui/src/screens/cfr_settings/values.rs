use super::CfrInfo;
use super::state::is_changed;
use crate::cfr::{self, CfrOption, CfrOptionType, CfrValue};
use crate::screens::render;
use crate::screens::render::FontSize;
use crate::settings::{MenuItem, external_boot_name, get_option, push_truncated};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use heapless::String as StackString;

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

pub(super) fn truncate_for_width(text: &str, max_width: u32, size: FontSize) -> StackString<256> {
    render::ellipsize(text, max_width, size)
}

pub(super) fn full_value(option: &CfrOption, value: &CfrValue) -> String {
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
pub(super) fn row_parts(
    cfr: &CfrInfo<'_>,
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
            String::from(crate::cfr::level_name(*current_level)),
            String::from(crate::cfr::level_name(*original_level)),
            true,
            None,
        )),
        MenuItem::CrabExternalBoot {
            current, original, ..
        } => Some((
            String::from("External boot"),
            String::from(external_boot_name(*current)),
            String::from(external_boot_name(*original)),
            true,
            None,
        )),
        _ => None,
    }
}

pub(super) const EXTERNAL_BOOT_HELP: &str =
    "Whether USB and removable media may boot. Menu only: only when picked in the boot menu.";

pub(super) fn changed_count(items: &[MenuItem]) -> usize {
    items.iter().filter(|item| is_changed(item)).count()
}

pub(super) fn changed_items<'a>(
    cfr: &'a CfrInfo,
    items: &'a [MenuItem],
) -> Vec<(String, String, String)> {
    items
        .iter()
        .filter(|item| is_changed(item))
        .filter_map(|item| match item {
            MenuItem::CrabLogLevel {
                current_level,
                original_level,
            } => Some((
                String::from("CrabEFI log level"),
                String::from(crate::cfr::level_name(*original_level)),
                String::from(crate::cfr::level_name(*current_level)),
            )),
            MenuItem::CrabExternalBoot {
                current, original, ..
            } => Some((
                String::from("External boot"),
                String::from(external_boot_name(*original)),
                String::from(external_boot_name(*current)),
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
