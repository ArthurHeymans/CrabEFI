use super::geometry::{fw_layout, row_rect};
use super::paint::draw_graphical_menu;
use super::state::{is_changed, section_rows};
use super::values::{EXTERNAL_BOOT_HELP, changed_count, changed_items, full_value};
use super::{CfrInfo, FramebufferInfo, GraphicalState, Rect};
use crate::cfr::{self, CfrOptionType, CfrValue};
use crate::screens::controls::ButtonKind;
use crate::screens::dialog::{Block, Choice};
use crate::screens::kit::Tone;
use crate::screens::layout::Metrics;
use crate::screens::{NavItem, dialog};
use crate::settings::{
    MenuItem, SettingEdit, apply_edit, can_edit_item, external_boot_choices, external_boot_name,
    get_option, has_changes, save_all_changes, validate_number,
};
use alloc::string::String;
use alloc::vec::Vec;

/// Status messages describe the selected row; drop them when the selection
/// moves. Save results stay until the draft changes.
pub(super) fn clear_row_notice(state: &mut GraphicalState, selected_before: usize) {
    if state.selected != selected_before {
        state.status_message = None;
    }
}

pub(super) fn save_graphical_changes(
    cfr: &CfrInfo<'_>,
    items: &mut [MenuItem],
    state: &mut GraphicalState,
) {
    if !has_changes(items) {
        state.status_message = Some(("Nothing to save.", true));
        return;
    }
    state.save_result = Some(save_all_changes(cfr, items));
    state.status_message = None;
}

/// Restore only unsaved drafts; successful writes in a partial save remain saved.
pub(super) fn discard_graphical_changes(items: &mut [MenuItem]) {
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
            MenuItem::CrabExternalBoot {
                current, original, ..
            } => *current = *original,
            _ => {}
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Destination {
    Page(&'static str),
    Restart,
}
pub(super) fn destination(nav: NavItem) -> Destination {
    Destination::Page(match nav {
        NavItem::Boot => "the Boot page",
        #[cfg(feature = "secure-boot")]
        NavItem::Security => "the Security page",
        NavItem::Firmware => "Firmware",
    })
}

/// Changes listed name by name, capped so instructions always stay visible.
pub(super) fn change_blocks(cfr: &CfrInfo<'_>, items: &[MenuItem], cap: usize) -> Vec<Block> {
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

pub(super) async fn leave_graphical(
    cfr: &CfrInfo<'_>,
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
        .await
    };
    match choice {
        1 => {
            discard_graphical_changes(items);
            state.save_result = None;
            state.status_message = Some(("Unsaved changes discarded.", true));
            fb.set_firmware_dirty(false);
            true
        }
        2 => {
            save_graphical_changes(cfr, items, state);
            let done = !has_changes(items);
            fb.set_firmware_dirty(!done);
            done
        }
        _ => false,
    }
}

pub(super) async fn discard_graphical(
    cfr: &CfrInfo<'_>,
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
        .await
    };
    if choice == 1 {
        discard_graphical_changes(items);
        state.save_result = None;
        state.status_message = Some(("Unsaved changes discarded.", true));
    }
}

pub(super) async fn help_graphical_item(
    cfr: &CfrInfo<'_>,
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
                crate::cfr::level_name(*current_level),
            ));
            content.push(Block::fact(
                "Saved",
                crate::cfr::level_name(*original_level),
            ));
            content.push(Block::fact(
                "Default",
                crate::cfr::level_name(crate::cfr::DEFAULT_LEVEL),
            ));
            String::from("CrabEFI log level")
        }
        MenuItem::CrabExternalBoot {
            current,
            original,
            floor,
        } => {
            content.push(Block::text(EXTERNAL_BOOT_HELP));
            content.push(Block::text(
                "Choices looser than the firmware build are not offered. Applies when saved.",
            ));
            content.push(Block::fact("Current", external_boot_name(*current)));
            content.push(Block::fact("Saved", external_boot_name(*original)));
            content.push(Block::fact("Default", external_boot_name(*floor)));
            String::from("External boot")
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
        .await
    };
    if choice == 1 {
        restore_graphical_default(cfr, items, state);
    }
}

pub(super) fn restore_graphical_default(
    cfr: &CfrInfo<'_>,
    items: &mut [MenuItem],
    state: &mut GraphicalState,
) {
    state.status_message = Some(
        match apply_graphical_edit(cfr, items, state, SettingEdit::RestoreDefault) {
            Some(true) => ("Default value set; save to keep it.", true),
            Some(false) => ("Already at the default value.", true),
            None => (
                "Read-only or unavailable; the default cannot be applied.",
                false,
            ),
        },
    );
}

/// Numeric editors accept an explicit decimal or 0x-prefixed hexadecimal value.
pub(super) fn parse_graphical_number(
    text: &str,
    min: u32,
    max: u32,
    step: u32,
) -> Result<u32, &'static str> {
    let text = text.trim();
    let n = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        text.parse::<u32>()
    }
    .map_err(|_| "Enter a decimal number or 0x-prefixed hexadecimal.")?;
    validate_number(n, min, max, step)?;
    Ok(n)
}

/// The selected row, as the anchor for pickers and field editors.
fn selected_anchor(
    cfr: &CfrInfo<'_>,
    items: &[MenuItem],
    state: &GraphicalState,
    fb: &FramebufferInfo,
) -> Option<Rect> {
    let l = fw_layout(fb);
    let rows = section_rows(cfr, items, state.section);
    let pos = rows.iter().position(|i| *i == state.selected)?;
    row_rect(&l, fb, pos, state.scroll_offset, rows.len())
}

pub(super) fn choice_tags(
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

pub(super) async fn edit_graphical_item(
    cfr: &CfrInfo<'_>,
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
    let result: Option<SettingEdit> = {
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
                let labels: Vec<&str> = crate::cfr::LEVEL_CHOICES
                    .iter()
                    .map(|level| crate::cfr::level_name(*level))
                    .collect();
                let current = crate::cfr::level_index(*current_level);
                let tags = choice_tags(
                    Some(crate::cfr::level_index(*original_level)),
                    Some(crate::cfr::level_index(crate::cfr::DEFAULT_LEVEL)),
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
                .await
                .and_then(|index| cfr::LEVEL_CHOICES.get(index).copied())
                .map(SettingEdit::SetLogLevel)
            }
            Some(MenuItem::CrabExternalBoot {
                current,
                original,
                floor,
            }) => {
                let choices = external_boot_choices(*floor);
                let labels: Vec<&str> = choices.clone().map(external_boot_name).collect();
                let pos = |choice: usize| choice.checked_sub(*floor);
                let selected = pos(*current).unwrap_or(0);
                let tags = choice_tags(pos(*original), Some(0), selected);
                dialog::select(
                    fb,
                    &backdrop,
                    anchor,
                    "External boot",
                    &labels,
                    selected,
                    &tags,
                )
                .await
                .map(|i| SettingEdit::SetExternalBoot(choices.start + i))
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
                        Some(SettingEdit::Set(CfrValue::Bool(!*value)))
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
                        .await
                        .and_then(|i| i.checked_sub(extra))
                        .and_then(|i| choices.get(i))
                        .map(|c| SettingEdit::Set(CfrValue::Number(c.value)))
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
                        .await
                        .and_then(|text| parse_graphical_number(&text, *min, *max, *step).ok())
                        .map(|n| SettingEdit::Set(CfrValue::Number(n)))
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
                    .await
                    .map(|text| SettingEdit::Set(CfrValue::Varchar(text))),
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
    let _ = apply_graphical_edit(cfr, items, state, result);
}

pub(super) fn apply_graphical_edit(
    cfr: &CfrInfo<'_>,
    items: &mut [MenuItem],
    state: &mut GraphicalState,
    edit: SettingEdit,
) -> Option<bool> {
    // Only a changed draft supersedes the previous save attempt.
    let changed = apply_edit(cfr, items, state.selected, edit)?;
    if changed {
        state.save_result = None;
        state.status_message = None;
    }
    Some(changed)
}
