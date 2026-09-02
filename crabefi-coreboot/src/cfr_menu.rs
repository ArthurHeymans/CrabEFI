//! CFR Firmware Settings Menu
//!
//! This module provides a user interface for viewing and modifying
//! coreboot firmware options exposed via CFR (Coreboot Form Representation).
//!
//! The menu displays all CFR forms and their options, allowing the user
//! to navigate and modify settings. Changes are persisted to UEFI variables.
//!
//! Dependency evaluation is supported: options whose dependencies are not
//! met are hidden or shown as inactive according to their flags.

use crate::cfr::{self, CfrInfo, CfrOption, CfrOptionType, CfrValue};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
#[cfg(feature = "ui")]
use crabefi::FramebufferConfig as FramebufferInfo;
use crabefi::drivers::serial as serial_driver;
use crabefi::framebuffer_console::{
    Color, DEFAULT_BG, DEFAULT_FG, FramebufferConsole, HIGHLIGHT_BG, HIGHLIGHT_FG,
};
use crabefi::menu_common::{self, KeyPress, SerialWriter};
use crabefi::time::delay_ms;
#[cfg(feature = "ui")]
use crabefi::ui::{self, NavItem, render, theme};

use heapless::String as StackString;
#[cfg(feature = "ui")]
use render::{FontSize, Rgb};

/// Menu title
const MENU_TITLE: &str = "Firmware Settings";

/// Help text
const HELP_TEXT: &str =
    "Up/Down: Navigate | Enter/Space: Edit | +/-: Inc/Dec | ?: Help | Esc: Exit";

/// Menu item types
#[derive(Debug, Clone)]
enum MenuItem {
    /// Form header (category separator)
    FormHeader { name: String },
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

/// Returns true if any option's current value differs from its original value
fn has_changes(items: &[MenuItem]) -> bool {
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

/// Treat the current in-menu values as saved after a successful explicit save.
#[cfg(feature = "ui")]
fn mark_changes_saved(items: &mut [MenuItem]) {
    for item in items {
        match item {
            MenuItem::CrabLogLevel {
                current_level,
                original_level,
            } => *original_level = *current_level,
            MenuItem::Option {
                current_value,
                original_value,
                ..
            } => *original_value = current_value.clone(),
            _ => {}
        }
    }
}

/// Show the CFR firmware settings menu
///
/// Displays the menu and handles user interaction.
/// Returns when the user exits the menu.
pub fn show_cfr_menu() {
    let empty_cfr;
    let cfr_info = match cfr::get_cfr() {
        Some(cfr) => cfr,
        None => {
            empty_cfr = CfrInfo::new();
            &empty_cfr
        }
    };

    #[cfg(feature = "ui")]
    if let Some(fb) = crabefi::handoff::framebuffer() {
        show_cfr_menu_graphical(cfr_info, &fb);
        return;
    }

    let fb_info = crabefi::handoff::framebuffer();
    let mut fb_console = fb_info.as_ref().map(FramebufferConsole::new);

    let mut items = build_menu_items(cfr_info);

    if items.is_empty() {
        show_no_options_message(&mut fb_console);
        return;
    }

    let mut selected = find_first_selectable(cfr_info, &items, 0);
    let mut status_message: Option<(&str, bool)> = None;
    let mut scroll_offset = 0usize;

    loop {
        menu_common::clear_screen(&mut fb_console);
        let modified = has_changes(&items);
        // Ensure scroll keeps selected item visible without allocating.
        let sel_vis_pos = visible_position_of(cfr_info, &items, selected).unwrap_or(0);
        let screen_rows = get_visible_rows(&fb_console);
        if sel_vis_pos < scroll_offset {
            scroll_offset = sel_vis_pos;
        } else if sel_vis_pos >= scroll_offset + screen_rows {
            scroll_offset = sel_vis_pos - screen_rows + 1;
        }
        scroll_offset =
            scroll_offset.min(visible_count(cfr_info, &items).saturating_sub(screen_rows));
        draw_menu(
            cfr_info,
            &items,
            selected,
            scroll_offset,
            modified,
            status_message,
            &mut fb_console,
        );

        status_message = None;

        loop {
            if let Some(key) = menu_common::read_key() {
                match key {
                    KeyPress::Up | KeyPress::Char('k') => {
                        selected = find_prev_selectable(cfr_info, &items, selected);
                        break;
                    }
                    KeyPress::Down | KeyPress::Char('j') => {
                        selected = find_next_selectable(cfr_info, &items, selected);
                        break;
                    }
                    KeyPress::Enter | KeyPress::Char(' ') => {
                        if can_edit_item(cfr_info, &items, selected) {
                            if let Some(MenuItem::Option {
                                form_idx,
                                option_idx,
                                current_value,
                                ..
                            }) = items.get_mut(selected)
                            {
                                let (fi, oi) = (*form_idx, *option_idx);
                                if let Some(option) = get_option(cfr_info, fi, oi) {
                                    toggle_value(option, current_value);
                                }
                            } else {
                                increment_option(cfr_info, &mut items, selected);
                            }
                        } else if is_selectable_item(items.get(selected)) {
                            status_message = Some(("Option is read-only", false));
                        }
                        break;
                    }
                    KeyPress::Char('+') | KeyPress::Char('=') => {
                        increment_option(cfr_info, &mut items, selected);
                        break;
                    }
                    KeyPress::Char('-') => {
                        decrement_option(cfr_info, &mut items, selected);
                        break;
                    }
                    KeyPress::Escape | KeyPress::Char('q') | KeyPress::Char('Q') => {
                        if has_changes(&items) && confirm_save(&mut fb_console) {
                            let (saved, failed) = save_all_changes(cfr_info, &items);
                            show_save_result(saved, failed, &mut fb_console);
                        }
                        return;
                    }
                    KeyPress::Char('?') => {
                        if let Some(MenuItem::Option {
                            form_idx,
                            option_idx,
                            ..
                        }) = items.get(selected)
                            && let Some(option) = get_option(cfr_info, *form_idx, *option_idx)
                        {
                            show_help(option, &mut fb_console);
                        } else if matches!(items.get(selected), Some(MenuItem::CrabLogLevel { .. }))
                        {
                            status_message = Some(("Controls CrabEFI serial log verbosity", true));
                        }
                        break;
                    }
                    _ => {}
                }
            }
            delay_ms(10);
        }
    }
}

/// Build menu items from CFR info.
///
/// All non-suppressed items are included regardless of dependency state.
/// Dependencies are evaluated dynamically at draw/interaction time so that
/// toggling a "parent" option immediately shows or hides dependent items.
fn build_menu_items(cfr: &CfrInfo) -> Vec<MenuItem> {
    let mut items = Vec::new();

    let mut crabefi_name = String::new();
    crabefi_name.push_str("CrabEFI");
    items.push(MenuItem::FormHeader { name: crabefi_name });
    let current_level = crabefi::logger::configured_level();
    items.push(MenuItem::CrabLogLevel {
        current_level,
        original_level: current_level,
    });

    for (form_idx, form) in cfr.forms.iter().enumerate() {
        if !form.is_visible() {
            continue;
        }

        items.push(MenuItem::FormHeader {
            name: form.ui_name.clone(),
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
                    let current_value = cfr::read_option_value(option);
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

/// Look up the current in-flight numeric value for an option identified by
/// `object_id`, checking the menu items first (which reflect the user's
/// uncommitted edits) and falling back to persistent storage via
/// `CfrInfo::find_numeric_value`.
fn find_live_numeric_value(cfr: &CfrInfo, items: &[MenuItem], object_id: u64) -> Option<u32> {
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
    // Fallback to stored value
    cfr.find_numeric_value(object_id)
}

/// Evaluate whether a dependency is met using live (in-flight) menu values.
fn is_dep_met_live(
    cfr: &CfrInfo,
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

/// Check if a menu item is currently visible based on live dependency state.
///
/// Form headers are visible if the form's dependency is met. Options, comments,
/// and subform headers are visible if the owning form's dependency AND the
/// item's own dependency are both met.
fn is_item_visible(cfr: &CfrInfo, items: &[MenuItem], item: &MenuItem) -> bool {
    match item {
        MenuItem::FormHeader { name } => {
            // Find the form by name and check its dependency
            cfr.forms
                .iter()
                .find(|f| f.ui_name == *name)
                .is_none_or(|form| {
                    is_dep_met_live(cfr, items, form.dependency_id, &form.dep_values)
                })
        }
        MenuItem::Option {
            form_idx,
            option_idx,
            ..
        } => {
            let form_ok = cfr.forms.get(*form_idx).is_none_or(|form| {
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

/// Get an option by form and option index
fn get_option(cfr: &CfrInfo, form_idx: usize, option_idx: usize) -> Option<&CfrOption> {
    cfr.forms
        .get(form_idx)
        .and_then(|f| f.options.get(option_idx))
}

/// Find the first selectable and visible item starting from index
fn find_first_selectable(cfr: &CfrInfo, items: &[MenuItem], start: usize) -> usize {
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

fn find_prev_selectable(cfr: &CfrInfo, items: &[MenuItem], current: usize) -> usize {
    for i in (0..current).rev() {
        if is_selectable(&items[i]) && is_item_visible(cfr, items, &items[i]) {
            return i;
        }
    }
    current
}

fn find_next_selectable(cfr: &CfrInfo, items: &[MenuItem], current: usize) -> usize {
    for (i, item) in items.iter().enumerate().skip(current + 1) {
        if is_selectable(item) && is_item_visible(cfr, items, item) {
            return i;
        }
    }
    current
}

fn is_selectable(item: &MenuItem) -> bool {
    matches!(
        item,
        MenuItem::Option { .. } | MenuItem::CrabLogLevel { .. }
    )
}

fn is_selectable_item(item: Option<&MenuItem>) -> bool {
    item.is_some_and(is_selectable)
}

/// Check if the item at `index` is an editable, visible option (immutable borrow).
fn can_edit_item(cfr: &CfrInfo, items: &[MenuItem], index: usize) -> bool {
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

fn get_visible_rows(fb_console: &Option<FramebufferConsole>) -> usize {
    fb_console
        .as_ref()
        .map(|c| c.rows() as usize)
        .unwrap_or(20)
        .saturating_sub(10)
}

/// Toggle/cycle a value (Enter/Space)
fn toggle_value(option: &CfrOption, value: &mut CfrValue) -> bool {
    match (&option.option_type, value) {
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
                return true;
            }
            false
        }
        (CfrOptionType::Number { min, max, step, .. }, CfrValue::Number(n)) => {
            let new_val = (*n).saturating_add(*step);
            if new_val <= *max {
                *n = new_val;
            } else {
                *n = *min; // Wrap around
            }
            true
        }
        _ => false,
    }
}

/// Increment a numeric/enum option in-place
fn increment_option(cfr: &CfrInfo, items: &mut [MenuItem], index: usize) -> bool {
    // Check editability with live dependencies before taking a mutable borrow
    if !can_edit_item(cfr, items, index) {
        return false;
    }

    if let Some(MenuItem::CrabLogLevel { current_level, .. }) = items.get_mut(index) {
        let current_idx = crabefi::logger::level_index(*current_level);
        let next_idx = (current_idx + 1) % crabefi::logger::LEVEL_CHOICES.len();
        *current_level = crabefi::logger::LEVEL_CHOICES[next_idx];
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
        (CfrOptionType::Number { max, step, .. }, CfrValue::Number(n)) => {
            let new_val = (*n).saturating_add(*step);
            if new_val <= *max {
                *n = new_val;
                true
            } else if *n < *max {
                // Unaligned: clamp to max
                *n = *max;
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Decrement a numeric/enum option in-place
fn decrement_option(cfr: &CfrInfo, items: &mut [MenuItem], index: usize) -> bool {
    // Check editability with live dependencies before taking a mutable borrow
    if !can_edit_item(cfr, items, index) {
        return false;
    }

    if let Some(MenuItem::CrabLogLevel { current_level, .. }) = items.get_mut(index) {
        let current_idx = crabefi::logger::level_index(*current_level);
        let prev_idx = if current_idx == 0 {
            crabefi::logger::LEVEL_CHOICES.len().saturating_sub(1)
        } else {
            current_idx - 1
        };
        *current_level = crabefi::logger::LEVEL_CHOICES[prev_idx];
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
        (CfrOptionType::Number { min, step, .. }, CfrValue::Number(n)) => {
            if *n >= *min + *step {
                *n -= *step;
                true
            } else if *n > *min {
                // Unaligned: clamp to min
                *n = *min;
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Save modified option values to persistent storage.
///
/// Only writes options that were actually changed by the user, reducing
/// unnecessary SPI flash wear. Returns `(saved, failed)` counts.
fn save_all_changes(cfr: &CfrInfo, items: &[MenuItem]) -> (usize, usize) {
    let mut saved = 0usize;
    let mut failed = 0usize;
    for item in items {
        match item {
            MenuItem::CrabLogLevel {
                current_level,
                original_level,
            } if current_level != original_level => {
                match crabefi::logger::set_configured_level(*current_level) {
                    Ok(()) => saved += 1,
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
                    match cfr::write_option_value(option, current_value) {
                        Ok(()) => saved += 1,
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

/// Show confirmation dialog for saving on exit
fn confirm_save(fb_console: &mut Option<FramebufferConsole>) -> bool {
    menu_common::confirm_dialog(
        fb_console,
        "Save changes? (CFR changes may require reset)",
        "Press Y to save, N to discard",
    )
}

/// Show a brief save result message (displayed on the confirm screen)
fn show_save_result(saved: usize, failed: usize, fb_console: &mut Option<FramebufferConsole>) {
    if failed == 0 {
        let _ = write!(
            SerialWriter,
            "\r\n\x1b[1;32m  Saved {} option(s).\x1b[0m\r\n",
            saved
        );
        if let Some(console) = fb_console {
            let rows = console.rows();
            console.set_fg_color(Color::new(0, 255, 0));
            let mut buf = [0u8; 64];
            let msg = fmt_save_msg(&mut buf, saved, 0);
            console.write_centered(rows / 2 + 4, msg);
            console.reset_colors();
        }
    } else {
        let _ = write!(
            SerialWriter,
            "\r\n\x1b[1;31m  Saved {} option(s), {} failed to write.\x1b[0m\r\n",
            saved, failed
        );
        if let Some(console) = fb_console {
            let rows = console.rows();
            console.set_fg_color(Color::new(255, 64, 64));
            let mut buf = [0u8; 64];
            let msg = fmt_save_msg(&mut buf, saved, failed);
            console.write_centered(rows / 2 + 4, msg);
            console.reset_colors();
        }
    }
    // Brief pause so the user can read the message
    delay_ms(1500);
}

/// Format save result into a stack buffer (no alloc needed for a short message)
fn fmt_save_msg(buf: &mut [u8; 64], saved: usize, failed: usize) -> &str {
    use core::fmt::Write;
    struct BufWriter<'a> {
        buf: &'a mut [u8],
        pos: usize,
    }
    impl<'a> core::fmt::Write for BufWriter<'a> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let end = (self.pos + bytes.len()).min(self.buf.len());
            let count = end - self.pos;
            self.buf[self.pos..end].copy_from_slice(&bytes[..count]);
            self.pos = end;
            Ok(())
        }
    }
    let mut w = BufWriter {
        buf: buf.as_mut_slice(),
        pos: 0,
    };
    if failed == 0 {
        let _ = write!(w, "Saved {} option(s).", saved);
    } else {
        let _ = write!(w, "Saved {}, {} failed to write.", saved, failed);
    }
    let len = w.pos;
    core::str::from_utf8(&buf[..len]).unwrap_or("Save complete.")
}

/// Show help for an option
fn show_help(option: &CfrOption, fb_console: &mut Option<FramebufferConsole>) {
    serial_driver::write_str("\x1b[2J\x1b[H");
    serial_driver::write_str("\r\n");
    serial_driver::write_str("\x1b[1;36m");
    serial_driver::write_str("  ");
    serial_driver::write_str(&option.ui_name);
    serial_driver::write_str("\x1b[0m\r\n\r\n");

    if !option.ui_helptext.is_empty() {
        serial_driver::write_str("  ");
        serial_driver::write_str(&option.ui_helptext);
        serial_driver::write_str("\r\n");
    } else {
        serial_driver::write_str("  No help available for this option.\r\n");
    }

    serial_driver::write_str("\r\n  Press any key to continue...\r\n");

    if let Some(console) = fb_console {
        console.clear();
        let rows = console.rows();
        console.set_fg_color(Color::new(0, 192, 192));
        console.write_centered(4, &option.ui_name);
        console.reset_colors();

        if !option.ui_helptext.is_empty() {
            console.set_position(4, 7);
            let _ = console.write_str(&option.ui_helptext);
        } else {
            console.write_centered(7, "No help available for this option.");
        }

        console.write_centered(rows - 3, "Press any key to continue...");
    }

    loop {
        if menu_common::read_key().is_some() {
            break;
        }
        delay_ms(10);
    }
}

/// Show message that no options are available
fn show_no_options_message(fb_console: &mut Option<FramebufferConsole>) {
    serial_driver::write_str("\r\n");
    serial_driver::write_str("\x1b[1;33m");
    serial_driver::write_str("  No configurable options found\r\n");
    serial_driver::write_str("\x1b[0m");
    serial_driver::write_str("\r\n  Press any key to continue...\r\n");

    if let Some(console) = fb_console {
        console.clear();
        let rows = console.rows();
        console.set_fg_color(Color::new(255, 255, 0));
        console.write_centered(rows / 2, "No configurable options found");
        console.reset_colors();
        console.write_centered(rows / 2 + 2, "Press any key to continue...");
    }

    loop {
        if menu_common::read_key().is_some() {
            break;
        }
        delay_ms(10);
    }
}

// ============================================================================
// Graphical UI (feature = "ui")
// ============================================================================

#[cfg(feature = "ui")]
const GFX_ITEM_H: u32 = 50;
#[cfg(feature = "ui")]
const GFX_ITEM_GAP: u32 = 6;
#[cfg(feature = "ui")]
const GFX_ITEM_STRIDE: u32 = GFX_ITEM_H + GFX_ITEM_GAP;
#[cfg(feature = "ui")]
const GFX_TITLE_H: u32 = 68;

#[cfg(feature = "ui")]
struct GraphicalState {
    selected: usize,
    hovered: Option<usize>,
    scroll_offset: usize,
    status_message: Option<(&'static str, bool)>,
}

#[cfg(feature = "ui")]
impl GraphicalState {
    fn new(selected: usize) -> Self {
        Self {
            selected,
            hovered: None,
            scroll_offset: 0,
            status_message: None,
        }
    }
}

/// Show the CFR settings menu using the graphical CrabEFI UI.
#[cfg(feature = "ui")]
fn show_cfr_menu_graphical(cfr_info: &CfrInfo, fb: &FramebufferInfo) {
    let mut items = build_menu_items(cfr_info);

    if items.is_empty() {
        show_no_options_graphical(fb);
        return;
    }

    let mut cursor = crabefi::cursor::CursorRenderer::new();
    let mut state = GraphicalState::new(find_first_selectable(cfr_info, &items, 0));

    draw_graphical_menu(cfr_info, &items, &state, fb);

    loop {
        ui::poll_and_render_cursor(fb, &mut cursor);

        let hovered = graphical_item_hit(cfr_info, &items, &state, fb);
        if hovered != state.hovered {
            state.hovered = hovered;
            draw_graphical_menu(cfr_info, &items, &state, fb);
        }

        if let Some(key) = menu_common::read_key() {
            state.status_message = None;
            match key {
                KeyPress::Up | KeyPress::Char('k') => {
                    state.selected = find_prev_selectable(cfr_info, &items, state.selected);
                }
                KeyPress::Down | KeyPress::Char('j') => {
                    state.selected = find_next_selectable(cfr_info, &items, state.selected);
                }
                KeyPress::Enter | KeyPress::Char(' ') => {
                    if can_edit_item(cfr_info, &items, state.selected) {
                        if let Some(MenuItem::Option {
                            form_idx,
                            option_idx,
                            current_value,
                            ..
                        }) = items.get_mut(state.selected)
                        {
                            if let Some(option) = get_option(cfr_info, *form_idx, *option_idx) {
                                toggle_value(option, current_value);
                            }
                        } else {
                            increment_option(cfr_info, &mut items, state.selected);
                        }
                    } else if is_selectable_item(items.get(state.selected)) {
                        state.status_message = Some(("Option is read-only", false));
                    }
                }
                KeyPress::Char('+') | KeyPress::Char('=') => {
                    if !increment_option(cfr_info, &mut items, state.selected) {
                        state.status_message = Some(("Option cannot be increased", false));
                    }
                }
                KeyPress::Char('-') => {
                    if !decrement_option(cfr_info, &mut items, state.selected) {
                        state.status_message = Some(("Option cannot be decreased", false));
                    }
                }
                KeyPress::Char('s') | KeyPress::Char('S') => {
                    if has_changes(&items) {
                        cursor.hide(fb);
                        let (saved, failed) = save_all_changes(cfr_info, &items);
                        show_save_result_graphical(fb, saved, failed);
                        if failed == 0 {
                            mark_changes_saved(&mut items);
                        }
                    } else {
                        state.status_message = Some(("No changes to save", true));
                    }
                }
                KeyPress::Char('f') | KeyPress::Char('F') => {
                    state.status_message = Some(("Already in firmware settings", true));
                }
                KeyPress::Char('r') | KeyPress::Char('R') => {
                    crabefi::reset_system();
                }
                KeyPress::Escape | KeyPress::Char('q') | KeyPress::Char('Q') => {
                    cursor.hide(fb);
                    if has_changes(&items) && confirm_save_graphical(fb) {
                        let (saved, failed) = save_all_changes(cfr_info, &items);
                        show_save_result_graphical(fb, saved, failed);
                    }
                    return;
                }
                KeyPress::Char('?') => {
                    if let Some(MenuItem::Option {
                        form_idx,
                        option_idx,
                        ..
                    }) = items.get(state.selected)
                        && let Some(option) = get_option(cfr_info, *form_idx, *option_idx)
                    {
                        cursor.hide(fb);
                        show_help_graphical(fb, option);
                    } else if matches!(
                        items.get(state.selected),
                        Some(MenuItem::CrabLogLevel { .. })
                    ) {
                        state.status_message =
                            Some(("Controls CrabEFI serial log verbosity", true));
                    }
                }
                KeyPress::MouseClick { .. } => {
                    if let Some(item_idx) = state.hovered {
                        if is_selectable(&items[item_idx]) {
                            state.selected = item_idx;
                            if can_edit_item(cfr_info, &items, item_idx) {
                                if let Some(MenuItem::Option {
                                    form_idx,
                                    option_idx,
                                    current_value,
                                    ..
                                }) = items.get_mut(item_idx)
                                {
                                    if let Some(option) =
                                        get_option(cfr_info, *form_idx, *option_idx)
                                    {
                                        toggle_value(option, current_value);
                                    }
                                } else {
                                    increment_option(cfr_info, &mut items, item_idx);
                                }
                            }
                        }
                    }
                }
                KeyPress::MouseScroll(dz) => {
                    if dz > 0 {
                        state.selected = find_next_selectable(cfr_info, &items, state.selected);
                    } else {
                        state.selected = find_prev_selectable(cfr_info, &items, state.selected);
                    }
                }
                _ => {}
            }

            keep_graphical_selection_visible(cfr_info, &items, &mut state, fb);
            draw_graphical_menu(cfr_info, &items, &state, fb);
        }

        delay_ms(8);
    }
}

#[cfg(feature = "ui")]
fn graphical_canvas(fb: &FramebufferInfo) -> (i32, i32, u32, u32) {
    let x = theme::SIDEBAR_W as i32 + theme::PAD as i32;
    let y = (theme::HEADER_H + theme::PAD) as i32;
    let w = fb.width - theme::SIDEBAR_W - theme::PAD * 2;
    let h = fb.height - theme::HEADER_H - theme::FOOTER_H - theme::PAD * 2;
    (x, y, w, h)
}

#[cfg(feature = "ui")]
fn graphical_list_area(fb: &FramebufferInfo) -> (i32, i32, u32, u32) {
    let (cx, cy, cw, ch) = graphical_canvas(fb);
    let y = cy + GFX_TITLE_H as i32;
    (cx, y, cw, ch.saturating_sub(GFX_TITLE_H))
}

#[cfg(feature = "ui")]
fn graphical_visible_slots(fb: &FramebufferInfo) -> usize {
    let (_, _, _, h) = graphical_list_area(fb);
    (h / GFX_ITEM_STRIDE).max(1) as usize
}

#[cfg(feature = "ui")]
fn keep_graphical_selection_visible(
    cfr: &CfrInfo,
    items: &[MenuItem],
    state: &mut GraphicalState,
    fb: &FramebufferInfo,
) {
    let Some(sel_vis_pos) = visible_position_of(cfr, items, state.selected) else {
        state.selected = find_first_selectable(cfr, items, 0);
        state.scroll_offset = 0;
        return;
    };
    let slots = graphical_visible_slots(fb);
    if sel_vis_pos < state.scroll_offset {
        state.scroll_offset = sel_vis_pos;
    } else if sel_vis_pos >= state.scroll_offset + slots {
        state.scroll_offset = sel_vis_pos - slots + 1;
    }
    state.scroll_offset = state
        .scroll_offset
        .min(visible_count(cfr, items).saturating_sub(slots));
}

#[cfg(feature = "ui")]
fn draw_graphical_menu(
    cfr: &CfrInfo,
    items: &[MenuItem],
    state: &GraphicalState,
    fb: &FramebufferInfo,
) {
    ui::clear(fb);
    ui::draw_header(fb);
    ui::draw_sidebar(fb, NavItem::Firmware, None);

    let footer = if has_changes(items) {
        "Up/Down Navigate  Enter Edit  +/- Adjust  ? Help  S Save  F Firmware  R Reset  Esc Save/Exit"
    } else {
        "Up/Down Navigate  Enter Edit  +/- Adjust  ? Help  S Save  F Firmware  R Reset  Esc Back"
    };
    ui::draw_footer(fb, footer);

    let (cx, cy, cw, _) = graphical_canvas(fb);
    draw_graphical_title(fb, cx, cy, cw, has_changes(items));

    let slots = graphical_visible_slots(fb);
    let visible_len = visible_count(cfr, items);
    let (_, list_y, _, _) = graphical_list_area(fb);

    for screen_idx in 0..slots {
        let Some(item_idx) = visible_index_at(cfr, items, state.scroll_offset + screen_idx) else {
            break;
        };
        let y = list_y + (screen_idx as u32 * GFX_ITEM_STRIDE) as i32;
        draw_graphical_item(
            cfr,
            &items[item_idx],
            item_idx == state.selected,
            state.hovered == Some(item_idx),
            fb,
            cx,
            y,
            cw,
        );
    }

    draw_graphical_scroll(fb, visible_len, state.scroll_offset, slots);

    if let Some((msg, ok)) = state.status_message {
        let color = if ok { theme::GREEN } else { theme::ERROR };
        render::draw_text_centered(
            fb,
            cx,
            (fb.height - theme::FOOTER_H - 24) as i32,
            cw,
            msg,
            FontSize::Small,
            color,
            None,
        );
    }
}

#[cfg(feature = "ui")]
fn draw_graphical_title(fb: &FramebufferInfo, cx: i32, cy: i32, cw: u32, modified: bool) {
    render::draw_text_spaced(
        fb,
        cx,
        cy,
        "HARDWARE CONFIGURATION",
        FontSize::Small,
        2,
        theme::PRIMARY.darken(80),
        None,
    );
    let title_y = cy + render::font_height(FontSize::Small) as i32 + 4;
    render::draw_text(
        fb,
        cx,
        title_y,
        if modified {
            "Firmware Settings *"
        } else {
            "Firmware Settings"
        },
        FontSize::Display,
        theme::TEXT,
        None,
    );
    render::draw_text_right(
        fb,
        cx,
        title_y + 10,
        cw,
        "COREBOOT CFR",
        FontSize::Small,
        theme::OUTLINE,
        None,
    );
}

#[cfg(feature = "ui")]
fn draw_graphical_item(
    cfr: &CfrInfo,
    item: &MenuItem,
    selected: bool,
    hovered: bool,
    fb: &FramebufferInfo,
    x: i32,
    y: i32,
    w: u32,
) {
    match item {
        MenuItem::FormHeader { name } => {
            render::draw_text_spaced(
                fb,
                x,
                y + 16,
                &truncate_for_width(name, w.saturating_sub(24), FontSize::Small),
                FontSize::Small,
                2,
                theme::PRIMARY,
                None,
            );
            render::draw_separator(fb, x, y + GFX_ITEM_H as i32 - 8, w, theme::GHOST, theme::BG);
        }
        MenuItem::SubformHeader { name } => {
            render::draw_text(
                fb,
                x + 12,
                y + 15,
                &truncate_for_width(name, w.saturating_sub(24), FontSize::Normal),
                FontSize::Normal,
                theme::TERTIARY,
                None,
            );
        }
        MenuItem::Comment { text } => {
            render::draw_text(
                fb,
                x + 12,
                y + 17,
                &truncate_for_width(text, w.saturating_sub(24), FontSize::Small),
                FontSize::Small,
                theme::TEXT_DIM,
                None,
            );
        }
        MenuItem::Option {
            form_idx,
            option_idx,
            current_value,
            ..
        } => {
            if let Some(option) = get_option(cfr, *form_idx, *option_idx) {
                draw_graphical_option(fb, option, current_value, selected, hovered, x, y, w);
            }
        }
        MenuItem::CrabLogLevel { current_level, .. } => {
            draw_graphical_log_level(fb, *current_level, selected, hovered, x, y, w);
        }
    }
}

#[cfg(feature = "ui")]
fn draw_graphical_log_level(
    fb: &FramebufferInfo,
    level: log::LevelFilter,
    selected: bool,
    hovered: bool,
    x: i32,
    y: i32,
    w: u32,
) {
    let bg = if selected {
        theme::BRIGHT
    } else if hovered {
        theme::CONT_HIGH
    } else {
        theme::CONTAINER
    };
    render::fill_rounded_rect(fb, x, y, w, GFX_ITEM_H, theme::RADIUS, bg);
    render::fill_rect(
        fb,
        x,
        y + 3,
        theme::ACCENT_BAR,
        GFX_ITEM_H - 6,
        theme::PRIMARY,
    );

    let label = crabefi::logger::level_name(level);
    let value_w = value_width(label).min(w / 2);
    let value_x = x + w as i32 - value_w as i32 - 14;
    let name_max_w = (value_x - x - 34).max(32) as u32;

    render::draw_text(
        fb,
        x + 18,
        y + 8,
        &truncate_for_width("CrabEFI log level", name_max_w, FontSize::Normal),
        FontSize::Normal,
        theme::TEXT,
        Some(bg),
    );
    render::draw_text(
        fb,
        x + 18,
        y + 31,
        "serial verbosity",
        FontSize::Small,
        theme::OUTLINE,
        Some(bg),
    );
    draw_value_pill(fb, value_x, y + 12, value_w, label, true);
}

#[cfg(feature = "ui")]
fn draw_graphical_option(
    fb: &FramebufferInfo,
    option: &CfrOption,
    value: &CfrValue,
    selected: bool,
    hovered: bool,
    x: i32,
    y: i32,
    w: u32,
) {
    let editable = option.is_editable();
    let bg = if selected {
        theme::BRIGHT
    } else if hovered {
        theme::CONT_HIGH
    } else {
        theme::CONTAINER
    };
    render::fill_rounded_rect(fb, x, y, w, GFX_ITEM_H, theme::RADIUS, bg);

    let accent = if selected {
        theme::PRIMARY
    } else if editable {
        theme::GHOST
    } else {
        theme::CONT_LOW
    };
    render::fill_rect(fb, x, y + 3, theme::ACCENT_BAR, GFX_ITEM_H - 6, accent);

    let value_label = format_value(option, value);
    let value_w = value_width(&value_label).min(w / 2);
    let value_x = x + w as i32 - value_w as i32 - 14;
    let name_max_w = (value_x - x - 34).max(32) as u32;
    let name_color = if editable {
        theme::TEXT
    } else {
        theme::TEXT_DIM
    };

    render::draw_text(
        fb,
        x + 18,
        y + 8,
        &truncate_for_width(&option.ui_name, name_max_w, FontSize::Normal),
        FontSize::Normal,
        name_color,
        Some(bg),
    );

    if !option.ui_helptext.is_empty() {
        render::draw_text(
            fb,
            x + 18,
            y + 31,
            "? help available",
            FontSize::Small,
            theme::OUTLINE,
            Some(bg),
        );
    }

    match (&option.option_type, value) {
        (CfrOptionType::Bool { .. }, CfrValue::Bool(on)) => {
            render::draw_toggle(fb, value_x, y + 16, *on, theme::PRIMARY);
        }
        _ => draw_value_pill(fb, value_x, y + 12, value_w, &value_label, editable),
    }
}

#[cfg(feature = "ui")]
fn draw_graphical_scroll(
    fb: &FramebufferInfo,
    visible_len: usize,
    scroll_offset: usize,
    visible_slots: usize,
) {
    if visible_len <= visible_slots {
        return;
    }
    let (cx, list_y, cw, list_h) = graphical_list_area(fb);
    let track_x = cx + cw as i32 - 4;
    render::fill_rounded_rect(fb, track_x, list_y, 4, list_h, 2, theme::SIDE);
    let fraction = visible_slots as u32 * 255 / visible_len as u32;
    let thumb_h = (list_h * fraction / 255).max(24).min(list_h);
    let max_off = visible_len.saturating_sub(visible_slots).max(1);
    let thumb_y = list_y + ((list_h - thumb_h) as usize * scroll_offset / max_off) as i32;
    render::fill_rounded_rect(fb, track_x, thumb_y, 4, thumb_h, 2, theme::PRIMARY);
}

#[cfg(feature = "ui")]
fn graphical_item_hit(
    cfr: &CfrInfo,
    items: &[MenuItem],
    state: &GraphicalState,
    fb: &FramebufferInfo,
) -> Option<usize> {
    let (mx, my) = crabefi::drivers::mouse_cursor::position();
    let (x, y, w, _) = graphical_list_area(fb);
    if mx < x || mx >= x + w as i32 || my < y {
        return None;
    }
    let slot = ((my - y) as u32 / GFX_ITEM_STRIDE) as usize;
    if slot >= graphical_visible_slots(fb) {
        return None;
    }
    visible_index_at(cfr, items, state.scroll_offset + slot)
}

fn push_truncated<const N: usize>(out: &mut StackString<N>, text: &str, max_chars: usize) {
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

#[cfg(feature = "ui")]
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

#[cfg(feature = "ui")]
fn value_width(label: &str) -> u32 {
    render::text_width(label, FontSize::Small) + 18
}

#[cfg(feature = "ui")]
fn draw_value_pill(fb: &FramebufferInfo, x: i32, y: i32, w: u32, label: &str, editable: bool) {
    let bg = if editable {
        theme::CONT_LOW
    } else {
        theme::SIDE
    };
    let fg = if editable {
        theme::PRIMARY
    } else {
        theme::TEXT_DIM
    };
    render::fill_rounded_rect(fb, x, y, w, 26, 13, bg);
    render::draw_text_centered(
        fb,
        x,
        y + 5,
        w,
        &truncate_for_width(label, w.saturating_sub(16), FontSize::Small),
        FontSize::Small,
        fg,
        Some(bg),
    );
}

#[cfg(feature = "ui")]
fn truncate_for_width(text: &str, max_width: u32, size: FontSize) -> StackString<128> {
    let max_chars = (max_width / render::font_width(size)).max(1) as usize;
    let char_count = text.chars().count();
    if char_count <= max_chars {
        let mut out = StackString::new();
        let _ = out.push_str(text);
        return out;
    }

    let mut out = StackString::new();
    for (idx, ch) in text.chars().enumerate() {
        if idx + 1 >= max_chars {
            let _ = out.push('~');
            break;
        }
        let _ = out.push(ch);
    }
    out
}

#[cfg(feature = "ui")]
fn show_help_graphical(fb: &FramebufferInfo, option: &CfrOption) {
    let mut cursor = crabefi::cursor::CursorRenderer::new();
    draw_help_graphical(fb, option);
    loop {
        ui::poll_and_render_cursor(fb, &mut cursor);
        if menu_common::read_key().is_some() {
            cursor.hide(fb);
            return;
        }
        delay_ms(8);
    }
}

#[cfg(feature = "ui")]
fn draw_help_graphical(fb: &FramebufferInfo, option: &CfrOption) {
    ui::clear(fb);
    ui::draw_header(fb);
    ui::draw_sidebar(fb, NavItem::Firmware, None);
    ui::draw_footer(fb, "Any key Back");

    let (cx, cy, cw, _) = graphical_canvas(fb);
    render::draw_text_spaced(
        fb,
        cx,
        cy,
        "SETTING HELP",
        FontSize::Small,
        2,
        theme::PRIMARY.darken(80),
        None,
    );
    render::draw_text(
        fb,
        cx,
        cy + render::font_height(FontSize::Small) as i32 + 4,
        &truncate_for_width(&option.ui_name, cw, FontSize::Display),
        FontSize::Display,
        theme::TEXT,
        None,
    );

    let card_y = cy + GFX_TITLE_H as i32;
    render::fill_rounded_rect(fb, cx, card_y, cw, 180, theme::RADIUS, theme::CONTAINER);
    render::fill_rect(fb, cx, card_y + 3, theme::ACCENT_BAR, 174, theme::PRIMARY);

    let text = if option.ui_helptext.is_empty() {
        "No help available for this option."
    } else {
        &option.ui_helptext
    };
    draw_wrapped_text(
        fb,
        cx + 18,
        card_y + 18,
        cw.saturating_sub(36),
        text,
        FontSize::Normal,
        theme::TEXT_DIM,
        Some(theme::CONTAINER),
        6,
    );
}

#[cfg(feature = "ui")]
fn draw_wrapped_text(
    fb: &FramebufferInfo,
    x: i32,
    mut y: i32,
    w: u32,
    text: &str,
    size: FontSize,
    fg: Rgb,
    bg: Option<Rgb>,
    max_lines: usize,
) {
    let max_chars = (w / render::font_width(size)).max(1) as usize;
    let mut line: StackString<160> = StackString::new();
    let mut lines = 0usize;

    for word in text.split(' ') {
        if lines >= max_lines {
            break;
        }
        let add_len = if line.is_empty() {
            word.len()
        } else {
            word.len() + 1
        };
        if !line.is_empty() && line.len() + add_len > max_chars {
            render::draw_text(fb, x, y, &line, size, fg, bg);
            y += render::font_height(size) as i32 + 4;
            line.clear();
            lines += 1;
        }
        if !line.is_empty() {
            let _ = line.push(' ');
        }
        let _ = line.push_str(word);
    }

    if !line.is_empty() && lines < max_lines {
        render::draw_text(fb, x, y, &line, size, fg, bg);
    }
}

#[cfg(feature = "ui")]
fn confirm_save_graphical(fb: &FramebufferInfo) -> bool {
    let mut cursor = crabefi::cursor::CursorRenderer::new();
    draw_confirm_save_graphical(fb);
    loop {
        ui::poll_and_render_cursor(fb, &mut cursor);
        if let Some(key) = menu_common::read_key() {
            match key {
                KeyPress::Char('y') | KeyPress::Char('Y') | KeyPress::Enter => {
                    cursor.hide(fb);
                    return true;
                }
                KeyPress::Char('n') | KeyPress::Char('N') | KeyPress::Escape => {
                    cursor.hide(fb);
                    return false;
                }
                KeyPress::MouseClick { x, y } => {
                    let (yes, no) = confirm_button_rects(fb);
                    if point_in_rect(x as i32, y as i32, yes) {
                        cursor.hide(fb);
                        return true;
                    }
                    if point_in_rect(x as i32, y as i32, no) {
                        cursor.hide(fb);
                        return false;
                    }
                }
                _ => {}
            }
        }
        delay_ms(8);
    }
}

#[cfg(feature = "ui")]
fn draw_confirm_save_graphical(fb: &FramebufferInfo) {
    ui::clear(fb);
    ui::draw_header(fb);
    ui::draw_sidebar(fb, NavItem::Firmware, None);
    ui::draw_footer(fb, "Y/Enter Save   N/Esc Discard");

    let (cx, cy, cw, ch) = graphical_canvas(fb);
    let modal_w = cw.min(520);
    let modal_h = 180;
    let x = cx + (cw - modal_w) as i32 / 2;
    let y = cy + (ch - modal_h) as i32 / 2;

    render::fill_rounded_rect(fb, x, y, modal_w, modal_h, theme::RADIUS, theme::CONTAINER);
    render::draw_glow(
        fb,
        x,
        y,
        modal_w,
        modal_h,
        theme::RADIUS,
        3,
        theme::PRIMARY,
        theme::BG,
    );
    render::draw_text_centered(
        fb,
        x,
        y + 24,
        modal_w,
        "Save firmware setting changes?",
        FontSize::Heading,
        theme::TEXT,
        Some(theme::CONTAINER),
    );
    render::draw_text_centered(
        fb,
        x,
        y + 62,
        modal_w,
        "Changes take effect after reset.",
        FontSize::Small,
        theme::TEXT_DIM,
        Some(theme::CONTAINER),
    );

    let (yes, no) = confirm_button_rects(fb);
    draw_button(fb, yes, "SAVE", true);
    draw_button(fb, no, "DISCARD", false);
}

#[cfg(feature = "ui")]
fn confirm_button_rects(fb: &FramebufferInfo) -> ((i32, i32, u32, u32), (i32, i32, u32, u32)) {
    let (cx, cy, cw, ch) = graphical_canvas(fb);
    let modal_w = cw.min(520);
    let modal_h = 180;
    let x = cx + (cw - modal_w) as i32 / 2;
    let y = cy + (ch - modal_h) as i32 / 2;
    let bw = 132;
    let bh = 38;
    let gap = 16;
    let by = y + 118;
    let bx = x + (modal_w as i32 - (bw * 2 + gap)) / 2;
    (
        (bx, by, bw as u32, bh as u32),
        (bx + bw + gap, by, bw as u32, bh as u32),
    )
}

#[cfg(feature = "ui")]
fn draw_button(fb: &FramebufferInfo, rect: (i32, i32, u32, u32), label: &str, primary: bool) {
    let (x, y, w, h) = rect;
    let bg = if primary {
        theme::PRIMARY
    } else {
        theme::CONT_HIGH
    };
    let fg = if primary {
        theme::ON_PRIMARY
    } else {
        theme::TEXT
    };
    render::fill_rounded_rect(fb, x, y, w, h, theme::RADIUS, bg);
    render::draw_text_centered(fb, x, y + 9, w, label, FontSize::Small, fg, Some(bg));
}

#[cfg(feature = "ui")]
fn point_in_rect(px: i32, py: i32, rect: (i32, i32, u32, u32)) -> bool {
    let (x, y, w, h) = rect;
    px >= x && px < x + w as i32 && py >= y && py < y + h as i32
}

#[cfg(feature = "ui")]
fn show_save_result_graphical(fb: &FramebufferInfo, saved: usize, failed: usize) {
    ui::clear(fb);
    ui::draw_header(fb);
    ui::draw_sidebar(fb, NavItem::Firmware, None);
    ui::draw_footer(fb, "Returning to firmware menu");

    let (cx, cy, cw, ch) = graphical_canvas(fb);
    let mut msg: StackString<80> = StackString::new();
    let ok = failed == 0;
    if ok {
        let _ = write!(msg, "Saved {} option(s).", saved);
    } else {
        let _ = write!(msg, "Saved {}, {} failed to write.", saved, failed);
    }
    render::draw_text_centered(
        fb,
        cx,
        cy + ch as i32 / 2 - 18,
        cw,
        &msg,
        FontSize::Heading,
        if ok { theme::GREEN } else { theme::ERROR },
        None,
    );
    delay_ms(1500);
}

#[cfg(feature = "ui")]
fn show_no_options_graphical(fb: &FramebufferInfo) {
    let mut cursor = crabefi::cursor::CursorRenderer::new();
    ui::clear(fb);
    ui::draw_header(fb);
    ui::draw_sidebar(fb, NavItem::Firmware, None);
    ui::draw_footer(fb, "Esc Back");

    let (cx, cy, cw, ch) = graphical_canvas(fb);
    render::draw_text_centered(
        fb,
        cx,
        cy + ch as i32 / 2 - 12,
        cw,
        "No configurable options found",
        FontSize::Normal,
        theme::TEXT_DIM,
        None,
    );

    loop {
        ui::poll_and_render_cursor(fb, &mut cursor);
        if let Some(key) = menu_common::read_key()
            && matches!(key, KeyPress::Escape | KeyPress::Enter | KeyPress::Char(_))
        {
            cursor.hide(fb);
            return;
        }
        delay_ms(8);
    }
}

// ============================================================================
// Drawing
// ============================================================================

/// Count menu items that are currently visible (dependency-aware).
fn visible_count(cfr: &CfrInfo, items: &[MenuItem]) -> usize {
    items
        .iter()
        .filter(|item| is_item_visible(cfr, items, item))
        .count()
}

/// Return the visible-list position of an item index without allocating.
fn visible_position_of(cfr: &CfrInfo, items: &[MenuItem], target: usize) -> Option<usize> {
    let mut pos = 0usize;
    for (idx, item) in items.iter().enumerate() {
        if !is_item_visible(cfr, items, item) {
            continue;
        }
        if idx == target {
            return Some(pos);
        }
        pos += 1;
    }
    None
}

/// Return the item index at a visible-list position without allocating.
fn visible_index_at(cfr: &CfrInfo, items: &[MenuItem], target_pos: usize) -> Option<usize> {
    let mut pos = 0usize;
    for (idx, item) in items.iter().enumerate() {
        if !is_item_visible(cfr, items, item) {
            continue;
        }
        if pos == target_pos {
            return Some(idx);
        }
        pos += 1;
    }
    None
}

/// Draw the complete menu
fn draw_menu(
    cfr: &CfrInfo,
    items: &[MenuItem],
    selected: usize,
    scroll_offset: usize,
    modified: bool,
    status_message: Option<(&str, bool)>,
    fb_console: &mut Option<FramebufferConsole>,
) {
    let cols = fb_console.as_ref().map(|c| c.cols()).unwrap_or(80) as usize;
    let rows = fb_console.as_ref().map(|c| c.rows()).unwrap_or(25) as usize;

    // Draw header
    let title = if modified {
        "Firmware Settings (modified)"
    } else {
        MENU_TITLE
    };
    menu_common::draw_header(title, fb_console, cols);

    // Calculate visible area
    let start_row = 4;
    let visible_rows = rows.saturating_sub(8);
    let vis_len = visible_count(cfr, items);

    // Draw items — only the visible ones, respecting scroll_offset.
    for screen_idx in 0..visible_rows {
        let Some(item_idx) = visible_index_at(cfr, items, scroll_offset + screen_idx) else {
            break;
        };
        let row = start_row + screen_idx;
        let is_selected = item_idx == selected;
        draw_item(cfr, &items[item_idx], is_selected, row, fb_console, cols);
    }

    // Draw scroll indicators
    if scroll_offset > 0 {
        draw_scroll_indicator(start_row - 1, "^", fb_console);
    }
    if scroll_offset + visible_rows < vis_len {
        draw_scroll_indicator(start_row + visible_rows, "v", fb_console);
    }

    // Draw help text
    let help_row = rows.saturating_sub(3);
    draw_help(help_row, fb_console, cols);

    // Draw status message if any
    if let Some((msg, is_success)) = status_message {
        draw_status_message(rows.saturating_sub(2), msg, is_success, fb_console);
    }
}

/// Draw a single menu item
fn draw_item(
    cfr: &CfrInfo,
    item: &MenuItem,
    is_selected: bool,
    row: usize,
    fb_console: &mut Option<FramebufferConsole>,
    cols: usize,
) {
    match item {
        MenuItem::FormHeader { name } => {
            draw_form_header(name, row, fb_console);
        }
        MenuItem::SubformHeader { name } => {
            draw_subform_header(name, row, fb_console);
        }
        MenuItem::Option {
            form_idx,
            option_idx,
            current_value,
            ..
        } => {
            if let Some(option) = get_option(cfr, *form_idx, *option_idx) {
                draw_option_item(option, current_value, is_selected, row, fb_console, cols);
            }
        }
        MenuItem::CrabLogLevel { current_level, .. } => {
            draw_log_level_item(*current_level, is_selected, row, fb_console, cols);
        }
        MenuItem::Comment { text } => {
            draw_comment(text, row, fb_console);
        }
    }
}

/// Draw a form header (category separator)
fn draw_form_header(name: &str, row: usize, fb_console: &mut Option<FramebufferConsole>) {
    let ansi_row = row + 1;
    let _ = write!(SerialWriter, "\x1b[{};1H", ansi_row);
    serial_driver::write_str("\x1b[1;36m");
    serial_driver::write_str("--- ");
    serial_driver::write_str(name);
    serial_driver::write_str(" ---");
    serial_driver::write_str("\x1b[0m\x1b[K\r\n");

    if let Some(console) = fb_console {
        console.set_position(0, row as u32);
        console.set_fg_color(Color::new(0, 192, 192));
        let _ = console.write_str("--- ");
        let _ = console.write_str(name);
        let _ = console.write_str(" ---");
        clear_line_remainder(console);
        console.reset_colors();
    }
}

/// Draw a subform header (indented section within a form)
fn draw_subform_header(name: &str, row: usize, fb_console: &mut Option<FramebufferConsole>) {
    let ansi_row = row + 1;
    let _ = write!(SerialWriter, "\x1b[{};1H", ansi_row);
    serial_driver::write_str("\x1b[1;35m"); // Magenta bold
    serial_driver::write_str("     ");
    serial_driver::write_str(name);
    serial_driver::write_str("\x1b[0m\x1b[K\r\n");

    if let Some(console) = fb_console {
        console.set_position(0, row as u32);
        console.set_fg_color(Color::new(192, 0, 192)); // Magenta
        let _ = console.write_str("     ");
        let _ = console.write_str(name);
        clear_line_remainder(console);
        console.reset_colors();
    }
}

/// Draw the CrabEFI log-level item.
fn draw_log_level_item(
    level: log::LevelFilter,
    is_selected: bool,
    row: usize,
    fb_console: &mut Option<FramebufferConsole>,
    cols: usize,
) {
    let name = "CrabEFI log level";
    let mut value_str = String::new();
    value_str.push('[');
    value_str.push_str(crabefi::logger::level_name(level));
    value_str.push(']');

    let ansi_row = row + 1;
    let _ = write!(SerialWriter, "\x1b[{};1H", ansi_row);

    if is_selected {
        serial_driver::write_str("\x1b[7m");
    }

    serial_driver::write_str("   ");
    serial_driver::write_str(name);

    let name_len = name.len();
    let pad_to = 40.min(cols.saturating_sub(value_str.len() + 5));
    for _ in name_len + 3..pad_to {
        serial_driver::write_str(" ");
    }
    serial_driver::write_str(&value_str);
    serial_driver::write_str("\x1b[0m\x1b[K\r\n");

    if let Some(console) = fb_console {
        console.set_position(0, row as u32);

        if is_selected {
            console.set_colors(HIGHLIGHT_FG, HIGHLIGHT_BG);
        } else {
            console.set_colors(DEFAULT_FG, DEFAULT_BG);
        }

        let _ = console.write_str("   ");
        let _ = console.write_str(name);

        let term_cols = console.cols() as usize;
        let pad_to = 40.min(term_cols.saturating_sub(value_str.len() + 5));
        for _ in name_len + 3..pad_to {
            let _ = console.write_str(" ");
        }
        let _ = console.write_str(&value_str);

        clear_line_remainder(console);
        console.reset_colors();
    }
}

/// Draw an option item
fn draw_option_item(
    option: &CfrOption,
    value: &CfrValue,
    is_selected: bool,
    row: usize,
    fb_console: &mut Option<FramebufferConsole>,
    cols: usize,
) {
    let is_editable = option.is_editable();

    // Format the value for display
    let mut value_str: StackString<128> = StackString::new();
    match (&option.option_type, value) {
        (CfrOptionType::Bool { .. }, CfrValue::Bool(b)) => {
            let _ = value_str.push_str(if *b { "[Enabled]" } else { "[Disabled]" });
        }
        (CfrOptionType::Enum { choices, .. }, CfrValue::Number(n)) => {
            if let Some(choice) = choices.iter().find(|c| c.value == *n) {
                let _ = value_str.push('[');
                push_truncated(&mut value_str, &choice.ui_name, 120);
                let _ = value_str.push(']');
            } else {
                let _ = write!(value_str, "[{}]", n);
            }
        }
        (CfrOptionType::Number { hex_display, .. }, CfrValue::Number(n)) => {
            if *hex_display {
                let _ = write!(value_str, "[0x{:X}]", n);
            } else {
                let _ = write!(value_str, "[{}]", n);
            }
        }
        (CfrOptionType::Varchar { .. }, CfrValue::Varchar(s)) => {
            let _ = value_str.push('[');
            push_truncated(&mut value_str, s, 20);
            let _ = value_str.push(']');
        }
        _ => {
            let _ = value_str.push_str("[-]");
        }
    }

    // Serial output
    let ansi_row = row + 1;
    let _ = write!(SerialWriter, "\x1b[{};1H", ansi_row);

    if is_selected {
        serial_driver::write_str("\x1b[7m");
    }
    if !is_editable {
        serial_driver::write_str("\x1b[90m");
    }

    serial_driver::write_str("   ");
    serial_driver::write_str(&option.ui_name);

    let name_len = option.ui_name.len();
    let pad_to = 40.min(cols.saturating_sub(value_str.len() + 5));
    for _ in name_len + 3..pad_to {
        serial_driver::write_str(" ");
    }
    serial_driver::write_str(&value_str);

    serial_driver::write_str("\x1b[0m\x1b[K\r\n");

    // Framebuffer output
    if let Some(console) = fb_console {
        console.set_position(0, row as u32);

        if is_selected {
            console.set_colors(HIGHLIGHT_FG, HIGHLIGHT_BG);
        } else if !is_editable {
            console.set_fg_color(Color::new(128, 128, 128));
        } else {
            console.set_colors(DEFAULT_FG, DEFAULT_BG);
        }

        let _ = console.write_str("   ");
        let _ = console.write_str(&option.ui_name);

        let name_len = option.ui_name.len();
        let term_cols = console.cols() as usize;
        let pad_to = 40.min(term_cols.saturating_sub(value_str.len() + 5));
        for _ in name_len + 3..pad_to {
            let _ = console.write_str(" ");
        }
        let _ = console.write_str(&value_str);

        clear_line_remainder(console);
        console.reset_colors();
    }
}

/// Draw a comment item
fn draw_comment(text: &str, row: usize, fb_console: &mut Option<FramebufferConsole>) {
    let ansi_row = row + 1;
    let _ = write!(SerialWriter, "\x1b[{};1H", ansi_row);
    serial_driver::write_str("\x1b[90m");
    serial_driver::write_str("   ");
    serial_driver::write_str(text);
    serial_driver::write_str("\x1b[0m\x1b[K\r\n");

    if let Some(console) = fb_console {
        console.set_position(0, row as u32);
        console.set_fg_color(Color::new(128, 128, 128));
        let _ = console.write_str("   ");
        let _ = console.write_str(text);
        clear_line_remainder(console);
        console.reset_colors();
    }
}

/// Draw scroll indicator
fn draw_scroll_indicator(row: usize, indicator: &str, fb_console: &mut Option<FramebufferConsole>) {
    let ansi_row = row + 1;
    let _ = write!(SerialWriter, "\x1b[{};40H{}", ansi_row, indicator);

    if let Some(console) = fb_console {
        let cols = console.cols();
        console.set_position(cols / 2, row as u32);
        console.set_fg_color(Color::new(128, 128, 128));
        let _ = console.write_str(indicator);
        console.reset_colors();
    }
}

/// Draw help text
fn draw_help(row: usize, fb_console: &mut Option<FramebufferConsole>, cols: usize) {
    menu_common::draw_help(row, HELP_TEXT, fb_console, cols);
}

/// Draw a status message
fn draw_status_message(
    row: usize,
    message: &str,
    is_success: bool,
    fb_console: &mut Option<FramebufferConsole>,
) {
    menu_common::draw_status_message(row, message, is_success, fb_console);
}

/// Clear remaining characters on the current line of a framebuffer console
fn clear_line_remainder(console: &mut FramebufferConsole) {
    menu_common::clear_line_remainder(console);
}
