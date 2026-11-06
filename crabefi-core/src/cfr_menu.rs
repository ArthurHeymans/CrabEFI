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

#[cfg(feature = "ui")]
use crate::FramebufferConfig as FramebufferInfo;
use crate::cfr::{self, CfrInfo, CfrOption, CfrOptionType, CfrValue};
use crate::drivers::serial as serial_driver;
use crate::framebuffer_console::{
    Color, DEFAULT_BG, DEFAULT_FG, FramebufferConsole, HIGHLIGHT_BG, HIGHLIGHT_FG,
};
use crate::menu_common::{self, KeyPress, SerialWriter};
use crate::time::delay_ms;
#[cfg(feature = "ui")]
use crate::ui::{self, NavItem, dialog, render, theme};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use heapless::String as StackString;
#[cfg(feature = "ui")]
use render::FontSize;

/// A screen rectangle: x, y, width, height.
#[cfg(feature = "ui")]
type Rect = (i32, i32, u32, u32);

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
    if let Some(fb) = crate::handoff::framebuffer() {
        // Legacy providers cannot return a destination through their bool hook.
        // Honor navigation locally instead of silently dropping it.
        let mut nav = show_cfr_menu_graphical(cfr_info, &fb);
        loop {
            nav = match nav {
                #[cfg(feature = "secure-boot")]
                ui::ScreenNav::Nav(NavItem::Security) => ui::secure_boot::show(&fb),
                ui::ScreenNav::Nav(NavItem::Firmware) => show_cfr_menu_graphical(cfr_info, &fb),
                _ => return,
            };
        }
    }

    let fb_info = crate::handoff::framebuffer();
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
                            let (saved, failed) = save_all_changes(cfr_info, &mut items);
                            show_save_result(saved, failed, &mut fb_console);
                            if failed > 0 {
                                break; // Keep failed drafts available for retry or discard.
                            }
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
    let current_level = crate::logger::configured_level();
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
            if min > max {
                return false;
            }
            *n = stepped_number(*n, *min, *max, *step, true).unwrap_or(*min);
            true
        }
        _ => false,
    }
}

/// Move to the next representable value on the minimum-relative step grid.
/// Never clamp to an unaligned maximum or overflow at either u32 boundary.
fn stepped_number(current: u32, min: u32, max: u32, step: u32, forward: bool) -> Option<u32> {
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

/// Increment a numeric/enum option in-place
fn increment_option(cfr: &CfrInfo, items: &mut [MenuItem], index: usize) -> bool {
    // Check editability with live dependencies before taking a mutable borrow
    if !can_edit_item(cfr, items, index) {
        return false;
    }

    if let Some(MenuItem::CrabLogLevel { current_level, .. }) = items.get_mut(index) {
        let current_idx = crate::logger::level_index(*current_level);
        let next_idx = (current_idx + 1) % crate::logger::LEVEL_CHOICES.len();
        *current_level = crate::logger::LEVEL_CHOICES[next_idx];
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

/// Decrement a numeric/enum option in-place
fn decrement_option(cfr: &CfrInfo, items: &mut [MenuItem], index: usize) -> bool {
    // Check editability with live dependencies before taking a mutable borrow
    if !can_edit_item(cfr, items, index) {
        return false;
    }

    if let Some(MenuItem::CrabLogLevel { current_level, .. }) = items.get_mut(index) {
        let current_idx = crate::logger::level_index(*current_level);
        let prev_idx = if current_idx == 0 {
            crate::logger::LEVEL_CHOICES.len().saturating_sub(1)
        } else {
            current_idx - 1
        };
        *current_level = crate::logger::LEVEL_CHOICES[prev_idx];
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

/// Save modified option values to persistent storage.
///
/// Only writes options that were actually changed by the user, reducing
/// unnecessary SPI flash wear. Returns `(saved, failed)` counts.
fn save_all_changes(cfr: &CfrInfo, items: &mut [MenuItem]) -> (usize, usize) {
    let mut saved = 0usize;
    let mut failed = 0usize;
    for item in items {
        match item {
            MenuItem::CrabLogLevel {
                current_level,
                original_level,
            } if current_level != original_level => {
                match crate::logger::set_configured_level(*current_level) {
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
                    match cfr::write_option_value(option, current_value) {
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
const GFX_TITLE_H: u32 = 92;

#[cfg(feature = "ui")]
struct GraphicalState {
    selected: usize,
    hovered: Option<usize>,
    scroll_offset: usize,
    status_message: Option<(&'static str, bool)>,
    save_result: Option<(usize, usize)>,
}

#[cfg(feature = "ui")]
impl GraphicalState {
    fn new(selected: usize) -> Self {
        Self {
            selected,
            hovered: None,
            scroll_offset: 0,
            status_message: None,
            save_result: None,
        }
    }
}

/// Graphical platform-hook entry point, preserving the requested destination.
#[cfg(feature = "ui")]
pub fn show_graphical_firmware_settings() -> ui::ScreenNav {
    let Some(fb) = crate::handoff::framebuffer() else {
        return ui::ScreenNav::Back;
    };
    let empty = CfrInfo::new();
    show_cfr_menu_graphical(cfr::get_cfr().unwrap_or(&empty), &fb)
}

/// Show the CFR settings menu using the graphical CrabEFI UI.
#[cfg(feature = "ui")]
fn show_cfr_menu_graphical(cfr_info: &CfrInfo, fb: &FramebufferInfo) -> ui::ScreenNav {
    let mut items = build_menu_items(cfr_info);

    if items.is_empty() {
        show_no_options_graphical(fb);
        return ui::ScreenNav::Back;
    }

    let mut cursor = crate::cursor::CursorRenderer::new();
    let mut state = GraphicalState::new(find_first_selectable(cfr_info, &items, 0));
    let mut sidebar_hover = None;

    draw_graphical_menu(cfr_info, &items, &state, fb);

    loop {
        ui::poll_and_render_cursor(fb, &mut cursor);
        ui::update_sidebar_hover(fb, &mut cursor, &mut sidebar_hover, NavItem::Firmware);

        let hovered = graphical_item_hit(cfr_info, &items, &state, fb);
        if hovered != state.hovered {
            let previous = core::mem::replace(&mut state.hovered, hovered);
            cursor.while_hidden(fb, || {
                let (x, y, w, _) = graphical_list_area(fb);
                for i in previous.into_iter().chain(hovered) {
                    if let Some(pos) = visible_position_of(cfr_info, &items, i)
                        && pos >= state.scroll_offset
                        && pos < state.scroll_offset + graphical_visible_slots(fb)
                    {
                        draw_graphical_item(
                            cfr_info,
                            &items[i],
                            i == state.selected,
                            hovered == Some(i),
                            fb,
                            x,
                            y + ((pos - state.scroll_offset) as u32 * GFX_ITEM_STRIDE) as i32,
                            w,
                        );
                    }
                }
            });
        }

        if let Some(key) = menu_common::read_key() {
            state.status_message = None;
            state.save_result = None;
            match key {
                KeyPress::Up | KeyPress::Char('k') => {
                    state.selected = find_prev_selectable(cfr_info, &items, state.selected);
                }
                KeyPress::Down | KeyPress::Char('j') => {
                    state.selected = find_next_selectable(cfr_info, &items, state.selected);
                }
                key @ (KeyPress::Home | KeyPress::End | KeyPress::PageUp | KeyPress::PageDown) => {
                    state.selected = graphical_page_selection(
                        cfr_info,
                        &items,
                        state.selected,
                        key,
                        graphical_visible_slots(fb),
                    );
                }
                KeyPress::Enter | KeyPress::Char(' ') => {
                    cursor.hide(fb);
                    edit_graphical_item(cfr_info, &mut items, &mut state, fb);
                }
                KeyPress::Right | KeyPress::Char('+') | KeyPress::Char('=') => {
                    if !increment_option(cfr_info, &mut items, state.selected) {
                        state.status_message = Some(("Option cannot be increased", false));
                    }
                }
                KeyPress::Left | KeyPress::Char('-') => {
                    if !decrement_option(cfr_info, &mut items, state.selected) {
                        state.status_message = Some(("Option cannot be decreased", false));
                    }
                }
                KeyPress::Char('w') | KeyPress::Char('W') => {
                    save_graphical_changes(cfr_info, &mut items, &mut state);
                }
                #[cfg(feature = "secure-boot")]
                KeyPress::Char('s') | KeyPress::Char('S') => {
                    cursor.hide(fb);
                    if leave_graphical(cfr_info, &mut items, &mut state, fb) {
                        return ui::ScreenNav::Nav(NavItem::Security);
                    }
                }
                KeyPress::Char('f') | KeyPress::Char('F') => {
                    state.status_message = Some(("Already in firmware settings", true));
                }
                KeyPress::Char('r') | KeyPress::Char('R') => {
                    cursor.hide(fb);
                    if leave_graphical(cfr_info, &mut items, &mut state, fb) {
                        ui::confirm_reset(fb, NavItem::Firmware);
                    }
                }
                KeyPress::Escape
                | KeyPress::Char('b')
                | KeyPress::Char('B')
                | KeyPress::Char('q')
                | KeyPress::Char('Q') => {
                    cursor.hide(fb);
                    if leave_graphical(cfr_info, &mut items, &mut state, fb) {
                        return ui::ScreenNav::Back;
                    }
                }
                KeyPress::Char('?') => {
                    cursor.hide(fb);
                    help_graphical_item(cfr_info, &mut items, &mut state, fb);
                }
                KeyPress::Char('d') | KeyPress::Char('D') => {
                    restore_graphical_default(cfr_info, &mut items, &mut state);
                }
                KeyPress::MouseClick { x, y } => {
                    cursor.hide(fb);
                    if let Some(nav) = ui::sidebar_hit()
                        && nav != NavItem::Firmware
                    {
                        if leave_graphical(cfr_info, &mut items, &mut state, fb) {
                            return ui::ScreenNav::Nav(nav);
                        }
                    } else if let Some(action) = toolbar_rects(fb)
                        .iter()
                        .position(|r| dialog::contains(*r, x as i32, y as i32))
                    {
                        match action {
                            0 => edit_graphical_item(cfr_info, &mut items, &mut state, fb),
                            1 => help_graphical_item(cfr_info, &mut items, &mut state, fb),
                            2 => save_graphical_changes(cfr_info, &mut items, &mut state),
                            _ => {
                                if leave_graphical(cfr_info, &mut items, &mut state, fb) {
                                    return ui::ScreenNav::Back;
                                }
                            }
                        }
                    } else if let Some(item_idx) = graphical_item_hit(cfr_info, &items, &state, fb)
                        && is_selectable(&items[item_idx])
                    {
                        if state.selected == item_idx {
                            edit_graphical_item(cfr_info, &mut items, &mut state, fb);
                        } else {
                            state.selected = item_idx;
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
            cursor.while_hidden(fb, || draw_graphical_menu(cfr_info, &items, &state, fb));
            sidebar_hover = None;
        }

        delay_ms(8);
    }
}

#[cfg(feature = "ui")]
fn graphical_canvas(fb: &FramebufferInfo) -> Rect {
    let x = theme::SIDEBAR_W as i32 + theme::PAD as i32;
    let y = (theme::HEADER_H + theme::PAD) as i32;
    let w = fb.width - theme::SIDEBAR_W - theme::PAD * 2;
    let h = fb.height - theme::HEADER_H - theme::FOOTER_H - theme::PAD * 2;
    (x, y, w, h)
}

#[cfg(feature = "ui")]
fn graphical_list_area(fb: &FramebufferInfo) -> Rect {
    let (cx, cy, cw, ch) = graphical_canvas(fb);
    let y = cy + GFX_TITLE_H as i32;
    (cx, y, cw, ch.saturating_sub(GFX_TITLE_H + 92))
}

#[cfg(feature = "ui")]
fn graphical_visible_slots(fb: &FramebufferInfo) -> usize {
    let (_, _, _, h) = graphical_list_area(fb);
    (h / GFX_ITEM_STRIDE).max(1) as usize
}

#[cfg(feature = "ui")]
fn graphical_page_selection(
    cfr: &CfrInfo,
    items: &[MenuItem],
    current: usize,
    key: KeyPress,
    page: usize,
) -> usize {
    match key {
        KeyPress::Home => find_first_selectable(cfr, items, 0),
        KeyPress::End => items
            .iter()
            .enumerate()
            .rev()
            .find(|(_, item)| is_selectable(item) && is_item_visible(cfr, items, item))
            .map_or(current, |(i, _)| i),
        KeyPress::PageUp | KeyPress::PageDown => {
            let mut selected = current;
            for _ in 0..page.max(1) {
                selected = if matches!(key, KeyPress::PageUp) {
                    find_prev_selectable(cfr, items, selected)
                } else {
                    find_next_selectable(cfr, items, selected)
                };
            }
            selected
        }
        _ => current,
    }
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

    ui::draw_footer(
        fb,
        "Pg/Home/End Move   Enter Edit   ? Help   D Default   W Save   Esc Back",
    );

    let (cx, cy, cw, _) = graphical_canvas(fb);
    draw_graphical_title(fb, cx, cy, cw, has_changes(items));
    render::draw_text(
        fb,
        cx,
        cy + 62,
        if cfr.total_options() == 0 {
            "No platform options supplied. CrabEFI settings only."
        } else {
            "Select, then Edit. Dependent options update as you edit."
        },
        FontSize::Small,
        theme::TEXT_DIM,
        None,
    );

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
    for (i, (rect, label)) in toolbar_rects(fb)
        .into_iter()
        .zip(["Edit", "Help", "Save (W)", "Back"])
        .enumerate()
    {
        dialog::button(fb, rect, label, i == 2 && has_changes(items));
    }

    let result_message = state.save_result.map(|(saved, failed)| {
        if failed == 0 {
            alloc::format!("Saved {saved}. Firmware changes apply after restart.")
        } else {
            alloc::format!("Saved {saved}; {failed} failed. Starred edits kept; retry or discard.")
        }
    });
    let feedback = result_message
        .as_deref()
        .map(|s| (s, state.save_result.is_some_and(|(_, failed)| failed == 0)))
        .or(state.status_message);
    if let Some((msg, ok)) = feedback {
        let color = if ok { theme::GREEN } else { theme::ERROR };
        dialog::wrapped(
            fb,
            (cx, (fb.height - theme::FOOTER_H - 88) as i32, cw, 40),
            msg,
            color,
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
        "Firmware Settings",
        FontSize::Display,
        theme::TEXT,
        None,
    );
    render::draw_text_right(
        fb,
        cx,
        title_y + 10,
        cw,
        if modified { "UNSAVED" } else { "SAVED" },
        FontSize::Small,
        if modified {
            theme::ORANGE
        } else {
            theme::TEXT_DIM
        },
        None,
    );
}

#[allow(clippy::too_many_arguments)]
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
            original_value,
        } => {
            if let Some(option) = get_option(cfr, *form_idx, *option_idx) {
                draw_graphical_option(
                    fb,
                    option,
                    current_value,
                    current_value != original_value,
                    selected,
                    hovered,
                    x,
                    y,
                    w,
                );
            }
        }
        MenuItem::CrabLogLevel {
            current_level,
            original_level,
        } => {
            draw_graphical_log_level(
                fb,
                *current_level,
                current_level != original_level,
                selected,
                hovered,
                x,
                y,
                w,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "ui")]
fn draw_graphical_log_level(
    fb: &FramebufferInfo,
    level: log::LevelFilter,
    modified: bool,
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

    let label = crate::logger::level_name(level);
    let value_w = value_width(label).min(w / 2);
    let value_x = x + w as i32 - value_w as i32 - 14;
    let name_max_w = (value_x - x - 34).max(32) as u32;

    render::draw_text(
        fb,
        x + 18,
        y + 8,
        &truncate_for_width(
            if modified {
                "* CrabEFI log level"
            } else {
                "CrabEFI log level"
            },
            name_max_w,
            FontSize::Normal,
        ),
        FontSize::Normal,
        theme::TEXT,
        Some(bg),
    );
    render::draw_text(
        fb,
        x + 18,
        y + 31,
        "Serial verbosity; applies on Save",
        FontSize::Small,
        theme::OUTLINE,
        Some(bg),
    );
    draw_value_pill(fb, value_x, y + 12, value_w, label, true);
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "ui")]
fn draw_graphical_option(
    fb: &FramebufferInfo,
    option: &CfrOption,
    value: &CfrValue,
    modified: bool,
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
        &truncate_for_width(
            &alloc::format!("{}{}", if modified { "* " } else { "" }, option.ui_name),
            name_max_w,
            FontSize::Normal,
        ),
        FontSize::Normal,
        name_color,
        Some(bg),
    );

    let description = if option.flags & cfr::CFR_OPTFLAG_READONLY != 0 {
        "Read-only: supplied by firmware"
    } else if !editable {
        "Unavailable: fixed by firmware"
    } else if option.ui_helptext.is_empty() {
        "Select, then Edit to change the draft"
    } else {
        &option.ui_helptext
    };
    render::draw_text(
        fb,
        x + 18,
        y + 31,
        &truncate_for_width(description, w.saturating_sub(40), FontSize::Small),
        FontSize::Small,
        theme::TEXT_DIM,
        Some(bg),
    );

    match (&option.option_type, value) {
        (CfrOptionType::Bool { .. }, CfrValue::Bool(on)) => {
            draw_value_pill(
                fb,
                value_x,
                y + 4,
                value_w,
                if *on { "Enabled" } else { "Disabled" },
                editable,
            );
        }
        _ => draw_value_pill(fb, value_x, y + 4, value_w, &value_label, editable),
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
    let (mx, my) = crate::drivers::mouse_cursor::position();
    let (x, y, w, _) = graphical_list_area(fb);
    if mx < x || mx >= x + w as i32 || my < y || (my - y) as u32 % GFX_ITEM_STRIDE >= GFX_ITEM_H {
        return None;
    }
    let slot = ((my - y) as u32 / GFX_ITEM_STRIDE) as usize;
    if slot >= graphical_visible_slots(fb) {
        return None;
    }
    visible_index_at(cfr, items, state.scroll_offset + slot).filter(|i| is_selectable(&items[*i]))
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
fn truncate_for_width(text: &str, max_width: u32, size: FontSize) -> StackString<256> {
    render::ellipsize(text, max_width, size)
}

#[cfg(feature = "ui")]
fn show_help_graphical(fb: &FramebufferInfo, option: &CfrOption, details: &str) -> bool {
    let mut cursor = crate::cursor::CursorRenderer::new();
    let (x, y, w, h) = graphical_canvas(fb);
    let text = alloc::format!(
        "{} {}",
        details,
        if option.ui_helptext.is_empty() {
            "No additional help supplied."
        } else {
            &option.ui_helptext
        }
    );
    let lines = dialog::wrap_lines(
        &text,
        (w.saturating_sub(32) / render::font_width(FontSize::Small)) as usize,
    );
    let slots = (h.saturating_sub(120) / 20).max(1) as usize;
    let mut offset = 0;
    loop {
        cursor.hide(fb);
        draw_help_graphical(fb, option, &lines, offset, slots);
        let back = (
            x,
            y + 76 + help_card_height(lines.len(), slots, h) as i32,
            (w - 8) / 2,
            38,
        );
        let defaults = (x + back.2 as i32 + 8, back.1, back.2, 38);
        dialog::button(fb, back, "Back", true);
        dialog::button(
            fb,
            defaults,
            if option.is_editable() {
                "Use default (D)"
            } else {
                "Read-only"
            },
            false,
        );
        loop {
            ui::poll_and_render_cursor(fb, &mut cursor);
            if let Some(key) = menu_common::read_key() {
                match key {
                    KeyPress::Escape | KeyPress::Enter => {
                        cursor.hide(fb);
                        return false;
                    }
                    KeyPress::Char('d') | KeyPress::Char('D') if option.is_editable() => {
                        cursor.hide(fb);
                        return true;
                    }
                    key @ (KeyPress::Home
                    | KeyPress::End
                    | KeyPress::PageUp
                    | KeyPress::PageDown) => {
                        offset = ui::page_selection(
                            key,
                            offset,
                            lines.len().saturating_sub(slots) + 1,
                            slots,
                        )
                        .unwrap_or(offset);
                        break;
                    }
                    KeyPress::Down | KeyPress::MouseScroll(1..) => {
                        offset = (offset + 1).min(lines.len().saturating_sub(slots));
                        break;
                    }
                    KeyPress::Up | KeyPress::MouseScroll(..=-1) => {
                        offset = offset.saturating_sub(1);
                        break;
                    }
                    KeyPress::MouseClick { x, y } => {
                        if dialog::contains(back, x as i32, y as i32) {
                            cursor.hide(fb);
                            return false;
                        }
                        if option.is_editable() && dialog::contains(defaults, x as i32, y as i32) {
                            cursor.hide(fb);
                            return true;
                        }
                    }
                    _ => {}
                }
            }
            delay_ms(8);
        }
    }
}

#[cfg(feature = "ui")]
fn help_card_height(lines: usize, slots: usize, canvas_h: u32) -> u32 {
    (lines.min(slots).max(1) as u32 * 20 + 16).min(canvas_h.saturating_sub(120))
}

#[cfg(feature = "ui")]
fn draw_help_graphical(
    fb: &FramebufferInfo,
    option: &CfrOption,
    lines: &[String],
    offset: usize,
    slots: usize,
) {
    ui::clear(fb);
    ui::draw_header(fb);
    ui::draw_sidebar(fb, NavItem::Firmware, None);
    ui::draw_footer(
        fb,
        "Pg/Home/End Scroll   D Default draft   Enter / Esc Back",
    );

    let (cx, cy, cw, ch) = graphical_canvas(fb);
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

    let card_y = cy + 64;
    render::fill_rounded_rect(
        fb,
        cx,
        card_y,
        cw,
        help_card_height(lines.len(), slots, ch),
        theme::RADIUS,
        theme::CONTAINER,
    );
    for (i, line) in lines.iter().skip(offset).take(slots).enumerate() {
        render::draw_text(
            fb,
            cx + 16,
            card_y + 8 + i as i32 * 20,
            line,
            FontSize::Small,
            theme::TEXT_DIM,
            None,
        );
    }
    ui::draw_scrollbar(
        fb,
        cx + cw as i32 - 4,
        card_y,
        help_card_height(lines.len(), slots, ch),
        lines.len(),
        offset,
        slots,
    );
}

#[cfg(feature = "ui")]
fn toolbar_rects(fb: &FramebufferInfo) -> [Rect; 4] {
    let (x, _, w, _) = graphical_canvas(fb);
    let bw = (w - 24) / 4;
    core::array::from_fn(|i| {
        (
            x + i as i32 * (bw + 8) as i32,
            (fb.height - theme::FOOTER_H - 42) as i32,
            bw,
            34,
        )
    })
}

#[cfg(feature = "ui")]
fn save_graphical_changes(cfr: &CfrInfo, items: &mut [MenuItem], state: &mut GraphicalState) {
    if !has_changes(items) {
        state.status_message = Some(("No changes to save", true));
        return;
    }
    state.save_result = Some(save_all_changes(cfr, items));
    state.status_message = None;
}

/// Restore only unsaved drafts; successful writes in a partial save remain saved.
#[cfg(feature = "ui")]
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

/// Put consequences first and cap names so long lists cannot hide instructions.
#[cfg(feature = "ui")]
fn unsaved_summary(names: &[&str]) -> String {
    let mut message = alloc::format!(
        "Cancel keeps editing. Discard drops only unsaved changes. Save keeps changes; firmware options apply after restart. {} changed: ",
        names.len()
    );
    for (i, name) in names.iter().take(2).enumerate() {
        if i != 0 {
            message.push_str(", ");
        }
        message.push_str(&truncate_for_width(name, 256, FontSize::Small));
    }
    if names.len() > 2 {
        let _ = write!(message, "; +{} more", names.len() - 2);
    }
    message
}

#[cfg(feature = "ui")]
fn leave_graphical(
    cfr: &CfrInfo,
    items: &mut [MenuItem],
    state: &mut GraphicalState,
    fb: &FramebufferInfo,
) -> bool {
    if !has_changes(items) {
        return true;
    }
    let names: Vec<&str> = items
        .iter()
        .filter_map(|item| match item {
            MenuItem::CrabLogLevel {
                current_level,
                original_level,
            } if current_level != original_level => Some("CrabEFI log level"),
            MenuItem::Option {
                form_idx,
                option_idx,
                current_value,
                original_value,
            } if current_value != original_value => {
                get_option(cfr, *form_idx, *option_idx).map(|o| o.ui_name.as_str())
            }
            _ => None,
        })
        .collect();
    let message = unsaved_summary(&names);
    match dialog::choose(
        fb,
        NavItem::Firmware,
        "Unsaved changes",
        &message,
        &["Cancel", "Discard", "Save & leave"],
    ) {
        1 => {
            discard_graphical_changes(items);
            state.status_message = Some(("Unsaved changes discarded.", true));
            true
        }
        2 => {
            save_graphical_changes(cfr, items, state);
            !has_changes(items)
        }
        _ => false,
    }
}

#[cfg(feature = "ui")]
fn help_graphical_item(
    cfr: &CfrInfo,
    items: &mut [MenuItem],
    state: &mut GraphicalState,
    fb: &FramebufferInfo,
) {
    let restore = if let Some(MenuItem::Option {
        form_idx,
        option_idx,
        current_value,
        original_value,
    }) = items.get(state.selected)
        && let Some(option) = get_option(cfr, *form_idx, *option_idx)
    {
        let default = CfrValue::from_option_type(&option.option_type);
        let mut details = alloc::format!(
            "Draft: {}. Saved: {}. Default: {}.",
            format_value(option, current_value),
            format_value(option, original_value),
            format_value(option, &default)
        );
        if let CfrOptionType::Number { min, max, step, .. } = option.option_type {
            let _ = write!(details, " Range {min} to {max}; step {step}.");
        }
        show_help_graphical(fb, option, &details)
    } else {
        state.status_message = Some((
            "Log level controls serial verbosity; applies on Save. +/- changes it.",
            true,
        ));
        false
    };
    if restore {
        restore_graphical_default(cfr, items, state);
    }
}

#[cfg(feature = "ui")]
fn restore_graphical_default(cfr: &CfrInfo, items: &mut [MenuItem], state: &mut GraphicalState) {
    if !can_edit_item(cfr, items, state.selected) {
        state.status_message = Some((
            "Read-only or unavailable; defaults cannot be changed.",
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
    state.status_message = Some(("Default restored in draft. Choose Save to keep it.", true));
}

/// Numeric editors accept an explicit decimal or 0x-prefixed hexadecimal value.
#[cfg(feature = "ui")]
fn parse_graphical_number(text: &str, min: u32, max: u32, step: u32) -> Result<u32, &'static str> {
    let text = text.trim();
    let n = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        text.parse::<u32>()
    }
    .map_err(|_| "Enter a decimal number or 0x-prefixed hexadecimal.")?;
    if n < min || n > max {
        return Err("Value is outside the displayed range.");
    }
    if step > 1 && !(n - min).is_multiple_of(step) {
        return Err("Value must match the displayed step from the minimum.");
    }
    Ok(n)
}

#[cfg(feature = "ui")]
fn edit_graphical_item(
    cfr: &CfrInfo,
    items: &mut [MenuItem],
    state: &mut GraphicalState,
    fb: &FramebufferInfo,
) {
    if !can_edit_item(cfr, items, state.selected) {
        state.status_message = Some(("Read-only or unavailable; choose Help for details.", false));
        return;
    }
    let Some(MenuItem::Option {
        form_idx,
        option_idx,
        current_value,
        ..
    }) = items.get_mut(state.selected)
    else {
        increment_option(cfr, items, state.selected);
        return;
    };
    let Some(option) = get_option(cfr, *form_idx, *option_idx) else {
        return;
    };
    match (&option.option_type, current_value) {
        (CfrOptionType::Bool { .. }, CfrValue::Bool(value)) => *value = !*value,
        (CfrOptionType::Enum { choices, .. }, CfrValue::Number(value)) => {
            let current = choices.iter().position(|c| c.value == *value);
            let unknown = alloc::format!("Unlisted value {value} (keep unchanged)");
            let mut labels: Vec<&str> = choices.iter().map(|c| c.ui_name.as_str()).collect();
            let extra = usize::from(current.is_none());
            if extra > 0 {
                labels.insert(0, &unknown);
            }
            if let Some(i) = dialog::select(fb, &option.ui_name, &labels, current.unwrap_or(0))
                && let Some(choice) = i.checked_sub(extra).and_then(|i| choices.get(i))
            {
                *value = choice.value;
            }
        }
        (CfrOptionType::Number { min, max, step, .. }, CfrValue::Number(value)) => {
            let hint = alloc::format!(
                "Range {min} to {max}; step {step}. Decimal or 0x hex. Apply changes the draft only."
            );
            if let Some(text) = dialog::input(
                fb,
                &option.ui_name,
                &hint,
                &alloc::format!("{value}"),
                |s| parse_graphical_number(s, *min, *max, *step).map(|_| ()),
            ) && let Ok(n) = parse_graphical_number(&text, *min, *max, *step)
            {
                *value = n;
            }
        }
        (CfrOptionType::Varchar { .. }, CfrValue::Varchar(value)) => {
            if let Some(text) = dialog::input(
                fb,
                &option.ui_name,
                "Text, up to 255 bytes (ASCII input). Backspace to delete; Ctrl+U to clear. Apply changes the draft only.",
                value,
                |_| Ok(()),
            ) {
                *value = text;
            }
        }
        _ => state.status_message = Some(("No choices supplied for this option", false)),
    }
}

#[cfg(feature = "ui")]
fn show_no_options_graphical(fb: &FramebufferInfo) {
    let mut cursor = crate::cursor::CursorRenderer::new();
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
    value_str.push_str(crate::logger::level_name(level));
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

#[cfg(all(test, feature = "ui"))]
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

    #[test]
    fn changed_log_level_has_a_visible_dirty_marker_even_when_value_is_identical() {
        let mut clean_pixels = std::vec![0u32; 640 * 480];
        let mut dirty_pixels = clean_pixels.clone();
        let framebuffer = |pixels: &mut [u32]| FramebufferInfo {
            physical_address: pixels.as_mut_ptr() as u64,
            width: 640,
            height: 480,
            stride: 640,
            bits_per_pixel: 32,
            red_mask_pos: 16,
            red_mask_size: 8,
            green_mask_pos: 8,
            green_mask_size: 8,
            blue_mask_pos: 0,
            blue_mask_size: 8,
        };
        let clean = MenuItem::CrabLogLevel {
            current_level: log::LevelFilter::Info,
            original_level: log::LevelFilter::Info,
        };
        let dirty = MenuItem::CrabLogLevel {
            current_level: log::LevelFilter::Info,
            original_level: log::LevelFilter::Debug,
        };
        let cfr = CfrInfo::new();
        draw_graphical_item(
            &cfr,
            &clean,
            true,
            false,
            &framebuffer(&mut clean_pixels),
            184,
            160,
            440,
        );
        draw_graphical_item(
            &cfr,
            &dirty,
            true,
            false,
            &framebuffer(&mut dirty_pixels),
            184,
            160,
            440,
        );
        assert_ne!(
            clean_pixels, dirty_pixels,
            "dirty marker must be rendered, independently of the displayed value"
        );
    }

    #[test]
    fn long_unsaved_lists_cannot_hide_cancel_discard_or_save_instructions() {
        let long =
            "A very long firmware option name that must never push instructions out of the dialog";
        let names = std::vec![long; 100];
        let summary = unsaved_summary(&names);
        assert!(summary.starts_with(
            "Cancel keeps editing. Discard drops only unsaved changes. Save keeps changes;"
        ));
        assert!(summary.contains("100 changed:"));
        assert!(summary.contains("+98 more"));
        assert!(summary.chars().count() < 240);
        assert!(dialog::wrap_lines(&summary, 50).len() <= 6);
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
    fn long_help_text_is_capacity_aware_on_wide_displays() {
        let text = "Description ".repeat(30);
        let label = truncate_for_width(&text, 1800, FontSize::Small);
        assert!(label.starts_with("Description "));
        assert!(label.ends_with('~'));
        assert!(label.len() <= 256);
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
    fn discard_before_cancelled_restart_restores_unsaved_values_only() {
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
            items[0],
            MenuItem::Option {
                current_value: CfrValue::Bool(true),
                ..
            }
        ));
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

    #[test]
    fn page_navigation_skips_headers_and_hidden_dependencies() {
        let mut options: Vec<_> = (1..=40).map(option).collect();
        options[20].dependency_id = 1;
        let cfr = CfrInfo {
            version: 0,
            forms: alloc::vec![CfrForm {
                object_id: 100,
                dependency_id: 0,
                ui_name: String::from("Test"),
                flags: 0,
                options,
                dep_values: Vec::new(),
            }],
        };
        let mut items = alloc::vec![MenuItem::FormHeader {
            name: String::from("Test")
        }];
        items.extend((0..40).map(|i| MenuItem::Option {
            form_idx: 0,
            option_idx: i,
            current_value: CfrValue::Bool(false),
            original_value: CfrValue::Bool(false),
        }));
        assert_eq!(
            graphical_page_selection(&cfr, &items, 30, KeyPress::Home, 5),
            1
        );
        assert_eq!(
            graphical_page_selection(&cfr, &items, 1, KeyPress::End, 5),
            40
        );
        assert_eq!(
            graphical_page_selection(&cfr, &items, 1, KeyPress::PageDown, 5),
            6
        );
        assert_eq!(
            graphical_page_selection(&cfr, &items, 20, KeyPress::PageDown, 1),
            22
        );
        assert_eq!(
            graphical_page_selection(&cfr, &items, 1, KeyPress::PageUp, 5),
            1
        );
    }

    struct FailingStore {
        fail: AtomicBool,
        first_writes: AtomicUsize,
        second_writes: AtomicUsize,
    }
    impl OptionStore for FailingStore {
        fn keeps(&self, option: &CfrOption) -> bool {
            option.opt_name.starts_with("ui_regression_")
        }
        fn read(&self, _: &CfrOption) -> Option<CfrValue> {
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
        static STORE: FailingStore = FailingStore {
            fail: AtomicBool::new(true),
            first_writes: AtomicUsize::new(0),
            second_writes: AtomicUsize::new(0),
        };
        cfr::set_option_store(&STORE);
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
        assert!(matches!(
            items[0],
            MenuItem::Option {
                original_value: CfrValue::Bool(true),
                ..
            }
        ));
        assert!(matches!(
            items[1],
            MenuItem::Option {
                original_value: CfrValue::Bool(false),
                current_value: CfrValue::Bool(true),
                ..
            }
        ));
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
        assert!(matches!(
            items[1],
            MenuItem::Option {
                current_value: CfrValue::Bool(false),
                original_value: CfrValue::Bool(true),
                ..
            }
        ));
    }
}
