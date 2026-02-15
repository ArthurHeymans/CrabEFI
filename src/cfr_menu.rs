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

use crate::coreboot::{
    self,
    cfr::{self, CfrInfo, CfrOption, CfrOptionType, CfrValue},
};
use crate::drivers::serial as serial_driver;
use crate::framebuffer_console::{
    Color, DEFAULT_BG, DEFAULT_FG, FramebufferConsole, HIGHLIGHT_BG, HIGHLIGHT_FG,
};
use crate::menu_common::{self, KeyPress, SerialWriter};
use crate::time::delay_ms;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

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
        )
    })
}

/// Show the CFR firmware settings menu
///
/// Displays the menu and handles user interaction.
/// Returns when the user exits the menu.
pub fn show_cfr_menu() {
    let cfr_info = match coreboot::get_cfr() {
        Some(cfr) => cfr,
        None => {
            show_no_cfr_message();
            return;
        }
    };

    let fb_info = coreboot::get_framebuffer();
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
        // Ensure scroll keeps selected item visible
        let vis = visible_indices(cfr_info, &items);
        let sel_vis_pos = vis.iter().position(|&i| i == selected).unwrap_or(0);
        let screen_rows = get_visible_rows(&fb_console);
        if sel_vis_pos < scroll_offset {
            scroll_offset = sel_vis_pos;
        } else if sel_vis_pos >= scroll_offset + screen_rows {
            scroll_offset = sel_vis_pos - screen_rows + 1;
        }
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
                        // Check visibility/editability before taking a mutable borrow
                        let can_edit = if let Some(
                            item @ MenuItem::Option {
                                form_idx,
                                option_idx,
                                ..
                            },
                        ) = items.get(selected)
                        {
                            is_item_visible(cfr_info, &items, item)
                                && get_option(cfr_info, *form_idx, *option_idx)
                                    .is_some_and(|o| o.is_editable())
                        } else {
                            false
                        };
                        if can_edit {
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
                            }
                        } else if matches!(items.get(selected), Some(MenuItem::Option { .. })) {
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
    matches!(item, MenuItem::Option { .. })
}

/// Check if the item at `index` is an editable, visible option (immutable borrow).
fn can_edit_item(cfr: &CfrInfo, items: &[MenuItem], index: usize) -> bool {
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
        if let MenuItem::Option {
            form_idx,
            option_idx,
            current_value,
            original_value,
        } = item
            && current_value != original_value
            && let Some(option) = get_option(cfr, *form_idx, *option_idx)
        {
            match cfr::write_option_value(option, current_value) {
                Ok(()) => saved += 1,
                Err(e) => {
                    log::warn!("Failed to save '{}': {}", option.opt_name, e);
                    failed += 1;
                }
            }
        }
    }
    (saved, failed)
}

/// Show confirmation dialog for saving on exit
fn confirm_save(fb_console: &mut Option<FramebufferConsole>) -> bool {
    serial_driver::write_str("\x1b[2J\x1b[H");
    serial_driver::write_str("\r\n\r\n");
    serial_driver::write_str("\x1b[1;33m");
    serial_driver::write_str("  Save changes? (takes effect after reset)\r\n");
    serial_driver::write_str("\x1b[0m\r\n");
    serial_driver::write_str("  Press Y to save, N to discard\r\n");

    if let Some(console) = fb_console {
        console.clear();
        let rows = console.rows();
        let confirm_row = rows / 2;
        console.set_fg_color(Color::new(255, 255, 0));
        console.write_centered(confirm_row, "Save changes? (takes effect after reset)");
        console.reset_colors();
        console.write_centered(confirm_row + 2, "Press Y to save, N to discard");
    }

    loop {
        if let Some(key) = menu_common::read_key() {
            match key {
                KeyPress::Char('y') | KeyPress::Char('Y') => return true,
                KeyPress::Char('n') | KeyPress::Char('N') | KeyPress::Escape => return false,
                _ => {}
            }
        }
        delay_ms(10);
    }
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

/// Show message that CFR is not available
fn show_no_cfr_message() {
    let fb_info = coreboot::get_framebuffer();
    let mut fb_console = fb_info.as_ref().map(FramebufferConsole::new);

    serial_driver::write_str("\r\n");
    serial_driver::write_str("\x1b[1;33m");
    serial_driver::write_str("  Firmware settings not available\r\n");
    serial_driver::write_str("\x1b[0m");
    serial_driver::write_str("  This firmware does not expose CFR configuration options.\r\n");
    serial_driver::write_str("\r\n  Press any key to continue...\r\n");

    if let Some(console) = &mut fb_console {
        console.clear();
        let rows = console.rows();
        console.set_fg_color(Color::new(255, 255, 0));
        console.write_centered(rows / 2 - 1, "Firmware settings not available");
        console.reset_colors();
        console.write_centered(
            rows / 2 + 1,
            "This firmware does not expose CFR configuration options.",
        );
        console.write_centered(rows / 2 + 3, "Press any key to continue...");
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
// Drawing
// ============================================================================

/// Collect the indices of items that are currently visible (dependency-aware).
fn visible_indices(cfr: &CfrInfo, items: &[MenuItem]) -> Vec<usize> {
    items
        .iter()
        .enumerate()
        .filter(|(_, item)| is_item_visible(cfr, items, item))
        .map(|(i, _)| i)
        .collect()
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

    // Build list of visible item indices (dependency-aware)
    let vis = visible_indices(cfr, items);

    // Calculate visible area
    let start_row = 4;
    let visible_rows = rows.saturating_sub(8);

    // Draw items — only the visible ones, respecting scroll_offset
    for (screen_idx, &item_idx) in vis
        .iter()
        .enumerate()
        .skip(scroll_offset)
        .take(visible_rows)
    {
        let row = start_row + (screen_idx - scroll_offset);
        let is_selected = item_idx == selected;
        draw_item(cfr, &items[item_idx], is_selected, row, fb_console, cols);
    }

    // Draw scroll indicators
    if scroll_offset > 0 {
        draw_scroll_indicator(start_row - 1, "^", fb_console);
    }
    if scroll_offset + visible_rows < vis.len() {
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
    let mut value_str = String::new();
    match (&option.option_type, value) {
        (CfrOptionType::Bool { .. }, CfrValue::Bool(b)) => {
            value_str.push_str(if *b { "[Enabled]" } else { "[Disabled]" });
        }
        (CfrOptionType::Enum { choices, .. }, CfrValue::Number(n)) => {
            if let Some(choice) = choices.iter().find(|c| c.value == *n) {
                value_str.push('[');
                value_str.push_str(&choice.ui_name);
                value_str.push(']');
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
            value_str.push('[');
            let max_len = 20;
            if s.len() > max_len {
                value_str.push_str(&s[..max_len]);
                value_str.push_str("...");
            } else {
                value_str.push_str(s);
            }
            value_str.push(']');
        }
        _ => {
            value_str.push_str("[-]");
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
    let ansi_row = row + 1;
    let _ = write!(SerialWriter, "\x1b[{};1H", ansi_row);
    serial_driver::write_str("\x1b[36m");
    let help_pad = (cols.saturating_sub(HELP_TEXT.len())) / 2;
    for _ in 0..help_pad {
        serial_driver::write_str(" ");
    }
    serial_driver::write_str(HELP_TEXT);
    serial_driver::write_str("\x1b[0m");

    if let Some(console) = fb_console {
        console.set_fg_color(Color::new(0, 192, 192));
        console.write_centered(row as u32, HELP_TEXT);
        console.reset_colors();
    }
}

/// Draw a status message
fn draw_status_message(
    row: usize,
    message: &str,
    is_success: bool,
    fb_console: &mut Option<FramebufferConsole>,
) {
    let color = if is_success {
        Color::new(0, 255, 0)
    } else {
        Color::new(255, 0, 0)
    };

    let ansi_row = row + 1;
    let _ = write!(SerialWriter, "\x1b[{};1H", ansi_row);
    if is_success {
        serial_driver::write_str("\x1b[32m");
    } else {
        serial_driver::write_str("\x1b[31m");
    }
    serial_driver::write_str("  ");
    serial_driver::write_str(message);
    serial_driver::write_str("\x1b[0m");

    if let Some(console) = fb_console {
        console.set_fg_color(color);
        console.write_centered(row as u32, message);
        console.reset_colors();
    }
}

/// Clear remaining characters on the current line of a framebuffer console
fn clear_line_remainder(console: &mut FramebufferConsole) {
    let (col, _) = console.position();
    for _ in col..console.cols() {
        let _ = console.write_str(" ");
    }
}
