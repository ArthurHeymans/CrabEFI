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
use crate::drivers::serial as serial_driver;
use crate::framebuffer_console::{
    Color, DEFAULT_BG, DEFAULT_FG, FramebufferConsole, HIGHLIGHT_BG, HIGHLIGHT_FG,
};
use crate::menu_common::{self, KeyPress, SerialWriter};
use crate::time::delay_ms;
#[cfg(feature = "ui")]
use crate::ui::{self, NavItem};
use alloc::string::String;
use core::fmt::Write;

use crabefi_ui::cfr::SettingsModel;
use crabefi_ui::settings::{
    MenuItem, Session, build_menu_items, can_edit_item, decrement_option, find_first_selectable,
    get_option, has_changes, increment_option, is_item_visible, is_selectable, push_truncated,
    save_all_changes, stepped_number,
};
use heapless::String as StackString;

/// The settings model one menu session reads.
type Model<'a> = dyn SettingsModel + 'a;

/// Menu title
const MENU_TITLE: &str = "Firmware Settings";

/// Help text
const HELP_TEXT: &str =
    "Up/Down: Navigate | Enter/Space: Edit | +/-: Inc/Dec | ?: Help | Esc: Exit";

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
    if let Some(fb) = crate::handoff::framebuffer().filter(ui::supports_framebuffer) {
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

    let session = Session::new(cfr_info);
    let cfr_info: &Model<'_> = &session;
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

fn find_prev_selectable(cfr: &Model<'_>, items: &[MenuItem], current: usize) -> usize {
    for i in (0..current).rev() {
        if is_selectable(&items[i]) && is_item_visible(cfr, items, &items[i]) {
            return i;
        }
    }
    current
}

fn find_next_selectable(cfr: &Model<'_>, items: &[MenuItem], current: usize) -> usize {
    for (i, item) in items.iter().enumerate().skip(current + 1) {
        if is_selectable(item) && is_item_visible(cfr, items, item) {
            return i;
        }
    }
    current
}

fn is_selectable_item(item: Option<&MenuItem>) -> bool {
    item.is_some_and(is_selectable)
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
#[path = "cfr_menu_graphical.rs"]
mod graphical;
#[cfg(feature = "ui")]
use graphical::show_cfr_menu_graphical;
#[cfg(feature = "ui")]
pub use graphical::show_graphical_firmware_settings;

// ============================================================================
// Drawing
// ============================================================================

/// Count menu items that are currently visible (dependency-aware).
fn visible_count(cfr: &Model<'_>, items: &[MenuItem]) -> usize {
    items
        .iter()
        .filter(|item| is_item_visible(cfr, items, item))
        .count()
}

/// Return the visible-list position of an item index without allocating.
fn visible_position_of(cfr: &Model<'_>, items: &[MenuItem], target: usize) -> Option<usize> {
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
fn visible_index_at(cfr: &Model<'_>, items: &[MenuItem], target_pos: usize) -> Option<usize> {
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
    cfr: &Model<'_>,
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
    cfr: &Model<'_>,
    item: &MenuItem,
    is_selected: bool,
    row: usize,
    fb_console: &mut Option<FramebufferConsole>,
    cols: usize,
) {
    match item {
        MenuItem::FormHeader { name, .. } => {
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
