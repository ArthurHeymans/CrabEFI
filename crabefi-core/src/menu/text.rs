//! Serial and framebuffer boot menu: selection, countdown and rendering.

use super::cmdline::{EditResult, edit_cmdline};
use super::{BootCategory, BootEntry, BootMenu};
use crate::drivers::serial as serial_driver;
use crate::framebuffer_console::{
    Color, DEFAULT_BG, DEFAULT_FG, FramebufferConsole, HIGHLIGHT_BG, HIGHLIGHT_FG,
};
use crate::menu_common::{self, KeyPress, SerialWriter};
use crate::time::{Timeout, delay_ms};
use core::fmt::Write;
use heapless::String;

/// Menu title
const MENU_TITLE: &str = "CrabEFI Boot Menu";

/// Help text
#[cfg(feature = "secure-boot")]
const HELP_TEXT: &str = "Enter: Boot | F: Firmware | C: Cmdline | S: Secure Boot | R: Reset";
/// Help text without the Secure Boot entry.
#[cfg(not(feature = "secure-boot"))]
const HELP_TEXT: &str = "Enter: Boot | F: Firmware | C: Cmdline | R: Reset";

/// Update the mouse cursor on the framebuffer.
///
/// Call this in the menu event loop to render the cursor at its current position.
#[cfg(feature = "ui")]
fn update_cursor(
    cursor_renderer: &mut crate::cursor::CursorRenderer,
    fb_info: &Option<crate::FramebufferConfig>,
) {
    if let Some(fb) = fb_info
        && crate::drivers::mouse_cursor::is_initialized()
    {
        let (x, y) = crate::drivers::mouse_cursor::position();
        cursor_renderer.update(fb, x, y);
    }
}

/// Result of running an interactive boot menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MenuAction {
    /// User (or timeout) selected the entry at this index.
    Selected(usize),
    /// USB storage changed; re-discover entries and reopen the menu.
    Refresh,
    /// Menu exited without selecting an entry.
    #[cfg_attr(not(feature = "ui"), allow(dead_code))]
    Exit,
}

/// Show the boot menu and wait for user selection
///
/// # Arguments
///
/// * `menu` - The boot menu with discovered entries
///
/// # Returns
///
/// The index of the selected boot entry, or `None` if no selection was made.
/// Boot [`BootMenu::entry_for_boot`] for that index so a one-shot
/// command-line edit made in the menu applies to this boot attempt.
pub fn show_menu(menu: &mut BootMenu) -> Option<usize> {
    match show_menu_for_mode::<false>(menu) {
        MenuAction::Selected(index) => Some(index),
        MenuAction::Refresh | MenuAction::Exit => None,
    }
}

pub(crate) fn show_menu_for_mode<const NATIVE: bool>(menu: &mut BootMenu) -> MenuAction {
    let draw_menu = draw_menu::<NATIVE>;
    menu.clear_edited_cmdline();
    // An empty, indefinite menu still provides firmware/security settings.
    // The boot manager uses this for explicit setup requests without media.
    if menu.entry_count() == 0 {
        menu.set_timeout(0);
    }

    // Get framebuffer for console and cursor rendering.
    let fb_config = crate::handoff::framebuffer();
    #[cfg(feature = "ui")]
    let fb_info = fb_config;
    #[cfg(not(feature = "ui"))]
    let _ = (); // fb_info unused without ui

    // Create framebuffer console if available
    let mut fb_console = fb_config.as_ref().map(FramebufferConsole::new);

    // Clear screen
    menu_common::clear_screen(&mut fb_console);

    // Initial display
    draw_menu(menu, &mut fb_console);

    // Handle input with timeout
    let mut remaining_seconds = menu.timeout_seconds;
    let mut last_second_check = Timeout::from_ms(1000);

    // Zero disables autoboot; do not announce "Booting now..." in setup.
    if remaining_seconds > 0 {
        draw_countdown(remaining_seconds, &mut fb_console);
    }

    // Initialize cursor renderer for mouse support
    #[cfg(feature = "ui")]
    let mut cursor_renderer = crate::cursor::CursorRenderer::new();

    let storage_revision = crate::drivers::usb::storage_revision();
    loop {
        crate::exec::poll_background();
        if storage_revision != crate::drivers::usb::storage_revision() {
            return MenuAction::Refresh;
        }
        // Update mouse cursor on framebuffer
        #[cfg(feature = "ui")]
        update_cursor(&mut cursor_renderer, &fb_info);
        // Read input before the countdown can expire, so a key queued during
        // the last second still stops the automatic boot.
        let key = menu_common::read_key();
        // Any key stops the automatic boot, as in the graphical menu: only an
        // explicit choice boots after that. This also keeps a restricted boot
        // policy from timing out into an external entry the user merely moved
        // to.
        if key.is_some() && remaining_seconds > 0 {
            remaining_seconds = 0;
            menu.set_timeout(0);
            clear_countdown(&mut fb_console);
        }

        // Check for timeout (first tick fires after 1 real second)
        if remaining_seconds > 0 && last_second_check.is_expired() {
            remaining_seconds -= 1;
            last_second_check = Timeout::from_ms(1000);

            // Update countdown display
            draw_countdown(remaining_seconds, &mut fb_console);

            if remaining_seconds == 0 {
                // Timeout - boot selected entry
                return MenuAction::Selected(menu.selected);
            }
        }

        if let Some(key) = key {
            match key {
                KeyPress::Up | KeyPress::Char('k') => {
                    menu.select_previous();
                    draw_menu(menu, &mut fb_console);
                }
                KeyPress::Down | KeyPress::Char('j') => {
                    menu.select_next();
                    draw_menu(menu, &mut fb_console);
                }
                KeyPress::Enter if menu.entry_count() > 0 => {
                    // Show booting message before returning
                    if let Some(entry) = menu.entries.get(menu.selected) {
                        log::info!(
                            "Selected entry: name='{}', path='{}'",
                            entry.name,
                            entry.path
                        );
                        let mut msg: String<64> = String::new();
                        let _ = msg.push_str("Booting ");
                        let _ = msg.push_str(&entry.name);
                        let _ = msg.push_str("...");
                        draw_status(&msg, &mut fb_console);
                    } else {
                        log::error!("No entry at selected index {}", menu.selected);
                        draw_status("Error: No entry selected", &mut fb_console);
                    }
                    return MenuAction::Selected(menu.selected);
                }
                KeyPress::Escape => {
                    // Future: file browser
                    draw_status("File browser not yet implemented", &mut fb_console);
                }
                #[cfg(feature = "secure-boot")]
                KeyPress::Char('s') | KeyPress::Char('S') if !NATIVE => {
                    // Open Secure Boot settings menu
                    crate::secure_boot_menu::show_secure_boot_menu();
                    // Redraw boot menu after returning
                    menu_common::clear_screen(&mut fb_console);
                    draw_menu(menu, &mut fb_console);
                }
                KeyPress::Char('f') | KeyPress::Char('F') if !NATIVE => {
                    // Open platform-provided firmware settings menu.
                    if let Some(hooks) = crate::handoff::callbacks().hooks {
                        if !hooks.show_firmware_settings() {
                            draw_status("Firmware settings not available", &mut fb_console);
                            delay_ms(500);
                        }
                    } else {
                        draw_status("Firmware settings not available", &mut fb_console);
                        delay_ms(500);
                    }
                    // Redraw boot menu after returning
                    menu_common::clear_screen(&mut fb_console);
                    draw_menu(menu, &mut fb_console);
                }
                KeyPress::Char('r') | KeyPress::Char('R') => {
                    // Reset the system
                    draw_status("Resetting system...", &mut fb_console);
                    delay_ms(500);
                    crate::reset_system();
                }
                KeyPress::Char('c') | KeyPress::Char('C') => {
                    // Edit kernel command line (one-shot: recorded on the
                    // menu, never written into the entry itself)
                    let selected = menu.selected;
                    let editing = menu
                        .entries
                        .get(selected)
                        .filter(|entry| entry.has_cmdline())
                        .and_then(|entry| {
                            menu.effective_cmdline(selected)
                                .map(|initial| (entry.name.clone(), initial))
                        });
                    if let Some((name, initial)) = editing {
                        match edit_cmdline(&name, initial, &mut fb_console) {
                            (EditResult::Boot, edited) => {
                                menu.set_edited_cmdline(selected, edited);
                                // Boot immediately with the edited command line
                                let mut msg: String<64> = String::new();
                                let _ = msg.push_str("Booting ");
                                let _ = msg.push_str(&name);
                                let _ = msg.push_str("...");
                                menu_common::clear_screen(&mut fb_console);
                                draw_status(&msg, &mut fb_console);
                                return MenuAction::Selected(selected);
                            }
                            (EditResult::Confirmed, edited) => {
                                menu.set_edited_cmdline(selected, edited);
                                draw_status("Command line updated", &mut fb_console);
                            }
                            (EditResult::Cancelled, _) => {
                                draw_status("Edit cancelled", &mut fb_console);
                            }
                        }
                    } else {
                        draw_status("This entry has no editable command line", &mut fb_console);
                    }
                    // Redraw menu after editing (unless we're booting)
                    delay_ms(500);
                    menu_common::clear_screen(&mut fb_console);
                    draw_menu(menu, &mut fb_console);
                }
                KeyPress::Char(c) if c.is_ascii_digit() => {
                    // Direct selection by number
                    let num = (c as u8 - b'0') as usize;
                    if num > 0 && num <= menu.entry_count() {
                        menu.selected = num - 1;
                        draw_menu(menu, &mut fb_console);
                    }
                }
                // Handle mouse clicks - select entry under cursor
                #[cfg(feature = "ui")]
                KeyPress::MouseClick { y, .. } => {
                    // Map screen Y pixel to menu entry index
                    // Menu entries start at row ~5 (after header + category)
                    let row = y / crate::framebuffer_console::CHAR_HEIGHT;
                    if let Some(idx) = row_to_entry_index(
                        menu,
                        row,
                        menu_scroll_offset(menu, &fb_console),
                        menu_visible_rows(&fb_console),
                    ) {
                        menu.selected = idx;
                        draw_menu(menu, &mut fb_console);
                    }
                }
                #[cfg(feature = "ui")]
                KeyPress::MouseScroll(dz) => {
                    if dz > 0 {
                        menu.select_next();
                    } else {
                        menu.select_previous();
                    }
                    draw_menu(menu, &mut fb_console);
                }
                _ => {}
            }
        }

        // Small delay to avoid busy-waiting
        delay_ms(10);
    }
}

/// Map a screen row to a menu entry index.
///
/// Returns `Some(index)` if the row corresponds to a boot entry,
/// `None` if it's a header, separator, or out of range.
#[cfg(feature = "ui")]
fn row_to_entry_index(
    menu: &BootMenu,
    row: u32,
    scroll_offset: usize,
    visible_rows: usize,
) -> Option<usize> {
    // Menu layout: row 0-2 = header, row 3 = blank, row 4+ = visible menu rows.
    let start_row = 4usize;
    let target_row = row as usize;
    if target_row < start_row || target_row >= start_row + visible_rows {
        return None;
    }
    let mut logical_row = 0usize;
    let mut current_category: Option<BootCategory> = None;

    for (i, entry) in menu.entries.iter().enumerate() {
        if current_category != Some(entry.category) {
            if current_category.is_some() {
                logical_row += 1; // blank line
            }
            logical_row += 1; // category separator
            current_category = Some(entry.category);
        }

        if logical_row >= scroll_offset {
            let screen_row = start_row + logical_row - scroll_offset;
            if target_row == screen_row {
                return Some(i);
            }
        }
        logical_row += 1;
    }
    None
}

fn menu_visible_rows(fb_console: &Option<FramebufferConsole>) -> usize {
    let rows = fb_console.as_ref().map(|c| c.rows()).unwrap_or(25) as usize;
    rows.saturating_sub(10).max(1)
}

fn menu_item_count(menu: &BootMenu) -> usize {
    let mut count = 0usize;
    let mut current_category: Option<BootCategory> = None;
    for entry in &menu.entries {
        if current_category != Some(entry.category) {
            if current_category.is_some() {
                count += 1;
            }
            count += 1;
            current_category = Some(entry.category);
        }
        count += 1;
    }
    count
}

fn selected_menu_position(menu: &BootMenu) -> usize {
    let mut pos = 0usize;
    let mut current_category: Option<BootCategory> = None;
    for (i, entry) in menu.entries.iter().enumerate() {
        if current_category != Some(entry.category) {
            if current_category.is_some() {
                pos += 1;
            }
            pos += 1;
            current_category = Some(entry.category);
        }
        if i == menu.selected {
            return pos;
        }
        pos += 1;
    }
    0
}

fn menu_scroll_offset(menu: &BootMenu, fb_console: &Option<FramebufferConsole>) -> usize {
    let visible_rows = menu_visible_rows(fb_console);
    let selected_pos = selected_menu_position(menu);
    if selected_pos >= visible_rows {
        selected_pos - visible_rows + 1
    } else {
        0
    }
}

/// Draw the menu on both outputs
fn draw_menu<const NATIVE: bool>(menu: &BootMenu, fb_console: &mut Option<FramebufferConsole>) {
    let cols = fb_console.as_ref().map(|c| c.cols()).unwrap_or(80) as usize;
    let rows = fb_console.as_ref().map(|c| c.rows()).unwrap_or(25) as usize;
    let visible_rows = menu_visible_rows(fb_console);
    let scroll_offset = menu_scroll_offset(menu, fb_console);
    let total_rows = menu_item_count(menu);

    // Draw header
    draw_header(fb_console, cols);

    // Draw entries with category separators
    let start_row = 4;
    let mut logical_row = 0usize;
    let mut screen_row = start_row;
    let mut current_category: Option<BootCategory> = None;

    for (i, entry) in menu.entries.iter().enumerate() {
        // Check if we need a category separator
        if current_category != Some(entry.category) {
            // Add blank line before separator (except for first category)
            if current_category.is_some() {
                logical_row += 1;
            }
            if logical_row >= scroll_offset && logical_row < scroll_offset + visible_rows {
                draw_category_separator(entry.category, screen_row, fb_console, cols);
                screen_row += 1;
            }
            logical_row += 1;
            current_category = Some(entry.category);
        }

        let is_selected = i == menu.selected;
        if logical_row >= scroll_offset && logical_row < scroll_offset + visible_rows {
            draw_entry(i, entry, is_selected, screen_row, fb_console, cols);
            screen_row += 1;
        }
        logical_row += 1;
    }

    clear_scroll_indicator(start_row - 1, fb_console);
    clear_scroll_indicator(start_row + visible_rows, fb_console);
    if scroll_offset > 0 {
        draw_scroll_indicator(start_row - 1, "^", fb_console);
    }
    if scroll_offset + visible_rows < total_rows {
        draw_scroll_indicator(start_row + visible_rows, "v", fb_console);
    }

    if menu.entry_count() == 0 {
        let message = if NATIVE {
            "No bootable media"
        } else {
            "No bootable media - firmware settings are still available"
        };
        draw_status(message, fb_console);
    }

    // Draw help text
    let help_row = rows.saturating_sub(5);
    let help = if NATIVE {
        "Enter: Boot | C: Cmdline | R: Reset"
    } else {
        HELP_TEXT
    };
    menu_common::draw_help(help_row, help, fb_console, cols);
}

/// Draw a category separator line
fn draw_category_separator(
    category: BootCategory,
    row: usize,
    fb_console: &mut Option<FramebufferConsole>,
    cols: usize,
) {
    let label = category.display_name();

    // Build separator: "--- Category Name ---" style
    let dashes_total = cols.saturating_sub(label.len() + 2); // 2 for spaces around label
    let dashes_left = dashes_total / 2;
    let dashes_right = dashes_total - dashes_left;

    // Serial output
    let ansi_row = row + 1; // ANSI is 1-based
    let _ = write!(SerialWriter, "\x1b[{};1H", ansi_row);
    serial_driver::write_str("\x1b[90m"); // Dark gray

    for _ in 0..dashes_left.min(40) {
        serial_driver::write_str("-");
    }
    serial_driver::write_str(" ");
    serial_driver::write_str(label);
    serial_driver::write_str(" ");
    for _ in 0..dashes_right.min(40) {
        serial_driver::write_str("-");
    }

    serial_driver::write_str("\x1b[0m\x1b[K\r\n");

    // Framebuffer output
    if let Some(console) = fb_console {
        console.set_position(0, row as u32);
        console.set_fg_color(Color::new(128, 128, 128)); // Gray

        for _ in 0..dashes_left.min(40) {
            let _ = console.write_str("-");
        }
        let _ = console.write_str(" ");
        let _ = console.write_str(label);
        let _ = console.write_str(" ");
        for _ in 0..dashes_right.min(40) {
            let _ = console.write_str("-");
        }

        // Clear rest of line
        let (col, _) = console.position();
        let term_cols = console.cols();
        for _ in col..term_cols {
            let _ = console.write_str(" ");
        }

        console.reset_colors();
    }
}

fn draw_header(fb_console: &mut Option<FramebufferConsole>, cols: usize) {
    menu_common::draw_header(MENU_TITLE, fb_console, cols);
}

/// Draw a single boot entry
fn draw_entry(
    index: usize,
    entry: &BootEntry,
    is_selected: bool,
    row: usize,
    fb_console: &mut Option<FramebufferConsole>,
    _cols: usize,
) {
    let mut desc: String<128> = String::new();
    entry.format_description(&mut desc);

    // Build the line
    let marker = if is_selected { "[*]" } else { "[ ]" };

    // Serial output
    let ansi_row = row + 1; // ANSI is 1-based
    let _ = write!(SerialWriter, "\x1b[{};1H", ansi_row); // Position cursor

    if is_selected {
        serial_driver::write_str("\x1b[7m"); // Inverse video
    }

    let _ = write!(SerialWriter, "   {}. {} {}", index + 1, marker, desc);

    if is_selected {
        serial_driver::write_str("\x1b[0m"); // Reset
    }

    // Clear rest of line
    serial_driver::write_str("\x1b[K\r\n");

    // Framebuffer output
    if let Some(console) = fb_console {
        console.set_position(3, row as u32);

        if is_selected {
            console.set_colors(HIGHLIGHT_FG, HIGHLIGHT_BG);
        } else {
            console.set_colors(DEFAULT_FG, DEFAULT_BG);
        }

        let _ = write!(console, "{}. {} {}", index + 1, marker, desc);

        // Clear rest of line with spaces
        let (col, _) = console.position();
        let cols = console.cols();
        for _ in col..cols {
            let _ = console.write_str(" ");
        }

        console.reset_colors();
    }
}

/// Clear a possible scroll indicator row.
fn clear_scroll_indicator(row: usize, fb_console: &mut Option<FramebufferConsole>) {
    let ansi_row = row + 1;
    let _ = write!(SerialWriter, "\x1b[{};40H ", ansi_row);

    if let Some(console) = fb_console {
        let cols = console.cols();
        console.set_position(cols / 2, row as u32);
        let _ = console.write_str(" ");
    }
}

/// Draw a simple scroll indicator when the menu does not fit on screen.
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

/// Draw the countdown timer
fn draw_countdown(seconds: u32, fb_console: &mut Option<FramebufferConsole>) {
    let mut msg: String<64> = String::new();
    if seconds > 0 {
        let _ = write!(msg, "Booting in {} seconds...", seconds);
    } else {
        let _ = write!(msg, "Booting now...");
    }

    // Serial output - position at bottom area
    serial_driver::write_str("\x1b[20;1H"); // Row 20
    serial_driver::write_str("\x1b[33m"); // Yellow
    serial_driver::write_str(&msg);
    serial_driver::write_str("\x1b[K"); // Clear rest of line
    serial_driver::write_str("\x1b[0m");

    // Framebuffer output
    if let Some(console) = fb_console {
        let row = console.rows().saturating_sub(3);
        console.set_fg_color(Color::new(255, 255, 0)); // Yellow
        console.write_centered(row, &msg);
        console.reset_colors();
    }
}

/// Remove the countdown line once the automatic boot is cancelled.
fn clear_countdown(fb_console: &mut Option<FramebufferConsole>) {
    serial_driver::write_str("\x1b[20;1H\x1b[K");
    if let Some(console) = fb_console {
        let row = console.rows().saturating_sub(3);
        console.clear_line(row);
    }
}

/// Draw a status message (always red — used for errors)
fn draw_status(message: &str, fb_console: &mut Option<FramebufferConsole>) {
    let row = fb_console
        .as_ref()
        .map(|c| c.rows() as usize)
        .unwrap_or(25)
        .saturating_sub(1);
    menu_common::draw_status_message(row, message, false, fb_console);
}
