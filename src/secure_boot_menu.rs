//! Secure Boot Settings Menu
//!
//! This module provides a user interface for managing Secure Boot settings,
//! including viewing status, enabling/disabling Secure Boot, and managing keys.

use crate::coreboot;
use crate::drivers::keyboard;
use crate::drivers::serial as serial_driver;
use crate::efi::auth::{self, boot as secure_boot};
use crate::framebuffer_console::{
    Color, FramebufferConsole, DEFAULT_BG, DEFAULT_FG, HIGHLIGHT_BG, HIGHLIGHT_FG, TITLE_COLOR,
};
use crate::time::delay_ms;
use core::fmt::Write;
use heapless::String;

/// Menu title
const MENU_TITLE: &str = "Secure Boot Settings";

/// Menu options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuOption {
    ToggleSecureBoot,
    EnrollDefaultKeys,
    EnrollCustomPK,
    ClearAllKeys,
    ReturnToBootMenu,
}

impl MenuOption {
    fn label(&self, secure_boot_enabled: bool, setup_mode: bool) -> &'static str {
        match self {
            MenuOption::ToggleSecureBoot => {
                if setup_mode {
                    "Enable Secure Boot (unavailable in Setup Mode)"
                } else if secure_boot_enabled {
                    "Disable Secure Boot"
                } else {
                    "Enable Secure Boot"
                }
            }
            MenuOption::EnrollDefaultKeys => {
                if setup_mode {
                    "Enroll Default Keys (Microsoft)"
                } else {
                    "Enroll Default Keys (requires Setup Mode)"
                }
            }
            MenuOption::EnrollCustomPK => {
                if setup_mode {
                    "Enroll Custom PK from ESP (EFI\\keys\\PK.cer)"
                } else {
                    "Enroll Custom PK (requires Setup Mode)"
                }
            }
            MenuOption::ClearAllKeys => "Clear All Keys (return to Setup Mode)",
            MenuOption::ReturnToBootMenu => "Return to Boot Menu",
        }
    }

    fn is_enabled(&self, _secure_boot_enabled: bool, setup_mode: bool) -> bool {
        match self {
            MenuOption::ToggleSecureBoot => !setup_mode, // Can only toggle in User Mode
            MenuOption::EnrollDefaultKeys => setup_mode, // Can only enroll in Setup Mode
            MenuOption::EnrollCustomPK => setup_mode,    // Can only enroll in Setup Mode
            MenuOption::ClearAllKeys => true,            // Always available
            MenuOption::ReturnToBootMenu => true,        // Always available
        }
    }
}

const MENU_OPTIONS: [MenuOption; 5] = [
    MenuOption::ToggleSecureBoot,
    MenuOption::EnrollDefaultKeys,
    MenuOption::EnrollCustomPK,
    MenuOption::ClearAllKeys,
    MenuOption::ReturnToBootMenu,
];

/// Show the Secure Boot settings menu
///
/// This displays Secure Boot status and allows the user to manage settings.
pub fn show_secure_boot_menu() {
    // Get framebuffer for rendering
    let fb_info = coreboot::get_framebuffer();
    let mut fb_console = fb_info.as_ref().map(FramebufferConsole::new);

    let mut selected = 0usize;
    let mut status_message: Option<(&str, bool)> = None; // (message, is_success)

    loop {
        // Get current state
        let setup_mode = auth::is_setup_mode();
        let secure_boot_enabled = auth::is_secure_boot_enabled();
        let (pk_count, kek_count, db_count, dbx_count) = secure_boot::get_enrollment_summary();

        // Clear and draw
        clear_screen(&mut fb_console);
        draw_menu(
            &mut fb_console,
            selected,
            setup_mode,
            secure_boot_enabled,
            pk_count,
            kek_count,
            db_count,
            dbx_count,
            status_message,
        );

        // Clear status message after displaying
        status_message = None;

        // Wait for input
        loop {
            if let Some(key) = read_key() {
                match key {
                    KeyPress::Up | KeyPress::Char('k') => {
                        if selected > 0 {
                            selected -= 1;
                        }
                        break;
                    }
                    KeyPress::Down | KeyPress::Char('j') => {
                        if selected + 1 < MENU_OPTIONS.len() {
                            selected += 1;
                        }
                        break;
                    }
                    KeyPress::Enter => {
                        let option = MENU_OPTIONS[selected];

                        if option == MenuOption::ReturnToBootMenu {
                            return;
                        }

                        if !option.is_enabled(secure_boot_enabled, setup_mode) {
                            status_message = Some(("Option not available in current mode", false));
                            break;
                        }

                        // Execute the action
                        match option {
                            MenuOption::ToggleSecureBoot => {
                                if secure_boot_enabled {
                                    auth::disable_secure_boot();
                                    status_message = Some(("Secure Boot disabled", true));
                                } else {
                                    auth::enable_secure_boot();
                                    status_message = Some(("Secure Boot enabled", true));
                                }
                                // Update status variables
                                let _ = secure_boot::update_status_variables();
                            }
                            MenuOption::EnrollDefaultKeys => {
                                status_message = Some(("Enrolling keys...", true));
                                // Redraw to show "enrolling" message
                                clear_screen(&mut fb_console);
                                draw_menu(
                                    &mut fb_console,
                                    selected,
                                    setup_mode,
                                    secure_boot_enabled,
                                    pk_count,
                                    kek_count,
                                    db_count,
                                    dbx_count,
                                    status_message,
                                );

                                match enroll_default_keys() {
                                    Ok(()) => {
                                        status_message =
                                            Some(("Default keys enrolled successfully!", true));
                                    }
                                    Err(msg) => {
                                        status_message = Some((msg, false));
                                    }
                                }
                            }
                            MenuOption::EnrollCustomPK => {
                                status_message = Some(("Searching for PK on ESP...", true));
                                // Redraw to show "searching" message
                                clear_screen(&mut fb_console);
                                draw_menu(
                                    &mut fb_console,
                                    selected,
                                    setup_mode,
                                    secure_boot_enabled,
                                    pk_count,
                                    kek_count,
                                    db_count,
                                    dbx_count,
                                    status_message,
                                );

                                match enroll_custom_pk() {
                                    Ok(source) => {
                                        status_message = Some((source, true));
                                    }
                                    Err(msg) => {
                                        status_message = Some((msg, false));
                                    }
                                }
                            }
                            MenuOption::ClearAllKeys => {
                                // Confirm before clearing
                                if confirm_action(&mut fb_console, "Clear ALL Secure Boot keys?") {
                                    match secure_boot::clear_all_keys() {
                                        Ok(()) => {
                                            status_message = Some(("All keys cleared", true));
                                        }
                                        Err(_) => {
                                            status_message = Some(("Failed to clear keys", false));
                                        }
                                    }
                                } else {
                                    status_message = Some(("Cancelled", true));
                                }
                            }
                            MenuOption::ReturnToBootMenu => unreachable!(),
                        }
                        break;
                    }
                    KeyPress::Escape | KeyPress::Char('q') => {
                        return;
                    }
                    _ => {}
                }
            }
            delay_ms(10);
        }
    }
}

/// Enroll default keys
fn enroll_default_keys() -> Result<(), &'static str> {
    use crate::efi::auth::enrollment;

    // Enroll in memory
    enrollment::enroll_default_keys().map_err(|_| "Failed to enroll keys")?;

    // Enter user mode
    auth::enter_user_mode();

    // Persist to storage
    secure_boot::persist_key_databases().map_err(|_| "Failed to persist keys")?;

    // Update status variables
    secure_boot::update_status_variables().map_err(|_| "Failed to update status")?;

    Ok(())
}

/// Enroll custom PK from ESP
fn enroll_custom_pk() -> Result<&'static str, &'static str> {
    use crate::efi::auth::key_files;

    match key_files::enroll_pk_from_file() {
        Ok(source) => {
            // Return a success message with the source
            match source {
                "NVMe" => Ok("Custom PK enrolled from NVMe ESP!"),
                "SATA" => Ok("Custom PK enrolled from SATA ESP!"),
                "SD" => Ok("Custom PK enrolled from SD card ESP!"),
                _ => Ok("Custom PK enrolled successfully!"),
            }
        }
        Err(auth::AuthError::NoSuitableKey) => {
            Err("No PK file found (place PK.cer in EFI\\keys\\)")
        }
        Err(auth::AuthError::CertificateParseError) => Err("Invalid certificate format"),
        Err(_) => Err("Failed to enroll custom PK"),
    }
}

/// Show a confirmation dialog
fn confirm_action(fb_console: &mut Option<FramebufferConsole>, message: &str) -> bool {
    // Draw confirmation
    let rows = fb_console.as_ref().map(|c| c.rows()).unwrap_or(25);
    let confirm_row = rows / 2;

    // Serial
    serial_driver::write_str("\x1b[2J\x1b[H"); // Clear
    serial_driver::write_str("\r\n\r\n");
    serial_driver::write_str("\x1b[1;33m"); // Yellow bold
    serial_driver::write_str("  ");
    serial_driver::write_str(message);
    serial_driver::write_str("\x1b[0m\r\n\r\n");
    serial_driver::write_str("  Press Y to confirm, N to cancel\r\n");

    // Framebuffer
    if let Some(console) = fb_console {
        console.clear();
        console.set_fg_color(Color::new(255, 255, 0)); // Yellow
        console.write_centered(confirm_row, message);
        console.reset_colors();
        console.write_centered(confirm_row + 2, "Press Y to confirm, N to cancel");
    }

    // Wait for response
    loop {
        if let Some(key) = read_key() {
            match key {
                KeyPress::Char('y') | KeyPress::Char('Y') => return true,
                KeyPress::Char('n') | KeyPress::Char('N') | KeyPress::Escape => return false,
                _ => {}
            }
        }
        delay_ms(10);
    }
}

/// Draw the complete menu
fn draw_menu(
    fb_console: &mut Option<FramebufferConsole>,
    selected: usize,
    setup_mode: bool,
    secure_boot_enabled: bool,
    pk_count: usize,
    kek_count: usize,
    db_count: usize,
    dbx_count: usize,
    status_message: Option<(&str, bool)>,
) {
    let cols = fb_console.as_ref().map(|c| c.cols()).unwrap_or(80) as usize;

    // Draw header
    draw_header(fb_console, cols);

    // Draw status section
    let status_start_row = 4;
    draw_status(
        fb_console,
        status_start_row,
        setup_mode,
        secure_boot_enabled,
        pk_count,
        kek_count,
        db_count,
        dbx_count,
    );

    // Draw menu options
    let options_start_row = status_start_row + 8;
    draw_options(
        fb_console,
        options_start_row,
        selected,
        setup_mode,
        secure_boot_enabled,
    );

    // Draw help text
    let help_row = options_start_row + MENU_OPTIONS.len() + 2;
    draw_help(fb_console, help_row, cols);

    // Draw status message if any
    if let Some((msg, is_success)) = status_message {
        draw_status_message(fb_console, help_row + 2, msg, is_success);
    }
}

/// Draw the menu header
fn draw_header(fb_console: &mut Option<FramebufferConsole>, cols: usize) {
    // Build horizontal line
    let mut line = [0u8; 128];
    let line_len = cols.min(line.len());
    line[..line_len].fill(b'=');
    let line_str = core::str::from_utf8(&line[..line_len]).unwrap_or("");

    // Serial output
    serial_driver::write_str("\x1b[H"); // Home cursor
    serial_driver::write_str("\x1b[1;33m"); // Yellow, bold
    serial_driver::write_str(line_str);
    serial_driver::write_str("\r\n");

    // Center title
    let title_pad = (cols.saturating_sub(MENU_TITLE.len())) / 2;
    for _ in 0..title_pad {
        serial_driver::write_str(" ");
    }
    serial_driver::write_str(MENU_TITLE);
    serial_driver::write_str("\r\n");

    serial_driver::write_str(line_str);
    serial_driver::write_str("\r\n\x1b[0m");

    // Framebuffer output
    if let Some(console) = fb_console {
        console.set_position(0, 0);
        console.set_fg_color(TITLE_COLOR);
        let _ = console.write_str(line_str);
        console.set_position(0, 1);
        console.write_centered(1, MENU_TITLE);
        console.set_position(0, 2);
        let _ = console.write_str(line_str);
        console.reset_colors();
    }
}

/// Draw the status section
fn draw_status(
    fb_console: &mut Option<FramebufferConsole>,
    start_row: usize,
    setup_mode: bool,
    secure_boot_enabled: bool,
    pk_count: usize,
    kek_count: usize,
    db_count: usize,
    dbx_count: usize,
) {
    let mode_str = if setup_mode {
        "Setup Mode"
    } else {
        "User Mode"
    };
    let sb_str = if secure_boot_enabled {
        "ENABLED"
    } else {
        "Disabled"
    };

    // Mode color: yellow for setup, green for user
    let mode_color = if setup_mode {
        Color::new(255, 255, 0)
    } else {
        Color::new(0, 255, 0)
    };

    // Secure boot color: green if enabled, red if disabled
    let sb_color = if secure_boot_enabled {
        Color::new(0, 255, 0)
    } else {
        Color::new(255, 100, 100)
    };

    // Serial output
    let _ = write!(SerialWriter, "\x1b[{};1H", start_row + 1);
    serial_driver::write_str("\x1b[1m  Current Status:\x1b[0m\r\n\r\n");

    serial_driver::write_str("    Mode:        ");
    if setup_mode {
        serial_driver::write_str("\x1b[33m"); // Yellow
    } else {
        serial_driver::write_str("\x1b[32m"); // Green
    }
    serial_driver::write_str(mode_str);
    serial_driver::write_str("\x1b[0m\r\n");

    serial_driver::write_str("    Secure Boot: ");
    if secure_boot_enabled {
        serial_driver::write_str("\x1b[32m"); // Green
    } else {
        serial_driver::write_str("\x1b[31m"); // Red
    }
    serial_driver::write_str(sb_str);
    serial_driver::write_str("\x1b[0m\r\n\r\n");

    let _ = write!(
        SerialWriter,
        "    Enrolled Keys: PK={}, KEK={}, db={}, dbx={}\r\n",
        pk_count, kek_count, db_count, dbx_count
    );

    // Framebuffer output
    if let Some(console) = fb_console {
        console.set_position(2, start_row as u32);
        console.set_fg_color(Color::white());
        let _ = console.write_str("Current Status:");

        console.set_position(4, (start_row + 2) as u32);
        console.reset_colors();
        let _ = console.write_str("Mode:        ");
        console.set_fg_color(mode_color);
        let _ = console.write_str(mode_str);

        console.set_position(4, (start_row + 3) as u32);
        console.reset_colors();
        let _ = console.write_str("Secure Boot: ");
        console.set_fg_color(sb_color);
        let _ = console.write_str(sb_str);

        console.set_position(4, (start_row + 5) as u32);
        console.reset_colors();
        let mut key_info: String<64> = String::new();
        let _ = write!(
            key_info,
            "Enrolled Keys: PK={}, KEK={}, db={}, dbx={}",
            pk_count, kek_count, db_count, dbx_count
        );
        let _ = console.write_str(&key_info);
    }
}

/// Draw menu options
fn draw_options(
    fb_console: &mut Option<FramebufferConsole>,
    start_row: usize,
    selected: usize,
    setup_mode: bool,
    secure_boot_enabled: bool,
) {
    // Serial: position cursor
    let _ = write!(SerialWriter, "\x1b[{};1H", start_row + 1);
    serial_driver::write_str("\x1b[1m  Actions:\x1b[0m\r\n\r\n");

    for (i, option) in MENU_OPTIONS.iter().enumerate() {
        let is_selected = i == selected;
        let is_enabled = option.is_enabled(secure_boot_enabled, setup_mode);
        let label = option.label(secure_boot_enabled, setup_mode);

        // Serial output
        if is_selected {
            serial_driver::write_str("\x1b[7m"); // Inverse
        }
        if !is_enabled {
            serial_driver::write_str("\x1b[90m"); // Gray
        }

        let marker = if is_selected { " > " } else { "   " };
        let _ = write!(SerialWriter, "  {} {}", marker, label);

        serial_driver::write_str("\x1b[0m"); // Reset
        serial_driver::write_str("\x1b[K\r\n"); // Clear to EOL

        // Framebuffer output
        if let Some(console) = fb_console {
            let row = (start_row + 2 + i) as u32;
            console.set_position(2, row);

            if is_selected {
                console.set_colors(HIGHLIGHT_FG, HIGHLIGHT_BG);
            } else if !is_enabled {
                console.set_fg_color(Color::new(128, 128, 128)); // Gray
            } else {
                console.set_colors(DEFAULT_FG, DEFAULT_BG);
            }

            let _ = write!(console, " {} {} ", marker, label);

            // Fill rest of line
            let (col, _) = console.position();
            let cols = console.cols();
            for _ in col..cols.saturating_sub(2) {
                let _ = console.write_str(" ");
            }

            console.reset_colors();
        }
    }
}

/// Draw help text
fn draw_help(fb_console: &mut Option<FramebufferConsole>, row: usize, cols: usize) {
    let help_text = "Up/Down: Navigate | Enter: Select | Esc/Q: Back";

    // Serial
    let _ = write!(SerialWriter, "\x1b[{};1H", row + 1);
    serial_driver::write_str("\x1b[36m"); // Cyan
    let help_pad = (cols.saturating_sub(help_text.len())) / 2;
    for _ in 0..help_pad {
        serial_driver::write_str(" ");
    }
    serial_driver::write_str(help_text);
    serial_driver::write_str("\x1b[0m");

    // Framebuffer
    if let Some(console) = fb_console {
        console.set_fg_color(Color::new(0, 192, 192)); // Cyan
        console.write_centered(row as u32, help_text);
        console.reset_colors();
    }
}

/// Draw a status message
fn draw_status_message(
    fb_console: &mut Option<FramebufferConsole>,
    row: usize,
    message: &str,
    is_success: bool,
) {
    let color = if is_success {
        Color::new(0, 255, 0) // Green
    } else {
        Color::new(255, 0, 0) // Red
    };

    // Serial
    let _ = write!(SerialWriter, "\x1b[{};1H", row + 1);
    if is_success {
        serial_driver::write_str("\x1b[32m"); // Green
    } else {
        serial_driver::write_str("\x1b[31m"); // Red
    }
    serial_driver::write_str("  ");
    serial_driver::write_str(message);
    serial_driver::write_str("\x1b[0m");

    // Framebuffer
    if let Some(console) = fb_console {
        console.set_fg_color(color);
        console.write_centered(row as u32, message);
        console.reset_colors();
    }
}

/// Clear screen
fn clear_screen(fb_console: &mut Option<FramebufferConsole>) {
    serial_driver::write_str("\x1b[2J\x1b[H");
    if let Some(console) = fb_console {
        console.clear();
    }
}

/// Key press types
#[derive(Debug, Clone, Copy)]
enum KeyPress {
    Up,
    Down,
    Enter,
    Escape,
    Char(char),
}

/// Read a key from keyboard or serial
fn read_key() -> Option<KeyPress> {
    // Try PS/2 keyboard first
    if let Some((scan_code, unicode_char)) = keyboard::try_read_key() {
        return match scan_code {
            0x01 => Some(KeyPress::Up),
            0x02 => Some(KeyPress::Down),
            0x17 => Some(KeyPress::Escape),
            0 if unicode_char == 0x0D => Some(KeyPress::Enter),
            0 if unicode_char > 0 => Some(KeyPress::Char(unicode_char as u8 as char)),
            _ => None,
        };
    }

    // Try serial input
    if let Some(byte) = serial_driver::try_read() {
        return match byte {
            0x1B => {
                delay_ms(10);
                if let Some(b'[') = serial_driver::try_read() {
                    match serial_driver::try_read() {
                        Some(b'A') => Some(KeyPress::Up),
                        Some(b'B') => Some(KeyPress::Down),
                        _ => Some(KeyPress::Escape),
                    }
                } else {
                    Some(KeyPress::Escape)
                }
            }
            b'\r' | b'\n' => Some(KeyPress::Enter),
            c => Some(KeyPress::Char(c as char)),
        };
    }

    None
}

/// Helper for serial formatted output
struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial_driver::write_str(s);
        Ok(())
    }
}
