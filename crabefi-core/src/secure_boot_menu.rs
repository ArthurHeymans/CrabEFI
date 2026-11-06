//! Secure Boot Settings Menu
//!
//! This module provides a user interface for managing Secure Boot settings,
//! including viewing status, enabling/disabling Secure Boot, and managing keys.

use crate::drivers::serial as serial_driver;
use crate::efi::auth::{self, boot as secure_boot};
use crate::framebuffer_console::{
    Color, DEFAULT_BG, DEFAULT_FG, FramebufferConsole, HIGHLIGHT_BG, HIGHLIGHT_FG,
};
use crate::menu_common::{self, KeyPress, SerialWriter};
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
    ImportDbxUpdate,
    ClearAllKeys,
    ReturnToBootMenu,
}

impl MenuOption {
    fn label(&self, secure_boot_enabled: bool, setup_mode: bool) -> &'static str {
        match self {
            MenuOption::ToggleSecureBoot => {
                if secure_boot_enabled {
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
            MenuOption::ImportDbxUpdate => "Import dbx Update from ESP (EFI\\keys\\dbxupdate.auth)",
            MenuOption::ClearAllKeys => "Clear All Keys (return to Setup Mode)",
            MenuOption::ReturnToBootMenu => "Return to Boot Menu",
        }
    }

    fn is_enabled(&self, _secure_boot_enabled: bool, setup_mode: bool) -> bool {
        match self {
            MenuOption::ToggleSecureBoot => true, // Preference is valid in Setup Mode too
            MenuOption::EnrollDefaultKeys => setup_mode, // Can only enroll in Setup Mode
            MenuOption::EnrollCustomPK => setup_mode, // Can only enroll in Setup Mode
            MenuOption::ImportDbxUpdate => true,  // Can import dbx anytime
            MenuOption::ClearAllKeys => true,     // Always available
            MenuOption::ReturnToBootMenu => true, // Always available
        }
    }
}

const MENU_OPTIONS: [MenuOption; 6] = [
    MenuOption::ToggleSecureBoot,
    MenuOption::EnrollDefaultKeys,
    MenuOption::EnrollCustomPK,
    MenuOption::ImportDbxUpdate,
    MenuOption::ClearAllKeys,
    MenuOption::ReturnToBootMenu,
];

/// Show the Secure Boot settings menu
///
/// This displays Secure Boot status and allows the user to manage settings.
pub fn show_secure_boot_menu() {
    // Get framebuffer for rendering
    let fb_info = crate::handoff::framebuffer();
    let mut fb_console = fb_info.as_ref().map(FramebufferConsole::new);

    let mut selected = 0usize;
    let mut status_message: Option<(&str, bool)> = None; // (message, is_success)

    loop {
        // Get current state
        let setup_mode = auth::is_setup_mode();
        // Action labels/toggles follow the saved preference. Enforcement is
        // rendered separately and remains off in Setup Mode.
        let secure_boot_enabled = auth::is_secure_boot_requested();
        let (pk_count, kek_count, db_count, dbx_count) = secure_boot::get_enrollment_summary();

        // Clear and draw
        menu_common::clear_screen(&mut fb_console);
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
            if let Some(key) = menu_common::read_key() {
                match key {
                    KeyPress::Up | KeyPress::Char('k') => {
                        selected = selected.saturating_sub(1);
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
                                status_message = Some(toggle_secure_boot_action());
                                // Update status variables
                                let _ = secure_boot::update_status_variables();
                            }
                            MenuOption::EnrollDefaultKeys => {
                                status_message = Some(("Enrolling keys...", true));
                                // Redraw to show "enrolling" message
                                menu_common::clear_screen(&mut fb_console);
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
                                menu_common::clear_screen(&mut fb_console);
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
                            MenuOption::ImportDbxUpdate => {
                                status_message = Some(("Searching for dbx on ESP...", true));
                                // Redraw to show "searching" message
                                menu_common::clear_screen(&mut fb_console);
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

                                match import_dbx_update() {
                                    Ok(msg) => {
                                        status_message = Some((msg, true));
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
                    KeyPress::Char('s') | KeyPress::Char('S') => {
                        break;
                    }
                    KeyPress::Char('f') | KeyPress::Char('F') => {
                        if let Some(hooks) = crate::handoff::callbacks().hooks {
                            if !hooks.show_firmware_settings() {
                                status_message = Some(("Firmware settings not available", false));
                            }
                        } else {
                            status_message = Some(("Firmware settings not available", false));
                        }
                        break;
                    }
                    KeyPress::Char('r') | KeyPress::Char('R') => {
                        crate::reset_system();
                    }
                    KeyPress::Escape | KeyPress::Char('q') | KeyPress::Char('Q') => {
                        return;
                    }
                    _ => {}
                }
            }
            delay_ms(10);
        }
    }
}

/// Shared action for graphical and text setup; report persistence failures.
pub(crate) fn toggle_secure_boot_action() -> (&'static str, bool) {
    match auth::toggle_secure_boot() {
        Ok(state) if !state.requested => ("Secure Boot disabled", true),
        Ok(state) if state.enforcing => ("Secure Boot enabled", true),
        Ok(_) => ("Secure Boot enabled; awaiting PK enrollment", true),
        Err(_) => ("Failed to save Secure Boot preference", false),
    }
}

/// Effective state displayed independently from the requested preference.
pub(crate) fn secure_boot_state_label(state: auth::SecureBootState) -> &'static str {
    if state.enforcing {
        "ACTIVE"
    } else if state.requested {
        "AWAITING PK"
    } else {
        "DISABLED"
    }
}

/// Enroll default keys through the authoritative runtime variable store.
fn enroll_default_keys() -> Result<(), &'static str> {
    secure_boot::enroll_and_persist_default_keys().map_err(|_| "Failed to enroll keys")
}

/// Enroll custom PK from ESP
pub(crate) fn enroll_custom_pk() -> Result<&'static str, &'static str> {
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
        Err(error) => Err(custom_pk_error(error)),
    }
}

pub(crate) fn custom_pk_error(error: auth::AuthError) -> &'static str {
    match error {
        auth::AuthError::NoSuitableKey => "No PK file found (place PK.cer in EFI\\keys\\)",
        auth::AuthError::CertificateParseError => "Invalid certificate format",
        _ => "Failed to enroll custom PK",
    }
}

/// Import dbx (forbidden signature database) update from ESP
pub(crate) fn import_dbx_update() -> Result<&'static str, &'static str> {
    use crate::efi::auth::dbx_update;

    match dbx_update::enroll_dbx_from_file() {
        Ok(result) => {
            // Log the details
            log::info!(
                "dbx update imported: {} SHA-256 hashes, {} certificates from {}",
                result.sha256_count,
                result.x509_count,
                result.source
            );

            // Return a success message with the source
            match result.source {
                "NVMe" => Ok("dbx update imported from NVMe ESP!"),
                "SATA" => Ok("dbx update imported from SATA ESP!"),
                "SD" => Ok("dbx update imported from SD card ESP!"),
                _ => Ok("dbx update imported successfully!"),
            }
        }
        Err(error) => Err(dbx_error(error)),
    }
}

pub(crate) fn dbx_error(error: auth::AuthError) -> &'static str {
    match error {
        auth::AuthError::NoSuitableKey if auth::is_setup_mode() => {
            "No dbx found; use dbxupdate.auth, dbx.bin or dbx.esl in EFI\\keys\\"
        }
        auth::AuthError::NoSuitableKey => {
            "No signed dbx found; use EFI\\keys\\dbxupdate.auth or dbx.auth"
        }
        auth::AuthError::InvalidTimestamp => {
            "dbx timestamp is invalid or not newer; obtain a newer update"
        }
        auth::AuthError::SignatureVerificationFailed => {
            "dbx rejected; verify the update is signed by an enrolled KEK or PK"
        }
        auth::AuthError::AccessDenied => {
            "Runtime refused dbx; check authentication history, policy or variable storage"
        }
        auth::AuthError::BufferTooSmall => {
            "Not enough variable storage for dbx; free space before retrying"
        }
        auth::AuthError::InvalidHeader => "Invalid dbx file format",
        _ => "Failed to import dbx update",
    }
}

/// Show a confirmation dialog
fn confirm_action(fb_console: &mut Option<FramebufferConsole>, message: &str) -> bool {
    menu_common::confirm_dialog(fb_console, message, "Press Y to confirm, N to cancel")
}

/// Draw the complete menu
// Menu state is flat counters rendered in one pass; grouping them would
// scatter the row layout across an extra struct.
#[allow(clippy::too_many_arguments)]
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

fn draw_header(fb_console: &mut Option<FramebufferConsole>, cols: usize) {
    menu_common::draw_header(MENU_TITLE, fb_console, cols);
}

/// Draw the status section
// Same flat menu-state counters as draw_menu.
#[allow(clippy::too_many_arguments)]
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
    let enforcing = auth::is_secure_boot_enabled();
    let sb_str = secure_boot_state_label(auth::SecureBootState {
        requested: secure_boot_enabled,
        setup_mode,
        enforcing,
    });

    // Mode color: yellow for setup, green for user
    let mode_color = if setup_mode {
        Color::new(255, 255, 0)
    } else {
        Color::new(0, 255, 0)
    };

    let sb_color = if enforcing {
        Color::new(0, 255, 0)
    } else if secure_boot_enabled {
        Color::new(255, 190, 0)
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
    if enforcing {
        serial_driver::write_str("\x1b[32m"); // Green
    } else if secure_boot_enabled {
        serial_driver::write_str("\x1b[33m"); // Pending enrollment
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
    menu_common::draw_help(
        row,
        "Up/Down: Navigate | Enter: Select | S: Secure | F: Firmware | R: Reset | Esc/Q: Back",
        fb_console,
        cols,
    );
}

/// Draw a status message
fn draw_status_message(
    fb_console: &mut Option<FramebufferConsole>,
    row: usize,
    message: &str,
    is_success: bool,
) {
    menu_common::draw_status_message(row, message, is_success, fb_console);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_mode_can_enable_and_disable_the_pending_preference() {
        let option = MenuOption::ToggleSecureBoot;
        for setup in [false, true] {
            assert!(option.is_enabled(false, setup));
            assert!(option.is_enabled(true, setup));
            assert_eq!(option.label(false, setup), "Enable Secure Boot");
            assert_eq!(option.label(true, setup), "Disable Secure Boot");
        }
    }

    #[test]
    fn displayed_pending_state_is_not_reported_as_active_enforcement() {
        for (state, label) in [
            (
                auth::SecureBootState {
                    requested: false,
                    setup_mode: true,
                    enforcing: false,
                },
                "DISABLED",
            ),
            (
                auth::SecureBootState {
                    requested: true,
                    setup_mode: true,
                    enforcing: false,
                },
                "AWAITING PK",
            ),
            (
                auth::SecureBootState {
                    requested: true,
                    setup_mode: false,
                    enforcing: true,
                },
                "ACTIVE",
            ),
        ] {
            assert_eq!(secure_boot_state_label(state), label);
        }
    }
}
