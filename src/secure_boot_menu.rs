//! Secure Boot Settings Menu
//!
//! This module provides a user interface for managing Secure Boot settings,
//! including viewing status, enabling/disabling Secure Boot, and managing keys.

use crate::coreboot;
use crate::efi::auth::{self, boot as secure_boot};
use crate::menu_common::{self, KeyPress};
use crate::time::delay_ms;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, HighlightSpacing, List, ListItem, ListState, Paragraph};
use ratatui::Terminal;

/// Menu title
const MENU_TITLE: &str = "Secure Boot Settings";

/// Help text
const HELP_TEXT: &str = "Up/Down: Navigate | Enter: Select | Esc/Q: Back";

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
            MenuOption::ImportDbxUpdate => "Import dbx Update from ESP (EFI\\keys\\dbx.bin)",
            MenuOption::ClearAllKeys => "Clear All Keys (return to Setup Mode)",
            MenuOption::ReturnToBootMenu => "Return to Boot Menu",
        }
    }

    fn is_enabled(&self, _secure_boot_enabled: bool, setup_mode: bool) -> bool {
        match self {
            MenuOption::ToggleSecureBoot => !setup_mode, // Can only toggle in User Mode
            MenuOption::EnrollDefaultKeys => setup_mode, // Can only enroll in Setup Mode
            MenuOption::EnrollCustomPK => setup_mode,    // Can only enroll in Setup Mode
            MenuOption::ImportDbxUpdate => true,         // Can import dbx anytime
            MenuOption::ClearAllKeys => true,            // Always available
            MenuOption::ReturnToBootMenu => true,        // Always available
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
    let fb_info = coreboot::get_framebuffer();
    let backend = crate::tui::DualBackend::new(fb_info.as_ref());
    let mut terminal = match Terminal::new(backend) {
        Ok(t) => t,
        Err(_) => {
            log::error!("Failed to create ratatui terminal");
            return;
        }
    };
    let _ = terminal.clear();
    let _ = terminal.hide_cursor();

    let mut selected = 0usize;
    let mut status_message: Option<(String, bool)> = None; // (message, is_success)

    loop {
        // Get current state
        let setup_mode = auth::is_setup_mode();
        let secure_boot_enabled = auth::is_secure_boot_enabled();
        let (pk_count, kek_count, db_count, dbx_count) = secure_boot::get_enrollment_summary();

        // Render
        render_menu(
            &mut terminal,
            selected,
            setup_mode,
            secure_boot_enabled,
            pk_count,
            kek_count,
            db_count,
            dbx_count,
            &status_message,
        );

        // Clear status message after displaying
        status_message = None;

        // Wait for input
        loop {
            if let Some(key) = read_key() {
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
                            status_message =
                                Some(("Option not available in current mode".into(), false));
                            break;
                        }

                        // Execute the action
                        match option {
                            MenuOption::ToggleSecureBoot => {
                                if secure_boot_enabled {
                                    auth::disable_secure_boot();
                                    status_message = Some(("Secure Boot disabled".into(), true));
                                } else {
                                    auth::enable_secure_boot();
                                    status_message = Some(("Secure Boot enabled".into(), true));
                                }
                                let _ = secure_boot::update_status_variables();
                            }
                            MenuOption::EnrollDefaultKeys => {
                                status_message = Some(("Enrolling keys...".into(), true));
                                render_menu(
                                    &mut terminal,
                                    selected,
                                    setup_mode,
                                    secure_boot_enabled,
                                    pk_count,
                                    kek_count,
                                    db_count,
                                    dbx_count,
                                    &status_message,
                                );

                                match enroll_default_keys() {
                                    Ok(()) => {
                                        status_message = Some((
                                            "Default keys enrolled successfully!".into(),
                                            true,
                                        ));
                                    }
                                    Err(msg) => {
                                        status_message = Some((msg.into(), false));
                                    }
                                }
                            }
                            MenuOption::EnrollCustomPK => {
                                status_message = Some(("Searching for PK on ESP...".into(), true));
                                render_menu(
                                    &mut terminal,
                                    selected,
                                    setup_mode,
                                    secure_boot_enabled,
                                    pk_count,
                                    kek_count,
                                    db_count,
                                    dbx_count,
                                    &status_message,
                                );

                                match enroll_custom_pk() {
                                    Ok(source) => {
                                        status_message = Some((source.into(), true));
                                    }
                                    Err(msg) => {
                                        status_message = Some((msg.into(), false));
                                    }
                                }
                            }
                            MenuOption::ImportDbxUpdate => {
                                status_message = Some(("Searching for dbx on ESP...".into(), true));
                                render_menu(
                                    &mut terminal,
                                    selected,
                                    setup_mode,
                                    secure_boot_enabled,
                                    pk_count,
                                    kek_count,
                                    db_count,
                                    dbx_count,
                                    &status_message,
                                );

                                match import_dbx_update() {
                                    Ok(msg) => {
                                        status_message = Some((msg.into(), true));
                                    }
                                    Err(msg) => {
                                        status_message = Some((msg.into(), false));
                                    }
                                }
                            }
                            MenuOption::ClearAllKeys => {
                                if confirm_action(&mut terminal, "Clear ALL Secure Boot keys?") {
                                    match secure_boot::clear_all_keys() {
                                        Ok(()) => {
                                            status_message =
                                                Some(("All keys cleared".into(), true));
                                        }
                                        Err(_) => {
                                            status_message =
                                                Some(("Failed to clear keys".into(), false));
                                        }
                                    }
                                } else {
                                    status_message = Some(("Cancelled".into(), true));
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

/// Render the complete menu with ratatui
fn render_menu(
    terminal: &mut Terminal<crate::tui::DualBackend>,
    selected: usize,
    setup_mode: bool,
    secure_boot_enabled: bool,
    pk_count: usize,
    kek_count: usize,
    db_count: usize,
    dbx_count: usize,
    status_message: &Option<(String, bool)>,
) {
    let _ = terminal.draw(|frame| {
        let area = frame.area();

        let chunks = Layout::vertical([
            Constraint::Length(3), // header
            Constraint::Length(7), // status section
            Constraint::Min(8),    // options list
            Constraint::Length(3), // status msg + help
        ])
        .split(area);

        // --- Header ---
        let header = Paragraph::new(Line::from(MENU_TITLE).alignment(Alignment::Center))
            .style(Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .block(
                Block::new()
                    .borders(Borders::TOP | Borders::BOTTOM)
                    .border_style(Style::new().fg(Color::Yellow)),
            );
        frame.render_widget(header, chunks[0]);

        // --- Status section ---
        let mode_str = if setup_mode {
            "Setup Mode"
        } else {
            "User Mode"
        };
        let mode_color = if setup_mode {
            Color::Yellow
        } else {
            Color::Green
        };
        let sb_str = if secure_boot_enabled {
            "ENABLED"
        } else {
            "Disabled"
        };
        let sb_color = if secure_boot_enabled {
            Color::Green
        } else {
            Color::LightRed
        };

        let status_lines = vec![
            Line::from(Span::styled(
                "  Current Status:",
                Style::new().add_modifier(Modifier::BOLD),
            )),
            Line::raw(""),
            Line::from(vec![
                Span::raw("    Mode:        "),
                Span::styled(mode_str, Style::new().fg(mode_color)),
            ]),
            Line::from(vec![
                Span::raw("    Secure Boot: "),
                Span::styled(sb_str, Style::new().fg(sb_color)),
            ]),
            Line::raw(""),
            Line::from(Span::raw(format!(
                "    Enrolled Keys: PK={}, KEK={}, db={}, dbx={}",
                pk_count, kek_count, db_count, dbx_count
            ))),
        ];
        frame.render_widget(Paragraph::new(status_lines), chunks[1]);

        // --- Options list ---
        let header_items: [ListItem; 2] = [
            ListItem::new(Line::from(Span::styled(
                "  Actions:",
                Style::new().add_modifier(Modifier::BOLD),
            ))),
            ListItem::new(Line::raw("")),
        ];

        let option_items = MENU_OPTIONS.iter().map(|option| {
            let is_enabled = option.is_enabled(secure_boot_enabled, setup_mode);
            let label = option.label(secure_boot_enabled, setup_mode);

            let style = if !is_enabled {
                Style::new().fg(Color::DarkGray)
            } else {
                Style::new().fg(Color::Gray)
            };

            ListItem::new(Line::raw(format!("  {}", label))).style(style)
        });

        let items: alloc::vec::Vec<ListItem> =
            header_items.into_iter().chain(option_items).collect();

        let list = List::new(items)
            .highlight_style(
                Style::new()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(" > ")
            .highlight_spacing(HighlightSpacing::Always);

        // Offset by 2 to skip the "Actions:" header and blank line
        let mut list_state = ListState::default().with_selected(Some(selected + 2));
        frame.render_stateful_widget(list, chunks[2], &mut list_state);

        // --- Footer: status message + help ---
        let footer_chunks = Layout::vertical([
            Constraint::Length(1), // status or blank
            Constraint::Length(1), // blank
            Constraint::Length(1), // help
        ])
        .split(chunks[3]);

        if let Some((msg, is_success)) = status_message {
            let color = if *is_success {
                Color::Green
            } else {
                Color::Red
            };
            let line = Line::from(Span::styled(msg.as_str(), Style::new().fg(color)))
                .alignment(Alignment::Center);
            frame.render_widget(Paragraph::new(line), footer_chunks[0]);
        }

        let help = Paragraph::new(
            Line::from(HELP_TEXT)
                .style(Style::new().fg(Color::Cyan))
                .alignment(Alignment::Center),
        );
        frame.render_widget(help, footer_chunks[2]);
    });
}

/// Show a confirmation dialog
fn confirm_action(terminal: &mut Terminal<crate::tui::DualBackend>, message: &str) -> bool {
    let msg = String::from(message);
    let _ = terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::vertical([
            Constraint::Percentage(40),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(area);

        let prompt = Paragraph::new(
            Line::from(Span::styled(
                msg.as_str(),
                Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ))
            .alignment(Alignment::Center),
        );
        frame.render_widget(prompt, chunks[1]);

        let help = Paragraph::new(
            Line::from("Press Y to confirm, N to cancel")
                .alignment(Alignment::Center)
                .style(Style::new().fg(Color::Gray)),
        );
        frame.render_widget(help, chunks[3]);
    });

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

// --- Business logic (unchanged) ---

/// Enroll default keys
fn enroll_default_keys() -> Result<(), &'static str> {
    use crate::efi::auth::enrollment;

    enrollment::enroll_default_keys().map_err(|_| "Failed to enroll keys")?;
    auth::enter_user_mode();
    secure_boot::persist_key_databases().map_err(|_| "Failed to persist keys")?;
    secure_boot::update_status_variables().map_err(|_| "Failed to update status")?;
    Ok(())
}

/// Enroll custom PK from ESP
fn enroll_custom_pk() -> Result<&'static str, &'static str> {
    use crate::efi::auth::key_files;

    match key_files::enroll_pk_from_file() {
        Ok(source) => match source {
            "NVMe" => Ok("Custom PK enrolled from NVMe ESP!"),
            "SATA" => Ok("Custom PK enrolled from SATA ESP!"),
            "SD" => Ok("Custom PK enrolled from SD card ESP!"),
            _ => Ok("Custom PK enrolled successfully!"),
        },
        Err(auth::AuthError::NoSuitableKey) => {
            Err("No PK file found (place PK.cer in EFI\\keys\\)")
        }
        Err(auth::AuthError::CertificateParseError) => Err("Invalid certificate format"),
        Err(_) => Err("Failed to enroll custom PK"),
    }
}

/// Import dbx (forbidden signature database) update from ESP
fn import_dbx_update() -> Result<&'static str, &'static str> {
    use crate::efi::auth::dbx_update;

    match dbx_update::enroll_dbx_from_file() {
        Ok(result) => {
            log::info!(
                "dbx update imported: {} SHA-256 hashes, {} certificates from {}",
                result.sha256_count,
                result.x509_count,
                result.source
            );

            match result.source {
                "NVMe" => Ok("dbx update imported from NVMe ESP!"),
                "SATA" => Ok("dbx update imported from SATA ESP!"),
                "SD" => Ok("dbx update imported from SD card ESP!"),
                _ => Ok("dbx update imported successfully!"),
            }
        }
        Err(auth::AuthError::NoSuitableKey) => {
            Err("No dbx file found (place dbx.bin in EFI\\keys\\)")
        }
        Err(auth::AuthError::InvalidHeader) => Err("Invalid dbx file format"),
        Err(_) => Err("Failed to import dbx update"),
    }
}

fn read_key() -> Option<KeyPress> {
    menu_common::read_key()
}
