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
use crate::menu_common::{self, KeyPress};
use crate::time::delay_ms;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use ratatui::Terminal;
use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, HighlightSpacing, List, ListItem, ListState, Paragraph};

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
            show_message_screen("Firmware settings not available",
                "This firmware does not expose CFR configuration options.");
            return;
        }
    };

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

    let mut items = build_menu_items(cfr_info);

    if items.is_empty() {
        show_message_screen("No configurable options found", "");
        return;
    }

    let mut selected = find_first_selectable(cfr_info, &items, 0);
    let mut status_message: Option<(String, bool)> = None;

    loop {
        let modified = has_changes(&items);

        render_menu(
            &mut terminal,
            cfr_info,
            &items,
            selected,
            modified,
            &status_message,
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
                            status_message = Some(("Option is read-only".into(), false));
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
                        if has_changes(&items)
                            && confirm_dialog(
                                &mut terminal,
                                "Save changes? (takes effect after reset)",
                                "Press Y to save, N to discard",
                            )
                        {
                            let (saved, failed) = save_all_changes(cfr_info, &items);
                            let msg = if failed == 0 {
                                format!("Saved {} option(s).", saved)
                            } else {
                                format!("Saved {}, {} failed to write.", saved, failed)
                            };
                            let is_ok = failed == 0;
                            status_message = Some((msg, is_ok));
                            render_menu(
                                &mut terminal,
                                cfr_info,
                                &items,
                                selected,
                                false,
                                &status_message,
                            );
                            delay_ms(1500);
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
                            show_help_screen(&mut terminal, option);
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

// ============================================================================
// Rendering
// ============================================================================

/// Render the complete menu with ratatui
fn render_menu(
    terminal: &mut Terminal<crate::tui::DualBackend>,
    cfr: &CfrInfo,
    items: &[MenuItem],
    selected: usize,
    modified: bool,
    status_message: &Option<(String, bool)>,
) {
    let _ = terminal.draw(|frame| {
        let area = frame.area();

        let chunks = Layout::vertical([
            Constraint::Length(3), // header
            Constraint::Min(4),   // item list
            Constraint::Length(3), // status + help
        ])
        .split(area);

        // --- Header ---
        let title = if modified {
            "Firmware Settings (modified)"
        } else {
            MENU_TITLE
        };
        let header = Paragraph::new(Line::from(title).alignment(Alignment::Center))
            .style(Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .block(
                Block::new()
                    .borders(Borders::TOP | Borders::BOTTOM)
                    .border_style(Style::new().fg(Color::Yellow)),
            );
        frame.render_widget(header, chunks[0]);

        // --- Build visible item list ---
        let vis = visible_indices(cfr, items);
        let mut list_items: Vec<ListItem> = Vec::new();
        let mut selected_list_pos: Option<usize> = None;

        for &item_idx in &vis {
            let item = &items[item_idx];
            let list_pos = list_items.len();

            match item {
                MenuItem::FormHeader { name } => {
                    let text = format!("--- {} ---", name);
                    list_items.push(
                        ListItem::new(Line::raw(text))
                            .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    );
                }
                MenuItem::SubformHeader { name } => {
                    let text = format!("  {}", name);
                    list_items.push(
                        ListItem::new(Line::raw(text))
                            .style(Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
                    );
                }
                MenuItem::Comment { text } => {
                    list_items.push(
                        ListItem::new(Line::raw(text.as_str()))
                            .style(Style::new().fg(Color::DarkGray)),
                    );
                }
                MenuItem::Option {
                    form_idx,
                    option_idx,
                    current_value,
                    ..
                } => {
                    if let Some(option) = get_option(cfr, *form_idx, *option_idx) {
                        let value_str = format_value(option, current_value);
                        let is_editable = option.is_editable();

                        // Pad name to align values
                        let name = &option.ui_name;
                        let cols = area.width as usize;
                        let pad_to = 40.min(cols.saturating_sub(value_str.len() + 8));
                        let name_display_len = name.len();
                        let padding = if pad_to > name_display_len {
                            pad_to - name_display_len
                        } else {
                            1
                        };
                        let pad: String = core::iter::repeat(' ').take(padding).collect();
                        let text = format!("{}{}{}", name, pad, value_str);

                        let style = if !is_editable {
                            Style::new().fg(Color::DarkGray)
                        } else {
                            Style::new().fg(Color::Gray)
                        };

                        list_items.push(ListItem::new(Line::raw(text)).style(style));
                    }

                    if item_idx == selected {
                        selected_list_pos = Some(list_pos);
                    }
                }
            }
        }

        let list = List::new(list_items)
            .highlight_style(
                Style::new()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ")
            .highlight_spacing(HighlightSpacing::Always)
            .scroll_padding(2);

        let mut list_state = ListState::default().with_selected(selected_list_pos);
        frame.render_stateful_widget(list, chunks[1], &mut list_state);

        // --- Footer ---
        let footer_chunks = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(chunks[2]);

        if let Some((msg, is_success)) = status_message {
            let color = if *is_success { Color::Green } else { Color::Red };
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

/// Format an option value for display
fn format_value(option: &CfrOption, value: &CfrValue) -> String {
    match (&option.option_type, value) {
        (CfrOptionType::Bool { .. }, CfrValue::Bool(b)) => {
            if *b {
                "[Enabled]".into()
            } else {
                "[Disabled]".into()
            }
        }
        (CfrOptionType::Enum { choices, .. }, CfrValue::Number(n)) => {
            if let Some(choice) = choices.iter().find(|c| c.value == *n) {
                format!("[{}]", choice.ui_name)
            } else {
                format!("[{}]", n)
            }
        }
        (CfrOptionType::Number { hex_display, .. }, CfrValue::Number(n)) => {
            if *hex_display {
                format!("[0x{:X}]", n)
            } else {
                format!("[{}]", n)
            }
        }
        (CfrOptionType::Varchar { .. }, CfrValue::Varchar(s)) => {
            if s.len() > 20 {
                format!("[{}...]", &s[..20])
            } else {
                format!("[{}]", s)
            }
        }
        _ => "[-]".into(),
    }
}

/// Show a help screen for an option
fn show_help_screen(
    terminal: &mut Terminal<crate::tui::DualBackend>,
    option: &CfrOption,
) {
    let name = option.ui_name.clone();
    let helptext = if !option.ui_helptext.is_empty() {
        option.ui_helptext.clone()
    } else {
        "No help available for this option.".into()
    };

    let _ = terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .split(area);

        let header = Paragraph::new(
            Line::from(Span::styled(
                name.as_str(),
                Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ))
            .alignment(Alignment::Center),
        )
        .block(
            Block::new()
                .borders(Borders::TOP | Borders::BOTTOM)
                .border_style(Style::new().fg(Color::Cyan)),
        );
        frame.render_widget(header, chunks[0]);

        let body = Paragraph::new(format!("    {}", helptext));
        frame.render_widget(body, chunks[2]);

        let footer = Paragraph::new(
            Line::from("Press any key to continue...")
                .alignment(Alignment::Center)
                .style(Style::new().fg(Color::DarkGray)),
        );
        frame.render_widget(footer, chunks[3]);
    });

    loop {
        if menu_common::read_key().is_some() {
            break;
        }
        delay_ms(10);
    }
}

/// Show a simple confirmation dialog. Returns true if user pressed Y.
fn confirm_dialog(
    terminal: &mut Terminal<crate::tui::DualBackend>,
    message: &str,
    help: &str,
) -> bool {
    let msg = String::from(message);
    let hlp = String::from(help);
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
                Style::new()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ))
            .alignment(Alignment::Center),
        );
        frame.render_widget(prompt, chunks[1]);

        let hint = Paragraph::new(
            Line::from(hlp.as_str())
                .alignment(Alignment::Center)
                .style(Style::new().fg(Color::Gray)),
        );
        frame.render_widget(hint, chunks[3]);
    });

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

/// Show a simple message screen (for errors / "not available" messages)
fn show_message_screen(title: &str, body: &str) {
    let fb_info = coreboot::get_framebuffer();
    let backend = crate::tui::DualBackend::new(fb_info.as_ref());
    let mut terminal = match Terminal::new(backend) {
        Ok(t) => t,
        Err(_) => return,
    };
    let _ = terminal.clear();

    let title_s = String::from(title);
    let body_s = String::from(body);
    let _ = terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::vertical([
            Constraint::Percentage(40),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(area);

        let t = Paragraph::new(
            Line::from(Span::styled(
                title_s.as_str(),
                Style::new()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ))
            .alignment(Alignment::Center),
        );
        frame.render_widget(t, chunks[1]);

        if !body_s.is_empty() {
            let b = Paragraph::new(
                Line::from(body_s.as_str())
                    .alignment(Alignment::Center)
                    .style(Style::new().fg(Color::Gray)),
            );
            frame.render_widget(b, chunks[3]);
        }

        let footer = Paragraph::new(
            Line::from("Press any key to continue...")
                .alignment(Alignment::Center)
                .style(Style::new().fg(Color::DarkGray)),
        );
        frame.render_widget(footer, chunks[4]);
    });

    loop {
        if menu_common::read_key().is_some() {
            break;
        }
        delay_ms(10);
    }
}

// ============================================================================
// Business logic (unchanged)
// ============================================================================

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
/// uncommitted edits) and falling back to persistent storage.
fn find_live_numeric_value(cfr: &CfrInfo, items: &[MenuItem], object_id: u64) -> Option<u32> {
    if object_id == 0 {
        return None;
    }
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
fn is_item_visible(cfr: &CfrInfo, items: &[MenuItem], item: &MenuItem) -> bool {
    match item {
        MenuItem::FormHeader { name } => cfr
            .forms
            .iter()
            .find(|f| f.ui_name == *name)
            .is_none_or(|form| {
                is_dep_met_live(cfr, items, form.dependency_id, &form.dep_values)
            }),
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
        MenuItem::Comment { .. } | MenuItem::SubformHeader { .. } => true,
    }
}

fn get_option(cfr: &CfrInfo, form_idx: usize, option_idx: usize) -> Option<&CfrOption> {
    cfr.forms
        .get(form_idx)
        .and_then(|f| f.options.get(option_idx))
}

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

/// Collect the indices of items that are currently visible (dependency-aware).
fn visible_indices(cfr: &CfrInfo, items: &[MenuItem]) -> Vec<usize> {
    items
        .iter()
        .enumerate()
        .filter(|(_, item)| is_item_visible(cfr, items, item))
        .map(|(i, _)| i)
        .collect()
}

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
                *n = *min;
            }
            true
        }
        _ => false,
    }
}

fn increment_option(cfr: &CfrInfo, items: &mut [MenuItem], index: usize) -> bool {
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
                *n = *max;
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

fn decrement_option(cfr: &CfrInfo, items: &mut [MenuItem], index: usize) -> bool {
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
                *n = *min;
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

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
