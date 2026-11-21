use super::geometry::{fw_layout, row_rect, section_rect, sections_area};
use super::operations::{
    Destination, apply_graphical_edit, clear_row_notice, destination, discard_graphical,
    edit_graphical_item, help_graphical_item, leave_graphical, restore_graphical_default,
    save_graphical_changes,
};
use super::paint::{draw_graphical_menu, observe_settings, paint_option_row, paint_section_row};
use super::state::{
    FwAction, actions, first_selectable, graphical_page_selection,
    keep_graphical_selection_visible, section_of, section_rows, visible_sections,
};
use super::{CfrInfo, FramebufferInfo, GraphicalState, ui};
use crate::KeyPress;
use crate::screens::controls::{self, FocusEvent, Group};
use crate::screens::layout::Metrics;
use crate::screens::{NavItem, dialog};
use crate::settings::{
    MenuItem, SettingEdit, StepDirection, build_menu_items, find_first_selectable, is_selectable,
};

/// Graphical platform-hook entry point, preserving the requested destination.
pub async fn show_graphical_firmware_settings(
    model: &CfrInfo<'_>,
    fb: &FramebufferInfo,
) -> ui::ScreenNav {
    show_cfr_menu_graphical(model, fb).await
}

/// Character accelerators and paging belong to the content group. Save (W,
/// F10) is page-wide and never dispatched inside an editor.
pub(super) fn graphical_key_allowed(group: Group, key: KeyPress) -> bool {
    group == Group::Content
        || (group == Group::Sections && matches!(key, KeyPress::Right | KeyPress::Char('j' | 'k')))
        || !matches!(
            key,
            KeyPress::Home
                | KeyPress::End
                | KeyPress::PageUp
                | KeyPress::PageDown
                | KeyPress::Left
                | KeyPress::Right
                | KeyPress::Char('j' | 'k' | '+' | '=' | '-' | 'd' | 'D')
        )
}

fn hovered_item(
    cfr: &CfrInfo<'_>,
    items: &[MenuItem],
    state: &GraphicalState,
    fb: &FramebufferInfo,
) -> Option<usize> {
    let (mx, my) = fb.position();
    let l = fw_layout(fb);
    let rows = section_rows(cfr, items, state.section);
    (state.scroll_offset..(state.scroll_offset + l.slots).min(rows.len()))
        .find(|pos| {
            row_rect(&l, fb, *pos, state.scroll_offset, rows.len())
                .is_some_and(|r| dialog::contains(r, mx, my))
        })
        .map(|pos| rows[pos])
        .filter(|i| is_selectable(&items[*i]))
}

/// Same geometry as painting: only rows inside the Sections viewport hit.
pub(super) fn section_hit(
    cfr: &CfrInfo<'_>,
    items: &[MenuItem],
    state: &GraphicalState,
    fb: &FramebufferInfo,
    x: i32,
    y: i32,
) -> Option<usize> {
    let l = fw_layout(fb);
    let sections = visible_sections(cfr, items);
    (state.section_offset..(state.section_offset + l.sec_slots).min(sections.len()))
        .find(|pos| {
            section_rect(fb, &l, state, *pos, sections.len())
                .is_some_and(|r| dialog::contains(r, x, y))
        })
        .map(|pos| sections[pos])
}

pub(super) fn open_section(
    cfr: &CfrInfo<'_>,
    items: &[MenuItem],
    state: &mut GraphicalState,
    fb: &FramebufferInfo,
    header: usize,
) {
    if state.section != header {
        state.section = header;
        state.scroll_offset = 0;
        let rows = section_rows(cfr, items, header);
        state.selected = first_selectable(items, &rows).unwrap_or(header);
    }
    let sections = visible_sections(cfr, items);
    if let Some(pos) = sections.iter().position(|h| *h == header) {
        controls::ensure_visible(
            &mut state.section_offset,
            pos,
            sections.len(),
            fw_layout(fb).sec_slots,
        );
    }
}

pub async fn show_cfr_menu_graphical(
    cfr_info: &CfrInfo<'_>,
    fb: &FramebufferInfo,
) -> ui::ScreenNav {
    let session = crate::settings::Session::new(cfr_info);
    let cfr_info: &CfrInfo<'_> = &session;
    let mut items = build_menu_items(cfr_info);
    if items.is_empty() {
        return show_no_options_graphical(fb).await;
    }
    let mut cursor = crate::cursor::CursorRenderer::new();
    let first = find_first_selectable(cfr_info, &items, 0);
    let mut state = GraphicalState::new(first);
    state.section = section_of(&items, first);
    let mut hover = ui::Hover::default();
    let mut clickable = draw_graphical_menu(cfr_info, &items, &state, fb);

    loop {
        ui::poll_and_render_cursor(fb, &mut cursor);
        ui::track_hover(
            fb,
            &mut cursor,
            &mut hover,
            Some((NavItem::Firmware, &state.focus)),
        );
        let (mx, my) = fb.position();
        let section = section_hit(cfr_info, &items, &state, fb, mx, my);
        if section != state.hovered_section {
            let previous = core::mem::replace(&mut state.hovered_section, section);
            cursor.while_hidden(fb, || {
                let l = fw_layout(fb);
                let sections = visible_sections(cfr_info, &items);
                for header in previous.into_iter().chain(section) {
                    if let Some(pos) = sections.iter().position(|h| *h == header) {
                        paint_section_row(fb, &l, cfr_info, &items, &state, pos, header);
                    }
                }
            });
        }
        let hovered = hovered_item(cfr_info, &items, &state, fb);
        if hovered != state.hovered {
            let previous = core::mem::replace(&mut state.hovered, hovered);
            cursor.while_hidden(fb, || {
                let l = fw_layout(fb);
                let rows = section_rows(cfr_info, &items, state.section);
                for i in previous.into_iter().chain(hovered) {
                    if let Some(pos) = rows.iter().position(|r| *r == i) {
                        paint_option_row(fb, &l, cfr_info, &items, &state, &rows, pos);
                    }
                }
            });
        }

        if let Some(mut key) = fb.key() {
            let selected_before = state.selected;
            let mut viewport_only = matches!(key, KeyPress::MouseScroll(_));
            let acts = actions(cfr_info, &items, &state, fb);
            let mut action = None;
            match ui::chrome_key(fb, key, &mut state.focus, NavItem::Firmware, acts.len()) {
                Some(FocusEvent::Navigate(i)) => {
                    cursor.hide(fb);
                    let nav = ui::nav_at(i);
                    if leave_graphical(cfr_info, &mut items, &mut state, fb, destination(nav)).await
                    {
                        observe_settings(cfr_info, &items, &state, fb);
                        return ui::ScreenNav::Nav(nav);
                    }
                    clickable = cursor
                        .while_hidden(fb, || draw_graphical_menu(cfr_info, &items, &state, fb));
                    hover.reset();
                    continue;
                }
                Some(FocusEvent::Moved) => {
                    if state.focus.group == Group::Content {
                        keep_graphical_selection_visible(cfr_info, &items, &mut state, fb);
                    }
                    clear_row_notice(&mut state, selected_before);
                    clickable = cursor
                        .while_hidden(fb, || draw_graphical_menu(cfr_info, &items, &state, fb));
                    hover.reset();
                    continue;
                }
                Some(FocusEvent::Action(i)) => action = acts.get(i).copied(),
                None => {}
            }
            if !graphical_key_allowed(state.focus.group, key) {
                continue;
            }
            if state.focus.group == Group::Sections {
                let sections = visible_sections(cfr_info, &items);
                let pos = sections
                    .iter()
                    .position(|h| *h == state.section)
                    .unwrap_or(0);
                match key {
                    KeyPress::Up | KeyPress::Char('k') => {
                        let header = sections[pos.saturating_sub(1)];
                        open_section(cfr_info, &items, &mut state, fb, header);
                        key = KeyPress::Char('\0');
                    }
                    KeyPress::Down | KeyPress::Char('j') => {
                        let header = sections[(pos + 1).min(sections.len() - 1)];
                        open_section(cfr_info, &items, &mut state, fb, header);
                        key = KeyPress::Char('\0');
                    }
                    KeyPress::Enter | KeyPress::Char(' ') | KeyPress::Right => {
                        state.focus.group = Group::Content;
                        key = KeyPress::Char('\0');
                    }
                    _ => {}
                }
            }
            let mut activated = action;
            if let Some(action) = action {
                cursor.hide(fb);
                match action {
                    FwAction::Edit => {
                        edit_graphical_item(cfr_info, &mut items, &mut state, fb).await
                    }
                    FwAction::Default => {
                        restore_graphical_default(cfr_info, &mut items, &mut state)
                    }
                    FwAction::Save => save_graphical_changes(cfr_info, &mut items, &mut state),
                    FwAction::Discard => {
                        discard_graphical(cfr_info, &mut items, &mut state, fb).await
                    }
                    FwAction::Restart => {
                        let backdrop = || {
                            draw_graphical_menu(cfr_info, &items, &state, fb);
                        };
                        ui::confirm_reset(fb, &backdrop).await;
                    }
                }
                key = KeyPress::Char('\0');
            }
            let content = state.focus.group == Group::Content;
            match key {
                KeyPress::Up | KeyPress::Down | KeyPress::Char('j' | 'k') if content => {
                    let rows = section_rows(cfr_info, &items, state.section);
                    let k = if matches!(key, KeyPress::Up | KeyPress::Char('k')) {
                        KeyPress::Up
                    } else {
                        KeyPress::Down
                    };
                    state.selected = graphical_page_selection(&items, &rows, state.selected, k, 1);
                }
                key @ (KeyPress::Home | KeyPress::End | KeyPress::PageUp | KeyPress::PageDown)
                    if content =>
                {
                    let rows = section_rows(cfr_info, &items, state.section);
                    state.selected = graphical_page_selection(
                        &items,
                        &rows,
                        state.selected,
                        key,
                        fw_layout(fb).slots,
                    );
                }
                KeyPress::Enter | KeyPress::Char(' ') if content => {
                    cursor.hide(fb);
                    edit_graphical_item(cfr_info, &mut items, &mut state, fb).await;
                }
                KeyPress::Left | KeyPress::Right | KeyPress::Char('+' | '=' | '-') if content => {
                    let direction = if matches!(key, KeyPress::Left | KeyPress::Char('-')) {
                        StepDirection::Backward
                    } else {
                        StepDirection::Forward
                    };
                    if apply_graphical_edit(
                        cfr_info,
                        &mut items,
                        &mut state,
                        SettingEdit::Step(direction),
                    )
                    .is_none()
                    {
                        state.status_message = Some(("This option cannot be changed.", false));
                    }
                }
                KeyPress::F10 | KeyPress::Char('w' | 'W') => {
                    save_graphical_changes(cfr_info, &mut items, &mut state);
                }
                #[cfg(feature = "secure-boot")]
                KeyPress::Char('s' | 'S') => {
                    cursor.hide(fb);
                    if leave_graphical(
                        cfr_info,
                        &mut items,
                        &mut state,
                        fb,
                        destination(NavItem::Security),
                    )
                    .await
                    {
                        observe_settings(cfr_info, &items, &state, fb);
                        return ui::ScreenNav::Nav(NavItem::Security);
                    }
                }
                KeyPress::Char('f' | 'F') => {}
                KeyPress::Char('r' | 'R') => {
                    cursor.hide(fb);
                    if leave_graphical(cfr_info, &mut items, &mut state, fb, Destination::Restart)
                        .await
                    {
                        let backdrop = || {
                            draw_graphical_menu(cfr_info, &items, &state, fb);
                        };
                        ui::confirm_reset(fb, &backdrop).await;
                    }
                }
                KeyPress::Escape | KeyPress::Char('b' | 'B' | 'q' | 'Q') => {
                    cursor.hide(fb);
                    if leave_graphical(
                        cfr_info,
                        &mut items,
                        &mut state,
                        fb,
                        destination(NavItem::Boot),
                    )
                    .await
                    {
                        observe_settings(cfr_info, &items, &state, fb);
                        return ui::ScreenNav::Back;
                    }
                }
                KeyPress::Char('?') => {
                    cursor.hide(fb);
                    help_graphical_item(cfr_info, &mut items, &mut state, fb).await;
                }
                KeyPress::Char('d' | 'D') if content => {
                    restore_graphical_default(cfr_info, &mut items, &mut state);
                }
                KeyPress::MouseClick { x, y } => {
                    cursor.hide(fb);
                    let (x, y) = (x as i32, y as i32);
                    let l = fw_layout(fb);
                    let rows = section_rows(cfr_info, &items, state.section);
                    let area = (
                        l.options.0,
                        l.rows_y,
                        l.options.2,
                        l.slots as u32 * Metrics::for_fb(fb).row,
                    );
                    if controls::scroll_track(
                        &mut state.scroll_offset,
                        area,
                        (x, y),
                        rows.len(),
                        l.slots,
                    ) {
                        viewport_only = true;
                    } else if let Some((action, _)) = clickable
                        .iter()
                        .find(|(_, r)| dialog::contains(*r, x, y))
                        .copied()
                    {
                        activated = Some(action);
                        let acts = actions(cfr_info, &items, &state, fb);
                        if let Some(i) = acts.iter().position(|a| *a == action) {
                            state.focus.group = Group::Actions;
                            state.focus.action = i;
                        }
                        match action {
                            FwAction::Edit => {
                                edit_graphical_item(cfr_info, &mut items, &mut state, fb).await
                            }
                            FwAction::Default => {
                                restore_graphical_default(cfr_info, &mut items, &mut state)
                            }
                            FwAction::Save => {
                                save_graphical_changes(cfr_info, &mut items, &mut state)
                            }
                            FwAction::Discard => {
                                discard_graphical(cfr_info, &mut items, &mut state, fb).await
                            }
                            FwAction::Restart => {
                                let backdrop = || {
                                    draw_graphical_menu(cfr_info, &items, &state, fb);
                                };
                                ui::confirm_reset(fb, &backdrop).await;
                            }
                        }
                    } else if controls::scroll_track(
                        &mut state.section_offset,
                        sections_area(fb, &l),
                        (x, y),
                        visible_sections(cfr_info, &items).len(),
                        l.sec_slots,
                    ) {
                        viewport_only = true;
                    } else if let Some(header) = section_hit(cfr_info, &items, &state, fb, x, y) {
                        open_section(cfr_info, &items, &mut state, fb, header);
                        state.focus.group = Group::Sections;
                    } else if let Some(item_idx) = hovered_item(cfr_info, &items, &state, fb) {
                        state.selected = item_idx;
                        state.focus.group = Group::Content;
                    }
                }
                KeyPress::MouseScroll(dz) => {
                    let rows = section_rows(cfr_info, &items, state.section);
                    controls::scroll(
                        &mut state.scroll_offset,
                        dz,
                        rows.len(),
                        fw_layout(fb).slots,
                    );
                }
                _ => {}
            }
            // Dependencies may hide the section or the selected option.
            let sections = visible_sections(cfr_info, &items);
            if !sections.contains(&state.section)
                && let Some(first) = sections.first()
            {
                open_section(cfr_info, &items, &mut state, fb, *first);
            }
            if !viewport_only {
                keep_graphical_selection_visible(cfr_info, &items, &mut state, fb);
            }
            clear_row_notice(&mut state, selected_before);
            let acts = actions(cfr_info, &items, &state, fb);
            // An action that replaced itself (Save -> Restart now) must not
            // hand its focus to a different, consequential button.
            if state.focus.group == Group::Actions
                && (acts.is_empty()
                    || activated.is_some_and(|a| acts.get(state.focus.action) != Some(&a)))
            {
                state.focus.group = Group::Content;
            }
            state.focus.action = state.focus.action.min(acts.len().saturating_sub(1));
            clickable =
                cursor.while_hidden(fb, || draw_graphical_menu(cfr_info, &items, &state, fb));
            hover.reset();
        }
        if fb.reset_requested() {
            return ui::ScreenNav::Reset;
        }
        fb.wait_for_frame().await;
    }
}

async fn show_no_options_graphical(fb: &FramebufferInfo) -> ui::ScreenNav {
    ui::empty_screen(
        fb,
        NavItem::Firmware,
        "No settings available",
        "This platform did not supply configurable settings.",
    )
    .await
}
