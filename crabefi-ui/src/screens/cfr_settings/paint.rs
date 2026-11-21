use super::geometry::{FwLayout, fw_layout, row_rect, section_rect, sections_area};
use super::state::{
    FwAction, actions, edit_label, is_changed, section_name, section_rows, strip_actions,
    visible_sections,
};
use super::values::{
    EXTERNAL_BOOT_HELP, changed_count, changed_items, full_value, row_parts, truncate_for_width,
};
use super::{CfrInfo, FramebufferInfo, GraphicalState, Rect, ui};
use crate::cfr::{self, CfrOptionType, CfrValue};
use crate::screens::controls::{self, ButtonKind, Control, Group, Role};
use crate::screens::kit::{self, Fact, StripButton, Tone};
use crate::screens::layout::Metrics;
use crate::screens::{NavItem, render, theme};
use crate::settings::{
    FirmwareObservation, MenuItem, external_boot_choices, external_boot_name, get_option,
    has_changes, is_selectable,
};
use crate::{Screen, UiState};
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn paint_section_row(
    fb: &FramebufferInfo,
    l: &FwLayout,
    cfr: &CfrInfo<'_>,
    items: &[MenuItem],
    state: &GraphicalState,
    pos: usize,
    header: usize,
) {
    let Some(rect) = section_rect(fb, l, state, pos, visible_sections(cfr, items).len()) else {
        return;
    };
    let m = Metrics::for_fb(fb);
    let rows = section_rows(cfr, items, header);
    let count = rows.iter().filter(|i| is_selectable(&items[**i])).count();
    let dirty = rows.iter().any(|i| is_changed(&items[*i]));
    let mut c = Control::new(header as u64, Role::Option, section_name(items, header));
    c.selected = header == state.section;
    c.focused = c.selected && state.focus.group == Group::Sections;
    let bg = controls::row(fb, rect, &c, state.hovered_section == Some(header));
    let ty = rect.1 + ((m.row - render::font_height(m.body)) / 2) as i32;
    if dirty {
        render::draw_text_bold(fb, rect.0 + 10, ty, "*", m.body, theme::WARN, Some(bg));
    }
    let count_text = alloc::format!("{count}");
    let cw = render::text_width(&count_text, m.small);
    render::draw_text(
        fb,
        rect.0 + rect.2 as i32 - cw as i32 - 10,
        ty + 2,
        &count_text,
        m.small,
        theme::INK3,
        Some(bg),
    );
    let nx = rect.0 + 10 + render::font_width(m.body) as i32 + 6;
    render::draw_text_weight(
        fb,
        nx,
        ty,
        &render::ellipsize(
            c.label,
            (rect.0 + rect.2 as i32 - nx - cw as i32 - 18).max(0) as u32,
            m.body,
        ),
        m.body,
        c.selected,
        theme::INK,
        Some(bg),
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) fn draw_setting_row(
    fb: &FramebufferInfo,
    l: &FwLayout,
    cfr: &CfrInfo<'_>,
    item: &MenuItem,
    rect: Rect,
    selected: bool,
    focused: bool,
    hovered: bool,
) {
    let m = Metrics::for_fb(fb);
    let ty = rect.1 + ((rect.3 - render::font_height(m.body)) / 2) as i32;
    match item {
        MenuItem::SubformHeader { name } => {
            render::fill_rect(fb, rect.0, rect.1, rect.2, rect.3, theme::SHEET);
            render::draw_text_bold(
                fb,
                rect.0 + 4,
                rect.1 + rect.3 as i32 - m.small_line as i32 - 4,
                &truncate_for_width(name, rect.2 - 8, m.small),
                m.small,
                theme::INK3,
                Some(theme::SHEET),
            );
            render::fill_rect(
                fb,
                rect.0,
                rect.1 + rect.3 as i32 - 1,
                rect.2,
                1,
                theme::RULE,
            );
            return;
        }
        MenuItem::Comment { text } => {
            render::fill_rect(fb, rect.0, rect.1, rect.2, rect.3, theme::SHEET);
            render::draw_text(
                fb,
                rect.0 + l.marker_w as i32,
                ty + 2,
                &truncate_for_width(text, rect.2 - l.marker_w - 8, m.small),
                m.small,
                theme::INK2,
                Some(theme::SHEET),
            );
            return;
        }
        MenuItem::FormHeader { .. } => return,
        _ => {}
    }
    let Some((label, value, saved, editable, tag)) = row_parts(cfr, item) else {
        return;
    };
    let changed = is_changed(item);
    let mut c = Control::new(0, Role::Option, &label);
    c.selected = selected;
    c.focused = focused;
    c.changed = changed;
    c.read_only = !editable;
    let bg = controls::row(fb, rect, &c, hovered);
    if changed {
        render::draw_text_bold(fb, rect.0 + 10, ty, "*", m.body, theme::WARN, Some(bg));
    }
    let lx = rect.0 + l.marker_w as i32;
    let value_x = lx + l.label_w as i32 + 10;
    let label_text = truncate_for_width(&label, l.label_w.saturating_sub(4), m.body);
    let lw = render::draw_text_weight(
        fb,
        lx,
        ty,
        &label_text,
        m.body,
        selected,
        if editable { theme::INK } else { theme::INK3 },
        Some(bg),
    );
    // Dot leaders guide the eye from label to value; at least three or none.
    let fw = render::font_width(m.body) as i32;
    let dots = ((value_x - 10 - (lx + lw as i32 + 10)) / fw).max(0) as usize;
    if dots >= 3 {
        let leader: String = core::iter::repeat_n('.', dots).collect();
        render::draw_text(
            fb,
            lx + lw as i32 + 10,
            ty,
            &leader,
            m.body,
            theme::RULE_STRONG,
            Some(bg),
        );
    }
    let right = rect.0 + rect.2 as i32 - 10;
    let mut x = value_x;
    let arrows = selected && editable;
    if arrows {
        x += render::draw_text(fb, x, ty, "< ", m.body, theme::INK3, Some(bg)) as i32;
    }
    let room = (right - x - if arrows { fw * 2 } else { 0 }).max(0) as u32;
    let shown = truncate_for_width(&value, room, m.body);
    x += render::draw_text_weight(
        fb,
        x,
        ty,
        &shown,
        m.body,
        changed,
        if changed {
            theme::WARN
        } else if editable {
            theme::INK
        } else {
            theme::INK3
        },
        Some(bg),
    ) as i32;
    if arrows {
        x += render::draw_text(fb, x, ty, " >", m.body, theme::INK3, Some(bg)) as i32;
    }
    // Read-only and unavailable tags follow the value and yield to it.
    if let Some(tag) = tag {
        let tw = render::text_width(tag, m.small) + 10;
        if x + 10 + tw as i32 <= right {
            let th = render::font_height(m.small) + 2;
            let tyy = rect.1 + ((rect.3 - th) / 2) as i32;
            render::draw_border(fb, x + 10, tyy, tw, th, theme::RULE_STRONG);
            render::draw_text(fb, x + 15, tyy + 1, tag, m.small, theme::INK2, Some(bg));
        }
    }
    if changed && m.large {
        let was = alloc::format!("was {saved}");
        let room = (right - x - 16).max(0) as u32;
        if room > render::text_width("was ...", m.small) {
            render::draw_text(
                fb,
                x + 16,
                ty + 2,
                &truncate_for_width(&was, room, m.small),
                m.small,
                theme::INK3,
                Some(bg),
            );
        }
    }
}

pub(super) fn paint_option_row(
    fb: &FramebufferInfo,
    l: &FwLayout,
    cfr: &CfrInfo<'_>,
    items: &[MenuItem],
    state: &GraphicalState,
    rows: &[usize],
    pos: usize,
) {
    let Some(rect) = row_rect(l, fb, pos, state.scroll_offset, rows.len()) else {
        return;
    };
    let index = rows[pos];
    draw_setting_row(
        fb,
        l,
        cfr,
        &items[index],
        rect,
        index == state.selected,
        index == state.selected && state.focus.group == Group::Content,
        state.hovered == Some(index),
    );
    let m = Metrics::for_fb(fb);
    if let Some(sel) = rows.iter().position(|i| *i == state.selected) {
        controls::viewport_focus(
            fb,
            (l.options.0, l.rows_y, l.options.2, l.slots as u32 * m.row),
            state.focus.group == Group::Content,
            sel,
            state.scroll_offset,
            l.slots,
        );
    }
}

/// Pick the strip headline and detail.
///
/// A failed save stays visible until the draft changes so its Try again
/// action remains discoverable; a later status message leads and the failure
/// becomes the detail. After a successful save, a later status message
/// replaces the summary.
pub(super) fn strip_notice(
    save_result: Option<(usize, usize)>,
    status_message: Option<(&'static str, bool)>,
    changed: usize,
    names_text: String,
) -> (Tone, String, String) {
    match (save_result, status_message) {
        (Some((saved, failed)), message) if failed > 0 => {
            let failure = if saved == 0 && failed == 1 {
                String::from("Could not save the change.")
            } else if saved == 0 {
                alloc::format!("Could not save {failed} changes.")
            } else {
                alloc::format!("Could not save {failed} of {} changes.", saved + failed)
            };
            // The strip is one line and drops the detail when space is short;
            // lead with the newer message. Try again still marks the failure.
            match message {
                Some((text, _)) => (Tone::Bad, String::from(text), failure),
                None => (
                    Tone::Bad,
                    failure,
                    String::from("Your edits are kept (starred)."),
                ),
            }
        }
        (Some((saved, _)), None) => (
            Tone::Ok,
            alloc::format!(
                "Saved {saved} {}.",
                if saved == 1 { "change" } else { "changes" }
            ),
            String::from("They apply after restart."),
        ),
        (_, Some((message, ok))) => (
            if ok {
                if changed > 0 { Tone::Warn } else { Tone::Ok }
            } else {
                Tone::Bad
            },
            String::from(message),
            if changed > 0 {
                alloc::format!("{changed} unsaved: {names_text}")
            } else {
                String::new()
            },
        ),
        (None, None) if changed > 0 => (
            Tone::Warn,
            alloc::format!(
                "{changed} unsaved {}",
                if changed == 1 { "change" } else { "changes" }
            ),
            names_text,
        ),
        _ => (
            Tone::Neutral,
            String::from("No unsaved changes."),
            String::from("Saved settings apply after restart."),
        ),
    }
}

fn paint_strip(
    fb: &FramebufferInfo,
    l: &FwLayout,
    cfr: &CfrInfo<'_>,
    items: &[MenuItem],
    state: &GraphicalState,
    focused: Option<FwAction>,
) -> Vec<(FwAction, Rect)> {
    let changed = changed_count(items);
    let names: Vec<String> = changed_items(cfr, items)
        .into_iter()
        .map(|(n, _, _)| n)
        .collect();
    let mut names_text = names.join(", ");
    if !names_text.is_empty() {
        names_text.push('.');
    }
    let (tone, headline, detail) =
        strip_notice(state.save_result, state.status_message, changed, names_text);
    let acts = strip_actions(items, state);
    let buttons: Vec<StripButton<'_>> = acts
        .iter()
        .map(|a| match a {
            FwAction::Save => StripButton {
                label: if state.save_result.is_some_and(|(_, f)| f > 0) {
                    "Try again"
                } else {
                    "Save changes"
                },
                key: Some("F10"),
                kind: ButtonKind::Primary,
                focused: focused == Some(*a),
            },
            FwAction::Discard => StripButton {
                label: "Discard...",
                key: None,
                kind: ButtonKind::Neutral,
                focused: focused == Some(*a),
            },
            _ => StripButton {
                label: "Restart now",
                key: Some("R"),
                kind: ButtonKind::Primary,
                focused: focused == Some(*a),
            },
        })
        .collect();
    let rects = kit::strip(fb, l.strip, tone, &headline, &detail, &buttons, None);
    acts.into_iter().zip(rects).collect()
}

/// Title, description, facts, read-only status and when changes apply.
type HelpContent<'a> = (
    String,
    String,
    Vec<(&'a str, String)>,
    Option<String>,
    &'static str,
);

fn paint_help(
    fb: &FramebufferInfo,
    l: &FwLayout,
    cfr: &CfrInfo<'_>,
    items: &[MenuItem],
    state: &GraphicalState,
    focused: Option<FwAction>,
) -> Vec<(FwAction, Rect)> {
    let Some(rect) = l.help else {
        return Vec::new();
    };
    let m = Metrics::for_fb(fb);
    kit::side(fb, rect);
    let (hx, hy, hw, hh) = rect;
    let x = hx + m.pad as i32;
    let w = hw - m.pad * 2;
    let max_y = hy + hh as i32 - m.pad as i32;
    let Some(item) = items.get(state.selected) else {
        return Vec::new();
    };
    let changed = is_changed(item);
    let (title, help, facts_owned, status, applies): HelpContent<'_> = match item {
        MenuItem::Option {
            form_idx,
            option_idx,
            current_value,
            original_value,
        } => {
            let Some(option) = get_option(cfr, *form_idx, *option_idx) else {
                return Vec::new();
            };
            let mut facts = Vec::new();
            if changed {
                facts.push(("Unsaved", full_value(option, current_value)));
            }
            facts.push(("Saved", full_value(option, original_value)));
            facts.push((
                "Default",
                full_value(option, &CfrValue::from_option_type(&option.option_type)),
            ));
            match &option.option_type {
                CfrOptionType::Enum { choices, .. } => {
                    let list: Vec<&str> = choices.iter().map(|c| c.ui_name.as_str()).collect();
                    facts.push(("Choices", list.join(", ")));
                }
                CfrOptionType::Number { min, max, step, .. } => {
                    facts.push(("Range", alloc::format!("{min} to {max}, step {step}")));
                }
                CfrOptionType::Varchar { .. } => {
                    facts.push(("Length", String::from("Up to 255 characters")));
                }
                _ => {}
            }
            let status = if option.flags & cfr::CFR_OPTFLAG_INACTIVE != 0 {
                Some(String::from(
                    "Unavailable: the platform reports this option as inactive.",
                ))
            } else if !option.is_editable() {
                Some(String::from(
                    "Read-only: this value is supplied by firmware.",
                ))
            } else {
                None
            };
            (
                option.ui_name.clone(),
                if option.ui_helptext.is_empty() {
                    String::from("No description supplied.")
                } else {
                    option.ui_helptext.clone()
                },
                facts,
                status,
                "After restart",
            )
        }
        MenuItem::CrabLogLevel {
            current_level,
            original_level,
        } => {
            let mut facts = Vec::new();
            if changed {
                facts.push((
                    "Unsaved",
                    String::from(crate::cfr::level_name(*current_level)),
                ));
            }
            facts.push((
                "Saved",
                String::from(crate::cfr::level_name(*original_level)),
            ));
            facts.push((
                "Default",
                String::from(crate::cfr::level_name(crate::cfr::DEFAULT_LEVEL)),
            ));
            let names: Vec<&str> = crate::cfr::LEVEL_CHOICES
                .iter()
                .map(|l| crate::cfr::level_name(*l))
                .collect();
            facts.push(("Choices", names.join(", ")));
            (
                String::from("CrabEFI log level"),
                String::from("How much CrabEFI writes to the serial console."),
                facts,
                None,
                "When saved",
            )
        }
        MenuItem::CrabExternalBoot {
            current,
            original,
            floor,
        } => {
            let mut facts = Vec::new();
            if changed {
                facts.push(("Unsaved", String::from(external_boot_name(*current))));
            }
            facts.push(("Saved", String::from(external_boot_name(*original))));
            facts.push(("Default", String::from(external_boot_name(*floor))));
            let names: Vec<&str> = external_boot_choices(*floor)
                .map(external_boot_name)
                .collect();
            facts.push(("Choices", names.join(", ")));
            (
                String::from("External boot"),
                String::from(EXTERNAL_BOOT_HELP),
                facts,
                None,
                "When saved",
            )
        }
        _ => return Vec::new(),
    };
    let mut y = kit::caption_title(fb, x, hy + m.pad as i32, w, "Option", &title);
    y = kit::prose(fb, x, y, w, &help, m.body, theme::INK, 5) + m.gap as i32 / 2;
    let mut facts: Vec<Fact<'_>> = facts_owned
        .iter()
        .map(|(k, v)| {
            if *k == "Unsaved" {
                Fact::strong(k, v, theme::WARN)
            } else {
                Fact::new(k, v)
            }
        })
        .collect();
    facts.push(Fact::new("Applies", applies));
    y = kit::facts(fb, x, y, w, &facts, max_y) + m.gap as i32 / 2;
    if let Some(status) = status {
        return {
            kit::prose(fb, x, y, w, &status, m.body, theme::WARN, 3);
            Vec::new()
        };
    }
    let buttons = [
        StripButton {
            label: edit_label(cfr, item),
            key: Some("Enter"),
            kind: ButtonKind::Neutral,
            focused: focused == Some(FwAction::Edit),
        },
        StripButton {
            label: "Reset to default",
            key: Some("D"),
            kind: ButtonKind::Neutral,
            focused: focused == Some(FwAction::Default),
        },
    ];
    let needed = 2 * (m.button as i32 + 10);
    let rects = kit::button_stack(fb, x, y.min(max_y - needed), w, &buttons);
    alloc::vec![(FwAction::Edit, rects[0]), (FwAction::Default, rects[1])]
}

/// Report the page state to the host (automation only; firmware ignores it).
pub(super) fn observe_settings(
    cfr: &CfrInfo<'_>,
    items: &[MenuItem],
    state: &GraphicalState,
    fb: &FramebufferInfo,
) {
    fb.observe(UiState {
        screen: Screen::Firmware,
        selected: Some(state.selected),
        scroll_offset: state.scroll_offset,
        countdown: 0,
    });
    fb.observe_firmware(&FirmwareObservation {
        model: cfr,
        items,
        selected: state.selected,
        section: section_name(items, state.section),
        dirty_count: changed_count(items),
        save_result: state.save_result,
        status: state.status_message,
    });
}

/// Paints the page. Returns clickable actions with their rectangles.
pub(super) fn draw_graphical_menu(
    cfr: &CfrInfo<'_>,
    items: &[MenuItem],
    state: &GraphicalState,
    fb: &FramebufferInfo,
) -> Vec<(FwAction, Rect)> {
    observe_settings(cfr, items, state, fb);
    fb.set_firmware_dirty(has_changes(items));
    ui::draw_shell(fb, NavItem::Firmware, &state.focus, None);
    let m = Metrics::for_fb(fb);
    let l = fw_layout(fb);
    let acts = actions(cfr, items, state, fb);
    let focused = (state.focus.group == Group::Actions)
        .then(|| acts.get(state.focus.action).copied())
        .flatten();
    let mut clickable = paint_strip(fb, &l, cfr, items, state, focused);

    // Sections column.
    let (sx, sy, sw, _) = l.sections;
    kit::pane_title(fb, sx, sy, sw, "Sections", "", false);
    let sections = visible_sections(cfr, items);
    for (pos, header) in sections
        .iter()
        .enumerate()
        .skip(state.section_offset)
        .take(l.sec_slots)
    {
        paint_section_row(fb, &l, cfr, items, state, pos, *header);
    }
    controls::scrollbar(
        fb,
        sections_area(fb, &l),
        sections.len(),
        state.section_offset,
        l.sec_slots,
    );

    // Options ledger.
    let rows = section_rows(cfr, items, state.section);
    let count = rows.iter().filter(|i| is_selectable(&items[**i])).count();
    let (ox, oy, ow, _) = l.options;
    let note = alloc::format!("{count} {}", if count == 1 { "option" } else { "options" });
    let title_h = kit::pane_title(
        fb,
        ox,
        oy,
        ow,
        section_name(items, state.section),
        &note,
        true,
    );
    kit::table_head(
        fb,
        ox,
        oy + title_h as i32,
        ow,
        &[
            ("Option", l.marker_w as i32),
            ("Value", (l.marker_w + l.label_w + 10) as i32),
        ],
    );
    for pos in state.scroll_offset..(state.scroll_offset + l.slots).min(rows.len()) {
        paint_option_row(fb, &l, cfr, items, state, &rows, pos);
    }
    if rows.is_empty() {
        render::draw_text(
            fb,
            ox + 10,
            l.rows_y + 8,
            "No options in this section.",
            m.body,
            theme::INK2,
            None,
        );
    }
    let area = (ox, l.rows_y, ow, l.slots as u32 * m.row);
    controls::scrollbar(fb, area, rows.len(), state.scroll_offset, l.slots);

    clickable.extend(paint_help(fb, &l, cfr, items, state, focused));
    let failed = state.save_result.is_some_and(|(_, f)| f > 0);
    let save = if failed { "Retry save" } else { "Save" };
    let keys: Vec<(&str, &str)> = if state.focus.group == Group::Sections {
        alloc::vec![
            ("Up Down", "Section"),
            ("Enter", "Open"),
            ("F10", save),
            ("Tab", "Next pane"),
            ("Esc", "Back to Boot"),
        ]
    } else if m.large {
        alloc::vec![
            ("Up Down", "Select"),
            ("Left Right", "Change"),
            ("Enter", "Edit"),
            ("D", "Default"),
            ("F10", save),
            ("Tab", "Next pane"),
            ("Esc", "Back to Boot"),
        ]
    } else {
        alloc::vec![
            ("Up Down", "Select"),
            ("Left Right", "Change"),
            ("Enter", "Edit"),
            ("F10", save),
            ("Tab", "Pane"),
            ("Esc", "Back to Boot"),
        ]
    };
    kit::draw_keys(fb, &keys, true);
    clickable
}
