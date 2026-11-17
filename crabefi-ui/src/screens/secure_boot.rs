//! Secure Boot page: plain-language state, key-store table, grouped actions
//! with a details pane, and identity-before-consent review of owned bytes.

use super::{
    NavItem, ScreenNav, canvas,
    controls::{self, ButtonKind, Control, Focus, FocusEvent, Group, Role},
    dialog::{self, Block, Choice, Rect},
    kit::{self, Fact, StripButton, Tone},
    layout::Metrics,
    render, theme,
};
use crate::{
    KeyPress, Screen, SecurityAction, Surface as FramebufferInfo, UiState, cursor::CursorRenderer,
};
use alloc::{string::String, vec::Vec};
use core::fmt::Write;

/// Operation ids (stable for the backends).
const TOGGLE: usize = 0;
const DEFAULT_KEYS: usize = 1;
const CUSTOM_KEYS: usize = 2;
const DBX: usize = 3;
const CLEAR: usize = 4;
const SHOW_KEYS: usize = 5;

const ACTION_COUNT: usize = 6;
/// Display order: inspect and enroll, then enforcement, then danger.
const ACTION_ORDER: [usize; ACTION_COUNT] =
    [SHOW_KEYS, CUSTOM_KEYS, DEFAULT_KEYS, DBX, TOGGLE, CLEAR];
const GROUPS: [(&str, usize); 3] = [("Keys", 0), ("Enforcement", 4), ("Danger", 5)];

struct ActionText {
    title: &'static str,
    row: &'static str,
    row_short: &'static str,
    detail: &'static str,
    changes: &'static str,
    button: &'static str,
}

fn action_text(fb: &FramebufferInfo, idx: usize) -> ActionText {
    let on = fb.security_state().requested;
    match idx {
        SHOW_KEYS => ActionText {
            title: "Show enrolled keys",
            row: "Subjects and SHA-256 fingerprints; changes nothing",
            row_short: "Fingerprints; changes nothing",
            detail: "Lists every certificate in PK, KEK and db with its subject, validity and SHA-256 fingerprint, plus the dbx revocation count. Nothing is changed.",
            changes: "None",
            button: "Show enrolled keys",
        },
        CUSTOM_KEYS => ActionText {
            title: "Enroll custom keys from disk",
            row: "Review EFI\\keys\\PK.cer, KEK.cer and db.cer first",
            row_short: "Reviews PK, KEK, db files first",
            detail: "Reads PK.cer, KEK.cer and db.cer from EFI\\keys\\ on a boot disk and shows every certificate with its fingerprint before anything is enrolled. Without KEK.cer, PK is also used as KEK.",
            changes: "Replaces PK, KEK and db",
            button: "Review keys...",
        },
        DEFAULT_KEYS => ActionText {
            title: "Enroll default keys",
            row: "Trust the bundled Microsoft UEFI certificates",
            row_short: "Bundled Microsoft certificates",
            detail: "Installs the bundled Microsoft UEFI certificates as PK, KEK and db. This leaves Setup Mode and may start signature enforcement immediately.",
            changes: "Sets PK, KEK and db",
            button: "Enroll default keys...",
        },
        DBX => ActionText {
            title: "Import dbx update",
            row: "Review a signed .auth revocation file first",
            row_short: "Reviews signed .auth file first",
            detail: "Reads a dbx update from EFI\\keys\\ and shows its signer, timestamp and contents before importing. In User Mode only updates signed by an enrolled KEK or PK are accepted.",
            changes: "Adds to or replaces dbx; mode shown in review",
            button: "Review update...",
        },
        TOGGLE if on => ActionText {
            title: "Disable Secure Boot",
            row: "Unsigned boot software will be allowed to start",
            row_short: "Allows unsigned boot software",
            detail: "Firmware stops checking signatures before starting boot software. Enrolled keys are kept; you can turn Secure Boot back on from this page.",
            changes: "Stops enforcement; keys kept",
            button: "Disable Secure Boot...",
        },
        TOGGLE => ActionText {
            title: "Enable Secure Boot",
            row: "Require signed boot software",
            row_short: "Require signed boot software",
            detail: "Firmware requires boot software to be signed by a key in db once a platform key (PK) is enrolled. In Setup Mode the preference is saved until keys are enrolled.",
            changes: "Starts enforcement",
            button: "Enable Secure Boot...",
        },
        _ => ActionText {
            title: "Clear all keys",
            row: "Removes PK, KEK, db and dbx; enters Setup Mode",
            row_short: "Deletes PK, KEK, db and dbx",
            detail: "Deletes PK, KEK, db and dbx. The firmware returns to Setup Mode and stops checking signatures until new keys are enrolled.",
            changes: "All key stores",
            button: "Clear all keys...",
        },
    }
}

fn unavailable_reason(fb: &FramebufferInfo, idx: usize) -> Option<&'static str> {
    if matches!(idx, DEFAULT_KEYS | CUSTOM_KEYS) && !fb.security_state().setup_mode {
        Some("Unavailable: requires Setup Mode")
    } else if idx == CLEAR && !fb.security_state().has_stored_keys {
        Some("Unavailable: no keys enrolled")
    } else {
        None
    }
}
fn action_color(fb: &FramebufferInfo, idx: usize) -> render::Rgb {
    if unavailable_reason(fb, idx).is_some() {
        theme::INK3
    } else if idx == CLEAR {
        theme::BAD
    } else if idx == TOGGLE && fb.security_state().requested {
        theme::WARN
    } else {
        theme::INK
    }
}

// ─── Layout ─────────────────────────────────────────────────────────────

struct SecLayout {
    card: Option<Rect>,
    /// Card shows a one-line store summary instead of the table.
    card_compact: bool,
    strip: Option<Rect>,
    list: Rect,
    groups: Vec<(&'static str, i32)>,
    rows: [Rect; ACTION_COUNT],
    side: Option<Rect>,
    bar: Option<Rect>,
    short_text: bool,
}

fn sec_layout(fb: &FramebufferInfo, status: bool) -> SecLayout {
    sec_layout_with_metrics(fb, status, Metrics::for_fb(fb))
}

fn sec_layout_with_metrics(fb: &FramebufferInfo, status: bool, m: Metrics) -> SecLayout {
    let (cx, cy, cw, ch) = m.canvas(fb);
    let bottom = cy + ch as i32;
    let side_w = m.side_width(cw);
    // Narrow screens report status beside the action button instead.
    let status = status && side_w.is_some();
    let card_compact = cw < 860;
    let card_full_h = if card_compact {
        render::font_height(m.big) + m.line + m.pad * 2
    } else {
        (render::font_height(m.small) + 8 + 4 * (m.row - 8))
            .max(render::font_height(m.big) + m.line * 3 + 8)
            + m.pad * 2
    };
    let strip_h = m.row + 8;
    let title_h = render::font_height(m.title) + 8;
    let group_h = m.small_line + 10;
    let bar_h = if side_w.is_none() {
        m.button + m.gap
    } else {
        0
    };
    let rows_h = ACTION_COUNT as u32 * m.row;
    let need = |card: bool, groups: bool| {
        (if card { card_full_h + m.gap } else { 0 })
            + (if status { strip_h + m.gap } else { 0 })
            + title_h
            + if groups {
                group_h * GROUPS.len() as u32
            } else {
                4
            }
            + rows_h
            + bar_h
    };
    let (show_card, show_groups) = if need(true, true) <= ch {
        (true, true)
    } else if need(true, false) <= ch {
        (true, false)
    } else {
        (false, ch >= need(false, true))
    };
    let mut y = cy;
    let card = show_card.then(|| {
        let r = (cx, y, cw, card_full_h);
        y += (card_full_h + m.gap) as i32;
        r
    });
    let strip = status.then(|| {
        let r = (cx, y, cw, strip_h);
        y += (strip_h + m.gap) as i32;
        r
    });
    let top = y;
    let list_w = side_w.map_or(cw, |s| cw - s - m.gap);
    let mut ry = top + title_h as i32;
    let mut groups = Vec::new();
    let mut rows = [(0, 0, 0, 0); ACTION_COUNT];
    for (i, row) in rows.iter_mut().enumerate() {
        if let Some((label, _)) = GROUPS.iter().find(|(_, first)| *first == i) {
            if show_groups {
                groups.push((*label, ry + 6));
                ry += group_h as i32;
            } else if i > 0 {
                ry += 4;
            }
        }
        *row = (cx, ry, list_w, m.row);
        ry += m.row as i32;
    }
    SecLayout {
        card,
        card_compact,
        strip,
        list: (cx, top, list_w, (bottom - top).max(0) as u32),
        groups,
        rows,
        side: side_w.map(|s| (cx + (list_w + m.gap) as i32, top, s, (bottom - top) as u32)),
        bar: side_w
            .is_none()
            .then(|| (cx, bottom - m.button as i32, (cw / 2).min(300), m.button)),
        short_text: list_w < 760,
    }
}

// ─── Painting ───────────────────────────────────────────────────────────

fn status_card(fb: &FramebufferInfo, rect: Rect, compact: bool) {
    let m = Metrics::for_fb(fb);
    kit::side(fb, rect);
    let state = fb.security_state();
    let e = state;
    let (headline, dot, text) = if state.enforcing {
        (
            "Secure Boot is on",
            theme::ACCENT,
            "Boot software must be signed by a key in db and not revoked by dbx.",
        )
    } else if state.setup_mode {
        (
            "Secure Boot is off (Setup Mode)",
            theme::WARN,
            "No platform key (PK) is enrolled, so signatures are not checked.",
        )
    } else if state.requested {
        (
            "Secure Boot is waiting",
            theme::WARN,
            "Enforcement is requested and starts once keys are in place.",
        )
    } else {
        (
            "Secure Boot is off",
            theme::WARN,
            "Signatures are not checked. Enrolled keys are kept.",
        )
    };
    let (x, y, w, h) = rect;
    let px = x + m.pad as i32;
    let py = y + m.pad as i32;
    let bh = render::font_height(m.big);
    render::draw_dot(fb, px + 6, py + bh as i32 / 2, 6, dot);
    render::draw_text_bold(
        fb,
        px + 22,
        py,
        headline,
        m.big,
        theme::INK,
        Some(theme::SIDE),
    );
    let counts = [
        ("PK", e.keys.pk, "Platform owner"),
        ("KEK", e.keys.kek, "May update db and dbx"),
        ("db", e.keys.db, "Allowed signers"),
        ("dbx", e.keys.dbx, "Revoked hashes and signers"),
    ];
    if compact {
        let mut line = String::new();
        for (name, n, _) in counts {
            let _ = write!(line, "{name} {n}   ");
        }
        render::draw_text(
            fb,
            px,
            py + bh as i32 + 8,
            line.trim_end(),
            m.body,
            theme::INK2,
            Some(theme::SIDE),
        );
        return;
    }
    let left_w = (w * 40 / 100).min(560);
    let mut ty = kit::prose(
        fb,
        px,
        py + bh as i32 + 8,
        left_w - m.pad,
        text,
        m.body,
        theme::INK2,
        3,
    ) + 6;
    let mode = if state.setup_mode { "Setup" } else { "User" };
    render::draw_text(fb, px, ty, "Mode", m.body, theme::INK3, Some(theme::SIDE));
    render::draw_text(fb, px + 60, ty, mode, m.body, theme::INK, Some(theme::SIDE));
    ty += m.line as i32;
    let _ = ty;
    // Key-store table.
    let tx = x + left_w as i32 + m.pad as i32;
    let tw = (x + w as i32 - m.pad as i32 - tx).max(0) as u32;
    let col1 = (render::font_width(m.body) * 5) as i32;
    let col2 = col1 + (render::font_width(m.body) * 9) as i32;
    let head = kit::table_head(
        fb,
        tx,
        y + m.pad as i32 - 6,
        tw,
        &[("Store", 0), ("Entries", col1 + 8), ("Purpose", col2 + 10)],
    );
    let rh = m.row - 8;
    for (i, (name, n, purpose)) in counts.iter().enumerate() {
        let ry = y + m.pad as i32 - 6 + head as i32 + (i as u32 * rh) as i32;
        let ty = ry + ((rh - render::font_height(m.body)) / 2) as i32;
        render::draw_text_bold(fb, tx, ty, name, m.body, theme::INK, Some(theme::SIDE));
        let count = alloc::format!("{n}");
        render::draw_text_right(
            fb,
            tx + col1,
            ty,
            (col2 - col1) as u32 - 8,
            &count,
            m.body,
            theme::INK,
            Some(theme::SIDE),
        );
        render::draw_text(
            fb,
            tx + col2 + 10,
            ty,
            &render::ellipsize(purpose, tw.saturating_sub(col2 as u32 + 10), m.body),
            m.body,
            theme::INK2,
            Some(theme::SIDE),
        );
        if i + 1 < counts.len() {
            render::fill_rect(fb, tx, ry + rh as i32 - 1, tw, 1, theme::RULE);
        }
    }
    let _ = h;
}

fn paint_action_row(
    fb: &FramebufferInfo,
    l: &SecLayout,
    i: usize,
    selected: usize,
    hovered: Option<usize>,
    focus: &Focus,
) {
    let m = Metrics::for_fb(fb);
    let idx = ACTION_ORDER[i];
    let text = action_text(fb, idx);
    let rect = l.rows[i];
    let mut c = Control::new(idx as u64, Role::Option, text.title);
    c.selected = i == selected;
    c.focused = focus.group == Group::Content && i == selected;
    c.enabled = unavailable_reason(fb, idx).is_none();
    let bg = controls::row(fb, rect, &c, hovered == Some(i));
    let ty = rect.1 + ((rect.3 - render::font_height(m.body)) / 2) as i32;
    let name_w = if l.short_text {
        render::font_width(m.body) * 31
    } else if m.large {
        440
    } else {
        320
    }
    .min(rect.2 * 55 / 100);
    render::draw_text_weight(
        fb,
        rect.0 + 14,
        ty,
        &render::ellipsize(text.title, name_w - 20, m.body),
        m.body,
        c.selected,
        action_color(fb, idx),
        Some(bg),
    );
    let desc = unavailable_reason(fb, idx).unwrap_or(if l.short_text {
        text.row_short
    } else {
        text.row
    });
    let dx = rect.0 + name_w as i32 + 4;
    render::draw_text(
        fb,
        dx,
        ty,
        &render::ellipsize(
            desc,
            (rect.0 + rect.2 as i32 - dx - 12).max(0) as u32,
            m.body,
        ),
        m.body,
        if c.enabled { theme::INK2 } else { theme::INK3 },
        Some(bg),
    );
}

fn paint_details(
    fb: &FramebufferInfo,
    l: &SecLayout,
    selected: usize,
    focus: &Focus,
) -> Option<Rect> {
    let m = Metrics::for_fb(fb);
    let idx = ACTION_ORDER[selected];
    let text = action_text(fb, idx);
    let reason = unavailable_reason(fb, idx);
    let focused = focus.group == Group::Actions;
    let kind = if reason.is_some() {
        ButtonKind::Neutral
    } else {
        match idx {
            CLEAR => ButtonKind::Danger,
            TOGGLE if fb.security_state().requested => ButtonKind::Danger,
            _ => ButtonKind::Neutral,
        }
    };
    let Some(side) = l.side else {
        let rect = l.bar?;
        let mut c = Control::new(1, Role::Button, text.button);
        c.focused = focused;
        c.enabled = reason.is_none();
        controls::button_with_key(fb, rect, &c, kind, Some("Enter"));
        return Some(rect);
    };
    kit::side(fb, side);
    let (sx, sy, sw, sh) = side;
    let x = sx + m.pad as i32;
    let w = sw - m.pad * 2;
    let max_y = sy + sh as i32 - m.pad as i32;
    let mut y = kit::caption_title(fb, x, sy + m.pad as i32, w, "Action", text.title);
    y = kit::prose(fb, x, y, w, text.detail, m.body, theme::INK, 6) + m.gap as i32 / 2;
    let mut facts = alloc::vec![Fact::new("Changes", text.changes)];
    if matches!(idx, CUSTOM_KEYS | DBX | DEFAULT_KEYS | CLEAR | TOGGLE) {
        facts.push(Fact::new("Requires", "Your confirmation"));
    }
    if idx == CLEAR {
        facts.push(Fact::strong("Undo", "Not possible", theme::BAD));
    }
    if let Some(reason) = reason {
        facts.push(Fact::strong(
            "Status",
            reason.trim_start_matches("Unavailable: "),
            theme::WARN,
        ));
    }
    y = kit::facts(fb, x, y, w, &facts, max_y) + m.gap as i32 / 2;
    let rects = kit::button_stack(
        fb,
        x,
        y.min(max_y - m.button as i32),
        w,
        &[StripButton {
            label: text.button,
            key: Some("Enter"),
            kind,
            focused,
        }],
    );
    if reason.is_some() {
        // Drawn as available-to-focus but quiet; Enter explains instead.
        let r = rects[0];
        let mut c = Control::new(1, Role::Button, text.button);
        c.focused = focused;
        c.enabled = false;
        controls::button_with_key(fb, r, &c, ButtonKind::Neutral, Some("Enter"));
    }
    rects.first().copied()
}

fn draw_screen(
    fb: &FramebufferInfo,
    selected: usize,
    focus: &Focus,
    status: Option<(&str, Tone)>,
) -> Option<Rect> {
    fb.observe(UiState {
        screen: Screen::Security,
        selected: Some(selected),
        scroll_offset: 0,
        countdown: 0,
    });
    super::draw_shell(fb, NavItem::Security, focus, None);
    let m = Metrics::for_fb(fb);
    let l = sec_layout(fb, status.is_some());
    if let Some(card) = l.card {
        status_card(fb, card, l.card_compact);
    }
    if let Some((message, tone)) = status {
        let (headline, message) = match tone {
            Tone::Bad => ("Error:", message),
            Tone::Ok => ("Done:", message),
            Tone::Warn => ("Unavailable:", message.trim_start_matches("Unavailable: ")),
            Tone::Neutral => (message, ""),
        };
        if let Some(rect) = l.strip {
            kit::strip(fb, rect, tone, headline, message, &[], None);
        } else if let Some(bar) = l.bar {
            let (cx, _, cw, _) = canvas(fb);
            let x = bar.0 + bar.2 as i32 + m.gap as i32;
            let w = (cx + cw as i32 - x).max(0) as u32;
            let color = match tone {
                Tone::Bad => theme::BAD,
                Tone::Ok => theme::ACCENT,
                Tone::Warn => theme::WARN,
                Tone::Neutral => theme::INK2,
            };
            let text = alloc::format!("{headline} {message}");
            kit::prose(fb, x, bar.1, w, text.trim_start(), m.small, color, 2);
        }
    }
    let (lx, ly, lw, _) = l.list;
    kit::pane_title(
        fb,
        lx,
        ly,
        lw,
        "Actions",
        "Every change is reviewed first",
        true,
    );
    for (label, gy) in &l.groups {
        render::draw_text(
            fb,
            lx + 2,
            *gy,
            label,
            m.small,
            if *label == "Danger" {
                theme::BAD
            } else {
                theme::INK3
            },
            None,
        );
    }
    for i in 0..ACTION_COUNT {
        paint_action_row(fb, &l, i, selected, None, focus);
    }
    let button = paint_details(fb, &l, selected, focus);
    kit::draw_keys(
        fb,
        &[
            ("Up Down", "Select"),
            ("Enter", "Open"),
            ("Tab", "Next pane"),
            ("Esc", "Back to Boot"),
        ],
        true,
    );
    button
}

fn draw_progress(fb: &FramebufferInfo, selected: usize, message: &str) {
    let focus = Focus::new(super::nav_item_index(NavItem::Security));
    draw_screen(fb, selected, &focus, Some((message, Tone::Neutral)));
}

// ─── Page loop ──────────────────────────────────────────────────────────

pub async fn show(fb: &FramebufferInfo) -> ScreenNav {
    let mut cursor = CursorRenderer::new();
    let mut focus = Focus::new(super::nav_item_index(NavItem::Security));
    // Start on the first harmless, available action.
    let mut selected = if fb.security_state().setup_mode { 1 } else { 0 };
    let mut status: Option<(&'static str, Tone)> = None;
    cursor.hide(fb);
    let mut button = draw_screen(fb, selected, &focus, status);
    let mut hovered = None;
    let mut hover = super::Hover::default();
    loop {
        super::poll_and_render_cursor(fb, &mut cursor);
        super::track_hover(
            fb,
            &mut cursor,
            &mut hover,
            Some((NavItem::Security, &focus)),
        );
        let (mx, my) = fb.position();
        let l = sec_layout(fb, status.is_some());
        let next = (0..ACTION_COUNT).find(|i| dialog::contains(l.rows[*i], mx, my));
        if hovered != next {
            let previous = core::mem::replace(&mut hovered, next);
            cursor.while_hidden(fb, || {
                for i in previous.into_iter().chain(next) {
                    paint_action_row(fb, &l, i, selected, next, &focus);
                }
            });
        }
        if let Some(key) = fb.key() {
            let event = super::chrome_key(fb, key, &mut focus, NavItem::Security, 1);
            let mut open = false;
            match event {
                Some(FocusEvent::Navigate(i)) => {
                    cursor.hide(fb);
                    return ScreenNav::Nav(super::nav_at(i));
                }
                Some(FocusEvent::Moved) => {}
                Some(FocusEvent::Action(_)) => open = true,
                None => match key {
                    KeyPress::Escape | KeyPress::Char('q' | 'Q') => {
                        cursor.hide(fb);
                        return ScreenNav::Back;
                    }
                    KeyPress::Up | KeyPress::Char('k') if focus.group == Group::Content => {
                        selected = selected.saturating_sub(1)
                    }
                    KeyPress::Down | KeyPress::Char('j') if focus.group == Group::Content => {
                        selected = (selected + 1).min(ACTION_COUNT - 1)
                    }
                    KeyPress::Home | KeyPress::End | KeyPress::PageUp | KeyPress::PageDown
                        if focus.group == Group::Content =>
                    {
                        selected = super::page_selection(key, selected, ACTION_COUNT, ACTION_COUNT)
                            .unwrap_or(selected)
                    }
                    KeyPress::Enter if focus.group == Group::Content => open = true,
                    KeyPress::Char('r' | 'R') => {
                        cursor.hide(fb);
                        let backdrop = || {
                            draw_screen(fb, selected, &focus, status);
                        };
                        super::confirm_reset(fb, &backdrop).await;
                    }
                    KeyPress::MouseClick { x, y } => {
                        if button.is_some_and(|r| dialog::contains(r, x as i32, y as i32)) {
                            open = true;
                            focus.group = Group::Actions;
                        } else if let Some(i) = hovered {
                            selected = i;
                            focus.group = Group::Content;
                        }
                    }
                    _ => {}
                },
            }
            if open {
                cursor.hide(fb);
                let snapshot_focus = focus;
                let backdrop = || {
                    draw_screen(fb, selected, &snapshot_focus, None);
                };
                status = handle_action(fb, selected, &backdrop).await;
                if let Some((message, Tone::Bad)) = status {
                    // Never truncate recovery instructions in the narrow
                    // action bar. The modal wraps the complete result.
                    dialog::modal(
                        fb,
                        &backdrop,
                        Tone::Bad,
                        "Operation failed",
                        &[Block::text(message)],
                        &[Choice::new("Close", Some("Esc"), ButtonKind::Neutral)],
                    )
                    .await;
                }
            }
            cursor.hide(fb);
            button = draw_screen(fb, selected, &focus, status);
            hovered = None;
            hover.reset();
        }
        if fb.reset_requested() {
            return ScreenNav::Reset;
        }
        fb.wait_for_frame().await;
    }
}

// Identities are supplied by the host. Firmware retains the verified bytes
// and certificate parsing; the test harness labels its simulated records.
async fn show_key_details(fb: &FramebufferInfo, backdrop: dialog::Backdrop<'_>) {
    let s = fb.security_state();
    let sections = fb.enrolled_keys();
    let intro = [
        Block::fact(
            "Mode",
            if s.setup_mode {
                "Setup Mode"
            } else {
                "User Mode"
            },
        ),
        Block::fact("Protection", if s.enforcing { "On" } else { "Off" }),
    ];
    dialog::review(
        fb,
        backdrop,
        "Enrolled Secure Boot keys",
        &intro,
        &sections,
        &[],
        None,
    )
    .await;
}

// ─── Operations ─────────────────────────────────────────────────────────

async fn handle_action(
    fb: &FramebufferInfo,
    selected: usize,
    backdrop: dialog::Backdrop<'_>,
) -> Option<(&'static str, Tone)> {
    let idx = ACTION_ORDER[selected];
    if idx == SHOW_KEYS {
        show_key_details(fb, backdrop).await;
        return None;
    }
    if let Some(reason) = unavailable_reason(fb, idx) {
        return Some((reason, Tone::Warn));
    }
    if matches!(idx, CUSTOM_KEYS | DBX) {
        draw_progress(fb, selected, "Loading and verifying identities...");
        let prepared = match fb.prepare_import(if idx == CUSTOM_KEYS {
            SecurityAction::EnrollCustomPk
        } else {
            SecurityAction::ImportDbx
        }) {
            Ok(p) => p,
            Err(error) => return Some((error, Tone::Bad)),
        };
        let crate::ImportReview {
            payload,
            intro,
            sections,
            outro,
        } = prepared;
        let (title, confirm) = if idx == CUSTOM_KEYS {
            ("Review keys before enrolling", "Enroll these keys")
        } else {
            ("Review dbx update before importing", "Import this update")
        };
        if !dialog::review(
            fb,
            backdrop,
            title,
            &intro,
            &sections,
            &outro,
            Some(confirm),
        )
        .await
        {
            return Some(("Cancelled; nothing was changed.", Tone::Neutral));
        }
        draw_progress(fb, selected, "Working; please wait...");
        let result = fb.commit_import(payload);
        return Some(match result {
            Ok(message) => (message, Tone::Ok),
            Err(message) => (message, Tone::Bad),
        });
    }
    let e = fb.security_state();
    let (title, tone, mut content, confirm, kind) = match idx {
        TOGGLE if fb.security_state().requested => (
            "Disable Secure Boot?",
            Tone::Warn,
            alloc::vec![
                Block::text(
                    "Signature checks stop immediately. Untrusted boot software will be allowed to start."
                ),
                Block::muted(
                    "Enrolled keys are kept. You can enable Secure Boot again from this page."
                ),
            ],
            "Disable Secure Boot",
            ButtonKind::Danger,
        ),
        TOGGLE => (
            "Enable Secure Boot?",
            Tone::Neutral,
            alloc::vec![
                Block::text(
                    "Boot software must be signed by a key in db once a platform key (PK) is enrolled."
                ),
                Block::muted(
                    "In Setup Mode the preference is saved; enforcement starts after enrollment."
                ),
            ],
            "Enable Secure Boot",
            ButtonKind::Primary,
        ),
        DEFAULT_KEYS => (
            "Enroll default keys?",
            Tone::Neutral,
            alloc::vec![
                Block::text("Installs the bundled Microsoft UEFI certificates as PK, KEK and db."),
                Block::muted(
                    "This leaves Setup Mode and may start signature enforcement immediately."
                ),
            ],
            "Enroll default keys",
            ButtonKind::Accent,
        ),
        _ => (
            "Clear all Secure Boot keys?",
            Tone::Bad,
            alloc::vec![
                Block::text("This permanently deletes every enrolled key and signature list:"),
                Block::strong_fact(
                    "PK",
                    &alloc::format!("{} (platform owner)", plural(e.keys.pk, "certificate"))
                ),
                Block::strong_fact("KEK", &plural(e.keys.kek, "certificate")),
                Block::strong_fact("db", &plural(e.keys.db, "entry")),
                Block::strong_fact("dbx", &plural(e.keys.dbx, "revocation")),
                Block::text(
                    "Secure Boot stops enforcing until new keys are enrolled. This cannot be undone; keep copies of your keys before continuing."
                ),
            ],
            "Clear all keys",
            ButtonKind::Danger,
        ),
    };
    if idx == CLEAR && e.keys_incomplete {
        content.insert(0, Block::text("Warning: the key inventory is incomplete. These counts may omit malformed stored entries; clearing deletes those entries too."));
    }
    let choice = dialog::modal(
        fb,
        backdrop,
        tone,
        title,
        &content,
        &[
            Choice::new("Cancel", Some("Esc"), ButtonKind::Neutral),
            Choice::new(confirm, None, kind),
        ],
    )
    .await;
    if choice != 1 {
        return Some(("Cancelled; nothing was changed.", Tone::Neutral));
    }
    draw_progress(fb, selected, "Working; please wait...");
    let action = match idx {
        TOGGLE => SecurityAction::Toggle,
        DEFAULT_KEYS => SecurityAction::EnrollDefaults,
        _ => SecurityAction::ClearKeys,
    };
    let (message, ok) = fb.security_action(action);
    Some((message, if ok { Tone::Ok } else { Tone::Bad }))
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        alloc::format!("1 {noun}")
    } else if let Some(stem) = noun.strip_suffix('y') {
        alloc::format!("{n} {stem}ies")
    } else {
        alloc::format!("{n} {noun}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plural_nouns() {
        assert_eq!(plural(1, "entry"), "1 entry");
        assert_eq!(plural(2, "entry"), "2 entries");
        assert_eq!(plural(0, "certificate"), "0 certificates");
    }
    fn fb(mem: &mut [u32], width: u32, height: u32) -> FramebufferInfo {
        crate::test_surface(crate::FramebufferConfig {
            physical_address: mem.as_mut_ptr() as u64,
            width,
            height,
            stride: width,
            bits_per_pixel: 32,
            red_mask_pos: 16,
            red_mask_size: 8,
            green_mask_pos: 8,
            green_mask_size: 8,
            blue_mask_pos: 0,
            blue_mask_size: 8,
        })
    }
    #[test]
    fn every_action_row_fits_above_the_key_legend() {
        for (width, height) in [
            (640, 400),
            (640, 480),
            (800, 600),
            (1024, 768),
            (1280, 800),
            (1920, 1080),
        ] {
            let f = fb(&mut [], width, height);
            for large in [false, true] {
                let m = Metrics::for_request(&f, large);
                for status in [false, true] {
                    let l = sec_layout_with_metrics(&f, status, m);
                    let (_, cy, _, ch) = m.canvas(&f);
                    for r in l.rows {
                        assert!(
                            r.1 + r.3 as i32 <= cy + ch as i32,
                            "{width}x{height} status={status} large={large}"
                        );
                    }
                    if let Some(bar) = l.bar {
                        assert!(
                            l.rows[ACTION_COUNT - 1].1 + l.rows[ACTION_COUNT - 1].3 as i32 <= bar.1
                        );
                    }
                }
            }
            if (width, height) == (1024, 768) {
                let l = sec_layout(&f, true);
                assert!(
                    l.card.is_some() && !l.card_compact && l.side.is_some() && !l.groups.is_empty()
                );
            }
        }
    }
    #[test]
    fn hover_repaints_match_a_full_list() {
        for (width, height) in [(640, 400), (1024, 768), (1920, 1080)] {
            let mut pixels = std::vec![0; width as usize * height as usize];
            let f = fb(&mut pixels, width, height);
            let focus = Focus::new(1);
            let l = sec_layout(&f, false);
            for i in 0..ACTION_COUNT {
                paint_action_row(&f, &l, i, 0, None, &focus);
            }
            let mut cursor = CursorRenderer::new();
            for hovered in 0..ACTION_COUNT {
                cursor.update(&f, l.rows[hovered].0 + 20, l.rows[hovered].1 + 8);
                cursor.while_hidden(&f, || {
                    paint_action_row(&f, &l, hovered, 0, Some(hovered), &focus)
                });
                cursor.while_hidden(&f, || paint_action_row(&f, &l, hovered, 0, None, &focus));
                cursor.hide(&f);
                let mut expected = std::vec![0; pixels.len()];
                let e = fb(&mut expected, width, height);
                for i in 0..ACTION_COUNT {
                    paint_action_row(&e, &l, i, 0, None, &focus);
                }
                assert_eq!(pixels, expected, "{width}x{height}, hovered={hovered}");
            }
        }
    }
}
