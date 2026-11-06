//! Secure Boot setup: inspect state, choose an operation, review owned bytes.

use super::{
    NavItem, ScreenNav, canvas,
    controls::{self, ButtonKind, Control, Focus, FocusEvent, Group, Role},
    dialog::{self, Rect, ReviewSection},
    layout::Metrics,
    render, theme,
};
use crate::{
    FramebufferConfig as FramebufferInfo,
    cursor::CursorRenderer,
    menu_common::{self, KeyPress},
    time::delay_ms,
};
use alloc::{string::String, vec::Vec};
use core::fmt::Write;

const ACTION_COUNT: usize = 6;
const ACTION_BACK: usize = 5;
/// Organize by intent, with disruptive operations after enrollment/revocations.
const ACTION_ORDER: [usize; ACTION_COUNT] = [1, 2, 3, 0, 4, 5];
const ACTION_ITEMS: [(&str, &str); ACTION_COUNT] = [
    (
        "Enable Secure Boot",
        "Protection: require signed boot software after key enrollment",
    ),
    (
        "Enroll default keys",
        "Keys: trust bundled Microsoft UEFI certificates",
    ),
    (
        "Enroll custom owner key",
        "Keys: inspect certificates from EFI\\keys\\ on the ESP",
    ),
    (
        "Import revocations",
        "Revocations: inspect a dbx update before importing",
    ),
    (
        "Clear all keys",
        "DANGER: remove trust and revocations; stop protection",
    ),
    (
        "Back to Boot",
        "Return without changing Secure Boot configuration",
    ),
];

pub fn show(fb: &FramebufferInfo) -> ScreenNav {
    let mut cursor = CursorRenderer::new();
    let mut focus = Focus::new(super::nav_item_index(NavItem::Security));
    let mut selected = if crate::efi::auth::is_setup_mode() {
        0
    } else {
        2
    };
    let mut offset = 0usize;
    let mut status: Option<(&'static str, bool)> = None;
    controls::ensure_visible(
        &mut offset,
        selected,
        ACTION_COUNT,
        action_visible_slots(fb),
    );
    cursor.hide(fb);
    draw_screen(fb, selected, offset, &focus, status);
    let mut hovered = None;
    loop {
        super::poll_and_render_cursor(fb, &mut cursor);
        let (mx, my) = crate::drivers::mouse_cursor::position();
        let next = (offset..(offset + action_visible_slots(fb)).min(ACTION_COUNT)).find(|i| {
            action_card_rect(fb, offset, *i).is_some_and(|r| dialog::contains(r, mx, my))
        });
        if hovered != next {
            let previous = core::mem::replace(&mut hovered, next);
            cursor.while_hidden(fb, || {
                for i in previous.into_iter().chain(next) {
                    paint_action_card(fb, i, selected, next, offset, &focus);
                }
            });
        }
        if let Some(key) = menu_common::read_key() {
            let event = super::chrome_key(fb, key, &mut focus, NavItem::Security, 2);
            let mut open = false;
            let mut inspect = false;
            let mut reveal = true;
            match event {
                Some(FocusEvent::Navigate(i)) => {
                    cursor.hide(fb);
                    return ScreenNav::Nav(super::nav_at(i));
                }
                Some(FocusEvent::Moved) => {}
                Some(FocusEvent::Action(i)) => {
                    open = i == 0;
                    inspect = i == 1;
                }
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
                        selected = super::page_selection(
                            key,
                            selected,
                            ACTION_COUNT,
                            action_visible_slots(fb),
                        )
                        .unwrap_or(selected)
                    }
                    KeyPress::Enter if focus.group == Group::Content => open = true,
                    KeyPress::Char('r' | 'R') => {
                        cursor.hide(fb);
                        super::confirm_reset(fb, NavItem::Security);
                    }
                    KeyPress::MouseScroll(dz) => {
                        controls::scroll(&mut offset, dz, ACTION_COUNT, action_visible_slots(fb));
                        reveal = false;
                    }
                    KeyPress::MouseClick { x, y } => {
                        let buttons = action_buttons(fb);
                        if controls::scroll_track(
                            &mut offset,
                            action_list_area(fb),
                            (x as i32, y as i32),
                            ACTION_COUNT,
                            action_visible_slots(fb),
                        ) {
                            reveal = false;
                        } else if dialog::contains(buttons[0], x as i32, y as i32) {
                            open = true;
                            focus.group = Group::Actions;
                            focus.action = 0;
                        } else if dialog::contains(buttons[1], x as i32, y as i32) {
                            inspect = true;
                            focus.group = Group::Actions;
                            focus.action = 1;
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
                let index = ACTION_ORDER[selected];
                if index == ACTION_BACK {
                    return ScreenNav::Back;
                }
                status = handle_action(fb, index);
            }
            if inspect {
                cursor.hide(fb);
                show_key_details(fb);
            }
            if reveal {
                controls::ensure_visible(
                    &mut offset,
                    selected,
                    ACTION_COUNT,
                    action_visible_slots(fb),
                );
            }
            // Wheel changes the viewport only; do not reveal selection again
            // before painting, or the scroll operation would be undone.
            cursor.hide(fb);
            draw_screen(fb, selected, offset, &focus, status);
            hovered = None;
        }
        delay_ms(8);
    }
}

fn unavailable_reason(idx: usize) -> Option<&'static str> {
    if matches!(idx, 1 | 2) && !crate::efi::auth::is_setup_mode() {
        Some("Requires Setup Mode; an owner key is already enrolled")
    } else if idx == 4 && !crate::efi::auth::boot::has_stored_keys() {
        Some("No keys enrolled; there is nothing to clear")
    } else {
        None
    }
}

/// Keep the verified bytes owned across review. Never reopen ESP files after consent.
enum PendingImport {
    Keys(crate::efi::auth::key_files::KeyFileSearchResult),
    Dbx(Vec<u8>, crate::efi::auth::dbx_update::DbxSource),
}
fn fingerprint(hash: &[u8; 32]) -> String {
    let mut text = String::new();
    for (i, byte) in hash.iter().enumerate() {
        if i > 0 && i.is_multiple_of(4) {
            text.push(' ');
        }
        let _ = write!(text, "{byte:02x}");
    }
    text
}
fn key_identity(label: &str, data: &[u8]) -> ReviewSection {
    ReviewSection::new(label, &fingerprint(&crate::efi::auth::sha256(data)))
}
fn prepare_import(idx: usize) -> Result<Option<(PendingImport, Vec<ReviewSection>)>, &'static str> {
    use crate::efi::auth::{self, dbx_update, key_files, sha256};
    match idx {
        2 => {
            let keys = key_files::find_key_files().ok_or_else(|| {
                crate::secure_boot_menu::custom_pk_error(auth::AuthError::NoSuitableKey)
            })?;
            key_files::validate_key_files(&keys)
                .map_err(crate::secure_boot_menu::custom_pk_error)?;
            let pk = keys.pk.as_deref().ok_or("No PK certificate supplied")?;
            let mut sections = alloc::vec![
                ReviewSection::new("Source", keys.source),
                key_identity("Owner key (PK) - SHA-256", pk)
            ];
            match keys.kek.as_deref() {
                Some(kek) if kek != pk => {
                    sections.push(key_identity("Update key (KEK) - SHA-256", kek))
                }
                _ => sections.push(ReviewSection::new(
                    "Update key (KEK)",
                    "Same certificate as the owner key (PK).",
                )),
            }
            if let Some(db) = keys.db.as_deref() {
                if db == pk {
                    sections.push(ReviewSection::new(
                        "Custom boot signer (db)",
                        "Same certificate as the owner key (PK).",
                    ));
                } else if keys.kek.as_deref() == Some(db) {
                    sections.push(ReviewSection::new(
                        "Custom boot signer (db)",
                        "Same certificate as the update key (KEK).",
                    ));
                } else {
                    sections.push(key_identity("Custom boot signer (db) - SHA-256", db));
                }
            }
            sections.push(ReviewSection::new("Additional boot trust","Bundled Microsoft UEFI CA certificates are also added to db. Existing dbx revocations are kept."));
            Ok(Some((PendingImport::Keys(keys), sections)))
        }
        3 => {
            let (data, source) = dbx_update::find_dbx_file().ok_or_else(|| {
                crate::secure_boot_menu::dbx_error(auth::AuthError::NoSuitableKey)
            })?;
            let preview = dbx_update::preview_dbx_update(&data, source)
                .map_err(crate::secure_boot_menu::dbx_error)?;
            let mut sections = alloc::vec![
                ReviewSection::new("Source", preview.entries.source),
                ReviewSection::new(
                    "Update contents",
                    &alloc::format!(
                        "{} SHA-256 hashes; {} certificates.",
                        preview.entries.sha256_count,
                        preview.entries.x509_count
                    )
                )
            ];
            if let Some(t) = preview.timestamp {
                let (year, month, day, hour, minute, second) =
                    (t.year, t.month, t.day, t.hour, t.minute, t.second);
                sections.push(ReviewSection::new(
                    "Update timestamp",
                    &alloc::format!(
                        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"
                    ),
                ));
            }
            if let Some(signer) = preview.signer_sha256 {
                sections.push(ReviewSection::new(
                    "Verified signer - SHA-256",
                    &fingerprint(&signer),
                ));
            } else {
                sections.push(ReviewSection::new(
                    "UNSIGNED update",
                    "Signature not verified. Allowed only for provisioning in Setup Mode.",
                ));
            }
            sections.push(ReviewSection::new("WARNING - replaces existing dbx","Existing revocations absent from this file will be REMOVED. Previously revoked boot software may become bootable."));
            sections.push(ReviewSection::new(
                "Reviewed file - SHA-256",
                &fingerprint(&sha256(&data)),
            ));
            Ok(Some((PendingImport::Dbx(data, source), sections)))
        }
        _ => Ok(None),
    }
}

fn handle_action(fb: &FramebufferInfo, idx: usize) -> Option<(&'static str, bool)> {
    use crate::efi::auth;
    if idx == ACTION_BACK {
        return None;
    }
    if let Some(reason) = unavailable_reason(idx) {
        dialog::choose(
            fb,
            NavItem::Security,
            "Action unavailable",
            reason,
            &["Back"],
        );
        return Some((reason, false));
    }
    let (title, message, confirm) = match idx {
        0 if auth::is_secure_boot_requested() => (
            "Disable Secure Boot?",
            "Signature enforcement will stop immediately. Untrusted boot software will be allowed. Enrolled keys are kept.",
            "Disable",
        ),
        0 => (
            "Enable Secure Boot?",
            "Signed boot software will be required once an owner key (PK) is enrolled. In Setup Mode the preference is saved, but enforcement stays off until enrollment.",
            "Enable",
        ),
        1 => (
            "Trust default keys?",
            "Install the bundled Microsoft UEFI certificates (PK, KEK and db). This leaves Setup Mode and may activate signature enforcement immediately.",
            "Enroll",
        ),
        2 => (
            "Enroll custom owner key?",
            "Replace PK/KEK/db using the reviewed ESP certificates and bundled Microsoft UEFI CA trust. Without a KEK file, PK also becomes KEK. Enrolling PK leaves Setup Mode and may start enforcement now.",
            "Enroll",
        ),
        3 => (
            "Import revocations?",
            if auth::is_setup_mode() {
                "Import the reviewed dbx file. Setup Mode also allows unsigned provisioning. Revoked boot software may stop booting. Only import a revocation list you trust."
            } else {
                "Import the reviewed dbx file, verified against an enrolled KEK or PK. Unsigned files are not accepted in User Mode. Revoked boot software may stop booting."
            },
            "Import",
        ),
        4 => (
            "Clear all Secure Boot keys?",
            "Remove PK, KEK, db and dbx. Signature enforcement stops and Setup Mode is restored. You will need trusted key files to restore custom keys.",
            "Clear keys",
        ),
        _ => return None,
    };
    if matches!(idx, 2 | 3) {
        draw_progress(fb, idx, "Loading and verifying identities...");
    }
    let mut prepared = match prepare_import(idx) {
        Ok(p) => p,
        Err(error) => return Some((error, false)),
    };
    let consent = if let Some((_, sections)) = prepared.as_mut() {
        sections.insert(0, ReviewSection::new("Operation and consequences", message));
        dialog::review(fb, NavItem::Security, title, sections, confirm)
    } else {
        dialog::choose(fb, NavItem::Security, title, message, &["Cancel", confirm]) == 1
    };
    if !consent {
        return Some(("Cancelled; no changes made", true));
    }
    draw_progress(fb, idx, "Working; please wait...");
    let result = match idx {
        0 => return Some(crate::secure_boot_menu::toggle_secure_boot_action()),
        1 => auth::boot::enroll_and_persist_default_keys()
            .map(|_| "Default keys enrolled")
            .map_err(|_| "Failed to enroll keys; check variable storage"),
        2 | 3 => match prepared.map(|(pending, _)| pending) {
            Some(PendingImport::Keys(keys)) => auth::key_files::enroll_key_files(keys)
                .map(|_| "Custom PK enrolled; reviewed identities committed")
                .map_err(crate::secure_boot_menu::custom_pk_error),
            Some(PendingImport::Dbx(data, source)) => {
                auth::dbx_update::enroll_dbx_data(data, source)
                    .map(|_| "dbx imported; reviewed update committed")
                    .map_err(crate::secure_boot_menu::dbx_error)
            }
            None => Err("No verified import was prepared"),
        },
        4 => auth::boot::clear_all_keys()
            .map(|_| "All keys cleared; Setup Mode restored")
            .map_err(|_| "Failed to clear keys; check variable storage"),
        _ => return None,
    };
    Some(match result {
        Ok(message) => (message, true),
        Err(message) => (message, false),
    })
}

fn action_buttons(fb: &FramebufferInfo) -> [Rect; 2] {
    let m = Metrics::for_fb(fb);
    let (x, y, w, h) = canvas(fb);
    let bw = ((w - 12) / 2).min(280);
    [
        (x, y + h as i32 - m.button as i32, bw, m.button),
        (
            x + bw as i32 + 12,
            y + h as i32 - m.button as i32,
            bw,
            m.button,
        ),
    ]
}
fn action_list_area(fb: &FramebufferInfo) -> Rect {
    let m = Metrics::for_fb(fb);
    let (x, y, w, h) = canvas(fb);
    let heading = render::font_height(m.title) + 12 + if h > 350 { m.line * 2 + 12 } else { 0 };
    let status = if h > 350 { m.line * 2 } else { m.line };
    (
        x,
        y + heading as i32,
        if w >= 1050 { w * 3 / 5 - 16 } else { w },
        h.saturating_sub(heading + m.button + status + 20),
    )
}
fn action_row_height(fb: &FramebufferInfo) -> u32 {
    let m = Metrics::for_fb(fb);
    if canvas(fb).3 < 300 { m.row } else { m.entry }
}
fn action_visible_slots(fb: &FramebufferInfo) -> usize {
    (action_list_area(fb).3 / (action_row_height(fb) + 4)).max(1) as usize
}
fn action_card_rect(fb: &FramebufferInfo, offset: usize, i: usize) -> Option<Rect> {
    if i < offset || i >= offset + action_visible_slots(fb) {
        return None;
    }
    let (x, y, w, _) = action_list_area(fb);
    let h = action_row_height(fb);
    Some((
        x,
        y + ((i - offset) as u32 * (h + 4)) as i32,
        w - controls::SCROLL_GUTTER,
        h,
    ))
}
fn paint_action_card(
    fb: &FramebufferInfo,
    i: usize,
    selected: usize,
    hovered: Option<usize>,
    offset: usize,
    focus: &Focus,
) {
    let Some(rect) = action_card_rect(fb, offset, i) else {
        return;
    };
    let m = Metrics::for_fb(fb);
    let idx = ACTION_ORDER[i];
    let (mut title, mut desc) = ACTION_ITEMS[idx];
    let danger = idx == 4 || (idx == 0 && crate::efi::auth::is_secure_boot_requested());
    if idx == 0 && crate::efi::auth::is_secure_boot_requested() {
        title = "Disable Secure Boot";
        desc = "DANGER: stop signature enforcement; enrolled keys are kept";
    }
    let unavailable = unavailable_reason(idx);
    if let Some(reason) = unavailable {
        desc = reason;
    }
    let mut c = Control::new(idx as u64, Role::Option, title);
    c.focused = focus.group == Group::Content && i == selected;
    c.selected = i == selected;
    c.enabled = unavailable.is_none();
    let bg = controls::frame(fb, rect, &c, hovered == Some(i));
    if danger {
        render::fill_rect(fb, rect.0 + 8, rect.1 + 5, 3, rect.3 - 10, theme::ERROR);
    }
    let label = alloc::format!(
        "{} {}{}",
        if i == selected { ">" } else { " " },
        if danger { "! " } else { "" },
        title
    );
    render::draw_text(
        fb,
        rect.0 + 16,
        rect.1 + 8,
        &render::ellipsize(&label, rect.2 - 32, m.body),
        m.body,
        if c.enabled {
            theme::TEXT
        } else {
            theme::TEXT_DIM
        },
        Some(bg),
    );
    if rect.3 >= m.entry {
        render::draw_text(
            fb,
            rect.0 + 30,
            rect.1 + 12 + render::font_height(m.body) as i32,
            &render::ellipsize(desc, rect.2 - 44, m.small),
            m.small,
            theme::TEXT_DIM,
            Some(bg),
        );
    }
    controls::viewport_focus(
        fb,
        action_list_area(fb),
        focus.group == Group::Content,
        selected,
        offset,
        action_visible_slots(fb),
    );
}
fn draw_screen(
    fb: &FramebufferInfo,
    selected: usize,
    offset: usize,
    focus: &Focus,
    status: Option<(&str, bool)>,
) {
    super::draw_shell(fb, NavItem::Security, focus, None);
    let m = Metrics::for_fb(fb);
    let (x, y, w, h) = canvas(fb);
    let state = crate::efi::auth::secure_boot_state();
    let label = if state.enforcing {
        "ON"
    } else if state.requested {
        "Pending"
    } else {
        "OFF"
    };
    render::draw_text(
        fb,
        x,
        y,
        &alloc::format!("Secure Boot: {label}"),
        m.title,
        theme::TEXT,
        None,
    );
    if h > 350 {
        dialog::wrapped(
            fb,
            (
                x,
                y + render::font_height(m.title) as i32 + 10,
                w,
                m.line * 2,
            ),
            if state.enforcing {
                "Only signed, trusted boot software is allowed. Keys and revocations define that trust."
            } else if state.setup_mode {
                "Setup Mode: no owner key is enrolled. Signature protection is not active."
            } else {
                "Signature protection is off. Enrolled keys are kept."
            },
            theme::TEXT_DIM,
        );
    }
    for i in offset..(offset + action_visible_slots(fb)).min(ACTION_COUNT) {
        paint_action_card(fb, i, selected, None, offset, focus);
    }
    let (lx, ly, lw, lh) = action_list_area(fb);
    super::draw_scrollbar(
        fb,
        lx + lw as i32 - 22,
        ly,
        lh,
        ACTION_COUNT,
        offset,
        action_visible_slots(fb),
    );
    controls::viewport_focus(
        fb,
        (lx, ly, lw, lh),
        focus.group == Group::Content,
        selected,
        offset,
        action_visible_slots(fb),
    );
    if w >= 1050 {
        let rect = (lx + lw as i32 + 16, ly, w - lw - 16, lh);
        let c = Control::new(900, Role::Option, "Current trust");
        controls::frame(fb, rect, &c, false);
        dialog::wrapped(
            fb,
            (rect.0 + 16, rect.1 + 16, rect.2 - 32, rect.3 - 32),
            &key_details_text(),
            theme::TEXT_DIM,
        );
    }
    let buttons = action_buttons(fb);
    let target = match ACTION_ORDER[selected] {
        0 if state.requested => "Disable protection",
        0 => "Enable protection",
        1 => "Default keys",
        2 => "Custom owner key",
        3 => "Revocations",
        4 => "Clear all keys",
        _ => "Back to Boot",
    };
    let open = alloc::format!("Open: {target}");
    for (i, label) in [open.as_str(), "Current key details"].iter().enumerate() {
        let mut c = Control::new(1000 + i as u64, Role::Button, label);
        c.focused = focus.group == Group::Actions && focus.action == i;
        controls::button(fb, buttons[i], &c, ButtonKind::Neutral);
    }
    if let Some((message, ok)) = status {
        draw_feedback(
            fb,
            message,
            if ok { Feedback::Done } else { Feedback::Error },
        );
    }
    super::draw_footer(fb, "Tab Focus   Arrows Move   Enter Open   Esc Back");
}
enum Feedback {
    Info,
    Done,
    Error,
}
fn draw_feedback(fb: &FramebufferInfo, message: &str, feedback: Feedback) {
    let m = Metrics::for_fb(fb);
    let (x, _, w, h) = canvas(fb);
    let height = if h > 350 { m.line * 2 } else { m.line };
    let (prefix, color) = match feedback {
        Feedback::Info => ("Info", theme::TEXT_DIM),
        Feedback::Done => ("Done", theme::GREEN),
        Feedback::Error => ("Error", theme::ERROR),
    };
    dialog::wrapped(
        fb,
        (x, action_buttons(fb)[0].1 - height as i32 - 8, w, height),
        &alloc::format!("{prefix}: {message}"),
        color,
    );
}
fn draw_progress(fb: &FramebufferInfo, index: usize, message: &str) {
    let selected = ACTION_ORDER.iter().position(|i| *i == index).unwrap_or(0);
    let mut offset = 0;
    controls::ensure_visible(
        &mut offset,
        selected,
        ACTION_COUNT,
        action_visible_slots(fb),
    );
    let focus = Focus::new(super::nav_item_index(NavItem::Security));
    draw_screen(fb, selected, offset, &focus, None);
    draw_feedback(fb, message, Feedback::Info);
}

fn key_details_text() -> String {
    let s = crate::efi::auth::secure_boot_state();
    let e = crate::efi::auth::enrollment::get_enrollment_status();
    alloc::format!(
        "Current trust\n\nMode: {}\nProtection: {}\n\nOwner key (PK): {}\nControls platform ownership.\n\nUpdate keys (KEK): {}\nAuthorize trust-database updates.\n\nAllowed signers (db): {}\nMay sign boot software.\n\nRevocations (dbx): {}\nBlock revoked boot software.\n\nClear all keys also removes revocations.",
        if s.setup_mode {
            "Setup Mode"
        } else {
            "User Mode"
        },
        if s.enforcing { "ON" } else { "OFF" },
        e.pk_count,
        e.kek_count,
        e.db_count,
        e.dbx_count
    )
}
fn show_key_details(fb: &FramebufferInfo) {
    dialog::choose(
        fb,
        NavItem::Security,
        "Current Secure Boot trust",
        &key_details_text(),
        &["Back"],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_fingerprint_preserves_every_sha256_byte() {
        let hash = core::array::from_fn(|i| i as u8);
        assert_eq!(
            fingerprint(&hash),
            "00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617 18191a1b 1c1d1e1f"
        );
    }
    fn fb(mem: &mut [u32], width: u32, height: u32) -> FramebufferInfo {
        FramebufferInfo {
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
        }
    }
    #[test]
    fn action_focus_and_hover_repaints_match_a_full_list() {
        for (width, height) in [(640, 400), (640, 480), (1024, 768), (1920, 1080)] {
            let mut pixels = std::vec![0;width as usize*height as usize];
            let f = fb(&mut pixels, width, height);
            let focus = Focus::new(1);
            let mut offset = 0;
            let mut selected = 0;
            for i in 0..action_visible_slots(&f).min(ACTION_COUNT) {
                paint_action_card(&f, i, selected, None, offset, &focus);
            }
            let mut cursor = CursorRenderer::new();
            cursor.update(&f, 200, 250);
            for next in 1..ACTION_COUNT {
                let old = selected;
                let old_offset = offset;
                selected = next;
                controls::ensure_visible(
                    &mut offset,
                    selected,
                    ACTION_COUNT,
                    action_visible_slots(&f),
                );
                cursor.while_hidden(&f, || {
                    if old_offset != offset {
                        let (x, y, w, h) = action_list_area(&f);
                        render::fill_rect(&f, x, y, w, h, theme::BG);
                        for i in offset..(offset + action_visible_slots(&f)).min(ACTION_COUNT) {
                            paint_action_card(&f, i, selected, None, offset, &focus);
                        }
                    } else {
                        paint_action_card(&f, old, selected, None, offset, &focus);
                        paint_action_card(&f, selected, selected, None, offset, &focus);
                    }
                });
                cursor.hide(&f);
                let mut expected = std::vec![0;pixels.len()];
                let e = fb(&mut expected, width, height);
                if old_offset != offset {
                    let (x, y, w, h) = action_list_area(&e);
                    render::fill_rect(&e, x, y, w, h, theme::BG);
                }
                for i in offset..(offset + action_visible_slots(&e)).min(ACTION_COUNT) {
                    paint_action_card(&e, i, selected, None, offset, &focus);
                }
                assert_eq!(pixels, expected, "{width}x{height}, selected={selected}");
                cursor.update(&f, 200, 250);
            }
        }
    }
}
