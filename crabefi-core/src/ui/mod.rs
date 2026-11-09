//! Keyboard-first, native firmware setup UI ("Ledger" design). Shared focus and
//! physical geometry; domain state and authentication remain owned by their
//! existing backends.

pub mod controls;
pub mod dialog;
pub mod firmware_settings;
pub mod kit;
pub mod layout;
pub mod render;
#[cfg(feature = "secure-boot")]
pub mod secure_boot;
pub mod theme;

use crate::FramebufferConfig as FramebufferInfo;
use crate::cursor::CursorRenderer;
use crate::drivers::mouse_cursor;
use crate::menu::{BootEntry, BootEntryKind, BootMenu};
use crate::menu_common::{self, KeyPress};
use crate::time::{Timeout, delay_ms};
use alloc::string::String;
use alloc::vec::Vec;
use controls::{ButtonKind, Control, Focus, FocusEvent, Group, Role};
use core::sync::atomic::{AtomicBool, Ordering};
use kit::{Fact, StripButton, Tone};
use layout::Metrics;

type Rect = dialog::Rect;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NavItem {
    Boot,
    #[cfg(feature = "secure-boot")]
    Security,
    Firmware,
}
pub enum ScreenNav {
    Back,
    Nav(NavItem),
}
enum BootResult {
    Selected(usize),
    Nav(NavItem),
}
const NAV_ITEMS: &[(NavItem, &str)] = &[
    (NavItem::Boot, "Boot"),
    #[cfg(feature = "secure-boot")]
    (NavItem::Security, "Security"),
    (NavItem::Firmware, "Firmware"),
];

/// Firmware settings hold unsaved drafts; shown as "Firmware *" on every page.
#[cfg(not(test))]
static FIRMWARE_DIRTY: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
std::thread_local! {
    static FIRMWARE_DIRTY: AtomicBool = const { AtomicBool::new(false) };
}
fn firmware_dirty() -> bool {
    #[cfg(not(test))]
    return FIRMWARE_DIRTY.load(Ordering::Relaxed);
    #[cfg(test)]
    FIRMWARE_DIRTY.with(|d| d.load(Ordering::Relaxed))
}
pub fn set_firmware_dirty(dirty: bool) {
    #[cfg(not(test))]
    FIRMWARE_DIRTY.store(dirty, Ordering::Relaxed);
    #[cfg(test)]
    FIRMWARE_DIRTY.with(|d| d.store(dirty, Ordering::Relaxed));
}

pub(crate) fn nav_item_index(item: NavItem) -> usize {
    NAV_ITEMS
        .iter()
        .position(|(nav, _)| *nav == item)
        .unwrap_or(0)
}
pub fn supports_framebuffer(fb: &FramebufferInfo) -> bool {
    fb.width >= 640 && fb.height >= 400
}
pub fn clear(fb: &FramebufferInfo) {
    render::fill_rect(fb, 0, 0, fb.width, fb.height, theme::SHEET);
}

/// Header band with brand and the Secure Boot state chip.
pub fn draw_header(fb: &FramebufferInfo) {
    let tabs_end = nav_rects(fb).last().map_or(0, |r| r.0 + r.2 as i32);
    #[cfg(feature = "secure-boot")]
    {
        let state = crate::efi::auth::secure_boot_state();
        let chip = if state.enforcing {
            ("Secure Boot on", theme::ACCENT)
        } else if state.setup_mode {
            ("Setup Mode", theme::WARN)
        } else {
            ("Secure Boot off", theme::WARN)
        };
        kit::draw_header(fb, Some(chip), tabs_end);
    }
    #[cfg(not(feature = "secure-boot"))]
    kit::draw_header(fb, None, tabs_end);
}
fn nav_rects(fb: &FramebufferInfo) -> Vec<Rect> {
    let labels: Vec<&str> = NAV_ITEMS.iter().map(|(_, l)| *l).collect();
    kit::tab_rects(fb, &labels)
}
pub(crate) fn draw_navigation(
    fb: &FramebufferInfo,
    active: NavItem,
    focus: Option<usize>,
    hovered: Option<NavItem>,
) {
    let dirty = firmware_dirty();
    let tabs: Vec<kit::Tab<'_>> = NAV_ITEMS
        .iter()
        .enumerate()
        .map(|(i, (nav, label))| kit::Tab {
            label,
            active: *nav == active,
            focused: focus == Some(i),
            hovered: hovered == Some(*nav) && *nav != active,
            dirty: dirty && *nav == NavItem::Firmware,
        })
        .collect();
    kit::draw_tabs(fb, &tabs);
}
/// Compatibility name for platform integrations; navigation is the tab row.
pub fn draw_sidebar(fb: &FramebufferInfo, active: NavItem, hovered: Option<NavItem>) {
    draw_navigation(fb, active, None, hovered);
}
pub(crate) fn draw_shell(
    fb: &FramebufferInfo,
    active: NavItem,
    focus: &Focus,
    hovered: Option<NavItem>,
) {
    controls::clear_buttons();
    clear(fb);
    draw_header(fb);
    draw_navigation(
        fb,
        active,
        (focus.group == Group::Navigation).then_some(focus.navigation),
        hovered,
    );
}
pub(crate) fn navigation_hit(fb: &FramebufferInfo, x: i32, y: i32) -> Option<NavItem> {
    nav_rects(fb)
        .into_iter()
        .zip(NAV_ITEMS)
        .find(|(rect, _)| dialog::contains(*rect, x, y))
        .map(|(_, (nav, _))| *nav)
}
pub fn update_sidebar_hover(
    fb: &FramebufferInfo,
    cursor: &mut CursorRenderer,
    hovered: &mut Option<NavItem>,
    active: NavItem,
) -> bool {
    let (x, y) = mouse_cursor::position();
    let next = navigation_hit(fb, x, y);
    if next == *hovered {
        return false;
    }
    *hovered = next;
    cursor.while_hidden(fb, || draw_navigation(fb, active, None, next));
    true
}

/// Pointer hover shared by every page: tabs and buttons highlight the same
/// way everywhere. Rows are highlighted by each page's own list painter.
#[derive(Default)]
pub(crate) struct Hover {
    tab: Option<NavItem>,
    button: Option<usize>,
}
impl Hover {
    /// A full repaint drew everything unhighlighted.
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Call once per poll. `tabs` is the active page and focus when the tab row
/// is live; dialogs and editors pass `None`.
pub(crate) fn track_hover(
    fb: &FramebufferInfo,
    cursor: &mut CursorRenderer,
    hover: &mut Hover,
    tabs: Option<(NavItem, &Focus)>,
) {
    let (x, y) = mouse_cursor::position();
    if let Some((active, focus)) = tabs {
        let tab = navigation_hit(fb, x, y).filter(|t| *t != active);
        if tab != hover.tab {
            hover.tab = tab;
            cursor.while_hidden(fb, || {
                draw_navigation(
                    fb,
                    active,
                    (focus.group == Group::Navigation).then_some(focus.navigation),
                    tab,
                )
            });
        }
    }
    let button = controls::button_at(x, y);
    if button != hover.button {
        let previous = core::mem::replace(&mut hover.button, button);
        cursor.while_hidden(fb, || {
            if let Some(i) = previous {
                controls::repaint_button(fb, i, false);
            }
            if let Some(i) = button {
                controls::repaint_button(fb, i, true);
            }
        });
    }
}

/// Handle common focus/navigation only. Callers still gate leaving unsaved forms.
pub(crate) fn chrome_key(
    fb: &FramebufferInfo,
    key: KeyPress,
    focus: &mut Focus,
    active: NavItem,
    actions: usize,
) -> Option<FocusEvent> {
    if key == KeyPress::F8 {
        layout::toggle_text_size(fb);
        return Some(FocusEvent::Moved);
    }
    if let Some(event) = focus.handle(key, NAV_ITEMS.len(), actions) {
        return Some(match event {
            FocusEvent::Navigate(i) if nav_at(i) == active => FocusEvent::Moved,
            event => event,
        });
    }
    let destination = match key {
        KeyPress::Char('b' | 'B') => Some(NavItem::Boot),
        #[cfg(feature = "secure-boot")]
        KeyPress::Char('s' | 'S') => Some(NavItem::Security),
        KeyPress::Char('f' | 'F') => Some(NavItem::Firmware),
        KeyPress::MouseClick { x, y } => navigation_hit(fb, x as i32, y as i32),
        _ => None,
    }?;
    focus.navigation = nav_item_index(destination);
    if destination == active {
        Some(FocusEvent::Moved)
    } else {
        Some(FocusEvent::Navigate(focus.navigation))
    }
}
pub(crate) fn nav_at(index: usize) -> NavItem {
    NAV_ITEMS[index.min(NAV_ITEMS.len() - 1)].0
}

/// Compatibility: a plain-text hint in the key legend band.
pub fn draw_footer(fb: &FramebufferInfo, hint: &str) {
    let m = Metrics::for_fb(fb);
    let y = fb.height.saturating_sub(m.footer) as i32;
    let (x, _, w, _) = m.canvas(fb);
    render::fill_rect(fb, 0, y, fb.width, m.footer, theme::BAND);
    render::fill_rect(fb, 0, y, fb.width, 1, theme::RULE_STRONG);
    render::draw_text(
        fb,
        x,
        y + ((m.footer - render::font_height(m.small)) / 2) as i32,
        &render::ellipsize(hint, w, m.small),
        m.small,
        theme::INK2,
        Some(theme::BAND),
    );
}
pub(crate) fn canvas(fb: &FramebufferInfo) -> Rect {
    Metrics::for_fb(fb).canvas(fb)
}
pub(crate) fn page_selection(
    key: KeyPress,
    current: usize,
    count: usize,
    page: usize,
) -> Option<usize> {
    let last = count.checked_sub(1)?;
    Some(match key {
        KeyPress::Home => 0,
        KeyPress::End => last,
        KeyPress::PageUp => current.saturating_sub(page.max(1)),
        KeyPress::PageDown => current.saturating_add(page.max(1)).min(last),
        _ => return None,
    })
}
pub(crate) fn confirm_reset(fb: &FramebufferInfo, backdrop: dialog::Backdrop<'_>) {
    if dialog::modal(
        fb,
        backdrop,
        Tone::Warn,
        "Restart the computer?",
        &[dialog::Block::text(
            "The computer restarts now. Connect any new boot devices first.",
        )],
        &[
            dialog::Choice::new("Cancel", Some("Esc"), ButtonKind::Neutral),
            dialog::Choice::new("Restart", None, ButtonKind::Primary),
        ],
    ) == 1
    {
        crate::reset_system();
    }
}
pub fn poll_and_render_cursor(fb: &FramebufferInfo, cursor: &mut CursorRenderer) {
    mouse_cursor::poll();
    let (x, y) = mouse_cursor::position();
    cursor.update(fb, x, y);
}
pub fn draw_scrollbar(
    fb: &FramebufferInfo,
    x: i32,
    y: i32,
    h: u32,
    total: usize,
    offset: usize,
    visible: usize,
) {
    controls::scrollbar(fb, (x - 8, y, 16, h), total, offset, visible);
}

/// Show the graphical boot menu; returns the selected entry index. Boot
/// [`BootMenu::entry_for_boot`] for that index so a one-shot command-line
/// edit made in the menu applies to this boot attempt.
pub fn show_graphical_menu(menu: &mut BootMenu) -> Option<usize> {
    menu.clear_edited_cmdline();
    let fb = crate::handoff::framebuffer()?;
    if !supports_framebuffer(&fb) {
        return crate::menu::show_menu(menu);
    }
    let default = menu.selected;
    let mut screen = NavItem::Boot;
    loop {
        let next = match screen {
            NavItem::Boot => match run_boot(&fb, menu, default) {
                BootResult::Selected(i) => return Some(i),
                BootResult::Nav(nav) => ScreenNav::Nav(nav),
            },
            #[cfg(feature = "secure-boot")]
            NavItem::Security => secure_boot::show(&fb),
            NavItem::Firmware => firmware_settings::show(&fb),
        };
        screen = match next {
            ScreenNav::Back => NavItem::Boot,
            ScreenNav::Nav(nav) => nav,
        };
    }
}
pub fn show_no_media_screen() {
    let Some(fb) = crate::handoff::framebuffer() else {
        return;
    };
    if !supports_framebuffer(&fb) {
        no_media_text(&fb);
        return;
    }
    let mut nav = NavItem::Boot;
    loop {
        let next = match nav {
            NavItem::Boot => empty_screen(
                &fb,
                NavItem::Boot,
                "No bootable media",
                "Connect a boot device, then restart. Security and Firmware settings remain available.",
            ),
            #[cfg(feature = "secure-boot")]
            NavItem::Security => secure_boot::show(&fb),
            NavItem::Firmware => firmware_settings::show(&fb),
        };
        match no_media_destination(nav, next) {
            Some(next) => nav = next,
            None => return,
        }
    }
}

fn no_media_destination(current: NavItem, result: ScreenNav) -> Option<NavItem> {
    match result {
        ScreenNav::Back if current == NavItem::Boot => None,
        ScreenNav::Back => Some(NavItem::Boot),
        ScreenNav::Nav(next) => Some(next),
    }
}

fn no_media_text(fb: &FramebufferInfo) {
    let mut console = Some(crate::framebuffer_console::FramebufferConsole::new(fb));
    let mut redraw = true;
    loop {
        if redraw {
            menu_common::clear_screen(&mut console);
            menu_common::draw_header("No bootable media", &mut console, 80);
            menu_common::draw_help(
                5,
                if cfg!(feature = "secure-boot") {
                    "R Restart   F Settings   S Security   Esc Halt"
                } else {
                    "R Restart   F Settings   Esc Halt"
                },
                &mut console,
                80,
            );
            redraw = false;
        }
        match menu_common::read_key() {
            Some(KeyPress::Escape) => return,
            Some(KeyPress::Char('r' | 'R')) => crate::reset_system(),
            #[cfg(feature = "secure-boot")]
            Some(KeyPress::Char('s' | 'S')) => {
                crate::secure_boot_menu::show_secure_boot_menu();
                redraw = true;
            }
            Some(KeyPress::Char('f' | 'F')) => {
                if let Some(hooks) = crate::handoff::callbacks().hooks {
                    hooks.show_firmware_settings();
                }
                redraw = true;
            }
            _ => {}
        }
        delay_ms(10);
    }
}

fn empty_screen_paint(
    fb: &FramebufferInfo,
    nav: NavItem,
    focus: &Focus,
    title: &str,
    message: &str,
) -> Rect {
    draw_shell(fb, nav, focus, None);
    let m = Metrics::for_fb(fb);
    let (x, y, w, _) = canvas(fb);
    kit::strip(
        fb,
        (x, y, w, kit::strip_height(fb)),
        Tone::Warn,
        title,
        "",
        &[],
        None,
    );
    let mut ty = y + (kit::strip_height(fb) + m.gap) as i32;
    ty = kit::prose(fb, x, ty, w.min(900), message, m.body, theme::INK2, 4) + m.gap as i32;
    let restart = (
        x,
        ty,
        controls::button_width(fb, "Restart", Some("R")).max(220),
        m.button,
    );
    let mut c = Control::new(100, Role::Button, "Restart");
    c.focused = focus.group == Group::Actions;
    controls::button_with_key(fb, restart, &c, ButtonKind::Primary, Some("R"));
    kit::draw_keys(
        fb,
        &[("Tab", "Next"), ("Enter", "Activate"), ("Esc", "Back")],
        true,
    );
    restart
}

pub(crate) fn empty_screen(
    fb: &FramebufferInfo,
    nav: NavItem,
    title: &str,
    message: &str,
) -> ScreenNav {
    let mut cursor = CursorRenderer::new();
    let mut focus = Focus::new(nav_item_index(nav));
    focus.group = Group::Actions;
    let mut hover = Hover::default();
    loop {
        cursor.hide(fb);
        let restart = empty_screen_paint(fb, nav, &focus, title, message);
        hover.reset();
        loop {
            poll_and_render_cursor(fb, &mut cursor);
            track_hover(fb, &mut cursor, &mut hover, Some((nav, &focus)));
            if let Some(key) = menu_common::read_key() {
                let snapshot = focus;
                let backdrop = || {
                    empty_screen_paint(fb, nav, &snapshot, title, message);
                };
                match chrome_key(fb, key, &mut focus, nav, 1) {
                    Some(FocusEvent::Navigate(i)) => {
                        cursor.hide(fb);
                        return ScreenNav::Nav(nav_at(i));
                    }
                    Some(FocusEvent::Action(_)) => {
                        cursor.hide(fb);
                        confirm_reset(fb, &backdrop);
                        break;
                    }
                    Some(FocusEvent::Moved) => {
                        // Static explanatory text is not a keyboard stop.
                        if focus.group == Group::Content {
                            focus.group = if key == KeyPress::BackTab {
                                Group::Navigation
                            } else {
                                Group::Actions
                            };
                        }
                        break;
                    }
                    None => match key {
                        KeyPress::Escape => return ScreenNav::Back,
                        KeyPress::Char('r' | 'R') => {
                            cursor.hide(fb);
                            confirm_reset(fb, &backdrop);
                            break;
                        }
                        KeyPress::MouseClick { x, y }
                            if dialog::contains(restart, x as i32, y as i32) =>
                        {
                            cursor.hide(fb);
                            confirm_reset(fb, &backdrop);
                            break;
                        }
                        _ => {}
                    },
                }
            }
            delay_ms(8);
        }
    }
}

// ─── Boot page ──────────────────────────────────────────────────────────

struct BState {
    sel: usize,
    hovered: Option<usize>,
    scroll_offset: usize,
    countdown: u32,
    init_timeout: u32,
    tick: Timeout,
    count: usize,
    focus: Focus,
    default: usize,
    /// One-shot command line editor, owned by the details pane.
    edit: Option<dialog::Editor>,
}
impl BState {
    fn new(count: usize, sel: usize, timeout: u32) -> Self {
        Self {
            sel,
            hovered: None,
            scroll_offset: 0,
            countdown: timeout,
            init_timeout: timeout,
            tick: Timeout::from_ms(1000),
            count,
            focus: Focus::new(0),
            default: sel,
            edit: None,
        }
    }
    fn sel_next(&mut self) {
        self.sel = (self.sel + 1).min(self.count.saturating_sub(1));
    }
    fn sel_prev(&mut self) {
        self.sel = self.sel.saturating_sub(1);
    }
}
fn deliberate_pointer_motion(origin: (i32, i32), current: (i32, i32)) -> bool {
    origin.0.abs_diff(current.0) >= 8 || origin.1.abs_diff(current.1) >= 8
}
fn cancel_boot_countdown(menu: &mut BootMenu, state: &mut BState) -> bool {
    let was_running = state.countdown > 0;
    state.countdown = 0;
    menu.timeout_seconds = 0;
    was_running
}

fn kind_label(entry: &BootEntry) -> &'static str {
    match entry.kind {
        BootEntryKind::Uefi => "UEFI app",
        BootEntryKind::BlsLinux { .. } => "Linux",
        BootEntryKind::BlsUki => "Linux UKI",
        BootEntryKind::GrubLinux { .. } => "GRUB",
        BootEntryKind::Payload { .. } => "Payload",
    }
}
fn kind_detail(entry: &BootEntry) -> &'static str {
    match entry.kind {
        BootEntryKind::Uefi => "UEFI application",
        BootEntryKind::BlsLinux { .. } => "Linux (Boot Loader Spec)",
        BootEntryKind::BlsUki => "Unified kernel image",
        BootEntryKind::GrubLinux { .. } => "Linux (GRUB entry)",
        BootEntryKind::Payload { .. } => "coreboot payload",
    }
}
fn disk_name(entry: &BootEntry) -> String {
    use crate::drivers::storage::StorageId;
    let n = match entry.storage {
        StorageId::Nvme { controller_id, .. } => controller_id,
        StorageId::Ahci { port, .. } => port,
        StorageId::Usb { device_addr, .. } => device_addr as usize,
        StorageId::Sdhci { controller_id } => controller_id,
        StorageId::Platform { index } => index,
    };
    alloc::format!("{} {n}", entry.storage.description())
}
fn disk_short(entry: &BootEntry) -> String {
    if entry.is_payload() {
        return String::from("CBFS");
    }
    alloc::format!("{} p{}", disk_name(entry), entry.partition_num)
}
fn disk_long(entry: &BootEntry) -> String {
    if entry.is_payload() {
        return String::from("Firmware flash (CBFS)");
    }
    alloc::format!(
        "{}, partition {}",
        storage_identity(entry.storage),
        entry.partition_num
    )
}
fn storage_identity(id: crate::drivers::storage::StorageId) -> String {
    use crate::drivers::storage::StorageId;
    match id {
        StorageId::Nvme {
            controller_id,
            nsid,
        } => alloc::format!("NVMe controller {controller_id}, namespace {nsid}"),
        StorageId::Ahci {
            controller_id,
            port,
        } => alloc::format!("SATA controller {controller_id}, port {port}"),
        StorageId::Usb {
            controller_id,
            device_addr,
        } => alloc::format!("USB controller {controller_id}, device {device_addr}"),
        _ => alloc::format!(
            "{} {}",
            id.description(),
            match id {
                StorageId::Sdhci { controller_id } => controller_id,
                StorageId::Platform { index } => index,
                _ => unreachable!(),
            }
        ),
    }
}
fn disk_count(menu: &BootMenu) -> usize {
    let mut seen: Vec<crate::drivers::storage::StorageId> = Vec::new();
    for e in &menu.entries {
        if !e.is_payload() && !seen.contains(&e.storage) {
            seen.push(e.storage);
        }
    }
    seen.len()
}

/// Boot page geometry, shared by painting, hit-testing and tests.
struct BootLayout {
    strip: Option<Rect>,
    list: Rect,
    rows_y: i32,
    slots: usize,
    side: Option<Rect>,
    /// Narrow screens: action buttons under the list.
    bar: Option<Rect>,
    kind_x: i32,
    disk_x: Option<i32>,
}
fn boot_layout(fb: &FramebufferInfo, countdown: bool) -> BootLayout {
    let m = Metrics::for_fb(fb);
    let (cx, cy, cw, ch) = canvas(fb);
    let bottom = cy + ch as i32;
    let mut top = cy;
    let strip = countdown.then(|| {
        let r = (cx, cy, cw, kit::strip_height(fb));
        top += (r.3 + m.gap) as i32;
        r
    });
    let side_w = m.side_width(cw);
    let list_w = side_w.map_or(cw, |s| cw - s - m.gap);
    let bar = side_w
        .is_none()
        .then(|| (cx, bottom - m.button as i32, cw, m.button));
    let list_bottom = bar.map_or(bottom, |b| b.1 - m.gap as i32);
    let title_h = render::font_height(m.title) + 8;
    let head_h = render::font_height(m.small) + 12;
    let rows_y = top + (title_h + head_h) as i32;
    let slots = (((list_bottom - rows_y).max(0) as u32) / m.row).max(1) as usize;
    let disk_w = if m.large { 170 } else { 110 };
    let kind_w: i32 = if m.large { 140 } else { 96 };
    let inner = list_w - controls::SCROLL_GUTTER;
    let disk_x = (inner >= 520).then_some(cx + (inner - disk_w) as i32);
    let kind_x = disk_x.unwrap_or(cx + inner as i32) - kind_w;
    BootLayout {
        strip,
        list: (cx, top, list_w, (list_bottom - top).max(0) as u32),
        rows_y,
        slots,
        side: side_w.map(|s| (cx + (list_w + m.gap) as i32, top, s, (bottom - top) as u32)),
        bar,
        kind_x,
        disk_x,
    }
}
fn boot_visible_slots(fb: &FramebufferInfo, state: &BState) -> usize {
    boot_layout(fb, state.countdown > 0).slots
}
fn keep_boot_selection_visible(fb: &FramebufferInfo, state: &mut BState) {
    let slots = boot_visible_slots(fb, state);
    controls::ensure_visible(&mut state.scroll_offset, state.sel, state.count, slots);
}
fn row_rect(fb: &FramebufferInfo, state: &BState, index: usize) -> Option<Rect> {
    let l = boot_layout(fb, state.countdown > 0);
    if index < state.scroll_offset || index >= state.scroll_offset + l.slots {
        return None;
    }
    let m = Metrics::for_fb(fb);
    let gutter = if state.count > l.slots {
        controls::SCROLL_GUTTER
    } else {
        0
    };
    Some((
        l.list.0,
        l.rows_y + ((index - state.scroll_offset) as u32 * m.row) as i32,
        l.list.2 - gutter,
        m.row,
    ))
}
fn boot_hit(fb: &FramebufferInfo, menu: &BootMenu, state: &BState) -> Option<usize> {
    let (x, y) = mouse_cursor::position();
    (state.scroll_offset
        ..(state.scroll_offset + boot_visible_slots(fb, state)).min(menu.entry_count()))
        .find(|i| row_rect(fb, state, *i).is_some_and(|r| dialog::contains(r, x, y)))
}

fn boot_actions(menu: &BootMenu, state: &BState) -> usize {
    if state.edit.is_some()
        || menu
            .entries
            .get(state.sel)
            .is_some_and(BootEntry::has_cmdline)
    {
        2
    } else {
        1
    }
}

fn paint_boot(fb: &FramebufferInfo, menu: &BootMenu, state: &BState) -> Vec<Rect> {
    draw_shell(fb, NavItem::Boot, &state.focus, None);
    let m = Metrics::for_fb(fb);
    let mut l = boot_layout(fb, state.countdown > 0);
    // F8 can remove the side pane mid-edit. Keep the same editor and action
    // order visible in a full-canvas details pane instead of hiding the draft.
    if state.edit.is_some() && l.side.is_none() {
        l.side = Some(canvas(fb));
        return paint_boot_details(fb, menu, state, &l);
    }
    paint_boot_strip(fb, menu, state);
    let disks = disk_count(menu);
    let note = alloc::format!(
        "{} {} on {} {}",
        menu.entry_count(),
        if menu.entry_count() == 1 {
            "entry"
        } else {
            "entries"
        },
        disks,
        if disks == 1 { "disk" } else { "disks" }
    );
    let (lx, ly, lw, _) = l.list;
    let title_h = kit::pane_title(fb, lx, ly, lw, "Boot entries", &note, true);
    let mut cols = alloc::vec![("Name", 14), ("Kind", l.kind_x - lx + 10)];
    if let Some(dx) = l.disk_x {
        cols.push(("Disk", dx - lx + 10));
    }
    kit::table_head(fb, lx, ly + title_h as i32, lw, &cols);
    for i in state.scroll_offset..(state.scroll_offset + l.slots).min(menu.entry_count()) {
        paint_boot_row(fb, menu, state, i);
    }
    let scroll_area = (lx, l.rows_y, lw, l.slots as u32 * m.row);
    controls::scrollbar(
        fb,
        scroll_area,
        menu.entry_count(),
        state.scroll_offset,
        l.slots,
    );
    controls::viewport_focus(
        fb,
        scroll_area,
        state.focus.group == Group::Content,
        state.sel,
        state.scroll_offset,
        l.slots,
    );
    let buttons = paint_boot_details(fb, menu, state, &l);
    if state.edit.is_some() {
        kit::draw_keys(
            fb,
            &[
                ("Left Right", "Move"),
                ("Home End", "Jump"),
                ("Tab", "Buttons"),
                ("Enter", "Boot"),
                ("Esc", "Cancel"),
            ],
            false,
        );
    } else {
        let has_cmdline = menu
            .entries
            .get(state.sel)
            .is_some_and(BootEntry::has_cmdline);
        let mut keys = alloc::vec![("Up Down", "Select"), ("Enter", "Boot")];
        if has_cmdline {
            keys.push(("E", "Edit command line"));
        }
        keys.push(("Tab", "Next pane"));
        kit::draw_keys(fb, &keys, true);
    }
    buttons
}

fn paint_boot_strip(fb: &FramebufferInfo, menu: &BootMenu, state: &BState) {
    let Some(rect) = boot_layout(fb, state.countdown > 0).strip else {
        return;
    };
    let m = Metrics::for_fb(fb);
    let name = menu.entries.get(state.sel).map_or("", |e| e.name.as_str());
    let long = alloc::format!("Booting \"{name}\" in {} s.", state.countdown);
    let short = alloc::format!("Booting the selected entry in {} s.", state.countdown);
    let fits =
        render::text_width(&long, m.body) + render::text_width("Any key cancels.", m.body) + 60
            < rect.2;
    kit::strip(
        fb,
        rect,
        Tone::Warn,
        if fits { &long } else { &short },
        "Any key cancels.",
        &[],
        Some((
            state.init_timeout.saturating_sub(state.countdown) + 1,
            state.init_timeout.max(1),
        )),
    );
}

fn paint_boot_row(fb: &FramebufferInfo, menu: &BootMenu, state: &BState, index: usize) {
    let Some(rect) = row_rect(fb, state, index) else {
        return;
    };
    let Some(entry) = menu.entries.get(index) else {
        return;
    };
    let m = Metrics::for_fb(fb);
    let l = boot_layout(fb, state.countdown > 0);
    let mut c = Control::new(index as u64, Role::Option, &entry.name);
    c.focused = state.focus.group == Group::Content && state.sel == index;
    c.selected = state.sel == index;
    let bg = controls::row(fb, rect, &c, state.hovered == Some(index));
    let ty = rect.1 + (rect.3.saturating_sub(render::font_height(m.body)) / 2) as i32;
    let tag = (index == state.default).then_some("default");
    let tag_w = tag.map_or(0, |t| render::text_width(t, m.small) + 22);
    let name_w = (l.kind_x - rect.0 - 28).max(0) as u32;
    let name = render::ellipsize(&entry.name, name_w.saturating_sub(tag_w), m.body);
    let w = render::draw_text_weight(
        fb,
        rect.0 + 14,
        ty,
        &name,
        m.body,
        c.selected,
        theme::INK,
        Some(bg),
    );
    if let Some(t) = tag {
        let tx = rect.0 + 14 + w as i32 + 10;
        let th = render::font_height(m.small) + 2;
        let tw = render::text_width(t, m.small) + 10;
        let tyy = rect.1 + ((rect.3 - th) / 2) as i32;
        render::draw_border(fb, tx, tyy, tw, th, theme::ACCENT);
        render::draw_text_bold(fb, tx + 5, tyy + 1, t, m.small, theme::ACCENT, Some(bg));
    }
    render::draw_text(
        fb,
        l.kind_x + 10,
        ty,
        kind_label(entry),
        m.body,
        theme::INK2,
        Some(bg),
    );
    if let Some(dx) = l.disk_x {
        render::draw_text(
            fb,
            dx + 10,
            ty,
            &render::ellipsize(
                &disk_short(entry),
                rect.0 as u32 + rect.2 - dx as u32 - 14,
                m.body,
            ),
            m.body,
            theme::INK2,
            Some(bg),
        );
    }
    controls::viewport_focus(
        fb,
        (l.list.0, l.rows_y, l.list.2, l.slots as u32 * m.row),
        state.focus.group == Group::Content,
        state.sel,
        state.scroll_offset,
        l.slots,
    );
}

/// Details pane (or narrow action bar). Returns action button rectangles in
/// focus order.
fn paint_boot_details(
    fb: &FramebufferInfo,
    menu: &BootMenu,
    state: &BState,
    l: &BootLayout,
) -> Vec<Rect> {
    let m = Metrics::for_fb(fb);
    let Some(entry) = menu.entries.get(state.sel) else {
        return Vec::new();
    };
    let action_focus = |i: usize| state.focus.group == Group::Actions && state.focus.action == i;
    let has_cmdline = entry.has_cmdline();
    let Some(side) = l.side else {
        // Narrow screens: actions below the list; details stay in the editor.
        let (bx, by, bw, bh) = l.bar.unwrap_or((0, 0, 0, 0));
        let half = (bw - 12) / 2;
        let mut rects = Vec::new();
        let mut c = Control::new(1, Role::Button, "Boot this entry");
        c.focused = action_focus(0);
        controls::button_with_key(
            fb,
            (bx, by, half, bh),
            &c,
            ButtonKind::Primary,
            Some("Enter"),
        );
        rects.push((bx, by, half, bh));
        if has_cmdline {
            let r = (bx + half as i32 + 12, by, half, bh);
            let mut c = Control::new(2, Role::Button, "Edit command line once");
            c.focused = action_focus(1);
            controls::button_with_key(fb, r, &c, ButtonKind::Neutral, Some("E"));
            rects.push(r);
        }
        return rects;
    };
    kit::side(fb, side);
    let (sx, sy, sw, sh) = side;
    let x = sx + m.pad as i32;
    let w = sw - m.pad * 2;
    let max_y = sy + sh as i32 - m.pad as i32;
    let mut y = kit::caption_title(fb, x, sy + m.pad as i32, w, "Selected entry", &entry.name);
    let kind = kind_detail(entry);
    let disk = disk_long(entry);
    let mut facts = alloc::vec![Fact::new("Kind", kind), Fact::new("Disk", &disk)];
    let initrd;
    match &entry.kind {
        BootEntryKind::BlsLinux {
            linux_path,
            initrd_paths,
            ..
        }
        | BootEntryKind::GrubLinux {
            linux_path,
            initrd_paths,
            ..
        } => {
            facts.push(Fact::new("Kernel", linux_path.as_str()));
            initrd = match initrd_paths.len() {
                0 => String::from("none"),
                1 => String::from(initrd_paths[0].as_str()),
                n => alloc::format!("{} (+{} more)", initrd_paths[0], n - 1),
            };
            facts.push(Fact::new("Initrd", &initrd));
        }
        BootEntryKind::Payload { path, .. } => facts.push(Fact::new("File", path.as_str())),
        _ => facts.push(Fact::new("Path", entry.path.as_str())),
    }
    // Reserve a visible field, its labels and the entire action stack before
    // metadata wraps. Long paths must not push the editor under its buttons.
    let field = if state.edit.is_some() {
        m.line + 16 + m.small_line * 2 + 8 + m.gap / 2
    } else if has_cmdline {
        m.line + 16 + m.small_line + 2
    } else {
        0
    };
    let actions = if has_cmdline { 2 } else { 1 };
    let reserved = field + actions * (m.button + 10) + m.gap + 12;
    y = kit::facts(fb, x, y, w, &facts, max_y - reserved as i32) + m.gap as i32 / 2;
    let mut buttons: Vec<StripButton<'_>> = Vec::new();
    if let Some(edit) = &state.edit {
        render::draw_text(
            fb,
            x,
            y,
            "Command line (this boot only)",
            m.small,
            theme::INK3,
            None,
        );
        y += m.small_line as i32 + 2;
        let field_bottom = max_y - (2 * (m.button + 10) + m.small_line + m.gap / 2 + 14) as i32;
        y = paint_cmdline_editor(fb, (x, y, w), edit, field_bottom) + 6;
        render::draw_text(
            fb,
            x,
            y,
            &render::ellipsize("Not saved. The entry file is unchanged.", w, m.small),
            m.small,
            theme::INK2,
            None,
        );
        y += m.small_line as i32 + m.gap as i32 / 2;
        buttons.push(StripButton {
            label: "Boot with this command line",
            key: Some("Enter"),
            kind: ButtonKind::Primary,
            focused: edit.focus == 2,
        });
        buttons.push(StripButton {
            label: "Cancel",
            key: Some("Esc"),
            kind: ButtonKind::Neutral,
            focused: edit.focus == 1,
        });
    } else {
        if let Some(cmdline) = entry.get_cmdline() {
            render::draw_text(fb, x, y, "Command line", m.small, theme::INK3, None);
            y += m.small_line as i32 + 2;
            let field_bottom = max_y - (2 * (m.button + 10) + m.gap / 2 + 8) as i32;
            y = paint_code_box(fb, (x, y, w), cmdline, field_bottom) + m.gap as i32 / 2;
        }
        buttons.push(StripButton {
            label: "Boot this entry",
            key: Some("Enter"),
            kind: ButtonKind::Primary,
            focused: action_focus(0),
        });
        if has_cmdline {
            buttons.push(StripButton {
                label: "Edit command line once",
                key: Some("E"),
                kind: ButtonKind::Neutral,
                focused: action_focus(1),
            });
        }
    }
    let needed = buttons.len() as i32 * (m.button as i32 + 10);
    debug_assert!(
        y + needed + 4 <= max_y,
        "entry details must leave room for their actions"
    );
    let y = y.min(max_y - needed).max(sy + m.pad as i32);
    kit::button_stack(fb, x, y + 4, w, &buttons)
}

fn paint_code_box(fb: &FramebufferInfo, area: (i32, i32, u32), text: &str, max_y: i32) -> i32 {
    let m = Metrics::for_fb(fb);
    let (x, y, w) = area;
    let cols = ((w - 20) / render::font_width(m.body)).max(1) as usize;
    let lines = dialog::wrap_lines(text, cols);
    let room = ((max_y - y - 16).max(m.line as i32) as u32 / m.line) as usize;
    let shown = lines.len().clamp(1, room.clamp(1, 5));
    let h = shown as u32 * m.line + 16;
    render::fill_rect(fb, x, y, w, h, theme::PAPER);
    render::draw_border(fb, x, y, w, h, theme::RULE);
    for (i, line) in lines.iter().take(shown).enumerate() {
        let line = if i + 1 == shown && lines.len() > shown {
            // Character columns, never byte offsets: BLS options are arbitrary UTF-8.
            let kept: String = line.chars().take(cols.saturating_sub(3)).collect();
            alloc::format!("{kept}...")
        } else {
            line.clone()
        };
        render::draw_text(
            fb,
            x + 10,
            y + 8 + (i as u32 * m.line) as i32,
            &line,
            m.body,
            theme::INK,
            Some(theme::PAPER),
        );
    }
    y + h as i32
}

/// Character-wrapped editor with a block caret; the caret line stays visible.
fn paint_cmdline_editor(
    fb: &FramebufferInfo,
    area: (i32, i32, u32),
    edit: &dialog::Editor,
    max_y: i32,
) -> i32 {
    let m = Metrics::for_fb(fb);
    let (x, y, w) = area;
    let cols = ((w - 20) / render::font_width(m.body)).max(1) as usize;
    let chars: Vec<char> = edit.value.chars().collect();
    let caret = edit.value[..edit.caret].chars().count();
    let total_lines = chars.len() / cols + 1;
    let room = ((max_y - y - 16).max(m.line as i32) as u32 / m.line) as usize;
    let shown = total_lines.clamp(1, room.clamp(1, 6));
    let caret_line = caret / cols;
    let first = caret_line
        .saturating_sub(shown - 1)
        .min(total_lines.saturating_sub(shown));
    let h = shown as u32 * m.line + 16;
    render::fill_rect(fb, x, y, w, h, theme::SHEET);
    render::draw_thick_border(
        fb,
        x,
        y,
        w,
        h,
        2,
        if edit.focus == 0 {
            theme::INK
        } else {
            theme::RULE_STRONG
        },
    );
    for line in 0..shown {
        let start = (first + line) * cols;
        let text: String = chars.iter().skip(start).take(cols).collect();
        let ly = y + 8 + (line as u32 * m.line) as i32;
        render::draw_text(
            fb,
            x + 10,
            ly,
            &text,
            m.body,
            theme::INK,
            Some(theme::SHEET),
        );
    }
    if edit.focus == 0 && caret_line >= first && caret_line < first + shown {
        let cx = x + 10 + ((caret % cols) as u32 * render::font_width(m.body)) as i32;
        let cy = y + 8 + ((caret_line - first) as u32 * m.line) as i32;
        let fw = render::font_width(m.body);
        render::fill_rect(fb, cx, cy, fw, render::font_height(m.body), theme::INK);
        if let Some(ch) = chars.get(caret) {
            render::draw_char(fb, cx, cy, *ch, m.body, theme::SHEET, Some(theme::INK));
        }
    }
    y + h as i32
}

fn run_boot(fb: &FramebufferInfo, menu: &mut BootMenu, default: usize) -> BootResult {
    let mut cursor = CursorRenderer::new();
    let mut state = BState::new(menu.entry_count(), menu.selected, menu.timeout_seconds);
    state.default = default;
    keep_boot_selection_visible(fb, &mut state);
    let mut buttons = paint_boot(fb, menu, &state);
    let mut hover = Hover::default();
    let origin = mouse_cursor::position();
    loop {
        poll_and_render_cursor(fb, &mut cursor);
        // Tabs are not live while the command-line editor owns the keys.
        let tabs = state
            .edit
            .is_none()
            .then_some((NavItem::Boot, &state.focus));
        track_hover(fb, &mut cursor, &mut hover, tabs);
        if deliberate_pointer_motion(origin, mouse_cursor::position())
            && cancel_boot_countdown(menu, &mut state)
        {
            keep_boot_selection_visible(fb, &mut state);
            buttons = cursor.while_hidden(fb, || paint_boot(fb, menu, &state));
            hover.reset();
        }
        let hovered = boot_hit(fb, menu, &state);
        if hovered != state.hovered {
            let previous = core::mem::replace(&mut state.hovered, hovered);
            cursor.while_hidden(fb, || {
                for i in previous.into_iter().chain(hovered) {
                    paint_boot_row(fb, menu, &state, i);
                }
            });
        }
        if let Some(key) = menu_common::read_key() {
            let mut viewport_only = matches!(key, KeyPress::MouseScroll(_));
            cancel_boot_countdown(menu, &mut state);
            if state.edit.is_some() {
                match boot_edit_key(fb, menu, &mut state, key, &buttons) {
                    Some(result) => {
                        cursor.hide(fb);
                        return result;
                    }
                    None => {
                        buttons = cursor.while_hidden(fb, || paint_boot(fb, menu, &state));
                        hover.reset();
                        delay_ms(8);
                        continue;
                    }
                }
            }
            let actions = boot_actions(menu, &state);
            let mut activate: Option<usize> = None;
            match chrome_key(fb, key, &mut state.focus, NavItem::Boot, actions) {
                Some(FocusEvent::Navigate(i)) => {
                    cursor.hide(fb);
                    return BootResult::Nav(nav_at(i));
                }
                // Space activates buttons, but never the one that boots.
                Some(FocusEvent::Action(i)) if !(i == 0 && key == KeyPress::Char(' ')) => {
                    activate = Some(i)
                }
                Some(FocusEvent::Action(_)) => {}
                Some(FocusEvent::Moved) => {}
                None => match key {
                    KeyPress::Enter if state.focus.group == Group::Content => activate = Some(0),
                    KeyPress::Char('e' | 'E') => activate = Some(1),
                    KeyPress::Up | KeyPress::Char('k') if state.focus.group == Group::Content => {
                        state.sel_prev()
                    }
                    KeyPress::Down | KeyPress::Char('j') if state.focus.group == Group::Content => {
                        state.sel_next()
                    }
                    KeyPress::Home | KeyPress::End | KeyPress::PageUp | KeyPress::PageDown
                        if state.focus.group == Group::Content =>
                    {
                        state.sel = page_selection(
                            key,
                            state.sel,
                            state.count,
                            boot_visible_slots(fb, &state),
                        )
                        .unwrap_or(state.sel);
                    }
                    KeyPress::Char('r' | 'R') => {
                        cursor.hide(fb);
                        let backdrop = || {
                            paint_boot(fb, menu, &state);
                        };
                        confirm_reset(fb, &backdrop);
                    }
                    KeyPress::MouseScroll(delta) => {
                        let slots = boot_visible_slots(fb, &state);
                        controls::scroll(&mut state.scroll_offset, delta, state.count, slots);
                    }
                    KeyPress::MouseClick { x, y } => {
                        let l = boot_layout(fb, state.countdown > 0);
                        let m = Metrics::for_fb(fb);
                        if controls::scroll_track(
                            &mut state.scroll_offset,
                            (l.list.0, l.rows_y, l.list.2, l.slots as u32 * m.row),
                            (x as i32, y as i32),
                            state.count,
                            l.slots,
                        ) {
                            viewport_only = true;
                        } else if let Some(i) = buttons
                            .iter()
                            .position(|r| dialog::contains(*r, x as i32, y as i32))
                        {
                            state.focus.group = Group::Actions;
                            state.focus.action = i;
                            activate = Some(i);
                        } else if let Some(i) = state.hovered {
                            state.sel = i;
                            state.focus.group = Group::Content;
                        }
                    }
                    _ => {}
                },
            }
            match activate {
                Some(0) => {
                    cursor.hide(fb);
                    return BootResult::Selected(state.sel);
                }
                Some(_) => {
                    if let Some(entry) = menu.entries.get(state.sel)
                        && let Some(cmdline) = entry.get_cmdline()
                    {
                        if boot_layout(fb, false).side.is_some() {
                            let mut editor = dialog::Editor::with_limit(cmdline, 511);
                            editor.space_commits = false;
                            state.edit = Some(editor);
                        } else {
                            cursor.hide(fb);
                            let edited = {
                                let backdrop = || {
                                    paint_boot(fb, menu, &state);
                                };
                                dialog::input_with(
                                    fb,
                                    &backdrop,
                                    None,
                                    "Command line (this boot only)",
                                    "Not saved. Enter boots with this command line.",
                                    cmdline,
                                    511,
                                    false,
                                    |_| Ok(()),
                                )
                            };
                            if let Some(text) = edited {
                                return apply_cmdline_and_boot(menu, state.sel, &text);
                            }
                        }
                    }
                }
                None => {}
            }
            if !viewport_only && state.focus.group == Group::Content {
                keep_boot_selection_visible(fb, &mut state);
            }
            menu.selected = state.sel;
            buttons = cursor.while_hidden(fb, || paint_boot(fb, menu, &state));
            hover.reset();
        }
        if state.countdown > 0 && state.tick.is_expired() {
            state.countdown -= 1;
            state.tick = Timeout::from_ms(1000);
            if state.countdown == 0 {
                cursor.hide(fb);
                return BootResult::Selected(state.sel);
            }
            cursor.while_hidden(fb, || paint_boot_strip(fb, menu, &state));
        }
        delay_ms(8);
    }
}

fn apply_cmdline_and_boot(menu: &mut BootMenu, index: usize, text: &str) -> BootResult {
    // Record the edit as the menu's one-shot override; the entry keeps its
    // discovered command line and the boot path applies this to a clone.
    if menu.entries.get(index).is_some_and(|e| e.has_cmdline()) {
        let mut edited: heapless::String<512> = heapless::String::new();
        for ch in text.chars() {
            if edited.push(ch).is_err() {
                break;
            }
        }
        menu.set_edited_cmdline(index, edited);
    }
    BootResult::Selected(index)
}

/// Keys while the details pane owns the one-shot command-line editor.
fn boot_edit_key(
    fb: &FramebufferInfo,
    menu: &mut BootMenu,
    state: &mut BState,
    key: KeyPress,
    buttons: &[Rect],
) -> Option<BootResult> {
    let edit = state.edit.as_mut()?;
    let event = match key {
        KeyPress::F8 => {
            layout::toggle_text_size(fb);
            return None;
        }
        KeyPress::MouseClick { x, y } => {
            if buttons
                .first()
                .is_some_and(|r| dialog::contains(*r, x as i32, y as i32))
            {
                dialog::EditEvent::Apply
            } else if buttons
                .get(1)
                .is_some_and(|r| dialog::contains(*r, x as i32, y as i32))
            {
                dialog::EditEvent::Cancel
            } else {
                dialog::EditEvent::Changed
            }
        }
        // Buttons are drawn Boot-then-Cancel; the editor's stops are field,
        // Cancel, Apply. Map Tab order to the visual order.
        KeyPress::Tab => {
            edit.focus = match edit.focus {
                0 => 2,
                2 => 1,
                _ => 0,
            };
            dialog::EditEvent::Changed
        }
        KeyPress::BackTab => {
            edit.focus = match edit.focus {
                0 => 1,
                1 => 2,
                _ => 0,
            };
            dialog::EditEvent::Changed
        }
        key => edit.key(key),
    };
    match event {
        dialog::EditEvent::Apply => {
            let text = state.edit.take()?.value;
            Some(apply_cmdline_and_boot(menu, state.sel, &text))
        }
        dialog::EditEvent::Cancel => {
            state.edit = None;
            state.focus.group = Group::Content;
            None
        }
        dialog::EditEvent::Changed => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::storage::StorageId;
    use crate::fs::gpt::Partition;
    use crate::menu::{BootCategory, BootEntry, BootEntryKind};
    fn framebuffer(mem: &mut [u32], width: u32, height: u32) -> FramebufferInfo {
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
    fn boot_menu(count: usize) -> BootMenu {
        let mut menu = BootMenu::new();
        for i in 0..count {
            let mut name = heapless::String::new();
            let _ = core::fmt::write(&mut name, format_args!("Entry {i}"));
            menu.add_entry(BootEntry {
                name,
                path: heapless::String::new(),
                storage: StorageId::Nvme {
                    controller_id: 0,
                    nsid: 1,
                },
                pci: None,
                partition_num: 1,
                partition: Partition {
                    type_guid: [0; 16],
                    partition_guid: [0; 16],
                    first_lba: 0,
                    last_lba: 0,
                    attributes: 0,
                    is_esp: true,
                    block_size: 512,
                },
                kind: BootEntryKind::Uefi,
                category: BootCategory::Uefi,
            });
        }
        menu
    }
    #[test]
    fn page_navigation_is_bounded_and_handles_empty_lists() {
        assert_eq!(page_selection(KeyPress::End, 0, 40, 6), Some(39));
        assert_eq!(page_selection(KeyPress::Home, 30, 40, 6), Some(0));
        assert_eq!(page_selection(KeyPress::PageDown, 38, 40, 6), Some(39));
        assert_eq!(page_selection(KeyPress::PageUp, 2, 40, 6), Some(0));
        assert_eq!(page_selection(KeyPress::PageDown, 0, 0, 6), None);
    }
    #[test]
    fn activating_the_current_navigation_tab_does_not_leave_the_screen() {
        let fb = framebuffer(&mut [], 640, 480);
        let mut focus = Focus::new(nav_item_index(NavItem::Firmware));
        focus.group = Group::Navigation;
        assert_eq!(
            chrome_key(&fb, KeyPress::Enter, &mut focus, NavItem::Firmware, 4),
            Some(FocusEvent::Moved)
        );
        focus.group = Group::Content;
        assert_eq!(
            chrome_key(&fb, KeyPress::Char(' '), &mut focus, NavItem::Boot, 2),
            None
        );
    }

    #[test]
    fn backing_out_of_no_media_subscreens_returns_to_the_restart_screen() {
        assert_eq!(
            no_media_destination(NavItem::Firmware, ScreenNav::Back),
            Some(NavItem::Boot)
        );
        #[cfg(feature = "secure-boot")]
        assert_eq!(
            no_media_destination(NavItem::Security, ScreenNav::Back),
            Some(NavItem::Boot)
        );
        assert_eq!(no_media_destination(NavItem::Boot, ScreenNav::Back), None);
    }

    #[test]
    fn mouse_jitter_does_not_cancel_unattended_boot() {
        for x in 393..408 {
            assert!(!deliberate_pointer_motion((400, 300), (x, 301)));
        }
        assert!(deliberate_pointer_motion((400, 300), (408, 300)));
        assert!(deliberate_pointer_motion((400, 300), (400, 292)));
    }
    #[test]
    fn short_boot_framebuffer_requires_text_fallback() {
        let mut mem = std::vec![0; 800 * 240];
        assert!(!supports_framebuffer(&framebuffer(&mut mem, 800, 240)));
    }
    #[test]
    fn countdown_cancellation_survives_returning_from_settings() {
        let mut menu = boot_menu(1);
        menu.timeout_seconds = 5;
        let mut state = BState::new(1, 0, 5);
        assert!(cancel_boot_countdown(&mut menu, &mut state));
        let returned = BState::new(1, menu.selected, menu.timeout_seconds);
        assert_eq!(returned.countdown, 0);
        assert!(!cancel_boot_countdown(&mut menu, &mut state));
    }
    #[test]
    fn hover_cannot_erase_the_offscreen_selections_region_focus() {
        let menu = boot_menu(20);
        let mut pixels = std::vec![0; 640 * 400];
        let fb = framebuffer(&mut pixels, 640, 400);
        let mut state = BState::new(20, 0, 0);
        state.scroll_offset = 2;
        paint_boot(&fb, &menu, &state);
        state.hovered = Some(2);
        paint_boot_row(&fb, &menu, &state, 2);
        let mut expected = std::vec![0; pixels.len()];
        paint_boot(&framebuffer(&mut expected, 640, 400), &menu, &state);
        assert!(
            pixels == expected,
            "hover must preserve the complete region outline"
        );
    }

    #[test]
    fn hover_repaint_and_focus_geometry_match_full_repaint() {
        let menu = boot_menu(20);
        for (width, height) in [(640, 400), (800, 600), (1024, 768), (1920, 1080)] {
            let mut pixels = std::vec![0; width as usize * height as usize];
            let fb = framebuffer(&mut pixels, width, height);
            let mut state = BState::new(20, 0, 0);
            paint_boot(&fb, &menu, &state);
            let mut cursor = CursorRenderer::new();
            for i in 0..20 {
                state.sel = i;
                state.hovered = None;
                keep_boot_selection_visible(&fb, &mut state);
                paint_boot(&fb, &menu, &state);
                let row = row_rect(&fb, &state, i).unwrap();
                cursor.update(&fb, row.0 + 30, row.1 + 10);
                state.hovered = Some(i);
                cursor.while_hidden(&fb, || paint_boot_row(&fb, &menu, &state, i));
                cursor.hide(&fb);
                let mut expected = std::vec![0; pixels.len()];
                paint_boot(&framebuffer(&mut expected, width, height), &menu, &state);
                assert!(
                    pixels == expected,
                    "hover repaint differs at {width}x{height}, row {i}"
                );
                state.hovered = None;
                paint_boot_row(&fb, &menu, &state, i);
                paint_boot(&framebuffer(&mut expected, width, height), &menu, &state);
                assert!(
                    pixels == expected,
                    "hover removal differs at {width}x{height}, row {i}"
                );
                let (_, y, _, h) = row_rect(&fb, &state, i).unwrap();
                let (_, cy, _, ch) = canvas(&fb);
                assert!(y + h as i32 <= cy + ch as i32);
            }
        }
    }

    #[test]
    fn countdown_strip_repaint_matches_full_repaint() {
        let menu = boot_menu(3);
        let (width, height) = (1024, 768);
        let mut pixels = std::vec![0; width as usize * height as usize];
        let fb = framebuffer(&mut pixels, width, height);
        let mut state = BState::new(3, 0, 5);
        paint_boot(&fb, &menu, &state);
        state.countdown = 3;
        paint_boot_strip(&fb, &menu, &state);
        let mut expected = std::vec![0; pixels.len()];
        paint_boot(&framebuffer(&mut expected, width, height), &menu, &state);
        assert!(pixels == expected);
    }

    #[test]
    fn long_multibyte_command_lines_paint_without_splitting_characters() {
        let (width, height) = (1024, 768);
        let mut pixels = std::vec![0; width as usize * height as usize];
        let fb = framebuffer(&mut pixels, width, height);
        let mut menu = boot_menu(1);
        let mut cmdline = heapless::String::<512>::new();
        while cmdline.push_str("é ünïcødé ").is_ok() {}
        menu.entries[0].kind = BootEntryKind::BlsLinux {
            linux_path: heapless::String::new(),
            initrd_paths: heapless::Vec::new(),
            cmdline,
        };
        let state = BState::new(1, 0, 0);
        paint_boot(&fb, &menu, &state);
    }

    #[test]
    fn editor_and_actions_remain_visible_with_long_paths_and_without_a_side_pane() {
        let mut menu = boot_menu(1);
        menu.entries[0].kind = BootEntryKind::BlsLinux {
            linux_path: heapless::String::try_from("/very-long-kernel-path/".repeat(5).as_str())
                .unwrap(),
            initrd_paths: {
                let mut paths = heapless::Vec::new();
                paths
                    .push(
                        heapless::String::try_from("/very-long-initrd-path/".repeat(5).as_str())
                            .unwrap(),
                    )
                    .unwrap();
                paths
            },
            cmdline: heapless::String::try_from("console=ttyS0 root=/dev/sda1").unwrap(),
        };
        for (width, height) in [(900, 600), (1024, 600), (1024, 768)] {
            let mut pixels = std::vec![0; width as usize * height as usize];
            let fb = framebuffer(&mut pixels, width, height);
            let mut state = BState::new(1, 0, 0);
            state.edit = Some(dialog::Editor::new("one-shot draft"));
            let buttons = paint_boot(&fb, &menu, &state);
            assert_eq!(buttons.len(), 2);
            assert!(
                buttons[1].1 > buttons[0].1,
                "Boot then Cancel, not the narrow non-edit actions"
            );
            assert_eq!(state.edit.as_ref().unwrap().value, "one-shot draft");
            let (_, cy, _, ch) = canvas(&fb);
            assert!(buttons[1].1 + buttons[1].3 as i32 <= cy + ch as i32);
        }
    }

    #[test]
    fn disk_details_distinguish_controllers_and_namespaces() {
        use crate::drivers::storage::StorageId;
        assert_ne!(
            storage_identity(StorageId::Ahci {
                controller_id: 0,
                port: 1
            }),
            storage_identity(StorageId::Ahci {
                controller_id: 1,
                port: 1
            })
        );
        assert!(
            storage_identity(StorageId::Nvme {
                controller_id: 2,
                nsid: 3
            })
            .contains("namespace 3")
        );
        assert!(
            storage_identity(StorageId::Usb {
                controller_id: 4,
                device_addr: 5
            })
            .contains("controller 4")
        );
    }

    #[test]
    fn x61_layout_has_details_pane_and_room_for_rows() {
        let fb = framebuffer(&mut [], 1024, 768);
        let l = boot_layout(&fb, true);
        assert!(l.side.is_some() && l.bar.is_none() && l.disk_x.is_some());
        assert!(l.slots >= 10, "{}", l.slots);
        let narrow = framebuffer(&mut [], 640, 480);
        let l = boot_layout(&narrow, false);
        assert!(l.side.is_none() && l.bar.is_some());
    }
}
