//! Keyboard-first, native firmware setup UI. Shared focus and physical geometry;
//! domain state and authentication remain owned by their existing backends.

pub mod controls;
pub mod dialog;
pub mod firmware_settings;
pub mod layout;
pub mod render;
#[cfg(feature = "secure-boot")]
pub mod secure_boot;
pub mod theme;

use crate::FramebufferConfig as FramebufferInfo;
use crate::cursor::CursorRenderer;
use crate::drivers::mouse_cursor;
use crate::menu::{BootCategory, BootMenu};
use crate::menu_common::{self, KeyPress};
use crate::time::{Timeout, delay_ms};
use controls::{ButtonKind, Control, Focus, FocusEvent, Group, Role};
use layout::Metrics;
use render::FontSize;

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
    (NavItem::Boot, "Boot [B]"),
    #[cfg(feature = "secure-boot")]
    (NavItem::Security, "Security [S]"),
    (NavItem::Firmware, "Settings [F]"),
];
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
    // SAFETY: the platform supplied this framebuffer mapping.
    unsafe { fb.clear(theme::BG.r, theme::BG.g, theme::BG.b) };
}

pub fn draw_header(fb: &FramebufferInfo) {
    let m = Metrics::for_fb(fb);
    let (x, _, w, _) = m.canvas(fb);
    render::fill_rect(fb, 0, 0, fb.width, m.header, theme::SIDE);
    render::draw_text(fb, x, 10, "CrabEFI", m.body, theme::TEXT, Some(theme::SIDE));
    render::draw_text_right(
        fb,
        x,
        12,
        w,
        "Text size [F8]",
        m.small,
        theme::TEXT_DIM,
        Some(theme::SIDE),
    );
    render::fill_rect(fb, 0, m.header as i32 - 1, fb.width, 1, theme::BORDER);
}
fn nav_rect(fb: &FramebufferInfo, i: usize) -> Rect {
    let m = Metrics::for_fb(fb);
    let (x, _, w, _) = m.canvas(fb);
    let width = (w / NAV_ITEMS.len() as u32).min(200);
    (
        x + (i as u32 * width) as i32,
        if m.body == FontSize::Heading { 48 } else { 40 },
        width - 8,
        m.button,
    )
}
pub(crate) fn draw_navigation(
    fb: &FramebufferInfo,
    active: NavItem,
    focus: Option<usize>,
    hovered: Option<NavItem>,
) {
    let m = Metrics::for_fb(fb);
    for (i, (nav, label)) in NAV_ITEMS.iter().enumerate() {
        let rect = nav_rect(fb, i);
        let mut c = Control::new(i as u64, Role::Button, label);
        c.focused = focus == Some(i);
        c.selected = active == *nav;
        let bg = controls::frame(fb, rect, &c, hovered == Some(*nav));
        render::draw_text_centered(
            fb,
            rect.0 + 8,
            rect.1 + (rect.3 - render::font_height(m.small)) as i32 / 2,
            rect.2 - 16,
            label,
            m.small,
            theme::TEXT,
            Some(bg),
        );
    }
}
/// Compatibility name for platform integrations; navigation now occupies the top bar.
pub fn draw_sidebar(fb: &FramebufferInfo, active: NavItem, hovered: Option<NavItem>) {
    draw_navigation(fb, active, None, hovered);
}
pub(crate) fn draw_shell(
    fb: &FramebufferInfo,
    active: NavItem,
    focus: &Focus,
    hovered: Option<NavItem>,
) {
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
    NAV_ITEMS
        .iter()
        .enumerate()
        .find(|(i, _)| dialog::contains(nav_rect(fb, *i), x, y))
        .map(|(_, (nav, _))| *nav)
}
pub(crate) fn sidebar_hit() -> Option<NavItem> {
    let fb = crate::handoff::framebuffer()?;
    let (x, y) = mouse_cursor::position();
    navigation_hit(&fb, x, y)
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

/// Handle common focus/navigation only. Callers still gate leaving unsaved forms.
pub(crate) fn chrome_key(
    fb: &FramebufferInfo,
    key: KeyPress,
    focus: &mut Focus,
    active: NavItem,
    actions: usize,
) -> Option<FocusEvent> {
    let (cx, _, cw, _) = canvas(fb);
    let resize = key == KeyPress::F8
        || matches!(key, KeyPress::MouseClick { x, y }
        if dialog::contains((cx + cw as i32 - 180, 4, 180, 32), x as i32, y as i32));
    if resize {
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

pub fn draw_footer(fb: &FramebufferInfo, hint: &str) {
    let m = Metrics::for_fb(fb);
    let y = fb.height.saturating_sub(m.footer) as i32;
    let (x, _, w, _) = m.canvas(fb);
    render::fill_rect(fb, 0, y, fb.width, m.footer, theme::SIDE);
    render::fill_rect(fb, 0, y, fb.width, 1, theme::BORDER);
    render::draw_text(
        fb,
        x,
        y + 5,
        &render::ellipsize(hint, w, m.small),
        m.small,
        theme::TEXT_DIM,
        Some(theme::SIDE),
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
pub(crate) fn confirm_reset(fb: &FramebufferInfo, nav: NavItem) {
    if dialog::choose(
        fb,
        nav,
        "Restart the system?",
        "The system will restart now. Attach any new boot devices before restarting.",
        &["Cancel", "Restart"],
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
    let Some((top, thumb)) = controls::scrollbar_thumb(h, total, offset, visible) else {
        return;
    };
    render::fill_rect(fb, x, y, 12, h, theme::CONT_HIGH);
    render::fill_rect(fb, x, y + top as i32, 12, thumb, theme::TEXT_DIM);
}

pub fn show_graphical_menu(menu: &mut BootMenu) -> Option<usize> {
    let fb = crate::handoff::framebuffer()?;
    if !supports_framebuffer(&fb) {
        return crate::menu::show_menu(menu);
    }
    let mut screen = NavItem::Boot;
    loop {
        let next = match screen {
            NavItem::Boot => match run_boot(&fb, menu) {
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
                "Connect a boot device, then press R to restart. Settings remain available.",
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

pub(crate) fn empty_screen(
    fb: &FramebufferInfo,
    nav: NavItem,
    title: &str,
    message: &str,
) -> ScreenNav {
    let mut cursor = CursorRenderer::new();
    let mut focus = Focus::new(nav_item_index(nav));
    focus.group = Group::Navigation;
    loop {
        cursor.hide(fb);
        draw_shell(fb, nav, &focus, None);
        let m = Metrics::for_fb(fb);
        let (x, y, w, h) = canvas(fb);
        render::draw_text(fb, x, y, title, m.title, theme::TEXT, None);
        dialog::wrapped(
            fb,
            (x, y + 48, w, h.saturating_sub(120)),
            message,
            theme::TEXT_DIM,
        );
        let mut c = Control::new(100, Role::Button, "Back");
        c.focused = focus.group == Group::Actions;
        let back = (x, y + h as i32 - m.button as i32, w.min(240), m.button);
        controls::button(fb, back, &c, ButtonKind::Neutral);
        draw_footer(fb, "Tab Focus   Arrows Move   Enter Open   Esc Back");
        loop {
            poll_and_render_cursor(fb, &mut cursor);
            if let Some(key) = menu_common::read_key() {
                match chrome_key(fb, key, &mut focus, nav, 1) {
                    Some(FocusEvent::Navigate(i)) => {
                        cursor.hide(fb);
                        return ScreenNav::Nav(nav_at(i));
                    }
                    Some(FocusEvent::Action(_)) => return ScreenNav::Back,
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
                            confirm_reset(fb, nav);
                            break;
                        }
                        KeyPress::MouseClick { x, y }
                            if dialog::contains(back, x as i32, y as i32) =>
                        {
                            return ScreenNav::Back;
                        }
                        _ => {}
                    },
                }
            }
            delay_ms(8);
        }
    }
}

struct BState {
    sel: usize,
    hovered: Option<usize>,
    scroll_offset: usize,
    countdown: u32,
    init_timeout: u32,
    tick: Timeout,
    count: usize,
    focus: Focus,
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
fn run_boot(fb: &FramebufferInfo, menu: &mut BootMenu) -> BootResult {
    let mut cursor = CursorRenderer::new();
    let mut state = BState::new(menu.entry_count(), menu.selected, menu.timeout_seconds);
    keep_boot_selection_visible(fb, &mut state);
    paint_boot(fb, menu, &state);
    let origin = mouse_cursor::position();
    loop {
        poll_and_render_cursor(fb, &mut cursor);
        if deliberate_pointer_motion(origin, mouse_cursor::position())
            && cancel_boot_countdown(menu, &mut state)
        {
            cursor.while_hidden(fb, || paint_boot_footer(fb, menu, &state));
        }
        let hovered = boot_hit(fb, menu, &state);
        if hovered != state.hovered {
            let previous = core::mem::replace(&mut state.hovered, hovered);
            cursor.while_hidden(fb, || {
                for i in previous.into_iter().chain(hovered) {
                    paint_boot_card(fb, menu, &state, i);
                }
            });
        }
        if let Some(key) = menu_common::read_key() {
            let mut viewport_only = matches!(key, KeyPress::MouseScroll(_));
            cancel_boot_countdown(menu, &mut state);
            match chrome_key(fb, key, &mut state.focus, NavItem::Boot, 2) {
                Some(FocusEvent::Navigate(i)) => {
                    cursor.hide(fb);
                    return BootResult::Nav(nav_at(i));
                }
                Some(FocusEvent::Action(0)) => {
                    cursor.hide(fb);
                    return BootResult::Selected(state.sel);
                }
                Some(FocusEvent::Action(_)) => {
                    cursor.hide(fb);
                    show_boot_details(fb, menu, state.sel);
                }
                Some(FocusEvent::Moved) => {
                    if state.focus.group == Group::Content {
                        keep_boot_selection_visible(fb, &mut state);
                    }
                }
                None => match key {
                    KeyPress::Enter if state.focus.group == Group::Content => {
                        cursor.hide(fb);
                        return BootResult::Selected(state.sel);
                    }
                    KeyPress::Up | KeyPress::Char('k') if state.focus.group == Group::Content => {
                        state.sel_prev()
                    }
                    KeyPress::Down | KeyPress::Char('j') if state.focus.group == Group::Content => {
                        state.sel_next()
                    }
                    KeyPress::Home | KeyPress::End | KeyPress::PageUp | KeyPress::PageDown
                        if state.focus.group == Group::Content =>
                    {
                        state.sel =
                            page_selection(key, state.sel, state.count, boot_visible_slots(fb))
                                .unwrap_or(state.sel);
                    }
                    KeyPress::Char('r' | 'R') => {
                        cursor.hide(fb);
                        confirm_reset(fb, NavItem::Boot);
                    }
                    KeyPress::MouseScroll(delta) => controls::scroll(
                        &mut state.scroll_offset,
                        delta,
                        state.count,
                        boot_visible_slots(fb),
                    ),
                    KeyPress::MouseClick { x, y } => {
                        let actions = boot_action_rects(fb);
                        if controls::scroll_track(
                            &mut state.scroll_offset,
                            boot_list_area(fb),
                            (x as i32, y as i32),
                            state.count,
                            boot_visible_slots(fb),
                        ) {
                            viewport_only = true;
                        } else if dialog::contains(actions[0], x as i32, y as i32) {
                            cursor.hide(fb);
                            return BootResult::Selected(state.sel);
                        } else if dialog::contains(actions[1], x as i32, y as i32) {
                            cursor.hide(fb);
                            show_boot_details(fb, menu, state.sel);
                        } else if let Some(i) = state.hovered {
                            state.sel = i;
                            state.focus.group = Group::Content;
                        }
                    }
                    _ => {}
                },
            }
            if !viewport_only && state.focus.group == Group::Content {
                keep_boot_selection_visible(fb, &mut state);
            }
            menu.selected = state.sel;
            cursor.while_hidden(fb, || paint_boot(fb, menu, &state));
        }
        if state.countdown > 0 && state.tick.is_expired() {
            state.countdown -= 1;
            state.tick = Timeout::from_ms(1000);
            if state.countdown == 0 {
                cursor.hide(fb);
                return BootResult::Selected(state.sel);
            }
            cursor.while_hidden(fb, || paint_boot_footer(fb, menu, &state));
        }
        delay_ms(8);
    }
}
fn boot_action_rects(fb: &FramebufferInfo) -> [Rect; 2] {
    let m = Metrics::for_fb(fb);
    let (x, y, w, h) = canvas(fb);
    let width = ((w - 12) / 2).min(280);
    [
        (x, y + h as i32 - m.button as i32, width, m.button),
        (
            x + width as i32 + 12,
            y + h as i32 - m.button as i32,
            width,
            m.button,
        ),
    ]
}
fn boot_status_height(fb: &FramebufferInfo) -> u32 {
    Metrics::for_fb(fb).line * if canvas(fb).3 < 300 { 1 } else { 2 } + 12
}
fn boot_list_area(fb: &FramebufferInfo) -> Rect {
    let m = Metrics::for_fb(fb);
    let (x, y, w, h) = canvas(fb);
    let heading = render::font_height(m.title) + 16;
    (
        x,
        y + heading as i32,
        if w >= 1050 { w * 3 / 5 } else { w },
        h.saturating_sub(heading + m.button + boot_status_height(fb) + 8),
    )
}
fn boot_visible_slots(fb: &FramebufferInfo) -> usize {
    (boot_list_area(fb).3 / (Metrics::for_fb(fb).entry + 4)).max(1) as usize
}
fn keep_boot_selection_visible(fb: &FramebufferInfo, state: &mut BState) {
    controls::ensure_visible(
        &mut state.scroll_offset,
        state.sel,
        state.count,
        boot_visible_slots(fb),
    );
}
fn card_rect(fb: &FramebufferInfo, state: &BState, index: usize) -> Option<Rect> {
    if index < state.scroll_offset || index >= state.scroll_offset + boot_visible_slots(fb) {
        return None;
    }
    let m = Metrics::for_fb(fb);
    let (x, y, w, _) = boot_list_area(fb);
    Some((
        x,
        y + ((index - state.scroll_offset) as u32 * (m.entry + 4)) as i32,
        w.saturating_sub(controls::SCROLL_GUTTER),
        m.entry,
    ))
}
fn boot_hit(fb: &FramebufferInfo, menu: &BootMenu, state: &BState) -> Option<usize> {
    let (x, y) = mouse_cursor::position();
    (state.scroll_offset..(state.scroll_offset + boot_visible_slots(fb)).min(menu.entry_count()))
        .find(|i| card_rect(fb, state, *i).is_some_and(|r| dialog::contains(r, x, y)))
}
fn paint_boot(fb: &FramebufferInfo, menu: &BootMenu, state: &BState) {
    draw_shell(fb, NavItem::Boot, &state.focus, None);
    let m = Metrics::for_fb(fb);
    let (x, y, w, _) = canvas(fb);
    render::draw_text(fb, x, y, "Choose a boot entry", m.title, theme::TEXT, None);
    for i in
        state.scroll_offset..(state.scroll_offset + boot_visible_slots(fb)).min(menu.entry_count())
    {
        paint_boot_card(fb, menu, state, i);
    }
    paint_boot_scrollbar(fb, menu, state);
    let (lx, ly, lw, lh) = boot_list_area(fb);
    controls::viewport_focus(
        fb,
        (lx, ly, lw, lh),
        state.focus.group == Group::Content,
        state.sel,
        state.scroll_offset,
        boot_visible_slots(fb),
    );
    if w > lw + 40 {
        let rect = (lx + lw as i32 + 16, ly, w - lw - 16, lh);
        let c = Control::new(1000, Role::Option, "Selected entry");
        controls::frame(fb, rect, &c, false);
        if let Some(entry) = menu.entries.get(state.sel) {
            let text = alloc::format!(
                "Selected entry\n\n{}\n\nType: {}\n\nPath: {}\n\nEnter on the list boots this entry. Scrolling does not change the selection.",
                entry.name,
                category_label(entry.category),
                entry.path
            );
            dialog::wrapped(
                fb,
                (rect.0 + 16, rect.1 + 16, rect.2 - 32, rect.3 - 32),
                &text,
                theme::TEXT_DIM,
            );
        }
    }
    paint_boot_footer(fb, menu, state);
}
fn category_label(category: BootCategory) -> &'static str {
    match category {
        BootCategory::Uefi => "UEFI",
        BootCategory::Bls => "Linux",
        BootCategory::Grub => "GRUB",
        BootCategory::Payload => "Payload",
    }
}
fn paint_boot_card(fb: &FramebufferInfo, menu: &BootMenu, state: &BState, index: usize) {
    let Some(rect) = card_rect(fb, state, index) else {
        return;
    };
    let Some(entry) = menu.entries.get(index) else {
        return;
    };
    let m = Metrics::for_fb(fb);
    let mut c = Control::new(index as u64, Role::Option, &entry.name);
    c.focused = state.focus.group == Group::Content && state.sel == index;
    c.selected = state.sel == index;
    c.value = Some(&entry.path);
    let bg = controls::frame(fb, rect, &c, state.hovered == Some(index));
    let label = alloc::format!("{} {}", if c.selected { ">" } else { " " }, entry.name);
    render::draw_text(
        fb,
        rect.0 + 14,
        rect.1 + 6,
        &render::ellipsize(&label, rect.2 - 28, m.body),
        m.body,
        theme::TEXT,
        Some(bg),
    );
    let path = alloc::format!("{}  {}", category_label(entry.category), entry.path);
    render::draw_text(
        fb,
        rect.0 + 30,
        rect.1 + 10 + render::font_height(m.body) as i32,
        &render::ellipsize(&path, rect.2 - 44, m.small),
        m.small,
        theme::TEXT_DIM,
        Some(bg),
    );
    controls::viewport_focus(
        fb,
        boot_list_area(fb),
        state.focus.group == Group::Content,
        state.sel,
        state.scroll_offset,
        boot_visible_slots(fb),
    );
}
fn paint_boot_scrollbar(fb: &FramebufferInfo, menu: &BootMenu, state: &BState) {
    let (x, y, w, h) = boot_list_area(fb);
    draw_scrollbar(
        fb,
        x + w as i32 - 22,
        y,
        h,
        menu.entry_count(),
        state.scroll_offset,
        boot_visible_slots(fb),
    );
}
fn paint_boot_footer(fb: &FramebufferInfo, menu: &BootMenu, state: &BState) {
    let (x, _, w, _) = canvas(fb);
    let actions = boot_action_rects(fb);
    let status_h = boot_status_height(fb);
    let y = actions[0].1 - status_h as i32;
    render::fill_rect(fb, x, y, w, status_h, theme::BG);
    let offscreen = state.sel < state.scroll_offset
        || state.sel >= state.scroll_offset + boot_visible_slots(fb);
    let text = if offscreen {
        alloc::format!("Selected: {}", menu.entries[state.sel].name)
    } else if state.countdown > 0 {
        alloc::format!("Automatic boot in {} s. Any key cancels.", state.countdown)
    } else if state.init_timeout > 0 {
        alloc::string::String::from("Automatic boot cancelled for this session.")
    } else {
        alloc::string::String::from("Click selects an entry. Choose Boot to start it.")
    };
    dialog::wrapped(fb, (x, y, w, status_h - 12), &text, theme::TEXT_DIM);
    for (i, label) in ["Boot selected entry", "Entry details"].iter().enumerate() {
        let mut c = Control::new(2000 + i as u64, Role::Button, label);
        c.focused = state.focus.group == Group::Actions && state.focus.action == i;
        controls::button(
            fb,
            actions[i],
            &c,
            if i == 0 {
                ButtonKind::Primary
            } else {
                ButtonKind::Neutral
            },
        );
    }
    draw_footer(fb, "Tab Focus   Arrows Move   Enter Boot   F8 Text size");
}
fn show_boot_details(fb: &FramebufferInfo, menu: &BootMenu, selected: usize) {
    if let Some(entry) = menu.entries.get(selected) {
        let message = alloc::format!(
            "{}\n\nType: {}\n\nPath: {}",
            entry.name,
            category_label(entry.category),
            entry.path
        );
        dialog::choose(fb, NavItem::Boot, "Boot entry details", &message, &["Back"]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::storage::StorageId;
    use crate::fs::gpt::Partition;
    use crate::menu::{BootEntry, BootEntryKind};
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
        paint_boot_card(&fb, &menu, &state, 2);
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
        for (width, height) in [(640, 400), (800, 600), (1920, 1080)] {
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
                let row = card_rect(&fb, &state, i).unwrap();
                cursor.update(&fb, row.0 + 30, row.1 + 20);
                state.hovered = Some(i);
                cursor.while_hidden(&fb, || paint_boot_card(&fb, &menu, &state, i));
                cursor.hide(&fb);
                let mut expected = std::vec![0; pixels.len()];
                paint_boot(&framebuffer(&mut expected, width, height), &menu, &state);
                assert!(
                    pixels == expected,
                    "hover repaint differs at {width}x{height}, row {i}"
                );
                state.hovered = None;
                paint_boot_card(&fb, &menu, &state, i);
                paint_boot(&framebuffer(&mut expected, width, height), &menu, &state);
                assert!(
                    pixels == expected,
                    "hover removal differs at {width}x{height}, row {i}"
                );
                let (_, y, _, h) = card_rect(&fb, &state, i).unwrap();
                assert!(
                    y + h as i32
                        <= boot_action_rects(&fb)[0].1 - (Metrics::for_fb(&fb).line * 2) as i32
                );
            }
        }
    }
}
