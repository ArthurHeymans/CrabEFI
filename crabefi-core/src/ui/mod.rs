//! Firmware services for the shared setup UI in `crabefi-ui`.
//!
//! The screens are portable; this module supplies firmware input, time,
//! Secure Boot actions and platform settings, and runs the screens to
//! completion. Reset outcomes restart the machine here.
use crate::FramebufferConfig;
#[cfg(feature = "secure-boot")]
use alloc::boxed::Box;
#[cfg(feature = "secure-boot")]
use alloc::vec::Vec;
#[cfg(feature = "secure-boot")]
use core::any::Any;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Context, Poll};
use crabefi_ui::screens::{self as shared, layout::TextSize};
use crabefi_ui::{Backend, Outcome, Surface};

pub use shared::{NavItem, ScreenNav, supports_framebuffer};

#[cfg(feature = "secure-boot")]
mod security_backend;

#[cfg(feature = "secure-boot")]
pub mod secure_boot {
    /// The Security page, for menus outside the shared Boot page.
    pub fn show(fb: &crate::FramebufferConfig) -> super::ScreenNav {
        let surface = super::surface(fb);
        super::finish(embassy_futures::block_on(super::shared::secure_boot::show(
            &surface,
        )))
    }
}

/// The F8 text size outlives each page's surface.
static TEXT_SIZE: AtomicU8 = AtomicU8::new(0);

struct FirmwareBackend;
impl Backend for FirmwareBackend {
    fn poll_pointer(&mut self) -> (i32, i32) {
        crate::drivers::mouse_cursor::poll();
        crate::drivers::mouse_cursor::position()
    }
    fn read_key(&mut self) -> Option<crabefi_ui::KeyPress> {
        crate::menu_common::read_key()
    }
    fn now_ms(&self) -> u64 {
        (crate::time::read_counter() as u128 * 1000
            / crate::time::counter_frequency().max(1) as u128) as u64
    }
    fn poll_frame(&mut self, _: &mut Context<'_>) -> Poll<()> {
        crate::time::delay_ms(8);
        Poll::Ready(())
    }
    fn text_size(&self) -> TextSize {
        match TEXT_SIZE.load(Ordering::Relaxed) {
            1 => TextSize::Large,
            2 => TextSize::Compact,
            _ => TextSize::Auto,
        }
    }
    fn set_text_size(&mut self, size: TextSize) {
        let value = match size {
            TextSize::Auto => 0,
            TextSize::Large => 1,
            TextSize::Compact => 2,
        };
        TEXT_SIZE.store(value, Ordering::Relaxed);
    }
    fn firmware_page(&mut self) -> Option<crabefi_ui::FirmwarePage> {
        let hooks = crate::handoff::callbacks().hooks?;
        hooks.firmware_settings_available().then(|| {
            crabefi_ui::FirmwarePage::Platform(alloc::boxed::Box::new(move || {
                hooks.show_graphical_firmware_settings()
            }))
        })
    }
    #[cfg(feature = "secure-boot")]
    fn security_state(&self) -> crabefi_ui::SecurityState {
        let state = crate::efi::auth::secure_boot_state();
        let keys = crate::efi::auth::enrollment::get_enrollment_status();
        crabefi_ui::SecurityState {
            requested: state.requested,
            setup_mode: state.setup_mode,
            enforcing: state.enforcing,
            keys: crabefi_ui::KeyCounts {
                pk: keys.pk_count,
                kek: keys.kek_count,
                db: keys.db_count,
                dbx: keys.dbx_count,
            },
            has_stored_keys: crate::efi::auth::boot::has_stored_keys(),
            keys_incomplete: !crate::efi::auth::boot::key_inventory_complete(),
        }
    }
    #[cfg(feature = "secure-boot")]
    fn security_action(&mut self, action: crabefi_ui::SecurityAction) -> (&'static str, bool) {
        use crate::efi::auth;
        use crabefi_ui::SecurityAction;
        match action {
            SecurityAction::Toggle => crate::secure_boot_menu::toggle_secure_boot_action(),
            SecurityAction::EnrollDefaults if !auth::is_setup_mode() => {
                ("Keys already enrolled", false)
            }
            SecurityAction::EnrollDefaults => match auth::boot::enroll_and_persist_default_keys() {
                Ok(_) => ("Default keys enrolled.", true),
                Err(_) => ("Failed to enroll keys; check variable storage.", false),
            },
            SecurityAction::ClearKeys => match auth::boot::clear_all_keys() {
                Ok(_) => ("All keys cleared; Setup Mode restored.", true),
                Err(error) => (crate::secure_boot_menu::clear_keys_error(error), false),
            },
            _ => ("Use the reviewed import", false),
        }
    }
    #[cfg(feature = "secure-boot")]
    fn prepare_import(
        &mut self,
        action: crabefi_ui::SecurityAction,
    ) -> Result<crabefi_ui::ImportReview, &'static str> {
        security_backend::prepare(action)
    }
    #[cfg(feature = "secure-boot")]
    fn commit_import(&mut self, payload: Box<dyn Any>) -> Result<&'static str, &'static str> {
        security_backend::commit(payload)
    }
    #[cfg(feature = "secure-boot")]
    fn enrolled_keys(&self) -> Vec<shared::dialog::ReviewSection> {
        security_backend::enrolled_key_sections()
    }
}

pub(crate) fn surface(fb: &FramebufferConfig) -> Surface {
    let surface = Surface::new(*fb, FirmwareBackend);
    surface.set_pointer(crate::drivers::mouse_cursor::position());
    surface
}

/// A page's result; a confirmed restart resets here.
#[cfg(any(feature = "secure-boot", feature = "cfr"))]
pub(crate) fn finish(result: ScreenNav) -> ScreenNav {
    if matches!(result, ScreenNav::Reset) {
        crate::reset_system();
    }
    result
}

/// Show the graphical boot menu; returns the selected entry index. Boot
/// [`BootMenu::entry_for_boot`](crabefi_ui::BootMenu::entry_for_boot) for
/// that index so a one-shot command-line edit made in the menu applies to
/// this boot attempt.
pub fn show_graphical_menu(menu: &mut crate::menu::BootMenu) -> Option<usize> {
    menu.clear_edited_cmdline();
    let fb = crate::handoff::framebuffer()?;
    if !supports_framebuffer(&fb) {
        return crate::menu::show_menu(menu);
    }
    let surface = surface(&fb);
    match embassy_futures::block_on(shared::show_graphical_menu(&surface, &mut menu.menu)) {
        Outcome::Boot(index) => Some(index),
        Outcome::Reset => crate::reset_system(),
        Outcome::Exit => None,
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
    let surface = surface(&fb);
    if embassy_futures::block_on(shared::show_no_media_screen(&surface)) == Outcome::Reset {
        crate::reset_system();
    }
}
fn no_media_text(fb: &FramebufferConfig) {
    use crate::menu_common::{self, KeyPress};
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
        crate::time::delay_ms(10);
    }
}
