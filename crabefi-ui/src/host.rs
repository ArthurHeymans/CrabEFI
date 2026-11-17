use crate::FramebufferConfig;
use crate::KeyPress;
use crate::screens::dialog::{Block, ReviewSection};
use crate::screens::{controls::PaintedButton, layout::TextSize};
use alloc::{boxed::Box, vec::Vec as OwnedVec};
use core::{
    any::Any,
    cell::{Cell, RefCell},
    ops::Deref,
    task::{Context, Poll},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Boot,
    Security,
    Firmware,
    NoMedia,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiState {
    pub screen: Screen,
    pub selected: Option<usize>,
    pub scroll_offset: usize,
    pub countdown: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Boot(usize),
    Reset,
    Exit,
}
/// Entries in each Secure Boot signature database.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyCounts {
    pub pk: usize,
    pub kek: usize,
    pub db: usize,
    pub dbx: usize,
}
impl KeyCounts {
    pub fn as_array(&self) -> [usize; 4] {
        [self.pk, self.kek, self.db, self.dbx]
    }
}
#[derive(Debug, Clone, Copy, Default)]
pub struct SecurityState {
    pub requested: bool,
    pub setup_mode: bool,
    pub enforcing: bool,
    pub keys: KeyCounts,
    pub has_stored_keys: bool,
    /// Stored key data was malformed or only partly loaded; counts fall short.
    pub keys_incomplete: bool,
}
#[derive(Debug, Clone, Copy)]
pub enum SecurityAction {
    Toggle,
    EnrollDefaults,
    EnrollCustomPk,
    ImportDbx,
    ClearKeys,
}

/// The host owns the verified bytes until the UI's review has completed.
/// Firmware uses an opaque owned payload; no reopening a file after consent.
pub struct ImportReview {
    pub payload: Box<dyn Any>,
    pub intro: OwnedVec<Block>,
    pub sections: OwnedVec<ReviewSection>,
    pub outro: OwnedVec<Block>,
}

/// What the Firmware tab shows. The backend is not borrowed while it runs.
pub enum FirmwarePage {
    /// CFR settings drawn by the shared page on the current surface.
    #[cfg(feature = "cfr")]
    Cfr(alloc::rc::Rc<dyn crate::cfr::SettingsModel>),
    /// A platform-owned settings UI, run to completion. Returns the next page.
    Platform(Box<dyn FnOnce() -> crate::screens::ScreenNav>),
}

/// Services, not UI policy. `poll_frame` yields in an event-loop host and may
/// block in firmware. No borrowed backend guard survives a frame boundary.
pub trait Backend {
    fn poll_pointer(&mut self) -> (i32, i32);
    fn read_key(&mut self) -> Option<KeyPress>;
    fn now_ms(&self) -> u64;
    fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<()>;
    fn firmware_page(&mut self) -> Option<FirmwarePage> {
        None
    }
    #[cfg(feature = "cfr")]
    fn observe_firmware(&mut self, _state: &crate::settings::FirmwareObservation<'_>) {}
    fn security_state(&self) -> SecurityState {
        SecurityState::default()
    }
    fn security_action(&mut self, _action: SecurityAction) -> (&'static str, bool) {
        ("Secure Boot service unavailable", false)
    }
    fn prepare_import(&mut self, _action: SecurityAction) -> Result<ImportReview, &'static str> {
        Err("No key files in this simulated machine")
    }
    fn commit_import(&mut self, _payload: Box<dyn Any>) -> Result<&'static str, &'static str> {
        Err("No verified import")
    }
    fn enrolled_keys(&self) -> OwnedVec<ReviewSection> {
        OwnedVec::new()
    }
    /// The F8 text-size choice a new surface starts with.
    fn text_size(&self) -> TextSize {
        TextSize::Auto
    }
    /// Keep the F8 choice for later surfaces (firmware nests one per page).
    fn set_text_size(&mut self, _size: TextSize) {}
    fn observe(&mut self, _state: UiState) {}
    fn observe_dialog(&mut self, _title: Option<&str>) {}
}

/// A framebuffer and its host services. Drawing primitives still use the
/// unmodified framebuffer type; interactive screens borrow this surface.
pub struct Surface {
    framebuffer: FramebufferConfig,
    backend: RefCell<Box<dyn Backend>>,
    pointer: Cell<(i32, i32)>,
    reset: Cell<bool>,
    /// One Secure Boot snapshot per frame: firmware reads variables for it,
    /// and a single repaint consults it for every header chip and action row.
    security: Cell<Option<SecurityState>>,
    // Paint state of this UI session.
    dim: Cell<bool>,
    text_size: Cell<TextSize>,
    buttons: RefCell<OwnedVec<PaintedButton>>,
    firmware_dirty: Cell<bool>,
}
impl Deref for Surface {
    type Target = FramebufferConfig;
    fn deref(&self) -> &Self::Target {
        &self.framebuffer
    }
}
impl Surface {
    pub fn new(framebuffer: FramebufferConfig, backend: impl Backend + 'static) -> Self {
        let text_size = backend.text_size();
        Self {
            framebuffer,
            backend: RefCell::new(Box::new(backend)),
            pointer: Cell::new((-1, -1)),
            reset: Cell::new(false),
            security: Cell::new(None),
            dim: Cell::new(false),
            text_size: Cell::new(text_size),
            buttons: RefCell::new(OwnedVec::new()),
            firmware_dirty: Cell::new(false),
        }
    }
    /// Whether painting currently targets a dimmed modal backdrop.
    pub fn is_dimmed(&self) -> bool {
        self.dim.get()
    }
    /// Paint `f` with the dimmed palette.
    pub fn dimmed<R>(&self, f: impl FnOnce() -> R) -> R {
        let previous = self.dim.replace(true);
        let result = f();
        self.dim.set(previous);
        result
    }
    pub fn text_size(&self) -> TextSize {
        self.text_size.get()
    }
    pub fn set_text_size(&self, size: TextSize) {
        self.text_size.set(size);
        self.backend.borrow_mut().set_text_size(size);
    }
    /// Buttons painted on the live surface, for pointer hover and clicks.
    pub(crate) fn buttons(&self) -> core::cell::RefMut<'_, OwnedVec<PaintedButton>> {
        self.buttons.borrow_mut()
    }
    /// Firmware settings hold unsaved drafts; shown as "Firmware *".
    pub fn firmware_dirty(&self) -> bool {
        self.firmware_dirty.get()
    }
    pub fn set_firmware_dirty(&self, dirty: bool) {
        self.firmware_dirty.set(dirty);
    }
    pub fn request_reset(&self) {
        self.reset.set(true);
    }
    pub fn reset_requested(&self) -> bool {
        self.reset.get()
    }
    pub fn dialog_scope<'a>(&'a self, title: &str) -> DialogScope<'a> {
        self.observe_dialog(Some(title));
        DialogScope(self)
    }
    pub fn key(&self) -> Option<KeyPress> {
        self.backend.borrow_mut().read_key()
    }
    pub fn position(&self) -> (i32, i32) {
        self.pointer.get()
    }
    pub fn set_pointer(&self, pointer: (i32, i32)) {
        self.pointer.set(pointer);
    }
    pub fn poll_pointer(&self) -> (i32, i32) {
        let pointer = self.backend.borrow_mut().poll_pointer();
        self.pointer.set(pointer);
        pointer
    }
    pub fn now_ms(&self) -> u64 {
        self.backend.borrow().now_ms()
    }
    pub async fn wait_for_frame(&self) {
        self.security.set(None);
        core::future::poll_fn(|cx| self.backend.borrow_mut().poll_frame(cx)).await
    }
    pub fn firmware_page(&self) -> Option<FirmwarePage> {
        self.backend.borrow_mut().firmware_page()
    }
    #[cfg(feature = "cfr")]
    pub fn observe_firmware(&self, state: &crate::settings::FirmwareObservation<'_>) {
        self.backend.borrow_mut().observe_firmware(state);
    }
    pub fn security_state(&self) -> SecurityState {
        if let Some(state) = self.security.get() {
            return state;
        }
        let state = self.backend.borrow().security_state();
        self.security.set(Some(state));
        state
    }
    pub fn security_action(&self, action: SecurityAction) -> (&'static str, bool) {
        let result = self.backend.borrow_mut().security_action(action);
        self.security.set(None);
        result
    }
    pub fn prepare_import(&self, action: SecurityAction) -> Result<ImportReview, &'static str> {
        self.backend.borrow_mut().prepare_import(action)
    }
    pub fn commit_import(&self, payload: Box<dyn Any>) -> Result<&'static str, &'static str> {
        let result = self.backend.borrow_mut().commit_import(payload);
        self.security.set(None);
        result
    }
    pub fn enrolled_keys(&self) -> OwnedVec<ReviewSection> {
        self.backend.borrow().enrolled_keys()
    }
    pub fn observe(&self, state: UiState) {
        self.backend.borrow_mut().observe(state);
    }
    pub fn observe_dialog(&self, title: Option<&str>) {
        self.backend.borrow_mut().observe_dialog(title);
    }
}

pub struct DialogScope<'a>(&'a Surface);
impl Drop for DialogScope<'_> {
    fn drop(&mut self) {
        self.0.observe_dialog(None);
    }
}

#[cfg(test)]
pub(crate) fn test_surface(framebuffer: FramebufferConfig) -> Surface {
    struct TestBackend;
    impl Backend for TestBackend {
        fn poll_pointer(&mut self) -> (i32, i32) {
            (-1, -1)
        }
        fn read_key(&mut self) -> Option<KeyPress> {
            None
        }
        fn now_ms(&self) -> u64 {
            0
        }
        fn poll_frame(&mut self, _: &mut Context<'_>) -> Poll<()> {
            Poll::Ready(())
        }
    }
    Surface::new(framebuffer, TestBackend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;

    struct CountingBackend(Rc<Cell<usize>>);
    impl Backend for CountingBackend {
        fn poll_pointer(&mut self) -> (i32, i32) {
            (-1, -1)
        }
        fn read_key(&mut self) -> Option<KeyPress> {
            None
        }
        fn now_ms(&self) -> u64 {
            0
        }
        fn poll_frame(&mut self, _: &mut Context<'_>) -> Poll<()> {
            Poll::Ready(())
        }
        fn security_state(&self) -> SecurityState {
            self.0.set(self.0.get() + 1);
            SecurityState::default()
        }
        fn security_action(&mut self, _: SecurityAction) -> (&'static str, bool) {
            ("done", true)
        }
    }

    #[test]
    fn security_state_is_read_once_per_frame_and_after_actions() {
        let reads = Rc::new(Cell::new(0));
        let mut mem = [0u32; 4];
        let surface = Surface::new(
            FramebufferConfig {
                physical_address: mem.as_mut_ptr() as u64,
                width: 2,
                height: 2,
                stride: 2,
                bits_per_pixel: 32,
                red_mask_pos: 16,
                red_mask_size: 8,
                green_mask_pos: 8,
                green_mask_size: 8,
                blue_mask_pos: 0,
                blue_mask_size: 8,
            },
            CountingBackend(reads.clone()),
        );
        for _ in 0..10 {
            surface.security_state();
        }
        assert_eq!(reads.get(), 1);
        surface.security_action(SecurityAction::Toggle);
        surface.security_state();
        assert_eq!(reads.get(), 2);
        let mut frame = core::pin::pin!(surface.wait_for_frame());
        let _ = frame
            .as_mut()
            .poll(&mut Context::from_waker(core::task::Waker::noop()));
        surface.security_state();
        assert_eq!(reads.get(), 3);
    }
}
