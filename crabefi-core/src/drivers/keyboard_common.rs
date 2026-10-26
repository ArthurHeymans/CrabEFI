//! Keyboards
//!
//! PS/2 and USB HID keyboards, the platform's console input and peripheral
//! drivers each register a [`KeyboardDevice`]. Console and menu code read keys
//! from all of them through [`try_read_key`] and [`get_efi_key_state`].

use crate::cell::Local;
use crate::platform::{Key, KeyState};
use alloc::{boxed::Box, vec::Vec};

/// EFI shift state flags (from UEFI spec Table 107)
pub mod efi_shift_state {
    pub const SHIFT_STATE_VALID: u32 = 0x8000_0000;
    pub const RIGHT_SHIFT_PRESSED: u32 = 0x0000_0001;
    pub const LEFT_SHIFT_PRESSED: u32 = 0x0000_0002;
    pub const RIGHT_CONTROL_PRESSED: u32 = 0x0000_0004;
    pub const LEFT_CONTROL_PRESSED: u32 = 0x0000_0008;
    pub const RIGHT_ALT_PRESSED: u32 = 0x0000_0010;
    pub const LEFT_ALT_PRESSED: u32 = 0x0000_0020;
    pub const RIGHT_LOGO_PRESSED: u32 = 0x0000_0040;
    pub const LEFT_LOGO_PRESSED: u32 = 0x0000_0080;
}

/// EFI toggle state flags (from UEFI spec Table 108)
pub mod efi_toggle_state {
    pub const TOGGLE_STATE_VALID: u8 = 0x80;
    pub const KEY_STATE_EXPOSED: u8 = 0x40;
    pub const SCROLL_LOCK_ACTIVE: u8 = 0x01;
    pub const NUM_LOCK_ACTIVE: u8 = 0x02;
    pub const CAPS_LOCK_ACTIVE: u8 = 0x04;
}

// ============================================================================
// Keyboard devices
// ============================================================================

/// A keyboard or equivalent key source.
pub trait KeyboardDevice {
    /// Next key press, or `None` when none is waiting. Must not wait for input.
    fn read_key(&mut self) -> Option<Key>;

    /// Pressed modifiers and active toggles, without the VALID bits.
    fn key_state(&mut self) -> KeyState {
        KeyState::default()
    }

    /// Hand the device to the OS. Must not allocate or change the EFI memory
    /// map.
    fn stop(&mut self) {}
}

static DEVICES: Local<Vec<Box<dyn KeyboardDevice>>> = Local::new(Vec::new());

/// Register a keyboard for the rest of boot services.
pub fn register(device: Box<dyn KeyboardDevice>) {
    DEVICES.borrow_mut().push(device);
}

/// Run `f` on the registered devices without holding a borrow across their
/// callbacks.
fn with_devices<R>(f: impl FnOnce(&mut Vec<Box<dyn KeyboardDevice>>) -> R) -> R {
    let mut devices = core::mem::take(&mut *DEVICES.borrow_mut());
    let result = f(&mut devices);
    let mut registered = DEVICES.borrow_mut();
    devices.append(&mut registered);
    *registered = devices;
    result
}

/// Initialize the PS/2 keyboard and register the built-in keyboards.
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        crate::drivers::keyboard::init();
        register(Box::new(crate::drivers::keyboard::Ps2Keyboard));
    }
    register(Box::new(crate::drivers::usb::hid_keyboard::UsbKeyboard));
}

/// Hand every keyboard to the OS before ExitBootServices.
pub fn cleanup() {
    let mut devices = core::mem::take(&mut *DEVICES.borrow_mut());
    devices.iter_mut().for_each(|device| device.stop());
    // No deallocation during the handoff.
    core::mem::forget(devices);
}

/// Read a key from the first keyboard that has one.
///
/// Returns `(scan_code, unicode_char)` following EFI conventions.
pub fn try_read_key() -> Option<(u16, u16)> {
    with_devices(|devices| devices.iter_mut().find_map(|device| device.read_key()))
        .map(|key| (key.scancode, key.unicode_char))
}

/// Combined EFI shift and toggle state of every keyboard, with VALID bits.
pub fn get_efi_key_state() -> (u32, u8) {
    let state = with_devices(|devices| {
        devices.iter_mut().map(|device| device.key_state()).fold(
            KeyState::default(),
            |all, state| KeyState {
                shift_state: all.shift_state | state.shift_state,
                toggle_state: all.toggle_state | state.toggle_state,
            },
        )
    });
    (
        state.shift_state | efi_shift_state::SHIFT_STATE_VALID,
        state.toggle_state | efi_toggle_state::TOGGLE_STATE_VALID,
    )
}

/// The platform's console input as a keyboard.
pub(crate) struct PlatformKeyboard(pub &'static mut dyn crate::platform::ConsoleInput);

impl KeyboardDevice for PlatformKeyboard {
    fn read_key(&mut self) -> Option<Key> {
        self.0.poll();
        self.0.read_key()
    }

    fn key_state(&mut self) -> KeyState {
        self.0.key_state()
    }
}
