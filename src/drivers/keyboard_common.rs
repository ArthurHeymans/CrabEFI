//! Shared keyboard constants and arch-agnostic API
//!
//! This module provides:
//! - EFI key state constants (used by both PS/2 and USB keyboard drivers)
//! - The public keyboard API that delegates to the appropriate backend
//!
//! On x86, this dispatches to both PS/2 (i8042) and USB HID keyboards.
//! On aarch64, only USB HID keyboards are available.

// Re-export the EFI constants that were previously in drivers::keyboard
// so that all existing callers (hid_keyboard.rs, etc.) can use them.

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
// Arch-agnostic public API
// ============================================================================

/// Initialize keyboard subsystem
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    crate::drivers::keyboard::init();
}

/// Cleanup keyboard before ExitBootServices
pub fn cleanup() {
    #[cfg(target_arch = "x86_64")]
    crate::drivers::keyboard::cleanup();
}

/// Check if any keyboard has a key available
pub fn has_key() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // The PS/2 has_key() already polls USB internally
        return crate::drivers::keyboard::has_key();
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        crate::drivers::usb::poll_keyboards();
        crate::drivers::usb::keyboard_has_key()
    }
}

/// Try to read a key from any keyboard
pub fn try_read_key() -> Option<(u16, u16)> {
    #[cfg(target_arch = "x86_64")]
    {
        // The PS/2 try_read_key() already tries USB first
        return crate::drivers::keyboard::try_read_key();
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        crate::drivers::usb::poll_keyboards();
        crate::drivers::usb::keyboard_get_key()
    }
}

/// Get EFI key state from all keyboards
pub fn get_efi_key_state() -> (u32, u8) {
    #[cfg(target_arch = "x86_64")]
    {
        // The PS/2 get_efi_key_state() already combines USB state
        return crate::drivers::keyboard::get_efi_key_state();
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        use efi_shift_state::SHIFT_STATE_VALID;
        use efi_toggle_state::TOGGLE_STATE_VALID;

        let mut shift_state = SHIFT_STATE_VALID;
        let mut toggle_state = TOGGLE_STATE_VALID;

        let usb_state = crate::drivers::usb::keyboard_get_efi_state();
        shift_state |= usb_state.0;
        toggle_state |= usb_state.1;

        (shift_state, toggle_state)
    }
}
