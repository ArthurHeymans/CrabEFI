//! UEFI Simple Pointer Protocol
//!
//! Implements EFI_SIMPLE_POINTER_PROTOCOL for mouse input.
//! This protocol provides relative pointer movement and button state,
//! compatible with the UEFI 2.x specification.
//!
//! # References
//!
//! - UEFI Specification 2.10, Section 12.5

use crate::drivers::mouse_cursor;

// ============================================================================
// Protocol GUIDs and Types
// ============================================================================

/// EFI_SIMPLE_POINTER_PROTOCOL GUID
/// {31878C87-0B75-11D5-9A4F-0090273FC14D}
pub const SIMPLE_POINTER_PROTOCOL_GUID: r_efi::efi::Guid = r_efi::efi::Guid::from_fields(
    0x31878C87,
    0x0B75,
    0x11D5,
    0x9A,
    0x4F,
    &[0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D],
);

/// Resolution values for pointer movement.
///
/// These define the granularity of the pointer axes in counts per mm.
/// A value of 1 means the values are raw device counts.
const RESOLUTION_X: u64 = 1;
const RESOLUTION_Y: u64 = 1;
const RESOLUTION_Z: u64 = 1;

// ============================================================================
// Protocol Structures (matching UEFI spec layout)
// ============================================================================

/// EFI_SIMPLE_POINTER_STATE
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SimplePointerState {
    /// Relative X movement since last GetState call
    pub relative_movement_x: i32,
    /// Relative Y movement since last GetState call
    pub relative_movement_y: i32,
    /// Relative Z movement (scroll wheel)
    pub relative_movement_z: i32,
    /// Left button pressed
    pub left_button: r_efi::efi::Boolean,
    /// Right button pressed
    pub right_button: r_efi::efi::Boolean,
}

/// EFI_SIMPLE_POINTER_MODE
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SimplePointerMode {
    /// Resolution of X axis (counts per mm)
    pub resolution_x: u64,
    /// Resolution of Y axis (counts per mm)
    pub resolution_y: u64,
    /// Resolution of Z axis (counts per mm)
    pub resolution_z: u64,
    /// Whether left button is supported
    pub left_button: r_efi::efi::Boolean,
    /// Whether right button is supported
    pub right_button: r_efi::efi::Boolean,
}

/// EFI_SIMPLE_POINTER_PROTOCOL
#[repr(C)]
pub struct SimplePointerProtocol {
    /// Reset the pointer device
    pub reset: unsafe extern "efiapi" fn(
        this: *mut SimplePointerProtocol,
        extended_verification: r_efi::efi::Boolean,
    ) -> r_efi::efi::Status,
    /// Get the current state of the pointer
    pub get_state: unsafe extern "efiapi" fn(
        this: *mut SimplePointerProtocol,
        state: *mut SimplePointerState,
    ) -> r_efi::efi::Status,
    /// Event to wait for input
    pub wait_for_input: r_efi::efi::Event,
    /// Pointer to mode information
    pub mode: *mut SimplePointerMode,
}

// SAFETY: SimplePointerProtocol contains function pointers and an event handle.
// These are set once during init and remain valid for the firmware lifetime.
// CrabEFI is single-threaded.
unsafe impl Send for SimplePointerProtocol {}
unsafe impl Sync for SimplePointerProtocol {}

// ============================================================================
// Protocol Implementation
// ============================================================================

/// Reset the pointer device
unsafe extern "efiapi" fn pointer_reset(
    _this: *mut SimplePointerProtocol,
    _extended_verification: r_efi::efi::Boolean,
) -> r_efi::efi::Status {
    // Poll to drain any stale data
    mouse_cursor::poll();
    r_efi::efi::Status::SUCCESS
}

/// Get the current state of the pointer
unsafe extern "efiapi" fn pointer_get_state(
    _this: *mut SimplePointerProtocol,
    state: *mut SimplePointerState,
) -> r_efi::efi::Status {
    if state.is_null() {
        return r_efi::efi::Status::INVALID_PARAMETER;
    }

    // Poll for new data
    mouse_cursor::poll();

    let (x, y) = mouse_cursor::position();
    let _ = (x, y); // absolute position not used for SimplePointer

    // SimplePointer uses relative movement
    // We need the raw deltas, not the absolute position
    // Poll the underlying drivers directly for relative data

    #[cfg(target_arch = "x86_64")]
    let (ps2_dx, ps2_dy, ps2_dz) = crate::drivers::mouse::get_relative_motion();
    #[cfg(not(target_arch = "x86_64"))]
    let (ps2_dx, ps2_dy, ps2_dz) = (0i32, 0i32, 0i32);

    let (usb_dx, usb_dy) = crate::drivers::usb::hid_mouse::get_relative_motion();

    let dx = ps2_dx + usb_dx;
    let dy = ps2_dy + usb_dy;
    let dz = ps2_dz;

    if dx == 0 && dy == 0 && dz == 0 {
        return r_efi::efi::Status::NOT_READY;
    }

    let buttons = mouse_cursor::buttons();

    unsafe {
        (*state).relative_movement_x = dx;
        (*state).relative_movement_y = dy;
        (*state).relative_movement_z = dz;
        (*state).left_button = if (buttons & 1) != 0 {
            r_efi::efi::Boolean::TRUE
        } else {
            r_efi::efi::Boolean::FALSE
        };
        (*state).right_button = if (buttons & 2) != 0 {
            r_efi::efi::Boolean::TRUE
        } else {
            r_efi::efi::Boolean::FALSE
        };
    }

    r_efi::efi::Status::SUCCESS
}

// ============================================================================
// Global Protocol Instance
// ============================================================================

/// Global pointer mode
static mut POINTER_MODE: SimplePointerMode = SimplePointerMode {
    resolution_x: RESOLUTION_X,
    resolution_y: RESOLUTION_Y,
    resolution_z: RESOLUTION_Z,
    left_button: r_efi::efi::Boolean::TRUE,
    right_button: r_efi::efi::Boolean::TRUE,
};

/// Global protocol instance
static mut POINTER_PROTOCOL: SimplePointerProtocol = SimplePointerProtocol {
    reset: pointer_reset,
    get_state: pointer_get_state,
    wait_for_input: core::ptr::null_mut(),
    mode: core::ptr::addr_of_mut!(POINTER_MODE),
};

/// Get a pointer to the global SimplePointerProtocol instance.
///
/// The returned pointer is valid for the firmware lifetime.
pub fn get_protocol() -> *mut SimplePointerProtocol {
    core::ptr::addr_of_mut!(POINTER_PROTOCOL)
}

/// Get the protocol GUID.
pub fn guid() -> r_efi::efi::Guid {
    SIMPLE_POINTER_PROTOCOL_GUID
}
