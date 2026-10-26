//! UEFI Simple Pointer Protocol
//!
//! Implements EFI_SIMPLE_POINTER_PROTOCOL for mouse input.
//! This protocol provides relative pointer movement and button state,
//! compatible with the UEFI 2.x specification.
//!
//! # Data Flow
//!
//! This module reads the combined report of every registered pointing device
//! (`drivers::pointer`) directly rather than going through `mouse_cursor`,
//! which turns the same motion into an absolute UI cursor position.
//!
//! # References
//!
//! - UEFI Specification 2.10, Section 12.5

use crate::cell::StaticMut;
use crate::drivers::pointer;
use crate::efi::boot_services::POINTER_EVENT_ID;
use core::ffi::c_void;
use r_efi::efi::{Boolean, Event, Status};

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
    pub left_button: Boolean,
    /// Right button pressed
    pub right_button: Boolean,
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
    pub left_button: Boolean,
    /// Whether right button is supported
    pub right_button: Boolean,
}

/// EFI_SIMPLE_POINTER_PROTOCOL
#[repr(C)]
pub struct SimplePointerProtocol {
    /// Reset the pointer device
    pub reset: unsafe extern "efiapi" fn(
        this: *mut SimplePointerProtocol,
        extended_verification: Boolean,
    ) -> Status,
    /// Get the current state of the pointer
    pub get_state: unsafe extern "efiapi" fn(
        this: *mut SimplePointerProtocol,
        state: *mut SimplePointerState,
    ) -> Status,
    /// Event to wait for input
    pub wait_for_input: Event,
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
    _extended_verification: Boolean,
) -> Status {
    // Drain stale motion and acknowledge the current button level.
    pointer::poll();
    let _ = pointer::take();
    Status::SUCCESS
}

/// Get the current state of the pointer
unsafe extern "efiapi" fn pointer_get_state(
    _this: *mut SimplePointerProtocol,
    state: *mut SimplePointerState,
) -> Status {
    if state.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Report motion and button-only transitions.
    pointer::poll();
    if !pointer::is_ready() {
        return Status::NOT_READY;
    }
    let pointer::PointerReport {
        dx,
        dy,
        dz,
        buttons,
    } = pointer::take();

    unsafe {
        (*state).relative_movement_x = dx;
        (*state).relative_movement_y = dy;
        (*state).relative_movement_z = dz;
        (*state).left_button = if (buttons & 1) != 0 {
            Boolean::TRUE
        } else {
            Boolean::FALSE
        };
        (*state).right_button = if (buttons & 2) != 0 {
            Boolean::TRUE
        } else {
            Boolean::FALSE
        };
    }

    Status::SUCCESS
}

// ============================================================================
// Global Protocol Instance
// ============================================================================

/// Global pointer mode
static POINTER_MODE: StaticMut<SimplePointerMode> = StaticMut::new(SimplePointerMode {
    resolution_x: RESOLUTION_X,
    resolution_y: RESOLUTION_Y,
    resolution_z: RESOLUTION_Z,
    left_button: Boolean::TRUE,
    right_button: Boolean::TRUE,
});

/// Global protocol instance
static POINTER_PROTOCOL: StaticMut<SimplePointerProtocol> = StaticMut::new(SimplePointerProtocol {
    reset: pointer_reset,
    get_state: pointer_get_state,
    wait_for_input: POINTER_EVENT_ID as *mut c_void as Event,
    mode: POINTER_MODE.get(),
});

/// Get a pointer to the global SimplePointerProtocol instance.
///
/// The returned pointer is valid for the firmware lifetime.
pub fn get_protocol() -> *mut SimplePointerProtocol {
    POINTER_PROTOCOL.get()
}

/// Get the protocol GUID.
pub fn guid() -> r_efi::efi::Guid {
    SIMPLE_POINTER_PROTOCOL_GUID
}

/// Check if pointer input is available.
///
/// Polls every pointing device without consuming the pending report.
/// Used by `BS.WaitForEvent` / `BS.CheckEvent`.
pub(crate) fn pointer_check_ready() -> bool {
    pointer::poll();
    pointer::is_ready()
}
