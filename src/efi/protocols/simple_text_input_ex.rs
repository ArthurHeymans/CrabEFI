//! EFI Simple Text Input Ex Protocol
//!
//! This module implements EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL, which extends
//! the basic Simple Text Input protocol with:
//! - Key state reporting (shift/ctrl/alt/logo modifiers, toggle keys)
//! - Key notification callbacks (register for specific key combinations)
//! - SetState for controlling toggle key LEDs
//!
//! The protocol shares the keyboard event (KEYBOARD_EVENT_ID) with the
//! basic Simple Text Input protocol, and is installed on the same console handle.

use crate::drivers::keyboard;
use crate::efi::boot_services::KEYBOARD_EVENT_ID;
use crate::efi::protocols::console;
use crate::efi::utils::allocate_protocol_with_log;
use crate::state;
use core::ffi::c_void;
use r_efi::efi::{Boolean, Event, Guid, Handle, Status};
use r_efi::protocols::simple_text_input::InputKey;

// ============================================================================
// Protocol GUID
// ============================================================================

/// EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID
/// {DD9E7534-7762-4698-8C14-F58517A625AA}
pub const SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID: Guid = Guid::from_fields(
    0xdd9e7534,
    0x7762,
    0x4698,
    0x8c,
    0x14,
    &[0xf5, 0x85, 0x17, 0xa6, 0x25, 0xaa],
);

// ============================================================================
// Protocol Structures (matching UEFI spec)
// ============================================================================

/// EFI_KEY_STATE - describes the shift/toggle state of the keyboard
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyState {
    /// Shift key state (EFI_SHIFT_STATE_VALID | modifier bits)
    pub key_shift_state: u32,
    /// Toggle key state (EFI_TOGGLE_STATE_VALID | toggle bits)
    pub key_toggle_state: u8,
}

/// EFI_KEY_DATA - a key press with associated state
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyData {
    /// The EFI scan code and Unicode value
    pub key: InputKey,
    /// Shift and toggle state at time of key press
    pub key_state: KeyState,
}

// Compile-time layout assertions matching UEFI spec sizes:
// EFI_KEY_STATE: UINT32 + UINT8 = 5 bytes + 3 padding = 8 bytes (repr(C))
// EFI_KEY_DATA: EFI_INPUT_KEY (4 bytes) + EFI_KEY_STATE (8 bytes) = 12 bytes
const _: () = assert!(core::mem::size_of::<KeyState>() == 8);
const _: () = assert!(core::mem::size_of::<KeyData>() == 12);

/// Key notification callback function type
pub type KeyNotifyFunction = extern "efiapi" fn(key_data: *mut KeyData) -> Status;

/// EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL
#[repr(C)]
pub struct SimpleTextInputExProtocol {
    pub reset: extern "efiapi" fn(
        this: *mut SimpleTextInputExProtocol,
        extended_verification: Boolean,
    ) -> Status,
    pub read_key_stroke_ex:
        extern "efiapi" fn(this: *mut SimpleTextInputExProtocol, key_data: *mut KeyData) -> Status,
    pub wait_for_key_ex: Event,
    pub set_state: extern "efiapi" fn(
        this: *mut SimpleTextInputExProtocol,
        key_toggle_state: *mut u8,
    ) -> Status,
    pub register_key_notify: extern "efiapi" fn(
        this: *mut SimpleTextInputExProtocol,
        key_data: *mut KeyData,
        key_notification_function: KeyNotifyFunction,
        notify_handle: *mut Handle,
    ) -> Status,
    pub unregister_key_notify: extern "efiapi" fn(
        this: *mut SimpleTextInputExProtocol,
        notification_handle: Handle,
    ) -> Status,
}

// ============================================================================
// Key Notification Registry
// ============================================================================

/// Maximum number of registered key notifications
const MAX_KEY_NOTIFY: usize = 16;

/// A registered key notification entry
struct KeyNotifyEntry {
    /// Whether this slot is in use
    active: bool,
    /// The key pattern to match (scan_code + unicode_char)
    key: InputKey,
    /// Shift state to match (0 = match any)
    shift_state: u32,
    /// The callback function
    callback: Option<KeyNotifyFunction>,
}

impl KeyNotifyEntry {
    const fn empty() -> Self {
        Self {
            active: false,
            key: InputKey {
                scan_code: 0,
                unicode_char: 0,
            },
            shift_state: 0,
            callback: None,
        }
    }
}

/// Global key notification registry
static KEY_NOTIFY_REGISTRY: spin::Mutex<[KeyNotifyEntry; MAX_KEY_NOTIFY]> =
    spin::Mutex::new([const { KeyNotifyEntry::empty() }; MAX_KEY_NOTIFY]);

// ============================================================================
// Protocol Implementation
// ============================================================================

extern "efiapi" fn text_input_ex_reset(
    _this: *mut SimpleTextInputExProtocol,
    _extended_verification: Boolean,
) -> Status {
    log::debug!("SimpleTextInputEx.Reset()");
    Status::SUCCESS
}

extern "efiapi" fn text_input_ex_read_key_stroke(
    _this: *mut SimpleTextInputExProtocol,
    key_data: *mut KeyData,
) -> Status {
    if key_data.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Get current shift/toggle state (always valid, even if no key pressed)
    let (shift_state, toggle_state) = keyboard::get_efi_key_state();

    state::with_console_mut(|console_state| {
        let input_state = &mut console_state.input;

        // Use the shared key-reading function from console module
        match console::try_read_key(input_state) {
            Some((scan_code, unicode_char)) => {
                unsafe {
                    (*key_data).key.scan_code = scan_code;
                    (*key_data).key.unicode_char = unicode_char;
                    (*key_data).key_state.key_shift_state = shift_state;
                    (*key_data).key_state.key_toggle_state = toggle_state;
                }

                log::trace!(
                    "SimpleTextInputEx.ReadKeyStrokeEx: scan={:#x}, unicode={:#x}, shift={:#x}, toggle={:#x}",
                    scan_code,
                    unicode_char,
                    shift_state,
                    toggle_state
                );

                // Dispatch key notifications
                dispatch_key_notifications(scan_code, unicode_char, shift_state, toggle_state);

                Status::SUCCESS
            }
            None => {
                // No key available — still report the current state per spec
                unsafe {
                    (*key_data).key.scan_code = 0;
                    (*key_data).key.unicode_char = 0;
                    (*key_data).key_state.key_shift_state = shift_state;
                    (*key_data).key_state.key_toggle_state = toggle_state;
                }
                Status::NOT_READY
            }
        }
    })
}

extern "efiapi" fn text_input_ex_set_state(
    _this: *mut SimpleTextInputExProtocol,
    key_toggle_state: *mut u8,
) -> Status {
    if key_toggle_state.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let toggle = unsafe { *key_toggle_state };
    log::debug!("SimpleTextInputEx.SetState(toggle={:#x})", toggle);

    // We can't actually control keyboard LEDs from firmware easily,
    // so just accept the request. This matches the EDK2 terminal driver behavior.
    Status::SUCCESS
}

extern "efiapi" fn text_input_ex_register_key_notify(
    _this: *mut SimpleTextInputExProtocol,
    key_data: *mut KeyData,
    key_notification_function: KeyNotifyFunction,
    notify_handle: *mut Handle,
) -> Status {
    if key_data.is_null() || notify_handle.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let kd = unsafe { &*key_data };
    log::debug!(
        "SimpleTextInputEx.RegisterKeyNotify(scan={:#x}, unicode={:#x}, shift={:#x})",
        kd.key.scan_code,
        kd.key.unicode_char,
        kd.key_state.key_shift_state
    );

    let mut registry = KEY_NOTIFY_REGISTRY.lock();

    // Find a free slot
    for (i, entry) in registry.iter_mut().enumerate() {
        if !entry.active {
            entry.active = true;
            entry.key = kd.key;
            entry.shift_state = kd.key_state.key_shift_state;
            entry.callback = Some(key_notification_function);

            // Return slot index + 1 as the handle (avoid null)
            let handle = (i + 1) as *mut c_void;
            unsafe {
                *notify_handle = handle;
            }
            log::debug!("  -> registered as handle {:p}", handle);
            return Status::SUCCESS;
        }
    }

    log::warn!("SimpleTextInputEx: too many key notifications registered");
    Status::OUT_OF_RESOURCES
}

extern "efiapi" fn text_input_ex_unregister_key_notify(
    _this: *mut SimpleTextInputExProtocol,
    notification_handle: Handle,
) -> Status {
    let idx = notification_handle as usize;
    log::debug!("SimpleTextInputEx.UnregisterKeyNotify(handle={})", idx);

    if idx == 0 || idx > MAX_KEY_NOTIFY {
        return Status::INVALID_PARAMETER;
    }

    let mut registry = KEY_NOTIFY_REGISTRY.lock();
    let entry = &mut registry[idx - 1];

    if !entry.active {
        return Status::INVALID_PARAMETER;
    }

    *entry = KeyNotifyEntry::empty();
    Status::SUCCESS
}

/// A pending key notification to dispatch outside the lock
struct PendingNotify {
    callback: KeyNotifyFunction,
    key_data: KeyData,
}

/// Dispatch key notifications for a key press
fn dispatch_key_notifications(
    scan_code: u16,
    unicode_char: u16,
    shift_state: u32,
    toggle_state: u8,
) {
    // Collect callbacks to invoke outside the lock
    // Use MaybeUninit to avoid zeroed() warning on function pointers
    let mut callbacks: [core::mem::MaybeUninit<PendingNotify>; MAX_KEY_NOTIFY] =
        [const { core::mem::MaybeUninit::uninit() }; MAX_KEY_NOTIFY];
    let mut count = 0;

    {
        let registry = KEY_NOTIFY_REGISTRY.lock();
        for entry in registry.iter() {
            if !entry.active {
                continue;
            }
            let callback = match entry.callback {
                Some(f) => f,
                None => continue,
            };

            // Match key pattern: if registered key has non-zero scan/unicode, it must match
            let key_matches = (entry.key.scan_code == 0 && entry.key.unicode_char == 0)
                || (entry.key.scan_code == scan_code && entry.key.unicode_char == unicode_char);

            // Match shift state: if registered shift state has VALID bit, compare
            let shift_matches = (entry.shift_state & keyboard::efi_shift_state::SHIFT_STATE_VALID)
                == 0
                || (entry.shift_state & !keyboard::efi_shift_state::SHIFT_STATE_VALID)
                    == (shift_state & !keyboard::efi_shift_state::SHIFT_STATE_VALID);

            if key_matches && shift_matches && count < MAX_KEY_NOTIFY {
                let kd = KeyData {
                    key: InputKey {
                        scan_code,
                        unicode_char,
                    },
                    key_state: KeyState {
                        key_shift_state: shift_state,
                        key_toggle_state: toggle_state,
                    },
                };
                callbacks[count].write(PendingNotify {
                    callback,
                    key_data: kd,
                });
                count += 1;
            }
        }
    }

    // Invoke callbacks outside the lock
    for entry in callbacks.iter().take(count) {
        // Safety: we only read entries that were written above
        let pending = unsafe { entry.assume_init_ref() };
        let mut kd = pending.key_data;
        (pending.callback)(&mut kd);
    }
}

// ============================================================================
// Protocol Creation
// ============================================================================

/// Create a Simple Text Input Ex Protocol instance
///
/// Returns a pointer to the allocated protocol, or null on failure.
pub fn create_protocol() -> *mut c_void {
    let ptr =
        allocate_protocol_with_log::<SimpleTextInputExProtocol>("SimpleTextInputExProtocol", |p| {
            p.reset = text_input_ex_reset;
            p.read_key_stroke_ex = text_input_ex_read_key_stroke;
            p.wait_for_key_ex = KEYBOARD_EVENT_ID as *mut c_void as Event;
            p.set_state = text_input_ex_set_state;
            p.register_key_notify = text_input_ex_register_key_notify;
            p.unregister_key_notify = text_input_ex_unregister_key_notify;
        });
    if ptr.is_null() {
        return core::ptr::null_mut();
    }

    log::debug!("Created SimpleTextInputExProtocol at {:p}", ptr);
    ptr as *mut c_void
}
