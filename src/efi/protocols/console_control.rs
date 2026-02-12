//! EFI Console Control Protocol
//!
//! This protocol is used by bootloaders to switch between text and graphics
//! console modes. It was part of the Intel EFI specification but deprecated
//! in UEFI 2.0. Some bootloaders still use it for compatibility.

use core::ffi::c_void;
use r_efi::efi::{Boolean, Guid, Status};

use crate::efi::utils::allocate_protocol_with_log;

/// Console Control Protocol GUID
/// {F42F7782-012E-4C12-9956-49F94304F721}
pub const CONSOLE_CONTROL_PROTOCOL_GUID: Guid = Guid::from_fields(
    0xf42f7782,
    0x012e,
    0x4c12,
    0x99,
    0x56,
    &[0x49, 0xf9, 0x43, 0x04, 0xf7, 0x21],
);

/// Console screen mode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenMode {
    /// Text mode
    Text = 0,
    /// Graphics mode
    Graphics = 1,
    /// Maximum mode value (for bounds checking)
    MaxValue = 2,
}

/// Console Control Protocol structure
#[repr(C)]
pub struct ConsoleControlProtocol {
    pub get_mode: extern "efiapi" fn(
        this: *mut ConsoleControlProtocol,
        mode: *mut ScreenMode,
        gop_uga_exists: *mut Boolean,
        std_in_locked: *mut Boolean,
    ) -> Status,
    pub set_mode: extern "efiapi" fn(this: *mut ConsoleControlProtocol, mode: ScreenMode) -> Status,
    pub lock_std_in:
        extern "efiapi" fn(this: *mut ConsoleControlProtocol, password: *mut u16) -> Status,
}

/// Current screen mode (we start in graphics mode since we have a framebuffer)
static mut CURRENT_MODE: ScreenMode = ScreenMode::Graphics;

/// Get the current console mode
extern "efiapi" fn console_get_mode(
    _this: *mut ConsoleControlProtocol,
    mode: *mut ScreenMode,
    gop_uga_exists: *mut Boolean,
    std_in_locked: *mut Boolean,
) -> Status {
    if !mode.is_null() {
        unsafe {
            *mode = CURRENT_MODE;
        }
    }

    if !gop_uga_exists.is_null() {
        unsafe {
            // We have GOP (Graphics Output Protocol)
            *gop_uga_exists = Boolean::TRUE;
        }
    }

    if !std_in_locked.is_null() {
        unsafe {
            // StdIn is not locked
            *std_in_locked = Boolean::FALSE;
        }
    }

    Status::SUCCESS
}

/// Set the console mode
///
/// When switching to text mode, we set up the framebuffer console with
/// centered text rendering (like EDK2's GraphicsConsole DeltaX/DeltaY).
/// When switching to graphics mode, we clear the screen for GOP use.
extern "efiapi" fn console_set_mode(
    _this: *mut ConsoleControlProtocol,
    mode: ScreenMode,
) -> Status {
    if mode as u32 >= ScreenMode::MaxValue as u32 {
        return Status::INVALID_PARAMETER;
    }

    let prev_mode = unsafe { CURRENT_MODE };
    unsafe {
        CURRENT_MODE = mode;
    }

    log::debug!("ConsoleControl.SetMode({:?} -> {:?})", prev_mode, mode);

    match mode {
        ScreenMode::Text => {
            // Switch to text mode: set up centered text area
            crate::state::with_console_mut(|console| {
                let Some(ref fb) = console.efi_framebuffer else {
                    return;
                };

                let (cols, rows, delta_x, delta_y) =
                    crate::efi::protocols::console::compute_centered_text_layout(fb);

                // Clear entire framebuffer with the current background color
                let (bg_r, bg_g, bg_b) = console.bg_color;
                unsafe {
                    fb.fill_solid(bg_r, bg_g, bg_b);
                }

                console.start_row = 0;
                console.dimensions = (cols, rows);
                console.cursor_pos = (0, 0);
                console.delta_x = delta_x;
                console.delta_y = delta_y;

                log::debug!(
                    "ConsoleControl: text mode {}x{} chars, centered at ({}, {}) px",
                    cols,
                    rows,
                    delta_x,
                    delta_y
                );
            });
        }
        ScreenMode::Graphics => {
            // Switch to graphics mode: clear screen for GOP consumers
            crate::state::with_console_mut(|console| {
                let Some(ref fb) = console.efi_framebuffer else {
                    return;
                };

                // Graphics mode always clears to black (GOP starts fresh)
                unsafe {
                    fb.fill_solid(0, 0, 0);
                }

                // Reset centering offsets (GOP uses raw pixel addressing)
                console.delta_x = 0;
                console.delta_y = 0;
            });
        }
        _ => {}
    }

    Status::SUCCESS
}

/// Lock standard input (not implemented - just return success)
extern "efiapi" fn console_lock_std_in(
    _this: *mut ConsoleControlProtocol,
    _password: *mut u16,
) -> Status {
    log::debug!("ConsoleControl.LockStdIn() - not implemented");
    // We don't support password protection, just return success
    Status::SUCCESS
}

/// Create a Console Control Protocol instance
pub fn create_protocol() -> *mut c_void {
    let ptr = allocate_protocol_with_log::<ConsoleControlProtocol>("ConsoleControlProtocol", |p| {
        p.get_mode = console_get_mode;
        p.set_mode = console_set_mode;
        p.lock_std_in = console_lock_std_in;
    });
    if ptr.is_null() {
        return core::ptr::null_mut();
    }

    log::debug!("Created ConsoleControlProtocol at {:p}", ptr);
    // Log function pointer addresses to verify struct layout is correct
    unsafe {
        log::debug!(
            "  get_mode={:p}, set_mode={:p}, lock_std_in={:p}",
            (*ptr).get_mode as *const (),
            (*ptr).set_mode as *const (),
            (*ptr).lock_std_in as *const ()
        );
    }
    ptr as *mut c_void
}
