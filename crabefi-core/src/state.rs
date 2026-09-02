//! Global Firmware State
//!
//! Firmware state lives in `static` cells, one per subsystem, so that borrowing
//! one subsystem never implies a borrow of another. Every cell is a
//! [`Local`] (a `RefCell` for single-hart firmware) or a [`LocalCell`] (a
//! `Cell` for `Copy` values). All access is safe code: conflicting borrows
//! panic with a source location instead of silently aliasing.
//!
//! # Invariants
//!
//! - CrabEFI runs on a single hart and never touches state from interrupt
//!   context. That is the only reason the cells can be `Sync`.
//! - Never hold a borrow across a call into foreign code: a loaded image entry
//!   point, an event notify function, or a platform trait object. Copy what is
//!   needed out of the cell, drop the borrow, then call.
//! - Code that may run from inside a `log!` macro (serial output, framebuffer
//!   logger, timestamps) keeps its state in module-private cells that nothing
//!   else borrows, so logging inside a `with_*_mut` closure never conflicts.

use core::cell::Ref;

use crate::cell::{Local, LocalCell};

// ============================================================================
// Subsystem statics
// ============================================================================

/// Hardware driver state.
static DRIVERS: Local<DriverState> = Local::new(DriverState::new());
/// Validated boot-side client for the separately allocated runtime image.
static RUNTIME_IMAGE: LocalCell<Option<crate::efi::runtime_image::RuntimeImageClient>> =
    LocalCell::new(None);
/// Global framebuffer (coreboot tables or platform config).
static FRAMEBUFFER: LocalCell<Option<FramebufferConfig>> = LocalCell::new(None);
/// Platform trait objects that may be called from anywhere, including panic
/// and reset paths.
static PLATFORM_CALLBACKS: LocalCell<PlatformCallbacks> = LocalCell::new(PlatformCallbacks::new());

// ============================================================================
// Driver State
// ============================================================================

use crate::platform::FramebufferConfig;
use heapless::Vec as HeaplessVec;

/// Maximum number of memory regions we can store
pub const MAX_MEMORY_REGIONS: usize = 64;

/// Maximum number of capsule regions we can store.
pub const MAX_CAPSULES: usize = 32;

/// Hardware driver state, organized into logical subsystems.
pub struct DriverState {
    /// Platform hardware info from platform config.
    pub platform: PlatformInfo,

    /// Platform info from FDT (PCIe, GIC, etc.)
    pub fdt_info: crate::fdt::PlatformInfo,

    /// Platform info from ACPI tables (GIC from MADT, UART from SPCR, ECAM from MCFG).
    ///
    /// Populated by platforms that perform ACPI discovery before calling
    /// [`crate::init_platform()`] (using `heap_pre_initialized`).  Library
    /// consumers that provide MMIO regions via `PlatformConfig.memory_map`
    /// and ECAM via `PlatformConfig.ecam_regions` leave this empty.
    ///
    /// `init_platform()` checks all `acpi_info.ecam_regions` after explicit
    /// platform regions and before the FDT host-bridge region.
    pub acpi_info: crate::fdt::PlatformInfo,
}

impl DriverState {
    pub const fn new() -> Self {
        Self {
            platform: PlatformInfo::new(),
            fdt_info: crate::fdt::PlatformInfo::new(),
            acpi_info: crate::fdt::PlatformInfo::new(),
        }
    }
}

impl Default for DriverState {
    fn default() -> Self {
        Self::new()
    }
}

// ----------------------------------------------------------------------------
// Platform Info
// ----------------------------------------------------------------------------

/// Platform hardware info sourced from platform config.
pub struct PlatformInfo {
    /// Memory regions (for direct Linux boot)
    pub memory_regions: HeaplessVec<crate::platform::MemoryRegion, MAX_MEMORY_REGIONS>,

    /// ACPI RSDP address
    pub acpi_rsdp: Option<u64>,

    /// EFI firmware info (GUID, version, LSV) provided by the platform.
    pub efi_fw_info: Option<crate::platform::FirmwareInfo>,

    /// Capsule regions provided by the platform.
    pub capsule_regions: HeaplessVec<crate::platform::CapsuleRegion, MAX_CAPSULES>,
}

/// Platform trait objects, reachable from any context.
#[derive(Clone, Copy)]
pub struct PlatformCallbacks {
    /// Optional platform lifecycle callbacks.
    pub hooks: Option<&'static dyn crate::platform::PlatformHooks>,
    /// Platform reset handler.
    pub reset: Option<&'static dyn crate::platform::ResetHandler>,
    /// Optional firmware-visible boot timestamp recorder.
    pub timestamp_recorder: Option<&'static dyn crate::platform::TimestampRecorder>,
}

impl PlatformCallbacks {
    pub const fn new() -> Self {
        Self {
            hooks: None,
            reset: None,
            timestamp_recorder: None,
        }
    }
}

impl Default for PlatformCallbacks {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformInfo {
    pub const fn new() -> Self {
        Self {
            memory_regions: HeaplessVec::new(),
            acpi_rsdp: None,
            efi_fw_info: None,
            capsule_regions: HeaplessVec::new(),
        }
    }
}

impl Default for PlatformInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Accessors
// ============================================================================

/// Borrow driver state.
#[inline]
#[track_caller]
pub fn drivers() -> Ref<'static, DriverState> {
    DRIVERS.borrow()
}

/// Mutate driver state through a closure.
#[inline]
#[track_caller]
pub fn with_drivers_mut<R>(f: impl FnOnce(&mut DriverState) -> R) -> R {
    DRIVERS.with_mut(f)
}

/// The runtime image client, once the runtime image has been loaded.
#[inline]
pub fn runtime_image() -> Option<crate::efi::runtime_image::RuntimeImageClient> {
    RUNTIME_IMAGE.get()
}

/// Publish the runtime image client.
#[inline]
pub fn set_runtime_image(client: crate::efi::runtime_image::RuntimeImageClient) {
    RUNTIME_IMAGE.set(Some(client))
}

/// Store framebuffer info in global state.
///
/// Called from both the coreboot path (after parsing `lb_framebuffer`) and the
/// platform library path (after converting `FramebufferConfig`). The stored
/// info is used by boot menus, the Linux boot path (`screen_info`), and error
/// display, all of which call [`get_framebuffer()`].
pub fn store_framebuffer(fb: FramebufferConfig) {
    FRAMEBUFFER.set(Some(fb));
}

/// Get the global framebuffer info, if available.
pub fn get_framebuffer() -> Option<FramebufferConfig> {
    FRAMEBUFFER.get()
}

/// Platform trait objects (hooks, reset, timestamp recorder).
#[inline]
pub fn platform_callbacks() -> PlatformCallbacks {
    PLATFORM_CALLBACKS.get()
}

/// Install platform trait objects.
#[inline]
pub fn set_platform_callbacks(callbacks: PlatformCallbacks) {
    PLATFORM_CALLBACKS.set(callbacks)
}
