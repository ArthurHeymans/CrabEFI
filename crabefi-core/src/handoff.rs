//! Platform handoff data
//!
//! Data the platform layer (coreboot payload or library consumer) hands to the
//! core before boot: the memory map, ACPI/FDT discovery results, firmware
//! identity, capsule regions, the framebuffer, and the platform trait objects.
//! Nothing here is touched from the log path, so borrowing it never conflicts
//! with logging.

use core::cell::Ref;

use heapless::Vec;

use crate::cell::{Local, LocalCell};
use crate::platform::{CapsuleRegion, FirmwareInfo, FramebufferConfig, MemoryRegion};

/// Maximum number of memory regions we can store.
pub const MAX_MEMORY_REGIONS: usize = 96;

/// Maximum number of capsule regions we can store.
pub const MAX_CAPSULES: usize = 32;

/// Platform handoff data.
pub struct Handoff {
    /// Memory regions (for direct Linux boot)
    pub memory_regions: Vec<MemoryRegion, MAX_MEMORY_REGIONS>,

    /// ACPI RSDP address
    pub acpi_rsdp: Option<u64>,

    /// EFI firmware info (GUID, version, LSV) provided by the platform.
    pub efi_fw_info: Option<FirmwareInfo>,

    /// Capsule regions provided by the platform.
    pub capsule_regions: Vec<CapsuleRegion, MAX_CAPSULES>,

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

impl Handoff {
    const fn new() -> Self {
        Self {
            memory_regions: Vec::new(),
            acpi_rsdp: None,
            efi_fw_info: None,
            capsule_regions: Vec::new(),
            fdt_info: crate::fdt::PlatformInfo::new(),
            acpi_info: crate::fdt::PlatformInfo::new(),
        }
    }
}

/// Platform trait objects, reachable from any context including reset and
/// panic paths.
#[derive(Clone, Copy, Default)]
pub struct Callbacks {
    /// Optional platform lifecycle callbacks.
    pub hooks: Option<&'static dyn crate::platform::PlatformHooks>,
    /// Platform reset handler.
    pub reset: Option<&'static dyn crate::platform::ResetHandler>,
    /// Optional firmware-visible boot timestamp recorder.
    pub timestamp_recorder: Option<&'static dyn crate::platform::TimestampRecorder>,
}

impl Callbacks {
    const fn new() -> Self {
        Self {
            hooks: None,
            reset: None,
            timestamp_recorder: None,
        }
    }
}

static HANDOFF: Local<Handoff> = Local::new(Handoff::new());
/// Global framebuffer (coreboot tables or platform config).
static FRAMEBUFFER: LocalCell<Option<FramebufferConfig>> = LocalCell::new(None);
static CALLBACKS: LocalCell<Callbacks> = LocalCell::new(Callbacks::new());

/// Borrow the handoff data.
#[inline]
#[track_caller]
pub fn get() -> Ref<'static, Handoff> {
    HANDOFF.borrow()
}

/// Mutate the handoff data through a closure.
#[inline]
#[track_caller]
pub fn with_mut<R>(f: impl FnOnce(&mut Handoff) -> R) -> R {
    HANDOFF.with_mut(f)
}

/// Store framebuffer info.
///
/// Called from both the coreboot path (after parsing `lb_framebuffer`) and the
/// platform library path (after converting `FramebufferConfig`). The stored
/// info is used by boot menus, the Linux boot path (`screen_info`), and error
/// display, all of which call [`framebuffer()`].
pub fn store_framebuffer(fb: FramebufferConfig) {
    FRAMEBUFFER.set(Some(fb));
}

/// The framebuffer, if the platform provided one.
pub fn framebuffer() -> Option<FramebufferConfig> {
    FRAMEBUFFER.get()
}

/// Platform trait objects (hooks, reset, timestamp recorder).
#[inline]
pub fn callbacks() -> Callbacks {
    CALLBACKS.get()
}

/// Install platform trait objects.
#[inline]
pub fn set_callbacks(callbacks: Callbacks) {
    CALLBACKS.set(callbacks)
}
