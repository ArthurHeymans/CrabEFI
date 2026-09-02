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

use alloc::vec::Vec;
use core::cell::Ref;

use crate::cell::{Local, LocalCell};

// ============================================================================
// Subsystem statics
// ============================================================================

/// EFI service bookkeeping: handles, events, loaded images, filesystem.
static EFI: Local<EfiState> = Local::new(EfiState::new());
/// Hardware driver state.
static DRIVERS: Local<DriverState> = Local::new(DriverState::new());
/// EFI console state.
static CONSOLE: Local<ConsoleState> = Local::new(ConsoleState::new());
/// Validated boot-side client for the separately allocated runtime image.
static RUNTIME_IMAGE: LocalCell<Option<crate::efi::runtime_image::RuntimeImageClient>> =
    LocalCell::new(None);
/// Global framebuffer (coreboot tables or platform config).
static FRAMEBUFFER: LocalCell<Option<FramebufferConfig>> = LocalCell::new(None);
/// Platform trait objects that may be called from anywhere, including panic
/// and reset paths.
static PLATFORM_CALLBACKS: LocalCell<PlatformCallbacks> = LocalCell::new(PlatformCallbacks::new());

/// Allocate fixed-size EFI state tables after heap startup.
///
/// All tables keep their maximum length so their backing storage never moves.
/// Variable payloads remain empty until a variable is loaded or written.
///
/// # Returns
/// `true` when every table is ready.
pub fn init_efi_caches() -> bool {
    with_efi_mut(|efi| {
        init_entries(&mut efi.handles, MAX_HANDLES, HandleEntry::empty)
            && init_entries(&mut efi.events, MAX_EVENTS, EventEntry::empty)
            && init_entries(
                &mut efi.loaded_images,
                MAX_LOADED_IMAGES,
                LoadedImageEntry::empty,
            )
    })
}

fn init_entries<T>(entries: &mut Vec<T>, len: usize, init: impl FnMut() -> T) -> bool {
    if !entries.is_empty() {
        return true;
    }
    if entries.try_reserve_exact(len).is_err() {
        return false;
    }
    entries.resize_with(len, init);
    true
}

// ============================================================================
// EFI State
// ============================================================================

use crate::efi::tcg::types::TaggedDigest;
use r_efi::efi::{self, Guid, Handle};

/// Maximum number of handles we can track
pub const MAX_HANDLES: usize = 64;

/// Maximum number of protocols per handle
pub const MAX_PROTOCOLS_PER_HANDLE: usize = 8;

/// Maximum number of events we can track
pub const MAX_EVENTS: usize = 32;

/// Maximum number of loaded images we can track
pub const MAX_LOADED_IMAGES: usize = 16;

/// Protocol interface entry
#[derive(Clone, Copy)]
pub struct ProtocolEntry {
    pub guid: Guid,
    pub interface: *mut core::ffi::c_void,
}

impl ProtocolEntry {
    pub const fn empty() -> Self {
        Self {
            guid: Guid::from_fields(0, 0, 0, 0, 0, &[0, 0, 0, 0, 0, 0]),
            interface: core::ptr::null_mut(),
        }
    }
}

/// Handle entry in the handle database
pub struct HandleEntry {
    pub handle: Handle,
    pub protocols: [ProtocolEntry; MAX_PROTOCOLS_PER_HANDLE],
    pub protocol_count: usize,
}

impl HandleEntry {
    pub const fn empty() -> Self {
        Self {
            handle: core::ptr::null_mut(),
            protocols: [ProtocolEntry::empty(); MAX_PROTOCOLS_PER_HANDLE],
            protocol_count: 0,
        }
    }
}

/// Timer delay type matching UEFI TimerDelay enum
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TimerType {
    /// Timer is cancelled
    Cancel = 0,
    /// Timer fires repeatedly every trigger_time
    Periodic = 1,
    /// Timer fires once after trigger_time
    Relative = 2,
}

impl TryFrom<u32> for TimerType {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TimerType::Cancel),
            1 => Ok(TimerType::Periodic),
            2 => Ok(TimerType::Relative),
            other => Err(other),
        }
    }
}

/// Event entry for tracking created events
#[derive(Clone, Copy)]
pub struct EventEntry {
    pub event_type: u32,
    pub notify_tpl: efi::Tpl,
    pub signaled: bool,
    pub is_keyboard_event: bool,
    /// Notify callback function (for EVT_NOTIFY_SIGNAL and EVT_NOTIFY_WAIT)
    pub notify_function: Option<efi::EventNotify>,
    /// Context pointer passed to notify callback
    pub notify_context: *mut core::ffi::c_void,
    /// Event group GUID (for CreateEventEx)
    pub event_group: Option<efi::Guid>,
    /// Timer type (Cancel, Periodic, Relative)
    pub timer_type: TimerType,
    /// Timer trigger time in 100ns units (UEFI convention)
    pub timer_trigger_time: u64,
    /// TSC deadline for next timer firing
    pub timer_deadline_tsc: u64,
}

impl EventEntry {
    pub const fn empty() -> Self {
        Self {
            event_type: 0,
            notify_tpl: 0,
            signaled: false,
            is_keyboard_event: false,
            notify_function: None,
            notify_context: core::ptr::null_mut(),
            event_group: None,
            timer_type: TimerType::Cancel,
            timer_trigger_time: 0,
            timer_deadline_tsc: 0,
        }
    }
}

/// Loaded image entry - tracks PE images loaded via LoadImage
#[derive(Clone, Copy)]
pub struct LoadedImageEntry {
    /// Handle for this loaded image
    pub handle: Handle,
    /// Base address where image was loaded (section-aligned)
    pub image_base: u64,
    /// Size of the loaded image in bytes
    pub image_size: u64,
    /// Entry point address
    pub entry_point: u64,
    /// Base address of the underlying page allocation (for free_pages)
    pub alloc_base: u64,
    /// Number of pages allocated (covers alignment padding + image)
    pub num_pages: u64,
    /// Parent image handle that loaded this image
    pub parent_handle: Handle,
    /// PE subsystem value from the optional header.
    pub subsystem: u16,
    /// Pending PCR index for deferred application image measurement.
    pub measurement_pcr: u32,
    /// Pending TCG event type for deferred application image measurement.
    pub measurement_event_type: u32,
    /// Number of valid precomputed authenticode digests.
    pub measurement_digest_count: usize,
    /// Precomputed authenticode digests for deferred application measurement.
    pub measurement_digests: [TaggedDigest; 5],
    /// Serialized EFI_IMAGE_LOAD_EVENT data for deferred application measurement.
    pub measurement_event_data: *mut u8,
    /// Size of the deferred event data buffer.
    pub measurement_event_data_size: usize,
}

impl LoadedImageEntry {
    pub const fn empty() -> Self {
        Self {
            handle: core::ptr::null_mut(),
            image_base: 0,
            image_size: 0,
            entry_point: 0,
            alloc_base: 0,
            num_pages: 0,
            parent_handle: core::ptr::null_mut(),
            subsystem: 0,
            measurement_pcr: 0,
            measurement_event_type: 0,
            measurement_digest_count: 0,
            measurement_digests: [TaggedDigest::zeroed(0); 5],
            measurement_event_data: core::ptr::null_mut(),
            measurement_event_data_size: 0,
        }
    }
}

/// EFI subsystem state
pub struct EfiState {
    /// Handle database, allocated after heap startup.
    pub handles: Vec<HandleEntry>,
    /// Number of active handles
    pub handle_count: usize,
    /// Next handle value (unique identifier)
    pub next_handle: usize,

    /// Event database, allocated after heap startup.
    pub events: Vec<EventEntry>,
    /// Next event ID (starting at 2, 1 is reserved for keyboard)
    pub next_event_id: usize,

    /// Loaded images database, allocated after heap startup.
    pub loaded_images: Vec<LoadedImageEntry>,

    /// Monotonic counter for GetNextMonotonicCount
    pub monotonic_count: u64,

    /// Flag indicating EFI_EVENT_GROUP_READY_TO_BOOT has been signaled
    /// Per UEFI spec, this should only be signaled once before the first
    /// boot option is attempted.
    pub ready_to_boot_signaled: bool,
}

impl EfiState {
    pub const fn new() -> Self {
        Self {
            handles: Vec::new(),
            handle_count: 0,
            next_handle: 1,
            events: Vec::new(),
            next_event_id: 2, // Start at 2, reserve 1 for keyboard
            loaded_images: Vec::new(),
            monotonic_count: 0,
            ready_to_boot_signaled: false,
        }
    }
}

impl Default for EfiState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Driver State
// ============================================================================

use crate::drivers::pci::PciDevice;
use crate::drivers::pci::access::AnyPciAccess;
use crate::drivers::storage::StorageRegistry;
use crate::platform::{FramebufferConfig, PciEcamRegion};
use heapless::Vec as HeaplessVec;

/// Maximum number of PCI devices
pub const MAX_PCI_DEVICES: usize = 64;

/// Maximum number of storage controllers
pub const MAX_STORAGE_CONTROLLERS: usize = 4;

/// Maximum number of storage devices in registry
pub const MAX_STORAGE_DEVICES: usize = 16;

/// Maximum number of memory regions we can store
pub const MAX_MEMORY_REGIONS: usize = 64;

/// Maximum number of capsule regions we can store.
pub const MAX_CAPSULES: usize = 32;

/// Hardware driver state, organized into logical subsystems.
pub struct DriverState {
    /// PCI bus subsystem
    pub pci: PciState,

    /// Platform hardware info from platform config.
    pub platform: PlatformInfo,

    /// Storage device registry (tracks all block devices)
    pub(crate) storage_registry: StorageRegistry,

    /// Hardware RNG available and functional
    pub rng_available: bool,

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
            pci: PciState::new(),
            platform: PlatformInfo::new(),
            storage_registry: StorageRegistry::new(),
            rng_available: false,
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
// PCI State
// ----------------------------------------------------------------------------

/// PCI bus subsystem state
pub struct PciState {
    /// Enumerated PCI device list
    pub devices: HeaplessVec<PciDevice, MAX_PCI_DEVICES>,
    /// Validated PCIe ECAM allocations (from platform, ACPI MCFG, or FDT).
    pub ecam_regions: HeaplessVec<PciEcamRegion, { crate::fdt::MAX_ECAM_REGIONS }>,
    /// Whether firmware explicitly supplied ECAM configuration.
    pub ecam_configured: bool,
    /// Config space access method (legacy I/O CAM or PCIe ECAM)
    pub access: AnyPciAccess,
}

impl PciState {
    pub const fn new() -> Self {
        Self {
            devices: HeaplessVec::new(),
            ecam_regions: HeaplessVec::new(),
            ecam_configured: false,
            #[cfg(target_arch = "x86_64")]
            access: AnyPciAccess::IoCam(crate::drivers::pci::access::IoCamAccess),
            #[cfg(not(target_arch = "x86_64"))]
            access: AnyPciAccess::Unavailable,
        }
    }
}

impl Default for PciState {
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
// Console State
// ============================================================================

/// Console screen mode (Text or Graphics)
///
/// Used by the ConsoleControl protocol to track the current display mode.
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

/// Console and display state
pub struct ConsoleState {
    /// EFI console framebuffer info
    pub efi_framebuffer: Option<FramebufferConfig>,
    /// EFI console cursor position (col, row)
    pub cursor_pos: (u32, u32),
    /// EFI console dimensions (cols, rows)
    pub dimensions: (u32, u32),
    /// Console start row (EFI console uses bottom half of screen)
    pub start_row: u32,

    /// Pixel offset for centering the text region horizontally (EDK2 DeltaX)
    pub delta_x: u32,
    /// Pixel offset for centering the text region vertically (EDK2 DeltaY)
    pub delta_y: u32,

    /// Current foreground color (RGB) set by SetAttribute
    pub fg_color: (u8, u8, u8),
    /// Current background color (RGB) set by SetAttribute
    pub bg_color: (u8, u8, u8),

    /// Input state for escape sequence parsing
    pub input: InputState,

    /// GOP framebuffer for graphics output protocol Blt operations
    pub gop_framebuffer: Option<FramebufferConfig>,

    /// Screen mode (Text or Graphics) for ConsoleControl protocol
    pub screen_mode: ScreenMode,
}

impl ConsoleState {
    pub const fn new() -> Self {
        Self {
            efi_framebuffer: None,
            cursor_pos: (0, 0),
            dimensions: (80, 25),
            start_row: 0,
            delta_x: 0,
            delta_y: 0,
            fg_color: (170, 170, 170), // EFI_LIGHTGRAY (attribute 0x07, index 7)
            bg_color: (0, 0, 0),       // EFI_BLACK default
            input: InputState::new(),
            gop_framebuffer: None,
            screen_mode: ScreenMode::Graphics,
        }
    }
}

impl Default for ConsoleState {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum size of the escape sequence buffer
pub const ESCAPE_BUF_SIZE: usize = 8;

/// Input state for escape sequence parsing
pub struct InputState {
    /// Buffer for escape sequence bytes
    pub escape_buf: [u8; ESCAPE_BUF_SIZE],
    /// Number of bytes in the escape buffer
    pub escape_len: usize,
    /// Whether we're currently in an escape sequence
    pub in_escape: bool,
    /// Queued key to return (scan_code, unicode_char)
    pub queued_key: Option<(u16, u16)>,
    /// Key read-ahead by CheckEvent/WaitForEvent to confirm real input
    /// This prevents false "keyboard ready" signals from modifier-only
    /// or mouse data in the PS/2 output buffer.
    pub pending_key: Option<(u16, u16)>,
}

impl Default for InputState {
    fn default() -> Self {
        Self::new()
    }
}

impl InputState {
    pub const fn new() -> Self {
        Self {
            escape_buf: [0; ESCAPE_BUF_SIZE],
            escape_len: 0,
            in_escape: false,
            queued_key: None,
            pending_key: None,
        }
    }
}

// ============================================================================
// Accessors
// ============================================================================

/// Borrow EFI service state.
#[inline]
#[track_caller]
pub fn efi() -> Ref<'static, EfiState> {
    EFI.borrow()
}

/// Mutate EFI service state through a closure.
#[inline]
#[track_caller]
pub fn with_efi_mut<R>(f: impl FnOnce(&mut EfiState) -> R) -> R {
    EFI.with_mut(f)
}

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

/// Borrow console state.
#[inline]
#[track_caller]
pub fn console() -> Ref<'static, ConsoleState> {
    CONSOLE.borrow()
}

/// Mutate console state through a closure.
#[inline]
#[track_caller]
pub fn with_console_mut<R>(f: impl FnOnce(&mut ConsoleState) -> R) -> R {
    CONSOLE.with_mut(f)
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
