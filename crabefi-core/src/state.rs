//! Global Firmware State
//!
//! `FirmwareState` is allocated by the entry point and published through one
//! raw pointer. It does not expose `&'static` references. Instead, each major
//! subsystem lives in its own `UnsafeCell` and has a raw-pointer projection
//! (`efi_ptr`, `drivers_ptr`, `allocator_ptr`, and so on).
//!
//! The subsystem split matters: an EFI mutation no longer creates an exclusive
//! borrow of driver, console, allocator, or variable-store state. Mutable
//! closure accessors borrow only one cell and use always-on re-entrancy guards.
//! Log sinks use raw projections and must restrict themselves to their assigned
//! fields so logging can remain allocation-free and non-locking.
//!
//! CrabEFI is single-threaded. The atomic pointer and borrow flags therefore use
//! `Ordering::Relaxed`; they publish no cross-thread synchronization guarantee.

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::fs::fat::FatType;

/// Global pointer to the firmware state.
///
/// This is the ONLY global mutable state. It points to a `FirmwareState`
/// allocated on the stack in `init()`.
static STATE_PTR: AtomicPtr<FirmwareState> = AtomicPtr::new(core::ptr::null_mut());
static EFI_BORROWED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static DRIVER_BORROWED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static CONSOLE_BORROWED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static ALLOCATOR_BORROWED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static VARSTORE_BORROWED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

struct BorrowGuard(&'static core::sync::atomic::AtomicBool);

impl BorrowGuard {
    #[inline]
    fn enter(flag: &'static core::sync::atomic::AtomicBool, name: &str) -> Self {
        assert!(
            !flag.swap(true, Ordering::Relaxed),
            "re-entrant mutable {name} state access"
        );
        Self(flag)
    }
}

impl Drop for BorrowGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

/// Initialize the global state pointer.
///
/// # Safety
///
/// - Must only be called once, at the start of `init()`
/// - The `state` reference must remain valid for the entire firmware lifetime
/// - The firmware must be single-threaded
pub unsafe fn init(state: &mut FirmwareState) {
    // SAFETY: The caller guarantees that `state` remains valid for the
    // firmware lifetime and no other state has been installed.
    let _ = unsafe { (state as *const FirmwareState).as_ref() };
    STATE_PTR.store(state as *mut FirmwareState, Ordering::Relaxed);
}

/// Check if state has been initialized.
pub fn is_initialized() -> bool {
    !STATE_PTR.load(Ordering::Relaxed).is_null()
}

/// Get the raw pointer to the global firmware state.
///
/// No reference is returned: callers must project a subsystem pointer before
/// accessing state, so aliasing is explicit at every unsafe access site.
#[inline]
pub fn state_ptr() -> *mut FirmwareState {
    let ptr = STATE_PTR.load(Ordering::Relaxed);
    assert!(!ptr.is_null(), "FirmwareState not initialized");
    ptr
}

/// Try to get the raw global state pointer before initialization completes.
#[inline]
pub fn try_state_ptr() -> Option<*mut FirmwareState> {
    let ptr = STATE_PTR.load(Ordering::Relaxed);
    (!ptr.is_null()).then_some(ptr)
}

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
// Firmware State Structure
// ============================================================================

/// Main firmware state structure.
///
/// This struct holds all mutable state for the firmware, organized into
/// logical subsystems.
pub struct FirmwareState {
    /// EFI service state.
    efi: UnsafeCell<EfiState>,
    /// Page and pool allocator state, isolated from EFI service bookkeeping.
    allocator: UnsafeCell<MemoryAllocator>,
    /// Persistent variable-store bookkeeping.
    varstore: UnsafeCell<VarStoreState>,
    /// Filesystem block device.
    block_device: UnsafeCell<Option<crate::drivers::block::AnyBlockDevice>>,
    /// Hardware driver state.
    drivers: UnsafeCell<DriverState>,
    /// Console and display state.
    console: UnsafeCell<ConsoleState>,
}

impl FirmwareState {
    /// Create a new firmware state with default values.
    ///
    /// This is `const fn` so it can be used for static initialization
    /// or stack allocation.
    pub const fn new() -> Self {
        Self {
            efi: UnsafeCell::new(EfiState::new()),
            allocator: UnsafeCell::new(MemoryAllocator::new()),
            varstore: UnsafeCell::new(VarStoreState::new()),
            block_device: UnsafeCell::new(None),
            drivers: UnsafeCell::new(DriverState::new()),
            console: UnsafeCell::new(ConsoleState::new()),
        }
    }
}

impl Default for FirmwareState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// EFI State
// ============================================================================

use crate::efi::allocator::MemoryAllocator;
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

// SAFETY: ProtocolEntry contains raw pointers to protocol interfaces.
// These pointers point to memory allocated via the EFI allocator which
// remains valid for the lifetime of the firmware. CrabEFI is single-threaded.
unsafe impl Send for ProtocolEntry {}
unsafe impl Sync for ProtocolEntry {}

impl ProtocolEntry {
    pub const fn empty() -> Self {
        Self {
            guid: Guid::from_fields(0, 0, 0, 0, 0, &[0, 0, 0, 0, 0, 0]),
            interface: core::ptr::null_mut(),
        }
    }
}

/// Handle entry in the handle database
#[derive(Clone, Copy)]
pub struct HandleEntry {
    pub handle: Handle,
    pub protocols: [ProtocolEntry; MAX_PROTOCOLS_PER_HANDLE],
    pub protocol_count: usize,
}

// SAFETY: HandleEntry contains EFI Handle (raw pointer) and ProtocolEntry array.
// Handles are opaque identifiers that remain valid until explicitly closed.
// CrabEFI is single-threaded with no concurrent access to handle data.
unsafe impl Send for HandleEntry {}
unsafe impl Sync for HandleEntry {}

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

// Safety: EventEntry contains raw pointers used as opaque callback contexts.
// CrabEFI is single-threaded; all event access is serialized.
unsafe impl Send for EventEntry {}
unsafe impl Sync for EventEntry {}

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

// SAFETY: LoadedImageEntry contains opaque EFI handles and an optional owned
// measurement buffer pointer. They remain valid until StartImage/UnloadImage
// frees them, and all access to loaded image entries is serialized.
unsafe impl Send for LoadedImageEntry {}
unsafe impl Sync for LoadedImageEntry {}

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

/// Variable store persistence state
///
/// Tracks the runtime state of the persistent variable store region.
/// The actual storage location is determined at runtime from coreboot
/// tables (SMMSTORE v2) or FMAP (SMMSTORE region).
#[derive(Clone, Copy)]
pub struct VarStoreState {
    /// Whether the store header has been validated/written
    pub initialized: bool,
    /// Next free location for appending records (relative to store start)
    pub write_offset: u32,
    /// Whether the EDK2 FV uses authenticated variable headers (60 bytes vs 32)
    pub auth_format: bool,
    /// Size of the variable data area (after FV + VS headers)
    pub data_size: u32,
}

impl VarStoreState {
    pub const fn new() -> Self {
        Self {
            initialized: false,
            write_offset: 0,
            auth_format: false,
            data_size: 0,
        }
    }
}

impl Default for VarStoreState {
    fn default() -> Self {
        Self::new()
    }
}

/// One tracked `OpenProtocol` relationship.
#[derive(Clone, Copy)]
pub struct OpenProtocolEntry {
    pub handle: Handle,
    pub protocol: Guid,
    pub agent_handle: Handle,
    pub controller_handle: Handle,
    pub attributes: u32,
    pub open_count: u32,
}

/// EFI subsystem state
pub struct EfiState {
    /// Validated boot-side client for the separately allocated runtime image.
    pub runtime_image: Option<crate::efi::runtime_image::RuntimeImageClient>,

    /// Handle database, allocated after heap startup.
    pub handles: Vec<HandleEntry>,
    /// Number of active handles
    pub handle_count: usize,
    /// Active protocol opens, grown fallibly from the firmware heap.
    pub open_protocols: Vec<OpenProtocolEntry>,
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

    /// Filesystem state for SimpleFileSystem protocol
    pub filesystem: Option<FilesystemState>,
}

impl EfiState {
    pub const fn new() -> Self {
        Self {
            runtime_image: None,
            handles: Vec::new(),
            handle_count: 0,
            open_protocols: Vec::new(),
            next_handle: 1,
            events: Vec::new(),
            next_event_id: 2, // Start at 2, reserve 1 for keyboard
            loaded_images: Vec::new(),

            monotonic_count: 0,
            ready_to_boot_signaled: false,
            filesystem: None,
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
use crate::drivers::serial::{AnySerial, PlatformSerial};
use crate::drivers::storage::StorageRegistry;
use crate::efi::protocols::serial_io::SerialIoMode;
use crate::platform::{FramebufferConfig, PciEcamRegion};
use heapless::Vec as HeaplessVec;
use r_efi::efi::Boolean;
use r_efi::protocols::simple_text_output::Mode as SimpleTextOutputMode;

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

    /// Serial port (hardware driver + EFI protocol mode)
    pub serial: SerialState,

    /// Timing calibration (TSC/ARM generic timer)
    pub timing: TimingState,

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
            serial: SerialState::new(),
            timing: TimingState::new(),
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
// Serial State
// ----------------------------------------------------------------------------

/// Serial port state: hardware driver and EFI protocol mode.
pub struct SerialState {
    /// Active serial port driver (16550 UART, PL011, or platform-provided primary output).
    pub(crate) driver: Option<AnySerial>,
    /// Optional mirror for debug output such as a firmware memory console.
    pub(crate) debug_sink: Option<PlatformSerial>,
    /// EFI Serial IO protocol mode (current port settings).
    ///
    /// The Protocol.mode pointer is set to point here during init.
    pub io_mode: SerialIoMode,
}

impl SerialState {
    pub const fn new() -> Self {
        use crate::efi::protocols::serial_io::{
            EFI_SERIAL_CARRIER_DETECT, EFI_SERIAL_CLEAR_TO_SEND, EFI_SERIAL_DATA_SET_READY,
            EFI_SERIAL_DATA_TERMINAL_READY, EFI_SERIAL_INPUT_BUFFER_EMPTY,
            EFI_SERIAL_OUTPUT_BUFFER_EMPTY, EFI_SERIAL_REQUEST_TO_SEND, EFI_SERIAL_RING_INDICATE,
        };

        Self {
            driver: None,
            debug_sink: None,
            io_mode: SerialIoMode {
                control_mask: EFI_SERIAL_CLEAR_TO_SEND
                    | EFI_SERIAL_DATA_SET_READY
                    | EFI_SERIAL_RING_INDICATE
                    | EFI_SERIAL_CARRIER_DETECT
                    | EFI_SERIAL_INPUT_BUFFER_EMPTY
                    | EFI_SERIAL_OUTPUT_BUFFER_EMPTY
                    | EFI_SERIAL_REQUEST_TO_SEND
                    | EFI_SERIAL_DATA_TERMINAL_READY,
                timeout: 1000000,
                baud_rate: 115200,
                receive_fifo_depth: 16,
                data_bits: 8,
                parity: 1,    // NoParity
                stop_bits: 1, // OneStopBit
            },
        }
    }
}

impl Default for SerialState {
    fn default() -> Self {
        Self::new()
    }
}

// ----------------------------------------------------------------------------
// Timing State
// ----------------------------------------------------------------------------

/// Timing calibration state.
///
/// On x86, the TSC is calibrated against the ACPI PM timer.
/// On aarch64, the ARM Generic Timer frequency register is read directly.
pub struct TimingState {
    /// Counter frequency in Hz (set during calibration)
    pub counter_freq_hz: u64,
    /// Counter cycles per microsecond (cached for fast delay loops)
    pub counter_cycles_per_us: u64,
    /// Initial counter value at boot (for relative timestamps in log output)
    pub boot_counter: u64,
}

impl TimingState {
    pub const fn new() -> Self {
        Self {
            counter_freq_hz: 2_000_000_000, // Conservative 2 GHz fallback
            counter_cycles_per_us: 2000,
            boot_counter: 0,
        }
    }
}

impl Default for TimingState {
    fn default() -> Self {
        Self::new()
    }
}

// ----------------------------------------------------------------------------
// Platform Info
// ----------------------------------------------------------------------------

/// Platform hardware info sourced from platform config.
pub struct PlatformInfo {
    /// Global framebuffer info
    pub framebuffer: Option<FramebufferConfig>,

    /// Storage backend for variable persistence (SPI flash).
    ///
    /// Initialized during boot from detected SPI controller.
    /// Handles offset translation so reads/writes are relative to
    /// the variable store region.
    pub storage: Option<crate::efi::varstore::SpiStorageBackend>,

    /// Memory regions (for direct Linux boot)
    pub memory_regions: HeaplessVec<crate::platform::MemoryRegion, MAX_MEMORY_REGIONS>,

    /// ACPI RSDP address
    pub acpi_rsdp: Option<u64>,

    /// EFI firmware info (GUID, version, LSV) provided by the platform.
    pub efi_fw_info: Option<crate::platform::FirmwareInfo>,

    /// Capsule regions provided by the platform.
    pub capsule_regions: HeaplessVec<crate::platform::CapsuleRegion, MAX_CAPSULES>,

    /// Optional platform lifecycle callbacks.
    pub hooks: Option<&'static dyn crate::platform::PlatformHooks>,

    /// Platform reset handler.
    pub reset: Option<&'static dyn crate::platform::ResetHandler>,

    /// Optional firmware-visible boot timestamp recorder.
    pub timestamp_recorder: Option<&'static dyn crate::platform::TimestampRecorder>,
}

impl PlatformInfo {
    pub const fn new() -> Self {
        Self {
            framebuffer: None,
            storage: None,
            memory_regions: HeaplessVec::new(),
            acpi_rsdp: None,
            efi_fw_info: None,
            capsule_regions: HeaplessVec::new(),
            hooks: None,
            reset: None,
            timestamp_recorder: None,
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

    /// Logger framebuffer info (used by fb_log for debug output)
    pub logger_framebuffer: Option<FramebufferConfig>,
    /// Logger cursor position (row, col)
    pub logger_cursor: (u32, u32),

    /// GOP framebuffer for graphics output protocol Blt operations
    pub gop_framebuffer: Option<FramebufferConfig>,

    /// Screen mode (Text or Graphics) for ConsoleControl protocol
    pub screen_mode: ScreenMode,

    /// EFI SimpleTextOutput mode structure
    ///
    /// The Protocol.mode pointer is set to point here during init.
    /// This tracks cursor position, attribute, and mode for the EFI text console.
    pub output_mode: SimpleTextOutputMode,
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
            logger_framebuffer: None,
            logger_cursor: (0, 0),
            gop_framebuffer: None,
            screen_mode: ScreenMode::Graphics,
            output_mode: SimpleTextOutputMode {
                max_mode: 1,
                mode: 0,
                attribute: 0x07, // Light gray on black
                cursor_column: 0,
                cursor_row: 0,
                cursor_visible: Boolean::TRUE,
            },
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
// Filesystem State
// ============================================================================

/// Filesystem state - stores partition info for reading files
#[derive(Clone, Copy)]
pub struct FilesystemState {
    /// First LBA of the partition (in device blocks)
    pub partition_start: u64,
    /// FAT type
    pub fat_type: FatType,
    /// Bytes per sector (FAT's logical sector size)
    pub bytes_per_sector: u16,
    /// Device block size (physical block size, may differ from bytes_per_sector)
    pub device_block_size: u32,
    /// Sectors per cluster
    pub sectors_per_cluster: u8,
    /// First FAT sector (relative to partition start, in FAT sectors)
    pub fat_start: u32,
    /// Sectors per FAT
    pub sectors_per_fat: u32,
    /// First data sector (relative to partition start, in FAT sectors)
    pub data_start: u32,
    /// Root directory cluster (FAT32) or 0 (FAT12/16)
    pub root_cluster: u32,
    /// Root directory sector start (FAT12/16 only, in FAT sectors)
    pub root_dir_start: u32,
    /// Root directory sector count (FAT12/16 only)
    pub root_dir_sectors: u32,
}

impl FilesystemState {
    pub const fn empty() -> Self {
        Self {
            partition_start: 0,
            fat_type: FatType::Fat12,
            bytes_per_sector: 0,
            device_block_size: 0,
            sectors_per_cluster: 0,
            fat_start: 0,
            sectors_per_fat: 0,
            data_start: 0,
            root_cluster: 0,
            root_dir_start: 0,
            root_dir_sectors: 0,
        }
    }

    /// Translate FAT sector to device block
    pub fn fat_sector_to_device_block(&self, fat_sector: u64) -> u64 {
        if self.bytes_per_sector as u32 == self.device_block_size {
            fat_sector
        } else {
            (fat_sector * self.bytes_per_sector as u64) / self.device_block_size as u64
        }
    }
}

// ============================================================================
// Helper functions for accessing state components
// ============================================================================

/// Get a raw pointer to EFI service state.
#[inline]
pub fn efi_ptr() -> *mut EfiState {
    unsafe { UnsafeCell::raw_get(core::ptr::addr_of!((*state_ptr()).efi)) }
}

/// Access EFI service state mutably through its disjoint cell.
#[inline]
pub fn with_efi_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut EfiState) -> R,
{
    let _guard = BorrowGuard::enter(&EFI_BORROWED, "EFI");
    unsafe { f(&mut *efi_ptr()) }
}

/// Get a raw pointer to driver state.
#[inline]
pub fn drivers_ptr() -> *mut DriverState {
    unsafe { UnsafeCell::raw_get(core::ptr::addr_of!((*state_ptr()).drivers)) }
}

/// Access driver state mutably through its disjoint cell.
#[inline]
pub fn with_drivers_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut DriverState) -> R,
{
    let _guard = BorrowGuard::enter(&DRIVER_BORROWED, "driver");
    unsafe { f(&mut *drivers_ptr()) }
}

// ---------------------------------------------------------------------------
// Framebuffer state — source-agnostic (coreboot tables or platform config)
// ---------------------------------------------------------------------------

/// Store framebuffer info in global state.
///
/// Called from both the coreboot path (after parsing `lb_framebuffer`) and the
/// platform library path (after converting `FramebufferConfig`). The stored
/// info is used by boot menus, the Linux boot path (`screen_info`), and error
/// display — all of which call [`get_framebuffer()`].
pub fn store_framebuffer(fb: crate::platform::FramebufferConfig) {
    with_drivers_mut(|drivers| {
        drivers.platform.framebuffer = Some(fb);
    });
}

/// Get the global framebuffer info, if available.
///
/// Returns `Some` when a framebuffer was provided by either coreboot tables
/// or the platform library's `FramebufferConfig`. Used by boot menus,
/// `boot_linux()` (screen_info), and error display.
pub fn get_framebuffer() -> Option<crate::platform::FramebufferConfig> {
    unsafe { (*drivers_ptr()).platform.framebuffer }
}

/// Get a raw pointer to console state.
#[inline]
pub fn console_ptr() -> *mut ConsoleState {
    unsafe { UnsafeCell::raw_get(core::ptr::addr_of!((*state_ptr()).console)) }
}

/// Access console state mutably through its disjoint cell.
#[inline]
pub fn with_console_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut ConsoleState) -> R,
{
    let _guard = BorrowGuard::enter(&CONSOLE_BORROWED, "console");
    unsafe { f(&mut *console_ptr()) }
}

/// Get a raw pointer to allocator state.
#[inline]
pub fn allocator_ptr() -> *mut MemoryAllocator {
    unsafe { UnsafeCell::raw_get(core::ptr::addr_of!((*state_ptr()).allocator)) }
}

/// Access allocator state mutably through its disjoint cell.
#[inline]
pub fn with_allocator_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut MemoryAllocator) -> R,
{
    let _guard = BorrowGuard::enter(&ALLOCATOR_BORROWED, "allocator");
    unsafe { f(&mut *allocator_ptr()) }
}

/// Access the block device mutably through a closure.
///
/// Returns `None` if no block device is configured.
#[inline]
pub fn with_block_device_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut crate::drivers::block::AnyBlockDevice) -> R,
{
    unsafe { (*block_device_ptr()).as_mut().map(f) }
}

/// Replace the filesystem block device.
pub fn set_block_device(device: crate::drivers::block::AnyBlockDevice) {
    unsafe { *block_device_ptr() = Some(device) };
}

#[inline]
fn block_device_ptr() -> *mut Option<crate::drivers::block::AnyBlockDevice> {
    unsafe { UnsafeCell::raw_get(core::ptr::addr_of!((*state_ptr()).block_device)) }
}

/// Access the storage backend mutably through a closure.
///
/// Returns `None` if no storage backend is configured.
#[inline]
pub fn with_storage_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut crate::efi::varstore::SpiStorageBackend) -> R,
{
    unsafe { (*drivers_ptr()).platform.storage.as_mut().map(f) }
}

/// Get a raw pointer to variable-store state.
#[inline]
pub fn varstore_ptr() -> *mut VarStoreState {
    unsafe { UnsafeCell::raw_get(core::ptr::addr_of!((*state_ptr()).varstore)) }
}

/// Access variable-store state mutably through its disjoint cell.
#[inline]
pub fn with_varstore_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut VarStoreState) -> R,
{
    let _guard = BorrowGuard::enter(&VARSTORE_BORROWED, "variable-store");
    unsafe { f(&mut *varstore_ptr()) }
}
