//! Global Firmware State
//!
//! This module provides a centralized state structure for CrabEFI that holds all
//! mutable state. Instead of having many scattered `static Mutex<T>` variables,
//! we allocate a single `FirmwareState` struct on the stack in the entry point
//! and store a pointer to it in a single global.
//!
//! This is more idiomatic Rust because:
//! - State ownership is clear (it lives on the main stack)
//! - All state is colocated, making it easier to reason about
//! - We minimize the number of global statics
//!
//! # Architecture
//!
//! ```text
//! init() in lib.rs
//!   |
//!   v
//! FirmwareState on stack
//!   |
//!   +-- efi: EfiState
//!   |     +-- handles, events, loaded_images
//!   |     +-- config_tables, variables, varstore
//!   |     +-- allocator, secure boot flags
//!   |
//!   +-- drivers: DriverState
//!   |     +-- pci: PciState (devices, ecam, access method)
//!   |     +-- serial: SerialState (driver, port, EFI mode)
//!   |     +-- timing: TimingState (counter freq, boot timestamp)
//!   |     +-- platform: PlatformInfo (framebuffer, SPI, handoff data)
//!   |     +-- keyboard, usb_keyboard, storage_registry, rng
//!   |
//!   +-- console: ConsoleState
//!         +-- framebuffer, cursor, dimensions, colors
//!         +-- input state, screen_mode, output_mode
//! ```
//!
//! # Thread Safety
//!
//! CrabEFI is single-threaded firmware. We use `UnsafeCell` for interior
//! mutability without the overhead of `Mutex`. The UEFI spec guarantees
//! that Boot Services are not reentrant.
//!
//! # Log-Path Contract
//!
//! Functions called from the `log` crate macros — serial output
//! ([`crate::drivers::serial`]), platform log sinks, framebuffer logging
//! ([`crate::fb_log`]), and the timestamp helper
//! ([`crate::logger::get_us_since_boot`]) — must **never** create Rust
//! references (`&` or `&mut`) into `FirmwareState`.
//!
//! This is necessary because `log::info!()` and friends may fire *inside*
//! a `with_mut()` / `with_drivers_mut()` closure, which holds a live
//! `&mut FirmwareState`.  Creating any `&FirmwareState` (e.g. via
//! [`drivers()`] or [`try_get()`]) would alias with that `&mut` — UB
//! under Rust's reference rules.
//!
//! Instead, log-path code uses **raw-pointer field access**:
//!
//! - **Writes**: `(*drivers_mut_ptr()).serial.driver` (serial, fb_log)
//! - **Reads**: `(*drivers_mut_ptr()).timing.boot_counter` (timestamps)
//!
//! Raw-pointer access is sound here because:
//!
//! 1. The firmware is single-threaded — no data races.
//! 2. The log-path functions only touch their own disjoint fields
//!    (e.g. `serial.driver`, `console.logger_*`, `timing.boot_counter`).
//! 3. They never read or write fields that the enclosing `with_mut()`
//!    closure is currently modifying.

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::fs::fat::FatType;

/// Global pointer to the firmware state.
///
/// This is the ONLY global mutable state. It points to a `FirmwareState`
/// allocated on the stack in `init()`.
static STATE_PTR: AtomicPtr<FirmwareState> = AtomicPtr::new(core::ptr::null_mut());

/// Pointer-free phase flag used by runtime entry points after boot state is
/// no longer reachable.
static EXIT_BOOT_SERVICES_CALLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Re-entrancy guard for `with_mut`. In debug builds, detects nested calls
/// that would create aliasing `&mut` references (undefined behavior).
#[cfg(debug_assertions)]
static IN_WITH_MUT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Initialize the global state pointer.
///
/// # Safety
///
/// - Must only be called once, at the start of `init()`
/// - `state` must point to a `FirmwareState` that remains valid for the entire
///   firmware lifetime
/// - The firmware must be single-threaded
///
/// Takes a raw pointer rather than `&mut` so callers can install a `static mut`
/// without tripping `static_mut_refs`.
pub unsafe fn init(state: *mut FirmwareState) {
    assert!(!state.is_null(), "FirmwareState pointer is null");
    STATE_PTR.store(state, Ordering::Release);
}

/// Check if state has been initialized.
pub fn is_initialized() -> bool {
    !STATE_PTR.load(Ordering::Acquire).is_null()
}

/// Relocate the global state pointer to a new virtual address.
///
/// Called by `SetVirtualAddressMap` when the OS remaps runtime services
/// memory from physical to virtual addresses.
///
/// # Safety
///
/// The new pointer must point to valid `FirmwareState` memory that has been
/// remapped by the OS.
pub unsafe fn relocate_state_ptr(new_ptr: *mut FirmwareState) {
    // SAFETY: The caller guarantees that `new_ptr` is the runtime-mapped
    // address of the installed firmware state.
    if unsafe { new_ptr.as_ref() }.is_none() {
        panic!("FirmwareState pointer is null");
    }
    STATE_PTR.store(new_ptr, Ordering::Release);
}

/// Get a reference to the global firmware state.
///
/// # Panics
///
/// Panics if called before `init()`.
#[inline]
pub fn get() -> &'static FirmwareState {
    let ptr = STATE_PTR.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "FirmwareState not initialized");
    unsafe { &*ptr }
}

/// Get a raw mutable pointer to the global firmware state.
///
/// This returns a raw pointer rather than a reference to avoid creating
/// multiple aliasing `&mut` references which would be undefined behavior.
///
/// # Panics
///
/// Panics if called before `init()`.
///
/// # Safety Note
///
/// The returned pointer is valid for the firmware lifetime. Callers must
/// ensure they don't create overlapping mutable references when dereferencing.
/// In single-threaded firmware this is typically safe, but care must be taken
/// with nested function calls.
#[inline]
pub fn get_mut_ptr() -> *mut FirmwareState {
    let ptr = STATE_PTR.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "FirmwareState not initialized");
    ptr
}

/// Access the firmware state mutably through a closure.
///
/// This is the preferred way to mutate firmware state as it makes the
/// borrowing scope explicit and prevents accidental aliasing.
///
/// # Example
///
/// ```ignore
/// state::with_mut(|state| {
///     state.efi.handle_count += 1;
/// });
/// ```
#[inline]
pub fn with_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut FirmwareState) -> R,
{
    #[cfg(debug_assertions)]
    assert!(
        !IN_WITH_MUT.swap(true, Ordering::Acquire),
        "Nested with_mut call detected — this creates aliasing &mut references (UB). \
         Refactor to avoid re-entrant state access."
    );

    let ptr = STATE_PTR.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "FirmwareState not initialized");
    // SAFETY: Single-threaded firmware, closure scope limits aliasing.
    // The debug_assertions guard above detects re-entrant calls at runtime.
    let result = unsafe { f(&mut *ptr) };

    #[cfg(debug_assertions)]
    IN_WITH_MUT.store(false, Ordering::Release);

    result
}

/// Try to get a reference to the global firmware state.
///
/// Returns `None` if state has not been initialized yet.
#[inline]
pub fn try_get() -> Option<&'static FirmwareState> {
    let ptr = STATE_PTR.load(Ordering::Acquire);
    (!ptr.is_null()).then(|| unsafe { &*ptr })
}

/// Try to get a raw mutable pointer to the global firmware state.
///
/// Returns `None` if state has not been initialized yet.
/// See `get_mut_ptr()` for safety considerations.
#[inline]
pub fn try_get_mut_ptr() -> Option<*mut FirmwareState> {
    let ptr = STATE_PTR.load(Ordering::Acquire);
    (!ptr.is_null()).then_some(ptr)
}

// ============================================================================
// Firmware State Structure
// ============================================================================

/// Main firmware state structure.
///
/// This struct holds all mutable state for the firmware, organized into
/// logical subsystems.
pub struct FirmwareState {
    /// EFI subsystem state (handles, events, allocator, etc.)
    pub efi: EfiState,

    /// Hardware driver state
    pub drivers: DriverState,

    /// Console and display state
    pub console: ConsoleState,
}

impl FirmwareState {
    /// Create a new firmware state with default values.
    ///
    /// This is `const fn` so it can be used for static initialization
    /// or stack allocation.
    pub const fn new() -> Self {
        Self {
            efi: EfiState::new(),
            drivers: DriverState::new(),
            console: ConsoleState::new(),
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

/// Maximum number of configuration tables
pub const MAX_CONFIG_TABLES: usize = 24;

/// Maximum number of EFI variables
pub const MAX_VARIABLES: usize = 64;

/// Maximum variable name length (in characters)
pub const MAX_VARIABLE_NAME_LEN: usize = 64;

/// Maximum variable data size (stored payload, after auth header stripping)
///
/// This must be large enough for Secure Boot key databases (PK, KEK, db, dbx).
/// A single X.509 certificate in an EFI_SIGNATURE_LIST is typically 1-2 KB,
/// and databases with multiple certificates (e.g. Microsoft CA chain + custom
/// keys from sbctl) can reach 4-8 KB.
///
/// This payload is stored inline inside [`FirmwareState`] rather than on the
/// heap. Runtime services reach the variable cache through `STATE_PTR`, which
/// `SetVirtualAddressMap` relocates as a single pointer; inline storage is
/// therefore addressed as an offset from that base and stays valid in virtual
/// mode. A heap-backed payload would keep a physical pointer that nothing
/// relocates, and the first post-SVAM `GetVariable` would fault.
pub const MAX_VARIABLE_DATA_SIZE: usize = 16 * 1024;

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

/// EFI Configuration Table entry
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ConfigurationTable {
    pub vendor_guid: Guid,
    pub vendor_table: *mut core::ffi::c_void,
}

// SAFETY: ConfigurationTable contains a raw pointer to vendor-specific data (e.g., ACPI tables).
// These pointers reference memory that:
// 1. Is allocated and initialized before being added to the configuration table
// 2. Remains valid for the entire firmware lifetime (ACPI tables, SMBIOS, etc.)
// 3. Is only read by the OS after ExitBootServices, at which point the firmware
//    is no longer running and there are no concurrent accesses
unsafe impl Send for ConfigurationTable {}
unsafe impl Sync for ConfigurationTable {}

impl ConfigurationTable {
    pub const fn empty() -> Self {
        Self {
            vendor_guid: Guid::from_fields(0, 0, 0, 0, 0, &[0, 0, 0, 0, 0, 0]),
            vendor_table: core::ptr::null_mut(),
        }
    }
}

/// EFI variable entry
///
/// The payload is stored inline so the whole entry relocates with
/// [`FirmwareState`] across `SetVirtualAddressMap`.
#[derive(Clone, Copy)]
pub struct VariableEntry {
    pub name: [u16; MAX_VARIABLE_NAME_LEN],
    pub vendor_guid: Guid,
    pub attributes: u32,
    pub data: [u8; MAX_VARIABLE_DATA_SIZE],
    pub data_size: usize,
    pub in_use: bool,
}

impl VariableEntry {
    /// Create an unused variable-cache entry.
    ///
    /// # Returns
    /// An empty cache entry.
    pub const fn empty() -> Self {
        Self {
            name: [0; MAX_VARIABLE_NAME_LEN],
            vendor_guid: Guid::from_fields(0, 0, 0, 0, 0, &[0, 0, 0, 0, 0, 0]),
            attributes: 0,
            data: [0; MAX_VARIABLE_DATA_SIZE],
            data_size: 0,
            in_use: false,
        }
    }

    /// Replace the variable payload without exceeding its UEFI size limit.
    ///
    /// The tail is zeroed as defense-in-depth for variable isolation, so a
    /// shorter payload cannot expose a previous variable's bytes.
    ///
    /// # Arguments
    /// * `data` - New variable payload.
    ///
    /// # Returns
    /// `Err(())` when the payload exceeds [`MAX_VARIABLE_DATA_SIZE`].
    pub fn set_data(&mut self, data: &[u8]) -> Result<(), ()> {
        if data.len() > MAX_VARIABLE_DATA_SIZE {
            return Err(());
        }
        self.data[..data.len()].copy_from_slice(data);
        self.data[data.len()..].fill(0);
        self.data_size = data.len();
        Ok(())
    }

    /// Release a deleted variable's payload.
    pub fn clear(&mut self) {
        self.data.fill(0);
        self.data_size = 0;
        self.in_use = false;
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

/// EFI subsystem state
pub struct EfiState {
    /// Handle database
    pub handles: [HandleEntry; MAX_HANDLES],
    /// Number of active handles
    pub handle_count: usize,
    /// Next handle value (unique identifier)
    pub next_handle: usize,

    /// Event database
    pub events: [EventEntry; MAX_EVENTS],
    /// Next event ID (starting at 2, 1 is reserved for keyboard)
    pub next_event_id: usize,

    /// Loaded images database
    pub loaded_images: [LoadedImageEntry; MAX_LOADED_IMAGES],

    /// Configuration tables
    ///
    /// The EFI system table publishes a pointer into this array, so it must
    /// relocate with [`FirmwareState`] rather than living on the heap.
    pub config_tables: [ConfigurationTable; MAX_CONFIG_TABLES],
    /// Number of configuration tables
    pub config_table_count: usize,

    /// EFI variables
    pub variables: [VariableEntry; MAX_VARIABLES],

    /// Variable store persistence state (SMMSTORE tracking)
    pub varstore: VarStoreState,

    /// Memory allocator
    pub allocator: MemoryAllocator,

    /// Monotonic counter for GetNextMonotonicCount
    pub monotonic_count: u64,

    /// Flag indicating EFI_EVENT_GROUP_READY_TO_BOOT has been signaled
    /// Per UEFI spec, this should only be signaled once before the first
    /// boot option is attempted.
    pub ready_to_boot_signaled: bool,

    /// Filesystem state for SimpleFileSystem protocol
    pub filesystem: Option<FilesystemState>,

    /// Block device for filesystem access
    pub block_device: Option<crate::drivers::block::AnyBlockDevice>,

    /// Secure Boot: whether in Setup Mode (PK not enrolled)
    pub setup_mode: bool,

    /// Secure Boot: whether Secure Boot is enabled
    pub secure_boot_enabled: bool,
}

impl EfiState {
    pub const fn new() -> Self {
        Self {
            handles: [const { HandleEntry::empty() }; MAX_HANDLES],
            handle_count: 0,
            next_handle: 1,
            events: [const { EventEntry::empty() }; MAX_EVENTS],
            next_event_id: 2, // Start at 2, reserve 1 for keyboard
            loaded_images: [const { LoadedImageEntry::empty() }; MAX_LOADED_IMAGES],
            config_tables: [const { ConfigurationTable::empty() }; MAX_CONFIG_TABLES],
            config_table_count: 0,
            variables: [const { VariableEntry::empty() }; MAX_VARIABLES],
            varstore: VarStoreState::new(),
            allocator: MemoryAllocator::new(),
            monotonic_count: 0,
            ready_to_boot_signaled: false,

            filesystem: None,
            block_device: None,
            setup_mode: true,
            secure_boot_enabled: false,
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
use crate::platform::FramebufferConfig;
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
    /// and ECAM via `PlatformConfig.ecam_base` leave this empty.
    ///
    /// `init_platform()` checks `acpi_info.ecam_base` as a fallback for PCI
    /// ECAM discovery (after `config.ecam_base`, before `fdt_info.ecam_base`).
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
    /// PCIe ECAM base address (from ACPI MCFG or coreboot)
    pub ecam_base: Option<u64>,
    /// PCIe ECAM window size in bytes, when known.
    pub ecam_size: Option<u64>,
    /// Config space access method (legacy I/O CAM or PCIe ECAM)
    pub access: AnyPciAccess,
}

impl PciState {
    pub const fn new() -> Self {
        Self {
            devices: HeaplessVec::new(),
            ecam_base: None,
            ecam_size: None,
            // x86 defaults to legacy I/O CAM (ports 0xCF8/0xCFC).
            // Non-x86 defaults to ECAM at address 0 — PCI init will
            // replace this once a real ECAM base is discovered from
            // ACPI MCFG, FDT, or PlatformConfig.ecam_base. Reads to
            // ECAM address 0 return bus errors / 0xFFFFFFFF (no device),
            // which is the correct "nothing here" response.
            #[cfg(target_arch = "x86_64")]
            access: AnyPciAccess::IoCam(crate::drivers::pci::access::IoCamAccess),
            #[cfg(not(target_arch = "x86_64"))]
            access: AnyPciAccess::Ecam(crate::drivers::pci::access::EcamAccess::new(0)),
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

/// Get a reference to the EFI state.
#[inline]
pub fn efi() -> &'static EfiState {
    &get().efi
}

/// Verify that the pointer-free runtime root is initialized and reserved.
///
/// Recursive pointer exclusion is enforced by the [`crate::runtime_state::VamSafe`]
/// const assertion. This runtime check verifies the root's linker placement and
/// the EFI memory descriptor that the OS will receive.
pub fn assert_runtime_relocatable() {
    use crate::efi::allocator::{self, MemoryType};

    let physical = crate::runtime_state::physical_address();
    let current = crate::runtime_state::get() as *const _ as u64;
    assert_eq!(
        current, physical,
        "runtime state root was not initialized to its physical address"
    );

    let size = core::mem::size_of::<crate::runtime_state::RuntimeState>() as u64;
    let Some(end) = physical.checked_add(size) else {
        panic!("runtime state address range overflows");
    };

    #[cfg(feature = "platform-entry")]
    {
        unsafe extern "C" {
            static _runtime_state_start: u8;
            static _runtime_state_end: u8;
        }
        let section_start = &raw const _runtime_state_start as u64;
        let section_end = &raw const _runtime_state_end as u64;
        assert!(
            physical >= section_start && end <= section_end,
            "runtime state root lies outside .runtime_state"
        );
    }

    let mut address = physical;
    while address < end {
        if allocator::get_memory_type_at(address) != Some(MemoryType::RuntimeServicesData) {
            log::error!(
                "Runtime state page at {:#x} is not reserved as RuntimeServicesData",
                address
            );
            panic!("runtime state root is not fully reserved as RuntimeServicesData");
        }
        address = address.saturating_add(allocator::PAGE_SIZE);
    }
    if allocator::get_memory_type_at(end - 1) != Some(MemoryType::RuntimeServicesData) {
        log::error!(
            "Runtime state final byte at {:#x} is not reserved as RuntimeServicesData",
            end - 1
        );
        panic!("runtime state root crosses out of RuntimeServicesData");
    }
}

/// Get a raw mutable pointer to the EFI state.
/// See `get_mut_ptr()` for safety considerations.
#[inline]
pub fn efi_mut_ptr() -> *mut EfiState {
    let ptr = get_mut_ptr();
    // Safety: ptr is valid, we're just computing an offset
    unsafe { core::ptr::addr_of_mut!((*ptr).efi) }
}

/// Access EFI state mutably through a closure.
#[inline]
pub fn with_efi_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut EfiState) -> R,
{
    with_mut(|state| f(&mut state.efi))
}

/// Get a reference to the driver state.
#[inline]
pub fn drivers() -> &'static DriverState {
    &get().drivers
}

/// Get a raw mutable pointer to the driver state.
/// See `get_mut_ptr()` for safety considerations.
#[inline]
pub fn drivers_mut_ptr() -> *mut DriverState {
    let ptr = get_mut_ptr();
    // Safety: ptr is valid, we're just computing an offset
    unsafe { core::ptr::addr_of_mut!((*ptr).drivers) }
}

/// Access driver state mutably through a closure.
#[inline]
pub fn with_drivers_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut DriverState) -> R,
{
    with_mut(|state| f(&mut state.drivers))
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
    try_get().and_then(|state| state.drivers.platform.framebuffer)
}

/// Get a reference to the console state.
#[inline]
pub fn console() -> &'static ConsoleState {
    &get().console
}

/// Get a raw mutable pointer to the console state.
/// See `get_mut_ptr()` for safety considerations.
#[inline]
pub fn console_mut_ptr() -> *mut ConsoleState {
    let ptr = get_mut_ptr();
    // Safety: ptr is valid, we're just computing an offset
    unsafe { core::ptr::addr_of_mut!((*ptr).console) }
}

/// Access console state mutably through a closure.
#[inline]
pub fn with_console_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut ConsoleState) -> R,
{
    with_mut(|state| f(&mut state.console))
}

/// Get a reference to the memory allocator.
#[inline]
pub fn allocator() -> &'static MemoryAllocator {
    &get().efi.allocator
}

/// Get a raw mutable pointer to the memory allocator.
/// See `get_mut_ptr()` for safety considerations.
#[inline]
pub fn allocator_mut_ptr() -> *mut MemoryAllocator {
    let ptr = get_mut_ptr();
    // Safety: ptr is valid, we're just computing an offset
    unsafe { core::ptr::addr_of_mut!((*ptr).efi.allocator) }
}

/// Access allocator state mutably through a closure.
#[inline]
pub fn with_allocator_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut MemoryAllocator) -> R,
{
    with_mut(|state| f(&mut state.efi.allocator))
}

/// Access the block device mutably through a closure.
///
/// Returns `None` if no block device is configured.
#[inline]
pub fn with_block_device_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut crate::drivers::block::AnyBlockDevice) -> R,
{
    with_mut(|state| state.efi.block_device.as_mut().map(f))
}

/// Access the storage backend mutably through a closure.
///
/// Returns `None` if no storage backend is configured.
#[inline]
pub fn with_storage_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut crate::efi::varstore::SpiStorageBackend) -> R,
{
    with_mut(|state| state.drivers.platform.storage.as_mut().map(f))
}

/// Get a reference to the varstore state.
#[inline]
pub fn varstore() -> &'static VarStoreState {
    &get().efi.varstore
}

/// Access varstore state mutably through a closure.
#[inline]
pub fn with_varstore_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut VarStoreState) -> R,
{
    with_mut(|state| f(&mut state.efi.varstore))
}

// ============================================================================
// ExitBootServices State
// ============================================================================

/// Check if ExitBootServices has been called.
///
/// After ExitBootServices, SPI flash is locked and variable writes
/// must be stored to ESP file instead.
#[inline]
pub fn is_exit_boot_services_called() -> bool {
    EXIT_BOOT_SERVICES_CALLED.load(Ordering::Acquire)
}

/// Mark that ExitBootServices has been called.
///
/// This should only be called from boot_services::exit_boot_services.
#[inline]
pub fn set_exit_boot_services_called() {
    EXIT_BOOT_SERVICES_CALLED.store(true, Ordering::Release);
}
