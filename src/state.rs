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
//!   |     +-- config_tables, variables
//!   |     +-- allocator
//!   |
//!   +-- drivers: DriverState
//!   |     +-- pci, serial, keyboard
//!   |     +-- storage controllers (nvme, ahci, usb)
//!   |
//!   +-- console: ConsoleState
//!         +-- framebuffer, cursor, dimensions
//!         +-- input state
//! ```
//!
//! # Thread Safety
//!
//! CrabEFI is single-threaded firmware. We use `UnsafeCell` for interior
//! mutability without the overhead of `Mutex`. The UEFI spec guarantees
//! that Boot Services are not reentrant.

use core::sync::atomic::{AtomicPtr, Ordering};

/// Global pointer to the firmware state.
///
/// This is the ONLY global mutable state. It points to a `FirmwareState`
/// allocated on the stack in `init()`.
static STATE_PTR: AtomicPtr<FirmwareState> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the global state pointer.
///
/// # Safety
///
/// - Must only be called once, at the start of `init()`
/// - The `state` reference must remain valid for the entire firmware lifetime
/// - The firmware must be single-threaded
pub unsafe fn init(state: &mut FirmwareState) {
    STATE_PTR.store(state as *mut FirmwareState, Ordering::Release);
}

/// Check if state has been initialized.
pub fn is_initialized() -> bool {
    !STATE_PTR.load(Ordering::Acquire).is_null()
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
    let ptr = STATE_PTR.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "FirmwareState not initialized");
    // Safety: Single-threaded firmware, closure scope limits aliasing
    unsafe { f(&mut *ptr) }
}

/// Try to get a reference to the global firmware state.
///
/// Returns `None` if state has not been initialized yet.
#[inline]
pub fn try_get() -> Option<&'static FirmwareState> {
    let ptr = STATE_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}

/// Try to get a raw mutable pointer to the global firmware state.
///
/// Returns `None` if state has not been initialized yet.
/// See `get_mut_ptr()` for safety considerations.
#[inline]
pub fn try_get_mut_ptr() -> Option<*mut FirmwareState> {
    let ptr = STATE_PTR.load(Ordering::Acquire);
    if ptr.is_null() { None } else { Some(ptr) }
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
pub const MAX_CONFIG_TABLES: usize = 16;

/// Maximum number of EFI variables
pub const MAX_VARIABLES: usize = 64;

/// Maximum variable name length (in characters)
pub const MAX_VARIABLE_NAME_LEN: usize = 64;

/// Maximum variable data size
pub const MAX_VARIABLE_DATA_SIZE: usize = 1024;

/// Protocol interface entry
#[derive(Clone, Copy)]
pub struct ProtocolEntry {
    pub guid: Guid,
    pub interface: *mut core::ffi::c_void,
}

// Safety: ProtocolEntry contains raw pointers but firmware is single-threaded
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

// Safety: HandleEntry contains raw pointers but firmware is single-threaded
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

/// Event entry for tracking created events
#[derive(Clone, Copy)]
pub struct EventEntry {
    pub event_type: u32,
    pub notify_tpl: efi::Tpl,
    pub signaled: bool,
    pub is_keyboard_event: bool,
}

impl EventEntry {
    pub const fn empty() -> Self {
        Self {
            event_type: 0,
            notify_tpl: 0,
            signaled: false,
            is_keyboard_event: false,
        }
    }
}

/// Loaded image entry - tracks PE images loaded via LoadImage
#[derive(Clone, Copy)]
pub struct LoadedImageEntry {
    /// Handle for this loaded image
    pub handle: Handle,
    /// Base address where image was loaded
    pub image_base: u64,
    /// Size of the loaded image in bytes
    pub image_size: u64,
    /// Entry point address
    pub entry_point: u64,
    /// Number of pages allocated
    pub num_pages: u64,
    /// Parent image handle that loaded this image
    pub parent_handle: Handle,
}

// Safety: LoadedImageEntry contains raw pointers but firmware is single-threaded
unsafe impl Send for LoadedImageEntry {}
unsafe impl Sync for LoadedImageEntry {}

impl LoadedImageEntry {
    pub const fn empty() -> Self {
        Self {
            handle: core::ptr::null_mut(),
            image_base: 0,
            image_size: 0,
            entry_point: 0,
            num_pages: 0,
            parent_handle: core::ptr::null_mut(),
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

// Safety: ConfigurationTable contains raw pointers but firmware is single-threaded
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
    pub config_tables: [ConfigurationTable; MAX_CONFIG_TABLES],
    /// Number of configuration tables
    pub config_table_count: usize,

    /// EFI variables
    pub variables: [VariableEntry; MAX_VARIABLES],

    /// Memory allocator
    pub allocator: MemoryAllocator,

    /// Filesystem state for SimpleFileSystem protocol
    pub filesystem: Option<FilesystemState>,

    /// Disk read function for filesystem access
    pub disk_read_fn: Option<DiskReadFn>,
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
            config_tables: [ConfigurationTable::empty(); MAX_CONFIG_TABLES],
            config_table_count: 0,
            variables: [const { VariableEntry::empty() }; MAX_VARIABLES],
            allocator: MemoryAllocator::new(),
            filesystem: None,
            disk_read_fn: None,
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

use crate::coreboot::FramebufferInfo;
use crate::drivers::pci::PciDevice;
use heapless::Vec as HeaplessVec;

/// Maximum number of PCI devices
pub const MAX_PCI_DEVICES: usize = 64;

/// Maximum number of storage controllers
pub const MAX_STORAGE_CONTROLLERS: usize = 4;

/// Maximum number of storage devices in registry
pub const MAX_STORAGE_DEVICES: usize = 16;

/// Hardware driver state
pub struct DriverState {
    /// PCI device list
    pub pci_devices: HeaplessVec<PciDevice, MAX_PCI_DEVICES>,
    /// PCIe ECAM base address
    pub ecam_base: Option<u64>,

    /// Serial port I/O base address
    pub serial_port: Option<u16>,

    /// PS/2 keyboard state
    pub keyboard: KeyboardState,

    /// Global framebuffer info (from coreboot)
    pub framebuffer: Option<FramebufferInfo>,
}

impl DriverState {
    pub const fn new() -> Self {
        Self {
            pci_devices: HeaplessVec::new(),
            ecam_base: None,
            serial_port: None,
            keyboard: KeyboardState::new(),
            framebuffer: None,
        }
    }
}

impl Default for DriverState {
    fn default() -> Self {
        Self::new()
    }
}

/// PS/2 keyboard state
pub struct KeyboardState {
    /// Shift key pressed
    pub shift_pressed: bool,
    /// Control key pressed
    pub ctrl_pressed: bool,
    /// Alt key pressed
    pub alt_pressed: bool,
    /// Caps lock enabled
    pub caps_lock: bool,
    /// Key buffer for storing pending keys
    pub key_buffer: [u8; 16],
    /// Number of keys in buffer
    pub key_count: usize,
    /// Read position in buffer
    pub read_pos: usize,
    /// Write position in buffer
    pub write_pos: usize,
}

impl KeyboardState {
    pub const fn new() -> Self {
        Self {
            shift_pressed: false,
            ctrl_pressed: false,
            alt_pressed: false,
            caps_lock: false,
            key_buffer: [0; 16],
            key_count: 0,
            read_pos: 0,
            write_pos: 0,
        }
    }
}

// ============================================================================
// Console State
// ============================================================================

/// Console and display state
pub struct ConsoleState {
    /// EFI console framebuffer info
    pub efi_framebuffer: Option<FramebufferInfo>,
    /// EFI console cursor position (col, row)
    pub cursor_pos: (u32, u32),
    /// EFI console dimensions (cols, rows)
    pub dimensions: (u32, u32),
    /// Console start row (EFI console uses bottom half of screen)
    pub start_row: u32,

    /// Input state for escape sequence parsing
    pub input: InputState,

    /// Logger framebuffer info
    pub logger_framebuffer: Option<FramebufferInfo>,
    /// Logger cursor position
    pub logger_cursor: (u32, u32),

    /// GOP framebuffer for graphics output protocol Blt operations
    pub gop_framebuffer: Option<FramebufferInfo>,
}

impl ConsoleState {
    pub const fn new() -> Self {
        Self {
            efi_framebuffer: None,
            cursor_pos: (0, 0),
            dimensions: (80, 25),
            start_row: 0,
            input: InputState::new(),
            logger_framebuffer: None,
            logger_cursor: (0, 0),
            gop_framebuffer: None,
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
}

impl InputState {
    pub const fn new() -> Self {
        Self {
            escape_buf: [0; ESCAPE_BUF_SIZE],
            escape_len: 0,
            in_escape: false,
            queued_key: None,
        }
    }
}

// ============================================================================
// Filesystem State
// ============================================================================

/// Filesystem state - stores partition info for reading files
#[derive(Clone, Copy)]
pub struct FilesystemState {
    /// First LBA of the partition
    pub partition_start: u64,
    /// FAT type (12, 16, or 32)
    pub fat_type: u8,
    /// Bytes per sector
    pub bytes_per_sector: u16,
    /// Sectors per cluster
    pub sectors_per_cluster: u8,
    /// First FAT sector (relative to partition start)
    pub fat_start: u32,
    /// Sectors per FAT
    pub sectors_per_fat: u32,
    /// First data sector (relative to partition start)
    pub data_start: u32,
    /// Root directory cluster (FAT32) or 0 (FAT12/16)
    pub root_cluster: u32,
    /// Root directory sector start (FAT12/16 only)
    pub root_dir_start: u32,
    /// Root directory sector count (FAT12/16 only)
    pub root_dir_sectors: u32,
}

impl FilesystemState {
    pub const fn empty() -> Self {
        Self {
            partition_start: 0,
            fat_type: 0,
            bytes_per_sector: 0,
            sectors_per_cluster: 0,
            fat_start: 0,
            sectors_per_fat: 0,
            data_start: 0,
            root_cluster: 0,
            root_dir_start: 0,
            root_dir_sectors: 0,
        }
    }
}

/// Disk read function type
pub type DiskReadFn = fn(u64, &mut [u8]) -> Result<(), ()>;

// ============================================================================
// Helper functions for accessing state components
// ============================================================================

/// Get a reference to the EFI state.
#[inline]
pub fn efi() -> &'static EfiState {
    &get().efi
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
