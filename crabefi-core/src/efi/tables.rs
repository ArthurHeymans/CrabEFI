//! Boot Services tables
//!
//! The handle database, event table, and loaded-image table used by Boot
//! Services, in a single cell owned by this module.

use alloc::vec::Vec;
use core::cell::Ref;

use r_efi::efi::{self, Guid, Handle};

use crate::cell::Local;
use crate::efi::tcg::types::TaggedDigest;

/// The Boot Services tables.
static TABLES: Local<Tables> = Local::new(Tables::new());

/// Borrow the tables.
#[inline]
#[track_caller]
pub fn tables() -> Ref<'static, Tables> {
    TABLES.borrow()
}

/// Mutate the tables through a closure.
#[inline]
#[track_caller]
pub fn with_tables_mut<R>(f: impl FnOnce(&mut Tables) -> R) -> R {
    TABLES.with_mut(f)
}

/// Allocate fixed-size EFI state tables after heap startup.
///
/// All tables keep their maximum length so their backing storage never moves.
/// Variable payloads remain empty until a variable is loaded or written.
///
/// # Returns
/// `true` when every table is ready.
pub fn init_caches() -> bool {
    with_tables_mut(|efi| {
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
    /// Whether this slot currently holds a live EFI event.
    pub in_use: bool,
    /// Generation encoded into dynamic handles to reject stale slot aliases.
    pub generation: usize,
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
            in_use: false,
            generation: 0,
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

/// Boot Services tables: handles, events, and loaded images.
pub struct Tables {
    /// Handle database, allocated after heap startup.
    pub handles: Vec<HandleEntry>,
    /// Number of active handles
    pub handle_count: usize,
    /// Next handle value (unique identifier)
    pub next_handle: usize,

    /// Event database, allocated after heap startup.
    pub events: Vec<EventEntry>,

    /// Loaded images database, allocated after heap startup.
    pub loaded_images: Vec<LoadedImageEntry>,

    /// Monotonic counter for GetNextMonotonicCount
    pub monotonic_count: u64,

    /// Flag indicating EFI_EVENT_GROUP_READY_TO_BOOT has been signaled
    /// Per UEFI spec, this should only be signaled once before the first
    /// boot option is attempted.
    pub ready_to_boot_signaled: bool,
}

impl Tables {
    pub const fn new() -> Self {
        Self {
            handles: Vec::new(),
            handle_count: 0,
            next_handle: 1,
            events: Vec::new(),
            loaded_images: Vec::new(),
            monotonic_count: 0,
            ready_to_boot_signaled: false,
        }
    }
}

impl Default for Tables {
    fn default() -> Self {
        Self::new()
    }
}
