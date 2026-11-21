//! Boot Services tables
//!
//! The handle database, event table, and loaded-image table used by Boot
//! Services, in a single cell owned by this module.

use alloc::vec::Vec;

use r_efi::efi::{self, Guid, Handle};

use crate::cell::Local;
#[cfg(feature = "tpm")]
use crate::efi::tcg::types::TaggedDigest;

/// The Boot Services tables.
static TABLES: Local<Tables> = Local::new(Tables::new());

/// Borrow the tables.
#[inline]
#[track_caller]
pub fn tables() -> crate::cell::Borrowed<'static, Tables> {
    TABLES.borrow()
}

/// Mutate the tables through a closure.
#[inline]
#[track_caller]
pub fn with_tables_mut<R>(f: impl FnOnce(&mut Tables) -> R) -> R {
    TABLES.with_mut(f)
}

/// Failure to allocate the EFI state tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableInitError;

impl core::fmt::Display for TableInitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "out of memory while allocating EFI state tables")
    }
}

/// Allocate the EFI state tables after heap startup.
///
/// The event table keeps its fixed length: event handles encode the slot
/// index. Handles and loaded images grow on demand; reserving room for a
/// typical boot up front only saves reallocations. No pointer into these
/// tables outlives a borrow, so growth may move them.
///
/// # Errors
///
/// Returns [`TableInitError`] when the heap cannot back any of the tables.
pub fn init_caches() -> Result<(), TableInitError> {
    with_tables_mut(|efi| {
        if efi.events.is_empty() {
            efi.events
                .try_reserve_exact(MAX_EVENTS)
                .map_err(|_| TableInitError)?;
            efi.events.resize_with(MAX_EVENTS, EventEntry::empty);
        }
        efi.handles
            .try_reserve(INITIAL_HANDLES)
            .map_err(|_| TableInitError)?;
        efi.loaded_images
            .try_reserve(INITIAL_LOADED_IMAGES)
            .map_err(|_| TableInitError)?;
        Ok(())
    })
}

/// Handles reserved up front: every disk, partition and loaded image takes
/// one, and the UEFI SCT alone keeps about 80 test images loaded. The table
/// grows past this.
const INITIAL_HANDLES: usize = 128;

/// Loaded images reserved up front; the table grows past this.
const INITIAL_LOADED_IMAGES: usize = 32;

/// Number of event slots.
///
/// Fixed because an event handle encodes its slot as `handle % MAX_EVENTS`.
pub const MAX_EVENTS: usize = 32;

/// Protocol interface entry
#[derive(Clone, Copy)]
pub struct ProtocolEntry {
    pub guid: Guid,
    pub interface: *mut core::ffi::c_void,
    /// Installation order; reinstall moves the instance to the end.
    pub generation: u64,
}

/// Handle entry in the handle database
pub struct HandleEntry {
    pub handle: Handle,
    /// Installed protocols in installation order, grown from the heap.
    pub protocols: Vec<ProtocolEntry>,
}

impl HandleEntry {
    /// A handle with no protocols installed yet.
    pub const fn new(handle: Handle) -> Self {
        Self {
            handle,
            protocols: Vec::new(),
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
    type Error = InvalidTimerType;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TimerType::Cancel),
            1 => Ok(TimerType::Periodic),
            2 => Ok(TimerType::Relative),
            other => Err(InvalidTimerType(other)),
        }
    }
}

/// Rejected [`TimerType`] value from an EFI caller.
///
/// Carries the offending raw value so callers can log it instead of
/// silently dropping it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTimerType(pub u32);

impl core::fmt::Display for InvalidTimerType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid TimerType value {}", self.0)
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
    /// LoadImage returned SECURITY_VIOLATION; StartImage must refuse it.
    pub security_violation: bool,
    /// Pending PCR index for deferred application image measurement.
    #[cfg(feature = "tpm")]
    pub measurement_pcr: u32,
    /// Pending TCG event type for deferred application image measurement.
    #[cfg(feature = "tpm")]
    pub measurement_event_type: u32,
    /// Number of valid precomputed authenticode digests.
    #[cfg(feature = "tpm")]
    pub measurement_digest_count: usize,
    /// Precomputed authenticode digests for deferred application measurement.
    #[cfg(feature = "tpm")]
    pub measurement_digests: [TaggedDigest; 5],
    /// Serialized EFI_IMAGE_LOAD_EVENT data for deferred application measurement.
    #[cfg(feature = "tpm")]
    pub measurement_event_data: *mut u8,
    /// Size of the deferred event data buffer.
    #[cfg(feature = "tpm")]
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
            security_violation: false,
            #[cfg(feature = "tpm")]
            measurement_pcr: 0,
            #[cfg(feature = "tpm")]
            measurement_event_type: 0,
            #[cfg(feature = "tpm")]
            measurement_digest_count: 0,
            #[cfg(feature = "tpm")]
            measurement_digests: [TaggedDigest::zeroed(0); 5],
            #[cfg(feature = "tpm")]
            measurement_event_data: core::ptr::null_mut(),
            #[cfg(feature = "tpm")]
            measurement_event_data_size: 0,
        }
    }
}

/// Maximum number of live `RegisterProtocolNotify` registrations.
pub const MAX_PROTOCOL_NOTIFIES: usize = 16;

/// One `RegisterProtocolNotify` registration.
///
/// A cursor over live protocol instances, shared by LocateHandle and
/// LocateProtocol. Removed instances disappear without leaving stale handles;
/// no per-registration queue or capacity limit is needed.
pub struct ProtocolNotifyEntry {
    /// Opaque token handed back to the caller as `Registration`.
    pub registration: usize,
    /// Protocol the caller asked to be notified about.
    pub protocol: Guid,
    /// Event signaled when a matching interface is installed.
    pub event: efi::Event,
    /// Generation last delivered; zero starts before all existing instances.
    pub cursor: u64,
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

/// Boot Services tables: handles, events, and loaded images.
pub struct Tables {
    /// Handle database: one entry per live handle, grown from the heap.
    pub handles: Vec<HandleEntry>,
    /// Next handle value (unique identifier)
    pub next_handle: usize,
    /// Active protocol opens, grown fallibly from the firmware heap.
    pub open_protocols: Vec<OpenProtocolEntry>,
    /// Live protocol-notify registrations, grown fallibly from the heap.
    pub protocol_notifies: Vec<ProtocolNotifyEntry>,
    /// Next opaque registration token handed out by RegisterProtocolNotify.
    pub next_registration: usize,
    /// Monotonic order for installed/reinstalled protocol instances.
    pub protocol_generation: u64,

    /// Event database, allocated after heap startup.
    pub events: Vec<EventEntry>,

    /// Loaded images database; a null `handle` marks a free slot.
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
            next_handle: 1,
            open_protocols: Vec::new(),
            protocol_notifies: Vec::new(),
            next_registration: 1,
            protocol_generation: 0,
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
