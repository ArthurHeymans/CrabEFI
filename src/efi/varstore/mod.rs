//! UEFI Variable Store
//!
//! This module provides persistent storage for UEFI variables using SPI flash.
//! Variables are stored in EDK2-compatible Firmware Volume (FV) format, matching
//! what coreboot's `get_uint_option()` / `set_uint_option()` expect.
//!
//! # On-Disk Format (EDK2 FV)
//!
//! ```text
//! +--------------------------------------------+ offset 0x0000
//! |  EFI_FIRMWARE_VOLUME_HEADER  (72 bytes)    |
//! +--------------------------------------------+ offset 0x0048
//! |  VARIABLE_STORE_HEADER       (28 bytes)    |
//! +--------------------------------------------+ offset 0x0064
//! |  Variable Record #1 (header + name + data) |
//! |  (padded to 4-byte alignment)              |
//! +--------------------------------------------+
//! |  Variable Record #2                        |
//! +--------------------------------------------+
//! |  ...                                       |
//! +--------------------------------------------+
//! |  Free space (0xFF)                         |
//! +--------------------------------------------+
//! ```
//!
//! The persistence layer (persistence.rs) reads and writes this format using
//! helpers in the edk2 submodule. When a variable is updated, the old record
//! is marked as deleted and a new record is appended. When the store is full,
//! compaction erases the region and rewrites only active variables.
//!
//! # Dual-Storage Mode
//!
//! - **Before ExitBootServices**: Write directly to SPI flash (EDK2 FV format)
//! - **After ExitBootServices**: SPI is locked; queue to deferred buffer in RAM
//! - **On Reset**: Deferred buffer is read, changes applied to SPI flash
//!
//! # Deferred Buffer (in-memory, transient)
//!
//! The deferred module uses postcard-serialized `VariableRecord`s in a RAM
//! buffer. This is an internal format that never touches flash — it bridges
//! variable writes across warm reboots when SPI is locked.

pub mod deferred;
pub mod edk2;
pub mod persistence;
pub mod storage;

// Re-export storage types
pub use storage::{SpiStorageBackend, StorageBackend, StorageError};

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

// Re-export key items from persistence
pub use persistence::{
    compact_varstore, delete_variable, get_variable_timestamp, get_varstore_stats,
    init as init_persistence, is_storage_available, is_varstore_initialized, persist_variable,
    persist_variable_with_timestamp, update_variable_in_memory,
};

// Re-export key items from deferred
pub use deferred::{
    check_pending as check_deferred_pending, configure_buffer as configure_deferred_buffer,
    deferred_buffer_base, deferred_buffer_size, get_stats as get_deferred_stats,
    init_buffer as init_deferred_buffer, process_pending as process_deferred_pending,
};

// ============================================================================
// Deferred buffer internal format (postcard-serialized VariableRecord)
//
// These types and constants are used ONLY by the deferred write buffer
// (deferred.rs) which queues variable changes in RAM across warm reboots.
// This is an internal in-memory format that never touches SPI flash.
// The on-disk format is EDK2 FV (see edk2.rs).
// ============================================================================

/// Maximum variable name length (in UTF-16 code units)
pub const MAX_NAME_LEN: usize = 64;

/// Maximum variable data size
pub const MAX_DATA_SIZE: usize = 4096;

/// Variable record header magic: 0xAA55
const RECORD_MAGIC: u16 = 0xAA55;

/// Record state: valid and active
const STATE_VALID: u8 = 0x7F;

/// Record state: deleted (superseded by newer record)
const STATE_DELETED: u8 = 0x00;

/// Error types for variable store operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarStoreError {
    /// Store not initialized
    NotInitialized,
    /// Store header invalid or corrupt
    InvalidHeader,
    /// Variable not found
    NotFound,
    /// Variable name too long
    NameTooLong,
    /// Variable data too large
    DataTooLarge,
    /// Store is full, needs compaction
    StoreFull,
    /// SPI flash operation failed
    SpiError,
    /// Serialization/deserialization failed
    SerdeError,
    /// Store is locked (after ExitBootServices)
    Locked,
    /// Invalid argument
    InvalidArgument,
    /// CRC mismatch
    CrcMismatch,
}

/// Result type for variable store operations
pub type Result<T> = core::result::Result<T, VarStoreError>;

/// A serialized GUID (16 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedGuid {
    pub bytes: [u8; 16],
}

impl SerializedGuid {
    /// Create from r_efi Guid
    pub fn from_guid(guid: &r_efi::efi::Guid) -> Self {
        let mut bytes = [0u8; 16];
        // Use as_bytes() which returns the GUID in its native UEFI format
        bytes.copy_from_slice(guid.as_bytes());
        Self { bytes }
    }

    /// Convert to r_efi Guid
    pub fn to_guid(&self) -> r_efi::efi::Guid {
        // GUID fields are stored in mixed-endian format:
        // - time_low: little-endian u32 (bytes 0-3)
        // - time_mid: little-endian u16 (bytes 4-5)
        // - time_hi_and_version: little-endian u16 (bytes 6-7)
        // - clock_seq_hi_and_reserved: u8 (byte 8)
        // - clock_seq_low: u8 (byte 9)
        // - node: [u8; 6] (bytes 10-15)
        r_efi::efi::Guid::from_fields(
            u32::from_le_bytes([self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]]),
            u16::from_le_bytes([self.bytes[4], self.bytes[5]]),
            u16::from_le_bytes([self.bytes[6], self.bytes[7]]),
            self.bytes[8],
            self.bytes[9],
            &[
                self.bytes[10],
                self.bytes[11],
                self.bytes[12],
                self.bytes[13],
                self.bytes[14],
                self.bytes[15],
            ],
        )
    }
}

/// A variable record for the deferred write buffer.
///
/// This is a postcard-serialized in-memory format used by the deferred module
/// to queue variable changes across warm reboots. It is NOT the on-disk format
/// (see edk2.rs for the EDK2 FV format written to SPI flash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableRecord {
    /// Record magic (RECORD_MAGIC)
    pub magic: u16,
    /// Record state (STATE_VALID or STATE_DELETED)
    pub state: u8,
    /// Variable attributes (EFI_VARIABLE_* flags)
    pub attributes: u32,
    /// Variable vendor GUID
    pub guid: SerializedGuid,
    /// Variable name (UTF-16LE, null-terminated)
    pub name: Vec<u16>,
    /// Variable data
    pub data: Vec<u8>,
    /// Monotonic counter for authenticated variables
    pub monotonic_count: u64,
    /// Timestamp for time-based authenticated variables
    pub timestamp: SerializedTime,
    /// CRC32 of the record (computed over all fields except this one)
    pub crc: u32,
}

/// Serialized EFI_TIME structure
///
/// Implements `Ord` for lexicographic comparison of timestamp fields.
/// Note: timezone and daylight are not used in ordering as they don't affect
/// the actual point in time for authenticated variable timestamp comparison.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanosecond: u32,
    pub timezone: i16,
    pub daylight: u8,
}

impl PartialOrd for SerializedTime {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SerializedTime {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // Normalize both to UTC minutes for consistent comparison, matching
        // EfiTime::compare behavior. This handles cases where timestamps
        // have different timezone offsets.
        self.to_utc_minutes().cmp(&other.to_utc_minutes())
    }
}

impl SerializedTime {
    /// Create from raw EFI_TIME-like fields
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanosecond: u32,
        timezone: i16,
        daylight: u8,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
            timezone,
            daylight,
        }
    }

    /// EFI_UNSPECIFIED_TIMEZONE value (0x7FF = 2047)
    const UNSPECIFIED_TIMEZONE: i16 = 0x7FF;

    /// Convert to approximate UTC minutes for ordering purposes.
    ///
    /// This matches the normalization in `EfiTime::to_utc_minutes` to ensure
    /// consistent ordering regardless of timezone differences.
    fn to_utc_minutes(self) -> i64 {
        let year = self.year as i64;
        let month = self.month as i64;
        let day = self.day as i64;
        let hour = self.hour as i64;
        let minute = self.minute as i64;
        let second = self.second as i64;
        let nanosecond = self.nanosecond as i64;
        let timezone = self.timezone;

        let days_from_years = year * 365 + year / 4 - year / 100 + year / 400;
        let days_from_months = (month - 1) * 30; // Approximation (same as EfiTime)
        let total_days = days_from_years + days_from_months + day;

        let total_minutes = total_days * 24 * 60 + hour * 60 + minute;
        let fractional = (second * 1_000_000_000 + nanosecond) / 60_000_000_000;
        let mut total = total_minutes * 1_000_000 + fractional;

        if timezone != Self::UNSPECIFIED_TIMEZONE && (-1440..=1440).contains(&timezone) {
            total -= (timezone as i64) * 1_000_000;
        }

        total
    }

    /// Check if this is a zero/default timestamp
    pub fn is_zero(&self) -> bool {
        self.year == 0
            && self.month == 0
            && self.day == 0
            && self.hour == 0
            && self.minute == 0
            && self.second == 0
            && self.nanosecond == 0
    }

    /// Compare two timestamps, returns true if self is strictly after other
    ///
    /// Special handling: if `other` is zero (uninitialized), any non-zero timestamp
    /// is considered "after". This is important for Secure Boot timestamp validation
    /// where a zero timestamp represents the initial state.
    pub fn is_after(&self, other: &SerializedTime) -> bool {
        // If other is zero (initial), any non-zero timestamp is "after"
        if other.is_zero() {
            return !self.is_zero();
        }

        // Use the Ord implementation for standard comparison
        self > other
    }
}

impl VariableRecord {
    /// Create a new variable record
    pub fn new(
        guid: &r_efi::efi::Guid,
        name: &[u16],
        attributes: u32,
        data: &[u8],
    ) -> Result<Self> {
        if name.len() > MAX_NAME_LEN {
            return Err(VarStoreError::NameTooLong);
        }
        if data.len() > MAX_DATA_SIZE {
            return Err(VarStoreError::DataTooLarge);
        }

        let mut record = Self {
            magic: RECORD_MAGIC,
            state: STATE_VALID,
            attributes,
            guid: SerializedGuid::from_guid(guid),
            name: name.to_vec(),
            data: data.to_vec(),
            monotonic_count: 0,
            timestamp: SerializedTime::default(),
            crc: 0,
        };
        record.crc = record.compute_crc().ok_or(VarStoreError::SerdeError)?;
        Ok(record)
    }

    /// Create a new variable record with a specific timestamp
    ///
    /// This is used for authenticated variables where the timestamp must be preserved.
    pub fn new_with_timestamp(
        guid: &r_efi::efi::Guid,
        name: &[u16],
        attributes: u32,
        data: &[u8],
        timestamp: SerializedTime,
    ) -> Result<Self> {
        if name.len() > MAX_NAME_LEN {
            return Err(VarStoreError::NameTooLong);
        }
        if data.len() > MAX_DATA_SIZE {
            return Err(VarStoreError::DataTooLarge);
        }

        let mut record = Self {
            magic: RECORD_MAGIC,
            state: STATE_VALID,
            attributes,
            guid: SerializedGuid::from_guid(guid),
            name: name.to_vec(),
            data: data.to_vec(),
            monotonic_count: 0,
            timestamp,
            crc: 0,
        };
        record.crc = record.compute_crc().ok_or(VarStoreError::SerdeError)?;
        Ok(record)
    }

    /// Create a deletion record (marks a variable as deleted)
    pub fn new_deleted(guid: &r_efi::efi::Guid, name: &[u16]) -> Result<Self> {
        if name.len() > MAX_NAME_LEN {
            return Err(VarStoreError::NameTooLong);
        }

        let mut record = Self {
            magic: RECORD_MAGIC,
            state: STATE_DELETED,
            attributes: 0,
            guid: SerializedGuid::from_guid(guid),
            name: name.to_vec(),
            data: Vec::new(),
            monotonic_count: 0,
            timestamp: SerializedTime::default(),
            crc: 0,
        };
        record.crc = record.compute_crc().ok_or(VarStoreError::SerdeError)?;
        Ok(record)
    }

    /// Compute CRC32 of the record
    ///
    /// Returns `None` if serialization fails, so callers can distinguish
    /// a real CRC of 0 from a serialization error.
    pub fn compute_crc(&self) -> Option<u32> {
        // Serialize all fields except CRC, then compute CRC
        let temp = Self {
            crc: 0,
            ..self.clone()
        };
        postcard::to_allocvec(&temp).ok().map(|bytes| crc32(&bytes))
    }

    /// Validate the record
    pub fn is_valid(&self) -> bool {
        self.magic == RECORD_MAGIC && self.compute_crc() == Some(self.crc)
    }

    /// Check if record is active (not deleted)
    pub fn is_active(&self) -> bool {
        self.is_valid() && self.state == STATE_VALID
    }

    /// Check if this record matches a given name and GUID
    pub fn matches(&self, guid: &r_efi::efi::Guid, name: &[u16]) -> bool {
        self.guid.to_guid() == *guid && self.name == name
    }

    /// Serialize the record to bytes
    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| VarStoreError::SerdeError)
    }

    /// Deserialize a record from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        match postcard::from_bytes(bytes) {
            Ok(record) => Ok(record),
            Err(e) => {
                // Log first few bytes to help debug
                if bytes.len() >= 8 {
                    log::debug!(
                        "postcard deserialize error at bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}... err={:?}",
                        bytes[0],
                        bytes[1],
                        bytes[2],
                        bytes[3],
                        bytes[4],
                        bytes[5],
                        bytes[6],
                        bytes[7],
                        e
                    );
                }
                Err(VarStoreError::SerdeError)
            }
        }
    }

    /// Get the timestamp from this record
    pub fn get_timestamp(&self) -> &SerializedTime {
        &self.timestamp
    }
}

/// Simple CRC32 implementation (IEEE 802.3 polynomial)
fn crc32(data: &[u8]) -> u32 {
    const CRC32_TABLE: [u32; 256] = crc32_table();
    let mut crc = 0xFFFF_FFFF_u32;
    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = CRC32_TABLE[index] ^ (crc >> 8);
    }
    !crc
}

/// Generate CRC32 lookup table at compile time
const fn crc32_table() -> [u32; 256] {
    const POLY: u32 = 0xEDB8_8320; // IEEE 802.3 polynomial (reversed)
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}
