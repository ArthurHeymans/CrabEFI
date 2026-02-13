//! UEFI Variable Store
//!
//! This module provides persistent storage for UEFI variables using SPI flash.
//! Variables are serialized using postcard (a compact, serde-based format).
//!
//! # Storage Architecture
//!
//! The variable store uses a simple append-only log format in SPI flash:
//!
//! ```text
//! +------------------+
//! | Store Header     |  <- Magic, version, flags
//! +------------------+
//! | Variable 1       |  <- Serialized VariableRecord
//! +------------------+
//! | Variable 2       |
//! +------------------+
//! | ...              |
//! +------------------+
//! | Free Space (0xFF)|
//! +------------------+
//! ```
//!
//! When a variable is updated, a new record is appended. When reading, we scan
//! from the beginning and keep only the latest version of each variable.
//! When the store is full, we compact it by erasing and rewriting only active variables.
//!
//! # Dual-Storage Mode
//!
//! - **Before ExitBootServices**: Write directly to SPI flash
//! - **After ExitBootServices**: SPI is locked; write to ESP file instead
//! - **On Reset**: Read ESP file, authenticate, apply to SPI, delete ESP file

pub mod deferred;
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

/// Store header magic value: "CRAB" in little-endian
pub const STORE_MAGIC: u32 = 0x42415243; // "CRAB"

/// Current store format version
pub const STORE_VERSION: u8 = 1;

/// Size of the store header
pub const STORE_HEADER_SIZE: usize = 16;

/// Default SMMSTORE region size (256KB, typical for coreboot)
pub const DEFAULT_STORE_SIZE: u32 = 256 * 1024;

/// SPI flash erase block size (4KB is typical)
pub const ERASE_BLOCK_SIZE: u32 = 4096;

/// Maximum variable name length (in UTF-16 code units)
pub const MAX_NAME_LEN: usize = 64;

/// Maximum variable data size
pub const MAX_DATA_SIZE: usize = 4096;

/// Variable record header magic: 0xAA55 (same as UEFI)
pub const RECORD_MAGIC: u16 = 0xAA55;

/// Record state: valid and active
pub const STATE_VALID: u8 = 0x7F;

/// Record state: deleted (superseded by newer record)
pub const STATE_DELETED: u8 = 0x00;

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

/// Store header at the beginning of the variable region
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct StoreHeader {
    /// Magic value (STORE_MAGIC)
    pub magic: u32,
    /// Format version
    pub version: u8,
    /// Flags (reserved)
    pub flags: u8,
    /// Reserved padding
    pub reserved: u16,
    /// Total store size in bytes
    pub store_size: u32,
    /// CRC32 of header (excluding this field)
    pub header_crc: u32,
}

impl StoreHeader {
    /// Create a new store header
    pub fn new(store_size: u32) -> Self {
        let mut header = Self {
            magic: STORE_MAGIC,
            version: STORE_VERSION,
            flags: 0,
            reserved: 0,
            store_size,
            header_crc: 0,
        };
        header.header_crc = header.compute_crc();
        header
    }

    /// Compute CRC32 of the header (excluding the CRC field itself)
    pub fn compute_crc(&self) -> u32 {
        // CRC32 of the first 12 bytes (before header_crc)
        let magic_bytes = self.magic.to_le_bytes();
        let reserved_bytes = self.reserved.to_le_bytes();
        let store_size_bytes = self.store_size.to_le_bytes();

        let bytes = [
            magic_bytes[0],
            magic_bytes[1],
            magic_bytes[2],
            magic_bytes[3],
            self.version,
            self.flags,
            reserved_bytes[0],
            reserved_bytes[1],
            store_size_bytes[0],
            store_size_bytes[1],
            store_size_bytes[2],
            store_size_bytes[3],
        ];
        crc32(&bytes)
    }

    /// Validate the header
    pub fn is_valid(&self) -> bool {
        self.magic == STORE_MAGIC
            && self.version == STORE_VERSION
            && self.header_crc == self.compute_crc()
    }
}

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

/// A variable record stored in flash
///
/// Each record contains a complete variable (name, GUID, attributes, data).
/// Records are immutable once written. To update a variable, write a new record
/// and mark the old one as deleted.
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

// Note: The legacy `VariableStore` struct has been removed. Variable
// persistence is now handled by the `persistence` submodule which
// uses the deferred/SMMSTORE-based approach.

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

/// Pending variable write for ESP file
///
/// When SPI is locked after ExitBootServices, variable writes are queued
/// to be written to a file on the ESP. On next boot, this file is read,
/// variables are authenticated, and applied to SPI flash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingVariableWrite {
    /// The variable record to write
    pub record: VariableRecord,
    /// Authentication signature (if authenticated variable)
    pub auth_signature: Option<Vec<u8>>,
}

/// ESP variable file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EspVariableFile {
    /// Magic value for the file
    pub magic: u32,
    /// Version
    pub version: u8,
    /// Pending variable writes
    pub pending: Vec<PendingVariableWrite>,
    /// CRC32 of the file contents
    pub crc: u32,
}

/// ESP variable file magic: "CVAR"
pub const ESP_FILE_MAGIC: u32 = 0x52415643;

impl EspVariableFile {
    /// Create a new ESP variable file
    pub fn new() -> Self {
        Self {
            magic: ESP_FILE_MAGIC,
            version: 1,
            pending: Vec::new(),
            crc: 0,
        }
    }

    /// Add a pending variable write
    pub fn add(&mut self, record: VariableRecord, auth_signature: Option<Vec<u8>>) {
        // Remove any existing pending write for this variable
        let guid = record.guid;
        let name = record.name.clone();
        self.pending
            .retain(|p| !(p.record.guid == guid && p.record.name == name));

        self.pending.push(PendingVariableWrite {
            record,
            auth_signature,
        });
    }

    /// Serialize to bytes
    pub fn serialize(&mut self) -> Result<Vec<u8>> {
        // Compute CRC of everything except the CRC field
        self.crc = 0;
        let temp_bytes = postcard::to_allocvec(&self).map_err(|_| VarStoreError::SerdeError)?;
        self.crc = crc32(&temp_bytes);

        postcard::to_allocvec(&self).map_err(|_| VarStoreError::SerdeError)
    }

    /// Deserialize from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let file: Self = postcard::from_bytes(bytes).map_err(|_| VarStoreError::SerdeError)?;

        if file.magic != ESP_FILE_MAGIC {
            return Err(VarStoreError::InvalidHeader);
        }

        // Verify CRC
        let mut temp = file.clone();
        temp.crc = 0;
        let temp_bytes = postcard::to_allocvec(&temp).map_err(|_| VarStoreError::SerdeError)?;
        let computed_crc = crc32(&temp_bytes);

        if file.crc != computed_crc {
            return Err(VarStoreError::CrcMismatch);
        }

        Ok(file)
    }
}

impl Default for EspVariableFile {
    fn default() -> Self {
        Self::new()
    }
}
