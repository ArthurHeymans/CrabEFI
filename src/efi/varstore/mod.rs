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

pub mod persistence;

use alloc::vec;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

// Re-export key items from persistence
pub use persistence::{
    delete_variable, get_pending_esp_data, init as init_persistence, is_smmstore_initialized,
    is_spi_available, persist_variable,
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
        // Simple CRC32 of the first 12 bytes (before header_crc)
        let bytes = [
            (self.magic & 0xFF) as u8,
            ((self.magic >> 8) & 0xFF) as u8,
            ((self.magic >> 16) & 0xFF) as u8,
            ((self.magic >> 24) & 0xFF) as u8,
            self.version,
            self.flags,
            (self.reserved & 0xFF) as u8,
            ((self.reserved >> 8) & 0xFF) as u8,
            (self.store_size & 0xFF) as u8,
            ((self.store_size >> 8) & 0xFF) as u8,
            ((self.store_size >> 16) & 0xFF) as u8,
            ((self.store_size >> 24) & 0xFF) as u8,
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
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
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
        record.crc = record.compute_crc();
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
        record.crc = record.compute_crc();
        Ok(record)
    }

    /// Compute CRC32 of the record
    pub fn compute_crc(&self) -> u32 {
        // Serialize all fields except CRC, then compute CRC
        let temp = Self {
            crc: 0,
            ..self.clone()
        };
        if let Ok(bytes) = postcard::to_allocvec(&temp) {
            crc32(&bytes)
        } else {
            0
        }
    }

    /// Validate the record
    pub fn is_valid(&self) -> bool {
        self.magic == RECORD_MAGIC && self.crc == self.compute_crc()
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
        postcard::from_bytes(bytes).map_err(|_| VarStoreError::SerdeError)
    }
}

/// Variable store state
pub struct VariableStore {
    /// Base address of the store in SPI flash
    base_addr: u32,
    /// Total size of the store
    store_size: u32,
    /// Current write offset (next free location)
    write_offset: u32,
    /// Whether the store is locked (after ExitBootServices)
    locked: bool,
    /// Cached variables (loaded on init)
    cache: Vec<VariableRecord>,
}

impl VariableStore {
    /// Create a new variable store instance
    ///
    /// Call `init()` to actually read from SPI flash.
    pub fn new(base_addr: u32, store_size: u32) -> Self {
        Self {
            base_addr,
            store_size,
            write_offset: STORE_HEADER_SIZE as u32,
            locked: false,
            cache: Vec::new(),
        }
    }

    /// Initialize the variable store from SPI flash
    ///
    /// Reads the store header and all variable records into the cache.
    pub fn init(&mut self, spi: &mut dyn crate::drivers::spi::SpiController) -> Result<()> {
        // Read and validate header
        let mut header_bytes = [0u8; STORE_HEADER_SIZE];
        spi.read(self.base_addr, &mut header_bytes)
            .map_err(|_| VarStoreError::SpiError)?;

        let header: StoreHeader =
            postcard::from_bytes(&header_bytes).map_err(|_| VarStoreError::InvalidHeader)?;

        if !header.is_valid() {
            // Store is uninitialized or corrupt - format it
            log::info!("Variable store not initialized, formatting...");
            self.format(spi)?;
            return Ok(());
        }

        // Scan for variable records
        self.cache.clear();
        let mut offset = STORE_HEADER_SIZE as u32;

        while offset < self.store_size {
            // Read length prefix (postcard uses variable-length encoding)
            // We'll read a chunk and try to deserialize
            let remaining = self.store_size - offset;
            let chunk_size = core::cmp::min(remaining, MAX_DATA_SIZE as u32 + 256);
            let mut chunk = vec![0u8; chunk_size as usize];

            spi.read(self.base_addr + offset, &mut chunk)
                .map_err(|_| VarStoreError::SpiError)?;

            // Check for empty space (0xFF means erased flash)
            if chunk[0] == 0xFF {
                break;
            }

            // Try to deserialize a record
            match VariableRecord::deserialize(&chunk) {
                Ok(record) => {
                    let record_size = record.serialize()?.len() as u32;

                    if record.is_active() {
                        // Remove any existing record with same name/GUID
                        self.cache
                            .retain(|r| !r.matches(&record.guid.to_guid(), &record.name));
                        self.cache.push(record);
                    } else if record.state == STATE_DELETED {
                        // Remove the variable from cache
                        let guid = record.guid.to_guid();
                        self.cache.retain(|r| !r.matches(&guid, &record.name));
                    }

                    offset += record_size;
                }
                Err(_) => {
                    // Invalid record - stop scanning
                    log::warn!("Invalid variable record at offset {:#x}", offset);
                    break;
                }
            }
        }

        self.write_offset = offset;
        log::info!(
            "Variable store initialized: {} variables, write offset {:#x}",
            self.cache.len(),
            self.write_offset
        );

        Ok(())
    }

    /// Format the variable store (erase and write new header)
    pub fn format(&mut self, spi: &mut dyn crate::drivers::spi::SpiController) -> Result<()> {
        // Erase the entire store region
        spi.erase(self.base_addr, self.store_size)
            .map_err(|_| VarStoreError::SpiError)?;

        // Write new header
        let header = StoreHeader::new(self.store_size);
        let header_bytes = postcard::to_allocvec(&header).map_err(|_| VarStoreError::SerdeError)?;

        spi.write(self.base_addr, &header_bytes)
            .map_err(|_| VarStoreError::SpiError)?;

        self.write_offset = STORE_HEADER_SIZE as u32;
        self.cache.clear();

        log::info!("Variable store formatted");
        Ok(())
    }

    /// Get a variable by name and GUID
    pub fn get(&self, guid: &r_efi::efi::Guid, name: &[u16]) -> Option<&VariableRecord> {
        self.cache.iter().find(|r| r.matches(guid, name))
    }

    /// Set a variable
    ///
    /// If the variable exists, it's updated. If data is empty, the variable is deleted.
    pub fn set(
        &mut self,
        spi: &mut dyn crate::drivers::spi::SpiController,
        guid: &r_efi::efi::Guid,
        name: &[u16],
        attributes: u32,
        data: &[u8],
    ) -> Result<()> {
        if self.locked {
            return Err(VarStoreError::Locked);
        }

        let record = if data.is_empty() {
            // Delete the variable
            VariableRecord::new_deleted(guid, name)?
        } else {
            VariableRecord::new(guid, name, attributes, data)?
        };

        let record_bytes = record.serialize()?;

        // Check if we have space
        if self.write_offset + record_bytes.len() as u32 > self.store_size {
            // Need to compact
            self.compact(spi)?;

            // Check again after compaction
            if self.write_offset + record_bytes.len() as u32 > self.store_size {
                return Err(VarStoreError::StoreFull);
            }
        }

        // Write the record to flash
        spi.write(self.base_addr + self.write_offset, &record_bytes)
            .map_err(|_| VarStoreError::SpiError)?;

        self.write_offset += record_bytes.len() as u32;

        // Update cache
        if data.is_empty() {
            self.cache.retain(|r| !r.matches(guid, name));
        } else {
            self.cache.retain(|r| !r.matches(guid, name));
            self.cache.push(record);
        }

        Ok(())
    }

    /// Enumerate all variables
    pub fn enumerate(&self) -> impl Iterator<Item = &VariableRecord> {
        self.cache.iter()
    }

    /// Compact the store by rewriting only active variables
    fn compact(&mut self, spi: &mut dyn crate::drivers::spi::SpiController) -> Result<()> {
        log::info!("Compacting variable store...");

        // Save current cache
        let saved_cache = core::mem::take(&mut self.cache);

        // Format the store
        self.format(spi)?;

        // Rewrite all cached variables
        for record in saved_cache {
            let record_bytes = record.serialize()?;

            if self.write_offset + record_bytes.len() as u32 > self.store_size {
                // Even after compaction, not enough space
                log::error!("Variable store full even after compaction");
                return Err(VarStoreError::StoreFull);
            }

            spi.write(self.base_addr + self.write_offset, &record_bytes)
                .map_err(|_| VarStoreError::SpiError)?;

            self.write_offset += record_bytes.len() as u32;
            self.cache.push(record);
        }

        log::info!(
            "Compaction complete: {} variables, write offset {:#x}",
            self.cache.len(),
            self.write_offset
        );

        Ok(())
    }

    /// Lock the store (called at ExitBootServices)
    pub fn lock(&mut self) {
        self.locked = true;
    }

    /// Check if the store is locked
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Get the number of cached variables
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
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
