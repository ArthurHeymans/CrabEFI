//! Deferred Variable Write Buffer
//!
//! This module provides a memory-based buffer for variable changes that occur
//! after ExitBootServices. Since SPI flash is locked and storage controllers
//! belong to the OS at that point, we queue changes to a reserved memory region.
//!
//! On warm reboot, the memory contents survive (on most hardware), allowing us
//! to apply the queued changes to SPI flash early in the next boot cycle.
//!
//! # Memory Layout
//!
//! ```text
//! +------------------+ <- DEFERRED_BUFFER_BASE
//! | Header (32 bytes)|
//! |   Magic "CVBF"   |
//! |   Version        |
//! |   Entry count    |
//! |   Total size     |
//! |   CRC32          |
//! +------------------+
//! | Entry 1          |
//! |   Entry header   |  <- flags (pre_verified, is_auth)
//! |   Record length  |
//! |   VariableRecord |
//! +------------------+
//! | Entry 2          |
//! +------------------+
//! | ...              |
//! +------------------+
//! | Free space       |
//! +------------------+ <- DEFERRED_BUFFER_BASE + DEFERRED_BUFFER_SIZE
//! ```
//!
//! # Warm vs Cold Boot
//!
//! - **Warm boot** (reset via keyboard controller, triple fault): RAM usually preserved
//! - **Cold boot** (power cycle): RAM cleared, no pending changes
//!
//! We use a CRC to detect corrupted/stale data from cold boots.
//!
//! # Authenticated Variables
//!
//! For authenticated variables (those with TIME_BASED_AUTHENTICATED_WRITE_ACCESS):
//! - The original signed data (with EFI_VARIABLE_AUTHENTICATION_2 header) is stored
//! - The timestamp from the authentication header is extracted and preserved
//! - On next boot, the signature is verified against current key databases
//! - Only after successful verification is the variable written to NVS with its timestamp
//!
//! This ensures that if key databases change between boots, the verification
//! uses the current trusted state. The timestamp is preserved to maintain
//! monotonicity requirements for future authenticated writes.

use core::sync::atomic::{AtomicBool, Ordering};

use super::{SerializedTime, VarStoreError, VariableRecord, crc32};
use crate::efi::auth;

/// Magic value for the deferred buffer header: "CVBF" (CrabVariable Buffer)
const DEFERRED_MAGIC: u32 = 0x46425643;

/// Current buffer format version
const DEFERRED_VERSION: u8 = 1;

/// Default base address for the deferred buffer
/// This should be in a region that:
/// 1. Is marked as EfiReservedMemoryType in the memory map
/// 2. Is unlikely to be overwritten during warm reset
/// 3. Is below 4GB for easy access
///
/// We use 0x1000_0000 (256MB) as a default - this should be adjusted
/// based on the actual memory map from coreboot.
pub const DEFAULT_DEFERRED_BUFFER_BASE: u64 = 0x0100_0000; // 16MB

/// Size of the deferred buffer (64KB should be plenty for variable changes)
pub const DEFERRED_BUFFER_SIZE: usize = 64 * 1024;

/// Header size
const HEADER_SIZE: usize = 32;

/// Maximum size of a single entry (including length prefix)
const MAX_ENTRY_SIZE: usize = 8 * 1024;

/// Entry flags
mod entry_flags {
    /// Entry contains an authenticated variable
    pub const IS_AUTHENTICATED: u8 = 0x01;
    /// Entry is a deletion (not a write)
    pub const IS_DELETION: u8 = 0x04;
}

/// Entry header (8 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
struct EntryHeader {
    /// Entry flags (IS_AUTHENTICATED, IS_DELETION)
    flags: u8,
    /// Reserved
    _reserved: [u8; 3],
    /// Length of the serialized VariableRecord
    record_len: u32,
}

/// Header structure for the deferred buffer
#[repr(C)]
#[derive(Clone, Copy)]
struct DeferredHeader {
    /// Magic value (DEFERRED_MAGIC)
    magic: u32,
    /// Format version
    version: u8,
    /// Flags (reserved)
    flags: u8,
    /// Number of entries
    entry_count: u16,
    /// Total size of all entries (not including header)
    total_size: u32,
    /// CRC32 of header fields (excluding crc itself)
    header_crc: u32,
    /// CRC32 of all entry data
    data_crc: u32,
    /// Reserved padding
    _reserved: [u8; 12],
}

impl DeferredHeader {
    /// Create a new empty header
    const fn new() -> Self {
        Self {
            magic: DEFERRED_MAGIC,
            version: DEFERRED_VERSION,
            flags: 0,
            entry_count: 0,
            total_size: 0,
            header_crc: 0,
            data_crc: 0,
            _reserved: [0; 12],
        }
    }

    /// Compute CRC of header fields
    fn compute_header_crc(&self) -> u32 {
        let magic_bytes = self.magic.to_le_bytes();
        let entry_count_bytes = self.entry_count.to_le_bytes();
        let total_size_bytes = self.total_size.to_le_bytes();

        let bytes = [
            magic_bytes[0],
            magic_bytes[1],
            magic_bytes[2],
            magic_bytes[3],
            self.version,
            self.flags,
            entry_count_bytes[0],
            entry_count_bytes[1],
            total_size_bytes[0],
            total_size_bytes[1],
            total_size_bytes[2],
            total_size_bytes[3],
        ];
        crc32(&bytes)
    }

    /// Check if header is valid
    fn is_valid(&self) -> bool {
        self.magic == DEFERRED_MAGIC
            && self.version == DEFERRED_VERSION
            && self.header_crc == self.compute_header_crc()
    }
}

/// Configured buffer base address
static BUFFER_BASE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(DEFAULT_DEFERRED_BUFFER_BASE);

/// Whether the deferred buffer has been initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Configure the deferred buffer base address
///
/// This should be called early in boot, before any variable operations.
/// The address should point to reserved memory that survives warm reset.
pub fn configure_buffer(base_addr: u64) {
    BUFFER_BASE.store(base_addr, Ordering::SeqCst);
    log::info!("Deferred variable buffer configured at {:#x}", base_addr);
}

/// Get the buffer base address
fn buffer_base() -> *mut u8 {
    BUFFER_BASE.load(Ordering::SeqCst) as *mut u8
}

/// Initialize the deferred buffer
///
/// This clears any existing data and writes a fresh header.
pub fn init_buffer() {
    let base = buffer_base();

    // Zero out the entire buffer
    unsafe {
        core::ptr::write_bytes(base, 0, DEFERRED_BUFFER_SIZE);
    }

    // Write fresh header
    let mut header = DeferredHeader::new();
    header.header_crc = header.compute_header_crc();

    unsafe {
        core::ptr::write(base as *mut DeferredHeader, header);
    }

    INITIALIZED.store(true, Ordering::SeqCst);
    log::debug!("Deferred variable buffer initialized");
}

/// Check if there are pending deferred writes from a previous boot
///
/// Returns the number of pending entries, or 0 if none/invalid.
pub fn check_pending() -> usize {
    let base = buffer_base();

    // Read header
    let header = unsafe { core::ptr::read(base as *const DeferredHeader) };

    if !header.is_valid() {
        log::debug!("No valid deferred buffer header found");
        return 0;
    }

    if header.entry_count == 0 {
        return 0;
    }

    // Verify data CRC
    let data_start = unsafe { base.add(HEADER_SIZE) };
    let data_slice = unsafe { core::slice::from_raw_parts(data_start, header.total_size as usize) };
    let computed_crc = crc32(data_slice);

    if computed_crc != header.data_crc {
        log::warn!(
            "Deferred buffer data CRC mismatch (expected {:#x}, got {:#x})",
            header.data_crc,
            computed_crc
        );
        return 0;
    }

    log::info!(
        "Found {} pending deferred variable writes",
        header.entry_count
    );
    header.entry_count as usize
}

/// Process all pending deferred writes
///
/// This reads each entry from the buffer, applies it to SPI flash,
/// then clears the buffer.
///
/// For authenticated variables:
/// - The signature is verified against the current key databases
/// - Only if verification succeeds is the variable written to NVS
/// - If verification fails, the entry is skipped (security policy)
///
/// Returns the number of entries processed.
pub fn process_pending() -> Result<usize, VarStoreError> {
    let pending_count = check_pending();
    if pending_count == 0 {
        return Ok(0);
    }

    let base = buffer_base();
    let header = unsafe { core::ptr::read(base as *const DeferredHeader) };

    let mut offset = HEADER_SIZE;
    let mut processed = 0usize;
    let entry_header_size = core::mem::size_of::<EntryHeader>();

    for i in 0..header.entry_count {
        // Bounds check: ensure we can read the entry header
        if offset
            .checked_add(entry_header_size)
            .is_none_or(|end| end > DEFERRED_BUFFER_SIZE)
        {
            log::warn!(
                "Entry header at index {} would exceed buffer bounds (offset={}, header_size={})",
                i,
                offset,
                entry_header_size
            );
            break;
        }

        // Read entry header
        let entry_hdr = unsafe {
            let hdr_ptr = base.add(offset) as *const EntryHeader;
            core::ptr::read_unaligned(hdr_ptr)
        };

        let record_len = entry_hdr.record_len as usize;
        let flags = entry_hdr.flags;

        if record_len == 0 || record_len > MAX_ENTRY_SIZE {
            log::warn!("Invalid record length {} at index {}", record_len, i);
            break;
        }

        offset += entry_header_size;

        // Bounds check: ensure we can read the record data
        if offset
            .checked_add(record_len)
            .is_none_or(|end| end > DEFERRED_BUFFER_SIZE)
        {
            log::warn!(
                "Record data at index {} would exceed buffer bounds (offset={}, record_len={})",
                i,
                offset,
                record_len
            );
            break;
        }

        // Read record data
        let record_data = unsafe { core::slice::from_raw_parts(base.add(offset), record_len) };

        let is_authenticated = flags & entry_flags::IS_AUTHENTICATED != 0;
        let is_deletion = flags & entry_flags::IS_DELETION != 0;

        // Deserialize the variable record
        match VariableRecord::deserialize(record_data) {
            Ok(record) => {
                let guid = record.guid.to_guid();

                if is_deletion {
                    // Delete from storage
                    if let Err(e) =
                        super::persistence::write_variable_deletion_internal(&guid, &record.name)
                    {
                        log::warn!("Failed to apply deferred variable deletion: {:?}", e);
                    } else {
                        super::persistence::delete_variable_from_memory(&guid, &record.name);
                        processed += 1;
                    }
                } else if record.is_active() {
                    // Determine the actual data to write and timestamp to preserve
                    let (actual_data, timestamp_to_use) = if is_authenticated {
                        // Authenticated variable: record.data contains the original signed blob
                        // The timestamp was extracted and stored in record.timestamp when queued
                        // Verify it against current key databases before writing to NVS
                        match auth::verify_authenticated_variable(
                            &record.name,
                            &guid,
                            record.attributes,
                            &record.data,
                        ) {
                            Ok(verified_data) => {
                                log::info!("Deferred authenticated variable verified successfully");
                                // Use the timestamp that was stored with the record
                                (verified_data, Some(record.timestamp))
                            }
                            Err(e) => {
                                log::warn!(
                                    "Deferred authenticated variable verification failed: {:?}, skipping",
                                    e
                                );
                                offset += record_len;
                                continue;
                            }
                        }
                    } else {
                        // Non-authenticated variable - use data directly, no timestamp needed
                        (record.data.clone(), None)
                    };

                    // Write to storage (with timestamp for authenticated variables)
                    let write_result = if let Some(ref timestamp) = timestamp_to_use {
                        // Use persist_variable_with_timestamp to preserve the timestamp
                        super::persistence::persist_variable_with_timestamp(
                            &guid,
                            &record.name,
                            record.attributes,
                            &actual_data,
                            *timestamp,
                        )
                    } else {
                        super::persistence::write_variable_to_storage_internal(
                            &guid,
                            &record.name,
                            record.attributes,
                            &actual_data,
                        )
                    };

                    if let Err(e) = write_result {
                        log::warn!("Failed to apply deferred variable write: {:?}", e);
                    } else {
                        // Also update in-memory (timestamp is handled by persist functions)
                        super::persistence::update_variable_in_memory(
                            &guid,
                            &record.name,
                            record.attributes,
                            &actual_data,
                        );
                        processed += 1;
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to deserialize deferred entry {}: {:?}", i, e);
            }
        }

        offset += record_len;
    }

    // Clear the buffer
    init_buffer();

    log::info!("Processed {} deferred variable writes", processed);
    Ok(processed)
}

/// Queue a variable write for deferred processing
///
/// This is called after ExitBootServices when we can't write to SPI directly.
///
/// For authenticated variables (those with TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
/// the original signed data (with EFI_VARIABLE_AUTHENTICATION_2 header) is stored
/// along with the extracted timestamp. The signature will be verified on next boot
/// before writing to NVS, and the timestamp will be preserved.
pub fn queue_write(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Result<(), VarStoreError> {
    let is_authenticated =
        (attributes & auth::attributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0;

    let mut flags: u8 = 0;

    let record = if is_authenticated {
        flags |= entry_flags::IS_AUTHENTICATED;

        // Extract the timestamp from the authentication header
        // This is critical for maintaining timestamp monotonicity after reboot
        let timestamp = extract_auth_timestamp(data)?;

        log::info!(
            "Queuing authenticated variable for deferred verification (timestamp: {}-{:02}-{:02} {:02}:{:02}:{:02})",
            timestamp.year,
            timestamp.month,
            timestamp.day,
            timestamp.hour,
            timestamp.minute,
            timestamp.second
        );

        // Store the data as-is (includes the auth header) along with the extracted timestamp
        VariableRecord::new_with_timestamp(guid, name, attributes, data, timestamp)?
    } else {
        // Non-authenticated variable - no timestamp needed
        VariableRecord::new(guid, name, attributes, data)?
    };

    queue_record_with_flags(&record, flags)
}

/// Extract the timestamp from an EFI_VARIABLE_AUTHENTICATION_2 header
fn extract_auth_timestamp(data: &[u8]) -> Result<SerializedTime, VarStoreError> {
    use auth::EfiVariableAuthentication2;

    let auth = EfiVariableAuthentication2::from_bytes(data).ok_or_else(|| {
        log::warn!("Failed to parse authentication header for timestamp extraction");
        VarStoreError::InvalidArgument
    })?;

    // Convert EfiTime to SerializedTime
    Ok(auth.time_stamp.to_serialized())
}

/// Queue a variable deletion for deferred processing
pub fn queue_deletion(guid: &r_efi::efi::Guid, name: &[u16]) -> Result<(), VarStoreError> {
    let record = VariableRecord::new_deleted(guid, name)?;
    queue_record_with_flags(&record, entry_flags::IS_DELETION)
}

/// Queue a variable record with flags
fn queue_record_with_flags(record: &VariableRecord, flags: u8) -> Result<(), VarStoreError> {
    let base = buffer_base();

    // Serialize the record
    let record_bytes = record.serialize()?;
    let record_len = record_bytes.len();

    if record_len > MAX_ENTRY_SIZE {
        return Err(VarStoreError::DataTooLarge);
    }

    // Read current header
    let mut header = unsafe { core::ptr::read(base as *const DeferredHeader) };

    // If header is invalid, initialize it
    if !header.is_valid() {
        header = DeferredHeader::new();
        header.header_crc = header.compute_header_crc();
    }

    // Calculate where to write
    // Entry format: EntryHeader (8 bytes) + record data
    let data_offset = HEADER_SIZE + header.total_size as usize;
    let entry_header_size = core::mem::size_of::<EntryHeader>();

    // Use checked_add to prevent integer overflow in bounds check
    let new_entry_size = match entry_header_size.checked_add(record_len) {
        Some(size) => size,
        None => {
            log::warn!("Entry size overflow");
            return Err(VarStoreError::DataTooLarge);
        }
    };

    // Use checked_add to prevent integer overflow when checking buffer space
    let required_space = match data_offset.checked_add(new_entry_size) {
        Some(space) => space,
        None => {
            log::warn!("Buffer space calculation overflow");
            return Err(VarStoreError::StoreFull);
        }
    };

    if required_space > DEFERRED_BUFFER_SIZE {
        log::warn!("Deferred buffer full");
        return Err(VarStoreError::StoreFull);
    }

    // Write entry header
    let entry_hdr = EntryHeader {
        flags,
        _reserved: [0; 3],
        record_len: record_len as u32,
    };
    unsafe {
        let hdr_ptr = base.add(data_offset) as *mut EntryHeader;
        core::ptr::write_unaligned(hdr_ptr, entry_hdr);
    }

    // Write record data
    unsafe {
        let data_ptr = base.add(data_offset + entry_header_size);
        core::ptr::copy_nonoverlapping(record_bytes.as_ptr(), data_ptr, record_len);
    }

    // Update header
    header.entry_count += 1;
    header.total_size += new_entry_size as u32;

    // Recompute CRCs
    header.header_crc = header.compute_header_crc();

    let data_start = unsafe { base.add(HEADER_SIZE) };
    let data_slice = unsafe { core::slice::from_raw_parts(data_start, header.total_size as usize) };
    header.data_crc = crc32(data_slice);

    // Write updated header
    unsafe {
        core::ptr::write(base as *mut DeferredHeader, header);
    }

    let flag_desc = if flags & entry_flags::IS_DELETION != 0 {
        " (deletion)"
    } else if flags & entry_flags::IS_AUTHENTICATED != 0 {
        " (authenticated, will verify on next boot)"
    } else {
        ""
    };

    log::debug!(
        "Queued deferred variable write{} (entry {}, {} bytes)",
        flag_desc,
        header.entry_count,
        record_len
    );

    Ok(())
}

/// Check if deferred buffer is initialized
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

/// Get statistics about the deferred buffer
pub fn get_stats() -> (usize, usize, usize) {
    let base = buffer_base();
    let header = unsafe { core::ptr::read(base as *const DeferredHeader) };

    if !header.is_valid() {
        return (0, 0, DEFERRED_BUFFER_SIZE - HEADER_SIZE);
    }

    let used = header.total_size as usize;
    let free = DEFERRED_BUFFER_SIZE - HEADER_SIZE - used;

    (header.entry_count as usize, used, free)
}
