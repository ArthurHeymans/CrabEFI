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

use core::sync::atomic::{AtomicBool, Ordering};

use super::{crc32, VarStoreError, VariableRecord};

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
        let bytes = [
            (self.magic & 0xFF) as u8,
            ((self.magic >> 8) & 0xFF) as u8,
            ((self.magic >> 16) & 0xFF) as u8,
            ((self.magic >> 24) & 0xFF) as u8,
            self.version,
            self.flags,
            (self.entry_count & 0xFF) as u8,
            ((self.entry_count >> 8) & 0xFF) as u8,
            (self.total_size & 0xFF) as u8,
            ((self.total_size >> 8) & 0xFF) as u8,
            ((self.total_size >> 16) & 0xFF) as u8,
            ((self.total_size >> 24) & 0xFF) as u8,
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

    for i in 0..header.entry_count {
        // Read entry length (4 bytes)
        let entry_len = unsafe {
            let len_ptr = base.add(offset) as *const u32;
            core::ptr::read_unaligned(len_ptr) as usize
        };

        if entry_len == 0 || entry_len > MAX_ENTRY_SIZE {
            log::warn!("Invalid entry length {} at index {}", entry_len, i);
            break;
        }

        offset += 4;

        // Read entry data
        let entry_data = unsafe { core::slice::from_raw_parts(base.add(offset), entry_len) };

        // Deserialize the variable record
        match VariableRecord::deserialize(entry_data) {
            Ok(record) => {
                let guid = record.guid.to_guid();

                if record.is_active() {
                    // Write to SPI
                    if let Err(e) = super::persistence::write_variable_to_spi_internal(
                        &guid,
                        &record.name,
                        record.attributes,
                        &record.data,
                    ) {
                        log::warn!("Failed to apply deferred variable write: {:?}", e);
                    } else {
                        // Also update in-memory
                        super::persistence::update_variable_in_memory(
                            &guid,
                            &record.name,
                            record.attributes,
                            &record.data,
                        );
                        processed += 1;
                    }
                } else {
                    // Delete from SPI
                    if let Err(e) = super::persistence::write_variable_deletion_to_spi_internal(
                        &guid,
                        &record.name,
                    ) {
                        log::warn!("Failed to apply deferred variable deletion: {:?}", e);
                    } else {
                        super::persistence::delete_variable_from_memory(&guid, &record.name);
                        processed += 1;
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to deserialize deferred entry {}: {:?}", i, e);
            }
        }

        offset += entry_len;
    }

    // Clear the buffer
    init_buffer();

    log::info!("Processed {} deferred variable writes", processed);
    Ok(processed)
}

/// Queue a variable write for deferred processing
///
/// This is called after ExitBootServices when we can't write to SPI directly.
pub fn queue_write(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Result<(), VarStoreError> {
    let record = VariableRecord::new(guid, name, attributes, data)?;
    queue_record(&record)
}

/// Queue a variable deletion for deferred processing
pub fn queue_deletion(guid: &r_efi::efi::Guid, name: &[u16]) -> Result<(), VarStoreError> {
    let record = VariableRecord::new_deleted(guid, name)?;
    queue_record(&record)
}

/// Queue a variable record
fn queue_record(record: &VariableRecord) -> Result<(), VarStoreError> {
    let base = buffer_base();

    // Serialize the record
    let record_bytes = record.serialize()?;
    let entry_len = record_bytes.len();

    if entry_len > MAX_ENTRY_SIZE {
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
    let data_offset = HEADER_SIZE + header.total_size as usize;
    let new_entry_size = 4 + entry_len; // length prefix + data

    if data_offset + new_entry_size > DEFERRED_BUFFER_SIZE {
        log::warn!("Deferred buffer full");
        return Err(VarStoreError::StoreFull);
    }

    // Write entry length
    unsafe {
        let len_ptr = base.add(data_offset) as *mut u32;
        core::ptr::write_unaligned(len_ptr, entry_len as u32);
    }

    // Write entry data
    unsafe {
        let data_ptr = base.add(data_offset + 4);
        core::ptr::copy_nonoverlapping(record_bytes.as_ptr(), data_ptr, entry_len);
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

    log::debug!(
        "Queued deferred variable write (entry {}, {} bytes)",
        header.entry_count,
        entry_len
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
