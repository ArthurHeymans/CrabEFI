//! Variable Store Persistence Layer
//!
//! This module handles persisting UEFI variables to SPI flash and ESP files.
//! It bridges the in-memory variable storage in `state::EfiState::variables`
//! with persistent storage.
//!
//! # Storage Strategy
//!
//! - **Before ExitBootServices**: Variables are written to SPI flash
//! - **After ExitBootServices**: SPI is locked; variables are queued for ESP file
//! - **On Reset**: ESP file is read, authenticated, applied to SPI, then deleted
//!
//! # SMMSTORE v2 Support
//!
//! When available, SMMSTORE configuration is read from coreboot tables (LB_TAG_SMMSTOREV2).
//! This provides the memory-mapped address and size of the variable store region.

use alloc::vec::Vec;
use spin::Mutex;

use crate::coreboot;
use crate::drivers::spi::{self, AnySpiController, SpiController};
use crate::state::{self, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN};

use super::{StoreHeader, VarStoreError, VariableRecord, STORE_HEADER_SIZE};

/// Default SMMSTORE base address in SPI flash
/// This is typically at the end of the flash region
/// Used only as fallback if coreboot tables don't provide SMMSTORE v2 info
pub const DEFAULT_SMMSTORE_BASE: u32 = 0x00F00000; // 15MB offset (for 16MB flash)

/// Default SMMSTORE size (256KB)
/// Used only as fallback if coreboot tables don't provide SMMSTORE v2 info
pub const DEFAULT_SMMSTORE_SIZE: u32 = 256 * 1024;

/// Global SPI controller (initialized at boot)
static SPI_CONTROLLER: Mutex<Option<AnySpiController>> = Mutex::new(None);

/// SMMSTORE configuration
static SMMSTORE_CONFIG: Mutex<SmmstoreConfig> = Mutex::new(SmmstoreConfig {
    base_addr: DEFAULT_SMMSTORE_BASE,
    size: DEFAULT_SMMSTORE_SIZE,
    initialized: false,
    write_offset: STORE_HEADER_SIZE as u32,
});

/// SMMSTORE configuration
struct SmmstoreConfig {
    base_addr: u32,
    size: u32,
    initialized: bool,
    write_offset: u32,
}

/// Initialize the variable store persistence layer
///
/// This should be called early in boot to:
/// 1. Check for SMMSTORE v2 configuration from coreboot tables
/// 2. Detect and initialize the SPI controller
/// 3. Read existing variables from SMMSTORE
/// 4. Load them into the in-memory variable cache
pub fn init() -> Result<(), VarStoreError> {
    log::info!("Initializing variable store persistence...");

    // Check for SMMSTORE v2 info from coreboot tables
    if let Some(smmstore_info) = coreboot::get_smmstorev2() {
        log::info!(
            "Using SMMSTORE v2 from coreboot: {} blocks x {} KB at {:#x}",
            smmstore_info.num_blocks,
            smmstore_info.block_size / 1024,
            smmstore_info.mmap_addr
        );

        // Update the SMMSTORE configuration with values from coreboot
        {
            let mut config = SMMSTORE_CONFIG.lock();
            // The mmap_addr is the memory-mapped address for read-only access
            // For SPI flash writes, we need to convert to the flash offset
            // The mmap_addr is typically in the 0xFF... range (memory-mapped SPI)
            // We'll calculate the actual base address based on the memory map
            config.base_addr = calculate_spi_offset(smmstore_info.mmap_addr);
            config.size = smmstore_info.num_blocks * smmstore_info.block_size;
            log::info!(
                "SMMSTORE: base={:#x}, size={} KB",
                config.base_addr,
                config.size / 1024
            );
        }
    } else {
        log::info!(
            "No SMMSTORE v2 in coreboot tables, using defaults: base={:#x}, size={} KB",
            DEFAULT_SMMSTORE_BASE,
            DEFAULT_SMMSTORE_SIZE / 1024
        );
    }

    // Detect SPI controller
    let controller = match spi::detect_and_init() {
        Some(c) => c,
        None => {
            log::warn!("No SPI controller found - variables will not be persistent");
            return Err(VarStoreError::NotInitialized);
        }
    };

    log::info!("SPI controller: {}", controller.name());

    // Store the controller globally
    {
        let mut spi = SPI_CONTROLLER.lock();
        *spi = Some(controller);
    }

    // Initialize SMMSTORE
    init_smmstore()?;

    // Load existing variables from SMMSTORE into memory
    load_variables_from_smmstore()?;

    log::info!("Variable store persistence initialized");
    Ok(())
}

/// Calculate SPI flash offset from memory-mapped address
///
/// Coreboot's SMMSTORE v2 provides a memory-mapped address for read-only access.
/// We need to convert this to the SPI flash offset for write operations.
///
/// On x86 systems, the SPI flash is typically mapped at the end of the 32-bit
/// address space (starting at 0xFF000000 for 16MB flash, 0xFE000000 for 32MB, etc.)
fn calculate_spi_offset(mmap_addr: u64) -> u32 {
    // If the address is in the memory-mapped range (top of 4GB)
    if mmap_addr >= 0xFF000000 {
        // For 16MB flash mapped at 0xFF000000:
        // mmap_addr 0xFF000000 -> SPI offset 0x000000
        // mmap_addr 0xFFF00000 -> SPI offset 0xF00000
        (mmap_addr - 0xFF000000) as u32
    } else if mmap_addr >= 0xFE000000 {
        // For 32MB flash mapped at 0xFE000000
        (mmap_addr - 0xFE000000) as u32
    } else if mmap_addr >= 0xFC000000 {
        // For 64MB flash mapped at 0xFC000000
        (mmap_addr - 0xFC000000) as u32
    } else if mmap_addr == 0 {
        // No address provided, use default
        DEFAULT_SMMSTORE_BASE
    } else {
        // Assume the address is already a flash offset
        mmap_addr as u32
    }
}

/// Initialize the SMMSTORE region
fn init_smmstore() -> Result<(), VarStoreError> {
    let mut spi_guard = SPI_CONTROLLER.lock();
    let spi = spi_guard.as_mut().ok_or(VarStoreError::NotInitialized)?;

    let mut config = SMMSTORE_CONFIG.lock();

    // Read the store header
    let mut header_bytes = [0u8; STORE_HEADER_SIZE];
    spi.read(config.base_addr, &mut header_bytes)
        .map_err(|_| VarStoreError::SpiError)?;

    // Check if the header is valid
    if let Ok(header) = postcard::from_bytes::<StoreHeader>(&header_bytes) {
        if header.is_valid() {
            log::info!(
                "SMMSTORE found at {:#x}, size {} KB",
                config.base_addr,
                header.store_size / 1024
            );
            config.size = header.store_size;
            config.initialized = true;
            return Ok(());
        }
    }

    // Header invalid or missing - format the store
    log::info!("Formatting SMMSTORE at {:#x}...", config.base_addr);

    // Try to enable writes
    if let Err(e) = spi.enable_writes() {
        log::warn!("Could not enable SPI writes: {:?}", e);
        // Continue anyway - the erase/write will fail if truly locked
    }

    // Erase the region
    spi.erase(config.base_addr, config.size)
        .map_err(|_| VarStoreError::SpiError)?;

    // Write new header
    let header = StoreHeader::new(config.size);
    let header_bytes = postcard::to_allocvec(&header).map_err(|_| VarStoreError::SerdeError)?;

    spi.write(config.base_addr, &header_bytes)
        .map_err(|_| VarStoreError::SpiError)?;

    config.initialized = true;
    config.write_offset = STORE_HEADER_SIZE as u32;

    log::info!("SMMSTORE formatted successfully");
    Ok(())
}

/// Load variables from SMMSTORE into the in-memory cache
fn load_variables_from_smmstore() -> Result<(), VarStoreError> {
    let mut spi_guard = SPI_CONTROLLER.lock();
    let spi = spi_guard.as_mut().ok_or(VarStoreError::NotInitialized)?;

    let config = SMMSTORE_CONFIG.lock();
    if !config.initialized {
        return Err(VarStoreError::NotInitialized);
    }

    let base = config.base_addr;
    let size = config.size;
    drop(config); // Release lock before calling state functions

    // Scan for variable records
    let mut offset = STORE_HEADER_SIZE as u32;
    let mut records: Vec<VariableRecord> = Vec::new();

    while offset < size {
        // Read a chunk to try deserializing
        let remaining = size - offset;
        let chunk_size = core::cmp::min(remaining, MAX_VARIABLE_DATA_SIZE as u32 + 256);
        let mut chunk = alloc::vec![0u8; chunk_size as usize];

        spi.read(base + offset, &mut chunk)
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
                    let guid = record.guid;
                    let name = record.name.clone();
                    records.retain(|r| !(r.guid == guid && r.name == name));
                    records.push(record);
                } else {
                    // Deleted record - remove from cache
                    let guid = record.guid;
                    let name = record.name.clone();
                    records.retain(|r| !(r.guid == guid && r.name == name));
                }

                offset += record_size;
            }
            Err(_) => {
                log::warn!("Invalid variable record at offset {:#x}", offset);
                break;
            }
        }
    }

    // Update write offset
    {
        let mut config = SMMSTORE_CONFIG.lock();
        config.write_offset = offset;
    }

    // Load records into in-memory variable cache
    state::with_efi_mut(|efi| {
        for record in records {
            // Find a free slot
            if let Some(slot) = efi.variables.iter_mut().find(|v| !v.in_use) {
                // Convert record to VariableEntry
                let name_len = record.name.len().min(MAX_VARIABLE_NAME_LEN);
                slot.name[..name_len].copy_from_slice(&record.name[..name_len]);
                if name_len < MAX_VARIABLE_NAME_LEN {
                    slot.name[name_len..].fill(0);
                }

                slot.vendor_guid = record.guid.to_guid();
                slot.attributes = record.attributes;

                let data_len = record.data.len().min(MAX_VARIABLE_DATA_SIZE);
                slot.data[..data_len].copy_from_slice(&record.data[..data_len]);
                slot.data_size = data_len;
                slot.in_use = true;

                log::debug!(
                    "Loaded variable from SMMSTORE: {:?}",
                    core::str::from_utf8(
                        &record
                            .name
                            .iter()
                            .take_while(|&&c| c != 0)
                            .map(|&c| c as u8)
                            .collect::<Vec<_>>()
                    )
                );
            } else {
                log::warn!("No free variable slots - some variables may be lost");
                break;
            }
        }
    });

    log::info!("Loaded variables from SMMSTORE");
    Ok(())
}

/// Persist a variable to storage
///
/// Before ExitBootServices: writes to SPI flash
/// After ExitBootServices: queues write for deferred processing on next boot
pub fn persist_variable(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Result<(), VarStoreError> {
    if state::is_exit_boot_services_called() {
        // After ExitBootServices - queue for deferred processing
        queue_variable_for_deferred(guid, name, attributes, data)
    } else {
        // Before ExitBootServices - write to SPI flash
        write_variable_to_spi_internal(guid, name, attributes, data)
    }
}

/// Delete a variable from storage
pub fn delete_variable(guid: &r_efi::efi::Guid, name: &[u16]) -> Result<(), VarStoreError> {
    if state::is_exit_boot_services_called() {
        // After ExitBootServices - queue deletion for deferred processing
        queue_variable_deletion_for_deferred(guid, name)
    } else {
        // Before ExitBootServices - mark deleted in SPI flash
        write_variable_deletion_to_spi_internal(guid, name)
    }
}

/// Write a variable record to SPI flash
///
/// This is the internal function that actually writes to SPI.
/// It's exposed to the deferred module for applying queued changes.
///
/// If the store is full, this function will attempt compaction first.
pub(super) fn write_variable_to_spi_internal(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Result<(), VarStoreError> {
    // Create the variable record first (before locking)
    let record = VariableRecord::new(guid, name, attributes, data)?;
    let record_bytes = record.serialize()?;
    let record_len = record_bytes.len() as u32;

    // Check if we need compaction
    {
        let config = SMMSTORE_CONFIG.lock();
        if config.initialized && config.write_offset + record_len > config.size {
            // Need compaction - release lock first
            drop(config);
            log::info!("SMMSTORE full, triggering compaction");
            compact_smmstore()?;
        }
    }

    // Now do the actual write
    let mut spi_guard = SPI_CONTROLLER.lock();
    let spi = spi_guard.as_mut().ok_or(VarStoreError::NotInitialized)?;

    let mut config = SMMSTORE_CONFIG.lock();
    if !config.initialized {
        return Err(VarStoreError::NotInitialized);
    }

    // Check again after compaction
    if config.write_offset + record_len > config.size {
        log::error!("SMMSTORE still full after compaction");
        return Err(VarStoreError::StoreFull);
    }

    // Try to enable writes
    if let Err(e) = spi.enable_writes() {
        log::warn!("Could not enable SPI writes: {:?}", e);
    }

    // Write the record
    spi.write(config.base_addr + config.write_offset, &record_bytes)
        .map_err(|_| VarStoreError::SpiError)?;

    config.write_offset += record_len;

    log::debug!(
        "Variable persisted to SPI at offset {:#x}",
        config.write_offset - record_len
    );

    Ok(())
}

/// Write a deletion record to SPI flash
///
/// This is the internal function that actually writes the deletion to SPI.
/// It's exposed to the deferred module for applying queued changes.
///
/// If the store is full, this function will attempt compaction first.
pub(super) fn write_variable_deletion_to_spi_internal(
    guid: &r_efi::efi::Guid,
    name: &[u16],
) -> Result<(), VarStoreError> {
    // Create a deletion record first (before locking)
    let record = VariableRecord::new_deleted(guid, name)?;
    let record_bytes = record.serialize()?;
    let record_len = record_bytes.len() as u32;

    // Check if we need compaction
    {
        let config = SMMSTORE_CONFIG.lock();
        if config.initialized && config.write_offset + record_len > config.size {
            // Need compaction - release lock first
            drop(config);
            log::info!("SMMSTORE full, triggering compaction for deletion");
            compact_smmstore()?;
        }
    }

    // Now do the actual write
    let mut spi_guard = SPI_CONTROLLER.lock();
    let spi = spi_guard.as_mut().ok_or(VarStoreError::NotInitialized)?;

    let mut config = SMMSTORE_CONFIG.lock();
    if !config.initialized {
        return Err(VarStoreError::NotInitialized);
    }

    // Check again after compaction
    if config.write_offset + record_len > config.size {
        log::error!("SMMSTORE still full after compaction");
        return Err(VarStoreError::StoreFull);
    }

    // Try to enable writes
    if let Err(e) = spi.enable_writes() {
        log::warn!("Could not enable SPI writes: {:?}", e);
    }

    // Write the record
    spi.write(config.base_addr + config.write_offset, &record_bytes)
        .map_err(|_| VarStoreError::SpiError)?;

    config.write_offset += record_len;

    log::debug!("Variable deletion persisted to SPI");

    Ok(())
}

/// Queue a variable write for deferred processing (after ExitBootServices)
///
/// When SPI is locked, variable changes are stored in a reserved memory
/// region that survives warm reboot. On next boot, these changes are
/// applied to SPI flash.
fn queue_variable_for_deferred(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Result<(), VarStoreError> {
    super::deferred::queue_write(guid, name, attributes, data)?;
    log::debug!("Variable queued for deferred processing");
    Ok(())
}

/// Queue a variable deletion for deferred processing (after ExitBootServices)
fn queue_variable_deletion_for_deferred(
    guid: &r_efi::efi::Guid,
    name: &[u16],
) -> Result<(), VarStoreError> {
    super::deferred::queue_deletion(guid, name)?;
    log::debug!("Variable deletion queued for deferred processing");
    Ok(())
}

/// Check if SPI controller is available
pub fn is_spi_available() -> bool {
    SPI_CONTROLLER.lock().is_some()
}

/// Check if SMMSTORE is initialized
pub fn is_smmstore_initialized() -> bool {
    SMMSTORE_CONFIG.lock().initialized
}

/// Get SMMSTORE statistics
pub fn get_smmstore_stats() -> (u32, u32, u32) {
    let config = SMMSTORE_CONFIG.lock();
    (config.base_addr, config.size, config.write_offset)
}

/// Compact the SMMSTORE by rewriting only active variables
///
/// This is called when the store is full. It:
/// 1. Reads all active variables from flash into memory
/// 2. Erases the entire SMMSTORE region
/// 3. Writes a fresh header
/// 4. Rewrites all active variables
///
/// Returns the number of bytes reclaimed.
pub fn compact_smmstore() -> Result<u32, VarStoreError> {
    log::info!("Compacting SMMSTORE...");

    let mut spi_guard = SPI_CONTROLLER.lock();
    let spi = spi_guard.as_mut().ok_or(VarStoreError::NotInitialized)?;

    let mut config = SMMSTORE_CONFIG.lock();
    if !config.initialized {
        return Err(VarStoreError::NotInitialized);
    }

    let base = config.base_addr;
    let size = config.size;
    let old_write_offset = config.write_offset;

    // Step 1: Collect all active variable records
    let mut active_records: Vec<VariableRecord> = Vec::new();
    let mut offset = STORE_HEADER_SIZE as u32;

    while offset < size {
        let remaining = size - offset;
        let chunk_size = core::cmp::min(remaining, super::MAX_DATA_SIZE as u32 + 256);
        let mut chunk = alloc::vec![0u8; chunk_size as usize];

        spi.read(base + offset, &mut chunk)
            .map_err(|_| VarStoreError::SpiError)?;

        // Check for empty space (0xFF = erased flash)
        if chunk[0] == 0xFF {
            break;
        }

        match VariableRecord::deserialize(&chunk) {
            Ok(record) => {
                let record_size = record.serialize()?.len() as u32;

                if record.is_active() {
                    // Keep only the latest version of each variable
                    let guid = record.guid;
                    let name = record.name.clone();
                    active_records.retain(|r| !(r.guid == guid && r.name == name));
                    active_records.push(record);
                }
                // Skip deleted records - they won't be rewritten

                offset += record_size;
            }
            Err(_) => {
                log::warn!("Invalid record during compaction at offset {:#x}", offset);
                break;
            }
        }
    }

    log::info!(
        "Found {} active variables to preserve during compaction",
        active_records.len()
    );

    // Step 2: Try to enable writes and erase the region
    if let Err(e) = spi.enable_writes() {
        log::warn!("Could not enable SPI writes for compaction: {:?}", e);
    }

    spi.erase(base, size).map_err(|_| VarStoreError::SpiError)?;

    // Step 3: Write fresh header
    let header = StoreHeader::new(size);
    let header_bytes = postcard::to_allocvec(&header).map_err(|_| VarStoreError::SerdeError)?;

    spi.write(base, &header_bytes)
        .map_err(|_| VarStoreError::SpiError)?;

    // Step 4: Rewrite all active variables
    let mut new_offset = STORE_HEADER_SIZE as u32;

    for record in active_records {
        let record_bytes = record.serialize()?;

        if new_offset + record_bytes.len() as u32 > size {
            log::error!("SMMSTORE full even after compaction - data loss!");
            config.write_offset = new_offset;
            return Err(VarStoreError::StoreFull);
        }

        spi.write(base + new_offset, &record_bytes)
            .map_err(|_| VarStoreError::SpiError)?;

        new_offset += record_bytes.len() as u32;
    }

    // Update configuration
    config.write_offset = new_offset;

    let reclaimed = old_write_offset - new_offset;
    log::info!(
        "SMMSTORE compaction complete: reclaimed {} bytes, new write offset {:#x}",
        reclaimed,
        new_offset
    );

    Ok(reclaimed)
}

/// Update a variable in the in-memory cache
///
/// This is used when applying deferred variable changes on boot.
pub(super) fn update_variable_in_memory(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) {
    use crate::state::{self, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN};

    state::with_efi_mut(|efi| {
        // Find existing or free slot
        let existing_idx = efi.variables.iter().position(|var| {
            var.in_use && var.vendor_guid == *guid && name_eq_slice(&var.name, name)
        });

        let idx = match existing_idx {
            Some(i) => i,
            None => match efi.variables.iter().position(|var| !var.in_use) {
                Some(i) => i,
                None => {
                    log::warn!("No free variable slots");
                    return;
                }
            },
        };

        // Copy name
        let name_len = name.len().min(MAX_VARIABLE_NAME_LEN);
        efi.variables[idx].name[..name_len].copy_from_slice(&name[..name_len]);
        if name_len < MAX_VARIABLE_NAME_LEN {
            efi.variables[idx].name[name_len..].fill(0);
        }

        // Copy data
        let data_len = data.len().min(MAX_VARIABLE_DATA_SIZE);
        efi.variables[idx].data[..data_len].copy_from_slice(&data[..data_len]);

        efi.variables[idx].vendor_guid = *guid;
        efi.variables[idx].attributes = attributes;
        efi.variables[idx].data_size = data_len;
        efi.variables[idx].in_use = true;
    });
}

/// Delete a variable from the in-memory cache
///
/// This is used when applying deferred variable deletions on boot.
pub(super) fn delete_variable_from_memory(guid: &r_efi::efi::Guid, name: &[u16]) {
    use crate::state;

    state::with_efi_mut(|efi| {
        if let Some(var) = efi
            .variables
            .iter_mut()
            .find(|var| var.in_use && var.vendor_guid == *guid && name_eq_slice(&var.name, name))
        {
            var.in_use = false;
        }
    });
}

/// Compare a stored name array with a name slice
fn name_eq_slice(stored: &[u16], name: &[u16]) -> bool {
    // Get length of stored name (up to null terminator)
    let stored_len = stored.iter().position(|&c| c == 0).unwrap_or(stored.len());

    // Get length of name (up to null terminator)
    let name_len = name.iter().position(|&c| c == 0).unwrap_or(name.len());

    if stored_len != name_len {
        return false;
    }

    stored[..stored_len] == name[..name_len]
}
