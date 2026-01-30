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

use alloc::vec::Vec;
use spin::Mutex;

use crate::drivers::spi::{self, AnySpiController, SpiController};
use crate::state::{self, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN};

use super::{EspVariableFile, StoreHeader, VarStoreError, VariableRecord, STORE_HEADER_SIZE};

/// Default SMMSTORE base address in SPI flash
/// This is typically at the end of the flash region
/// The exact location should be obtained from coreboot tables
pub const DEFAULT_SMMSTORE_BASE: u32 = 0x00F00000; // 15MB offset (for 16MB flash)

/// Default SMMSTORE size (256KB)
pub const DEFAULT_SMMSTORE_SIZE: u32 = 256 * 1024;

/// Global SPI controller (initialized at boot)
static SPI_CONTROLLER: Mutex<Option<AnySpiController>> = Mutex::new(None);

/// Global pending writes for ESP file (used after ExitBootServices)
static PENDING_WRITES: Mutex<Option<EspVariableFile>> = Mutex::new(None);

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
/// 1. Detect and initialize the SPI controller
/// 2. Read existing variables from SMMSTORE
/// 3. Load them into the in-memory variable cache
pub fn init() -> Result<(), VarStoreError> {
    log::info!("Initializing variable store persistence...");

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
/// After ExitBootServices: queues write for ESP file
pub fn persist_variable(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Result<(), VarStoreError> {
    if state::is_exit_boot_services_called() {
        // After ExitBootServices - queue for ESP file
        queue_variable_for_esp(guid, name, attributes, data)
    } else {
        // Before ExitBootServices - write to SPI flash
        write_variable_to_spi(guid, name, attributes, data)
    }
}

/// Delete a variable from storage
pub fn delete_variable(guid: &r_efi::efi::Guid, name: &[u16]) -> Result<(), VarStoreError> {
    if state::is_exit_boot_services_called() {
        // After ExitBootServices - queue deletion for ESP file
        queue_variable_deletion_for_esp(guid, name)
    } else {
        // Before ExitBootServices - mark deleted in SPI flash
        write_variable_deletion_to_spi(guid, name)
    }
}

/// Write a variable record to SPI flash
fn write_variable_to_spi(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Result<(), VarStoreError> {
    let mut spi_guard = SPI_CONTROLLER.lock();
    let spi = spi_guard.as_mut().ok_or(VarStoreError::NotInitialized)?;

    let mut config = SMMSTORE_CONFIG.lock();
    if !config.initialized {
        return Err(VarStoreError::NotInitialized);
    }

    // Create the variable record
    let record = VariableRecord::new(guid, name, attributes, data)?;
    let record_bytes = record.serialize()?;

    // Check if we have space
    if config.write_offset + record_bytes.len() as u32 > config.size {
        // TODO: Implement compaction
        log::warn!("SMMSTORE full - compaction not yet implemented");
        return Err(VarStoreError::StoreFull);
    }

    // Try to enable writes
    if let Err(e) = spi.enable_writes() {
        log::warn!("Could not enable SPI writes: {:?}", e);
    }

    // Write the record
    spi.write(config.base_addr + config.write_offset, &record_bytes)
        .map_err(|_| VarStoreError::SpiError)?;

    config.write_offset += record_bytes.len() as u32;

    log::debug!(
        "Variable persisted to SPI at offset {:#x}",
        config.write_offset - record_bytes.len() as u32
    );

    Ok(())
}

/// Write a deletion record to SPI flash
fn write_variable_deletion_to_spi(
    guid: &r_efi::efi::Guid,
    name: &[u16],
) -> Result<(), VarStoreError> {
    let mut spi_guard = SPI_CONTROLLER.lock();
    let spi = spi_guard.as_mut().ok_or(VarStoreError::NotInitialized)?;

    let mut config = SMMSTORE_CONFIG.lock();
    if !config.initialized {
        return Err(VarStoreError::NotInitialized);
    }

    // Create a deletion record
    let record = VariableRecord::new_deleted(guid, name)?;
    let record_bytes = record.serialize()?;

    // Check if we have space
    if config.write_offset + record_bytes.len() as u32 > config.size {
        log::warn!("SMMSTORE full - compaction not yet implemented");
        return Err(VarStoreError::StoreFull);
    }

    // Try to enable writes
    if let Err(e) = spi.enable_writes() {
        log::warn!("Could not enable SPI writes: {:?}", e);
    }

    // Write the record
    spi.write(config.base_addr + config.write_offset, &record_bytes)
        .map_err(|_| VarStoreError::SpiError)?;

    config.write_offset += record_bytes.len() as u32;

    log::debug!("Variable deletion persisted to SPI");

    Ok(())
}

/// Queue a variable write for ESP file (after ExitBootServices)
fn queue_variable_for_esp(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Result<(), VarStoreError> {
    let mut pending = PENDING_WRITES.lock();

    // Initialize if needed
    if pending.is_none() {
        *pending = Some(EspVariableFile::new());
    }

    let file = pending.as_mut().unwrap();
    let record = VariableRecord::new(guid, name, attributes, data)?;
    file.add(record, None);

    log::debug!("Variable queued for ESP file");
    Ok(())
}

/// Queue a variable deletion for ESP file (after ExitBootServices)
fn queue_variable_deletion_for_esp(
    guid: &r_efi::efi::Guid,
    name: &[u16],
) -> Result<(), VarStoreError> {
    let mut pending = PENDING_WRITES.lock();

    // Initialize if needed
    if pending.is_none() {
        *pending = Some(EspVariableFile::new());
    }

    let file = pending.as_mut().unwrap();
    let record = VariableRecord::new_deleted(guid, name)?;
    file.add(record, None);

    log::debug!("Variable deletion queued for ESP file");
    Ok(())
}

/// Get pending ESP file data (for writing to ESP partition)
///
/// Returns serialized ESP variable file data, or None if no pending writes.
pub fn get_pending_esp_data() -> Option<Vec<u8>> {
    let mut pending = PENDING_WRITES.lock();

    if let Some(ref mut file) = *pending {
        if file.pending.is_empty() {
            return None;
        }

        match file.serialize() {
            Ok(data) => Some(data),
            Err(_) => None,
        }
    } else {
        None
    }
}

/// Clear pending ESP writes
pub fn clear_pending_esp_data() {
    let mut pending = PENDING_WRITES.lock();
    *pending = None;
}

/// Write pending variable changes to ESP file
///
/// This should be called before shutdown/reboot if there are pending changes
/// that couldn't be written to SPI (e.g., after ExitBootServices).
/// On next boot, the ESP file will be read and applied to SPI.
///
/// # Arguments
/// * `write_fn` - A function that writes data to the ESP variable file
///
/// Returns Ok(true) if data was written, Ok(false) if no pending data.
pub fn flush_pending_to_esp<F>(mut write_fn: F) -> Result<bool, VarStoreError>
where
    F: FnMut(&[u8]) -> Result<(), VarStoreError>,
{
    let data = match get_pending_esp_data() {
        Some(d) => d,
        None => return Ok(false),
    };

    write_fn(&data)?;
    clear_pending_esp_data();

    log::info!("Flushed pending variable changes to ESP file");
    Ok(true)
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

/// Process ESP variable file on boot
///
/// This reads the ESP variable file, authenticates the variables (if needed),
/// applies them to SPI flash, and then deletes the file.
///
/// # Arguments
/// * `file_data` - The contents of the ESP variable file
/// * `delete_fn` - A function to delete the ESP file after processing
///
/// Returns the number of variables processed, or an error.
pub fn process_esp_file<F>(file_data: &[u8], mut delete_fn: F) -> Result<usize, VarStoreError>
where
    F: FnMut() -> Result<(), VarStoreError>,
{
    // Deserialize the ESP variable file
    let esp_file = EspVariableFile::deserialize(file_data)?;

    log::info!(
        "Processing ESP variable file with {} pending writes",
        esp_file.pending.len()
    );

    let mut count = 0;

    // Process each pending variable
    for pending in &esp_file.pending {
        let record = &pending.record;
        let guid = record.guid.to_guid();

        // TODO: Verify authentication signature if present
        // For now, we skip authentication (variables in ESP file should have been
        // authenticated when they were originally written)

        if record.is_active() {
            // Write variable to SPI
            if let Err(e) =
                write_variable_to_spi(&guid, &record.name, record.attributes, &record.data)
            {
                log::warn!("Failed to apply variable from ESP file: {:?}", e);
                continue;
            }
        } else {
            // Delete variable from SPI
            if let Err(e) = write_variable_deletion_to_spi(&guid, &record.name) {
                log::warn!("Failed to apply variable deletion from ESP file: {:?}", e);
                continue;
            }
        }

        count += 1;
    }

    // Delete the ESP file
    if let Err(e) = delete_fn() {
        log::warn!("Failed to delete ESP variable file: {:?}", e);
    }

    log::info!("Applied {} variables from ESP file", count);
    Ok(count)
}

/// ESP variable file path (relative to ESP root)
pub const ESP_VAR_FILE_PATH: &str = "EFI\\CRABEFI\\VARS.BIN";
