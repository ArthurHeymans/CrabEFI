//! Variable Store Persistence Layer
//!
//! This module handles persisting UEFI variables to storage (SPI flash, etc.)
//! and ESP files. It bridges the in-memory variable storage in
//! `state::EfiState::variables` with persistent storage.
//!
//! # Storage Strategy
//!
//! - **Before ExitBootServices**: Variables are written to storage (SPI flash)
//! - **After ExitBootServices**: Storage may be locked; variables are queued for ESP file
//! - **On Reset**: ESP file is read, authenticated, applied to storage, then deleted
//!
//! # Storage Backend Abstraction
//!
//! This module uses the `StorageBackend` trait to abstract storage operations,
//! allowing different backends (SPI flash, memory for testing, etc.) to be used.
//! The storage backend is stored in `state::DriverState::storage`.
//!
//! # Persistent Config Region
//!
//! The location of the variable store region is determined at runtime from:
//! 1. Coreboot tables (SMMSTORE v2 record)
//! 2. FMAP (SMMSTORE region)

use alloc::vec::Vec;

use crate::coreboot;
use crate::drivers::spi::{self, SpiController};
use crate::state::{self, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN};

use super::storage::{SpiStorageBackend, StorageBackend};
use super::{StoreHeader, VarStoreError, VariableRecord, STORE_HEADER_SIZE};

/// Default variable store base address in SPI flash
/// This is typically at the end of the flash region
/// Used only as fallback if coreboot tables don't provide config info
pub const DEFAULT_VARSTORE_BASE: u32 = 0x00F00000; // 15MB offset (for 16MB flash)

/// Default variable store size (256KB)
/// Used only as fallback if coreboot tables don't provide config info
pub const DEFAULT_VARSTORE_SIZE: u32 = 256 * 1024;

/// Initialize the variable store persistence layer
///
/// This should be called early in boot to:
/// 1. Detect and initialize the storage backend (SPI controller)
/// 2. Check for persistent config region from coreboot tables or FMAP
/// 3. Read existing variables from storage
/// 4. Load them into the in-memory variable cache
pub fn init() -> Result<(), VarStoreError> {
    log::info!("Initializing variable store persistence...");

    // Detect SPI controller first (we need it for FMAP parsing)
    let controller = match spi::detect_and_init() {
        Some(c) => c,
        None => {
            log::warn!("No SPI controller found - variables will not be persistent");
            return Err(VarStoreError::NotInitialized);
        }
    };

    log::info!("Storage backend: {}", controller.name());

    // Create storage backend with default values (will be updated after config detection)
    let mut backend =
        SpiStorageBackend::new(controller, DEFAULT_VARSTORE_BASE, DEFAULT_VARSTORE_SIZE);

    // Try to get persistent config region from multiple sources:
    // 1. Coreboot tables (SMMSTORE v2 record)
    // 2. FMAP in SPI flash
    // 3. Fall back to defaults (DISABLED for safety)
    let config_found =
        configure_from_coreboot_tables(&mut backend) || configure_from_fmap(&mut backend);

    if !config_found {
        // DANGER: Using default base address without verification
        // could overwrite boot code on small flash chips!
        // For safety, we disable persistence if we can't find config info.
        log::warn!(
            "No persistent config region found in coreboot tables or FMAP - persistence DISABLED"
        );
        log::warn!("Variables will be lost on reboot. Add SMMSTORE region to your FMAP.");
        return Err(VarStoreError::NotInitialized);
    }

    // Store the backend in global state
    state::with_mut(|s| {
        s.drivers.storage = Some(backend);
    });

    // Initialize the variable store region
    init_varstore()?;

    // Load existing variables from storage into memory
    load_variables_from_storage()?;

    log::info!("Variable store persistence initialized");
    Ok(())
}

/// Try to configure variable store from coreboot tables (SMMSTORE v2 record)
///
/// Returns true if configuration was found and applied.
fn configure_from_coreboot_tables(backend: &mut SpiStorageBackend) -> bool {
    if let Some(smmstore_info) = coreboot::get_smmstorev2() {
        log::info!(
            "Found SMMSTORE v2 in coreboot tables: {} blocks x {} KB at {:#x}",
            smmstore_info.num_blocks,
            smmstore_info.block_size / 1024,
            smmstore_info.mmap_addr
        );

        // The mmap_addr is the memory-mapped address for read-only access
        // For SPI flash writes, we need to convert to the flash offset
        // Use the BIOS region from IFD to calculate the correct offset
        let base_addr = calculate_spi_offset(smmstore_info.mmap_addr, backend.get_bios_region());
        let size = smmstore_info.num_blocks * smmstore_info.block_size;

        // Update the storage backend with the region location
        backend.set_base_offset(base_addr);
        backend.set_storage_size(size);

        log::info!(
            "Variable store configured: base={:#x}, size={} KB",
            base_addr,
            size / 1024
        );
        return true;
    }

    log::debug!("No SMMSTORE v2 record in coreboot tables");
    false
}

/// Try to configure variable store from FMAP in SPI flash
///
/// This is a fallback when coreboot tables don't provide SMMSTORE v2 info.
/// We read the FMAP structure from flash and look for the SMMSTORE region.
///
/// Returns true if configuration was found and applied.
fn configure_from_fmap(backend: &mut SpiStorageBackend) -> bool {
    use crate::coreboot::fmap;

    log::info!("Looking for variable store region in FMAP...");

    // Read FMAP from flash (uses boot_media_params if available, otherwise probes)
    // Note: fmap::get_smmstore_from_fmap expects an AnySpiController, so we access
    // the underlying controller directly
    if let Some(region_info) = fmap::get_smmstore_from_fmap(backend.controller_mut()) {
        log::info!(
            "Found '{}' in FMAP: offset={:#x}, size={} KB",
            region_info.name.as_str(),
            region_info.offset,
            region_info.size / 1024
        );

        // Update the storage backend with the region location
        backend.set_base_offset(region_info.offset);
        backend.set_storage_size(region_info.size);

        log::info!(
            "Variable store configured: base={:#x}, size={} KB",
            region_info.offset,
            region_info.size / 1024
        );
        return true;
    }

    log::debug!("Variable store region not found in FMAP");
    false
}

/// Calculate SPI flash offset from memory-mapped address
///
/// Coreboot's SMMSTORE v2 provides a memory-mapped address for read-only access.
/// We need to convert this to the SPI flash offset for write operations.
///
/// On x86 systems, the BIOS region of the flash is memory-mapped to end at 4GB
/// (0x100000000). The `bios_region` parameter provides the base and limit of the
/// BIOS region from the Intel Flash Descriptor (IFD), which allows us to calculate
/// the correct offset.
fn calculate_spi_offset(mmap_addr: u64, bios_region: Option<(u32, u32)>) -> u32 {
    // If we have BIOS region info from IFD, use it for accurate calculation
    if let Some((bios_base, bios_limit)) = bios_region {
        let bios_size = (bios_limit - bios_base + 1) as u64;
        // BIOS region is mapped to end at 4GB
        let mmap_base = 0x1_0000_0000u64 - bios_size;

        if mmap_addr >= mmap_base && mmap_addr < 0x1_0000_0000u64 {
            // Calculate offset within BIOS region, then add BIOS base in flash
            let offset_in_bios = (mmap_addr - mmap_base) as u32;
            let flash_offset = bios_base + offset_in_bios;
            log::debug!(
                "SPI offset calculation: mmap_addr={:#x}, bios_base={:#x}, bios_size={:#x}, mmap_base={:#x}, flash_offset={:#x}",
                mmap_addr,
                bios_base,
                bios_size,
                mmap_base,
                flash_offset
            );
            return flash_offset;
        }
    }

    // Fallback: assume the address is in a standard memory-mapped range
    // This is a heuristic based on common flash sizes
    log::warn!("No BIOS region info available, using fallback address calculation");

    if mmap_addr >= 0xFF000000 {
        // Assume 16MB flash mapped at 0xFF000000
        (mmap_addr - 0xFF000000) as u32
    } else if mmap_addr >= 0xFE000000 {
        // Assume 32MB flash mapped at 0xFE000000
        (mmap_addr - 0xFE000000) as u32
    } else if mmap_addr >= 0xFC000000 {
        // Assume 64MB flash mapped at 0xFC000000
        (mmap_addr - 0xFC000000) as u32
    } else if mmap_addr == 0 {
        // No address provided, use default
        DEFAULT_VARSTORE_BASE
    } else {
        // Assume the address is already a flash offset
        mmap_addr as u32
    }
}

/// Initialize the variable store region
///
/// Reads the store header to validate the region, or formats it if invalid.
fn init_varstore() -> Result<(), VarStoreError> {
    // Read the store header (offset 0 within the storage region)
    let mut header_bytes = [0u8; STORE_HEADER_SIZE];
    let storage_size = state::with_storage_mut(|storage| {
        storage
            .read(0, &mut header_bytes)
            .map_err(|_| VarStoreError::SpiError)?;
        Ok::<u32, VarStoreError>(storage.size())
    })
    .ok_or(VarStoreError::NotInitialized)??;

    // Log raw header bytes for debugging
    log::debug!(
        "Variable store header bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
        header_bytes[0],
        header_bytes[1],
        header_bytes[2],
        header_bytes[3],
        header_bytes[4],
        header_bytes[5],
        header_bytes[6],
        header_bytes[7],
        header_bytes[8],
        header_bytes[9],
        header_bytes[10],
        header_bytes[11],
        header_bytes[12],
        header_bytes[13],
        header_bytes[14],
        header_bytes[15]
    );

    // Check if the header is valid
    match postcard::from_bytes::<StoreHeader>(&header_bytes) {
        Ok(header) => {
            log::debug!(
                "Variable store header parsed: magic={:#x}, version={}, size={}",
                header.magic,
                header.version,
                header.store_size
            );
            if header.is_valid() {
                log::info!("Variable store found, size {} KB", header.store_size / 1024);
                // Update storage size if header specifies a different size
                if header.store_size != storage_size {
                    state::with_storage_mut(|storage| {
                        storage.set_storage_size(header.store_size);
                    });
                }
                state::with_varstore_mut(|vs| {
                    vs.initialized = true;
                });
                return Ok(());
            } else {
                log::debug!("Variable store header CRC mismatch or invalid magic");
            }
        }
        Err(e) => {
            log::debug!("Variable store header parse error: {:?}", e);
        }
    }

    // Header invalid or missing - format the store
    log::info!(
        "Formatting variable store (size {} KB)...",
        storage_size / 1024
    );

    // Try to enable writes, erase, and write header
    state::with_storage_mut(|storage| {
        if let Err(e) = storage.enable_writes() {
            log::warn!("Could not enable storage writes: {:?}", e);
            // Continue anyway - the erase/write will fail if truly locked
        }

        // Erase the region
        storage
            .erase(0, storage_size)
            .map_err(|_| VarStoreError::SpiError)?;

        // Write new header
        let header = StoreHeader::new(storage_size);
        let header_bytes = postcard::to_allocvec(&header).map_err(|_| VarStoreError::SerdeError)?;

        storage
            .write(0, &header_bytes)
            .map_err(|_| VarStoreError::SpiError)?;

        Ok::<(), VarStoreError>(())
    })
    .ok_or(VarStoreError::NotInitialized)??;

    state::with_varstore_mut(|vs| {
        vs.initialized = true;
        vs.write_offset = STORE_HEADER_SIZE as u32;
    });

    log::info!("Variable store formatted successfully");
    Ok(())
}

/// Load variables from storage into the in-memory cache
fn load_variables_from_storage() -> Result<(), VarStoreError> {
    if !state::varstore().initialized {
        return Err(VarStoreError::NotInitialized);
    }

    let size =
        state::with_storage_mut(|storage| storage.size()).ok_or(VarStoreError::NotInitialized)?;

    // Scan for variable records
    let mut offset = STORE_HEADER_SIZE as u32;
    let mut records: Vec<VariableRecord> = Vec::new();

    while offset < size {
        // Read a chunk to try deserializing
        // Use MAX_DATA_SIZE from varstore module (4096) not state module's smaller limit
        let remaining = size - offset;
        let chunk_size = core::cmp::min(remaining, super::MAX_DATA_SIZE as u32 + 256);
        let mut chunk = alloc::vec![0u8; chunk_size as usize];

        let read_result = state::with_storage_mut(|storage| storage.read(offset, &mut chunk))
            .ok_or(VarStoreError::NotInitialized)?;

        if read_result.is_err() {
            return Err(VarStoreError::SpiError);
        }

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
    state::with_varstore_mut(|vs| {
        vs.write_offset = offset;
    });

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
                    "Loaded variable: {:?}",
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

    log::info!("Loaded variables from storage");
    Ok(())
}

/// Get the timestamp of a stored variable
///
/// This reads the variable record from storage to retrieve its timestamp.
/// Returns None if the variable doesn't exist or has no timestamp.
pub fn get_variable_timestamp(
    guid: &r_efi::efi::Guid,
    name: &[u16],
) -> Option<super::SerializedTime> {
    let vs = state::varstore();
    if !vs.initialized {
        return None;
    }
    let write_offset = vs.write_offset;

    // Scan for the variable record
    let mut offset = STORE_HEADER_SIZE as u32;
    let mut found_timestamp: Option<super::SerializedTime> = None;

    while offset < write_offset {
        // Use MAX_DATA_SIZE from varstore module (4096) not state module's smaller limit
        let remaining = write_offset - offset;
        let chunk_size = core::cmp::min(remaining, super::MAX_DATA_SIZE as u32 + 256);
        let mut chunk = alloc::vec![0u8; chunk_size as usize];

        let read_result = state::with_storage_mut(|storage| storage.read(offset, &mut chunk));

        if read_result.is_none() || read_result.unwrap().is_err() {
            break;
        }

        if chunk[0] == 0xFF {
            break;
        }

        match VariableRecord::deserialize(&chunk) {
            Ok(record) => {
                let record_size = match record.serialize() {
                    Ok(bytes) => bytes.len() as u32,
                    Err(_) => break,
                };

                if record.is_active() && record.matches(guid, name) {
                    found_timestamp = Some(*record.get_timestamp());
                }

                offset += record_size;
            }
            Err(_) => break,
        }
    }

    found_timestamp
}

/// Persist a variable to storage
///
/// Before ExitBootServices: writes to storage directly
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
        // Before ExitBootServices - write to storage
        write_variable_to_storage_internal(guid, name, attributes, data)
    }
}

/// Persist a variable to storage with a specific timestamp
///
/// This version preserves the authenticated variable timestamp for proper
/// monotonic timestamp validation on subsequent updates.
///
/// Before ExitBootServices: writes to storage directly
/// After ExitBootServices: queues write for deferred processing on next boot
pub fn persist_variable_with_timestamp(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
    timestamp: super::SerializedTime,
) -> Result<(), VarStoreError> {
    if state::is_exit_boot_services_called() {
        // After ExitBootServices - queue for deferred processing
        // Note: deferred processing currently doesn't preserve timestamps,
        // but that's acceptable since authenticated variables shouldn't be
        // modified at runtime anyway
        queue_variable_for_deferred(guid, name, attributes, data)
    } else {
        // Before ExitBootServices - write to storage with timestamp
        write_variable_with_timestamp_internal(guid, name, attributes, data, timestamp)
    }
}

/// Delete a variable from storage
pub fn delete_variable(guid: &r_efi::efi::Guid, name: &[u16]) -> Result<(), VarStoreError> {
    if state::is_exit_boot_services_called() {
        // After ExitBootServices - queue deletion for deferred processing
        queue_variable_deletion_for_deferred(guid, name)
    } else {
        // Before ExitBootServices - mark deleted in storage
        write_variable_deletion_internal(guid, name)
    }
}

/// Write a variable record to storage
///
/// This is the internal function that actually writes to storage.
/// It's exposed to the deferred module for applying queued changes.
///
/// If the store is full, this function will attempt compaction first.
pub(super) fn write_variable_to_storage_internal(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Result<(), VarStoreError> {
    // Create the variable record first
    let record = VariableRecord::new(guid, name, attributes, data)?;
    let record_bytes = record.serialize()?;
    let record_len = record_bytes.len() as u32;

    // Check if we need compaction
    let vs = state::varstore();
    let storage_size =
        state::with_storage_mut(|s| s.size()).ok_or(VarStoreError::NotInitialized)?;

    if vs.initialized && vs.write_offset + record_len > storage_size {
        log::info!("Variable store full, triggering compaction");
        compact_varstore()?;
    }

    // Get current state again after potential compaction
    let vs = state::varstore();
    if !vs.initialized {
        return Err(VarStoreError::NotInitialized);
    }

    // Check again after compaction
    if vs.write_offset + record_len > storage_size {
        log::error!("Variable store still full after compaction");
        return Err(VarStoreError::StoreFull);
    }

    let write_offset = vs.write_offset;

    // Do the actual write
    state::with_storage_mut(|storage| {
        // Try to enable writes
        if let Err(e) = storage.enable_writes() {
            log::warn!("Could not enable storage writes: {:?}", e);
        }

        // Write the record
        storage
            .write(write_offset, &record_bytes)
            .map_err(|_| VarStoreError::SpiError)?;

        Ok::<(), VarStoreError>(())
    })
    .ok_or(VarStoreError::NotInitialized)??;

    // Update write offset
    state::with_varstore_mut(|vs| {
        vs.write_offset += record_len;
    });

    log::debug!("Variable persisted at offset {:#x}", write_offset);

    Ok(())
}

/// Write a variable record to storage with a specific timestamp
///
/// This is used for authenticated variables where the timestamp must be preserved
/// for proper monotonic timestamp validation on future updates.
pub(super) fn write_variable_with_timestamp_internal(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
    timestamp: super::SerializedTime,
) -> Result<(), VarStoreError> {
    // Create the variable record with timestamp first
    let record = VariableRecord::new_with_timestamp(guid, name, attributes, data, timestamp)?;
    let record_bytes = record.serialize()?;
    let record_len = record_bytes.len() as u32;

    // Check if we need compaction
    let vs = state::varstore();
    let storage_size =
        state::with_storage_mut(|s| s.size()).ok_or(VarStoreError::NotInitialized)?;

    if vs.initialized && vs.write_offset + record_len > storage_size {
        log::info!("Variable store full, triggering compaction");
        compact_varstore()?;
    }

    // Get current state again after potential compaction
    let vs = state::varstore();
    if !vs.initialized {
        return Err(VarStoreError::NotInitialized);
    }

    // Check again after compaction
    if vs.write_offset + record_len > storage_size {
        log::error!("Variable store still full after compaction");
        return Err(VarStoreError::StoreFull);
    }

    let write_offset = vs.write_offset;

    // Do the actual write
    state::with_storage_mut(|storage| {
        // Try to enable writes
        if let Err(e) = storage.enable_writes() {
            log::warn!("Could not enable storage writes: {:?}", e);
        }

        // Write the record
        storage
            .write(write_offset, &record_bytes)
            .map_err(|_| VarStoreError::SpiError)?;

        Ok::<(), VarStoreError>(())
    })
    .ok_or(VarStoreError::NotInitialized)??;

    // Update write offset
    state::with_varstore_mut(|vs| {
        vs.write_offset += record_len;
    });

    log::debug!(
        "Variable (with timestamp) persisted at offset {:#x}",
        write_offset
    );

    Ok(())
}

/// Write a deletion record to storage
///
/// This is the internal function that actually writes the deletion.
/// It's exposed to the deferred module for applying queued changes.
///
/// If the store is full, this function will attempt compaction first.
pub(super) fn write_variable_deletion_internal(
    guid: &r_efi::efi::Guid,
    name: &[u16],
) -> Result<(), VarStoreError> {
    // Create a deletion record first
    let record = VariableRecord::new_deleted(guid, name)?;
    let record_bytes = record.serialize()?;
    let record_len = record_bytes.len() as u32;

    // Check if we need compaction
    let vs = state::varstore();
    let storage_size =
        state::with_storage_mut(|s| s.size()).ok_or(VarStoreError::NotInitialized)?;

    if vs.initialized && vs.write_offset + record_len > storage_size {
        log::info!("Variable store full, triggering compaction for deletion");
        compact_varstore()?;
    }

    // Get current state again after potential compaction
    let vs = state::varstore();
    if !vs.initialized {
        return Err(VarStoreError::NotInitialized);
    }

    // Check again after compaction
    if vs.write_offset + record_len > storage_size {
        log::error!("Variable store still full after compaction");
        return Err(VarStoreError::StoreFull);
    }

    let write_offset = vs.write_offset;

    // Do the actual write
    state::with_storage_mut(|storage| {
        // Try to enable writes
        if let Err(e) = storage.enable_writes() {
            log::warn!("Could not enable storage writes: {:?}", e);
        }

        // Write the record
        storage
            .write(write_offset, &record_bytes)
            .map_err(|_| VarStoreError::SpiError)?;

        Ok::<(), VarStoreError>(())
    })
    .ok_or(VarStoreError::NotInitialized)??;

    // Update write offset
    state::with_varstore_mut(|vs| {
        vs.write_offset += record_len;
    });

    log::debug!("Variable deletion persisted");

    Ok(())
}

/// Queue a variable write for deferred processing (after ExitBootServices)
///
/// When storage is locked, variable changes are stored in a reserved memory
/// region that survives warm reboot. On next boot, these changes are
/// applied to storage.
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

/// Check if storage backend is available
pub fn is_storage_available() -> bool {
    state::with_storage_mut(|_| ()).is_some()
}

/// Check if variable store is initialized
pub fn is_varstore_initialized() -> bool {
    state::varstore().initialized
}

/// Get variable store statistics
///
/// Returns (base_offset, size, write_offset)
pub fn get_varstore_stats() -> Option<(u32, u32, u32)> {
    let vs = state::varstore();
    let (base, size) = state::with_storage_mut(|s| (s.base_offset(), s.size()))?;
    Some((base, size, vs.write_offset))
}

/// Compact the variable store by rewriting only active variables
///
/// This is called when the store is full. It:
/// 1. Reads all active variables from storage into memory
/// 2. Erases the entire region
/// 3. Writes a fresh header
/// 4. Rewrites all active variables
///
/// Returns the number of bytes reclaimed.
pub fn compact_varstore() -> Result<u32, VarStoreError> {
    log::info!("Compacting variable store...");

    let vs = state::varstore();
    if !vs.initialized {
        return Err(VarStoreError::NotInitialized);
    }

    let old_write_offset = vs.write_offset;
    let size = state::with_storage_mut(|s| s.size()).ok_or(VarStoreError::NotInitialized)?;

    // Step 1: Collect all active variable records
    let mut active_records: Vec<VariableRecord> = Vec::new();
    let mut offset = STORE_HEADER_SIZE as u32;

    while offset < size {
        let remaining = size - offset;
        let chunk_size = core::cmp::min(remaining, super::MAX_DATA_SIZE as u32 + 256);
        let mut chunk = alloc::vec![0u8; chunk_size as usize];

        let read_result = state::with_storage_mut(|storage| storage.read(offset, &mut chunk))
            .ok_or(VarStoreError::NotInitialized)?;

        if read_result.is_err() {
            return Err(VarStoreError::SpiError);
        }

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

    // Step 2: Enable writes and erase the region
    state::with_storage_mut(|storage| {
        if let Err(e) = storage.enable_writes() {
            log::warn!("Could not enable storage writes for compaction: {:?}", e);
        }

        storage
            .erase(0, size)
            .map_err(|_| VarStoreError::SpiError)?;

        // Step 3: Write fresh header
        let header = StoreHeader::new(size);
        let header_bytes = postcard::to_allocvec(&header).map_err(|_| VarStoreError::SerdeError)?;

        storage
            .write(0, &header_bytes)
            .map_err(|_| VarStoreError::SpiError)?;

        Ok::<(), VarStoreError>(())
    })
    .ok_or(VarStoreError::NotInitialized)??;

    // Step 4: Rewrite all active variables
    let mut new_offset = STORE_HEADER_SIZE as u32;

    for record in active_records {
        let record_bytes = record.serialize()?;

        if new_offset + record_bytes.len() as u32 > size {
            log::error!("Variable store full even after compaction - data loss!");
            state::with_varstore_mut(|vs| vs.write_offset = new_offset);
            return Err(VarStoreError::StoreFull);
        }

        state::with_storage_mut(|storage| {
            storage
                .write(new_offset, &record_bytes)
                .map_err(|_| VarStoreError::SpiError)
        })
        .ok_or(VarStoreError::NotInitialized)??;

        new_offset += record_bytes.len() as u32;
    }

    // Update write offset
    state::with_varstore_mut(|vs| {
        vs.write_offset = new_offset;
    });

    let reclaimed = old_write_offset - new_offset;
    log::info!(
        "Variable store compaction complete: reclaimed {} bytes, new write offset {:#x}",
        reclaimed,
        new_offset
    );

    Ok(reclaimed)
}

/// Update a variable in the in-memory cache
///
/// This is used when applying deferred variable changes on boot,
/// or when directly updating a variable without going through SetVariable.
pub fn update_variable_in_memory(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) {
    use crate::state::{self, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN};

    state::with_efi_mut(|efi| {
        // Find existing or free slot
        let existing_idx = efi.variables.iter().position(|var| {
            var.in_use && var.vendor_guid == *guid && crate::efi::utils::ucs2_eq(&var.name, name)
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
        if let Some(var) = efi.variables.iter_mut().find(|var| {
            var.in_use && var.vendor_guid == *guid && crate::efi::utils::ucs2_eq(&var.name, name)
        }) {
            var.in_use = false;
        }
    });
}

// name_eq_slice consolidated into crate::efi::utils::ucs2_eq
