//! Variable Store Persistence Layer
//!
//! This module handles persisting UEFI variables to storage (SPI flash, etc.)
//! and ESP files. It bridges the in-memory variable storage in
//! `state::EfiState::variables` with persistent storage.
//!
//! # Storage Format
//!
//! Variables are stored in EDK2-compatible Firmware Volume (FV) format,
//! matching what coreboot's `get_uint_option()` and `set_uint_option()` expect.
//! This replaces the previous CRAB/postcard format which was incompatible
//! with coreboot's SMMSTORE reader.
//!
//! # Storage Strategy
//!
//! - **Before ExitBootServices**: Variables are written to storage (SPI flash)
//! - **After ExitBootServices**: Storage may be locked; variables are queued for ESP file
//! - **On Reset**: ESP file is read, authenticated, applied to storage, then deleted
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

use super::edk2;
use super::storage::{SpiStorageBackend, StorageBackend};
use super::VarStoreError;

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
/// Reads the FV header to validate the region, or formats it if invalid.
/// This uses EDK2 Firmware Volume format compatible with coreboot's SMMSTORE.
fn init_varstore() -> Result<(), VarStoreError> {
    // Read enough bytes for FV header + VS header
    let header_size = edk2::FV_HEADER_LENGTH + edk2::VS_HEADER_LENGTH;
    let mut header_bytes = [0u8; 128]; // Enough for FV + VS headers (100 bytes needed)
    let storage_size = state::with_storage_mut(|storage| {
        storage
            .read(0, &mut header_bytes[..header_size])
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

    // Validate EDK2 FV header
    let validation = edk2::validate_fv(&header_bytes[..header_size], storage_size);

    if validation.valid {
        log::info!(
            "EDK2 FV found: auth_format={}, data_size={} KB",
            validation.auth_format,
            validation.data_size / 1024
        );

        // Store format info in varstore state
        state::with_varstore_mut(|vs| {
            vs.initialized = true;
            vs.auth_format = validation.auth_format;
            vs.data_size = validation.data_size;
        });

        // Find the write offset (first free byte)
        let auth_format = validation.auth_format;
        let data_size = validation.data_size;
        let write_offset = state::with_storage_mut(|storage| {
            let mut read_fn =
                |offset: u32, buf: &mut [u8]| -> bool { storage.read(offset, buf).is_ok() };
            edk2::find_write_offset(&mut read_fn, auth_format, data_size)
        })
        .ok_or(VarStoreError::NotInitialized)?;

        state::with_varstore_mut(|vs| {
            vs.write_offset = write_offset;
        });

        log::info!("Variable store write offset: {:#x}", write_offset);
        return Ok(());
    }

    // FV header invalid or missing - format the store with EDK2 FV headers
    log::info!(
        "Formatting variable store as EDK2 FV (size {} KB)...",
        storage_size / 1024
    );

    // Build EDK2 FV + VS headers
    let fv_headers = edk2::build_fv_headers(storage_size);

    // Try to enable writes, erase, and write headers
    state::with_storage_mut(|storage| {
        if let Err(e) = storage.enable_writes() {
            log::warn!("Could not enable storage writes: {:?}", e);
            // Continue anyway - the erase/write will fail if truly locked
        }

        // Erase the region
        storage
            .erase(0, storage_size)
            .map_err(|_| VarStoreError::SpiError)?;

        // Write new FV + VS headers
        storage
            .write(0, &fv_headers)
            .map_err(|_| VarStoreError::SpiError)?;

        Ok::<(), VarStoreError>(())
    })
    .ok_or(VarStoreError::NotInitialized)??;

    // Non-auth format (we always create non-auth stores)
    let data_size = storage_size - edk2::FV_HEADER_LENGTH as u32 - edk2::VS_HEADER_LENGTH as u32;

    state::with_varstore_mut(|vs| {
        vs.initialized = true;
        vs.auth_format = false;
        vs.data_size = data_size;
        vs.write_offset = edk2::VARIABLE_DATA_OFFSET;
    });

    log::info!("Variable store formatted as EDK2 FV successfully");
    Ok(())
}

/// Load variables from storage into the in-memory cache
fn load_variables_from_storage() -> Result<(), VarStoreError> {
    let vs = state::varstore();
    if !vs.initialized {
        return Err(VarStoreError::NotInitialized);
    }
    let auth_format = vs.auth_format;
    let data_size = vs.data_size;

    // Walk all variable records in the FV
    let vars = state::with_storage_mut(|storage| {
        let mut read_fn =
            |offset: u32, buf: &mut [u8]| -> bool { storage.read(offset, buf).is_ok() };
        edk2::walk_variables(&mut read_fn, auth_format, data_size)
    })
    .ok_or(VarStoreError::NotInitialized)?;

    // Filter to only VAR_ADDED records and deduplicate (keep latest)
    // Build a list of active variables
    let mut active_vars: Vec<&edk2::FvVariable> = Vec::new();
    for var in &vars {
        if !edk2::is_var_added(var.state) {
            continue;
        }
        // Remove any existing entry with same GUID + name
        active_vars.retain(|existing| {
            !(existing.guid == var.guid && edk2::name_matches(&existing.name, &var.name))
        });
        active_vars.push(var);
    }

    // Load active variables into in-memory cache
    state::with_efi_mut(|efi| {
        for var in &active_vars {
            // Find a free slot
            if let Some(slot) = efi.variables.iter_mut().find(|v| !v.in_use) {
                // Copy name (UTF-16, strip trailing null for the fixed-size buffer)
                let name_len = var.name.len().min(MAX_VARIABLE_NAME_LEN);
                slot.name[..name_len].copy_from_slice(&var.name[..name_len]);
                if name_len < MAX_VARIABLE_NAME_LEN {
                    slot.name[name_len..].fill(0);
                }

                // Convert GUID bytes to r_efi::efi::Guid
                slot.vendor_guid = guid_bytes_to_efi(&var.guid);
                slot.attributes = var.attributes;

                let data_len = var.data.len().min(MAX_VARIABLE_DATA_SIZE);
                slot.data[..data_len].copy_from_slice(&var.data[..data_len]);
                slot.data_size = data_len;
                slot.in_use = true;

                // Log the loaded variable name
                let name_str: Vec<u8> = var
                    .name
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8)
                    .collect();
                log::debug!("Loaded variable: {:?}", core::str::from_utf8(&name_str));
            } else {
                log::warn!("No free variable slots - some variables may be lost");
                break;
            }
        }
    });

    log::info!("Loaded {} variables from storage", active_vars.len());
    Ok(())
}

/// Get the timestamp of a stored variable
///
/// EDK2 non-auth format does not store timestamps. Auth format embeds them
/// in the header, but we don't currently parse them during walk.
/// Returns None for all records in the current implementation.
pub fn get_variable_timestamp(
    _guid: &r_efi::efi::Guid,
    _name: &[u16],
) -> Option<super::SerializedTime> {
    // EDK2 non-auth format has no timestamps.
    // Auth format timestamps could be extracted but we currently write non-auth.
    None
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
/// Note: In EDK2 non-auth format (which we write), timestamps are not stored
/// on disk. The timestamp is only preserved in the deferred write path.
///
/// Before ExitBootServices: writes to storage directly
/// After ExitBootServices: queues write for deferred processing on next boot
pub fn persist_variable_with_timestamp(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
    _timestamp: super::SerializedTime,
) -> Result<(), VarStoreError> {
    if state::is_exit_boot_services_called() {
        // After ExitBootServices - queue for deferred processing
        queue_variable_for_deferred(guid, name, attributes, data)
    } else {
        // Before ExitBootServices - write to storage
        // Note: non-auth EDK2 format doesn't store timestamps on disk
        write_variable_to_storage_internal(guid, name, attributes, data)
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

/// Write a variable to storage using EDK2 FV format
///
/// This is the internal function that actually writes to storage.
/// It's exposed to the deferred module for applying queued changes.
///
/// Steps:
/// 1. Walk existing records to find and delete any old version
/// 2. Append new record at write_offset using multi-stage protocol
/// 3. If store is full, compact and retry
pub(super) fn write_variable_to_storage_internal(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Result<(), VarStoreError> {
    let vs = state::varstore();
    if !vs.initialized {
        return Err(VarStoreError::NotInitialized);
    }

    let guid_bytes = edk2::guid_to_bytes(guid);

    // First, mark any existing record with same GUID+name as deleted
    delete_existing_record(&guid_bytes, name)?;

    // Check if we have space for the new record
    let record = edk2::build_variable_record(&guid_bytes, name, attributes, data);
    let record_len = record.len() as u32;

    let vs = state::varstore();
    let storage_size =
        state::with_storage_mut(|s| s.size()).ok_or(VarStoreError::NotInitialized)?;

    if vs.write_offset + record_len > storage_size {
        log::info!("Variable store full, triggering compaction");
        compact_varstore()?;
    }

    let vs = state::varstore();
    if vs.write_offset + record_len > storage_size {
        log::error!("Variable store still full after compaction");
        return Err(VarStoreError::StoreFull);
    }

    let write_offset = vs.write_offset;

    // Write the new record using multi-stage protocol
    let new_offset = state::with_storage_mut(|storage| {
        if let Err(e) = storage.enable_writes() {
            log::warn!("Could not enable storage writes: {:?}", e);
        }
        let mut write_fn =
            |offset: u32, data: &[u8]| -> bool { storage.write(offset, data).is_ok() };
        edk2::write_variable(
            &mut write_fn,
            write_offset,
            &guid_bytes,
            name,
            attributes,
            data,
        )
    })
    .ok_or(VarStoreError::NotInitialized)?
    .ok_or(VarStoreError::SpiError)?;

    state::with_varstore_mut(|vs| {
        vs.write_offset = new_offset;
    });

    log::debug!("Variable persisted at offset {:#x}", write_offset);
    Ok(())
}

/// Delete a variable from storage by marking its record as deleted
///
/// This is the internal function that actually writes the deletion.
/// It's exposed to the deferred module for applying queued changes.
pub(super) fn write_variable_deletion_internal(
    guid: &r_efi::efi::Guid,
    name: &[u16],
) -> Result<(), VarStoreError> {
    let vs = state::varstore();
    if !vs.initialized {
        return Err(VarStoreError::NotInitialized);
    }

    let guid_bytes = edk2::guid_to_bytes(guid);
    delete_existing_record(&guid_bytes, name)
}

/// Find and mark as deleted any existing record with the given GUID+name
fn delete_existing_record(guid_bytes: &[u8; 16], name: &[u16]) -> Result<(), VarStoreError> {
    let vs = state::varstore();
    let auth_format = vs.auth_format;
    let data_size = vs.data_size;

    // Walk all records to find matching ones
    let vars = state::with_storage_mut(|storage| {
        let mut read_fn =
            |offset: u32, buf: &mut [u8]| -> bool { storage.read(offset, buf).is_ok() };
        edk2::walk_variables(&mut read_fn, auth_format, data_size)
    })
    .ok_or(VarStoreError::NotInitialized)?;

    // Find and delete matching VAR_ADDED records
    for var in &vars {
        if edk2::is_var_added(var.state)
            && var.guid == *guid_bytes
            && edk2::name_matches(&var.name, name)
        {
            // Mark as deleted by writing to the state byte
            let deleted = state::with_storage_mut(|storage| {
                if let Err(e) = storage.enable_writes() {
                    log::warn!("Could not enable storage writes: {:?}", e);
                }
                let mut write_fn =
                    |offset: u32, data: &[u8]| -> bool { storage.write(offset, data).is_ok() };
                edk2::mark_deleted(&mut write_fn, var.state_offset)
            })
            .ok_or(VarStoreError::NotInitialized)?;

            if !deleted {
                log::warn!(
                    "Failed to mark variable as deleted at state_offset {:#x}",
                    var.state_offset
                );
                return Err(VarStoreError::SpiError);
            }

            log::debug!(
                "Marked existing variable as deleted at state_offset {:#x}",
                var.state_offset
            );
        }
    }

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
/// 3. Writes fresh EDK2 FV + VS headers
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
    let auth_format = vs.auth_format;
    let data_size = vs.data_size;
    let size = state::with_storage_mut(|s| s.size()).ok_or(VarStoreError::NotInitialized)?;

    // Step 1: Collect all active variable records
    let vars = state::with_storage_mut(|storage| {
        let mut read_fn =
            |offset: u32, buf: &mut [u8]| -> bool { storage.read(offset, buf).is_ok() };
        edk2::walk_variables(&mut read_fn, auth_format, data_size)
    })
    .ok_or(VarStoreError::NotInitialized)?;

    // Keep only VAR_ADDED records, deduplicated (latest wins)
    let mut active_vars: Vec<edk2::FvVariable> = Vec::new();
    for var in vars {
        if !edk2::is_var_added(var.state) {
            continue;
        }
        active_vars.retain(|existing| {
            !(existing.guid == var.guid && edk2::name_matches(&existing.name, &var.name))
        });
        active_vars.push(var);
    }

    log::info!(
        "Found {} active variables to preserve during compaction",
        active_vars.len()
    );

    // Step 2: Enable writes and erase the region
    // Step 3: Write fresh EDK2 FV + VS headers
    let fv_headers = edk2::build_fv_headers(size);

    state::with_storage_mut(|storage| {
        if let Err(e) = storage.enable_writes() {
            log::warn!("Could not enable storage writes for compaction: {:?}", e);
        }

        storage
            .erase(0, size)
            .map_err(|_| VarStoreError::SpiError)?;

        storage
            .write(0, &fv_headers)
            .map_err(|_| VarStoreError::SpiError)?;

        Ok::<(), VarStoreError>(())
    })
    .ok_or(VarStoreError::NotInitialized)??;

    // Step 4: Rewrite all active variables
    let mut new_offset = edk2::VARIABLE_DATA_OFFSET;

    for var in &active_vars {
        // Check if we have space
        let record = edk2::build_variable_record(&var.guid, &var.name, var.attributes, &var.data);
        if new_offset + record.len() as u32 > size {
            log::error!("Variable store full even after compaction - data loss!");
            state::with_varstore_mut(|vs| vs.write_offset = new_offset);
            return Err(VarStoreError::StoreFull);
        }

        let result = state::with_storage_mut(|storage| {
            let mut write_fn =
                |offset: u32, data: &[u8]| -> bool { storage.write(offset, data).is_ok() };
            edk2::write_variable(
                &mut write_fn,
                new_offset,
                &var.guid,
                &var.name,
                var.attributes,
                &var.data,
            )
        })
        .ok_or(VarStoreError::NotInitialized)?;

        match result {
            Some(next_offset) => {
                new_offset = next_offset;
            }
            None => {
                log::error!("Failed to write variable during compaction");
                return Err(VarStoreError::SpiError);
            }
        }
    }

    // Update varstore state (non-auth format since we wrote fresh headers)
    let new_data_size = size - edk2::FV_HEADER_LENGTH as u32 - edk2::VS_HEADER_LENGTH as u32;
    state::with_varstore_mut(|vs| {
        vs.write_offset = new_offset;
        vs.auth_format = false;
        vs.data_size = new_data_size;
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

// ============================================================================
// Helper functions
// ============================================================================

/// Convert 16-byte on-disk GUID to r_efi::efi::Guid
fn guid_bytes_to_efi(bytes: &[u8; 16]) -> r_efi::efi::Guid {
    r_efi::efi::Guid::from_fields(
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        bytes[8],
        bytes[9],
        &[
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ],
    )
}

// name_eq_slice consolidated into crate::efi::utils::ucs2_eq
