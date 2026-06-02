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
//! The location of the variable store region is determined by a
//! platform-provided [`crate::platform::VariableStoreLocator`]. This keeps
//! coreboot-specific concepts such as SMMSTORE table records and FMAP out of
//! the library persistence path.

use alloc::vec::Vec;

use crate::drivers::spi::{self, SpiController};
use crate::platform::{
    FirmwareStorage, FirmwareStorageRegion, StorageBackend, VarBackendError, VariableStoreLocator,
};
use crate::state::{self, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN};

use super::edk2;
use super::storage::SpiStorageBackend;
use super::{Edk2Store, VarStoreError};

/// Default variable store base address in SPI flash
/// This is typically at the end of the flash region
/// Used only as fallback if coreboot tables don't provide config info
pub const DEFAULT_VARSTORE_BASE: u32 = 0x00F00000; // 15MB offset (for 16MB flash)

/// Default variable store size (256KB)
/// Used only as fallback if coreboot tables don't provide config info
pub const DEFAULT_VARSTORE_SIZE: u32 = 256 * 1024;

fn map_backend_error(error: VarBackendError) -> VarStoreError {
    match error {
        VarBackendError::NotAvailable => VarStoreError::NotInitialized,
        VarBackendError::StoreFull => VarStoreError::StoreFull,
        VarBackendError::IoError => VarStoreError::SpiError,
        VarBackendError::Locked => VarStoreError::Locked,
        VarBackendError::NotFound => VarStoreError::NotFound,
        VarBackendError::DataTooLarge => VarStoreError::DataTooLarge,
        VarBackendError::NameTooLong => VarStoreError::NameTooLong,
        VarBackendError::Other => VarStoreError::InvalidArgument,
    }
}

fn with_edk2_store_mut<R>(
    f: impl FnOnce(&mut Edk2Store<'_>) -> Result<R, VarBackendError>,
) -> Result<R, VarStoreError> {
    state::with_mut(|state| {
        let storage = state
            .drivers
            .platform
            .storage
            .as_mut()
            .ok_or(VarBackendError::NotAvailable)?;
        let mut store = Edk2Store::new(storage, &mut state.efi.varstore);
        f(&mut store)
    })
    .map_err(map_backend_error)
}

/// Initialize the variable store persistence layer
///
/// This should be called early in boot to:
/// 1. Return immediately if the platform did not provide a variable-store locator
/// 2. Detect and initialize the storage backend (SPI controller)
/// 3. Ask the platform locator for the persistent variable-store region
/// 4. Read existing variables from storage
/// 5. Load them into the in-memory variable cache
pub fn init(locator: Option<&dyn VariableStoreLocator>) -> Result<(), VarStoreError> {
    log::info!("Initializing variable store persistence...");

    let Some(locator) = locator else {
        log::warn!("No variable-store locator provided - persistence DISABLED");
        log::warn!("Variables will be lost on reboot");
        return Err(VarStoreError::NotInitialized);
    };

    // Detect SPI controller after confirming the platform wants direct-flash
    // variable persistence.  Library integrations without a locator should not
    // probe platform-specific SPI hardware as a side effect.
    let controller = match spi::detect_and_init() {
        Some(c) => c,
        None => {
            log::warn!("No SPI controller found - variables will not be persistent");
            return Err(VarStoreError::NotInitialized);
        }
    };

    log::info!("Storage backend: {}", SpiController::name(&controller));

    // Create storage backend with default values (will be updated after config detection)
    let mut backend =
        SpiStorageBackend::new(controller, DEFAULT_VARSTORE_BASE, DEFAULT_VARSTORE_SIZE);

    // Ask the platform to locate the persistent variable store.  We keep the
    // default offset/size disabled unless the platform explicitly identifies a
    // safe region; using a guessed address could overwrite boot code on small
    // flash devices.
    configure_from_locator(&mut backend, locator)?;

    // Store the backend in global state
    state::with_mut(|s| {
        s.drivers.platform.storage = Some(backend);
    });

    // Initialize the variable store region
    init_varstore()?;

    // Load existing variables from storage into memory
    load_variables_from_storage()?;

    log::info!("Variable store persistence initialized");
    Ok(())
}

/// Configure the variable store from the platform-provided locator.
fn configure_from_locator(
    backend: &mut SpiStorageBackend,
    locator: &dyn VariableStoreLocator,
) -> Result<(), VarStoreError> {
    let located = locator
        .locate_variable_store(backend.controller_mut())
        .ok_or(VarStoreError::NotInitialized)?;
    let region = backend
        .controller()
        .resolve_location(located.location)
        .ok_or(VarStoreError::NotInitialized)?;
    let region = validate_variable_store_region(region, backend.controller().capacity())?;

    backend.set_base_offset(region.offset as u32);
    backend.set_storage_size(region.size as u32);

    log::info!(
        "Variable store configured from platform locator: '{}' base={:#x}, size={} KB",
        located.name.as_str(),
        region.offset,
        region.size / 1024
    );

    Ok(())
}

/// Validate and narrow a located variable-store region for the current storage backend.
fn validate_variable_store_region(
    region: FirmwareStorageRegion,
    storage_capacity: Option<u64>,
) -> Result<FirmwareStorageRegion, VarStoreError> {
    let header_size = (edk2::FV_HEADER_LENGTH + edk2::VS_HEADER_LENGTH) as u64;
    if region.size < header_size {
        log::warn!(
            "Ignoring variable-store region smaller than FV headers: offset={:#x}, size={:#x}",
            region.offset,
            region.size
        );
        return Err(VarStoreError::NotInitialized);
    }

    if region.offset > u32::MAX as u64 || region.size > u32::MAX as u64 {
        log::warn!(
            "Ignoring variable-store region outside 32-bit storage backend limits: offset={:#x}, size={:#x}",
            region.offset,
            region.size
        );
        return Err(VarStoreError::NotInitialized);
    }

    let Some(end) = region.offset.checked_add(region.size) else {
        log::warn!(
            "Ignoring overflowing variable-store region: offset={:#x}, size={:#x}",
            region.offset,
            region.size
        );
        return Err(VarStoreError::NotInitialized);
    };

    if end > u32::MAX as u64 + 1 {
        log::warn!(
            "Ignoring variable-store region past 32-bit storage backend limits: offset={:#x}, size={:#x}",
            region.offset,
            region.size
        );
        return Err(VarStoreError::NotInitialized);
    }

    if let Some(capacity) = storage_capacity
        && end > capacity
    {
        log::warn!(
            "Ignoring variable-store region outside firmware storage capacity: offset={:#x}, size={:#x}, capacity={:#x}",
            region.offset,
            region.size,
            capacity
        );
        return Err(VarStoreError::NotInitialized);
    }

    Ok(region)
}

/// Initialize the variable store region
///
/// Reads the FV header to validate the region, or formats it if invalid.
/// This uses EDK2 Firmware Volume format compatible with coreboot's SMMSTORE.
fn init_varstore() -> Result<(), VarStoreError> {
    with_edk2_store_mut(|store| store.ensure_initialized())
}

/// Load variables from storage into the in-memory cache
fn load_variables_from_storage() -> Result<(), VarStoreError> {
    struct CacheVisitor<'a> {
        variables: &'a mut [crate::state::VariableEntry],
        count: usize,
        full: bool,
    }

    impl crate::platform::VariableVisitor for CacheVisitor<'_> {
        fn visit(&mut self, name: &[u16], vendor: &r_efi::efi::Guid, attributes: u32, data: &[u8]) {
            let Some(slot) = self.variables.iter_mut().find(|v| !v.in_use) else {
                self.full = true;
                return;
            };

            let name_len = name.len().min(MAX_VARIABLE_NAME_LEN);
            slot.name[..name_len].copy_from_slice(&name[..name_len]);
            if name_len < MAX_VARIABLE_NAME_LEN {
                slot.name[name_len..].fill(0);
            }

            slot.vendor_guid = *vendor;
            slot.attributes = attributes;

            let data_len = data.len().min(MAX_VARIABLE_DATA_SIZE);
            slot.data[..data_len].copy_from_slice(&data[..data_len]);
            slot.data_size = data_len;
            slot.in_use = true;
            self.count += 1;

            let name_str: Vec<u8> = name.iter().map(|&c| c as u8).collect();
            log::debug!("Loaded variable: {:?}", core::str::from_utf8(&name_str));
        }
    }

    let (loaded, full) = state::with_mut(|state| {
        let storage = state
            .drivers
            .platform
            .storage
            .as_mut()
            .ok_or(VarBackendError::NotAvailable)?;
        let efi = &mut state.efi;
        let mut store = Edk2Store::new(storage, &mut efi.varstore);
        let mut visitor = CacheVisitor {
            variables: &mut efi.variables,
            count: 0,
            full: false,
        };
        store.load(&mut visitor)?;
        Ok::<(usize, bool), VarBackendError>((visitor.count, visitor.full))
    })
    .map_err(map_backend_error)?;

    if full {
        log::warn!("No free variable slots - some variables may be lost");
    }
    log::info!("Loaded {} variables from storage", loaded);
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
/// Delegates to the shared EDK2 store implementation, which preflights
/// compaction before modifying flash and appends replacements before deleting
/// old records.
pub(super) fn write_variable_to_storage_internal(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Result<(), VarStoreError> {
    with_edk2_store_mut(|store| store.write(name, guid, attributes, data))
}

/// Delete a variable from storage by marking its record as deleted
///
/// This is the internal function that actually writes the deletion.
/// It's exposed to the deferred module for applying queued changes.
pub(super) fn write_variable_deletion_internal(
    guid: &r_efi::efi::Guid,
    name: &[u16],
) -> Result<(), VarStoreError> {
    match with_edk2_store_mut(|store| store.delete(name, guid)) {
        Ok(()) | Err(VarStoreError::NotFound) => Ok(()),
        Err(e) => Err(e),
    }
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
    let reclaimed = with_edk2_store_mut(|store| store.compact())?;
    log::info!(
        "Variable store compaction complete: reclaimed {} bytes",
        reclaimed
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

// name_eq_slice consolidated into crate::efi::utils::ucs2_eq
