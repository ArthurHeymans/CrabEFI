//! Variable Store Persistence Layer
//!
//! This module bridges CrabEFI's in-memory EFI variable cache with a
//! platform-provided [`crate::platform::VariableBackend`].  The core library
//! never probes chipset flash, coreboot tables, FMAP, SMMSTORE, TF-A, or SMM
//! services directly; those details belong to the integration layer that
//! implements the backend trait.
//!
//! # Lifecycle
//!
//! - During initialization, [`init`] asks the backend to enumerate persisted
//!   variables and imports them into `state::EfiState::variables`.
//! - Before `ExitBootServices`, non-volatile writes are passed to the backend.
//! - After `ExitBootServices`, writes go directly to runtime-capable backends
//!   and otherwise are queued in the deferred warm-reboot buffer.
//! - On the next boot, deferred records are replayed through the same backend
//!   abstraction.

use crate::platform::{VarBackendError, VariableVisitor};
use crate::state::{self, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN};

use super::VarStoreError;

/// Initialize the variable store persistence layer.
///
/// This loads variables from the platform-provided
/// [`crate::platform::VariableBackend`] into CrabEFI's in-memory variable cache.
/// Hardware discovery is the platform integration's responsibility; library
/// initialization never probes platform-specific storage.
pub fn init() -> Result<(), VarStoreError> {
    log::info!("Initializing variable store persistence...");

    if state::has_variable_backend() {
        load_variables_from_platform_backend()?;
        log::info!("Variable store persistence initialized");
        return Ok(());
    }

    log::info!("No platform variable backend configured - variables are volatile");
    Err(VarStoreError::NotInitialized)
}

/// Visitor that imports variables from a [`crate::platform::VariableBackend`]
/// into CrabEFI's in-memory EFI variable cache.
struct MemoryVariableLoader {
    loaded: usize,
}

impl VariableVisitor for MemoryVariableLoader {
    fn visit(&mut self, name: &[u16], vendor: &r_efi::efi::Guid, attributes: u32, data: &[u8]) {
        update_variable_in_memory(vendor, name, attributes, data);
        self.loaded += 1;
    }
}

/// Load persisted variables from the platform-provided backend.
fn load_variables_from_platform_backend() -> Result<(), VarStoreError> {
    let mut loader = MemoryVariableLoader { loaded: 0 };
    state::with_variable_backend_mut(|backend| backend.load(&mut loader))
        .ok_or(VarStoreError::NotInitialized)?
        .map_err(var_backend_error_to_varstore)?;
    log::info!(
        "Loaded {} variables from platform variable backend",
        loader.loaded
    );
    Ok(())
}

fn var_backend_error_to_varstore(error: VarBackendError) -> VarStoreError {
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

/// Get the timestamp of a stored variable.
///
/// The generic backend trait currently persists variable payloads only. EDK2
/// non-auth format does not store timestamps, and authenticated timestamps are
/// preserved only while records are queued in the deferred buffer.
pub fn get_variable_timestamp(
    _guid: &r_efi::efi::Guid,
    _name: &[u16],
) -> Option<super::SerializedTime> {
    None
}

/// Persist a variable.
///
/// Before `ExitBootServices`, this calls the platform backend directly. After
/// `ExitBootServices`, runtime-capable backends are still called directly;
/// other backends receive the write on the next boot through the deferred
/// buffer.
pub fn persist_variable(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Result<(), VarStoreError> {
    if !state::has_variable_backend() {
        return Err(VarStoreError::NotInitialized);
    }

    persist_variable_via_platform_backend(guid, name, attributes, data)
}

/// Persist a variable while preserving a deferred authenticated timestamp.
pub fn persist_variable_with_timestamp(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
    _timestamp: super::SerializedTime,
) -> Result<(), VarStoreError> {
    persist_variable(guid, name, attributes, data)
}

/// Delete a persisted variable.
pub fn delete_variable(guid: &r_efi::efi::Guid, name: &[u16]) -> Result<(), VarStoreError> {
    if !state::has_variable_backend() {
        return Err(VarStoreError::NotInitialized);
    }

    delete_variable_via_platform_backend(guid, name)
}

/// Persist a variable through the platform-provided backend.
fn persist_variable_via_platform_backend(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Result<(), VarStoreError> {
    if state::is_exit_boot_services_called() && !state::variable_backend_runtime_capable() {
        return queue_variable_for_deferred(guid, name, attributes, data);
    }

    state::with_variable_backend_mut(|backend| backend.write(name, guid, attributes, data))
        .ok_or(VarStoreError::NotInitialized)?
        .map_err(var_backend_error_to_varstore)
}

/// Delete a variable through the platform-provided backend.
fn delete_variable_via_platform_backend(
    guid: &r_efi::efi::Guid,
    name: &[u16],
) -> Result<(), VarStoreError> {
    if state::is_exit_boot_services_called() && !state::variable_backend_runtime_capable() {
        return queue_variable_deletion_for_deferred(guid, name);
    }

    state::with_variable_backend_mut(|backend| backend.delete(name, guid))
        .ok_or(VarStoreError::NotInitialized)?
        .map_err(var_backend_error_to_varstore)
}

/// Queue a variable write for deferred processing after `ExitBootServices`.
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

/// Queue a variable deletion for deferred processing after `ExitBootServices`.
fn queue_variable_deletion_for_deferred(
    guid: &r_efi::efi::Guid,
    name: &[u16],
) -> Result<(), VarStoreError> {
    super::deferred::queue_deletion(guid, name)?;
    log::debug!("Variable deletion queued for deferred processing");
    Ok(())
}

/// Check if a persistent variable backend is available.
pub fn is_storage_available() -> bool {
    state::has_variable_backend()
}

/// Check if variable persistence is configured.
pub fn is_varstore_initialized() -> bool {
    state::has_variable_backend()
}

/// Get variable store statistics.
///
/// The generic [`crate::platform::VariableBackend`] trait intentionally does
/// not require capacity reporting. Backends that can report detailed capacity
/// should expose that through a backend-specific diagnostic interface.
pub fn get_varstore_stats() -> Option<(u32, u32, u32)> {
    None
}

/// Compact the variable store.
///
/// Compaction is backend-specific. The built-in EDK2 FV backend compacts
/// automatically when a write does not fit.
pub fn compact_varstore() -> Result<u32, VarStoreError> {
    Err(VarStoreError::NotInitialized)
}

/// Update a variable in the in-memory cache.
///
/// This is used when loading variables from a backend or applying deferred
/// variable changes on boot.
pub fn update_variable_in_memory(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) {
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

/// Delete a variable from the in-memory cache.
///
/// This is used when applying deferred variable deletions on boot.
pub(super) fn delete_variable_from_memory(guid: &r_efi::efi::Guid, name: &[u16]) {
    state::with_efi_mut(|efi| {
        if let Some(var) = efi.variables.iter_mut().find(|var| {
            var.in_use && var.vendor_guid == *guid && crate::efi::utils::ucs2_eq(&var.name, name)
        }) {
            var.in_use = false;
        }
    });
}
