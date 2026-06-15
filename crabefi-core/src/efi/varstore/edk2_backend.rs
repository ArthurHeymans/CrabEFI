//! EDK2 Firmware Volume Variable Backend
//!
//! This module provides shared EDK2 Firmware Volume variable-store logic plus
//! [`Edk2VarStore`], a [`VariableBackend`] implementation that stores EFI
//! variables on top of a raw [`StorageBackend`].
//!
//! The direct-flash persistence path and the platform [`VariableBackend`] path
//! both use [`Edk2Store`], so EDK2 FV parsing, replacement, deletion, and
//! compaction rules live in one place.

use alloc::vec::Vec;

use crate::platform::{StorageBackend, VarBackendError, VariableBackend, VariableVisitor};
use r_efi::efi::Guid;

use super::edk2;

/// Mutable EDK2 variable-store state tracked by a caller.
#[derive(Clone, Copy, Debug)]
pub struct Edk2StoreState {
    /// Whether the FV headers have been validated/initialized.
    pub initialized: bool,
    /// Whether the store uses authenticated variable headers.
    pub auth_format: bool,
    /// Size of the variable-record area after FV + variable-store headers.
    pub data_size: u32,
    /// Next free byte for appending records, relative to the store start.
    pub write_offset: u32,
}

impl Edk2StoreState {
    /// Create an empty, uninitialized EDK2 store state.
    pub const fn new() -> Self {
        Self {
            initialized: false,
            auth_format: false,
            data_size: 0,
            write_offset: 0,
        }
    }
}

impl Default for Edk2StoreState {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert 16-byte on-disk GUID bytes to an EFI GUID.
pub fn guid_bytes_to_efi(bytes: &[u8; 16]) -> Guid {
    Guid::from_fields(
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

#[derive(Clone)]
struct ActiveVar {
    guid: [u8; 16],
    name: Vec<u16>,
    attributes: u32,
    data: Vec<u8>,
}

/// Shared EDK2 Firmware Volume store implementation.
///
/// `Edk2Store` borrows a storage backend and the caller-owned state for the
/// duration of one operation. This keeps the parsing/write/compaction logic
/// shared while allowing existing global-state and platform-backend callers to
/// own their storage differently.
pub struct Edk2Store<'a> {
    storage: &'a mut dyn StorageBackend,
    state: &'a mut Edk2StoreState,
}

impl<'a> Edk2Store<'a> {
    /// Create a store view over `storage` and its mutable `state`.
    pub fn new(storage: &'a mut dyn StorageBackend, state: &'a mut Edk2StoreState) -> Self {
        Self { storage, state }
    }

    /// Check if the store has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.state.initialized
    }

    /// Return the current write offset.
    pub fn write_offset(&self) -> u32 {
        self.state.write_offset
    }

    /// Return whether the current FV uses authenticated variable headers.
    pub fn auth_format(&self) -> bool {
        self.state.auth_format
    }

    /// Return the current EDK2 variable data size.
    pub fn data_size(&self) -> u32 {
        self.state.data_size
    }

    /// Validate or format the FV headers.
    pub fn ensure_initialized(&mut self) -> Result<(), VarBackendError> {
        if self.state.initialized {
            return Ok(());
        }

        let storage_size = self.storage.size();
        let header_size = edk2::FV_HEADER_LENGTH + edk2::VS_HEADER_LENGTH;
        let mut header_bytes = [0u8; 128];
        self.storage
            .read(0, &mut header_bytes[..header_size])
            .map_err(|_| VarBackendError::IoError)?;

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

        let validation = edk2::validate_fv(&header_bytes[..header_size], storage_size);
        if validation.valid {
            let mut read_fn =
                |offset: u32, buf: &mut [u8]| -> bool { self.storage.read(offset, buf).is_ok() };
            let write_offset =
                edk2::find_write_offset(&mut read_fn, validation.auth_format, validation.data_size);

            self.state.initialized = true;
            self.state.auth_format = validation.auth_format;
            self.state.data_size = validation.data_size;
            self.state.write_offset = write_offset;

            log::info!(
                "EDK2 FV found: auth_format={}, data_size={} KB, write_offset={:#x}",
                validation.auth_format,
                validation.data_size / 1024,
                write_offset
            );
            return Ok(());
        }

        log::info!(
            "Formatting variable store as EDK2 FV ({} KB)...",
            storage_size / 1024
        );
        let fv_headers = edk2::build_fv_headers(storage_size);
        if let Err(e) = self.storage.enable_writes() {
            log::warn!("Could not enable storage writes: {:?}", e);
        }
        self.storage
            .erase(0, storage_size)
            .map_err(|_| VarBackendError::IoError)?;
        self.storage
            .write(0, &fv_headers)
            .map_err(|_| VarBackendError::IoError)?;

        self.state.initialized = true;
        self.state.auth_format = false;
        self.state.data_size = storage_size
            .checked_sub((edk2::FV_HEADER_LENGTH + edk2::VS_HEADER_LENGTH) as u32)
            .ok_or(VarBackendError::StoreFull)?;
        self.state.write_offset = edk2::VARIABLE_DATA_OFFSET;

        log::info!("Variable store formatted as EDK2 FV successfully");
        Ok(())
    }

    /// Load all active variables through `visitor`.
    pub fn load(&mut self, visitor: &mut dyn VariableVisitor) -> Result<usize, VarBackendError> {
        self.ensure_initialized()?;
        let active = self.active_variables_excluding(None);
        let count = active.len();

        for var in active {
            let vendor = guid_bytes_to_efi(&var.guid);
            let name_len = var
                .name
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(var.name.len());
            visitor.visit(&var.name[..name_len], &vendor, var.attributes, &var.data);
        }

        Ok(count)
    }

    /// Persist a variable write.
    pub fn write(
        &mut self,
        name: &[u16],
        vendor: &Guid,
        attributes: u32,
        data: &[u8],
    ) -> Result<(), VarBackendError> {
        self.ensure_initialized()?;

        let guid_bytes = edk2::guid_to_bytes(vendor);
        let record_len = Self::record_len(&guid_bytes, name, attributes, data)?;
        let storage_size = self.storage.size();
        let data_capacity = storage_size
            .checked_sub(edk2::VARIABLE_DATA_OFFSET)
            .ok_or(VarBackendError::StoreFull)?;
        if record_len > data_capacity {
            return Err(VarBackendError::StoreFull);
        }

        // Preflight the compacted layout before deleting or erasing anything.
        let compacted_active = self.active_variables_excluding(Some((&guid_bytes, name)));
        let compacted_end = Self::compacted_end(&compacted_active)?;
        if compacted_end
            .checked_add(record_len)
            .is_none_or(|end| end > storage_size)
        {
            return Err(VarBackendError::StoreFull);
        }

        let mut old_state_offsets = self.matching_active_state_offsets(&guid_bytes, name);
        if self
            .state
            .write_offset
            .checked_add(record_len)
            .is_none_or(|end| end > storage_size)
        {
            log::info!("Variable store full, compacting");
            self.compact_active(compacted_active)?;
            // Compaction rewrote the store without the replaced variable, so
            // the pre-compaction state offsets no longer refer to old records.
            old_state_offsets.clear();
        }

        let write_offset = self.state.write_offset;
        if let Err(e) = self.storage.enable_writes() {
            log::warn!("Could not enable storage writes: {:?}", e);
        }
        let mut write_fn =
            |offset: u32, data: &[u8]| -> bool { self.storage.write(offset, data).is_ok() };
        self.state.write_offset = edk2::write_variable(
            &mut write_fn,
            write_offset,
            &guid_bytes,
            name,
            attributes,
            data,
        )
        .ok_or(VarBackendError::IoError)?;

        // The new record is durable now. Delete old records afterwards so an
        // append failure cannot destroy the previous value. Deletion failures
        // are still fatal: coreboot's SMMSTORE reader is first-match, so an old
        // active record left before the appended replacement would keep the
        // persistent store semantically stale.
        for state_offset in old_state_offsets {
            self.mark_deleted_at(state_offset)?;
        }

        log::debug!("Variable persisted at offset {:#x}", write_offset);
        Ok(())
    }

    /// Mark active records for `name`/`vendor` deleted.
    pub fn delete(&mut self, name: &[u16], vendor: &Guid) -> Result<(), VarBackendError> {
        self.ensure_initialized()?;
        let guid_bytes = edk2::guid_to_bytes(vendor);
        let offsets = self.matching_active_state_offsets(&guid_bytes, name);
        if offsets.is_empty() {
            return Err(VarBackendError::NotFound);
        }

        for state_offset in offsets {
            self.mark_deleted_at(state_offset)?;
        }
        Ok(())
    }

    /// Compact the store by preserving the latest active variable records.
    pub fn compact(&mut self) -> Result<u32, VarBackendError> {
        self.ensure_initialized()?;
        let old_write_offset = self.state.write_offset;
        let active = self.active_variables_excluding(None);
        log::info!(
            "Found {} active variables to preserve during compaction",
            active.len()
        );
        self.compact_active(active)?;
        Ok(old_write_offset.saturating_sub(self.state.write_offset))
    }

    fn walk_variables(&mut self) -> Vec<edk2::FvVariable> {
        let auth_format = self.state.auth_format;
        let data_size = self.state.data_size;
        let mut read_fn =
            |offset: u32, buf: &mut [u8]| -> bool { self.storage.read(offset, buf).is_ok() };
        edk2::walk_variables(&mut read_fn, auth_format, data_size)
    }

    fn matching_active_state_offsets(&mut self, guid_bytes: &[u8; 16], name: &[u16]) -> Vec<u32> {
        self.walk_variables()
            .into_iter()
            .filter(|var| {
                edk2::is_var_added(var.state)
                    && var.guid == *guid_bytes
                    && edk2::name_matches(&var.name, name)
            })
            .map(|var| var.state_offset)
            .collect()
    }

    fn active_variables_excluding(
        &mut self,
        exclude: Option<(&[u8; 16], &[u16])>,
    ) -> Vec<ActiveVar> {
        let vars = self.walk_variables();
        let mut active: Vec<ActiveVar> = Vec::new();
        for var in vars {
            if !edk2::is_var_added(var.state) {
                continue;
            }
            if exclude.is_some_and(|(guid, name)| {
                var.guid == *guid && edk2::name_matches(&var.name, name)
            }) {
                continue;
            }
            active.retain(|existing| {
                !(existing.guid == var.guid && edk2::name_matches(&existing.name, &var.name))
            });
            active.push(ActiveVar {
                guid: var.guid,
                name: var.name,
                attributes: var.attributes,
                data: var.data,
            });
        }
        active
    }

    fn record_len(
        guid: &[u8; 16],
        name: &[u16],
        attributes: u32,
        data: &[u8],
    ) -> Result<u32, VarBackendError> {
        let len = edk2::build_variable_record(guid, name, attributes, data).len();
        if len > u32::MAX as usize {
            return Err(VarBackendError::DataTooLarge);
        }
        Ok(len as u32)
    }

    fn compacted_end(active: &[ActiveVar]) -> Result<u32, VarBackendError> {
        let mut offset = edk2::VARIABLE_DATA_OFFSET;
        for var in active {
            let len = Self::record_len(&var.guid, &var.name, var.attributes, &var.data)?;
            offset = offset.checked_add(len).ok_or(VarBackendError::StoreFull)?;
        }
        Ok(offset)
    }

    fn compact_active(&mut self, active: Vec<ActiveVar>) -> Result<(), VarBackendError> {
        let storage_size = self.storage.size();
        let final_offset = Self::compacted_end(&active)?;
        if final_offset > storage_size {
            return Err(VarBackendError::StoreFull);
        }

        let fv_headers = edk2::build_fv_headers(storage_size);
        if let Err(e) = self.storage.enable_writes() {
            log::warn!("Could not enable storage writes for compaction: {:?}", e);
        }
        self.storage
            .erase(0, storage_size)
            .map_err(|_| VarBackendError::IoError)?;
        self.storage
            .write(0, &fv_headers)
            .map_err(|_| VarBackendError::IoError)?;

        self.state.auth_format = false;
        self.state.data_size = storage_size
            .checked_sub((edk2::FV_HEADER_LENGTH + edk2::VS_HEADER_LENGTH) as u32)
            .ok_or(VarBackendError::StoreFull)?;
        self.state.write_offset = edk2::VARIABLE_DATA_OFFSET;

        for var in active {
            let mut write_fn =
                |offset: u32, data: &[u8]| -> bool { self.storage.write(offset, data).is_ok() };
            self.state.write_offset = edk2::write_variable(
                &mut write_fn,
                self.state.write_offset,
                &var.guid,
                &var.name,
                var.attributes,
                &var.data,
            )
            .ok_or(VarBackendError::IoError)?;
        }

        Ok(())
    }

    fn mark_deleted_at(&mut self, state_offset: u32) -> Result<(), VarBackendError> {
        if let Err(e) = self.storage.enable_writes() {
            log::warn!("Could not enable storage writes for deletion: {:?}", e);
        }
        let mut write_fn =
            |offset: u32, data: &[u8]| -> bool { self.storage.write(offset, data).is_ok() };
        if edk2::mark_deleted(&mut write_fn, state_offset) {
            Ok(())
        } else {
            Err(VarBackendError::IoError)
        }
    }
}

/// EDK2 Firmware Volume format variable store.
///
/// Wraps a [`StorageBackend`] (e.g., SPI flash) and implements the
/// [`VariableBackend`] trait using the same shared [`Edk2Store`] logic used by
/// the direct persistence path.
pub struct Edk2VarStore<'a> {
    storage: &'a mut dyn StorageBackend,
    state: Edk2StoreState,
}

impl<'a> Edk2VarStore<'a> {
    /// Create a new EDK2 variable store wrapping a storage backend.
    pub fn new(storage: &'a mut dyn StorageBackend) -> Self {
        Self {
            storage,
            state: Edk2StoreState::new(),
        }
    }

    /// Check if the store has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.state.initialized
    }
}

impl VariableBackend for Edk2VarStore<'_> {
    fn load(&mut self, visitor: &mut dyn VariableVisitor) -> Result<(), VarBackendError> {
        Edk2Store::new(self.storage, &mut self.state)
            .load(visitor)
            .map(|_| ())
    }

    fn write(
        &mut self,
        name: &[u16],
        vendor: &Guid,
        attributes: u32,
        data: &[u8],
    ) -> Result<(), VarBackendError> {
        Edk2Store::new(self.storage, &mut self.state).write(name, vendor, attributes, data)
    }

    fn delete(&mut self, name: &[u16], vendor: &Guid) -> Result<(), VarBackendError> {
        Edk2Store::new(self.storage, &mut self.state).delete(name, vendor)
    }

    fn runtime_capable(&self) -> bool {
        // Direct flash is NOT runtime-capable: after ExitBootServices, flash
        // may be locked by SMM. Writes go to the deferred buffer.
        false
    }

    fn notify_exit_boot_services(&mut self) {
        log::debug!("Edk2VarStore: ExitBootServices — flash writes disabled");
    }
}
