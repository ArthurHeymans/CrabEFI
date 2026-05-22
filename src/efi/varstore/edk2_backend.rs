//! EDK2 Firmware Volume Variable Backend
//!
//! This module provides [`Edk2VarStore`], a [`VariableBackend`] implementation
//! that stores EFI variables in EDK2-compatible Firmware Volume (FV) format
//! on top of a raw [`StorageBackend`].
//!
//! # Usage
//!
//! ```ignore
//! let mut spi_backend = SpiStorageBackend::new(controller, offset, size);
//! let mut edk2_store = crabefi::efi::varstore::Edk2VarStore::new(&mut spi_backend);
//!
//! let config = crabefi::PlatformConfig {
//!     variable_backend: Some(&mut edk2_store),
//!     // ...
//! };
//! ```
//!
//! This is the default variable backend for the coreboot target and any other
//! platform with direct byte-level access to a NOR flash or similar storage.
//! Platforms using SMM or TF-A MM should implement [`VariableBackend`] directly.

use alloc::vec::Vec;

use crate::platform::{StorageBackend, VarBackendError, VariableBackend, VariableVisitor};
use r_efi::efi::Guid;

use super::edk2;

fn guid_bytes_to_efi(bytes: &[u8; 16]) -> Guid {
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

struct ActiveVar {
    guid: [u8; 16],
    name: Vec<u16>,
    attributes: u32,
    data: Vec<u8>,
}

/// EDK2 Firmware Volume format variable store.
///
/// Wraps a [`StorageBackend`] (e.g., SPI flash) and implements the
/// [`VariableBackend`] trait using EDK2-compatible Firmware Volume format.
///
/// # Format
///
/// The storage is laid out as:
/// ```text
/// +-------------------------------------------+ offset 0
/// |  EFI_FIRMWARE_VOLUME_HEADER  (72 bytes)   |
/// +-------------------------------------------+ offset 0x48
/// |  VARIABLE_STORE_HEADER       (28 bytes)   |
/// +-------------------------------------------+ offset 0x64
/// |  Variable Record #1 (header + name + data)|
/// |  (padded to 4-byte alignment)             |
/// +-------------------------------------------+
/// |  Variable Record #2                       |
/// +-------------------------------------------+
/// |  ...                                      |
/// +-------------------------------------------+
/// |  Free space (0xFF)                        |
/// +-------------------------------------------+
/// ```
///
/// When a variable is updated, the old record is marked as deleted and a new
/// record is appended. When free space runs out, compaction erases the region
/// and rewrites only active variables.
pub struct Edk2VarStore<'a> {
    storage: &'a mut dyn StorageBackend,
    /// Whether the FV headers have been validated/initialized.
    initialized: bool,
    /// Whether the store uses authenticated variable format.
    auth_format: bool,
    /// Size of the data region (total size minus headers).
    data_size: u32,
    /// Current write offset (next free byte in the data region).
    write_offset: u32,
}

impl<'a> Edk2VarStore<'a> {
    /// Create a new EDK2 variable store wrapping a storage backend.
    ///
    /// The store is not initialized until [`VariableBackend::load()`] is called.
    pub fn new(storage: &'a mut dyn StorageBackend) -> Self {
        Self {
            storage,
            initialized: false,
            auth_format: false,
            data_size: 0,
            write_offset: 0,
        }
    }

    /// Check if the store has been initialized (load() called successfully).
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Read all variable records from the store.
    fn walk_variables(&mut self) -> Vec<edk2::FvVariable> {
        let auth_format = self.auth_format;
        let data_size = self.data_size;
        let storage = &mut self.storage;
        let mut read_fn =
            |offset: u32, buf: &mut [u8]| -> bool { storage.read(offset, buf).is_ok() };
        edk2::walk_variables(&mut read_fn, auth_format, data_size)
    }

    /// Mark any existing active record for `guid_bytes` and `name` as deleted.
    fn delete_existing_record(
        &mut self,
        guid_bytes: &[u8; 16],
        name: &[u16],
    ) -> Result<(), VarBackendError> {
        let vars = self.walk_variables();
        for var in &vars {
            if edk2::is_var_added(var.state)
                && var.guid == *guid_bytes
                && edk2::name_matches(&var.name, name)
            {
                let _ = self.storage.enable_writes();
                let storage = &mut self.storage;
                let mut write_fn =
                    |offset: u32, data: &[u8]| -> bool { storage.write(offset, data).is_ok() };
                if !edk2::mark_deleted(&mut write_fn, var.state_offset) {
                    return Err(VarBackendError::IoError);
                }
            }
        }
        Ok(())
    }

    /// Return the latest active variables, optionally excluding one variable.
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

    /// Compact the store by rewriting the provided active variables.
    fn compact_active(&mut self, active: Vec<ActiveVar>) -> Result<(), VarBackendError> {
        let storage_size = self.storage.size();
        let final_offset = Self::compacted_end(&active)?;
        if final_offset > storage_size {
            return Err(VarBackendError::StoreFull);
        }

        let fv_headers = edk2::build_fv_headers(storage_size);
        let _ = self.storage.enable_writes();
        self.storage
            .erase(0, storage_size)
            .map_err(|_| VarBackendError::IoError)?;
        self.storage
            .write(0, &fv_headers)
            .map_err(|_| VarBackendError::IoError)?;

        self.auth_format = false;
        self.data_size = storage_size - (edk2::FV_HEADER_LENGTH + edk2::VS_HEADER_LENGTH) as u32;
        self.write_offset = edk2::VARIABLE_DATA_OFFSET;

        for var in active {
            let storage = &mut self.storage;
            let mut write_fn =
                |offset: u32, data: &[u8]| -> bool { storage.write(offset, data).is_ok() };
            self.write_offset = edk2::write_variable(
                &mut write_fn,
                self.write_offset,
                &var.guid,
                &var.name,
                var.attributes,
                &var.data,
            )
            .ok_or(VarBackendError::IoError)?;
        }

        Ok(())
    }

    /// Append a variable record, compacting once if necessary.
    fn append_variable(
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

        // Preflight the compacted layout before deleting the existing record or
        // erasing flash. If the replacement cannot fit even after compaction,
        // leave the current store untouched.
        let compacted_active = self.active_variables_excluding(Some((&guid_bytes, name)));
        let compacted_end = Self::compacted_end(&compacted_active)?;
        if compacted_end
            .checked_add(record_len)
            .is_none_or(|end| end > storage_size)
        {
            return Err(VarBackendError::StoreFull);
        }

        if self
            .write_offset
            .checked_add(record_len)
            .is_some_and(|end| end <= storage_size)
        {
            self.delete_existing_record(&guid_bytes, name)?;
        } else {
            log::info!("Variable store full, compacting");
            self.compact_active(compacted_active)?;
        }

        let _ = self.storage.enable_writes();
        let storage = &mut self.storage;
        let mut write_fn =
            |offset: u32, data: &[u8]| -> bool { storage.write(offset, data).is_ok() };
        self.write_offset = edk2::write_variable(
            &mut write_fn,
            self.write_offset,
            &guid_bytes,
            name,
            attributes,
            data,
        )
        .ok_or(VarBackendError::IoError)?;

        Ok(())
    }

    /// Validate or format the FV headers.
    ///
    /// Returns Ok(()) if headers are valid or were successfully written.
    fn ensure_initialized(&mut self) -> Result<(), VarBackendError> {
        if self.initialized {
            return Ok(());
        }

        let storage_size = self.storage.size();

        // Read FV + VS headers
        let header_size = edk2::FV_HEADER_LENGTH + edk2::VS_HEADER_LENGTH;
        let mut header_bytes = [0u8; 128];
        self.storage
            .read(0, &mut header_bytes[..header_size])
            .map_err(|_| VarBackendError::IoError)?;

        // Validate
        let validation = edk2::validate_fv(&header_bytes[..header_size], storage_size);

        if validation.valid {
            self.auth_format = validation.auth_format;
            self.data_size = validation.data_size;

            // Find write offset
            let auth_format = self.auth_format;
            let data_size = self.data_size;
            let storage = &mut self.storage;
            let mut read_fn =
                |offset: u32, buf: &mut [u8]| -> bool { storage.read(offset, buf).is_ok() };
            self.write_offset = edk2::find_write_offset(&mut read_fn, auth_format, data_size);
            self.initialized = true;
            return Ok(());
        }

        // Format the store
        log::info!(
            "Formatting variable store as EDK2 FV ({} KB)...",
            storage_size / 1024
        );

        let fv_headers = edk2::build_fv_headers(storage_size);
        let _ = self.storage.enable_writes();
        self.storage
            .erase(0, storage_size)
            .map_err(|_| VarBackendError::IoError)?;
        self.storage
            .write(0, &fv_headers)
            .map_err(|_| VarBackendError::IoError)?;

        self.auth_format = false;
        self.data_size = storage_size - (edk2::FV_HEADER_LENGTH + edk2::VS_HEADER_LENGTH) as u32;
        self.write_offset = (edk2::FV_HEADER_LENGTH + edk2::VS_HEADER_LENGTH) as u32;
        self.initialized = true;

        Ok(())
    }
}

impl VariableBackend for Edk2VarStore<'_> {
    fn load(&mut self, visitor: &mut dyn VariableVisitor) -> Result<(), VarBackendError> {
        self.ensure_initialized()?;

        let vars = self.walk_variables();
        let mut active: Vec<&edk2::FvVariable> = Vec::new();
        for var in &vars {
            if !edk2::is_var_added(var.state) {
                continue;
            }
            active.retain(|existing| {
                !(existing.guid == var.guid && edk2::name_matches(&existing.name, &var.name))
            });
            active.push(var);
        }

        for var in active {
            let vendor = guid_bytes_to_efi(&var.guid);
            let name_len = var
                .name
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(var.name.len());
            visitor.visit(&var.name[..name_len], &vendor, var.attributes, &var.data);
        }

        Ok(())
    }

    fn write(
        &mut self,
        name: &[u16],
        vendor: &Guid,
        attributes: u32,
        data: &[u8],
    ) -> Result<(), VarBackendError> {
        self.append_variable(name, vendor, attributes, data)
    }

    fn delete(&mut self, name: &[u16], vendor: &Guid) -> Result<(), VarBackendError> {
        self.ensure_initialized()?;
        let guid_bytes = edk2::guid_to_bytes(vendor);
        self.delete_existing_record(&guid_bytes, name)
    }

    fn runtime_capable(&self) -> bool {
        // Direct flash is NOT runtime-capable: after ExitBootServices, flash
        // may be locked by SMM. Writes go to the deferred buffer.
        false
    }

    fn notify_exit_boot_services(&mut self) {
        // Mark that flash is now locked — writes should go to deferred buffer.
        log::debug!("Edk2VarStore: ExitBootServices — flash writes disabled");
    }
}
