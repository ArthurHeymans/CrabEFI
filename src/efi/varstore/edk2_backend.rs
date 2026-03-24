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

use crate::platform::{StorageBackend, VarBackendError, VariableBackend, VariableVisitor};
use r_efi::efi::Guid;

use super::edk2;

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

        // Read variable records from the FV and call visitor for each
        let auth_format = self.auth_format;
        let data_size = self.data_size;
        let header_offset = (edk2::FV_HEADER_LENGTH + edk2::VS_HEADER_LENGTH) as u32;
        let storage = &mut self.storage;

        // Walk the variable store records
        let mut offset = header_offset;
        let end = header_offset + data_size;

        while offset < end {
            // Read variable header
            let header_len = if auth_format {
                edk2::AUTH_VAR_HEADER_SIZE
            } else {
                edk2::VAR_HEADER_SIZE
            };

            if offset + header_len as u32 > end {
                break;
            }

            let mut header_buf = [0u8; 80]; // Large enough for auth header
            if storage.read(offset, &mut header_buf[..header_len]).is_err() {
                break;
            }

            // Check magic and state
            let start_id = u16::from_le_bytes([header_buf[0], header_buf[1]]);
            if start_id != 0xAA55 {
                break; // End of valid records (free space)
            }

            let state = header_buf[2];
            let attributes =
                u32::from_le_bytes([header_buf[3], header_buf[4], header_buf[5], header_buf[6]]);

            let (name_size, data_size_field) = if auth_format {
                let ns = u32::from_le_bytes([
                    header_buf[40],
                    header_buf[41],
                    header_buf[42],
                    header_buf[43],
                ]);
                let ds = u32::from_le_bytes([
                    header_buf[44],
                    header_buf[45],
                    header_buf[46],
                    header_buf[47],
                ]);
                (ns, ds)
            } else {
                let ns = u32::from_le_bytes([
                    header_buf[24],
                    header_buf[25],
                    header_buf[26],
                    header_buf[27],
                ]);
                let ds = u32::from_le_bytes([
                    header_buf[28],
                    header_buf[29],
                    header_buf[30],
                    header_buf[31],
                ]);
                (ns, ds)
            };

            // Extract vendor GUID
            let guid_offset = if auth_format { 48 } else { 32 };
            let vendor_guid = if guid_offset + 16 <= header_len {
                let guid_bytes = &header_buf[guid_offset..guid_offset + 16];
                // Parse GUID from mixed-endian format (first 3 fields LE, last 2 BE)
                let data1 = u32::from_le_bytes([
                    guid_bytes[0],
                    guid_bytes[1],
                    guid_bytes[2],
                    guid_bytes[3],
                ]);
                let data2 = u16::from_le_bytes([guid_bytes[4], guid_bytes[5]]);
                let data3 = u16::from_le_bytes([guid_bytes[6], guid_bytes[7]]);
                let data4_hi = u8::from_le_bytes([guid_bytes[8]]);
                let data4_lo = u8::from_le_bytes([guid_bytes[9]]);
                Guid::from_fields(
                    data1,
                    data2,
                    data3,
                    data4_hi,
                    data4_lo,
                    &[
                        guid_bytes[10],
                        guid_bytes[11],
                        guid_bytes[12],
                        guid_bytes[13],
                        guid_bytes[14],
                        guid_bytes[15],
                    ],
                )
            } else {
                break;
            };

            // Calculate total record size (header + name + data, padded to 4 bytes)
            let record_data_start = offset + header_len as u32;
            let total_payload = name_size + data_size_field;
            let record_size = header_len as u32 + total_payload + ((4 - (total_payload % 4)) % 4); // 4-byte align

            // Only process valid (non-deleted) records
            if state == 0x3F || state == 0x7F {
                // Read name and data
                if total_payload > 0 && record_data_start + total_payload <= end {
                    // Use a stack buffer for small records, skip huge ones
                    const MAX_PAYLOAD: usize = 32 * 1024;
                    if (total_payload as usize) <= MAX_PAYLOAD {
                        let mut payload = [0u8; MAX_PAYLOAD];
                        let payload_slice = &mut payload[..total_payload as usize];
                        if storage.read(record_data_start, payload_slice).is_ok() {
                            // Name is UTF-16LE, data follows
                            let name_bytes = &payload_slice[..name_size as usize];
                            let data_bytes =
                                &payload_slice[name_size as usize..total_payload as usize];

                            // Convert name bytes to &[u16]
                            let name_u16_count = name_size as usize / 2;
                            // SAFETY: name_bytes is aligned to u8, we manually convert
                            let mut name_u16 = [0u16; 128];
                            let name_len = name_u16_count.min(128);
                            for i in 0..name_len {
                                name_u16[i] =
                                    u16::from_le_bytes([name_bytes[i * 2], name_bytes[i * 2 + 1]]);
                            }
                            // Strip null terminator if present
                            let name_slice = if name_len > 0 && name_u16[name_len - 1] == 0 {
                                &name_u16[..name_len - 1]
                            } else {
                                &name_u16[..name_len]
                            };

                            visitor.visit(name_slice, &vendor_guid, attributes, data_bytes);
                        }
                    }
                }
            }

            // Advance to next record
            offset += record_size;
        }

        Ok(())
    }

    fn write(
        &mut self,
        _name: &[u16],
        _vendor: &Guid,
        _attributes: u32,
        _data: &[u8],
    ) -> Result<(), VarBackendError> {
        if !self.initialized {
            return Err(VarBackendError::NotAvailable);
        }

        // TODO: Delegate to the existing edk2 persistence code for writing.
        // This requires refactoring persistence.rs to work with a borrowed
        // StorageBackend rather than the global state accessor.
        //
        // For now, the legacy init() path handles writes through the existing
        // persistence module. This stub will be completed when the full
        // migration from init() to init_platform() happens.
        Err(VarBackendError::Other)
    }

    fn delete(&mut self, _name: &[u16], _vendor: &Guid) -> Result<(), VarBackendError> {
        if !self.initialized {
            return Err(VarBackendError::NotAvailable);
        }

        // TODO: Same as write() — pending persistence.rs refactoring.
        Err(VarBackendError::Other)
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
