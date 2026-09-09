//! Boot-only EDK2 variable persistence and runtime-image import.
//!
//! Persistent storage is never a Runtime Services authority. Existing records
//! and firmware-created boot values are copied directly into the separate
//! runtime image store; the boot image retains neither a variable copy nor an
//! ExitBootServices snapshot.
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
//! - **BootActive**: the audited runtime-image bridge updates the bounded backend
//!   before the image store commits a non-volatile variable.
//! - **After ExitBootServices**: the bridge is erased and the runtime image
//!   commits nonvolatile writes to its retained deferred journal. The next boot
//!   replays those records through the bridge before completing variable import.
//!
//! # Persistent Config Region
//!
//! The location of the variable store region is determined by a
//! platform-provided bounded [`crate::platform::StorageBackend`], or an explicit
//! standalone [`crate::platform::VariableStoreLocator`] SPI adapter. This keeps
//! coreboot-specific concepts such as SMMSTORE table records and FMAP out of
//! the library persistence path.

use alloc::vec::Vec;

use crabefi_runtime_abi::VariableTimestamp;

use crate::cell::{Local, LocalCell};
#[cfg(feature = "spi-flash")]
use crate::drivers::spi::{self, SpiController};
#[cfg(feature = "spi-flash")]
use crate::platform::{
    FirmwareStorage, FirmwareStorageLocation, FirmwareStorageRegion, VariableStoreLocator,
};
use crate::platform::{StorageError, VariableStorage};

use super::VarStoreError;
use super::edk2;
#[cfg(feature = "spi-flash")]
use super::storage::SpiStorageBackend;
use super::storage::{StorageBackend, validate_range};

/// Variable store persistence state
///
/// Tracks the runtime state of the persistent variable store region.
/// The actual storage location is determined at runtime from coreboot
/// tables (SMMSTORE v2) or FMAP (SMMSTORE region).
#[derive(Clone, Copy)]
struct VarStoreState {
    /// Whether the store header has been validated/written
    initialized: bool,
    /// Next free location for appending records (relative to store start)
    write_offset: u32,
    /// Whether the EDK2 FV uses authenticated variable headers (60 bytes vs 32)
    auth_format: bool,
    /// Size of the variable data area (after FV + VS headers)
    data_size: u32,
}

impl VarStoreState {
    const fn new() -> Self {
        Self {
            initialized: false,
            write_offset: 0,
            auth_format: false,
            data_size: 0,
        }
    }
}

/// Persistent variable-store bookkeeping.
static VARSTORE: LocalCell<VarStoreState> = LocalCell::new(VarStoreState::new());
/// Boot-lifetime backend, never callable from the sealed runtime image.
enum Storage {
    Platform(&'static mut dyn StorageBackend),
    #[cfg(feature = "spi-flash")]
    Spi(SpiStorageBackend),
}

impl core::ops::Deref for Storage {
    type Target = dyn StorageBackend;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Platform(backend) => &**backend,
            #[cfg(feature = "spi-flash")]
            Self::Spi(backend) => backend,
        }
    }
}
impl core::ops::DerefMut for Storage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Platform(backend) => &mut **backend,
            #[cfg(feature = "spi-flash")]
            Self::Spi(backend) => backend,
        }
    }
}
impl Storage {
    // Preserve typed media errors across EDK2's boolean callback interface.
    fn with_program<T>(
        &mut self,
        operation: impl FnOnce(&mut dyn FnMut(u32, &[u8]) -> bool) -> T,
    ) -> Result<T, VarStoreError> {
        let mut failure = None;
        let result = operation(&mut |offset, bytes| {
            if failure.is_some() {
                return false;
            }
            match self.program(offset, bytes) {
                Ok(()) => true,
                Err(error) => {
                    failure = Some(error);
                    false
                }
            }
        });
        match failure {
            Some(error) => Err(error.into()),
            None => Ok(result),
        }
    }

    fn read(&mut self, offset: u32, data: &mut [u8]) -> Result<(), StorageError> {
        validate_range(self.size(), offset, data.len(), 1)?;
        core::ops::DerefMut::deref_mut(self).read(offset, data)
    }
    fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError> {
        validate_range(self.size(), offset, data.len(), self.program_granularity())?;
        if self.is_write_protected() {
            return Err(StorageError::WriteProtected);
        }
        core::ops::DerefMut::deref_mut(self).program(offset, data)
    }
    fn erase(&mut self, offset: u32, size: u32) -> Result<(), StorageError> {
        validate_range(self.size(), offset, size as usize, self.erase_granularity())?;
        if self.is_write_protected() {
            return Err(StorageError::WriteProtected);
        }
        core::ops::DerefMut::deref_mut(self).erase(offset, size)
    }
    fn read_controller(&mut self, offset: u32, data: &mut [u8]) -> Result<(), StorageError> {
        validate_range(self.size(), offset, data.len(), 1)?;
        match self {
            Self::Platform(backend) => backend.read(offset, data),
            #[cfg(feature = "spi-flash")]
            Self::Spi(backend) => backend.read_controller(offset, data),
        }
    }
    fn has_mapped_read_base(&self) -> bool {
        match self {
            Self::Platform(_) => false,
            #[cfg(feature = "spi-flash")]
            Self::Spi(backend) => backend.has_mapped_read_base(),
        }
    }
    fn base_offset(&self) -> u32 {
        match self {
            Self::Platform(_) => 0,
            #[cfg(feature = "spi-flash")]
            Self::Spi(backend) => backend.base_offset(),
        }
    }
}

static STORAGE: Local<Option<Storage>> = Local::new(None);

fn with_storage_mut<R>(f: impl FnOnce(&mut Storage) -> R) -> Option<R> {
    STORAGE.borrow_mut().as_mut().map(f)
}

/// Standalone capsule code may explicitly use its SPI adapter, never a platform backend.
#[cfg(feature = "spi-flash")]
pub fn with_spi_storage_mut<R>(f: impl FnOnce(&mut SpiStorageBackend) -> R) -> Option<R> {
    with_storage_mut(|storage| match storage {
        Storage::Spi(backend) => Some(f(backend)),
        Storage::Platform(_) => None,
    })
    .flatten()
}

/// Forget the boot-owned reference before its memory can be reclaimed by the OS.
pub(crate) fn detach_backend() {
    // After EBS the boot allocator is sealed. Reclaiming the boot memory is
    // the OS's job; erase access without running backend allocation destructors.
    let _detached = core::mem::ManuallyDrop::new(STORAGE.borrow_mut().take());
}

fn validate_backend(backend: &dyn StorageBackend) -> Result<(), VarStoreError> {
    let minimum = (edk2::FV_HEADER_LENGTH + edk2::VS_HEADER_LENGTH) as u32;
    if backend.size() < minimum || backend.program_granularity() != 1 {
        return Err(VarStoreError::InvalidArgument);
    }
    validate_range(
        backend.size(),
        0,
        backend.size() as usize,
        backend.erase_granularity(),
    )
    .map_err(|_| VarStoreError::InvalidArgument)
}

/// Default variable store base address in SPI flash
/// This is typically at the end of the flash region
/// Used only as fallback if coreboot tables don't provide config info
#[cfg(feature = "spi-flash")]
pub const DEFAULT_VARSTORE_BASE: u32 = 0x00F00000; // 15MB offset (for 16MB flash)

/// Default variable store size (256KB)
/// Used only as fallback if coreboot tables don't provide config info
#[cfg(feature = "spi-flash")]
pub const DEFAULT_VARSTORE_SIZE: u32 = 256 * 1024;

/// Initialize the variable store persistence layer
///
/// Validates a host-owned bounded region (or the explicitly selected standalone
/// SPI adapter), reads EDK2 records, and imports them into the runtime image.
/// The supplied backend is used only until ExitBootServices seals the bridge.
pub fn init(source: VariableStorage<'static>) -> Result<(), VarStoreError> {
    let storage = match source {
        VariableStorage::None => return Err(VarStoreError::NotInitialized),
        VariableStorage::Platform(backend) => {
            validate_backend(backend)?;
            Storage::Platform(backend)
        }
        #[cfg(feature = "spi-flash")]
        VariableStorage::Spi(locator) => Storage::Spi(probe_spi(locator)?),
    };
    *STORAGE.borrow_mut() = Some(storage);
    if let Err(error) = init_varstore().and_then(|()| load_variables_from_storage()) {
        VARSTORE.set(VarStoreState::new());
        detach_backend();
        return Err(error);
    }
    Ok(())
}

#[cfg(feature = "spi-flash")]
fn probe_spi(locator: &dyn VariableStoreLocator) -> Result<SpiStorageBackend, VarStoreError> {
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
    validate_backend(&backend)?;
    if !backend
        .base_offset()
        .is_multiple_of(backend.erase_granularity())
    {
        return Err(VarStoreError::InvalidArgument);
    }
    // Only this explicit standalone SPI adapter can change controller protection.
    if let Err(error) = backend.prepare_writes() {
        log::warn!("SPI variable region remains write-protected: {:?}", error);
    }

    Ok(backend)
}

/// Configure the variable store from the platform-provided locator.
#[cfg(feature = "spi-flash")]
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

    if let FirmwareStorageLocation::OffsetWithMappedRead { phys_base, .. } = located.location {
        backend.set_mapped_read_base(phys_base);
        log::info!(
            "Variable store reads mapped at {:#x} (writes use SPI offset {:#x})",
            phys_base,
            region.offset
        );
    }

    log::info!(
        "Variable store configured from platform locator: '{}' base={:#x}, size={} KB",
        located.name.as_str(),
        region.offset,
        region.size / 1024
    );

    Ok(())
}

/// Validate and narrow a located variable-store region for the current storage backend.
#[cfg(feature = "spi-flash")]
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
/// Regions are formatted only when entirely erased; invalid non-erased contents
/// are preserved, independent of transport. Selecting SPI never authorizes reset.
/// This uses EDK2 Firmware Volume format compatible with coreboot's SMMSTORE.
fn init_varstore() -> Result<(), VarStoreError> {
    // Read enough bytes for FV header + VS header
    let header_size = edk2::FV_HEADER_LENGTH + edk2::VS_HEADER_LENGTH;
    let mut header_bytes = [0u8; 128]; // Enough for FV + VS headers (100 bytes needed)
    let storage_size = with_storage_mut(|storage| {
        storage
            .read(0, &mut header_bytes[..header_size])
            .map_err(VarStoreError::from)?;
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

        if !validation.auth_format {
            migrate_non_auth_store(storage_size, validation.data_size)?;
            return Ok(());
        }

        VARSTORE.update(|vs| {
            vs.initialized = true;
            vs.auth_format = true;
            vs.data_size = validation.data_size;
        });
        let write_offset = with_storage_mut(|storage| {
            let mut read_fn =
                |offset: u32, buf: &mut [u8]| -> bool { storage.read(offset, buf).is_ok() };
            edk2::find_write_offset(&mut read_fn, true, validation.data_size)
        })
        .ok_or(VarStoreError::NotInitialized)?;
        VARSTORE.update(|vs| vs.write_offset = write_offset);
        log::info!("Variable store write offset: {:#x}", write_offset);
        return Ok(());
    }

    if !is_erased_for_write(0, storage_size)? {
        return Err(VarStoreError::InvalidHeader);
    }

    if with_storage_mut(|storage| storage.is_write_protected())
        .ok_or(VarStoreError::NotInitialized)?
    {
        return Err(VarStoreError::WriteProtected);
    }

    // Only completely erased storage may be initialized, on every transport.
    log::info!(
        "Formatting variable store as EDK2 FV (size {} KB)...",
        storage_size / 1024
    );

    // Build EDK2 FV + VS headers
    let fv_headers = edk2::build_fv_headers(storage_size);

    // Erase and initialize only within the selected region; never unlock here.
    with_storage_mut(|storage| {
        // Erase the region
        storage
            .erase(0, storage_size)
            .map_err(VarStoreError::from)?;

        // Write new FV + VS headers
        storage
            .program(0, &fv_headers)
            .map_err(VarStoreError::from)?;

        Ok::<(), VarStoreError>(())
    })
    .ok_or(VarStoreError::NotInitialized)??;

    let data_size = storage_size - edk2::FV_HEADER_LENGTH as u32 - edk2::VS_HEADER_LENGTH as u32;

    VARSTORE.update(|vs| {
        vs.initialized = true;
        vs.auth_format = true;
        vs.data_size = data_size;
        vs.write_offset = edk2::VARIABLE_DATA_OFFSET;
    });

    log::info!("Variable store formatted as authenticated EDK2 FV successfully");
    Ok(())
}

fn migrate_non_auth_store(storage_size: u32, data_size: u32) -> Result<(), VarStoreError> {
    let variables = with_storage_mut(|storage| {
        let mut read_fn = |offset: u32, buffer: &mut [u8]| storage.read(offset, buffer).is_ok();
        edk2::walk_variables(&mut read_fn, false, data_size)
    })
    .ok_or(VarStoreError::NotInitialized)?;
    let mut active = Vec::new();
    for variable in variables
        .into_iter()
        .filter(|variable| edk2::is_var_added(variable.state))
    {
        active.retain(|existing: &edk2::FvVariable| {
            !(existing.guid == variable.guid && edk2::name_matches(&existing.name, &variable.name))
        });
        active.push(variable);
    }

    // Prebuild and bounds-check every expanded authenticated record before any
    // write could be enabled. This catches deterministic legacy->authenticated
    // growth without risking the source generation.
    match preflight_non_auth_migration(storage_size, data_size, &active) {
        Ok(final_offset) => log::warn!(
            "Legacy variable store requires authenticated migration ({} records, {:#x} bytes), but the sole flash bank was preserved because no atomic staging bank is available",
            active.len(),
            final_offset
        ),
        Err(VarStoreError::StoreFull) => log::warn!(
            "Legacy variable store cannot fit authenticated headers; preserving it read-only"
        ),
        Err(error) => return Err(error),
    }

    let write_offset = with_storage_mut(|storage| {
        let mut read_fn = |offset: u32, buffer: &mut [u8]| storage.read(offset, buffer).is_ok();
        edk2::find_write_offset(&mut read_fn, false, data_size)
    })
    .ok_or(VarStoreError::NotInitialized)?;
    VARSTORE.update(|store| {
        store.initialized = true;
        store.auth_format = false;
        store.data_size = data_size;
        store.write_offset = write_offset;
    });
    Ok(())
}

fn preflight_non_auth_migration(
    storage_size: u32,
    data_size: u32,
    active: &[edk2::FvVariable],
) -> Result<u32, VarStoreError> {
    let limit = edk2::VARIABLE_DATA_OFFSET
        .checked_add(data_size)
        .filter(|limit| *limit <= storage_size)
        .ok_or(VarStoreError::InvalidHeader)?;
    let mut offset = edk2::VARIABLE_DATA_OFFSET;
    for variable in active {
        let record = edk2::build_variable_record(
            &variable.guid,
            &variable.name,
            variable.attributes,
            &variable.data,
            None,
        )
        .ok_or(VarStoreError::InvalidArgument)?;
        let record_len = u32::try_from(record.len()).map_err(|_| VarStoreError::StoreFull)?;
        offset = offset
            .checked_add(record_len)
            .filter(|end| *end <= limit)
            .ok_or(VarStoreError::StoreFull)?;
    }
    Ok(offset)
}

/// Load variables from storage into the in-memory cache
fn load_variables_from_storage() -> Result<(), VarStoreError> {
    let vs = VARSTORE.get();
    if !vs.initialized {
        return Err(VarStoreError::NotInitialized);
    }
    let auth_format = vs.auth_format;
    let data_size = vs.data_size;

    // Walk all variable records in the FV
    let vars = with_storage_mut(|storage| {
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

    let client = crate::efi::runtime_image::installed().ok_or(VarStoreError::NotInitialized)?;
    for variable in &active_vars {
        let name_len = variable
            .name
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(variable.name.len());
        if name_len == 0
            || name_len > crabefi_runtime_abi::MAX_VARIABLE_NAME_LEN
            || variable.data.len() > crabefi_runtime_abi::MAX_VARIABLE_DATA_SIZE
        {
            return Err(VarStoreError::DataTooLarge);
        }
        let timestamp = variable.timestamp.unwrap_or_default();
        client
            .import_variable(&crabefi_runtime_abi::VariableImport {
                name_address: variable.name.as_ptr() as u64,
                name_len: name_len as u32,
                attributes: variable.attributes,
                guid: variable.guid,
                data_address: variable.data.as_ptr() as u64,
                data_len: variable.data.len() as u32,
                timestamp_valid: u32::from(variable.timestamp.is_some()),
                timestamp,
            })
            .map_err(|_| VarStoreError::StoreFull)?;
    }

    log::info!(
        "Imported {} variables into runtime image",
        active_vars.len()
    );
    Ok(())
}

/// Get the latest durable authenticated timestamp, including deletion floors.
pub fn get_variable_timestamp(guid: &r_efi::efi::Guid, name: &[u16]) -> Option<VariableTimestamp> {
    let variable_store = VARSTORE.get();
    if !variable_store.initialized || !variable_store.auth_format {
        return None;
    }
    let guid = edk2::guid_to_bytes(guid);
    with_storage_mut(|storage| {
        let mut read_fn = |offset: u32, buffer: &mut [u8]| storage.read(offset, buffer).is_ok();
        let variables = edk2::walk_variables(&mut read_fn, true, variable_store.data_size);
        latest_matching_timestamp(&variables, &guid, name)
    })
    .flatten()
}

fn latest_matching_timestamp(
    variables: &[edk2::FvVariable],
    guid: &[u8; 16],
    name: &[u16],
) -> Option<VariableTimestamp> {
    variables
        .iter()
        .filter(|variable| edk2::is_var_added(variable.state))
        .filter(|variable| variable.guid == *guid && edk2::name_matches(&variable.name, name))
        .filter_map(|variable| variable.timestamp)
        .next_back()
}

/// Write a variable to storage using EDK2 FV format
///
/// The new prepared record is committed and verified before older records are
/// retired. The function never performs destructive single-bank compaction.
fn require_writable_store(initialized: bool, auth_format: bool) -> Result<(), VarStoreError> {
    if initialized && auth_format {
        Ok(())
    } else {
        Err(VarStoreError::NotInitialized)
    }
}

pub(crate) fn write_variable_to_storage_internal(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
    timestamp: Option<VariableTimestamp>,
) -> Result<(), VarStoreError> {
    let vs = VARSTORE.get();
    require_writable_store(vs.initialized, vs.auth_format)?;

    let guid_bytes = edk2::guid_to_bytes(guid);

    // Preflight a new record without changing the currently visible durable value.
    let record = edk2::build_variable_record(&guid_bytes, name, attributes, data, timestamp)
        .ok_or(VarStoreError::InvalidArgument)?;
    let record_len = record.len() as u32;

    let storage_size = with_storage_mut(|s| s.size()).ok_or(VarStoreError::NotInitialized)?;

    let mut write_offset = VARSTORE.get().write_offset;
    if !write_slot_available(write_offset, record_len, storage_size)? {
        compact_variable_store()?;
        write_offset = VARSTORE.get().write_offset;
        if !write_slot_available(write_offset, record_len, storage_size)? {
            return Err(VarStoreError::StoreFull);
        }
    }

    // Write the new record using multi-stage protocol
    let new_offset = with_storage_mut(|storage| {
        storage.with_program(|mut write| {
            edk2::write_variable(
                &mut write,
                write_offset,
                &guid_bytes,
                name,
                attributes,
                data,
                timestamp,
            )
        })
    })
    .ok_or(VarStoreError::NotInitialized)??
    .ok_or(VarStoreError::StorageFailure)?;

    let mut expected_record = record;
    if let Some(state) = expected_record.get_mut(2) {
        *state = edk2::VAR_ADDED;
    }
    verify_written_record(write_offset, &expected_record)?;

    // The new VAR_ADDED record is now durable and is the visible commit point.
    // Retirement cannot turn that committed outcome back into a reported
    // failure; a later compaction will reclaim any stale predecessor.
    VARSTORE.update(|vs| vs.write_offset = new_offset);
    if let Err(error) = delete_existing_record_except(&guid_bytes, name, Some(write_offset + 2)) {
        log::warn!(
            "Variable committed but predecessor retirement failed: {:?}",
            error
        );
    }

    log::debug!(
        "Variable persisted at offset {:#x}: {}",
        write_offset,
        variable_name_for_log(name).as_str()
    );
    Ok(())
}

fn write_slot_available(offset: u32, len: u32, storage_size: u32) -> Result<bool, VarStoreError> {
    Ok(offset
        .checked_add(len)
        .is_some_and(|end| end <= storage_size)
        && is_erased_for_write(offset, len)?)
}

/// Compact live EDK2 records when the append area is full.
///
/// The runtime-image bridge calls this only during BootActive. The current
/// SMMSTORE integration has one erasable region, so compaction is necessarily
/// a platform power-failure boundary; records are nevertheless rebuilt with
/// the normal header-valid then VAR_ADDED protocol rather than becoming
/// permanently unreclaimable after ordinary updates.
fn compact_variable_store() -> Result<(), VarStoreError> {
    let vs = VARSTORE.get();
    if !vs.initialized || !vs.auth_format {
        return Err(VarStoreError::StoreFull);
    }
    let vars = with_storage_mut(|storage| {
        let mut read_fn = |offset: u32, buf: &mut [u8]| storage.read(offset, buf).is_ok();
        edk2::walk_variables(&mut read_fn, vs.auth_format, vs.data_size)
    })
    .ok_or(VarStoreError::NotInitialized)?;
    let mut active = Vec::new();
    for variable in vars
        .into_iter()
        .filter(|variable| edk2::is_var_added(variable.state))
    {
        active.retain(|existing: &edk2::FvVariable| {
            !(existing.guid == variable.guid && edk2::name_matches(&existing.name, &variable.name))
        });
        active.push(variable);
    }
    let storage_size =
        with_storage_mut(|storage| storage.size()).ok_or(VarStoreError::NotInitialized)?;
    let end = with_storage_mut(|storage| {
        storage
            .erase(0, storage_size)
            .map_err(VarStoreError::from)?;
        storage
            .program(0, &edk2::build_fv_headers(storage_size))
            .map_err(VarStoreError::from)?;
        let mut offset = edk2::VARIABLE_DATA_OFFSET;
        for variable in &active {
            offset = storage
                .with_program(|mut write| {
                    edk2::write_variable(
                        &mut write,
                        offset,
                        &variable.guid,
                        &variable.name,
                        variable.attributes,
                        &variable.data,
                        variable.timestamp,
                    )
                })?
                .ok_or(VarStoreError::StorageFailure)?;
        }
        Ok::<u32, VarStoreError>(offset)
    })
    .ok_or(VarStoreError::NotInitialized)??;
    VARSTORE.update(|store| {
        store.write_offset = end;
    });
    log::info!(
        "Compacted variable store; retained {} live records",
        active.len()
    );
    Ok(())
}

/// Check that a flash range is erased before programming it.
fn is_erased_for_write(offset: u32, len: u32) -> Result<bool, VarStoreError> {
    const CHUNK_SIZE: usize = 256;

    with_storage_mut(|storage| {
        let mut remaining = len as usize;
        let mut current = offset;
        let mut buffer = [0u8; CHUNK_SIZE];

        while remaining > 0 {
            let chunk_len = remaining.min(CHUNK_SIZE);
            storage
                .read_controller(current, &mut buffer[..chunk_len])
                .map_err(VarStoreError::from)?;

            if buffer[..chunk_len].iter().any(|&byte| byte != 0xFF) {
                return Ok(false);
            }

            remaining -= chunk_len;
            current += chunk_len as u32;
        }

        Ok::<bool, VarStoreError>(true)
    })
    .ok_or(VarStoreError::NotInitialized)?
}

/// Verify completed media writes; the SPI adapter also diagnoses stale mapped reads.
fn verify_written_record(offset: u32, expected: &[u8]) -> Result<(), VarStoreError> {
    with_storage_mut(|storage| {
        let mut controller_bytes = alloc::vec![0; expected.len()];
        storage
            .read_controller(offset, &mut controller_bytes)
            .map_err(VarStoreError::from)?;

        if controller_bytes.as_slice() != expected {
            log_record_mismatch("controller", offset, expected, &controller_bytes);
            return Err(VarStoreError::StorageFailure);
        }

        if storage.has_mapped_read_base() {
            let mut mapped_bytes = alloc::vec![0; expected.len()];
            match storage.read(offset, &mut mapped_bytes) {
                Ok(()) if mapped_bytes.as_slice() != expected => {
                    log_record_mismatch("mapped", offset, expected, &mapped_bytes);
                    log::warn!(
                        "Variable store mapped readback differs from controller readback; \
                         subsequent reads may use stale or incorrectly resolved mapped flash"
                    );
                }
                Ok(()) => {}
                Err(e) => log::warn!("Variable store mapped readback failed: {:?}", e),
            }
        }

        Ok::<(), VarStoreError>(())
    })
    .ok_or(VarStoreError::NotInitialized)??;

    Ok(())
}

fn log_record_mismatch(kind: &str, offset: u32, expected: &[u8], actual: &[u8]) {
    let mismatch = expected
        .iter()
        .zip(actual.iter())
        .position(|(expected, actual)| expected != actual)
        .unwrap_or(0);
    let expected_byte = expected.get(mismatch).copied().unwrap_or(0);
    let actual_byte = actual.get(mismatch).copied().unwrap_or(0);

    log::error!(
        "Variable store {} readback mismatch at offset {:#x}+{:#x}: expected {:#04x}, got {:#04x}",
        kind,
        offset,
        mismatch,
        expected_byte,
        actual_byte
    );
}

fn variable_name_for_log(name: &[u16]) -> alloc::string::String {
    name.iter()
        .take_while(|&&ch| ch != 0)
        .map(|&ch| char::from_u32(ch as u32).unwrap_or('?'))
        .collect()
}

/// Delete a variable from storage by marking its record as deleted
///
/// The one-way state transition is verified by rereading the state byte.
pub(crate) fn write_variable_deletion_internal(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    timestamp: Option<VariableTimestamp>,
) -> Result<(), VarStoreError> {
    let vs = VARSTORE.get();
    require_writable_store(vs.initialized, vs.auth_format)?;
    if timestamp.is_some() {
        // An active zero-length authenticated record is invisible to coreboot's
        // variable reader but retains the verified deletion replay floor.
        return write_variable_to_storage_internal(guid, name, attributes, &[], timestamp);
    }

    let guid_bytes = edk2::guid_to_bytes(guid);
    delete_existing_record_except(&guid_bytes, name, None)
}

/// Find and mark as deleted any existing record with the given GUID+name
fn delete_existing_record_except(
    guid_bytes: &[u8; 16],
    name: &[u16],
    keep_state_offset: Option<u32>,
) -> Result<(), VarStoreError> {
    let vs = VARSTORE.get();
    require_writable_store(vs.initialized, vs.auth_format)?;
    let auth_format = vs.auth_format;
    let data_size = vs.data_size;

    // Walk all records to find matching ones
    let vars = with_storage_mut(|storage| {
        let mut read_fn =
            |offset: u32, buf: &mut [u8]| -> bool { storage.read(offset, buf).is_ok() };
        edk2::walk_variables(&mut read_fn, auth_format, data_size)
    })
    .ok_or(VarStoreError::NotInitialized)?;

    // Find and delete matching VAR_ADDED records
    for var in &vars {
        if Some(var.state_offset) != keep_state_offset
            && edk2::is_var_added(var.state)
            && var.guid == *guid_bytes
            && edk2::name_matches(&var.name, name)
        {
            // Mark as deleted by writing to the state byte
            let deleted = with_storage_mut(|storage| {
                storage.with_program(|mut write| edk2::mark_deleted(&mut write, var.state_offset))
            })
            .ok_or(VarStoreError::NotInitialized)??;

            if !deleted {
                log::warn!(
                    "Failed to mark variable as deleted at state_offset {:#x}",
                    var.state_offset
                );
                return Err(VarStoreError::StorageFailure);
            }
            let state_byte = with_storage_mut(|storage| {
                let mut byte = [0u8; 1];
                storage
                    .read_controller(var.state_offset, &mut byte)
                    .map_err(VarStoreError::from)?;
                Ok::<u8, VarStoreError>(byte[0])
            })
            .ok_or(VarStoreError::NotInitialized)??;
            if edk2::is_var_added(state_byte) {
                return Err(VarStoreError::StorageFailure);
            }

            log::debug!(
                "Marked existing variable as deleted at state_offset {:#x}",
                var.state_offset
            );
        }
    }

    Ok(())
}

/// Check if storage backend is available
pub fn is_storage_available() -> bool {
    with_storage_mut(|_| ()).is_some()
}

/// Check if variable store is initialized.
pub fn is_varstore_initialized() -> bool {
    VARSTORE.get().initialized
}

/// Check whether the initialized store accepts durable authenticated writes.
pub fn is_varstore_writable() -> bool {
    let store = VARSTORE.get();
    store.initialized
        && store.auth_format
        && with_storage_mut(|backend| !backend.is_write_protected()).unwrap_or(false)
}

/// Get variable store statistics
///
/// Returns (base_offset, size, write_offset)
pub fn get_varstore_stats() -> Option<(u32, u32, u32)> {
    let vs = VARSTORE.get();
    let (base, size) = with_storage_mut(|s| (s.base_offset(), s.size()))?;
    Some((base, size, vs.write_offset))
}

/// Durably write a firmware-private value, then import it through the
/// privileged pre-boot runtime-image interface.
pub(crate) fn persist_firmware_variable(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Result<(), VarStoreError> {
    let name_len = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    if name_len == 0 || name_len > crabefi_runtime_abi::MAX_VARIABLE_NAME_LEN {
        return Err(VarStoreError::InvalidArgument);
    }
    if data.len() > crabefi_runtime_abi::MAX_VARIABLE_DATA_SIZE {
        return Err(VarStoreError::DataTooLarge);
    }
    let data_len = u32::try_from(data.len()).map_err(|_| VarStoreError::DataTooLarge)?;
    let mut terminated_name = [0u16; crabefi_runtime_abi::MAX_VARIABLE_NAME_LEN + 1];
    terminated_name[..name_len].copy_from_slice(&name[..name_len]);
    write_variable_to_storage_internal(
        guid,
        &terminated_name[..=name_len],
        attributes,
        data,
        None,
    )?;

    let client = crate::efi::runtime_image::installed().ok_or(VarStoreError::NotInitialized)?;
    client
        .import_variable(&crabefi_runtime_abi::VariableImport {
            name_address: terminated_name.as_ptr() as u64,
            name_len: name_len as u32,
            attributes,
            guid: edk2::guid_to_bytes(guid),
            data_address: data.as_ptr() as u64,
            data_len,
            timestamp_valid: 0,
            timestamp: VariableTimestamp::default(),
        })
        .map_err(|status| match status {
            r_efi::efi::Status::OUT_OF_RESOURCES => VarStoreError::StoreFull,
            _ => VarStoreError::InvalidArgument,
        })
}

#[cfg(test)]
#[path = "backend_tests.rs"]
mod backend_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn variable(state: u8, timestamp: u16, data: Vec<u8>) -> edk2::FvVariable {
        edk2::FvVariable {
            guid: [0x5a; 16],
            name: vec![b'T' as u16, 0],
            attributes: 7,
            data,
            timestamp: Some(VariableTimestamp {
                year: timestamp,
                month: 1,
                day: 1,
                ..VariableTimestamp::default()
            }),
            state,
            state_offset: 0,
        }
    }

    #[test]
    fn timestamp_ignores_later_incomplete_and_retired_records() {
        let variables = vec![
            variable(edk2::VAR_ADDED, 2024, vec![1]),
            variable(0x7f, 2025, vec![2]),
            variable(0xfd, 2026, vec![3]),
        ];
        assert_eq!(
            latest_matching_timestamp(&variables, &[0x5a; 16], &[b'T' as u16]),
            Some(VariableTimestamp {
                year: 2024,
                month: 1,
                day: 1,
                ..VariableTimestamp::default()
            })
        );
    }

    #[test]
    fn timestamp_keeps_active_authenticated_deletion_floor() {
        let variables = vec![
            variable(edk2::VAR_ADDED, 2024, vec![1]),
            variable(edk2::VAR_ADDED, 2027, Vec::new()),
        ];
        assert_eq!(
            latest_matching_timestamp(&variables, &[0x5a; 16], &[b'T' as u16])
                .map(|timestamp| timestamp.year),
            Some(2027)
        );
    }

    #[test]
    fn preserved_legacy_store_rejects_every_write_path() {
        assert_eq!(
            require_writable_store(true, false),
            Err(VarStoreError::NotInitialized)
        );
        assert_eq!(
            require_writable_store(false, true),
            Err(VarStoreError::NotInitialized)
        );
        assert_eq!(require_writable_store(true, true), Ok(()));
    }

    #[test]
    fn standard_edk2_size_reaches_migration_preflight() {
        let storage_size = 256u32;
        let mut headers = edk2::build_fv_headers(storage_size);
        let vs_offset = edk2::FV_HEADER_LENGTH;
        let non_auth_guid = [
            0x16, 0x36, 0xcf, 0xdd, 0x75, 0x32, 0x64, 0x41, 0x98, 0xb6, 0xfe, 0x85, 0x70, 0x7f,
            0xfe, 0x7d,
        ];
        headers[vs_offset..vs_offset + 16].copy_from_slice(&non_auth_guid);
        let standard_size = storage_size - edk2::FV_HEADER_LENGTH as u32;
        headers[vs_offset + 0x10..vs_offset + 0x14].copy_from_slice(&standard_size.to_le_bytes());

        let validation = edk2::validate_fv(&headers, storage_size);
        assert!(validation.valid);
        assert!(!validation.auth_format);
        assert_eq!(
            preflight_non_auth_migration(storage_size, validation.data_size, &[]),
            Ok(edk2::VARIABLE_DATA_OFFSET)
        );
    }

    #[test]
    fn expanded_legacy_migration_is_preflighted_without_flash_mutation() {
        let storage_size = 256;
        let data_size = storage_size - edk2::VARIABLE_DATA_OFFSET;
        let variable = variable(edk2::VAR_ADDED, 0, vec![0xa5; 100]);
        // The legacy 32-byte header fits, while the 60-byte authenticated
        // record does not. Preflight fails before migration has any write path.
        let legacy_size = 32 + variable.name.len() * 2 + variable.data.len();
        assert!(legacy_size <= data_size as usize);
        assert_eq!(
            preflight_non_auth_migration(storage_size, data_size, &[variable]),
            Err(VarStoreError::StoreFull)
        );
    }
}
