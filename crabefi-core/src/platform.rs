//! Platform Abstraction Traits
//!
//! This module defines the traits that platform firmware must implement to
//! integrate CrabEFI. These traits decouple the UEFI implementation from
//! specific hardware, allowing CrabEFI to run on any platform that provides
//! the required services.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │           External Firmware                  │
//! │  (coreboot, custom ARM SoC, TF-A, ...)      │
//! │                                              │
//! │  Implements: BlockDevice, VariableBackend,   │
//! │  Timer, ResetHandler, DebugOutput, ...       │
//! └───────────────┬─────────────────────────────┘
//!                 │  PlatformConfig
//!                 ▼
//! ┌─────────────────────────────────────────────┐
//! │           CrabEFI Library                    │
//! │                                              │
//! │  UEFI Boot/Runtime Services, Secure Boot,   │
//! │  Boot Manager, Filesystem, PE Loader         │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # Quick Start
//!
//! External firmware builds a [`PlatformConfig`] by providing trait
//! implementations for the platform's hardware, then calls
//! [`crate::init_platform()`] to hand off to the UEFI boot manager.
//! This function never returns (`-> !`).
//!
//! ```ignore
//! let config = crabefi::PlatformConfig {
//!     memory_map: &my_memory_map,
//!     timer: &my_timer,
//!     timestamp_recorder: None,
//!     reset: &my_reset_handler,
//!     block_devices: &mut [&mut my_emmc],
//!     variable_backend: None, // direct VariableBackend routing is not wired yet
//!     variable_store_locator: None,
//!     // ...
//! };
//! crabefi::init_platform(config); // never returns
//! ```

use r_efi::efi::Guid;

// ============================================================================
// Memory Map
// ============================================================================

/// Physical memory region descriptor.
///
/// The platform provides a list of these to describe the system's physical
/// address space. CrabEFI converts them into the EFI memory map.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    /// Starting physical address (must be page-aligned, 4 KiB).
    pub base: u64,
    /// Size in bytes (must be page-aligned, 4 KiB).
    pub size: u64,
    /// Type of memory in this region.
    pub region_type: MemoryType,
}

/// Memory region types.
///
/// These map directly to EFI memory types. The platform uses them to describe
/// which physical address ranges are usable RAM, reserved, MMIO, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoryType {
    /// Usable RAM (becomes `EfiConventionalMemory`).
    Ram,
    /// Reserved by firmware (becomes `EfiReservedMemoryType`).
    Reserved,
    /// ACPI tables, reclaimable after OS reads them (becomes `EfiACPIReclaimMemory`).
    AcpiReclaimable,
    /// ACPI Non-Volatile Storage (becomes `EfiACPINvsMemory`).
    AcpiNvs,
    /// Memory-mapped I/O registers (becomes `EfiMemoryMappedIO`).
    Mmio,
    /// Runtime services code (becomes `EfiRuntimeServicesCode` with `EFI_MEMORY_RUNTIME`).
    RuntimeServicesCode,
    /// Runtime services data (becomes `EfiRuntimeServicesData` with `EFI_MEMORY_RUNTIME`).
    RuntimeServicesData,
    /// Boot services data (becomes `EfiBootServicesData`).
    ///
    /// Reclaimed as ConventionalMemory after `ExitBootServices`. Use for
    /// firmware regions that are not needed at runtime (e.g., firmware
    /// BSS/stack when CrabEFI is called as a library).
    BootServicesData,
}

// ============================================================================
// Block Device
// ============================================================================

/// Information about a block device.
///
/// Maps closely to `EFI_BLOCK_IO_MEDIA` from the UEFI specification.
#[derive(Clone, Copy, Debug)]
pub struct BlockDeviceInfo {
    /// Total number of logical blocks on the device.
    pub num_blocks: u64,
    /// Size of each logical block in bytes (typically 512).
    pub block_size: u32,
    /// Media identifier (changes if removable media is swapped).
    pub media_id: u32,
    /// Whether the device has removable media (e.g., USB stick, SD card).
    pub removable: bool,
    /// Whether the media is read-only.
    pub read_only: bool,
}

/// Errors returned by block device operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockError {
    /// Unspecified device error.
    DeviceError,
    /// Invalid parameter (bad LBA, buffer too small, etc.).
    InvalidParameter,
    /// LBA out of range for this device.
    OutOfRange,
    /// No media present (removable device with nothing inserted).
    NoMedia,
    /// Media changed since last access.
    MediaChanged,
}

/// Block-level storage device interface.
///
/// All storage devices that CrabEFI should be able to boot from must implement
/// this trait. The library installs `EFI_BLOCK_IO_PROTOCOL` handles for each
/// provided block device.
///
/// # Implementor's Guide
///
/// - `read_blocks` must handle arbitrary LBA ranges within bounds.
/// - `info()` should return consistent values for the device's lifetime.
/// - `name()` is displayed in the boot menu; make it descriptive
///   (e.g., `"NVMe: Samsung 980 Pro"`, `"eMMC: partition 0"`).
///
/// # Example
///
/// ```ignore
/// struct MyEmmc { base: u64, num_sectors: u64 }
///
/// impl crabefi::BlockDevice for MyEmmc {
///     fn info(&self) -> crabefi::BlockDeviceInfo {
///         crabefi::BlockDeviceInfo {
///             num_blocks: self.num_sectors,
///             block_size: 512,
///             media_id: 0,
///             removable: false,
///             read_only: false,
///         }
///     }
///     fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8])
///         -> Result<(), crabefi::BlockError>
///     {
///         // ... hardware-specific read ...
///         Ok(())
///     }
///     fn name(&self) -> &str { "eMMC" }
/// }
/// ```
pub trait BlockDevice {
    /// Get device information (block count, block size, media properties).
    fn info(&self) -> BlockDeviceInfo;

    /// Read contiguous blocks from the device.
    ///
    /// # Arguments
    /// * `lba` - Starting logical block address.
    /// * `count` - Number of blocks to read.
    /// * `buffer` - Destination buffer (must be at least `count * block_size` bytes).
    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError>;

    /// Human-readable device name for the boot menu.
    fn name(&self) -> &str {
        "Block Device"
    }

    /// Validate parameters for a read operation.
    ///
    /// Default implementation checks LBA range and buffer size. Implementations
    /// should call this at the start of `read_blocks`.
    fn validate_read(&self, lba: u64, count: u32, buffer: &[u8]) -> Result<(), BlockError> {
        let info = self.info();
        if count == 0 {
            return Ok(());
        }
        let end_lba = lba
            .checked_add(count as u64)
            .ok_or(BlockError::OutOfRange)?;
        if end_lba > info.num_blocks {
            return Err(BlockError::OutOfRange);
        }
        let required = (count as usize)
            .checked_mul(info.block_size as usize)
            .ok_or(BlockError::InvalidParameter)?;
        if buffer.len() < required {
            return Err(BlockError::InvalidParameter);
        }
        Ok(())
    }

    /// Read a single block (convenience wrapper).
    fn read_block(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.read_blocks(lba, 1, buffer)
    }
}

// ============================================================================
// Variable Persistence
// ============================================================================

/// Errors returned by variable backend operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VarBackendError {
    /// Backend not initialized or not available.
    NotAvailable,
    /// Storage is full; cannot write more variables.
    StoreFull,
    /// I/O or communication error.
    IoError,
    /// Backend is locked (e.g., flash locked after ExitBootServices).
    Locked,
    /// Variable not found (for load/delete operations).
    NotFound,
    /// Data too large for the backend's capacity.
    DataTooLarge,
    /// Name too long for the backend's capacity.
    NameTooLong,
    /// Backend-specific error.
    Other,
}

/// Visitor interface for loading persisted variables.
///
/// The [`VariableBackend::load()`] method calls [`visit()`](Self::visit) once
/// per stored variable. CrabEFI provides the visitor; the backend just calls it.
pub trait VariableVisitor {
    /// Called for each variable found in persistent storage.
    ///
    /// # Arguments
    /// * `name` - Variable name as UTF-16LE code units (without null terminator).
    /// * `vendor` - Variable vendor GUID.
    /// * `attributes` - EFI variable attributes (`EFI_VARIABLE_*` flags).
    /// * `data` - Variable data payload (after any auth header stripping).
    fn visit(&mut self, name: &[u16], vendor: &Guid, attributes: u32, data: &[u8]);
}

/// EFI variable persistence backend.
///
/// This trait abstracts how EFI variables are stored across boots. Implementations
/// range from direct flash storage to SMM/TF-A MM RPC-based approaches.
///
/// # Backend Categories
///
/// | Category | `runtime_capable()` | Deferred buffer needed? | Example |
/// |----------|---------------------|------------------------|---------|
/// | Direct flash | `false` | Yes | SPI flash via `Edk2VarStore` |
/// | SMM | `true` | No | x86 SMI-based variable service |
/// | TF-A MM | `true` | No | Arm StandaloneMM via FF-A/SPM |
/// | RAM-only | `false` | Optional | Testing, volatile variables |
///
/// # Lifecycle
///
/// 1. [`load()`](Self::load) — Called once during early boot to populate the
///    in-memory variable cache. The backend calls `visitor.visit()` for each
///    stored variable.
///
/// 2. [`write()`](Self::write) / [`delete()`](Self::delete) — Called by
///    `SetVariable` when variables change.
///    - Before `ExitBootServices`: always called.
///    - After `ExitBootServices`: called only if `runtime_capable()` returns `true`.
///      Otherwise, CrabEFI buffers the write in the deferred buffer.
///
/// 3. [`notify_exit_boot_services()`](Self::notify_exit_boot_services) — Called
///    when `ExitBootServices` succeeds. The backend can release resources or
///    adjust its strategy (e.g., direct-flash backends note that flash is now locked).
///
/// 4. [`flush_deferred()`](Self::flush_deferred) — Called on the *next* boot
///    (after `load()`) to commit any writes that were buffered during the
///    previous boot's runtime phase. Only relevant for non-runtime-capable backends.
///
/// # Example: SMM Backend
///
/// ```ignore
/// struct SmmVarStore { smi_port: u16, comm_buffer: *mut u8 }
///
/// impl crabefi::VariableBackend for SmmVarStore {
///     fn load(&mut self, visitor: &mut dyn crabefi::VariableVisitor)
///         -> Result<(), crabefi::VarBackendError>
///     {
///         // Trigger SMI to enumerate variables, call visitor.visit() for each
///         Ok(())
///     }
///
///     fn write(&mut self, name: &[u16], vendor: &Guid, attrs: u32, data: &[u8])
///         -> Result<(), crabefi::VarBackendError>
///     {
///         // Trigger SMI with SetVariable command
///         Ok(())
///     }
///
///     fn delete(&mut self, name: &[u16], vendor: &Guid)
///         -> Result<(), crabefi::VarBackendError>
///     {
///         // Trigger SMI with delete command
///         Ok(())
///     }
///
///     fn runtime_capable(&self) -> bool { true }
/// }
/// ```
pub trait VariableBackend {
    /// Load all persisted variables into the in-memory cache.
    ///
    /// Called once during early boot. The backend iterates its stored variables
    /// and calls `visitor.visit()` for each one.
    fn load(&mut self, visitor: &mut dyn VariableVisitor) -> Result<(), VarBackendError>;

    /// Persist a variable write (create or update).
    ///
    /// Called when `SetVariable` is invoked with non-empty data.
    ///
    /// # Arguments
    /// * `name` - Variable name as UTF-16LE code units.
    /// * `vendor` - Variable vendor GUID.
    /// * `attributes` - EFI variable attributes.
    /// * `data` - Variable data payload.
    fn write(
        &mut self,
        name: &[u16],
        vendor: &Guid,
        attributes: u32,
        data: &[u8],
    ) -> Result<(), VarBackendError>;

    /// Persist a variable deletion.
    ///
    /// Called when `SetVariable` is invoked with empty data and
    /// `EFI_VARIABLE_APPEND_WRITE` is not set.
    fn delete(&mut self, name: &[u16], vendor: &Guid) -> Result<(), VarBackendError>;

    /// Whether this backend supports writes after `ExitBootServices`.
    ///
    /// - `true`: CrabEFI calls `write()`/`delete()` directly at runtime.
    ///   Suitable for SMM, TF-A MM, or any backend with a privileged agent.
    /// - `false` (default): CrabEFI buffers runtime writes in the deferred
    ///   buffer and calls `flush_deferred()` on the next boot.
    fn runtime_capable(&self) -> bool {
        false
    }

    /// Notification that `ExitBootServices` has been called.
    ///
    /// For direct-flash backends, this signals that flash may now be locked.
    /// For SMM/MM backends, this is typically a no-op.
    fn notify_exit_boot_services(&mut self) {}

    /// Commit deferred writes from a previous boot.
    ///
    /// Called after `load()` on the next boot when the previous boot had
    /// buffered runtime variable writes (because `runtime_capable()` was false).
    ///
    /// # Arguments
    /// * `records` - Iterator of (name, vendor, attributes, data) for each
    ///   deferred write. Empty data means delete.
    ///
    /// The default implementation calls `write()` or `delete()` for each record.
    fn flush_deferred(
        &mut self,
        records: &mut dyn Iterator<Item = (&[u16], &Guid, u32, &[u8])>,
    ) -> Result<usize, VarBackendError> {
        let mut count = 0;
        for (name, vendor, attrs, data) in records {
            if data.is_empty() {
                // Ignore NotFound for deletes — variable may not exist
                match self.delete(name, vendor) {
                    Ok(()) | Err(VarBackendError::NotFound) => {}
                    Err(e) => return Err(e),
                }
            } else {
                self.write(name, vendor, attrs, data)?;
            }
            count += 1;
        }
        Ok(count)
    }
}

// ============================================================================
// Raw Storage Backend
// ============================================================================

/// Errors returned by raw storage operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StorageError {
    /// Storage device not initialized.
    NotInitialized,
    /// Storage is write-protected.
    WriteProtected,
    /// Access denied (locked region).
    AccessDenied,
    /// Operation timed out.
    Timeout,
    /// Invalid address or length.
    InvalidArgument,
    /// Generic I/O error.
    IoError,
    /// Operation not supported by this backend.
    NotSupported,
}

/// Byte range within a firmware storage device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareStorageRegion {
    /// Absolute byte offset from the start of the firmware storage device.
    pub offset: u64,
    /// Region size in bytes.
    pub size: u64,
}

/// CPU-visible mapping window for a firmware storage device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareMmapWindow {
    /// Physical address where this storage window is visible to the CPU.
    pub phys_base: u64,
    /// Firmware-storage offset corresponding to [`Self::phys_base`].
    pub storage_offset: u64,
    /// Window size in bytes.
    pub size: u64,
}

/// Platform-described firmware storage location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareStorageLocation {
    /// The platform already described the region as a firmware-storage offset.
    Offset(FirmwareStorageRegion),
    /// The platform described the region as a firmware-storage offset, and also
    /// provided a CPU-visible read mapping for the same bytes.
    OffsetWithMappedRead {
        /// Absolute byte range in firmware storage.
        region: FirmwareStorageRegion,
        /// Physical address where `region.offset` is readable by the CPU.
        phys_base: u64,
    },
    /// The platform described the region by its CPU-visible physical mapping.
    Mapped {
        /// Physical base address of the mapped storage region.
        phys_base: u64,
        /// Region size in bytes.
        size: u64,
    },
}

/// Firmware storage access used for persistent variable storage.
///
/// All read/write/erase operations are addressed by absolute firmware-storage
/// offsets. Platforms that describe regions by CPU-visible memory mappings can
/// expose generic mmap windows or override [`resolve_mapped_region()`](Self::resolve_mapped_region)
/// to translate those physical addresses into storage offsets.
pub trait FirmwareStorage {
    /// Backend name for logging.
    fn name(&self) -> &str;

    /// Total storage capacity in bytes, if known.
    fn capacity(&self) -> Option<u64> {
        None
    }

    /// CPU-visible mapping windows for this storage device, if known.
    fn mmap_windows(&self) -> &[FirmwareMmapWindow] {
        &[]
    }

    /// Resolve a platform-described location to an offset-addressed region.
    fn resolve_location(&self, location: FirmwareStorageLocation) -> Option<FirmwareStorageRegion> {
        match location {
            FirmwareStorageLocation::Offset(region)
            | FirmwareStorageLocation::OffsetWithMappedRead { region, .. } => {
                self.validate_region(region)
            }
            FirmwareStorageLocation::Mapped { phys_base, size } => {
                self.resolve_mapped_region(phys_base, size)
            }
        }
    }

    /// Validate that an offset-addressed region is internally consistent and,
    /// when capacity is known, contained within this storage device.
    fn validate_region(&self, region: FirmwareStorageRegion) -> Option<FirmwareStorageRegion> {
        if region.size == 0 {
            return None;
        }

        let end = region.offset.checked_add(region.size)?;
        if let Some(capacity) = self.capacity()
            && end > capacity
        {
            return None;
        }

        Some(region)
    }

    /// Resolve a CPU-visible physical mapping to a firmware-storage offset.
    fn resolve_mapped_region(&self, phys_base: u64, size: u64) -> Option<FirmwareStorageRegion> {
        if size == 0 {
            return None;
        }

        self.mmap_windows().iter().find_map(|window| {
            let relative = phys_base.checked_sub(window.phys_base)?;
            let mapped_end = relative.checked_add(size)?;
            if mapped_end > window.size {
                return None;
            }

            let offset = window.storage_offset.checked_add(relative)?;
            self.validate_region(FirmwareStorageRegion { offset, size })
        })
    }

    /// Enable writes to the storage backend.
    fn enable_writes(&mut self) -> Result<(), StorageError>;

    /// Read bytes from storage at an absolute storage offset.
    fn read(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), StorageError>;

    /// Write bytes to storage at an absolute storage offset.
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), StorageError>;

    /// Erase bytes in storage at an absolute storage offset.
    fn erase(&mut self, offset: u64, size: u64) -> Result<(), StorageError>;
}

/// A located variable-store region in firmware storage.
#[derive(Debug, Clone)]
pub struct VariableStoreRegion {
    /// Region name for logging, for example `SMMSTORE`.
    pub name: heapless::String<32>,
    /// Platform-described storage location.
    pub location: FirmwareStorageLocation,
}

impl VariableStoreRegion {
    /// Create an offset-addressed variable-store region descriptor.
    ///
    /// # Arguments
    /// * `name` - Human-readable region name. Names longer than 32 bytes are
    ///   truncated for logging.
    /// * `offset` - Absolute byte offset from the start of firmware storage.
    /// * `size` - Region size in bytes.
    pub fn from_offset(name: &str, offset: u64, size: u64) -> Self {
        Self::new(
            name,
            FirmwareStorageLocation::Offset(FirmwareStorageRegion { offset, size }),
        )
    }

    /// Create an offset-addressed variable-store region descriptor with a
    /// CPU-visible read mapping for the same bytes.
    ///
    /// # Arguments
    /// * `name` - Human-readable region name. Names longer than 32 bytes are
    ///   truncated for logging.
    /// * `offset` - Absolute byte offset from the start of firmware storage.
    /// * `phys_base` - CPU-visible physical mapping address for `offset`.
    /// * `size` - Region size in bytes.
    pub fn from_offset_with_mapped_read(
        name: &str,
        offset: u64,
        phys_base: u64,
        size: u64,
    ) -> Self {
        Self::new(
            name,
            FirmwareStorageLocation::OffsetWithMappedRead {
                region: FirmwareStorageRegion { offset, size },
                phys_base,
            },
        )
    }

    /// Create a mapped variable-store region descriptor.
    ///
    /// # Arguments
    /// * `name` - Human-readable region name. Names longer than 32 bytes are
    ///   truncated for logging.
    /// * `phys_base` - CPU-visible physical mapping address.
    /// * `size` - Region size in bytes.
    pub fn from_mapped(name: &str, phys_base: u64, size: u64) -> Self {
        Self::new(name, FirmwareStorageLocation::Mapped { phys_base, size })
    }

    fn new(name: &str, location: FirmwareStorageLocation) -> Self {
        let mut region_name = heapless::String::new();
        for ch in name.chars() {
            if region_name.push(ch).is_err() {
                break;
            }
        }

        Self {
            name: region_name,
            location,
        }
    }
}

/// Platform-specific locator for the persistent EFI variable store.
///
/// CrabEFI's library code knows how to read and write an EDK2 variable store
/// once it has resolved a raw storage region, but it does not know how a
/// platform describes its flash layout. Coreboot can implement this by checking
/// SMMSTORE table records and FMAP; other integrations can use device-tree
/// properties, fixed board configuration, SMM, or any other platform-specific
/// mechanism.
pub trait VariableStoreLocator {
    /// Locate the persistent EFI variable-store region.
    ///
    /// # Arguments
    /// * `storage` - Firmware storage access for probing layout metadata.
    ///
    /// # Returns
    /// The storage location to use, or `None` if this platform has no persistent
    /// variable store available.
    fn locate_variable_store(
        &self,
        storage: &mut dyn FirmwareStorage,
    ) -> Option<VariableStoreRegion>;
}

/// Raw byte-level storage backend.
///
/// This trait provides low-level read/write/erase access to a storage device.
/// It is used by [`crate::efi::varstore::Edk2VarStore`] to implement the
/// EDK2 Firmware Volume format on top of raw flash.
///
/// Platform firmware that uses SMM or TF-A MM should implement
/// [`VariableBackend`] directly instead of this trait.
///
/// # Flash Semantics
///
/// - `read` works on any valid offset.
/// - `write` may require the region to be erased first (NOR flash: can only
///   clear bits 1→0).
/// - `erase` sets bytes to `0xFF` (NOR flash erased state).
pub trait StorageBackend: Send {
    /// Backend name for logging.
    fn name(&self) -> &str;

    /// Total storage size in bytes.
    fn size(&self) -> u32;

    /// Whether the storage is currently write-protected.
    fn is_write_protected(&self) -> bool;

    /// Enable writes (may clear hardware write-protection bits).
    fn enable_writes(&mut self) -> Result<(), StorageError>;

    /// Read data from storage.
    fn read(&mut self, offset: u32, buffer: &mut [u8]) -> Result<(), StorageError>;

    /// Write data to storage.
    ///
    /// For flash: the target region should be erased first.
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError>;

    /// Erase a region (sets bytes to `0xFF`).
    fn erase(&mut self, offset: u32, size: u32) -> Result<(), StorageError>;
}

// ============================================================================
// Capsule Update
// ============================================================================

/// Firmware identity and version information.
///
/// Used by the ESRT (EFI System Resource Table) to advertise firmware
/// components to the OS, and by the capsule update logic to validate
/// incoming update images (GUID match, version >= LSV).
///
/// Platform firmware populates this from:
/// - Coreboot's `LB_TAG_EFI_FW_INFO` table entry
/// - Build-time configuration
/// - Device tree / ACPI tables
#[derive(Debug, Clone, Copy)]
pub struct FirmwareInfo {
    /// Firmware class GUID (identifies this firmware component for updates).
    ///
    /// This GUID must match between the installed firmware, the ESRT entry,
    /// and the capsule's `UpdateImageTypeId` for an update to be accepted.
    pub guid: [u8; 16],

    /// Current firmware version.
    ///
    /// Higher values represent more recent versions. Encoding is
    /// platform-defined; coreboot uses `(major << 16) | minor`.
    pub version: u32,

    /// Lowest supported firmware version (rollback prevention).
    ///
    /// Capsule updates with a version below this value are rejected.
    /// Typically set equal to the current version or to a known-good
    /// minimum.
    pub lowest_supported_version: u32,

    /// Size of the firmware image in bytes.
    pub fw_size: u32,
}

/// A region of memory containing a single coalesced capsule.
///
/// These are produced by coreboot's capsule parsing code (from
/// `CapsuleUpdateData*` EFI variables) and published as
/// `LB_TAG_CAPSULE` entries in the coreboot table.
#[derive(Debug, Clone, Copy)]
pub struct CapsuleRegion {
    /// Physical base address of the capsule data in memory.
    pub base: u64,
    /// Size of the capsule data in bytes.
    pub size: u32,
}

/// An FMAP region descriptor.
///
/// Represents a named region within the SPI flash layout. Used by the
/// capsule update logic to validate RMAP manifests and determine where
/// firmware images should be written.
#[derive(Debug, Clone)]
pub struct FmapRegion {
    /// Region name (e.g., "COREBOOT", "SMMSTORE", "FMAP")
    pub name: heapless::String<32>,
    /// Offset within the flash device
    pub offset: u32,
    /// Size in bytes
    pub size: u32,
}

/// Capsule update backend.
///
/// Implemented by platform firmware to provide the low-level operations
/// needed for capsule update support. The capsule processing library
/// (`efi::capsule`) calls these methods during capsule application.
///
/// # Trust Model
///
/// The `capsule_trust_store()` method provides the root certificates
/// used to verify capsule PKCS#7 signatures. These are separate from
/// Secure Boot's `db`/`dbx` — a capsule can be signed by a different
/// key than the boot images.
pub trait CapsuleBackend {
    /// Firmware identity and version information.
    ///
    /// Returns `None` if the platform doesn't support capsule updates.
    fn firmware_info(&self) -> Option<&FirmwareInfo>;

    /// DER-encoded X.509 certificates trusted for capsule signature verification.
    ///
    /// Returns an empty slice if capsule authentication is not configured
    /// (which means all capsules will be rejected when auth is enforced).
    fn capsule_trust_store(&self) -> &[&[u8]];

    /// Write a firmware image to a named FMAP region.
    ///
    /// The implementation should:
    /// 1. Enable writes on the storage backend
    /// 2. Erase the target region
    /// 3. Write the image data
    ///
    /// `offset` is relative to the start of the named region.
    fn write_firmware_region(
        &mut self,
        region_name: &str,
        offset: u32,
        data: &[u8],
    ) -> Result<(), StorageError>;

    /// Get all FMAP regions for RMAP manifest validation.
    fn fmap_regions(&self) -> &[FmapRegion];
}

// ============================================================================
// Platform lifecycle hooks
// ============================================================================

/// Optional platform callbacks for UEFI lifecycle transitions.
///
/// Platforms use these hooks for integration-specific cleanup that the core
/// library must not know about (for example invalidating platform handoff data
/// or disabling non-runtime debug buffers before the OS takes over).
pub trait PlatformHooks {
    /// Called after `ExitBootServices()` succeeds, before the system table's
    /// Boot Services pointer is cleared.
    fn on_exit_boot_services(&self) {}

    /// Called at the start of `SetVirtualAddressMap()`, before CrabEFI commits
    /// to virtual mode.
    fn before_set_virtual_address_map(&self) {}

    /// Return whether the platform exposes a firmware settings UI.
    fn firmware_settings_available(&self) -> bool {
        false
    }

    /// Show the platform-specific firmware settings UI.
    ///
    /// Returns `true` when a platform UI was shown and `false` when the
    /// platform has no firmware settings provider.
    fn show_firmware_settings(&self) -> bool {
        false
    }
}

// ============================================================================
// Timer
// ============================================================================

/// Monotonic timer / clock source.
///
/// Provides time measurement for UEFI `Stall()` boot service, EFI timer
/// events, and internal timeout handling.
///
/// # Implementation Notes
///
/// - The counter must be monotonically increasing and not wrap during a single
///   boot (64-bit counters at GHz frequencies won't wrap for centuries).
/// - `stall()` must busy-wait for at least the requested duration.
/// - The timer does not need to survive `ExitBootServices` (UEFI timer events
///   are boot-services-only).
pub trait Timer {
    /// Read the current monotonic counter value.
    fn current_ticks(&self) -> u64;

    /// Counter frequency in Hz.
    ///
    /// For x86 TSC at 2 GHz, return `2_000_000_000`.
    /// For ARM Generic Timer at 62.5 MHz, return `62_500_000`.
    fn ticks_per_second(&self) -> u64;

    /// Busy-wait for at least the given number of microseconds.
    ///
    /// Works correctly for any timer frequency >= 1 Hz. For timers
    /// below 1 MHz, the computation avoids integer truncation by
    /// scaling in the opposite order.
    fn stall(&self, microseconds: u64) {
        let start = self.current_ticks();
        let freq = self.ticks_per_second();
        if freq == 0 {
            return;
        }
        // Compute target ticks = microseconds * freq / 1_000_000.
        // Use u128 intermediate to avoid overflow for large stall durations
        // at high frequencies (e.g., 2 GHz * 10_000_000 us overflows u64).
        let target = ((microseconds as u128 * freq as u128) / 1_000_000) as u64;
        if target == 0 {
            return;
        }
        while self.current_ticks().wrapping_sub(start) < target {
            core::hint::spin_loop();
        }
    }
}

// ============================================================================
// Boot Timestamp Recording
// ============================================================================

/// Platform boot timestamp sink.
///
/// CrabEFI records well-known boot milestones through this trait. Platforms
/// that have a firmware-visible timestamp log (for example coreboot's CBMEM
/// timestamp table) can implement this trait and pass it in
/// [`PlatformConfig::timestamp_recorder`]. Platforms without such a facility
/// can leave the field as `None`; timestamp recording then becomes a no-op.
pub trait TimestampRecorder {
    /// Record the current platform timestamp for `id`.
    fn record(&self, id: u32);
}

// ============================================================================
// Reset
// ============================================================================

/// Reset type for `ResetSystem` runtime service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResetType {
    /// Cold reset (full power cycle).
    Cold,
    /// Warm reset (CPU reset without full power cycle).
    Warm,
    /// System shutdown (power off).
    Shutdown,
}

/// System reset and shutdown handler.
///
/// Used by the UEFI `ResetSystem` runtime service. The implementation must
/// be in memory that remains mapped after `ExitBootServices` (runtime-safe).
///
/// # Safety Contract
///
/// Since `ResetSystem` is a runtime service, the platform must ensure that
/// the `ResetHandler` implementation and its vtable reside in memory marked
/// as `RuntimeServicesCode` or `RuntimeServicesData`.
pub trait ResetHandler {
    /// Perform a system reset or shutdown.
    ///
    /// This function must not return.
    fn reset(&self, reset_type: ResetType) -> !;
}

// ============================================================================
// Random Number Generation
// ============================================================================

/// Errors returned by the RNG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngError {
    /// No hardware RNG available.
    Unsupported,
    /// Hardware RNG failure.
    HardwareError,
    /// RNG not ready (transient, caller should retry).
    NotReady,
}

/// Hardware random number generator.
///
/// Used by the UEFI `EFI_RNG_PROTOCOL`. Implementations should use a
/// hardware entropy source (e.g., x86 RDRAND/RDSEED, ARM RNDR).
pub trait Rng {
    /// Fill `buffer` with random bytes.
    fn get_random(&self, buffer: &mut [u8]) -> Result<(), RngError>;
}

// ============================================================================
// Debug Output
// ============================================================================

/// Debug/log output channel (serial port or equivalent).
///
/// CrabEFI uses this for `log` crate output and EFI `SerialIO` protocol.
/// The implementation should be safe to call from any context (including
/// panic handlers), so it must not allocate or take locks that could deadlock.
///
/// For the coreboot target, the implementation typically multiplexes output
/// to a UART and the CBMEM console.
pub trait DebugOutput: core::fmt::Write + Send {
    /// Write a single byte. Must not block indefinitely.
    fn write_byte(&mut self, byte: u8);

    /// Try to read a byte (for serial console input on the debug channel).
    /// Returns `None` if no data is available.
    fn try_read_byte(&self) -> Option<u8> {
        None
    }

    /// Check if input data is available on the debug channel.
    fn has_input(&self) -> bool {
        false
    }
}

// ============================================================================
// Console Input
// ============================================================================

/// Key event from a console input device.
///
/// Maps to `EFI_INPUT_KEY` from the UEFI specification.
#[derive(Debug, Clone, Copy)]
pub struct Key {
    /// EFI scan code (0 = no scan code, use `unicode_char`).
    /// Non-zero for special keys: Up=0x01, Down=0x02, Right=0x03, Left=0x04,
    /// Home=0x05, End=0x06, Insert=0x07, Delete=0x08, PgUp=0x09, PgDn=0x0A,
    /// F1..F10=0x0B..0x14, Esc=0x17.
    pub scancode: u16,
    /// Unicode character (0 = no character, use `scancode`).
    pub unicode_char: u16,
}

/// Key state for extended keyboard protocols.
///
/// Maps to `EFI_KEY_STATE` from `EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL`.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyState {
    /// Shift key state flags (`EFI_SHIFT_STATE_VALID | LEFT_SHIFT_PRESSED | ...`).
    pub shift_state: u32,
    /// Toggle state flags (`TOGGLE_STATE_VALID | NUM_LOCK_ACTIVE | ...`).
    pub toggle_state: u8,
}

/// Console input device (keyboard or equivalent).
///
/// The platform provides this to handle keyboard input for the UEFI console
/// protocols (`SimpleTextInput`, `SimpleTextInputEx`) and the boot menu.
///
/// A typical implementation polls all available input sources (PS/2, USB HID,
/// serial console) and returns the first available key.
pub trait ConsoleInput {
    /// Try to read a key press. Returns `None` if no key is available.
    fn read_key(&mut self) -> Option<Key>;

    /// Check if a key press is available without consuming it.
    fn has_key(&self) -> bool;

    /// Get the current key state (modifier keys, toggle state).
    /// Returns default (all zeros) if not supported.
    fn key_state(&self) -> KeyState {
        KeyState::default()
    }

    /// Perform any necessary polling (e.g., USB controller polling).
    /// Called periodically by the boot manager and console protocols.
    fn poll(&mut self) {}
}

// ============================================================================
// Framebuffer
// ============================================================================

/// Framebuffer configuration for the Graphics Output Protocol.
///
/// The platform provides this when a framebuffer is available. CrabEFI uses
/// it for the EFI GOP protocol and the text-mode boot menu.
#[derive(Debug, Clone, Copy)]
pub struct FramebufferConfig {
    /// Physical address of the framebuffer memory.
    pub physical_address: u64,
    /// Horizontal resolution in pixels.
    pub width: u32,
    /// Vertical resolution in pixels.
    pub height: u32,
    /// Pixels per scanline (may be wider than `width` due to alignment).
    ///
    /// To get bytes per scanline, multiply by `bits_per_pixel / 8`.
    pub stride: u32,
    /// Bits per pixel (typically 32).
    pub bits_per_pixel: u8,
    /// Bit position of the red channel.
    pub red_mask_pos: u8,
    /// Number of bits in the red channel.
    pub red_mask_size: u8,
    /// Bit position of the green channel.
    pub green_mask_pos: u8,
    /// Number of bits in the green channel.
    pub green_mask_size: u8,
    /// Bit position of the blue channel.
    pub blue_mask_pos: u8,
    /// Number of bits in the blue channel.
    pub blue_mask_size: u8,
}

impl FramebufferConfig {
    /// Framebuffer size in bytes.
    pub fn size(&self) -> u64 {
        self.bytes_per_line() as u64 * self.height as u64
    }

    /// Bytes per scanline (`stride * bytes_per_pixel`).
    pub fn bytes_per_line(&self) -> u32 {
        self.stride * (self.bits_per_pixel as u32 / 8)
    }

    /// Raw pointer to the framebuffer.
    pub fn as_ptr(&self) -> *mut u8 {
        core::ptr::with_exposed_provenance_mut(self.physical_address as usize)
    }

    /// Byte offset for a pixel at coordinates (x, y).
    ///
    /// Uses `u64` intermediates to avoid overflow on large framebuffers.
    pub fn pixel_offset(&self, x: u32, y: u32) -> usize {
        let bpp = self.bits_per_pixel as u64 / 8;
        (y as u64 * self.stride as u64 * bpp + x as u64 * bpp) as usize
    }

    /// Encode a pixel value for the framebuffer's native format.
    ///
    /// For 32bpp, returns the native pixel encoding.
    /// For 16bpp, returns the 16-bit pixel zero-extended to u32.
    /// For other bpp, returns 0.
    pub fn encode_pixel(&self, r: u8, g: u8, b: u8) -> u32 {
        match self.bits_per_pixel {
            32 => self.encode_pixel_32(r, g, b),
            16 => self.encode_pixel_16(r, g, b) as u32,
            _ => 0,
        }
    }

    /// Write a pixel at (x, y) with the given RGB color.
    ///
    /// # Safety
    ///
    /// The framebuffer must be accessible and (x, y) must be in bounds.
    pub unsafe fn write_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8) {
        if x >= self.width || y >= self.height {
            return;
        }
        let offset = self.pixel_offset(x, y);
        let fb = self.as_ptr();
        unsafe {
            match self.bits_per_pixel {
                32 => {
                    let pixel = self.encode_pixel_32(r, g, b);
                    (fb.add(offset) as *mut u32).write_volatile(pixel);
                }
                24 => {
                    let ptr = fb.add(offset);
                    if self.blue_mask_pos < self.red_mask_pos {
                        ptr.write_volatile(b);
                        ptr.add(1).write_volatile(g);
                        ptr.add(2).write_volatile(r);
                    } else {
                        ptr.write_volatile(r);
                        ptr.add(1).write_volatile(g);
                        ptr.add(2).write_volatile(b);
                    }
                }
                16 => {
                    let pixel = self.encode_pixel_16(r, g, b);
                    (fb.add(offset) as *mut u16).write_volatile(pixel);
                }
                _ => {}
            }
        }
    }

    /// Fill a framebuffer region with a solid color.
    ///
    /// # Safety
    ///
    /// `dst` must point to `pixel_count * (bits_per_pixel/8)` writable bytes
    /// within the framebuffer.
    pub unsafe fn fill_pixels(&self, dst: *mut u8, pixel_count: usize, r: u8, g: u8, b: u8) {
        unsafe {
            match self.bits_per_pixel {
                32 => {
                    let pixel = self.encode_pixel_32(r, g, b);
                    let ptr = dst as *mut u32;
                    for i in 0..pixel_count {
                        ptr.add(i).write_volatile(pixel);
                    }
                }
                16 => {
                    let pixel = self.encode_pixel_16(r, g, b);
                    let ptr = dst as *mut u16;
                    for i in 0..pixel_count {
                        ptr.add(i).write_volatile(pixel);
                    }
                }
                _ => {
                    core::slice::from_raw_parts_mut(
                        dst,
                        pixel_count * (self.bits_per_pixel as usize / 8),
                    )
                    .fill(0);
                }
            }
        }
    }

    /// Fill the entire framebuffer with a solid color.
    ///
    /// # Safety
    ///
    /// The framebuffer must be accessible.
    pub unsafe fn fill_solid(&self, r: u8, g: u8, b: u8) {
        let bpl = self.bytes_per_line() as usize;
        let row_pixels = self.width as usize;
        let packed = bpl == row_pixels * (self.bits_per_pixel as usize / 8);
        // SAFETY: caller guarantees the framebuffer is identity-mapped.
        unsafe {
            let fb = self.as_ptr();
            if packed {
                let total = row_pixels * self.height as usize;
                self.fill_pixels(fb, total, r, g, b);
            } else {
                for y in 0..self.height {
                    let offset = (y as usize) * bpl;
                    self.fill_pixels(fb.add(offset), row_pixels, r, g, b);
                }
            }
        }
    }

    /// Clear the entire framebuffer.
    ///
    /// # Safety
    ///
    /// The framebuffer must be accessible.
    pub unsafe fn clear(&self, r: u8, g: u8, b: u8) {
        let fb = self.as_ptr();
        let bpl = self.bytes_per_line() as usize;
        unsafe {
            match self.bits_per_pixel {
                32 => {
                    let pixel = self.encode_pixel_32(r, g, b);
                    for y in 0..self.height as usize {
                        let row = fb.add(y * bpl);
                        for x in 0..self.width as usize {
                            (row.add(x * 4) as *mut u32).write_volatile(pixel);
                        }
                    }
                }
                _ => {
                    for y in 0..self.height {
                        for x in 0..self.width {
                            self.write_pixel(x, y, r, g, b);
                        }
                    }
                }
            }
        }
    }

    fn encode_pixel_32(&self, r: u8, g: u8, b: u8) -> u32 {
        let r = ((r as u32) >> 8u32.saturating_sub(self.red_mask_size as u32)) << self.red_mask_pos;
        let g =
            ((g as u32) >> 8u32.saturating_sub(self.green_mask_size as u32)) << self.green_mask_pos;
        let b =
            ((b as u32) >> 8u32.saturating_sub(self.blue_mask_size as u32)) << self.blue_mask_pos;
        r | g | b
    }

    fn encode_pixel_16(&self, r: u8, g: u8, b: u8) -> u16 {
        let r = ((r as u16) >> 8u16.saturating_sub(self.red_mask_size as u16)) << self.red_mask_pos;
        let g =
            ((g as u16) >> 8u16.saturating_sub(self.green_mask_size as u16)) << self.green_mask_pos;
        let b =
            ((b as u16) >> 8u16.saturating_sub(self.blue_mask_size as u16)) << self.blue_mask_pos;
        r | g | b
    }
}

// ============================================================================
// TPM Event Log
// ============================================================================

/// TPM event-log and TPM 2.0 backend configuration.
///
/// When the platform (e.g., coreboot) has already started measured boot and
/// maintains a TPM event log, it can pass that log data to CrabEFI via this
/// configuration. CrabEFI will copy the existing log. It appends new
/// PCR-extending measurements only when an attestable hardware/platform TPM
/// backend is configured and available.
///
/// # Coreboot Integration
///
/// Coreboot stores standard TPM event logs in CBMEM with IDs
/// `CBMEM_ID_TCPA_TCG_LOG` (0x54445041, TPM 1.2) and
/// `CBMEM_ID_TPM2_TCG_LOG` (0x54504d32, TPM 2.0). The coreboot payload can
/// read these regions and pass them here. The log format depends on the TPM
/// version:
///
/// - **TPM 2.0**: Crypto-agile log (`TCG_PCR_EVENT2`) with a `SpecIdEvent`
///   header. Uses SHA-256 (and optionally SHA-1) digests.
/// - **TPM 1.2**: SHA1-only log (`TCG_PCClientPCREvent`).
///
/// # Library Integration
///
/// When CrabEFI is used as a library, the caller can provide an event log
/// from any source — a hardware TPM driver, a pre-boot firmware phase, or
/// a hypervisor. The format must match the [`TpmLogFormat`] specified.
pub struct TpmEventLogConfig<'a> {
    /// Pre-existing event log data bytes.
    ///
    /// If `None`, CrabEFI starts a fresh log buffer. Without an available TPM
    /// backend, that buffer is exposed only for log discovery and is not used
    /// to create software-only attestable measurements.
    pub existing_log: Option<&'a [u8]>,

    /// Event log format of the existing data.
    ///
    /// This also determines which TCG protocol is installed:
    /// - `CryptoAgile`: installs `EFI_TCG2_PROTOCOL` (TPM 2.0)
    /// - `Sha1Only`: installs `EFI_TCG_PROTOCOL` (TPM 1.2)
    /// - `Both`: installs both protocols
    pub format: TpmLogFormat,

    /// TPM 2.0 device used for attestable PCR extension and raw command passthrough.
    ///
    /// This is separate from the event log source: a platform may provide an
    /// existing firmware log without exposing a TPM transport, or it may expose
    /// a TPM device while asking CrabEFI to start a fresh event log. Without a
    /// TPM device, `EFI_TCG2_PROTOCOL` is log-discovery/non-attestable: it
    /// reports no TPM, rejects PCR-extending measurements, and returns
    /// unsupported for raw TPM commands. Coreboot payloads commonly use
    /// [`Tpm2DeviceConfig::TisMmio`], while library users can pass a `'static`
    /// driver implementing [`Tpm2Device`].
    pub tpm2_device: Tpm2DeviceConfig,
}

/// TPM event log format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmLogFormat {
    /// Crypto-agile log for TPM 2.0 only (SHA-256 + optional SHA-1).
    CryptoAgile,
    /// SHA-1-only log for TPM 1.2 only.
    Sha1Only,
    /// Both TPM 2.0 (crypto-agile) and TPM 1.2 (SHA-1) logs.
    Both,
}

/// TPM 2.0 hardware source for library and payload integrations.
pub enum Tpm2DeviceConfig {
    /// Do not use a hardware TPM.
    ///
    /// In this mode TCG2 is non-attestable and log-discovery only:
    /// `GetCapability` reports no TPM, PCR-extending measurements fail with a
    /// device error, and raw TPM command passthrough returns unsupported.
    /// CrabEFI does not present software PCR state as hardware-backed measured
    /// boot evidence.
    None,
    /// Probe a memory-mapped TPM TIS device at `base`.
    ///
    /// This is useful for coreboot/QEMU x86 payloads where firmware can safely
    /// access the standard TIS MMIO window directly.
    TisMmio { base: u64 },
    /// Use a platform-provided TPM 2.0 driver.
    ///
    /// This is the preferred library abstraction for non-TIS hardware, firmware
    /// that already owns the TPM transport, or tests/hypervisors that proxy TPM
    /// commands without exposing MMIO to CrabEFI.
    ///
    /// The driver reference must be `'static` because the installed
    /// `EFI_TCG2_PROTOCOL` is stored in global firmware state and can be used
    /// until ExitBootServices. Shorter-lived platform drivers should be placed
    /// in static storage by the embedding firmware before being passed here.
    Driver(&'static mut dyn Tpm2Device),
}

impl Tpm2DeviceConfig {
    /// Return true when a hardware TPM source is configured.
    pub fn is_some(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Fixed-capacity list of active TPM PCR bank algorithms.
///
/// CrabEFI's TCG2 measured-boot implementation supports SHA-1, SHA-256,
/// SHA-384, and SHA-512 banks. If a hardware/platform TPM exposes additional
/// active banks (for example SM3-256), CrabEFI logs that they are unsupported
/// and exposes/extends only the supported SHA subset through its EFI TCG2
/// implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmPcrBanks {
    algorithms: [u16; 5],
    count: usize,
}

impl TpmPcrBanks {
    /// Create a PCR bank list from TPM algorithm IDs.
    pub fn new(algorithms: &[u16]) -> Self {
        let count = algorithms.len().min(5);
        let mut out = [0u16; 5];
        out[..count].copy_from_slice(&algorithms[..count]);
        Self {
            algorithms: out,
            count,
        }
    }

    /// Return the active TPM algorithm IDs.
    pub fn algorithms(&self) -> &[u16] {
        &self.algorithms[..self.count]
    }

    /// Return true when `algorithm` is active.
    pub fn contains(&self, algorithm: u16) -> bool {
        self.algorithms().contains(&algorithm)
    }
}

/// Digest view passed to a platform TPM 2.0 driver for PCR extension.
#[derive(Clone, Copy)]
pub struct TpmDigest<'a> {
    /// TPM algorithm ID, for example `0x000B` for SHA-256.
    pub algorithm: u16,
    /// Digest bytes for `algorithm`.
    pub digest: &'a [u8],
}

/// Errors returned by platform TPM drivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TpmError {
    /// The TPM or transport returned an unspecified device error.
    DeviceError,
    /// A caller supplied invalid parameters.
    InvalidParameter,
    /// The provided response buffer is too small.
    BufferTooSmall,
    /// The requested TPM operation or algorithm is unsupported.
    Unsupported,
}

/// Platform-provided TPM 2.0 device abstraction.
///
/// Implement this when CrabEFI is used as a library and the embedding firmware
/// owns TPM discovery/transport. The trait deliberately models the operations
/// CrabEFI needs rather than a specific bus: PCR extension for measured boot,
/// raw command passthrough for `EFI_TCG2_PROTOCOL.SubmitCommand`, and cached
/// capability metadata for `GetCapability`.
pub trait Tpm2Device: Send {
    /// Return active PCR bank algorithm IDs.
    ///
    /// CrabEFI accepts SHA-1 (`0x0004`), SHA-256 (`0x000B`), SHA-384
    /// (`0x000C`), and SHA-512 (`0x000D`) for measured boot. If additional
    /// algorithms are active, they are treated as unsupported by CrabEFI's EFI
    /// TCG2 implementation and will not be requested in
    /// [`pcr_extend`](Self::pcr_extend).
    fn active_pcr_banks(&self) -> TpmPcrBanks;

    /// Return the TPM manufacturer ID reported in `GetCapability`.
    fn manufacturer_id(&self) -> u32 {
        0
    }

    /// Return the TPM maximum command size, or zero if unknown.
    fn max_command_size(&self) -> u16 {
        0
    }

    /// Return the TPM maximum response size, or zero if unknown.
    fn max_response_size(&self) -> u16 {
        0
    }

    /// Extend `pcr_index` with one digest per CrabEFI-supported active bank
    /// (SHA-1, SHA-256, SHA-384, and/or SHA-512).
    fn pcr_extend(&mut self, pcr_index: u32, digests: &[TpmDigest<'_>]) -> Result<(), TpmError>;

    /// Submit a raw TPM 2.0 command and write the response into `response`.
    fn submit_command(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, TpmError>;
}

// ============================================================================
// Platform Configuration
// ============================================================================

/// Warm-reboot persistent buffer for deferred variable writes.
///
/// When the [`VariableBackend`] is not [`runtime_capable()`](VariableBackend::runtime_capable),
/// CrabEFI buffers `SetVariable` calls made after `ExitBootServices` into
/// this memory region. The platform must ensure this memory:
///
/// 1. Survives warm reboots (not cleared on CPU reset).
/// 2. Is in a memory region marked as `RuntimeServicesData` so the OS
///    preserves the mapping after `ExitBootServices`.
///
/// On the next boot, CrabEFI reads the buffer and commits the writes via
/// [`VariableBackend::flush_deferred()`].
///
/// Not needed if the variable backend is runtime-capable (SMM, TF-A MM).
#[derive(Debug, Clone, Copy)]
pub struct DeferredBufferConfig {
    /// Physical base address of the buffer.
    pub base: u64,
    /// Size of the buffer in bytes (typically 64 KiB).
    pub size: usize,
}

/// Memory region where CrabEFI's code and data are loaded.
///
/// The platform provides this so CrabEFI can mark these regions as
/// `RuntimeServicesCode` / `RuntimeServicesData` in the EFI memory map,
/// ensuring the OS preserves them after `ExitBootServices` and
/// `SetVirtualAddressMap` adjusts pointers correctly.
///
/// For the coreboot target, these come from linker-provided symbols.
/// External firmware must ensure CrabEFI's code lives in a region that
/// the OS will keep mapped.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeRegion {
    /// Base address of the runtime code section.
    pub code_base: u64,
    /// Size of the runtime code section in bytes.
    pub code_size: u64,
    /// Base address of the runtime data section (includes stack, state, heap).
    pub data_base: u64,
    /// Size of the runtime data section in bytes.
    pub data_size: u64,
}

/// Result of the UEFI boot manager.
///
/// Describes the outcome when the boot manager exhausts all boot attempts
/// without successfully handing off to an OS. Currently informational;
/// [`crate::init_platform()`] is `-> !` and halts the CPU on failure.
///
/// Note: when a UEFI application successfully calls `ExitBootServices`,
/// [`crate::init_platform()`] never returns — the OS has taken control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootResult {
    /// No bootable media found on any provided block device.
    NoBootMedia,
    /// Boot entries were found but all attempts failed.
    AllFailed,
    /// A UEFI application was loaded and ran, but returned control
    /// (e.g., GRUB exited, or the application called `Exit()`).
    ImageReturned,
}

/// Platform configuration for CrabEFI.
///
/// This is the main integration point. External firmware populates this
/// struct with platform-specific trait implementations, then calls
/// [`crate::init_platform()`] to start the UEFI boot manager.
///
/// # Lifetime
///
/// All references in this struct must remain valid for the duration of
/// [`crate::init_platform()`]. Since `init_platform()` is `-> !` (never
/// returns), drivers on the caller's stack naturally satisfy this — no
/// `'static` bounds required.
///
/// # Minimal Configuration
///
/// At minimum, provide `memory_map`, `timer`, and `reset`. Everything else
/// is optional (with reduced functionality).
pub struct PlatformConfig<'a> {
    // ---- Required ----
    /// Physical memory map describing all RAM, MMIO, and reserved regions.
    pub memory_map: &'a [MemoryRegion],

    /// Monotonic timer for `Stall()` and EFI timer events.
    pub timer: &'a dyn Timer,

    /// Optional firmware-visible boot timestamp recorder.
    pub timestamp_recorder: Option<&'a dyn TimestampRecorder>,

    /// System reset handler for `ResetSystem` runtime service.
    pub reset: &'a dyn ResetHandler,

    // ---- Storage ----
    /// Block devices to expose via `EFI_BLOCK_IO_PROTOCOL`.
    ///
    /// Each device gets its own EFI handle. The boot manager searches
    /// these for ESP partitions and boot entries.
    pub block_devices: &'a mut [&'a mut dyn BlockDevice],

    /// Variable persistence backend.
    ///
    /// Reserved for future SMM/TF-A MM-style backends. The current
    /// `init_platform()` path does not route this field into runtime variable
    /// services yet, so leave it as `None` unless that routing is implemented.
    pub variable_backend: Option<&'a mut dyn VariableBackend>,

    /// Platform-specific persistent variable-store locator.
    ///
    /// Direct-flash integrations provide this when CrabEFI should manage an
    /// EDK2-compatible variable store itself. Coreboot implements this by
    /// consulting its SMMSTORE records and FMAP. Library consumers that want
    /// volatile variables can leave this as `None`.
    pub variable_store_locator: Option<&'a dyn VariableStoreLocator>,

    // ---- Console ----
    /// Debug/log output (serial port or equivalent).
    ///
    /// Also used for `EFI_SERIAL_IO_PROTOCOL` if no other serial is available.
    pub debug_output: Option<&'a mut dyn DebugOutput>,

    /// Keyboard/console input for `SimpleTextInput` and the boot menu.
    pub console_input: Option<&'a mut dyn ConsoleInput>,

    /// Framebuffer for `EFI_GRAPHICS_OUTPUT_PROTOCOL` and the boot menu.
    pub framebuffer: Option<FramebufferConfig>,

    // ---- Platform Tables ----
    /// ACPI RSDP physical address. Required for ACPI-based OS boot (Linux, Windows).
    pub acpi_rsdp: Option<u64>,

    /// SMBIOS entry point physical address.
    pub smbios: Option<u64>,

    /// Flattened Device Tree blob (for DT-based platforms).
    pub fdt: Option<&'a [u8]>,

    /// Firmware identity and version information for ESRT/capsule updates.
    pub firmware_info: Option<FirmwareInfo>,

    /// Platform-provided in-memory capsules to process during boot.
    pub capsule_regions: &'a [CapsuleRegion],

    /// Optional platform lifecycle callbacks.
    pub hooks: Option<&'a dyn PlatformHooks>,

    // ---- Optional Hardware ----
    /// Hardware random number generator for `EFI_RNG_PROTOCOL`.
    pub rng: Option<&'a dyn Rng>,

    /// PCI ECAM configuration space base address.
    ///
    /// If provided, CrabEFI uses this directly for PCI config space access.
    /// Otherwise, it discovers the ECAM base from ACPI MCFG or FDT.
    pub ecam_base: Option<u64>,

    /// Size of the PCI ECAM window in bytes, when `ecam_base` is provided.
    pub ecam_size: Option<u64>,

    // ---- Runtime Support ----
    /// Warm-reboot persistent buffer for deferred variable writes.
    ///
    /// Only needed when `variable_backend` is not runtime-capable.
    /// See [`DeferredBufferConfig`] for requirements.
    pub deferred_buffer: Option<DeferredBufferConfig>,

    /// Memory region where CrabEFI's code and data reside.
    ///
    /// Needed for `SetVirtualAddressMap` support. If `None`, CrabEFI
    /// cannot provide runtime services after `ExitBootServices`.
    pub runtime_region: Option<RuntimeRegion>,

    // ---- Measured Boot ----
    /// TPM event log configuration for measured boot.
    ///
    /// When provided, CrabEFI installs `EFI_TCG_PROTOCOL` and/or
    /// `EFI_TCG2_PROTOCOL` and exposes the configured event log. TCG2
    /// measurements are attestable only when `tpm2_device` provides an
    /// available hardware/platform TPM backend; with [`Tpm2DeviceConfig::None`]
    /// the protocol is log-discovery/non-attestable and rejects PCR-extending
    /// measurements. If `existing_log` data is provided (e.g., from coreboot's
    /// CBMEM), CrabEFI appends its own measurements only when backed by TPM
    /// hardware.
    ///
    /// When `None`, no TCG protocols are installed (bootloaders will see
    /// "protocol not found" and skip measured boot).
    pub tpm_event_log: Option<TpmEventLogConfig<'a>>,

    // ---- Pre-initialization ----
    /// Whether the EFI environment and heap allocator were already set up
    /// before calling [`crate::init_platform()`].
    ///
    /// When `true`, `init_platform()` skips [`efi::init_from_platform()`]
    /// and [`heap::init()`]. The caller is responsible for having called
    /// both before entry, so that `alloc` works and the EFI memory map /
    /// system table are ready.
    ///
    /// This allows platforms to perform heap-dependent initialization
    /// (e.g., ACPI AML parsing, firmware configuration parsing) *before*
    /// handing off to the library, removing the need for a callback.
    pub heap_pre_initialized: bool,
}
