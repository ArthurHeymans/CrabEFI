//! Block Device Abstraction
//!
//! The [`BlockDevice`] trait is the single block interface for every disk
//! CrabEFI boots from: in-tree NVMe, AHCI, USB mass storage and SDHCI devices
//! as well as platform-provided devices from
//! [`crate::PlatformConfig::block_devices`]. Filesystem, partition and boot
//! code only see `&mut dyn BlockDevice`.

mod range;
pub use range::{BlockRange, BlockWriteError};

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
    /// Whether the media is read-only. Writes to a read-only device fail with
    /// [`BlockError::WriteProtected`].
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
    /// No media present (removable device with nothing inserted, or the
    /// device is no longer available).
    NoMedia,
    /// Media changed since last access.
    MediaChanged,
    /// The device or driver does not support writes.
    WriteProtected,
}

impl core::fmt::Display for BlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlockError::DeviceError => write!(f, "device error"),
            BlockError::InvalidParameter => write!(f, "invalid parameter"),
            BlockError::OutOfRange => write!(f, "LBA out of range"),
            BlockError::NoMedia => write!(f, "no media present"),
            BlockError::MediaChanged => write!(f, "media changed"),
            BlockError::WriteProtected => write!(f, "write protected"),
        }
    }
}

/// Block-level storage device interface.
///
/// # Implementor's Guide
///
/// - `read_blocks` must handle arbitrary LBA ranges within bounds.
/// - Writable devices override `write_blocks` (and `flush` if they cache
///   writes) and report `read_only: false`. The defaults reject writes with
///   [`BlockError::WriteProtected`].
/// - `info()` should return consistent values for the device's lifetime.
/// - `name()` is displayed in the boot menu for platform-provided devices;
///   make it descriptive (e.g., `"eMMC: partition 0"`).
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
///             read_only: true,
///         }
///     }
///     fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8])
///         -> Result<(), crabefi::BlockError>
///     {
///         self.validate_io(lba, count, buffer)?;
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

    /// Write contiguous blocks to the device.
    ///
    /// # Arguments
    /// * `lba` - Starting logical block address.
    /// * `count` - Number of blocks to write.
    /// * `buffer` - Source data (must be at least `count * block_size` bytes).
    ///
    /// An error does not imply an atomic rollback: some blocks, including
    /// part of a failed transfer, may already have changed. Filesystem metadata
    /// must be published and recovered independently of this interface.
    fn write_blocks(&mut self, _lba: u64, _count: u32, _buffer: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::WriteProtected)
    }

    /// Commit writes still held in device or driver caches to stable media.
    fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }

    /// Human-readable device name for the boot menu.
    fn name(&self) -> &str {
        "Block Device"
    }

    /// Validate parameters for a read or write operation.
    ///
    /// Checks the LBA range and buffer size. Implementations should call this
    /// at the start of `read_blocks` and `write_blocks`.
    fn validate_io(&self, lba: u64, count: u32, buffer: &[u8]) -> Result<(), BlockError> {
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

    /// Validate a read operation (retained for existing platform drivers).
    /// Read-only media is readable; protection is enforced by write methods.
    fn validate_read(&self, lba: u64, count: u32, buffer: &[u8]) -> Result<(), BlockError> {
        self.validate_io(lba, count, buffer)
    }

    /// Read a single block (convenience wrapper).
    fn read_block(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.read_blocks(lba, 1, buffer)
    }

    /// Write a single block (convenience wrapper).
    fn write_block(&mut self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        self.write_blocks(lba, 1, buffer)
    }
}
