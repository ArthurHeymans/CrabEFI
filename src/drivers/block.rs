//! Unified Block Device Abstraction
//!
//! This module provides a common interface for all storage devices (NVMe, AHCI, USB)
//! that maps directly to the UEFI EFI_BLOCK_IO_PROTOCOL.
//!
//! # Architecture
//!
//! All block devices implement the `BlockDevice` trait, providing:
//! - Device information (block count, block size, removable, etc.)
//! - Block read operations
//!
//! The `AnyBlockDevice` enum provides type-safe dispatch without trait objects,
//! similar to how `UsbControllerHandle` works for USB controllers.

use crate::drivers::{ahci, nvme, sdhci, usb};

/// Standard sector size (512 bytes)
pub const SECTOR_SIZE: usize = 512;

/// Information about a block device
///
/// This structure maps closely to EFI_BLOCK_IO_MEDIA.
#[derive(Clone, Copy, Debug)]
pub struct BlockDeviceInfo {
    /// Total number of blocks on the device
    pub num_blocks: u64,
    /// Size of each block in bytes
    pub block_size: u32,
    /// Media ID (changes if media is replaced)
    pub media_id: u32,
    /// True if the device is removable (USB, CD-ROM, etc.)
    pub removable: bool,
    /// True if the device is read-only
    pub read_only: bool,
}

/// Unified error type for block operations
#[derive(Debug)]
pub enum BlockError {
    /// Generic device error
    DeviceError,
    /// Invalid parameter (bad LBA, buffer too small, etc.)
    InvalidParameter,
    /// LBA out of range
    OutOfRange,
    /// No media present (for removable devices)
    NoMedia,
    /// Media has changed since last access
    MediaChanged,
}

// Error conversions from driver-specific errors

impl From<nvme::NvmeError> for BlockError {
    fn from(e: nvme::NvmeError) -> Self {
        match e {
            nvme::NvmeError::InvalidNamespace => BlockError::NoMedia,
            nvme::NvmeError::InvalidParameter => BlockError::InvalidParameter,
            _ => BlockError::DeviceError,
        }
    }
}

impl From<ahci::AhciError> for BlockError {
    fn from(e: ahci::AhciError) -> Self {
        match e {
            ahci::AhciError::NoDevice => BlockError::NoMedia,
            ahci::AhciError::InvalidParameter => BlockError::InvalidParameter,
            _ => BlockError::DeviceError,
        }
    }
}

impl From<usb::mass_storage::MassStorageError> for BlockError {
    fn from(e: usb::mass_storage::MassStorageError) -> Self {
        match e {
            usb::mass_storage::MassStorageError::NotReady => BlockError::NoMedia,
            usb::mass_storage::MassStorageError::InvalidParameter => BlockError::InvalidParameter,
            _ => BlockError::DeviceError,
        }
    }
}

impl From<sdhci::SdhciError> for BlockError {
    fn from(e: sdhci::SdhciError) -> Self {
        match e {
            sdhci::SdhciError::NoCard => BlockError::NoMedia,
            sdhci::SdhciError::InvalidParameter => BlockError::InvalidParameter,
            sdhci::SdhciError::NotInitialized => BlockError::NoMedia,
            _ => BlockError::DeviceError,
        }
    }
}

/// Trait for block-level storage devices
///
/// All storage devices (NVMe namespaces, AHCI ports, USB mass storage) implement
/// this trait, providing a unified interface for block I/O operations.
pub trait BlockDevice {
    /// Get device information
    fn info(&self) -> BlockDeviceInfo;

    /// Read blocks from the device
    ///
    /// # Arguments
    /// * `lba` - Starting logical block address
    /// * `count` - Number of blocks to read
    /// * `buffer` - Buffer to read into (must be at least count * block_size bytes)
    ///
    /// # Returns
    /// Ok(()) on success, Err(BlockError) on failure
    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError>;

    /// Read a single block (convenience method)
    fn read_block(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.read_blocks(lba, 1, buffer)
    }
}

// ============================================================================
// NVMe Block Device
// ============================================================================

/// NVMe block device wrapping a controller and namespace
pub struct NvmeBlockDevice {
    /// Index into the global NVMe controller array
    controller_id: usize,
    /// Namespace ID
    nsid: u32,
    /// Cached device info
    info: BlockDeviceInfo,
}

impl NvmeBlockDevice {
    /// Create a new NVMe block device
    ///
    /// # Arguments
    /// * `controller_id` - Index of the controller in the global array
    /// * `nsid` - Namespace ID
    /// * `num_blocks` - Total number of blocks
    /// * `block_size` - Block size in bytes
    /// * `media_id` - Media ID for BlockIO
    pub fn new(
        controller_id: usize,
        nsid: u32,
        num_blocks: u64,
        block_size: u32,
        media_id: u32,
    ) -> Self {
        Self {
            controller_id,
            nsid,
            info: BlockDeviceInfo {
                num_blocks,
                block_size,
                media_id,
                removable: false, // NVMe is not removable
                read_only: false,
            },
        }
    }

    /// Get the controller ID
    pub fn controller_id(&self) -> usize {
        self.controller_id
    }

    /// Get the namespace ID
    pub fn nsid(&self) -> u32 {
        self.nsid
    }
}

impl BlockDevice for NvmeBlockDevice {
    fn info(&self) -> BlockDeviceInfo {
        self.info
    }

    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError> {
        let controller = nvme::get_controller(self.controller_id).ok_or(BlockError::DeviceError)?;

        controller
            .read_sectors(self.nsid, lba, count, buffer.as_mut_ptr())
            .map_err(BlockError::from)
    }
}

// ============================================================================
// AHCI Block Device
// ============================================================================

/// AHCI block device wrapping a controller and port
pub struct AhciBlockDevice {
    /// Index into the global AHCI controller array
    controller_id: usize,
    /// Port index
    port: usize,
    /// Cached device info
    info: BlockDeviceInfo,
}

impl AhciBlockDevice {
    /// Create a new AHCI block device
    ///
    /// # Arguments
    /// * `controller_id` - Index of the controller in the global array
    /// * `port` - Port index
    /// * `num_blocks` - Total number of blocks
    /// * `block_size` - Block size in bytes
    /// * `media_id` - Media ID for BlockIO
    pub fn new(
        controller_id: usize,
        port: usize,
        num_blocks: u64,
        block_size: u32,
        media_id: u32,
    ) -> Self {
        Self {
            controller_id,
            port,
            info: BlockDeviceInfo {
                num_blocks,
                block_size,
                media_id,
                removable: false, // SATA drives are generally not removable
                read_only: false,
            },
        }
    }

    /// Get the controller ID
    pub fn controller_id(&self) -> usize {
        self.controller_id
    }

    /// Get the port index
    pub fn port(&self) -> usize {
        self.port
    }
}

impl BlockDevice for AhciBlockDevice {
    fn info(&self) -> BlockDeviceInfo {
        self.info
    }

    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError> {
        let controller = ahci::get_controller(self.controller_id).ok_or(BlockError::DeviceError)?;

        controller
            .read_sectors(self.port, lba, count, buffer.as_mut_ptr())
            .map_err(BlockError::from)
    }
}

// ============================================================================
// USB Block Device
// ============================================================================

/// USB mass storage block device
pub struct UsbBlockDevice {
    /// Controller index in the global USB controller array
    controller_id: usize,
    /// Device address (slot ID for xHCI, device address for others)
    device_addr: u8,
    /// Cached device info
    info: BlockDeviceInfo,
}

impl UsbBlockDevice {
    /// Create a new USB block device
    ///
    /// # Arguments
    /// * `controller_id` - Index of the USB controller in the global array
    /// * `device_addr` - Device address/slot ID
    /// * `num_blocks` - Total number of blocks
    /// * `block_size` - Block size in bytes
    /// * `media_id` - Media ID for BlockIO
    pub fn new(
        controller_id: usize,
        device_addr: u8,
        num_blocks: u64,
        block_size: u32,
        media_id: u32,
    ) -> Self {
        Self {
            controller_id,
            device_addr,
            info: BlockDeviceInfo {
                num_blocks,
                block_size,
                media_id,
                removable: true, // USB is removable
                read_only: false,
            },
        }
    }

    /// Get the controller ID
    pub fn controller_id(&self) -> usize {
        self.controller_id
    }

    /// Get the device address
    pub fn device_addr(&self) -> u8 {
        self.device_addr
    }
}

impl BlockDevice for UsbBlockDevice {
    fn info(&self) -> BlockDeviceInfo {
        self.info
    }

    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError> {
        // Get the USB controller and mass storage device, then read
        // This uses the global USB mass storage read function
        usb::mass_storage::global_read_sector(lba, buffer).map_err(|()| BlockError::DeviceError)?;

        // Handle multi-block reads by reading sectors one at a time
        // (global_read_sector handles single sectors)
        if count > 1 {
            let block_size = self.info.block_size as usize;
            for i in 1..count {
                let offset = i as usize * block_size;
                let sector_lba = lba + i as u64;
                usb::mass_storage::global_read_sector(sector_lba, &mut buffer[offset..])
                    .map_err(|()| BlockError::DeviceError)?;
            }
        }

        Ok(())
    }
}

// ============================================================================
// SDHCI Block Device
// ============================================================================

/// SDHCI (SD card) block device
pub struct SdhciBlockDevice {
    /// Index into the global SDHCI controller array
    controller_id: usize,
    /// Cached device info
    info: BlockDeviceInfo,
}

impl SdhciBlockDevice {
    /// Create a new SDHCI block device
    ///
    /// # Arguments
    /// * `controller_id` - Index of the controller in the global array
    /// * `num_blocks` - Total number of blocks
    /// * `block_size` - Block size in bytes
    /// * `media_id` - Media ID for BlockIO
    pub fn new(controller_id: usize, num_blocks: u64, block_size: u32, media_id: u32) -> Self {
        Self {
            controller_id,
            info: BlockDeviceInfo {
                num_blocks,
                block_size,
                media_id,
                removable: true, // SD cards are removable
                read_only: false,
            },
        }
    }

    /// Get the controller ID
    pub fn controller_id(&self) -> usize {
        self.controller_id
    }
}

impl BlockDevice for SdhciBlockDevice {
    fn info(&self) -> BlockDeviceInfo {
        self.info
    }

    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError> {
        let controller =
            sdhci::get_controller(self.controller_id).ok_or(BlockError::DeviceError)?;

        controller
            .read_sectors(lba, count, buffer.as_mut_ptr())
            .map_err(BlockError::from)
    }
}

// ============================================================================
// Reference-Based Disk Wrappers (for use with borrowed controllers)
// ============================================================================

/// NVMe disk wrapper for use with borrowed controller reference
///
/// This type is useful when you have a temporary mutable reference to an
/// NVMe controller and want to use it with GPT/filesystem code.
pub struct NvmeDisk<'a> {
    controller: &'a mut nvme::NvmeController,
    nsid: u32,
}

impl<'a> NvmeDisk<'a> {
    /// Create a new NVMe disk wrapper
    pub fn new(controller: &'a mut nvme::NvmeController, nsid: u32) -> Self {
        Self { controller, nsid }
    }
}

impl<'a> BlockDevice for NvmeDisk<'a> {
    fn info(&self) -> BlockDeviceInfo {
        if let Some(ns) = self.controller.get_namespace(self.nsid) {
            BlockDeviceInfo {
                num_blocks: ns.num_blocks,
                block_size: ns.block_size,
                media_id: 0,
                removable: false,
                read_only: false,
            }
        } else {
            BlockDeviceInfo {
                num_blocks: 0,
                block_size: 512,
                media_id: 0,
                removable: false,
                read_only: true,
            }
        }
    }

    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.controller
            .read_sectors(self.nsid, lba, count, buffer.as_mut_ptr())
            .map_err(BlockError::from)
    }
}

/// AHCI disk wrapper for use with borrowed controller reference
///
/// This type is useful when you have a temporary mutable reference to an
/// AHCI controller and want to use it with GPT/filesystem code.
pub struct AhciDisk<'a> {
    controller: &'a mut ahci::AhciController,
    port: usize,
}

impl<'a> AhciDisk<'a> {
    /// Create a new AHCI disk wrapper
    pub fn new(controller: &'a mut ahci::AhciController, port: usize) -> Self {
        Self { controller, port }
    }
}

impl<'a> BlockDevice for AhciDisk<'a> {
    fn info(&self) -> BlockDeviceInfo {
        if let Some(port_info) = self.controller.get_port(self.port) {
            BlockDeviceInfo {
                num_blocks: port_info.sector_count,
                block_size: port_info.sector_size,
                media_id: 0,
                removable: false,
                read_only: false,
            }
        } else {
            BlockDeviceInfo {
                num_blocks: 0,
                block_size: 512,
                media_id: 0,
                removable: false,
                read_only: true,
            }
        }
    }

    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.controller
            .read_sectors(self.port, lba, count, buffer.as_mut_ptr())
            .map_err(BlockError::from)
    }
}

/// USB disk wrapper for use with borrowed controller and mass storage device
///
/// This type is useful when you have temporary mutable references to a USB
/// controller and mass storage device and want to use them with GPT/filesystem code.
pub struct UsbDisk<'a> {
    device: &'a mut usb::UsbMassStorage,
    controller: &'a mut dyn usb::UsbController,
}

impl<'a> UsbDisk<'a> {
    /// Create a new USB disk wrapper
    pub fn new(
        device: &'a mut usb::UsbMassStorage,
        controller: &'a mut dyn usb::UsbController,
    ) -> Self {
        Self { device, controller }
    }
}

impl<'a> BlockDevice for UsbDisk<'a> {
    fn info(&self) -> BlockDeviceInfo {
        BlockDeviceInfo {
            num_blocks: self.device.num_blocks,
            block_size: self.device.block_size,
            media_id: 0,
            removable: true,
            read_only: false,
        }
    }

    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.device
            .read_sectors_generic(self.controller, lba, count, buffer)
            .map_err(BlockError::from)
    }
}

/// SDHCI disk wrapper for use with borrowed controller reference
///
/// This type is useful when you have a temporary mutable reference to an
/// SDHCI controller and want to use it with GPT/filesystem code.
pub struct SdhciDisk<'a> {
    controller: &'a mut sdhci::SdhciController,
}

impl<'a> SdhciDisk<'a> {
    /// Create a new SDHCI disk wrapper
    pub fn new(controller: &'a mut sdhci::SdhciController) -> Self {
        Self { controller }
    }
}

impl<'a> BlockDevice for SdhciDisk<'a> {
    fn info(&self) -> BlockDeviceInfo {
        BlockDeviceInfo {
            num_blocks: self.controller.num_blocks(),
            block_size: self.controller.block_size(),
            media_id: 0,
            removable: true,
            read_only: false,
        }
    }

    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.controller
            .read_sectors(lba, count, buffer.as_mut_ptr())
            .map_err(BlockError::from)
    }
}

// ============================================================================
// Unified Block Device Enum
// ============================================================================

/// Unified block device handle for type-safe dispatch
///
/// This enum allows working with any block device type without trait objects,
/// providing efficient dispatch similar to `UsbControllerHandle`.
pub enum AnyBlockDevice {
    /// NVMe namespace
    Nvme(NvmeBlockDevice),
    /// AHCI/SATA port
    Ahci(AhciBlockDevice),
    /// USB mass storage device
    Usb(UsbBlockDevice),
    /// SDHCI (SD card) device
    Sdhci(SdhciBlockDevice),
}

impl BlockDevice for AnyBlockDevice {
    fn info(&self) -> BlockDeviceInfo {
        match self {
            AnyBlockDevice::Nvme(dev) => dev.info(),
            AnyBlockDevice::Ahci(dev) => dev.info(),
            AnyBlockDevice::Usb(dev) => dev.info(),
            AnyBlockDevice::Sdhci(dev) => dev.info(),
        }
    }

    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError> {
        match self {
            AnyBlockDevice::Nvme(dev) => dev.read_blocks(lba, count, buffer),
            AnyBlockDevice::Ahci(dev) => dev.read_blocks(lba, count, buffer),
            AnyBlockDevice::Usb(dev) => dev.read_blocks(lba, count, buffer),
            AnyBlockDevice::Sdhci(dev) => dev.read_blocks(lba, count, buffer),
        }
    }
}

/// Macro for dispatching to the appropriate block device type
///
/// This reduces repetition when implementing functions that need to work
/// with any block device type through the BlockDevice trait.
#[macro_export]
macro_rules! with_block_device {
    // Mutable access version
    ($handle:expr, mut |$device:ident| $body:expr) => {
        match $handle {
            $crate::drivers::block::AnyBlockDevice::Nvme(ref mut $device) => $body,
            $crate::drivers::block::AnyBlockDevice::Ahci(ref mut $device) => $body,
            $crate::drivers::block::AnyBlockDevice::Usb(ref mut $device) => $body,
            $crate::drivers::block::AnyBlockDevice::Sdhci(ref mut $device) => $body,
        }
    };
    // Immutable access version
    ($handle:expr, |$device:ident| $body:expr) => {
        match $handle {
            $crate::drivers::block::AnyBlockDevice::Nvme(ref $device) => $body,
            $crate::drivers::block::AnyBlockDevice::Ahci(ref $device) => $body,
            $crate::drivers::block::AnyBlockDevice::Usb(ref $device) => $body,
            $crate::drivers::block::AnyBlockDevice::Sdhci(ref $device) => $body,
        }
    };
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create an NVMe block device from a controller and namespace
pub fn create_nvme_device(
    controller_id: usize,
    nsid: u32,
    media_id: u32,
) -> Option<NvmeBlockDevice> {
    let controller = nvme::get_controller(controller_id)?;
    let ns = controller.get_namespace(nsid)?;

    Some(NvmeBlockDevice::new(
        controller_id,
        nsid,
        ns.num_blocks,
        ns.block_size,
        media_id,
    ))
}

/// Create an AHCI block device from a controller and port
pub fn create_ahci_device(
    controller_id: usize,
    port: usize,
    media_id: u32,
) -> Option<AhciBlockDevice> {
    let controller = ahci::get_controller(controller_id)?;
    let port_info = controller.get_port(port)?;

    Some(AhciBlockDevice::new(
        controller_id,
        port,
        port_info.sector_count,
        port_info.sector_size,
        media_id,
    ))
}

/// Create an SDHCI block device from a controller
pub fn create_sdhci_device(controller_id: usize, media_id: u32) -> Option<SdhciBlockDevice> {
    let controller = sdhci::get_controller(controller_id)?;

    if !controller.is_ready() {
        return None;
    }

    Some(SdhciBlockDevice::new(
        controller_id,
        controller.num_blocks(),
        controller.block_size(),
        media_id,
    ))
}
