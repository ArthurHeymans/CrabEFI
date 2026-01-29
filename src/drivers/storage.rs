//! Unified Storage Device Abstraction
//!
//! This module provides a common interface for all storage devices (USB, NVMe, AHCI)
//! that can be used by the BlockIO protocol and filesystem code.

use spin::Mutex;

/// Maximum number of storage devices we can track
const MAX_STORAGE_DEVICES: usize = 8;

/// Storage device type
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StorageType {
    /// USB Mass Storage
    Usb { slot_id: u8 },
    /// NVMe
    Nvme { controller_id: usize, nsid: u32 },
    /// AHCI/SATA
    Ahci { controller_id: usize, port: usize },
    /// SDHCI (SD Card)
    Sdhci { controller_id: usize },
}

/// Storage device information
#[derive(Clone, Copy)]
pub struct StorageDevice {
    /// Device type and identifiers
    pub device_type: StorageType,
    /// Total number of blocks
    pub num_blocks: u64,
    /// Block size in bytes
    pub block_size: u32,
    /// Device ID for BlockIO media_id
    pub device_id: u32,
}

/// Internal storage for registered devices
struct StorageRegistry {
    devices: [Option<StorageDevice>; MAX_STORAGE_DEVICES],
    next_id: u32,
}

impl StorageRegistry {
    const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_STORAGE_DEVICES],
            next_id: 0,
        }
    }
}

static STORAGE_REGISTRY: Mutex<StorageRegistry> = Mutex::new(StorageRegistry::new());

/// Register a storage device and get its device ID
pub fn register_device(device_type: StorageType, num_blocks: u64, block_size: u32) -> Option<u32> {
    let mut registry = STORAGE_REGISTRY.lock();

    // Find a free slot index first
    let slot_idx = registry.devices.iter().position(|slot| slot.is_none())?;

    let device_id = registry.next_id;
    registry.next_id += 1;

    registry.devices[slot_idx] = Some(StorageDevice {
        device_type,
        num_blocks,
        block_size,
        device_id,
    });

    log::info!(
        "Storage: registered {:?} as device {} ({} blocks x {} bytes)",
        device_type,
        device_id,
        num_blocks,
        block_size
    );

    Some(device_id)
}

/// Get a storage device by ID
pub fn get_device(device_id: u32) -> Option<StorageDevice> {
    let registry = STORAGE_REGISTRY.lock();
    for slot in registry.devices.iter() {
        if let Some(dev) = slot {
            if dev.device_id == device_id {
                return Some(*dev);
            }
        }
    }
    None
}

/// Read sectors from a storage device
///
/// This is the unified read function used by BlockIO protocol.
pub fn read_sectors(device_id: u32, lba: u64, buffer: &mut [u8]) -> Result<(), ()> {
    let device = get_device(device_id).ok_or(())?;

    match device.device_type {
        StorageType::Usb { slot_id: _ } => {
            // Use the global USB read function
            crate::drivers::usb::mass_storage::global_read_sector(lba, buffer)
        }
        StorageType::Nvme {
            controller_id,
            nsid,
        } => {
            if let Some(controller) = crate::drivers::nvme::get_controller(controller_id) {
                controller.read_sector(nsid, lba, buffer).map_err(|e| {
                    log::error!("NVMe read failed at LBA {}: {:?}", lba, e);
                })
            } else {
                log::error!("NVMe controller {} not found", controller_id);
                Err(())
            }
        }
        StorageType::Ahci {
            controller_id: _,
            port: _,
        } => {
            // Use global_read_sector which handles sector size translation for SATAPI
            crate::drivers::ahci::global_read_sector(lba, buffer)
        }
        StorageType::Sdhci { controller_id: _ } => {
            // Use global_read_sector for SDHCI
            crate::drivers::sdhci::global_read_sector(lba, buffer)
        }
    }
}

/// Create a read function for a specific device ID
///
/// Returns a function pointer that can be used with BlockIO.
/// Note: This is a placeholder - the actual device_id is stored in BlockIO context.
pub fn make_read_fn(_device_id: u32) -> fn(u64, &mut [u8]) -> Result<(), ()> {
    // We need to capture the device_id, but fn pointers can't capture.
    // Instead, we'll use the device_id embedded in the BlockIO context.
    // This function exists for API compatibility.
    |lba, buffer| {
        // This will be replaced by the actual device read in BlockIO
        // For now, try device 0 (USB) as fallback
        read_sectors(0, lba, buffer)
    }
}
