//! Unified Storage Device Abstraction
//!
//! This module provides a common interface for all storage devices (USB, NVMe, AHCI)
//! that can be used by the BlockIO protocol and filesystem code.

/// Maximum number of storage devices we can track
const MAX_STORAGE_DEVICES: usize = 8;

/// Storage device type and instance identifier
///
/// This is the canonical enum for identifying a specific storage device across
/// the entire codebase: menu, boot, storage registry, and EFI protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageType {
    /// NVMe SSD
    Nvme { controller_id: usize, nsid: u32 },
    /// AHCI/SATA disk
    Ahci { controller_id: usize, port: usize },
    /// USB mass storage
    Usb {
        controller_id: usize,
        device_addr: u8,
    },
    /// SDHCI (SD Card)
    Sdhci { controller_id: usize },
}

impl StorageType {
    /// Get a short description of the device type
    pub fn description(&self) -> &'static str {
        match self {
            StorageType::Nvme { .. } => "NVMe",
            StorageType::Ahci { .. } => "SATA",
            StorageType::Usb { .. } => "USB",
            StorageType::Sdhci { .. } => "SD",
        }
    }
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
pub(crate) struct StorageRegistry {
    devices: [Option<StorageDevice>; MAX_STORAGE_DEVICES],
    next_id: u32,
}

impl StorageRegistry {
    pub(crate) const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_STORAGE_DEVICES],
            next_id: 0,
        }
    }
}

/// Register a storage device and get its device ID
pub fn register_device(device_type: StorageType, num_blocks: u64, block_size: u32) -> Option<u32> {
    crate::state::with_drivers_mut(|drivers| {
        let registry = &mut drivers.storage_registry;

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
    })
}

/// Get a storage device by ID
pub fn get_device(device_id: u32) -> Option<StorageDevice> {
    let registry = &crate::state::drivers().storage_registry;
    registry
        .devices
        .iter()
        .flatten()
        .find(|dev| dev.device_id == device_id)
        .copied()
}

/// Read sectors from a storage device
///
/// This is the unified read function used by BlockIO protocol.
pub fn read_sectors(device_id: u32, lba: u64, buffer: &mut [u8]) -> Result<(), ()> {
    let device = get_device(device_id).ok_or(())?;

    match device.device_type {
        StorageType::Usb { .. } => {
            // TODO: USB mass storage currently only supports a single global device.
            // A per-device registry (similar to NVMe/AHCI) is needed to support
            // multiple USB storage devices simultaneously.
            crate::drivers::usb::mass_storage::global_read_sectors(lba, buffer)
        }
        StorageType::Nvme {
            controller_id,
            nsid,
        } => {
            if let Some(controller_ptr) = crate::drivers::nvme::get_controller(controller_id) {
                // Safety: pointer valid for firmware lifetime; no overlapping &mut created
                let controller = unsafe { &mut *controller_ptr };
                let num_sectors = (buffer.len() as u32).div_ceil(device.block_size);
                controller
                    .read_sectors(nsid, lba, num_sectors, buffer.as_mut_ptr())
                    .map_err(|e| {
                        log::error!("NVMe read failed at LBA {}: {:?}", lba, e);
                    })
            } else {
                log::error!("NVMe controller {} not found", controller_id);
                Err(())
            }
        }
        StorageType::Ahci {
            controller_id,
            port,
        } => {
            if let Some(controller_ptr) = crate::drivers::ahci::get_controller(controller_id) {
                let controller = unsafe { &mut *controller_ptr };
                let num_sectors = (buffer.len() as u32).div_ceil(device.block_size);
                unsafe {
                    controller
                        .read_sectors(port, lba, num_sectors, buffer.as_mut_ptr())
                        .map_err(|e| {
                            log::error!("AHCI read failed at LBA {}: {:?}", lba, e);
                        })
                }
            } else {
                log::error!("AHCI controller {} not found", controller_id);
                Err(())
            }
        }
        StorageType::Sdhci { controller_id } => {
            if let Some(controller_ptr) = crate::drivers::sdhci::get_controller(controller_id) {
                // Safety: pointer valid for firmware lifetime; no overlapping &mut created
                let controller = unsafe { &mut *controller_ptr };
                controller.read_sector(lba, buffer).map_err(|e| {
                    log::error!("SDHCI read failed at LBA {}: {:?}", lba, e);
                })
            } else {
                log::error!("SDHCI controller {} not found", controller_id);
                Err(())
            }
        }
    }
}
