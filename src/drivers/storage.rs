//! Unified Storage Device Abstraction
//!
//! This module provides a common interface for all storage devices (USB, NVMe, AHCI)
//! that can be used by the BlockIO protocol and filesystem code.

/// Maximum number of storage devices we can track
const MAX_STORAGE_DEVICES: usize = 8;

/// Maximum number of platform-provided block devices.
pub const MAX_PLATFORM_BLOCK_DEVICES: usize = 8;

/// Global storage for platform-provided block device fat pointers.
///
/// Populated by [`register_platform_block_devices()`] during
/// [`crate::init_platform()`]. Each entry is a raw fat pointer
/// (`*mut dyn platform::BlockDevice`) stored as two `usize` words
/// (data pointer + vtable pointer).
///
/// # Safety invariant
///
/// Every non-zero entry is a valid `*mut dyn platform::BlockDevice` whose
/// referent lives for the firmware's entire lifetime (`init_platform` is `-> !`).
static mut PLATFORM_BLOCK_PTRS: [[usize; 2]; MAX_PLATFORM_BLOCK_DEVICES] =
    [[0; 2]; MAX_PLATFORM_BLOCK_DEVICES];
static mut PLATFORM_BLOCK_COUNT: usize = 0;

/// Register platform-provided block devices from [`crate::PlatformConfig`].
///
/// # Safety
///
/// Must be called exactly once from `init_platform()` before the boot manager
/// runs. The block device references in `devices` must remain valid for the
/// firmware's entire lifetime (guaranteed by `init_platform() -> !`).
pub unsafe fn register_platform_block_devices(
    devices: &mut [&mut dyn crate::platform::BlockDevice],
) {
    let count = devices.len().min(MAX_PLATFORM_BLOCK_DEVICES);
    for (i, dev) in devices.iter_mut().enumerate().take(count) {
        let fat: *mut dyn crate::platform::BlockDevice = *dev;
        // SAFETY: A trait object pointer is exactly two usizes (data + vtable).
        // We store it raw and reconstruct it in with_platform_block_device().
        unsafe {
            PLATFORM_BLOCK_PTRS[i] =
                core::mem::transmute::<*mut dyn crate::platform::BlockDevice, [usize; 2]>(fat);
        }
    }
    unsafe {
        PLATFORM_BLOCK_COUNT = count;
    }
    log::info!("Registered {} platform block device(s)", count);
}

/// Number of registered platform block devices.
pub fn platform_block_device_count() -> usize {
    // SAFETY: read-only after init_platform() completes registration;
    // single-threaded firmware.
    unsafe { PLATFORM_BLOCK_COUNT }
}

/// Access a platform block device by index, calling `f` with a mutable reference.
///
/// Returns `None` if the index is out of range.
pub fn with_platform_block_device<R>(
    index: usize,
    f: impl FnOnce(&mut dyn crate::platform::BlockDevice) -> R,
) -> Option<R> {
    // SAFETY: single-threaded firmware; read-only count set during init.
    let count = unsafe { PLATFORM_BLOCK_COUNT };
    if index >= count {
        return None;
    }
    // SAFETY: PLATFORM_BLOCK_PTRS[index] was written by register_platform_block_devices()
    // from a valid `*mut dyn BlockDevice`. The referent is alive (-> ! contract).
    unsafe {
        let words = PLATFORM_BLOCK_PTRS[index];
        if words[0] == 0 {
            return None;
        }
        let fat: *mut dyn crate::platform::BlockDevice =
            core::mem::transmute::<[usize; 2], *mut dyn crate::platform::BlockDevice>(words);
        Some(f(&mut *fat))
    }
}

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
    /// Platform-provided block device (via [`crate::PlatformConfig::block_devices`]).
    ///
    /// The `index` identifies the device's position in the global platform
    /// block device array, set up by [`crate::init_platform()`].
    Platform { index: usize },
}

impl StorageType {
    /// Get a short description of the device type
    pub fn description(&self) -> &'static str {
        match self {
            StorageType::Nvme { .. } => "NVMe",
            StorageType::Ahci { .. } => "SATA",
            StorageType::Usb { .. } => "USB",
            StorageType::Sdhci { .. } => "SD",
            StorageType::Platform { .. } => "Platform",
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
        StorageType::Platform { index } => with_platform_block_device(index, |dev| {
            let info = dev.info();
            let count = (buffer.len() as u32).div_ceil(info.block_size);
            dev.read_blocks(lba, count, buffer).map_err(|e| {
                log::error!(
                    "Platform device {} read failed at LBA {}: {:?}",
                    index,
                    lba,
                    e
                );
            })
        })
        .unwrap_or(Err(())),
    }
}
