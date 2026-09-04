//! Unified Storage Device Abstraction
//!
//! This module provides a common interface for all storage devices (USB, NVMe, AHCI)
//! that can be used by the BlockIO protocol and filesystem code.

use spin::Mutex;

use crate::cell::Local;

/// Maximum number of storage devices we can track
const MAX_STORAGE_DEVICES: usize = 8;

/// Maximum number of platform-provided block devices.
pub const MAX_PLATFORM_BLOCK_DEVICES: usize = 8;

/// Global storage for platform-provided block devices.
///
/// Populated by [`register_platform_block_devices()`] during
/// [`crate::init_platform()`]. Fat pointers are stored directly as
/// `Option<*mut dyn>` — no `transmute` through `[usize; 2]` needed, since
/// raw pointers are `Copy` and always `Send`, keeping the `Mutex` `Sync`.
///
/// # Safety invariant
///
/// Every `Some` entry is a valid `*mut dyn platform::BlockDevice` whose
/// referent lives for the firmware's entire lifetime (`init_platform` is `-> !`).
struct PlatformBlockRegistry {
    pointers: [Option<*mut dyn crate::platform::BlockDevice>; MAX_PLATFORM_BLOCK_DEVICES],
    count: usize,
}

// SAFETY: all accesses go through the `PLATFORM_BLOCKS` mutex, every stored
// referent lives for the firmware lifetime (`init_platform() -> !`), and
// CrabEFI is single-hart, so no thread can race the pointer metadata.
unsafe impl Send for PlatformBlockRegistry {}
unsafe impl Sync for PlatformBlockRegistry {}

static PLATFORM_BLOCKS: Mutex<PlatformBlockRegistry> = Mutex::new(PlatformBlockRegistry {
    pointers: [None; MAX_PLATFORM_BLOCK_DEVICES],
    count: 0,
});

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
    let mut registry = PLATFORM_BLOCKS.lock();
    for (i, dev) in devices.iter_mut().enumerate().take(count) {
        let fat: *mut dyn crate::platform::BlockDevice = *dev;
        // SAFETY: lifetime extension from the config borrow to 'static.
        // Justified by the `init_platform() -> !` contract documented above:
        // the referent outlives firmware. Layout is untouched, unlike the
        // previous `[usize; 2]` transmute.
        let fat: *mut (dyn crate::platform::BlockDevice + 'static) =
            unsafe { core::mem::transmute(fat) };
        registry.pointers[i] = Some(fat);
    }
    registry.count = count;
    log::info!("Registered {} platform block device(s)", count);
}

/// Number of registered platform block devices.
pub fn platform_block_device_count() -> usize {
    PLATFORM_BLOCKS.lock().count
}

/// Access a platform block device by index, calling `f` with a mutable reference.
///
/// Returns `None` if the index is out of range.
pub fn with_platform_block_device<R>(
    index: usize,
    f: impl FnOnce(&mut dyn crate::platform::BlockDevice) -> R,
) -> Option<R> {
    let registry = PLATFORM_BLOCKS.lock();
    if index >= registry.count {
        return None;
    }
    // SAFETY: the pointer entry was written by register_platform_block_devices()
    // from a valid `*mut dyn BlockDevice`. The referent is alive (-> ! contract).
    unsafe {
        let fat = registry.pointers[index]?;
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
struct StorageRegistry {
    devices: [Option<StorageDevice>; MAX_STORAGE_DEVICES],
    next_id: u32,
}

/// Registered block devices.
static REGISTRY: Local<StorageRegistry> = Local::new(StorageRegistry {
    devices: [const { None }; MAX_STORAGE_DEVICES],
    next_id: 0,
});

/// Register a storage device and get its device ID
pub fn register_device(device_type: StorageType, num_blocks: u64, block_size: u32) -> Option<u32> {
    REGISTRY.with_mut(|registry| {
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
    REGISTRY
        .borrow()
        .devices
        .iter()
        .flatten()
        .find(|dev| dev.device_id == device_id)
        .copied()
}

/// Read sectors from a storage device
///
/// This is the unified read function used by BlockIO protocol.
// Failure details are logged at the error site; callers only branch on success.
#[allow(clippy::result_unit_err)]
pub fn read_sectors(device_id: u32, lba: u64, buffer: &mut [u8]) -> Result<(), ()> {
    let device = get_device(device_id).ok_or(())?;
    let block_size = usize::try_from(device.block_size).map_err(|_| ())?;
    if block_size == 0 || buffer.is_empty() || !buffer.len().is_multiple_of(block_size) {
        log::error!(
            "Storage read buffer length {} is not a non-zero multiple of block size {}",
            buffer.len(),
            block_size
        );
        return Err(());
    }
    let num_sectors = u32::try_from(buffer.len() / block_size).map_err(|_| ())?;

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
        } => crate::drivers::nvme::with_controller(controller_id, |controller| {
            controller
                .read_sectors(nsid, lba, num_sectors, buffer)
                .map_err(|error| {
                    log::error!("NVMe read failed at LBA {}: {:?}", lba, error);
                })
        })
        .unwrap_or_else(|| {
            log::error!("NVMe controller {} not found", controller_id);
            Err(())
        }),
        StorageType::Ahci {
            controller_id,
            port,
        } => crate::drivers::ahci::with_controller(controller_id, |controller| {
            controller
                .read_sectors_into(port, lba, num_sectors, buffer)
                .map_err(|error| {
                    log::error!("AHCI read failed at LBA {}: {:?}", lba, error);
                })
        })
        .unwrap_or_else(|| {
            log::error!("AHCI controller {} not found", controller_id);
            Err(())
        }),
        StorageType::Sdhci { controller_id } => {
            crate::drivers::sdhci::with_controller(controller_id, |controller| {
                controller
                    .read_sectors(lba, num_sectors, buffer)
                    .map_err(|error| {
                        log::error!("SDHCI read failed at LBA {}: {:?}", lba, error);
                    })
            })
            .unwrap_or_else(|| {
                log::error!("SDHCI controller {} not found", controller_id);
                Err(())
            })
        }
        StorageType::Platform { index } => with_platform_block_device(index, |dev| {
            let info = dev.info();
            if info.block_size != device.block_size {
                log::error!(
                    "Platform device {} block size changed from {} to {}",
                    index,
                    device.block_size,
                    info.block_size
                );
                return Err(());
            }
            dev.read_blocks(lba, num_sectors, buffer).map_err(|e| {
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
