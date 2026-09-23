//! Storage Device Enumeration and Access
//!
//! Every disk CrabEFI can boot from is identified by a [`StorageId`].
//! [`devices()`] enumerates all of them (NVMe namespaces, AHCI ports, USB mass
//! storage, SDHCI cards and platform-provided devices) and [`with_disk()`]
//! lends one out as a `&mut dyn BlockDevice` for the duration of a closure.

use alloc::vec::Vec;
use core::fmt::Write;

use heapless::{String, Vec as FixedVec};

use crate::cell::Local;
use crate::drivers::block::{BlockDevice, BlockDeviceInfo, BlockError};
use crate::drivers::pci::PciAddress;
use crate::drivers::{ahci, nvme, sdhci, usb};

/// Maximum number of platform-provided block devices.
const MAX_PLATFORM_BLOCK_DEVICES: usize = 8;

/// Platform-provided block devices registered by [`crate::init_platform()`].
///
/// Every entry points to a device that lives for the firmware's entire
/// lifetime (`init_platform` is `-> !`).
static PLATFORM_BLOCK_DEVICES: Local<FixedVec<*mut dyn BlockDevice, MAX_PLATFORM_BLOCK_DEVICES>> =
    Local::new(FixedVec::new());

/// Register platform-provided block devices from [`crate::PlatformConfig`].
///
/// # Safety
///
/// The block device references in `devices` must remain valid for the
/// firmware's entire lifetime (guaranteed by `init_platform() -> !`).
pub unsafe fn register_platform_block_devices(devices: &mut [&mut dyn BlockDevice]) {
    PLATFORM_BLOCK_DEVICES.with_mut(|registered| {
        registered.clear();
        for device in devices.iter_mut().take(MAX_PLATFORM_BLOCK_DEVICES) {
            let device: *mut dyn BlockDevice = *device;
            // SAFETY: extends the config borrow to 'static; the caller
            // guarantees the referent outlives the firmware.
            let device: *mut (dyn BlockDevice + 'static) = unsafe { core::mem::transmute(device) };
            let _ = registered.push(device);
        }
        log::info!("Registered {} platform block device(s)", registered.len());
    });
}

/// Identity of one storage device across menu, boot and EFI protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageId {
    /// NVMe namespace
    Nvme { controller_id: usize, nsid: u32 },
    /// AHCI/SATA port (index into the controller's active ports)
    Ahci { controller_id: usize, port: usize },
    /// USB mass storage device
    Usb {
        controller_id: usize,
        device_addr: u8,
    },
    /// SDHCI (SD card / eMMC)
    Sdhci { controller_id: usize },
    /// Platform-provided block device (via [`crate::PlatformConfig::block_devices`]).
    Platform { index: usize },
}

impl StorageId {
    /// Get a short description of the device type
    pub fn description(&self) -> &'static str {
        match self {
            StorageId::Nvme { .. } => "NVMe",
            StorageId::Ahci { .. } => "SATA",
            StorageId::Usb { .. } => "USB",
            StorageId::Sdhci { .. } => "SD",
            StorageId::Platform { .. } => "Platform",
        }
    }
}

/// A storage device found by [`devices()`].
#[derive(Debug, Clone)]
pub struct StorageDevice {
    /// Device identity used with [`with_disk()`].
    pub id: StorageId,
    /// PCI address of the controller, when the device sits behind one.
    pub pci: Option<PciAddress>,
    /// Geometry and media properties.
    pub info: BlockDeviceInfo,
    /// Short display name for boot menu entries (e.g. "NVMe ns1").
    pub label: String<32>,
}

/// Enumerate every available storage device.
///
/// Order: NVMe namespaces, AHCI ports, USB mass storage, SDHCI cards, then
/// platform-provided devices. USB mass-storage devices are initialized on
/// first sight and stay registered afterwards.
pub fn devices() -> Vec<StorageDevice> {
    let mut devices = Vec::new();
    let mut push = |device: StorageDevice| devices.push(device);

    for controller_id in 0..nvme::controller_count() {
        nvme::with_controller(controller_id, |controller| {
            let pci = controller.pci_address();
            for namespace in controller.namespaces() {
                push(StorageDevice {
                    id: StorageId::Nvme {
                        controller_id,
                        nsid: namespace.nsid,
                    },
                    pci: Some(pci),
                    info: fixed_disk_info(namespace.num_blocks, namespace.block_size),
                    label: label(format_args!("NVMe ns{}", namespace.nsid)),
                });
            }
        });
    }

    for controller_id in 0..ahci::controller_count() {
        ahci::with_controller(controller_id, |controller| {
            let pci = controller.pci_address();
            for port in 0..controller.num_active_ports() {
                let Some(port_info) = controller.get_port(port) else {
                    continue;
                };
                push(StorageDevice {
                    id: StorageId::Ahci {
                        controller_id,
                        port,
                    },
                    pci: Some(pci),
                    info: fixed_disk_info(port_info.sector_count, port_info.sector_size),
                    label: label(format_args!("SATA port {}", port)),
                });
            }
        });
    }

    for (controller_id, device_addr) in usb::find_mass_storage_devices() {
        if !usb::mass_storage::probe(controller_id, device_addr) {
            continue;
        }
        usb::mass_storage::with_device(controller_id, device_addr, |device, controller| {
            push(StorageDevice {
                id: StorageId::Usb {
                    controller_id,
                    device_addr,
                },
                pci: None,
                info: usb_disk_info(device),
                label: label(format_args!("{} USB", controller.controller_type())),
            });
        });
    }

    for controller_id in 0..sdhci::controller_count() {
        sdhci::with_controller(controller_id, |controller| {
            if !controller.is_ready() {
                return;
            }
            let pci = controller.pci_address();
            push(StorageDevice {
                id: StorageId::Sdhci { controller_id },
                pci,
                info: sdhci_disk_info(controller),
                label: label(format_args!(
                    "{}",
                    if pci.is_some() { "SD card" } else { "eMMC" }
                )),
            });
        });
    }

    PLATFORM_BLOCK_DEVICES.with_mut(|platform_devices| {
        for (index, &device) in platform_devices.iter().enumerate() {
            // SAFETY: registered devices outlive the firmware and the borrow
            // of the registry serializes access to them.
            let device = unsafe { &*device };
            push(StorageDevice {
                id: StorageId::Platform { index },
                pci: None,
                info: device.info(),
                label: label(format_args!("{}", device.name())),
            });
        }
    });

    devices
}

/// Lend the device identified by `id` to `f` as a `&mut dyn BlockDevice`.
///
/// The owning controller stays locked while `f` runs, so `f` must not call
/// into loaded images or access the same controller through another path.
///
/// # Returns
/// The closure's result, or [`BlockError::NoMedia`] when `id` does not
/// resolve to a present device.
pub fn with_disk<R>(
    id: StorageId,
    f: impl FnOnce(&mut dyn BlockDevice) -> R,
) -> Result<R, BlockError> {
    match id {
        StorageId::Nvme {
            controller_id,
            nsid,
        } => nvme::with_controller(controller_id, |controller| {
            let namespace = controller.get_namespace(nsid)?;
            let info = fixed_disk_info(namespace.num_blocks, namespace.block_size);
            Some(f(&mut Disk::new(info, |lba, count, buffer| {
                controller
                    .read_sectors(nsid, lba, count, buffer)
                    .map_err(read_failed(id, lba))
            })))
        }),
        StorageId::Ahci {
            controller_id,
            port,
        } => ahci::with_controller(controller_id, |controller| {
            let port_info = controller.get_port(port)?;
            let info = fixed_disk_info(port_info.sector_count, port_info.sector_size);
            Some(f(&mut Disk::new(info, |lba, count, buffer| {
                controller
                    .read_sectors_into(port, lba, count, buffer)
                    .map_err(read_failed(id, lba))
            })))
        }),
        StorageId::Usb {
            controller_id,
            device_addr,
        } => usb::mass_storage::with_device(controller_id, device_addr, |device, controller| {
            let info = usb_disk_info(device);
            Some(f(&mut Disk::new(info, |lba, count, buffer| {
                device
                    .read_sectors_generic(controller, lba, count, buffer)
                    .map_err(read_failed(id, lba))
            })))
        }),
        StorageId::Sdhci { controller_id } => sdhci::with_controller(controller_id, |controller| {
            if !controller.is_ready() {
                return None;
            }
            let info = sdhci_disk_info(controller);
            Some(f(&mut Disk::new(info, |lba, count, buffer| {
                controller
                    .read_sectors(lba, count, buffer)
                    .map_err(read_failed(id, lba))
            })))
        }),
        StorageId::Platform { index } => Some(PLATFORM_BLOCK_DEVICES.with_mut(|devices| {
            let &device = devices.get(index)?;
            // SAFETY: registered devices outlive the firmware and the mutable
            // borrow of the registry excludes any other access to them.
            Some(f(unsafe { &mut *device }))
        })),
    }
    .flatten()
    .ok_or(BlockError::NoMedia)
}

/// Log a failed driver read and convert the driver error.
fn read_failed<E>(id: StorageId, lba: u64) -> impl FnOnce(E) -> BlockError
where
    E: core::fmt::Debug + Into<BlockError>,
{
    move |error| {
        log::error!("{:?}: read failed at LBA {}: {:?}", id, lba, error);
        error.into()
    }
}

/// A driver device borrowed for one [`with_disk()`] call.
struct Disk<F> {
    info: BlockDeviceInfo,
    read: F,
}

impl<F> Disk<F>
where
    F: FnMut(u64, u32, &mut [u8]) -> Result<(), BlockError>,
{
    fn new(info: BlockDeviceInfo, read: F) -> Self {
        Self { info, read }
    }
}

impl<F> BlockDevice for Disk<F>
where
    F: FnMut(u64, u32, &mut [u8]) -> Result<(), BlockError>,
{
    fn info(&self) -> BlockDeviceInfo {
        self.info
    }

    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.validate_read(lba, count, buffer)?;
        if count == 0 {
            return Ok(());
        }
        let len = count as usize * self.info.block_size as usize;
        (self.read)(lba, count, &mut buffer[..len])
    }
}

/// Media description of a fixed, writable disk.
fn fixed_disk_info(num_blocks: u64, block_size: u32) -> BlockDeviceInfo {
    BlockDeviceInfo {
        num_blocks,
        block_size,
        media_id: 0,
        removable: false,
        read_only: false,
    }
}

fn usb_disk_info(device: &usb::UsbMassStorage) -> BlockDeviceInfo {
    BlockDeviceInfo {
        removable: true,
        ..fixed_disk_info(device.num_blocks, device.block_size)
    }
}

fn sdhci_disk_info(controller: &sdhci::SdhciController) -> BlockDeviceInfo {
    BlockDeviceInfo {
        removable: controller.removable(),
        ..fixed_disk_info(controller.num_blocks(), controller.block_size())
    }
}

/// Format a device label, truncated to the label capacity.
fn label(args: core::fmt::Arguments<'_>) -> String<32> {
    struct Truncating(String<32>);

    impl Write for Truncating {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            s.chars()
                .try_for_each(|c| self.0.push(c))
                .map_err(|_| core::fmt::Error)
        }
    }

    let mut label = Truncating(String::new());
    let _ = label.write_fmt(args);
    label.0
}

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
