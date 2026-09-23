//! UEFI Boot Path
//!
//! Storage-agnostic boot logic shared by every [`StorageId`]:
//!
//! - `install_block_io_protocols()` — install BlockIO, DiskIO and DevicePath
//!   protocols for a disk and all its partitions
//! - `try_boot_from_esp()` — install SimpleFileSystem on the ESP and load and
//!   execute the EFI bootloader

#[cfg(feature = "tpm")]
use core::sync::atomic::{AtomicBool, Ordering};

use r_efi::efi::Status;

use crate::drivers::block::{BlockDevice, BlockDeviceInfo};
use crate::drivers::storage::{self, StorageId};
use crate::efi;
use crate::efi::boot_services;
use crate::efi::protocols::block_io::{self, BLOCK_IO_PROTOCOL_GUID};
use crate::efi::protocols::device_path::{self, DEVICE_PATH_PROTOCOL_GUID, DevicePathInfo};
use crate::efi::protocols::simple_file_system::{self, SIMPLE_FILE_SYSTEM_GUID};
use crate::fs;
use crate::menu;

#[cfg(feature = "tpm")]
static GPT_MEASURED: AtomicBool = AtomicBool::new(false);

/// Measure the GPT header and non-empty partition entries into PCR 5, once per
/// boot, per the TCG PC Client PFP EFI_GPT_DATA event format. Without the `tpm`
/// capability this is a no-op; the caller still reuses the detected layout for
/// the partition scan.
#[cfg(feature = "tpm")]
fn measure_gpt_once(disk: &mut dyn BlockDevice, header: &fs::gpt::GptHeader, is_hybrid: bool) {
    if let Ok(event_data) = fs::gpt::build_gpt_measurement_event_with(disk, header, is_hybrid)
        && !GPT_MEASURED.swap(true, Ordering::Relaxed)
    {
        // EDK2 measures EV_EFI_GPT_EVENT once per boot, not once per boot attempt.
        efi::tcg::measured_boot::measure_event_all(
            5,
            efi::tcg::types::EV_EFI_GPT_EVENT,
            &event_data,
            &event_data,
            "GPT partition table",
        );
    }
}

/// Without `tpm` there is nothing to measure.
#[cfg(not(feature = "tpm"))]
fn measure_gpt_once(_disk: &mut dyn BlockDevice, _header: &fs::gpt::GptHeader, _is_hybrid: bool) {}

/// Install BlockIO, DiskIO and DevicePath protocols for a disk and all its partitions
///
/// # Arguments
/// * `storage` - Disk to read the partition table from
/// * `info` - Geometry of the disk
/// * `path_info` - Device-specific info for constructing device paths
pub fn install_block_io_protocols(
    storage: StorageId,
    info: BlockDeviceInfo,
    path_info: &DevicePathInfo,
) {
    // Create BlockIO for the raw disk (whole device)
    let disk_block_io = block_io::create_disk_block_io(storage, info.num_blocks, info.block_size);

    if !disk_block_io.is_null()
        && let Some(disk_handle) = boot_services::create_handle()
    {
        // Install BlockIO protocol
        let status = boot_services::install_protocol(
            disk_handle,
            &BLOCK_IO_PROTOCOL_GUID,
            disk_block_io as *mut core::ffi::c_void,
        );
        if status == Status::SUCCESS {
            log::info!(
                "BlockIO protocol installed for raw disk on handle {:?}",
                disk_handle
            );
        }

        // Install DiskIO protocol on raw disk handle
        efi::protocols::disk_io::install_disk_io_on_handle(disk_handle);

        // Install DevicePath protocol for the raw disk
        let disk_device_path = device_path::create_disk_device_path(path_info);
        if !disk_device_path.is_null() {
            let status = boot_services::install_protocol(
                disk_handle,
                &DEVICE_PATH_PROTOCOL_GUID,
                disk_device_path as *mut core::ffi::c_void,
            );
            if status == Status::SUCCESS {
                log::info!(
                    "DevicePath protocol installed for raw disk on handle {:?}",
                    disk_handle
                );
            }
        }
    }

    let partitions = match storage::with_disk(storage, scan_partitions) {
        Ok(Ok(partitions)) => partitions,
        Ok(Err(error)) => {
            log::debug!("Failed to read partition table: {:?}", error);
            return;
        }
        Err(error) => {
            log::debug!("Failed to access {:?}: {}", storage, error);
            return;
        }
    };

    // Create BlockIO for each partition
    for (i, partition) in partitions.iter().enumerate() {
        let partition_num = (i + 1) as u32;
        let partition_blocks = partition.size_sectors();

        let partition_block_io = block_io::create_partition_block_io(
            storage,
            partition_num,
            partition.first_lba,
            partition_blocks,
            info.block_size,
        );

        if partition_block_io.is_null() {
            continue;
        }
        let Some(part_handle) = boot_services::create_handle() else {
            continue;
        };

        // Install BlockIO
        let status = boot_services::install_protocol(
            part_handle,
            &BLOCK_IO_PROTOCOL_GUID,
            partition_block_io as *mut core::ffi::c_void,
        );
        if status == Status::SUCCESS {
            log::info!(
                "BlockIO protocol installed for partition {} on handle {:?}",
                partition_num,
                part_handle
            );
        }

        // Install DiskIO protocol on partition handle
        efi::protocols::disk_io::install_disk_io_on_handle(part_handle);

        // Install DevicePath for partition
        let part_device_path = device_path::create_partition_device_path(
            path_info,
            partition_num,
            partition.first_lba,
            partition_blocks,
            &partition.partition_guid,
        );

        if !part_device_path.is_null() {
            let status = boot_services::install_protocol(
                part_handle,
                &DEVICE_PATH_PROTOCOL_GUID,
                part_device_path as *mut core::ffi::c_void,
            );
            if status == Status::SUCCESS {
                log::info!(
                    "DevicePath protocol installed for partition {} on handle {:?}",
                    partition_num,
                    part_handle
                );
            }
        }
    }
}

/// Read the partition table, measuring a GPT into PCR 5 once per boot.
///
/// Falls back to an MBR partition table when no GPT is present.
fn scan_partitions(
    disk: &mut dyn BlockDevice,
) -> Result<heapless::Vec<fs::gpt::Partition, 16>, fs::gpt::GptError> {
    // The layout is detected once and reused for the partition scan and the
    // measurement payload.
    let gpt_scan = fs::gpt::read_gpt_layout(disk).and_then(|(header, is_hybrid)| {
        fs::gpt::read_partitions_with(disk, &header, is_hybrid).map(|p| (header, is_hybrid, p))
    });
    match gpt_scan {
        Ok((header, is_hybrid, partitions)) => {
            measure_gpt_once(disk, &header, is_hybrid);
            Ok(partitions)
        }
        Err(error) => {
            log::debug!("GPT partition scan failed: {:?}; trying MBR", error);
            Ok(fs::gpt::read_mbr_partitions(disk)?.into_iter().collect())
        }
    }
}

/// Try to boot from an ESP partition
///
/// Mounts the ESP as SimpleFileSystem, installs it together with DevicePath,
/// BlockIO and DiskIO protocols on a new handle, then loads and executes the
/// EFI bootloader.
///
/// # Arguments
/// * `esp` - ESP partition info
/// * `partition_num` - 1-based partition number of the ESP
/// * `path_info` - Device path info for protocol installation
/// * `storage` - Disk holding the ESP
/// * `block_size` - Block size of the disk in bytes
pub fn try_boot_from_esp(
    esp: &fs::gpt::Partition,
    partition_num: u32,
    path_info: &DevicePathInfo,
    storage: StorageId,
    block_size: u32,
) -> bool {
    // Mounting the SimpleFileSystem also validates the FAT filesystem.
    let sfs_protocol = simple_file_system::init(storage, esp.first_lba);
    if sfs_protocol.is_null() {
        log::error!("Failed to initialize SimpleFileSystem protocol");
        return false;
    }
    log::info!("FAT filesystem mounted on ESP");

    // Create a device handle with SimpleFileSystem and DevicePath protocols
    let device_handle = match boot_services::create_handle() {
        Some(h) => h,
        None => {
            log::error!("Failed to create device handle");
            return false;
        }
    };

    // Install DevicePath protocol on the device handle
    let partition_size = esp.size_sectors();
    let dp = device_path::create_partition_device_path(
        path_info,
        partition_num,
        esp.first_lba,
        partition_size,
        &esp.partition_guid,
    );

    if !dp.is_null() {
        let status = boot_services::install_protocol(
            device_handle,
            &DEVICE_PATH_PROTOCOL_GUID,
            dp as *mut core::ffi::c_void,
        );
        if status == Status::SUCCESS {
            log::info!(
                "DevicePath protocol installed on device handle {:?}",
                device_handle
            );
        } else {
            log::warn!("Failed to install DevicePath protocol: {:?}", status);
        }
    }

    // Install BlockIO protocol on the device handle
    let block_io = block_io::create_partition_block_io(
        storage,
        partition_num,
        esp.first_lba,
        partition_size,
        block_size,
    );

    if !block_io.is_null() {
        let status = boot_services::install_protocol(
            device_handle,
            &BLOCK_IO_PROTOCOL_GUID,
            block_io as *mut core::ffi::c_void,
        );
        if status == Status::SUCCESS {
            log::info!(
                "BlockIO protocol installed on device handle {:?}",
                device_handle
            );
        } else {
            log::warn!("Failed to install BlockIO protocol: {:?}", status);
        }
    }

    // Install DiskIO protocol (byte-granular I/O wrapper over BlockIO)
    efi::protocols::disk_io::install_disk_io_on_handle(device_handle);

    // Install SimpleFileSystem protocol on the device handle
    let status = boot_services::install_protocol(
        device_handle,
        &SIMPLE_FILE_SYSTEM_GUID,
        sfs_protocol as *mut core::ffi::c_void,
    );

    if status != Status::SUCCESS {
        log::error!("Failed to install SimpleFileSystem protocol: {:?}", status);
        return false;
    }

    log::info!(
        "SimpleFileSystem protocol installed on device handle {:?}",
        device_handle
    );

    // Read the bootloader, then release the disk before executing it: the
    // loaded image reads through the same disk via the installed protocols.
    let boot_path = crate::menu::EFI_BOOT_PATH;
    let image = match storage::with_disk(storage, |disk| {
        read_bootloader(disk, esp.first_lba, boot_path)
    }) {
        Ok(Ok(image)) => image,
        Ok(Err(_)) => return false,
        Err(error) => {
            log::error!("Failed to access {:?}: {}", storage, error);
            return false;
        }
    };

    match execute_bootloader(image, boot_path, device_handle) {
        Ok(()) => true,
        Err(e) => {
            log::error!("Failed to execute bootloader: {:?}", e);
            false
        }
    }
}

/// A bootloader image read into a `LoaderData` pool buffer.
struct BootloaderImage {
    buffer: *mut u8,
    len: usize,
}

/// Read an EFI bootloader from the FAT filesystem at `partition_start`.
fn read_bootloader(
    disk: &mut dyn BlockDevice,
    partition_start: u64,
    path: &str,
) -> Result<BootloaderImage, Status> {
    use efi::allocator::{MemoryType, allocate_pool, free_pool};

    let mut fat = fs::fat::FatFilesystem::new(disk, partition_start).map_err(|e| {
        log::error!("Failed to mount FAT filesystem: {:?}", e);
        Status::VOLUME_CORRUPTED
    })?;
    let file_size = fat.file_size(path).map_err(|e| {
        log::warn!("Bootloader not found: {:?}", e);
        Status::NOT_FOUND
    })?;
    log::info!("Loading bootloader: {} ({} bytes)", path, file_size);

    let buffer = allocate_pool(MemoryType::LoaderData, file_size as usize)?;
    // SAFETY: the pool allocation spans file_size bytes and is exclusively owned here.
    let slice = unsafe { core::slice::from_raw_parts_mut(buffer, file_size as usize) };
    match fat.read_file_all(path, slice) {
        Ok(len) => Ok(BootloaderImage { buffer, len }),
        Err(e) => {
            log::error!("Failed to read bootloader file: {:?}", e);
            let _ = free_pool(buffer);
            Err(Status::DEVICE_ERROR)
        }
    }
}

/// Load and start a bootloader image, freeing its buffer.
fn execute_bootloader(
    image: BootloaderImage,
    path: &str,
    device_handle: r_efi::efi::Handle,
) -> Result<(), Status> {
    use core::ptr;
    use efi::allocator::free_pool;
    use efi::protocols::loaded_image::LOADED_IMAGE_PROTOCOL_GUID;

    let device_dp =
        boot_services::get_protocol_on_handle(device_handle, &DEVICE_PATH_PROTOCOL_GUID);
    let full_path = device_path::create_loaded_image_device_path(device_dp.cast(), path);
    if full_path.is_null() {
        let _ = free_pool(image.buffer);
        return Err(Status::OUT_OF_RESOURCES);
    }

    // Use the same authentication, measurement, protocol ownership, and execution
    // lifecycle as subsequently loaded children. LoadImage copies both buffers.
    let bs = unsafe { &*boot_services::get_boot_services() };
    let mut image_handle = ptr::null_mut();
    let status = (bs.load_image)(
        r_efi::efi::Boolean::TRUE,
        efi::get_firmware_handle(),
        full_path,
        image.buffer.cast(),
        image.len,
        &mut image_handle,
    );
    let _ = free_pool(image.buffer);
    let _ = free_pool(full_path.cast());
    if status != Status::SUCCESS {
        return Err(status);
    }

    // LoadImage derives LoadedImage.DeviceHandle by resolving the device path it
    // was given. A platform-provided block device has no device path protocol,
    // so that resolution fails and DeviceHandle is left NULL. Restore the handle
    // this bootloader was read from: shim and GRUB use it to locate their own
    // config and modules.
    let loaded_image =
        boot_services::get_protocol_on_handle(image_handle, &LOADED_IMAGE_PROTOCOL_GUID)
            as *mut r_efi::protocols::loaded_image::Protocol;
    if !loaded_image.is_null() && unsafe { (*loaded_image).device_handle.is_null() } {
        // SAFETY: the protocol is installed on the image handle we just created
        // and remains live until UnloadImage/StartImage teardown.
        unsafe { (*loaded_image).device_handle = device_handle };
        log::info!("LoadedImage.DeviceHandle restored to {device_handle:?}");
    }

    log::info!("Executing bootloader...");
    // No exit-data consumer at this level; StartImage frees any returned data.
    let status = (bs.start_image)(image_handle, ptr::null_mut(), ptr::null_mut());
    log::info!("Bootloader returned with status: {:?}", status);
    if status == Status::SUCCESS {
        Ok(())
    } else {
        // StartImage can also fail before invoking the application. If it did
        // run, its automatic teardown already removed the handle.
        let _ = (bs.unload_image)(image_handle);
        Err(status)
    }
}

/// Create DevicePathInfo from a BootEntry's device type and PCI info
///
/// For El Torito (ISO) boot entries on AHCI, this detects the case where
/// `partition_num == 0` (no GPT partition) and creates an `AhciCdrom` device
/// path instead of the normal `Ahci` hard drive path. This is critical for
/// Windows Boot Manager, which expects a CDROM media device path node
/// (type=0x04, subtype=0x02) rather than a HardDrive node.
pub fn device_path_info_from_entry(entry: &menu::BootEntry) -> DevicePathInfo {
    let (pci_device, pci_function) = entry
        .pci
        .map_or((0, 0), |address| (address.device(), address.function()));
    match entry.storage {
        StorageId::Nvme { nsid, .. } => DevicePathInfo::Nvme {
            pci_device,
            pci_function,
            namespace_id: nsid,
        },
        StorageId::Ahci { port, .. } => {
            // Detect El Torito boot: partition_num == 0 means this came from
            // ISO9660 El Torito discovery (not GPT). Use CDROM device path.
            if entry.partition_num == 0 {
                let partition_size = entry
                    .partition
                    .last_lba
                    .saturating_sub(entry.partition.first_lba)
                    + 1;
                DevicePathInfo::AhciCdrom {
                    pci_device,
                    pci_function,
                    port: port as u16,
                    boot_entry: 0, // Default boot catalog entry
                    partition_start: entry.partition.first_lba,
                    partition_size,
                }
            } else {
                DevicePathInfo::Ahci {
                    pci_device,
                    pci_function,
                    port: port as u16,
                }
            }
        }
        StorageId::Usb { .. } => DevicePathInfo::Usb {
            pci_device,
            pci_function,
            usb_port: 0,
        },
        StorageId::Sdhci { .. } => DevicePathInfo::Sdhci {
            pci_device,
            pci_function,
        },
        StorageId::Platform { index } => DevicePathInfo::Platform { index },
    }
}
