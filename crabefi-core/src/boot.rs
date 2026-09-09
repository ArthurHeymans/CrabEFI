//! Unified Boot Path Module
//!
//! This module consolidates the boot logic that was previously duplicated
//! per-storage-type in lib.rs. It provides:
//!
//! - `install_block_io_protocols()` — Generic function to install BlockIO and DevicePath
//!   protocols for a disk and all its GPT partitions
//! - `try_boot_from_esp()` — Generic function to mount FAT on the ESP, install
//!   SimpleFileSystem, and load/execute the EFI bootloader
//!
//! These replace the four `install_block_io_for_{usb,nvme,ahci,sdhci}_disk` functions
//! and the four `try_boot_from_esp_{usb,nvme,ahci,sdhci}` functions.

use core::sync::atomic::{AtomicBool, Ordering};

use r_efi::efi::Status;

use crate::drivers::block::{
    AhciBlockDevice, AnyBlockDevice, BlockDevice, NvmeBlockDevice, SdhciBlockDevice, UsbBlockDevice,
};
use crate::drivers::storage;
use crate::efi;
use crate::efi::boot_services;
use crate::efi::protocols::block_io::{self, BLOCK_IO_PROTOCOL_GUID};
use crate::efi::protocols::device_path::{self, DEVICE_PATH_PROTOCOL_GUID, DevicePathInfo};
use crate::efi::protocols::simple_file_system::{self, SIMPLE_FILE_SYSTEM_GUID};
use crate::fs;
use crate::menu;

static GPT_MEASURED: AtomicBool = AtomicBool::new(false);

/// Install BlockIO and DevicePath protocols for a disk and all its GPT partitions
///
/// This replaces the four `install_block_io_for_{usb,nvme,ahci,sdhci}_disk` functions.
///
/// # Arguments
/// * `disk` - Block device to read GPT from
/// * `storage_id` - Storage device ID for BlockIO media_id
/// * `block_size` - Block size in bytes
/// * `num_blocks` - Total number of blocks on the device
/// * `path_info` - Device-specific info for constructing device paths
///
/// # Returns
/// The ESP partition and its 1-based partition number, if found
pub fn install_block_io_protocols(
    disk: &mut dyn BlockDevice,
    storage_id: u32,
    block_size: u32,
    num_blocks: u64,
    path_info: &DevicePathInfo,
) -> Option<(u32, fs::gpt::Partition)> {
    // Create BlockIO for the raw disk (whole device)
    let disk_block_io = block_io::create_disk_block_io(storage_id, num_blocks, block_size);

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

    // Read GPT partitions, falling back to MBR for removable media. If a GPT is
    // present, measure its header and non-empty partition entries into PCR 5 per
    // the TCG PC Client PFP EFI_GPT_DATA event format. The layout is detected
    // once and reused for the partition scan and the measurement payload.
    let gpt_scan = fs::gpt::read_gpt_layout(disk).and_then(|(header, is_hybrid)| {
        fs::gpt::read_partitions_with(disk, &header, is_hybrid).map(|p| (header, is_hybrid, p))
    });
    let partitions = match gpt_scan {
        Ok((header, is_hybrid, partitions)) => {
            if let Ok(event_data) =
                fs::gpt::build_gpt_measurement_event_with(disk, &header, is_hybrid)
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
            partitions
        }
        Err(error) => {
            log::debug!("GPT partition scan failed: {:?}; trying MBR", error);
            match fs::gpt::read_mbr_partitions(disk) {
                Ok(p) => {
                    let mut partitions = heapless::Vec::new();
                    for partition in p {
                        let _ = partitions.push(partition);
                    }
                    partitions
                }
                Err(e) => {
                    log::debug!("Failed to read partition table: {:?}", e);
                    return None;
                }
            }
        }
    };

    let mut esp_partition: Option<(u32, fs::gpt::Partition)> = None;
    let mut candidate_partitions: heapless::Vec<(u32, fs::gpt::Partition), 8> =
        heapless::Vec::new();

    // Create BlockIO for each partition
    for (i, partition) in partitions.iter().enumerate() {
        let partition_num = (i + 1) as u32;
        let partition_blocks = partition.size_sectors();

        let partition_block_io = block_io::create_partition_block_io(
            storage_id,
            partition_num,
            partition.first_lba,
            partition_blocks,
            block_size,
        );

        if !partition_block_io.is_null()
            && let Some(part_handle) = boot_services::create_handle()
        {
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

        // Remember ESP for later (with partition number)
        if partition.is_esp {
            log::info!(
                "Found ESP: partition {}, LBA {}-{} ({} MB)",
                partition_num,
                partition.first_lba,
                partition.last_lba,
                partition.size_bytes() / (1024 * 1024)
            );
            esp_partition = Some((partition_num, partition.clone()));
        } else {
            // Track as candidate for fallback (small partitions are more likely to be EFI boot)
            let size_mb = partition.size_bytes() / (1024 * 1024);
            if size_mb > 0 && size_mb < 512 && partition.first_lba > 0 {
                let _ = candidate_partitions.push((partition_num, partition.clone()));
            }
        }
    }

    // If we found a proper ESP, return it
    if esp_partition.is_some() {
        return esp_partition;
    }

    // No proper ESP found - try candidate partitions (smaller ones first)
    candidate_partitions
        .as_mut_slice()
        .sort_unstable_by_key(|(_, partition)| partition.size_bytes());

    if let Some((partition_num, partition)) = candidate_partitions.first() {
        log::debug!(
            "Trying partition {} as potential ESP (no proper ESP found)",
            partition_num
        );
        return Some((*partition_num, partition.clone()));
    }

    None
}

/// Create an `AnyBlockDevice` for the SimpleFileSystem protocol
///
/// This creates the correct block device variant based on device type,
/// used by the SFS protocol for filesystem reads.
fn create_block_device_for_sfs(
    device_type: &menu::DeviceType,
    num_blocks: u64,
    block_size: u32,
) -> Option<AnyBlockDevice> {
    match *device_type {
        menu::DeviceType::Nvme {
            controller_id,
            nsid,
        } => {
            let block_dev = NvmeBlockDevice::new(controller_id, nsid, num_blocks, block_size, 0);
            Some(AnyBlockDevice::Nvme(block_dev))
        }
        menu::DeviceType::Ahci {
            controller_id,
            port,
        } => {
            let block_dev = AhciBlockDevice::new(controller_id, port, num_blocks, block_size, 0);
            Some(AnyBlockDevice::Ahci(block_dev))
        }
        menu::DeviceType::Usb {
            controller_id,
            device_addr,
        } => {
            let block_dev =
                UsbBlockDevice::new(controller_id, device_addr, num_blocks, block_size, 0);
            Some(AnyBlockDevice::Usb(block_dev))
        }
        menu::DeviceType::Sdhci { controller_id } => {
            let removable = crate::drivers::sdhci::with_controller(controller_id, |controller| {
                controller.removable()
            })?;
            let block_dev = SdhciBlockDevice::new_with_removable(
                controller_id,
                num_blocks,
                block_size,
                0,
                removable,
            );
            Some(AnyBlockDevice::Sdhci(block_dev))
        }
        menu::DeviceType::Platform { .. } => {
            // Platform block devices are accessed through with_disk() → PlatformBlockShim
            // rather than AnyBlockDevice, which only wraps PCI-discovered devices.
            None
        }
    }
}

/// Try to boot from an ESP partition
///
/// This replaces the four `try_boot_from_esp_{usb,nvme,ahci,sdhci}` functions.
/// It mounts FAT on the ESP, installs SimpleFileSystem + DevicePath + BlockIO
/// protocols on a new handle, then loads and executes the EFI bootloader.
///
/// # Arguments
/// * `esp` - ESP partition info
/// * `partition_num` - 1-based partition number of the ESP
/// * `path_info` - Device path info for protocol installation
/// * `device_type` - Device type for creating block device and storage registration
/// * `num_blocks` - Total number of blocks on the device
/// * `block_size` - Block size in bytes
pub fn try_boot_from_esp(
    esp: &fs::gpt::Partition,
    partition_num: u32,
    path_info: &DevicePathInfo,
    device_type: &menu::DeviceType,
    num_blocks: u64,
    block_size: u32,
) -> bool {
    let mut disk = match create_block_device_for_sfs(device_type, num_blocks, block_size) {
        Some(disk) => disk,
        None => {
            log::error!("Failed to create block device for ESP");
            return false;
        }
    };
    let block_device = match create_block_device_for_sfs(device_type, num_blocks, block_size) {
        Some(block_device) => block_device,
        None => {
            log::error!("Failed to create block device for SFS");
            return false;
        }
    };

    // Initialize SimpleFileSystem protocol with independently locked storage.
    let sfs_protocol = simple_file_system::init(block_device, esp.first_lba);
    if sfs_protocol.is_null() {
        log::error!("Failed to initialize SimpleFileSystem protocol");
        return false;
    }

    // Mount FAT filesystem
    match fs::fat::FatFilesystem::new(&mut disk, esp.first_lba) {
        Ok(mut fat) => {
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
            let storage_type = *device_type;
            let storage_id = storage::register_device(storage_type, num_blocks, block_size);

            if let Some(storage_id) = storage_id {
                let block_io = block_io::create_partition_block_io(
                    storage_id,
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

            // Look for EFI bootloader
            let boot_path = crate::menu::EFI_BOOT_PATH;
            match fat.file_size(boot_path) {
                Ok(size) => {
                    log::info!("Found bootloader: {} ({} bytes)", boot_path, size);

                    // Load and execute the bootloader with device handle
                    match load_and_execute_bootloader(&mut fat, boot_path, size, device_handle) {
                        Ok(()) => return true,
                        Err(e) => {
                            log::error!("Failed to execute bootloader: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Bootloader not found: {:?}", e);
                }
            }
        }
        Err(e) => {
            log::error!("Failed to mount FAT filesystem: {:?}", e);
        }
    }
    false
}

/// Load and execute an EFI bootloader from the filesystem
fn load_and_execute_bootloader(
    fat: &mut fs::fat::FatFilesystem<'_>,
    path: &str,
    file_size: u32,
    device_handle: r_efi::efi::Handle,
) -> Result<(), Status> {
    use core::ptr;
    use efi::allocator::{MemoryType, allocate_pool, free_pool};

    log::info!("Loading bootloader: {} ({} bytes)", path, file_size);
    let buffer_ptr = allocate_pool(MemoryType::LoaderData, file_size as usize)?;
    // SAFETY: the pool allocation spans file_size bytes and is exclusively owned here.
    let buffer = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, file_size as usize) };
    let bytes_read = fat.read_file_all(path, buffer).map_err(|e| {
        log::error!("Failed to read bootloader file: {:?}", e);
        let _ = free_pool(buffer_ptr);
        Status::DEVICE_ERROR
    })?;

    let device_dp =
        boot_services::get_protocol_on_handle(device_handle, &DEVICE_PATH_PROTOCOL_GUID);
    let full_path = device_path::create_loaded_image_device_path(device_dp.cast(), path);
    if full_path.is_null() {
        let _ = free_pool(buffer_ptr);
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
        buffer_ptr.cast(),
        bytes_read,
        &mut image_handle,
    );
    let _ = free_pool(buffer_ptr);
    let _ = free_pool(full_path.cast());
    if status != Status::SUCCESS {
        return Err(status);
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
    match entry.device_type {
        menu::DeviceType::Nvme {
            controller_id: _,
            nsid,
        } => DevicePathInfo::Nvme {
            pci_device: entry.pci_device,
            pci_function: entry.pci_function,
            namespace_id: nsid,
        },
        menu::DeviceType::Ahci {
            controller_id: _,
            port,
        } => {
            // Detect El Torito boot: partition_num == 0 means this came from
            // ISO9660 El Torito discovery (not GPT). Use CDROM device path.
            if entry.partition_num == 0 {
                let partition_size = entry
                    .partition
                    .last_lba
                    .saturating_sub(entry.partition.first_lba)
                    + 1;
                DevicePathInfo::AhciCdrom {
                    pci_device: entry.pci_device,
                    pci_function: entry.pci_function,
                    port: port as u16,
                    boot_entry: 0, // Default boot catalog entry
                    partition_start: entry.partition.first_lba,
                    partition_size,
                }
            } else {
                DevicePathInfo::Ahci {
                    pci_device: entry.pci_device,
                    pci_function: entry.pci_function,
                    port: port as u16,
                }
            }
        }
        menu::DeviceType::Usb {
            controller_id: _,
            device_addr: _,
        } => DevicePathInfo::Usb {
            pci_device: entry.pci_device,
            pci_function: entry.pci_function,
            usb_port: 0,
        },
        menu::DeviceType::Sdhci { controller_id: _ } => DevicePathInfo::Sdhci {
            pci_device: entry.pci_device,
            pci_function: entry.pci_function,
        },
        menu::DeviceType::Platform { index } => DevicePathInfo::Platform { index },
    }
}
