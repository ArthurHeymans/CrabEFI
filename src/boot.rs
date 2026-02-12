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

use crate::drivers::block::{
    AhciBlockDevice, AnyBlockDevice, BlockDevice, NvmeBlockDevice, SdhciBlockDevice, UsbBlockDevice,
};
use crate::drivers::storage::{self, StorageType};
use crate::efi;
use crate::efi::boot_services;
use crate::efi::protocols::block_io::{self, BLOCK_IO_PROTOCOL_GUID};
use crate::efi::protocols::device_path::{self, DEVICE_PATH_PROTOCOL_GUID, DevicePathInfo};
use crate::efi::protocols::simple_file_system::{self, SIMPLE_FILE_SYSTEM_GUID};
use crate::fs;
use crate::menu;
use crate::pe;
use r_efi::efi::Status;

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
pub fn install_block_io_protocols<D: BlockDevice>(
    disk: &mut D,
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

    // Read GPT header and all partitions
    let header = match fs::gpt::read_gpt_header(disk) {
        Ok(h) => h,
        Err(e) => {
            log::debug!("Failed to read GPT header: {:?}", e);
            return None;
        }
    };

    let partitions = match fs::gpt::read_partitions(disk, &header) {
        Ok(p) => p,
        Err(e) => {
            log::debug!("Failed to read partitions: {:?}", e);
            return None;
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
            let block_dev =
                NvmeBlockDevice::new(controller_id, nsid, num_blocks, block_size, 0);
            Some(AnyBlockDevice::Nvme(block_dev))
        }
        menu::DeviceType::Ahci {
            controller_id,
            port,
        } => {
            let block_dev =
                AhciBlockDevice::new(controller_id, port, num_blocks, block_size, 0);
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
            let block_dev =
                SdhciBlockDevice::new(controller_id, num_blocks, block_size, 0);
            Some(AnyBlockDevice::Sdhci(block_dev))
        }
    }
}

/// Create a StorageType for registering with the storage registry
fn create_storage_type(device_type: &menu::DeviceType) -> StorageType {
    match *device_type {
        menu::DeviceType::Nvme {
            controller_id,
            nsid,
        } => StorageType::Nvme {
            controller_id,
            nsid,
        },
        menu::DeviceType::Ahci {
            controller_id,
            port,
        } => StorageType::Ahci {
            controller_id,
            port,
        },
        menu::DeviceType::Usb {
            controller_id: _,
            device_addr: _,
        } => StorageType::Usb { slot_id: 0 },
        menu::DeviceType::Sdhci { controller_id } => StorageType::Sdhci { controller_id },
    }
}

/// Try to boot from an ESP partition
///
/// This replaces the four `try_boot_from_esp_{usb,nvme,ahci,sdhci}` functions.
/// It mounts FAT on the ESP, installs SimpleFileSystem + DevicePath + BlockIO
/// protocols on a new handle, then loads and executes the EFI bootloader.
///
/// # Arguments
/// * `disk` - Block device to read from
/// * `esp` - ESP partition info
/// * `partition_num` - 1-based partition number of the ESP
/// * `path_info` - Device path info for protocol installation
/// * `device_type` - Device type for creating block device and storage registration
/// * `num_blocks` - Total number of blocks on the device
/// * `block_size` - Block size in bytes
pub fn try_boot_from_esp<D: BlockDevice>(
    disk: &mut D,
    esp: &fs::gpt::Partition,
    partition_num: u32,
    path_info: &DevicePathInfo,
    device_type: &menu::DeviceType,
    num_blocks: u64,
    block_size: u32,
) -> bool {
    // Create block device for SimpleFileSystem
    let block_device = match create_block_device_for_sfs(device_type, num_blocks, block_size) {
        Some(bd) => bd,
        None => {
            log::error!("Failed to create block device for SFS");
            return false;
        }
    };

    // Initialize SimpleFileSystem protocol with the block device
    let sfs_protocol = simple_file_system::init(block_device, esp.first_lba);
    if sfs_protocol.is_null() {
        log::error!("Failed to initialize SimpleFileSystem protocol");
        return false;
    }

    // Mount FAT filesystem
    match fs::fat::FatFilesystem::new(disk, esp.first_lba) {
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
            let storage_type = create_storage_type(device_type);
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
            let boot_path = "EFI\\BOOT\\BOOTX64.EFI";
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
    use crate::display_secure_boot_error;
    use efi::allocator::{MemoryType, allocate_pool, free_pool};
    use efi::protocols::loaded_image::{LOADED_IMAGE_PROTOCOL_GUID, create_loaded_image_protocol};
    use r_efi::efi::Guid;

    /// EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID
    const LOADED_IMAGE_DEVICE_PATH_GUID: Guid = Guid::from_fields(
        0xbc62157e,
        0x3e33,
        0x4fec,
        0x99,
        0x20,
        &[0x2d, 0x3b, 0x36, 0xd7, 0x50, 0xdf],
    );

    log::info!("Loading bootloader: {} ({} bytes)", path, file_size);

    // Allocate buffer for raw file data
    let buffer_ptr = allocate_pool(MemoryType::LoaderData, file_size as usize)
        .map_err(|_| Status::OUT_OF_RESOURCES)?;

    // Read the file into the buffer
    let buffer = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, file_size as usize) };

    let bytes_read = fat.read_file_all(path, buffer).map_err(|e| {
        log::error!("Failed to read bootloader file: {:?}", e);
        let _ = free_pool(buffer_ptr);
        Status::DEVICE_ERROR
    })?;

    log::info!("Read {} bytes from {}", bytes_read, path);

    // Secure Boot verification (if enabled)
    if efi::auth::is_secure_boot_enabled() {
        log::debug!("Secure Boot: Verifying image...");
        match efi::auth::verify_pe_image_secure_boot(&buffer[..bytes_read]) {
            Ok(true) => {
                log::info!("Secure Boot: Image verification passed");
            }
            Ok(false) => {
                log::error!("Secure Boot: Image verification FAILED - not authorized");
                display_secure_boot_error();
                let _ = free_pool(buffer_ptr);
                return Err(Status::SECURITY_VIOLATION);
            }
            Err(e) => {
                log::error!("Secure Boot: Verification error: {:?}", e);
                display_secure_boot_error();
                let _ = free_pool(buffer_ptr);
                return Err(Status::SECURITY_VIOLATION);
            }
        }
    }

    // Load the PE image
    let loaded_image = pe::load_image(&buffer[..bytes_read]).inspect_err(|&status| {
        log::error!("Failed to load PE image: {:?}", status);
        let _ = free_pool(buffer_ptr);
    })?;

    // Free the raw file buffer
    let _ = free_pool(buffer_ptr);

    log::info!(
        "PE image loaded at {:#x}, entry point {:#x}, size {:#x}",
        loaded_image.image_base,
        loaded_image.entry_point,
        loaded_image.image_size
    );

    // Create an image handle for the loaded bootloader
    let image_handle = boot_services::create_handle().ok_or_else(|| {
        log::error!("Failed to create image handle");
        Status::OUT_OF_RESOURCES
    })?;

    // Create and install LoadedImageProtocol
    let system_table = efi::get_system_table();
    let firmware_handle = efi::get_firmware_handle();

    let loaded_image_protocol = create_loaded_image_protocol(
        firmware_handle,
        system_table,
        device_handle,
        loaded_image.image_base,
        loaded_image.image_size,
    );

    if loaded_image_protocol.is_null() {
        log::error!("Failed to create LoadedImageProtocol");
        pe::unload_image(&loaded_image);
        return Err(Status::OUT_OF_RESOURCES);
    }

    // Set the file path in LoadedImageProtocol
    let file_path = device_path::create_file_path_device_path(path);
    if !file_path.is_null() {
        unsafe {
            efi::protocols::loaded_image::set_file_path(loaded_image_protocol, file_path);
        }
        log::debug!("Set LoadedImage.FilePath to: {}", path);
    }

    let status = boot_services::install_protocol(
        image_handle,
        &LOADED_IMAGE_PROTOCOL_GUID,
        loaded_image_protocol as *mut core::ffi::c_void,
    );

    if status != Status::SUCCESS {
        log::error!("Failed to install LoadedImageProtocol: {:?}", status);
        pe::unload_image(&loaded_image);
        return Err(status);
    }

    log::info!("LoadedImageProtocol installed on handle {:?}", image_handle);

    // Install EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL
    // This is the full device path: <partition device path> / FilePath(bootloader)
    // Windows Boot Manager uses this to locate its boot device.
    let device_dp =
        boot_services::get_protocol_on_handle(device_handle, &DEVICE_PATH_PROTOCOL_GUID);
    let loaded_image_dp = device_path::create_loaded_image_device_path(
        device_dp as *const r_efi::protocols::device_path::Protocol,
        path,
    );
    if !loaded_image_dp.is_null() {
        let status = boot_services::install_protocol(
            image_handle,
            &LOADED_IMAGE_DEVICE_PATH_GUID,
            loaded_image_dp as *mut core::ffi::c_void,
        );
        if status == Status::SUCCESS {
            log::info!(
                "LoadedImageDevicePath protocol installed on handle {:?}",
                image_handle
            );
        } else {
            log::warn!("Failed to install LoadedImageDevicePath: {:?}", status);
        }
    }
    if !device_handle.is_null() {
        log::info!(
            "DeviceHandle set to {:?} (with SimpleFileSystem)",
            device_handle
        );
    }
    log::info!("Executing bootloader...");

    // Recompute CRC32 checksums since we've installed new protocols/handles
    efi::system_table::update_crc32();

    // Debug: verify system table integrity before execution
    unsafe {
        let st = &*system_table;
        log::debug!(
            "SystemTable check: boot_services={:?}, runtime_services={:?}",
            st.boot_services,
            st.runtime_services
        );
        if !st.boot_services.is_null() {
            let bs = &*st.boot_services;
            log::debug!(
                "BootServices check: signature={:#x}, check_event={:?}",
                bs.hdr.signature,
                bs.check_event
            );
        } else {
            log::error!("CRITICAL: boot_services is NULL!");
        }
    }

    // Execute the bootloader
    let exec_status = pe::execute_image(&loaded_image, image_handle, system_table);

    // If the bootloader returns, log it
    log::info!("Bootloader returned with status: {:?}", exec_status);

    // Clean up
    pe::unload_image(&loaded_image);

    if exec_status == Status::SUCCESS {
        Ok(())
    } else {
        Err(exec_status)
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
    }
}
