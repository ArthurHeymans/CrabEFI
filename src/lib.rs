//! CrabEFI - A minimal UEFI implementation as a coreboot payload
//!
//! This library provides the core functionality for a minimal UEFI environment
//! that can boot Linux via shim+GRUB2 or systemd-boot on real laptop hardware.

#![no_std]
#![feature(abi_x86_interrupt)]
#![allow(dead_code)]
#![allow(unsafe_op_in_unsafe_fn)]

// Note: We don't use alloc for now as we don't have a heap allocator yet
// extern crate alloc;

pub mod arch;
pub mod coreboot;
pub mod drivers;
pub mod efi;
pub mod fs;
pub mod logger;
pub mod pe;

use core::panic::PanicInfo;

/// Global panic handler
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Try to print the panic message to serial
    if let Some(location) = info.location() {
        log::error!(
            "PANIC at {}:{}: {}",
            location.file(),
            location.line(),
            info.message()
        );
    } else {
        log::error!("PANIC: {}", info.message());
    }

    // Halt the CPU
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

/// Initialize the CrabEFI firmware
///
/// This is called from the entry point after switching to 64-bit mode.
///
/// # Arguments
///
/// * `coreboot_table_ptr` - Pointer to the coreboot tables
pub fn init(coreboot_table_ptr: u64) {
    // Early serial initialization for debugging
    drivers::serial::init_early();

    // Initialize logging
    logger::init();

    log::info!("CrabEFI v{} starting...", env!("CARGO_PKG_VERSION"));
    log::info!("Coreboot table pointer: {:#x}", coreboot_table_ptr);

    // Parse coreboot tables
    let cb_info = coreboot::tables::parse(coreboot_table_ptr as *const u8);

    log::info!("Parsed coreboot tables:");
    if let Some(ref serial) = cb_info.serial {
        log::info!("  Serial: port={:#x}", serial.baseaddr);
    }
    if let Some(ref fb) = cb_info.framebuffer {
        log::info!(
            "  Framebuffer: {}x{} @ {:#x}",
            fb.x_resolution,
            fb.y_resolution,
            fb.physical_address
        );
    }
    if let Some(rsdp) = cb_info.acpi_rsdp {
        log::info!("  ACPI RSDP: {:#x}", rsdp);
    }
    log::info!("  Memory regions: {}", cb_info.memory_map.len());

    // Print memory map summary
    let total_ram: u64 = cb_info
        .memory_map
        .iter()
        .filter(|r| r.region_type == coreboot::memory::MemoryType::Ram)
        .map(|r| r.size)
        .sum();
    log::info!("  Total RAM: {} MB", total_ram / (1024 * 1024));

    // Initialize paging
    #[cfg(target_arch = "x86_64")]
    arch::x86_64::paging::init(&cb_info.memory_map);

    // Initialize EFI environment
    efi::init(&cb_info);

    log::info!("CrabEFI initialized successfully!");
    log::info!("EFI System Table at: {:p}", efi::get_system_table());

    // Initialize storage subsystem
    init_storage();

    log::info!("Press Ctrl+A X to exit QEMU");

    // Halt and wait
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

/// Initialize storage subsystem and attempt to find bootable media
fn init_storage() {
    log::info!("Initializing storage subsystem...");

    // Enumerate PCI devices
    drivers::pci::init();
    drivers::pci::print_devices();

    // Initialize NVMe controllers
    drivers::nvme::init();

    // Try to find ESP on NVMe
    if let Some(controller) = drivers::nvme::get_controller(0) {
        log::info!("Probing NVMe controller for ESP...");

        match fs::gpt::find_esp_on_nvme(controller) {
            Ok(esp) => {
                log::info!(
                    "Found ESP: LBA {}-{} ({} MB)",
                    esp.first_lba,
                    esp.last_lba,
                    esp.size_bytes() / (1024 * 1024)
                );

                // Try to read FAT filesystem and find bootloader
                if let Some(ns) = controller.default_namespace() {
                    let nsid = ns.nsid;
                    let mut disk = fs::gpt::NvmeDisk::new(controller, nsid);

                    match fs::fat::FatFilesystem::new(&mut disk, esp.first_lba) {
                        Ok(mut fat) => {
                            log::info!("FAT filesystem mounted on ESP");

                            // Look for EFI bootloader
                            let boot_path = "EFI\\BOOT\\BOOTX64.EFI";
                            match fat.file_size(boot_path) {
                                Ok(size) => {
                                    log::info!("Found bootloader: {} ({} bytes)", boot_path, size);

                                    // Load and execute the bootloader
                                    if let Err(e) =
                                        load_and_execute_bootloader(&mut fat, boot_path, size)
                                    {
                                        log::error!("Failed to execute bootloader: {:?}", e);
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
                }
            }
            Err(e) => {
                log::warn!("No ESP found on NVMe: {:?}", e);
            }
        }
    } else {
        log::info!("No NVMe controllers available");
    }

    // TODO: Also check AHCI/SATA controllers
    log::info!("Storage initialization complete");
}

/// Load and execute an EFI bootloader from the filesystem
fn load_and_execute_bootloader<R: fs::gpt::SectorRead>(
    fat: &mut fs::fat::FatFilesystem<R>,
    path: &str,
    file_size: u32,
) -> Result<(), r_efi::efi::Status> {
    use efi::allocator::{allocate_pool, free_pool, MemoryType};
    use efi::boot_services;
    use efi::protocols::loaded_image::{create_loaded_image_protocol, LOADED_IMAGE_PROTOCOL_GUID};
    use r_efi::efi::Status;

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

    // Load the PE image
    let loaded_image = pe::load_image(&buffer[..bytes_read]).map_err(|status| {
        log::error!("Failed to load PE image: {:?}", status);
        let _ = free_pool(buffer_ptr);
        status
    })?;

    // Free the raw file buffer (we no longer need it - PE loader copied sections)
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
        firmware_handle,       // parent_handle
        system_table,          // system_table
        core::ptr::null_mut(), // device_handle (no device path yet)
        loaded_image.image_base,
        loaded_image.image_size,
    );

    if loaded_image_protocol.is_null() {
        log::error!("Failed to create LoadedImageProtocol");
        pe::unload_image(&loaded_image);
        return Err(Status::OUT_OF_RESOURCES);
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
    log::info!("Executing bootloader...");

    // Execute the bootloader
    let exec_status = pe::execute_image(&loaded_image, image_handle, system_table);

    // If the bootloader returns, log it
    log::info!("Bootloader returned with status: {:?}", exec_status);

    // Clean up (normally the bootloader would call ExitBootServices and never return)
    pe::unload_image(&loaded_image);

    if exec_status == Status::SUCCESS {
        Ok(())
    } else {
        Err(exec_status)
    }
}
