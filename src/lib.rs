//! CrabEFI - A minimal UEFI implementation as a coreboot payload
//!
//! This library provides the core functionality for a minimal UEFI environment
//! that can boot Linux via shim+GRUB2 or systemd-boot on real laptop hardware.

#![no_std]
#![feature(abi_x86_interrupt)]
#![allow(unsafe_op_in_unsafe_fn)]
// Allow common firmware code patterns
#![allow(clippy::result_unit_err)] // Result<(), ()> is common in embedded code
#![allow(clippy::too_many_arguments)] // USB/hardware APIs often require many parameters
#![allow(clippy::field_reassign_with_default)] // Clearer than complex struct initializers

// Note: We don't use alloc for now as we don't have a heap allocator yet
// extern crate alloc;

pub mod arch;
pub mod coreboot;
pub mod drivers;
pub mod efi;
#[cfg(feature = "fb-log")]
pub mod fb_log;
pub mod framebuffer_console;
pub mod fs;
pub mod logger;
pub mod menu;
pub mod pe;
pub mod state;
pub mod time;

use crate::drivers::block::{AhciDisk, BlockDevice, NvmeDisk, SdhciDisk, UsbDisk};
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

/// Sort partition candidates by size (smallest first)
///
/// Uses bubble sort since heapless::Vec doesn't have sort methods.
/// Smaller partitions are tried first as they're more likely to be EFI boot partitions.
fn sort_partitions_by_size(partitions: &mut heapless::Vec<(u32, fs::gpt::Partition), 8>) {
    for i in 0..partitions.len() {
        for j in (i + 1)..partitions.len() {
            if partitions[j].1.size_bytes() < partitions[i].1.size_bytes() {
                partitions.swap(i, j);
            }
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
    // Allocate firmware state on the stack
    // This is THE primary state for the entire firmware
    let mut firmware_state = state::FirmwareState::new();

    // Initialize the global state pointer
    // SAFETY: We're in the main entry point, single-threaded, and the state
    // lives on this stack frame which persists for the entire firmware lifetime
    unsafe {
        state::init(&mut firmware_state);
    }

    // Parse coreboot tables first (before any I/O) to get hardware info
    // SAFETY: coreboot_table_ptr is passed from coreboot and points to valid tables
    let cb_info = unsafe { coreboot::tables::parse(coreboot_table_ptr as *const u8) };

    // Initialize CBMEM console early (before logging) so all output goes there
    if let Some(cbmem_addr) = cb_info.cbmem_console {
        coreboot::cbmem_console::init(cbmem_addr);
    }

    // Store framebuffer globally for menu rendering
    if let Some(ref fb) = cb_info.framebuffer {
        coreboot::store_framebuffer(fb.clone());
        // Also store in new state
        state::with_drivers_mut(|drivers| {
            drivers.framebuffer = Some(fb.clone());
        });
    }

    // Initialize serial port from coreboot info (if available)
    if let Some(ref serial) = cb_info.serial {
        drivers::serial::init_from_coreboot(serial.baseaddr, serial.baud);
    }

    // Initialize logging (now that serial is set up)
    logger::init();

    // Set framebuffer for logging output (so we can see logs on screen)
    if let Some(ref fb) = cb_info.framebuffer {
        logger::set_framebuffer(fb.clone());
    }

    // Initialize PS/2 keyboard (if available)
    drivers::keyboard::init();

    log::info!("CrabEFI v{} starting...", env!("CARGO_PKG_VERSION"));
    log::info!("Coreboot table pointer: {:#x}", coreboot_table_ptr);

    log::info!("Parsed coreboot tables:");
    if let Some(ref serial) = cb_info.serial {
        log::info!(
            "  Serial: port={:#x}, baud={}",
            serial.baseaddr,
            serial.baud
        );
    } else {
        log::info!("  Serial: not available");
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
    if let Some(cbmem_console) = cb_info.cbmem_console {
        log::info!("  CBMEM console: {:#x}", cbmem_console);
    }
    log::info!("  Memory regions: {}", cb_info.memory_map.len());

    // Initialize timing subsystem (calibrate TSC using ACPI PM timer)
    time::init(cb_info.acpi_rsdp);

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

    // Initialize IDT for exception handling
    #[cfg(target_arch = "x86_64")]
    arch::x86_64::idt::init();

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

    // Initialize all storage controllers
    drivers::nvme::init();
    drivers::ahci::init();
    drivers::usb::init_all();
    drivers::sdhci::init();

    // Discover boot entries and show menu
    let mut boot_menu = menu::discover_boot_entries();

    if boot_menu.entry_count() == 0 {
        log::warn!("No bootable media found!");
        log::info!("Storage initialization complete");
        return;
    }

    // If only one entry and no interactive mode requested, boot directly
    // For now, always show the menu for testing
    if let Some(selected_index) = menu::show_menu(&mut boot_menu)
        && let Some(entry) = boot_menu.get_entry(selected_index)
    {
        log::info!("Booting: {} from {}", entry.name, entry.path);
        boot_selected_entry(entry);
    }

    log::info!("Boot menu returned, storage initialization complete");
}

/// Boot a selected menu entry
fn boot_selected_entry(entry: &menu::BootEntry) {
    match entry.device_type {
        menu::DeviceType::Nvme {
            controller_id,
            nsid,
        } => {
            use drivers::storage::{self, StorageType};

            // Ensure device is stored globally
            if !drivers::nvme::store_global_device(controller_id, nsid) {
                log::error!("Failed to store NVMe device globally");
                return;
            }

            if let Some(controller) = drivers::nvme::get_controller(controller_id) {
                // Get disk info for storage registration
                let (num_blocks, block_size) = match controller.default_namespace() {
                    Some(ns) => (ns.num_blocks, ns.block_size),
                    None => {
                        log::error!("Failed to get NVMe namespace info");
                        return;
                    }
                };

                // Register with storage abstraction (needed for BlockIO)
                let storage_id = match storage::register_device(
                    StorageType::Nvme {
                        controller_id,
                        nsid,
                    },
                    num_blocks,
                    block_size,
                ) {
                    Some(id) => id,
                    None => {
                        log::error!("Failed to register NVMe device with storage");
                        return;
                    }
                };

                // Get PCI address
                let pci_addr = controller.pci_address();

                // Create disk for partition installation
                let mut disk = NvmeDisk::new(controller, nsid);

                // Install BlockIO for ALL partitions (GRUB needs this to enumerate)
                let _ = install_block_io_for_nvme_disk(
                    &mut disk,
                    storage_id,
                    block_size,
                    num_blocks,
                    pci_addr.device,
                    pci_addr.function,
                    nsid,
                );

                // Re-create disk and boot from ESP
                if let Some(controller) = drivers::nvme::get_controller(controller_id) {
                    let mut disk = NvmeDisk::new(controller, nsid);
                    if try_boot_from_esp_nvme(
                        &mut disk,
                        &entry.partition,
                        entry.partition_num,
                        entry.pci_device,
                        entry.pci_function,
                        nsid,
                    ) {
                        return;
                    }
                }
            }
            log::error!("Failed to boot NVMe entry");
        }
        menu::DeviceType::Ahci {
            controller_id,
            port,
        } => {
            use drivers::storage::{self, StorageType};

            // Ensure device is stored globally
            if !drivers::ahci::store_global_device(controller_id, port) {
                log::error!("Failed to store AHCI device globally");
                return;
            }

            if let Some(controller) = drivers::ahci::get_controller(controller_id) {
                // Get disk info for storage registration
                let (num_blocks, block_size) = match controller.get_port(port) {
                    Some(port_info) => (port_info.sector_count, port_info.sector_size),
                    None => {
                        log::error!("Failed to get AHCI port info");
                        return;
                    }
                };

                // Register with storage abstraction (needed for BlockIO)
                let storage_id = match storage::register_device(
                    StorageType::Ahci {
                        controller_id,
                        port,
                    },
                    num_blocks,
                    block_size,
                ) {
                    Some(id) => id,
                    None => {
                        log::error!("Failed to register AHCI device with storage");
                        return;
                    }
                };

                // Get PCI address
                let pci_addr = controller.pci_address();

                // Create disk for partition installation
                let mut disk = AhciDisk::new(controller, port);

                // Install BlockIO for ALL partitions (GRUB needs this to enumerate)
                let _ = install_block_io_for_ahci_disk(
                    &mut disk,
                    storage_id,
                    block_size,
                    num_blocks,
                    pci_addr.device,
                    pci_addr.function,
                    port as u16,
                );

                // Re-create disk and boot from ESP
                if let Some(controller) = drivers::ahci::get_controller(controller_id) {
                    let mut disk = AhciDisk::new(controller, port);
                    if try_boot_from_esp_ahci(
                        &mut disk,
                        &entry.partition,
                        entry.partition_num,
                        entry.pci_device,
                        entry.pci_function,
                        port as u16,
                    ) {
                        return;
                    }
                }
            }
            log::error!("Failed to boot AHCI entry");
        }
        menu::DeviceType::Usb {
            controller_id,
            device_addr: _,
        } => {
            use drivers::storage::{self, StorageType};

            // Get the controller pointer directly (no lock needed for the boot phase
            // since global_read_sector stores the pointer)
            let controller_ptr = match drivers::usb::get_controller_ptr(controller_id) {
                Some(ptr) => ptr,
                None => {
                    log::error!("Failed to get USB controller {}", controller_id);
                    return;
                }
            };

            // USB device should already be stored globally from discovery
            if let Some(usb_device) = drivers::usb::mass_storage::get_global_device() {
                // Get disk info for storage registration
                let num_blocks = usb_device.num_blocks;
                let block_size = usb_device.block_size;

                // Register with storage abstraction (needed for BlockIO)
                let storage_id = match storage::register_device(
                    StorageType::Usb { slot_id: 0 },
                    num_blocks,
                    block_size,
                ) {
                    Some(id) => id,
                    None => {
                        log::error!("Failed to register USB device with storage");
                        return;
                    }
                };

                // Safety: controller_ptr is valid for the entire boot process
                let controller = unsafe { &mut *controller_ptr };

                // Create disk for partition installation
                if let Some(usb_device) = drivers::usb::mass_storage::get_global_device() {
                    let mut disk = UsbDisk::new(usb_device, controller);

                    // Install BlockIO for ALL partitions (GRUB needs this to enumerate)
                    let _ = install_block_io_for_disk(
                        &mut disk,
                        storage_id,
                        block_size,
                        num_blocks,
                        entry.pci_device,
                        entry.pci_function,
                        0, // USB port
                    );
                }

                // Re-get usb_device and controller for boot attempt
                // (previous borrows have ended)
                let controller = unsafe { &mut *controller_ptr };
                if let Some(usb_device) = drivers::usb::mass_storage::get_global_device() {
                    let mut disk = UsbDisk::new(usb_device, controller);
                    if try_boot_from_esp_usb(
                        &mut disk,
                        &entry.partition,
                        entry.partition_num,
                        entry.pci_device,
                        entry.pci_function,
                        0, // USB port (default)
                    ) {
                        return;
                    }
                }
            }
            log::error!("Failed to boot USB entry");
        }
        menu::DeviceType::Sdhci { controller_id } => {
            use drivers::storage::{self, StorageType};

            // Ensure device is stored globally
            if !drivers::sdhci::store_global_device(controller_id) {
                log::error!("Failed to store SDHCI device globally");
                return;
            }

            if let Some(controller) = drivers::sdhci::get_controller(controller_id) {
                // Get disk info for storage registration
                let num_blocks = controller.num_blocks();
                let block_size = controller.block_size();

                // Register with storage abstraction (needed for BlockIO)
                let storage_id = match storage::register_device(
                    StorageType::Sdhci { controller_id },
                    num_blocks,
                    block_size,
                ) {
                    Some(id) => id,
                    None => {
                        log::error!("Failed to register SDHCI device with storage");
                        return;
                    }
                };

                // Get PCI address
                let pci_addr = controller.pci_address();

                // Create disk for partition installation
                let mut disk = SdhciDisk::new(controller);

                // Install BlockIO for ALL partitions (GRUB needs this to enumerate)
                let _ = install_block_io_for_sdhci_disk(
                    &mut disk,
                    storage_id,
                    block_size,
                    num_blocks,
                    pci_addr.device,
                    pci_addr.function,
                );

                // Re-create disk and boot from ESP
                if let Some(controller) = drivers::sdhci::get_controller(controller_id) {
                    let mut disk = SdhciDisk::new(controller);
                    if try_boot_from_esp_sdhci(
                        &mut disk,
                        &entry.partition,
                        entry.partition_num,
                        entry.pci_device,
                        entry.pci_function,
                    ) {
                        return;
                    }
                }
            }
            log::error!("Failed to boot SDHCI entry");
        }
    }
}

/// Install BlockIO protocols for a disk and all its partitions
///
/// Returns the ESP partition and its partition number (1-based) if found.
///
/// # Arguments
/// * `disk` - Disk to read GPT from
/// * `storage_id` - Storage device ID for BlockIO
/// * `block_size` - Block size in bytes
/// * `num_blocks` - Total number of blocks
/// * `pci_device` - PCI device number of the controller (for USB device path)
/// * `pci_function` - PCI function number
/// * `usb_port` - USB port number (0 for non-USB devices)
fn install_block_io_for_disk<R: BlockDevice>(
    disk: &mut R,
    storage_id: u32,
    block_size: u32,
    num_blocks: u64,
    pci_device: u8,
    pci_function: u8,
    usb_port: u8,
) -> Option<(u32, fs::gpt::Partition)> {
    use efi::boot_services;
    use efi::protocols::block_io::{self, BLOCK_IO_PROTOCOL_GUID};
    use efi::protocols::device_path::{self, DEVICE_PATH_PROTOCOL_GUID};
    use r_efi::efi::Status;

    // First, create BlockIO for the raw disk (whole device)
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

        // Install DevicePath protocol for the raw disk (USB device path)
        let disk_device_path =
            device_path::create_usb_device_path(pci_device, pci_function, usb_port);
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

            // Install DevicePath for partition (with full USB prefix for proper hierarchy)
            let device_path = device_path::create_usb_partition_device_path(
                pci_device,
                pci_function,
                usb_port,
                partition_num,
                partition.first_lba,
                partition_blocks,
                &partition.partition_guid,
            );

            if !device_path.is_null() {
                let status = boot_services::install_protocol(
                    part_handle,
                    &DEVICE_PATH_PROTOCOL_GUID,
                    device_path as *mut core::ffi::c_void,
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
            // Prioritize smaller partitions (< 512 MB) as they're more likely to be EFI boot partitions
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

    // No proper ESP found - try candidate partitions (smaller ones first, as they're more likely EFI)
    sort_partitions_by_size(&mut candidate_partitions);

    if let Some((partition_num, partition)) = candidate_partitions.first() {
        log::debug!(
            "Trying partition {} as potential ESP (no proper ESP found)",
            partition_num
        );
        return Some((*partition_num, partition.clone()));
    }

    None
}

/// Install BlockIO protocols for an NVMe disk and all its partitions
///
/// Returns the ESP partition and its partition number (1-based) if found.
///
/// # Arguments
/// * `disk` - Disk to read GPT from
/// * `storage_id` - Storage device ID for BlockIO
/// * `block_size` - Block size in bytes
/// * `num_blocks` - Total number of blocks
/// * `pci_device` - PCI device number of the NVMe controller
/// * `pci_function` - PCI function number
/// * `namespace_id` - NVMe namespace ID
fn install_block_io_for_nvme_disk<R: BlockDevice>(
    disk: &mut R,
    storage_id: u32,
    block_size: u32,
    num_blocks: u64,
    pci_device: u8,
    pci_function: u8,
    namespace_id: u32,
) -> Option<(u32, fs::gpt::Partition)> {
    use efi::boot_services;
    use efi::protocols::block_io::{self, BLOCK_IO_PROTOCOL_GUID};
    use efi::protocols::device_path::{self, DEVICE_PATH_PROTOCOL_GUID};
    use r_efi::efi::Status;

    // First, create BlockIO for the raw disk (whole device)
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
                "BlockIO protocol installed for raw NVMe disk on handle {:?}",
                disk_handle
            );
        }

        // Install DevicePath protocol for the raw disk (NVMe device path)
        let disk_device_path =
            device_path::create_nvme_device_path(pci_device, pci_function, namespace_id);
        if !disk_device_path.is_null() {
            let status = boot_services::install_protocol(
                disk_handle,
                &DEVICE_PATH_PROTOCOL_GUID,
                disk_device_path as *mut core::ffi::c_void,
            );
            if status == Status::SUCCESS {
                log::info!(
                    "DevicePath protocol installed for raw NVMe disk on handle {:?}",
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
                    "BlockIO protocol installed for NVMe partition {} on handle {:?}",
                    partition_num,
                    part_handle
                );
            }

            // Install DevicePath for partition (with full NVMe prefix for proper hierarchy)
            let device_path = device_path::create_nvme_partition_device_path(
                pci_device,
                pci_function,
                namespace_id,
                partition_num,
                partition.first_lba,
                partition_blocks,
                &partition.partition_guid,
            );

            if !device_path.is_null() {
                let status = boot_services::install_protocol(
                    part_handle,
                    &DEVICE_PATH_PROTOCOL_GUID,
                    device_path as *mut core::ffi::c_void,
                );
                if status == Status::SUCCESS {
                    log::info!(
                        "DevicePath protocol installed for NVMe partition {} on handle {:?}",
                        partition_num,
                        part_handle
                    );
                }
            }
        }

        // Remember ESP for later (with partition number)
        if partition.is_esp {
            log::info!(
                "Found ESP on NVMe: partition {}, LBA {}-{} ({} MB)",
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
    sort_partitions_by_size(&mut candidate_partitions);

    if let Some((partition_num, partition)) = candidate_partitions.first() {
        log::debug!(
            "Trying NVMe partition {} as potential ESP (no proper ESP found)",
            partition_num
        );
        return Some((*partition_num, partition.clone()));
    }

    None
}

/// Install BlockIO protocols for an AHCI disk and all its partitions
///
/// Returns the ESP partition and its partition number (1-based) if found.
///
/// # Arguments
/// * `disk` - Disk to read GPT from
/// * `storage_id` - Storage device ID for BlockIO
/// * `block_size` - Block size in bytes
/// * `num_blocks` - Total number of blocks
/// * `pci_device` - PCI device number of the AHCI controller
/// * `pci_function` - PCI function number
/// * `port` - AHCI port number
fn install_block_io_for_ahci_disk<R: BlockDevice>(
    disk: &mut R,
    storage_id: u32,
    block_size: u32,
    num_blocks: u64,
    pci_device: u8,
    pci_function: u8,
    port: u16,
) -> Option<(u32, fs::gpt::Partition)> {
    use efi::boot_services;
    use efi::protocols::block_io::{self, BLOCK_IO_PROTOCOL_GUID};
    use efi::protocols::device_path::{self, DEVICE_PATH_PROTOCOL_GUID};
    use r_efi::efi::Status;

    // First, create BlockIO for the raw disk (whole device)
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
                "BlockIO protocol installed for raw AHCI disk on handle {:?}",
                disk_handle
            );
        }

        // Install DevicePath protocol for the raw disk (SATA device path)
        let disk_device_path = device_path::create_sata_device_path(pci_device, pci_function, port);
        if !disk_device_path.is_null() {
            let status = boot_services::install_protocol(
                disk_handle,
                &DEVICE_PATH_PROTOCOL_GUID,
                disk_device_path as *mut core::ffi::c_void,
            );
            if status == Status::SUCCESS {
                log::info!(
                    "DevicePath protocol installed for raw AHCI disk on handle {:?}",
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
                    "BlockIO protocol installed for AHCI partition {} on handle {:?}",
                    partition_num,
                    part_handle
                );
            }

            // Install DevicePath for partition (with full SATA prefix for proper hierarchy)
            let device_path = device_path::create_sata_partition_device_path(
                pci_device,
                pci_function,
                port,
                partition_num,
                partition.first_lba,
                partition_blocks,
                &partition.partition_guid,
            );

            if !device_path.is_null() {
                let status = boot_services::install_protocol(
                    part_handle,
                    &DEVICE_PATH_PROTOCOL_GUID,
                    device_path as *mut core::ffi::c_void,
                );
                if status == Status::SUCCESS {
                    log::info!(
                        "DevicePath protocol installed for AHCI partition {} on handle {:?}",
                        partition_num,
                        part_handle
                    );
                }
            }
        }

        // Remember ESP for later (with partition number)
        if partition.is_esp {
            log::info!(
                "Found ESP on AHCI: partition {}, LBA {}-{} ({} MB)",
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
    sort_partitions_by_size(&mut candidate_partitions);

    if let Some((partition_num, partition)) = candidate_partitions.first() {
        log::debug!(
            "Trying AHCI partition {} as potential ESP (no proper ESP found)",
            partition_num
        );
        return Some((*partition_num, partition.clone()));
    }

    None
}

/// Try to boot from an ESP on USB (with SimpleFileSystem support)
///
/// # Arguments
/// * `disk` - USB disk to read from (any SectorRead implementer)
/// * `esp` - ESP partition info
/// * `partition_num` - 1-based partition number of the ESP
/// * `pci_device` - PCI device number of USB controller
/// * `pci_function` - PCI function number
/// * `usb_port` - USB port number
fn try_boot_from_esp_usb<D: BlockDevice>(
    disk: &mut D,
    esp: &fs::gpt::Partition,
    partition_num: u32,
    pci_device: u8,
    pci_function: u8,
    usb_port: u8,
) -> bool {
    use drivers::storage::{self, StorageType};
    use efi::boot_services;
    use efi::protocols::block_io::{self, BLOCK_IO_PROTOCOL_GUID};
    use efi::protocols::device_path::{self, DEVICE_PATH_PROTOCOL_GUID};
    use efi::protocols::simple_file_system::{self, SIMPLE_FILE_SYSTEM_GUID};
    use r_efi::efi::Status;

    // Extract filesystem state BEFORE creating FatFilesystem to avoid borrow conflict
    // This reads the boot sector directly from disk
    let fs_state = extract_fat_state(disk, esp.first_lba);

    match fs::fat::FatFilesystem::new(disk, esp.first_lba) {
        Ok(mut fat) => {
            log::info!("FAT filesystem mounted on ESP");

            // Initialize SimpleFileSystem protocol
            let sfs_protocol =
                simple_file_system::init(fs_state, drivers::usb::mass_storage::global_read_sector);

            // Create a device handle with SimpleFileSystem and DevicePath protocols
            let device_handle = match boot_services::create_handle() {
                Some(h) => h,
                None => {
                    log::error!("Failed to create device handle");
                    return false;
                }
            };

            // Install DevicePath protocol on the device handle
            // Use full USB partition path for proper hierarchy matching
            let partition_size = esp.size_sectors();
            let device_path = device_path::create_usb_partition_device_path(
                pci_device,
                pci_function,
                usb_port,
                partition_num,
                esp.first_lba,
                partition_size,
                &esp.partition_guid,
            );

            if !device_path.is_null() {
                let status = boot_services::install_protocol(
                    device_handle,
                    &DEVICE_PATH_PROTOCOL_GUID,
                    device_path as *mut core::ffi::c_void,
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
            // The bootloader needs this to access the disk
            if let Some(usb_device) = drivers::usb::mass_storage::get_global_device() {
                let block_size = usb_device.block_size;
                let num_blocks = usb_device.num_blocks;
                // Get slot_id from the device
                let slot_id = usb_device.slot_id();

                let storage_id =
                    storage::register_device(StorageType::Usb { slot_id }, num_blocks, block_size);

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
            }

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

/// Debug helper: check if system table is intact
fn check_system_table_integrity(label: &str) {
    let st = efi::get_system_table();
    unsafe {
        let bs = (*st).boot_services;
        if bs.is_null() {
            log::error!("[{}] CORRUPTION: boot_services is NULL!", label);
        } else {
            let sig = (*bs).hdr.signature;
            if sig != 0x56524553544f4f42 {
                // "BOOTSERV"
                log::error!(
                    "[{}] CORRUPTION: boot_services signature wrong: {:#x}",
                    label,
                    sig
                );
            } else {
                log::debug!("[{}] SystemTable OK, BS={:?}", label, bs);
            }
        }
    }
}

/// Try to boot from an ESP on NVMe (with SimpleFileSystem support)
///
/// # Arguments
/// * `disk` - NVMe disk to read from
/// * `esp` - ESP partition info
/// * `partition_num` - 1-based partition number of the ESP
/// * `pci_device` - PCI device number of NVMe controller
/// * `pci_function` - PCI function number
/// * `namespace_id` - NVMe namespace ID
fn try_boot_from_esp_nvme(
    disk: &mut NvmeDisk,
    esp: &fs::gpt::Partition,
    partition_num: u32,
    pci_device: u8,
    pci_function: u8,
    namespace_id: u32,
) -> bool {
    use drivers::storage::{self, StorageType};
    use efi::boot_services;
    use efi::protocols::block_io::{self, BLOCK_IO_PROTOCOL_GUID};
    use efi::protocols::device_path::{self, DEVICE_PATH_PROTOCOL_GUID};
    use efi::protocols::simple_file_system::{self, SIMPLE_FILE_SYSTEM_GUID};
    use r_efi::efi::Status;

    check_system_table_integrity("NVMe: start");

    match fs::fat::FatFilesystem::new(disk, esp.first_lba) {
        Ok(mut fat) => {
            log::info!("FAT filesystem mounted on ESP");
            check_system_table_integrity("NVMe: after FAT mount");

            // Extract filesystem state for the SimpleFileSystem protocol
            let fs_state = extract_fat_state_nvme(esp.first_lba);
            check_system_table_integrity("NVMe: after extract_fat_state");

            // Initialize SimpleFileSystem protocol with NVMe read function
            let sfs_protocol =
                simple_file_system::init(fs_state, drivers::nvme::global_read_sector);
            check_system_table_integrity("NVMe: after SFS init");

            // Create a device handle with SimpleFileSystem and DevicePath protocols
            let device_handle = match boot_services::create_handle() {
                Some(h) => h,
                None => {
                    log::error!("Failed to create device handle");
                    return false;
                }
            };

            // Install DevicePath protocol on the device handle
            // Use full NVMe partition path for proper hierarchy matching
            let partition_size = esp.size_sectors();
            let device_path = device_path::create_nvme_partition_device_path(
                pci_device,
                pci_function,
                namespace_id,
                partition_num,
                esp.first_lba,
                partition_size,
                &esp.partition_guid,
            );

            if !device_path.is_null() {
                let status = boot_services::install_protocol(
                    device_handle,
                    &DEVICE_PATH_PROTOCOL_GUID,
                    device_path as *mut core::ffi::c_void,
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
            // The bootloader needs this to access the disk
            if let Some(controller) = drivers::nvme::get_controller(0)
                && let Some(ns) = controller.default_namespace()
            {
                let block_size = ns.block_size;
                let storage_id = storage::register_device(
                    StorageType::Nvme {
                        controller_id: 0,
                        nsid: namespace_id,
                    },
                    ns.num_blocks,
                    block_size,
                );

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
            }

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

/// Try to boot from an ESP on AHCI (with SimpleFileSystem support)
///
/// # Arguments
/// * `disk` - AHCI disk to read from
/// * `esp` - ESP partition info
/// * `partition_num` - 1-based partition number of the ESP
/// * `pci_device` - PCI device number of AHCI controller
/// * `pci_function` - PCI function number
/// * `port` - AHCI port number
fn try_boot_from_esp_ahci(
    disk: &mut AhciDisk,
    esp: &fs::gpt::Partition,
    partition_num: u32,
    pci_device: u8,
    pci_function: u8,
    port: u16,
) -> bool {
    use drivers::storage::{self, StorageType};
    use efi::boot_services;
    use efi::protocols::block_io::{self, BLOCK_IO_PROTOCOL_GUID};
    use efi::protocols::device_path::{self, DEVICE_PATH_PROTOCOL_GUID};
    use efi::protocols::simple_file_system::{self, SIMPLE_FILE_SYSTEM_GUID};
    use r_efi::efi::Status;

    match fs::fat::FatFilesystem::new(disk, esp.first_lba) {
        Ok(mut fat) => {
            log::info!("FAT filesystem mounted on ESP");

            // Extract filesystem state for the SimpleFileSystem protocol
            let fs_state = extract_fat_state_ahci(esp.first_lba);

            // Initialize SimpleFileSystem protocol with AHCI read function
            let sfs_protocol =
                simple_file_system::init(fs_state, drivers::ahci::global_read_sector);

            // Create a device handle with SimpleFileSystem and DevicePath protocols
            let device_handle = match boot_services::create_handle() {
                Some(h) => h,
                None => {
                    log::error!("Failed to create device handle");
                    return false;
                }
            };

            // Install DevicePath protocol on the device handle
            // Use full SATA partition path for proper hierarchy matching
            let partition_size = esp.size_sectors();
            let device_path = device_path::create_sata_partition_device_path(
                pci_device,
                pci_function,
                port,
                partition_num,
                esp.first_lba,
                partition_size,
                &esp.partition_guid,
            );

            if !device_path.is_null() {
                let status = boot_services::install_protocol(
                    device_handle,
                    &DEVICE_PATH_PROTOCOL_GUID,
                    device_path as *mut core::ffi::c_void,
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
            // The bootloader needs this to access the disk
            // First register the storage device
            if let Some(controller) = drivers::ahci::get_controller(0)
                && let Some(port_info) = controller.get_port(port as usize)
            {
                let block_size = port_info.sector_size;
                let storage_id = storage::register_device(
                    StorageType::Ahci {
                        controller_id: 0,
                        port: port as usize,
                    },
                    port_info.sector_count,
                    block_size,
                );

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
            }

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

/// Extract FAT filesystem state for the SimpleFileSystem protocol (generic version)
///
/// This version uses the provided disk directly instead of global_read_sector,
/// which avoids deadlocks when called from within a with_controller closure.
fn extract_fat_state<R: BlockDevice>(
    disk: &mut R,
    partition_start: u64,
) -> efi::protocols::simple_file_system::FilesystemState {
    use efi::protocols::simple_file_system::FilesystemState;
    use fs::fat::SECTOR_SIZE;

    // Read boot sector directly from the disk
    let mut buffer = [0u8; SECTOR_SIZE];
    if disk.read_block(partition_start, &mut buffer).is_err() {
        log::error!("Failed to read boot sector for filesystem state");
        return FilesystemState::empty();
    }

    parse_fat_bpb(&buffer, partition_start)
}

/// Extract FAT filesystem state for AHCI devices
fn extract_fat_state_ahci(
    partition_start: u64,
) -> efi::protocols::simple_file_system::FilesystemState {
    use efi::protocols::simple_file_system::FilesystemState;
    use fs::fat::SECTOR_SIZE;

    // Read boot sector directly using AHCI global read
    let mut buffer = [0u8; SECTOR_SIZE];
    if drivers::ahci::global_read_sector(partition_start, &mut buffer).is_err() {
        log::error!("Failed to read boot sector for AHCI filesystem state");
        return FilesystemState::empty();
    }

    parse_fat_bpb(&buffer, partition_start)
}

/// Extract FAT filesystem state for NVMe devices
fn extract_fat_state_nvme(
    partition_start: u64,
) -> efi::protocols::simple_file_system::FilesystemState {
    use efi::protocols::simple_file_system::FilesystemState;
    use fs::fat::SECTOR_SIZE;

    // Read boot sector directly using NVMe global read
    let mut buffer = [0u8; SECTOR_SIZE];
    if drivers::nvme::global_read_sector(partition_start, &mut buffer).is_err() {
        log::error!("Failed to read boot sector for NVMe filesystem state");
        return FilesystemState::empty();
    }

    parse_fat_bpb(&buffer, partition_start)
}

/// Parse FAT BPB from boot sector buffer
fn parse_fat_bpb(
    buffer: &[u8],
    partition_start: u64,
) -> efi::protocols::simple_file_system::FilesystemState {
    use efi::protocols::simple_file_system::FilesystemState;

    // Parse BPB
    let bytes_per_sector = u16::from_le_bytes([buffer[11], buffer[12]]);
    let sectors_per_cluster = buffer[13];
    let reserved_sectors = u16::from_le_bytes([buffer[14], buffer[15]]);
    let num_fats = buffer[16];
    let root_entry_count = u16::from_le_bytes([buffer[17], buffer[18]]);
    let total_sectors_16 = u16::from_le_bytes([buffer[19], buffer[20]]);
    let sectors_per_fat_16 = u16::from_le_bytes([buffer[22], buffer[23]]);
    let total_sectors_32 = u32::from_le_bytes([buffer[32], buffer[33], buffer[34], buffer[35]]);

    // FAT32 extended BPB
    let sectors_per_fat_32 = u32::from_le_bytes([buffer[36], buffer[37], buffer[38], buffer[39]]);
    let root_cluster = u32::from_le_bytes([buffer[44], buffer[45], buffer[46], buffer[47]]);

    let sectors_per_fat = if sectors_per_fat_16 != 0 {
        sectors_per_fat_16 as u32
    } else {
        sectors_per_fat_32
    };

    let total_sectors = if total_sectors_16 != 0 {
        total_sectors_16 as u32
    } else {
        total_sectors_32
    };

    let root_dir_sectors = (root_entry_count as u32 * 32).div_ceil(bytes_per_sector as u32);
    let fat_start = reserved_sectors as u32;
    let root_dir_start = fat_start + (num_fats as u32 * sectors_per_fat);
    let data_start = root_dir_start + root_dir_sectors;

    let data_sectors = total_sectors - data_start;
    let data_clusters = data_sectors / sectors_per_cluster as u32;

    // Determine FAT type
    let fat_type = if data_clusters < 4085 {
        12
    } else if data_clusters < 65525 {
        16
    } else {
        32
    };

    let root_cluster_val = if fat_type == 32 { root_cluster } else { 0 };

    log::debug!(
        "FAT state: type={}, start={}, bps={}, spc={}",
        fat_type,
        partition_start,
        bytes_per_sector,
        sectors_per_cluster
    );

    FilesystemState {
        partition_start,
        fat_type,
        bytes_per_sector,
        sectors_per_cluster,
        fat_start,
        sectors_per_fat,
        data_start,
        root_cluster: root_cluster_val,
        root_dir_start,
        root_dir_sectors,
    }
}

/// Load and execute an EFI bootloader from the filesystem
fn load_and_execute_bootloader<R: BlockDevice>(
    fat: &mut fs::fat::FatFilesystem<R>,
    path: &str,
    file_size: u32,
    device_handle: r_efi::efi::Handle,
) -> Result<(), r_efi::efi::Status> {
    use efi::allocator::{MemoryType, allocate_pool, free_pool};
    use efi::boot_services;
    use efi::protocols::loaded_image::{LOADED_IMAGE_PROTOCOL_GUID, create_loaded_image_protocol};
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
    let loaded_image = pe::load_image(&buffer[..bytes_read]).inspect_err(|&status| {
        log::error!("Failed to load PE image: {:?}", status);
        let _ = free_pool(buffer_ptr);
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
        firmware_handle, // parent_handle
        system_table,    // system_table
        device_handle,   // device_handle - now with SimpleFileSystem!
        loaded_image.image_base,
        loaded_image.image_size,
    );

    if loaded_image_protocol.is_null() {
        log::error!("Failed to create LoadedImageProtocol");
        pe::unload_image(&loaded_image);
        return Err(Status::OUT_OF_RESOURCES);
    }

    // Set the file path in LoadedImageProtocol (tells bootloader what file was loaded)
    let file_path = efi::protocols::device_path::create_file_path_device_path(path);
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
    if !device_handle.is_null() {
        log::info!(
            "DeviceHandle set to {:?} (with SimpleFileSystem)",
            device_handle
        );
    }
    log::info!("Executing bootloader...");

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

    // Clean up (normally the bootloader would call ExitBootServices and never return)
    pe::unload_image(&loaded_image);

    if exec_status == Status::SUCCESS {
        Ok(())
    } else {
        Err(exec_status)
    }
}

/// Install BlockIO protocols for an SDHCI disk and all its partitions
///
/// Returns the ESP partition and its partition number (1-based) if found.
///
/// # Arguments
/// * `disk` - Disk to read GPT from
/// * `storage_id` - Storage device ID for BlockIO
/// * `block_size` - Block size in bytes
/// * `num_blocks` - Total number of blocks
/// * `pci_device` - PCI device number of the SDHCI controller
/// * `pci_function` - PCI function number
fn install_block_io_for_sdhci_disk<R: BlockDevice>(
    disk: &mut R,
    storage_id: u32,
    block_size: u32,
    num_blocks: u64,
    pci_device: u8,
    pci_function: u8,
) -> Option<(u32, fs::gpt::Partition)> {
    use efi::boot_services;
    use efi::protocols::block_io::{self, BLOCK_IO_PROTOCOL_GUID};
    use efi::protocols::device_path::{self, DEVICE_PATH_PROTOCOL_GUID};
    use r_efi::efi::Status;

    // First, create BlockIO for the raw disk (whole device)
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
                "BlockIO protocol installed for raw SDHCI disk on handle {:?}",
                disk_handle
            );
        }

        // Install DevicePath protocol for the raw disk (SD device path)
        // Use USB device path format for now (SD cards are often USB-connected logically)
        let disk_device_path = device_path::create_usb_device_path(pci_device, pci_function, 0);
        if !disk_device_path.is_null() {
            let status = boot_services::install_protocol(
                disk_handle,
                &DEVICE_PATH_PROTOCOL_GUID,
                disk_device_path as *mut core::ffi::c_void,
            );
            if status == Status::SUCCESS {
                log::info!(
                    "DevicePath protocol installed for raw SDHCI disk on handle {:?}",
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
                    "BlockIO protocol installed for SDHCI partition {} on handle {:?}",
                    partition_num,
                    part_handle
                );
            }

            // Install DevicePath for partition
            let device_path = device_path::create_usb_partition_device_path(
                pci_device,
                pci_function,
                0,
                partition_num,
                partition.first_lba,
                partition_blocks,
                &partition.partition_guid,
            );

            if !device_path.is_null() {
                let status = boot_services::install_protocol(
                    part_handle,
                    &DEVICE_PATH_PROTOCOL_GUID,
                    device_path as *mut core::ffi::c_void,
                );
                if status == Status::SUCCESS {
                    log::info!(
                        "DevicePath protocol installed for SDHCI partition {} on handle {:?}",
                        partition_num,
                        part_handle
                    );
                }
            }
        }

        // Remember ESP for later (with partition number)
        if partition.is_esp {
            log::info!(
                "Found ESP on SDHCI: partition {}, LBA {}-{} ({} MB)",
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
    for i in 0..candidate_partitions.len() {
        for j in (i + 1)..candidate_partitions.len() {
            if candidate_partitions[j].1.size_bytes() < candidate_partitions[i].1.size_bytes() {
                let tmp = candidate_partitions[i].clone();
                candidate_partitions[i] = candidate_partitions[j].clone();
                candidate_partitions[j] = tmp;
            }
        }
    }

    if let Some((partition_num, partition)) = candidate_partitions.first() {
        log::debug!(
            "Trying SDHCI partition {} as potential ESP (no proper ESP found)",
            partition_num
        );
        return Some((*partition_num, partition.clone()));
    }

    None
}

/// Try to boot from an ESP on SDHCI (with SimpleFileSystem support)
///
/// # Arguments
/// * `disk` - SDHCI disk to read from
/// * `esp` - ESP partition info
/// * `partition_num` - 1-based partition number of the ESP
/// * `pci_device` - PCI device number of SDHCI controller
/// * `pci_function` - PCI function number
fn try_boot_from_esp_sdhci(
    disk: &mut SdhciDisk,
    esp: &fs::gpt::Partition,
    partition_num: u32,
    pci_device: u8,
    pci_function: u8,
) -> bool {
    use drivers::storage::{self, StorageType};
    use efi::boot_services;
    use efi::protocols::block_io::{self, BLOCK_IO_PROTOCOL_GUID};
    use efi::protocols::device_path::{self, DEVICE_PATH_PROTOCOL_GUID};
    use efi::protocols::simple_file_system::{self, SIMPLE_FILE_SYSTEM_GUID};
    use r_efi::efi::Status;

    // Extract filesystem state BEFORE creating FatFilesystem to avoid borrow conflict
    // This reads the boot sector directly from disk
    let fs_state = extract_fat_state(disk, esp.first_lba);

    log::debug!(
        "SDHCI FAT state: type={}, partition_start={}, data_start={}",
        fs_state.fat_type,
        fs_state.partition_start,
        fs_state.data_start
    );

    match fs::fat::FatFilesystem::new(disk, esp.first_lba) {
        Ok(mut fat) => {
            log::info!("FAT filesystem mounted on ESP");

            // Initialize SimpleFileSystem protocol with SDHCI read function
            let sfs_protocol =
                simple_file_system::init(fs_state, drivers::sdhci::global_read_sector);

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
            let device_path = device_path::create_usb_partition_device_path(
                pci_device,
                pci_function,
                0,
                partition_num,
                esp.first_lba,
                partition_size,
                &esp.partition_guid,
            );

            if !device_path.is_null() {
                let status = boot_services::install_protocol(
                    device_handle,
                    &DEVICE_PATH_PROTOCOL_GUID,
                    device_path as *mut core::ffi::c_void,
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
            if let Some(controller) = drivers::sdhci::get_controller(0) {
                let block_size = controller.block_size();
                let storage_id = storage::register_device(
                    StorageType::Sdhci { controller_id: 0 },
                    controller.num_blocks(),
                    block_size,
                );

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
            }

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
