//! CrabEFI - A minimal UEFI implementation as a coreboot payload
//!
//! This library provides the core functionality for a minimal UEFI environment
//! that can boot Linux via shim+GRUB2 or systemd-boot on real laptop hardware.

#![no_std]
#![feature(abi_x86_interrupt)]
#![feature(never_type)] // Used for -> ! return type in payload chainloading
#![allow(unsafe_op_in_unsafe_fn)]
// Allow common firmware code patterns
#![allow(clippy::result_unit_err)] // Result<(), ()> is common in embedded code
#![allow(clippy::too_many_arguments)] // USB/hardware APIs often require many parameters
#![allow(clippy::field_reassign_with_default)] // Clearer than complex struct initializers

// Enable alloc crate for heap allocations (needed for RustCrypto)
extern crate alloc;

pub mod arch;
pub mod bls;
pub mod boot;
pub mod coreboot;
pub mod drivers;
pub mod efi;
#[cfg(feature = "fb-log")]
pub mod fb_log;
pub mod framebuffer_console;
pub mod fs;
pub mod grub;
pub mod heap;
pub mod linux_boot;
pub mod logger;
pub mod menu;
pub mod payload;
pub mod pe;
pub mod secure_boot_menu;
pub mod state;
pub mod time;

use crate::drivers::block::{AhciDisk, NvmeDisk, SdhciDisk, UsbDisk};
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

/// Display a Secure Boot violation error on screen
///
/// This function displays a prominent red error message in the center of the screen
/// when Secure Boot verification fails. It also outputs to the serial console.
/// The display persists for a few seconds so the user can see it.
pub fn display_secure_boot_error() {
    use framebuffer_console::{Color, DEFAULT_BG, FramebufferConsole};

    const ERROR_MESSAGE: &str = "SECURE BOOT VIOLATION: Image not authorized";

    // Output to serial console with red color (ANSI escape codes)
    drivers::serial::write_str("\r\n\x1b[1;31m"); // Bold red
    drivers::serial::write_str(
        "================================================================================\r\n",
    );
    drivers::serial::write_str(
        "                    SECURE BOOT VIOLATION: Image not authorized                 \r\n",
    );
    drivers::serial::write_str(
        "================================================================================\r\n",
    );
    drivers::serial::write_str("\x1b[0m\r\n"); // Reset color

    // Output to framebuffer if available
    if let Some(fb_info) = coreboot::get_framebuffer() {
        let mut console = FramebufferConsole::new(&fb_info);

        // Calculate center position
        let rows = console.rows();
        let center_row = rows / 2;

        // Set red foreground color
        let error_color = Color::new(255, 0, 0); // Bright red

        // Draw a border above the message
        console.set_colors(error_color, DEFAULT_BG);
        console.write_centered(center_row - 2, "========================================");

        // Draw the error message
        console.write_centered(center_row, ERROR_MESSAGE);

        // Draw a border below the message
        console.write_centered(center_row + 2, "========================================");

        console.reset_colors();
    }

    // Wait 3 seconds so the user can see the message
    time::delay_ms(3000);
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

    // Store framebuffer in global state for menu rendering
    if let Some(ref fb) = cb_info.framebuffer {
        coreboot::store_framebuffer(fb.clone());
    }

    // Store the coreboot framebuffer record address so we can invalidate it
    // at ExitBootServices to prevent a race between Linux's simplefb and efifb
    if let Some(addr) = cb_info.framebuffer_record_addr {
        coreboot::store_framebuffer_record_addr(addr);
    }

    // Store SMMSTORE v2 info globally for variable persistence
    if let Some(ref smmstore) = cb_info.smmstorev2 {
        coreboot::store_smmstorev2(smmstore.clone());
    }

    // Store SPI flash info globally (used for FMAP parsing)
    if let Some(ref spi_flash) = cb_info.spi_flash {
        coreboot::store_spi_flash(spi_flash.clone());
    }

    // Store boot media info globally (contains FMAP offset)
    if let Some(ref boot_media) = cb_info.boot_media {
        coreboot::store_boot_media(boot_media.clone());
    }

    // Store memory regions and ACPI RSDP for direct Linux boot
    state::with_drivers_mut(|drivers| {
        // Copy memory regions
        for region in cb_info.memory_map.iter() {
            let _ = drivers.memory_regions.push(*region);
        }
        // Store ACPI RSDP
        drivers.acpi_rsdp = cb_info.acpi_rsdp;
    });

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
    if let Some(ref smmstore) = cb_info.smmstorev2 {
        log::info!(
            "  SMMSTORE v2: {} blocks x {} KB at {:#x}",
            smmstore.num_blocks,
            smmstore.block_size / 1024,
            smmstore.mmap_addr
        );
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

    // Initialize IDT for exception handling
    #[cfg(target_arch = "x86_64")]
    arch::x86_64::idt::init();

    // Initialize EFI environment
    efi::init(&cb_info);

    // FirmwareState lives on the stack, which is inside the .stack section.
    // The .stack section is between __runtime_data_start and __runtime_data_end,
    // so reserve_runtime_region() (called by efi::init) already marks the entire
    // region — including FirmwareState — as RuntimeServicesData.
    //
    // DO NOT add a separate entry here; that would create overlapping memory map
    // entries which violates the UEFI spec and causes Windows to BSOD during
    // SetVirtualAddressMap processing.
    {
        let state_addr = &firmware_state as *const _ as u64;
        let state_size = core::mem::size_of::<state::FirmwareState>() as u64;
        log::info!(
            "FirmwareState at {:#x}-{:#x} ({} bytes) — covered by runtime data region",
            state_addr,
            state_addr + state_size,
            state_size
        );
    }

    // Initialize heap allocator (needed for crypto operations and alloc-dependent features)
    if !heap::init() {
        log::error!("Failed to initialize heap allocator! Secure Boot and other alloc-dependent features will be unavailable.");
        // Continue boot -- features requiring alloc will fail gracefully
    }

    log::info!("CrabEFI initialized successfully!");
    log::info!("EFI System Table at: {:p}", efi::get_system_table());

    // Initialize PCI early so we can detect SPI controller
    drivers::pci::init();

    // Reserve and initialize the deferred variable buffer (for runtime variable persistence)
    // This buffer survives warm reboot and allows variable changes after ExitBootServices
    // to be applied on the next boot.
    {
        use efi::allocator::{MemoryType, PAGE_SIZE};
        use efi::varstore::{deferred_buffer_base, deferred_buffer_size};

        let buffer_base = deferred_buffer_base();
        let buffer_pages = (deferred_buffer_size() as u64).div_ceil(PAGE_SIZE);

        // Reserve the memory region as ReservedMemoryType so the OS won't overwrite it
        state::with_allocator_mut(|alloc| {
            if let Err(e) =
                alloc.reserve_region(buffer_base, buffer_pages, MemoryType::ReservedMemoryType)
            {
                log::warn!(
                    "Could not reserve deferred buffer region at {:#x}: {:?}",
                    buffer_base,
                    e
                );
            } else {
                log::debug!(
                    "Reserved {} pages for deferred buffer at {:#x}",
                    buffer_pages,
                    buffer_base
                );
            }
        });
    }

    // Initialize variable store persistence (loads variables from SPI flash)
    match efi::varstore::init_persistence() {
        Ok(()) => {
            log::info!("Variable store persistence initialized");

            // Check for pending deferred writes from previous boot BEFORE clearing the buffer
            // This must be done after SPI init so we can write to SMMSTORE
            let pending_count = efi::varstore::check_deferred_pending();
            if pending_count > 0 {
                log::info!(
                    "Found {} pending deferred writes from previous boot",
                    pending_count
                );

                // Apply the deferred writes to SPI
                match efi::varstore::process_deferred_pending() {
                    Ok(n) => log::info!("Applied {} deferred variable writes", n),
                    Err(e) => log::warn!("Failed to process deferred writes: {:?}", e),
                }
            }

            // Initialize Secure Boot state (load keys from variables, create status vars)
            // This must be called after variables are loaded from SMMSTORE
            match efi::auth::boot::init_secure_boot_default() {
                Ok(status) => {
                    log::info!("Secure Boot initialized:");
                    log::info!(
                        "  Mode: {}",
                        if status.setup_mode { "Setup" } else { "User" }
                    );
                    log::info!(
                        "  Keys: PK={}, KEK={}, db={}, dbx={}",
                        status.pk_count,
                        status.kek_count,
                        status.db_count,
                        status.dbx_count
                    );
                    if status.secure_boot_enabled {
                        log::info!("  Secure Boot: ENABLED");
                    }
                }
                Err(e) => log::warn!("Secure Boot initialization failed: {:?}", e),
            }
        }
        Err(e) => log::warn!("Variable store persistence not available: {:?}", e),
    }

    // Now initialize the deferred buffer for this boot session
    // This clears the buffer so new runtime writes can be accumulated
    efi::varstore::init_deferred_buffer();

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

    // Print PCI devices (already initialized earlier for SPI detection)
    drivers::pci::print_devices();

    // Bind PCI drivers to discovered devices (NVMe, AHCI, USB, SDHCI)
    // This uses the table-driven driver model instead of hardcoded init calls
    drivers::pci::bind_drivers();

    // Initialize USB keyboards (needs to happen after USB controllers are bound)
    drivers::usb::init_keyboards_public();

    // Initialize pass-through protocols for TCG Opal support
    efi::protocols::pass_thru_init::init();

    // Discover boot entries and show menu
    let mut boot_menu = menu::discover_boot_entries();

    if boot_menu.entry_count() == 0 {
        log::warn!("No bootable media found!");
        log::info!("Storage initialization complete");
        return;
    }

    // If only one entry and no interactive mode requested, boot directly
    // For now, always show the menu for testing
    log::debug!("Showing boot menu...");
    let selected = menu::show_menu(&mut boot_menu);
    log::info!("Menu returned: {:?}", selected);

    if let Some(selected_index) = selected {
        log::info!("Selected index: {}", selected_index);
        if let Some(entry) = boot_menu.get_entry(selected_index) {
            log::info!("Booting: {} from {}", entry.name, entry.path);
            log::info!("Entry kind: {:?}", entry.kind);
            log::info!("Device type: {:?}", entry.device_type);
            boot_selected_entry(entry);
            log::warn!("boot_selected_entry returned - boot failed!");
        } else {
            log::error!("Failed to get entry at index {}", selected_index);
        }
    } else {
        log::warn!("No entry selected from menu");
    }

    log::info!("Boot menu returned, storage initialization complete");
}

/// Boot a selected menu entry
///
/// Dispatches to the appropriate boot method based on the entry kind:
/// - UEFI/UKI entries: Load and execute EFI application
/// - BLS/GRUB Linux entries: Direct Linux boot via linux_boot module
/// - Payload entries: Chainload coreboot payload
fn boot_selected_entry(entry: &menu::BootEntry) {
    log::info!("boot_selected_entry called");

    // First, dispatch based on entry kind
    match &entry.kind {
        // UEFI entries use the existing EFI boot path
        menu::BootEntryKind::Uefi | menu::BootEntryKind::BlsUki => {
            log::info!("Dispatching to UEFI boot path");
            boot_uefi_entry(entry);
        }

        // Direct Linux boot entries (BLS Type #1 or GRUB)
        menu::BootEntryKind::BlsLinux {
            linux_path,
            initrd_path,
            cmdline,
        }
        | menu::BootEntryKind::GrubLinux {
            linux_path,
            initrd_path,
            cmdline,
        } => {
            log::info!("Dispatching to direct Linux boot");
            boot_linux_entry(entry, linux_path, initrd_path, cmdline);
        }

        // Coreboot payload chainloading
        menu::BootEntryKind::Payload { path, format } => {
            log::info!("Dispatching to payload chainload");
            boot_payload_entry(entry, path, *format);
        }
    }
}

/// Boot a UEFI entry (EFI application or UKI)
///
/// Uses the unified boot module to handle all storage types generically.
/// The per-device-type code is limited to:
/// 1. Storing the device globally (for SimpleFileSystem reads)
/// 2. Getting disk info (num_blocks, block_size)
/// 3. Creating a disk to pass to the generic functions
fn boot_uefi_entry(entry: &menu::BootEntry) {
    use drivers::storage::{self, StorageType};

    let path_info = boot::device_path_info_from_entry(entry);

    // Per-device-type: store globally, get info, register, install BlockIO, then boot
    match entry.device_type {
        menu::DeviceType::Nvme {
            controller_id,
            nsid,
        } => {
            if !drivers::nvme::store_global_device(controller_id, nsid) {
                log::error!("Failed to store NVMe device globally");
                return;
            }

            if let Some(controller_ptr) = drivers::nvme::get_controller(controller_id) {
                // Safety: pointer valid for firmware lifetime; no overlapping &mut created
                let controller = unsafe { &mut *controller_ptr };
                let (num_blocks, block_size) = match controller.default_namespace() {
                    Some(ns) => (ns.num_blocks, ns.block_size),
                    None => {
                        log::error!("Failed to get NVMe namespace info");
                        return;
                    }
                };

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
                        log::error!("Failed to register device");
                        return;
                    }
                };

                let mut disk = NvmeDisk::new(controller, nsid);
                let _ = boot::install_block_io_protocols(
                    &mut disk, storage_id, block_size, num_blocks, &path_info,
                );
            }

            // Re-create disk for ESP boot (previous borrows ended)
            if let Some(controller_ptr) = drivers::nvme::get_controller(controller_id) {
                // Safety: pointer valid for firmware lifetime; no overlapping &mut created
                let controller = unsafe { &mut *controller_ptr };
                let info = match controller.default_namespace() {
                    Some(ns) => (ns.num_blocks, ns.block_size),
                    None => {
                        log::error!("Failed to get NVMe namespace for ESP boot");
                        return;
                    }
                };
                let mut disk = NvmeDisk::new(controller, nsid);
                if boot::try_boot_from_esp(
                    &mut disk,
                    &entry.partition,
                    entry.partition_num,
                    &path_info,
                    &entry.device_type,
                    info.0,
                    info.1,
                ) {
                    return;
                }
            }
            log::error!("Failed to boot NVMe entry");
        }
        menu::DeviceType::Ahci {
            controller_id,
            port,
        } => {
            if !drivers::ahci::store_global_device(controller_id, port) {
                log::error!("Failed to store AHCI device globally");
                return;
            }

            if let Some(controller_ptr) = drivers::ahci::get_controller(controller_id) {
                // Safety: pointer valid for firmware lifetime; no overlapping &mut created
                let controller = unsafe { &mut *controller_ptr };
                let (num_blocks, block_size) = match controller.get_port(port) {
                    Some(port_info) => (port_info.sector_count, port_info.sector_size),
                    None => {
                        log::error!("Failed to get AHCI port info");
                        return;
                    }
                };

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
                        log::error!("Failed to register device");
                        return;
                    }
                };

                let mut disk = AhciDisk::new(controller, port);
                let _ = boot::install_block_io_protocols(
                    &mut disk, storage_id, block_size, num_blocks, &path_info,
                );
            }

            if let Some(controller_ptr) = drivers::ahci::get_controller(controller_id) {
                // Safety: pointer valid for firmware lifetime; no overlapping &mut created
                let controller = unsafe { &mut *controller_ptr };
                let info = match controller.get_port(port) {
                    Some(p) => (p.sector_count, p.sector_size),
                    None => return,
                };
                let mut disk = AhciDisk::new(controller, port);
                if boot::try_boot_from_esp(
                    &mut disk,
                    &entry.partition,
                    entry.partition_num,
                    &path_info,
                    &entry.device_type,
                    info.0,
                    info.1,
                ) {
                    return;
                }
            }
            log::error!("Failed to boot AHCI entry");
        }
        menu::DeviceType::Usb {
            controller_id,
            device_addr: _,
        } => {
            let controller_ptr = match drivers::usb::get_controller_ptr(controller_id) {
                Some(ptr) => ptr,
                None => {
                    log::error!("Failed to get USB controller {}", controller_id);
                    return;
                }
            };

            if let Some(usb_device) = drivers::usb::mass_storage::get_global_device() {
                let num_blocks = usb_device.num_blocks;
                let block_size = usb_device.block_size;

                let storage_id = match storage::register_device(
                    StorageType::Usb { slot_id: 0 },
                    num_blocks,
                    block_size,
                ) {
                    Some(id) => id,
                    None => {
                        log::error!("Failed to register device");
                        return;
                    }
                };

                // Safety: controller_ptr is valid for the entire boot process
                let controller = unsafe { &mut *controller_ptr };
                if let Some(usb_device) = drivers::usb::mass_storage::get_global_device() {
                    let mut disk = UsbDisk::new(usb_device, controller);
                    let _ = boot::install_block_io_protocols(
                        &mut disk, storage_id, block_size, num_blocks, &path_info,
                    );
                }

                // Re-borrow for ESP boot
                let controller = unsafe { &mut *controller_ptr };
                if let Some(usb_device) = drivers::usb::mass_storage::get_global_device() {
                    let mut disk = UsbDisk::new(usb_device, controller);
                    if boot::try_boot_from_esp(
                        &mut disk,
                        &entry.partition,
                        entry.partition_num,
                        &path_info,
                        &entry.device_type,
                        num_blocks,
                        block_size,
                    ) {
                        return;
                    }
                }
            }
            log::error!("Failed to boot USB entry");
        }
        menu::DeviceType::Sdhci { controller_id } => {
            if !drivers::sdhci::store_global_device(controller_id) {
                log::error!("Failed to store SDHCI device globally");
                return;
            }

            if let Some(controller_ptr) = drivers::sdhci::get_controller(controller_id) {
                // Safety: pointer valid for firmware lifetime
                let controller = unsafe { &mut *controller_ptr };
                let num_blocks = controller.num_blocks();
                let block_size = controller.block_size();

                let storage_id = match storage::register_device(
                    StorageType::Sdhci { controller_id },
                    num_blocks,
                    block_size,
                ) {
                    Some(id) => id,
                    None => {
                        log::error!("Failed to register device");
                        return;
                    }
                };

                let mut disk = SdhciDisk::new(controller);
                let _ = boot::install_block_io_protocols(
                    &mut disk, storage_id, block_size, num_blocks, &path_info,
                );
            }

            if let Some(controller_ptr) = drivers::sdhci::get_controller(controller_id) {
                // Safety: pointer valid for firmware lifetime
                let controller = unsafe { &mut *controller_ptr };
                let num_blocks = controller.num_blocks();
                let block_size = controller.block_size();
                let mut disk = SdhciDisk::new(controller);
                if boot::try_boot_from_esp(
                    &mut disk,
                    &entry.partition,
                    entry.partition_num,
                    &path_info,
                    &entry.device_type,
                    num_blocks,
                    block_size,
                ) {
                    return;
                }
            }
            log::error!("Failed to boot SDHCI entry");
        }
    }
}

/// Boot Linux from a block device (shared logic for all device types)
///
/// Loads the kernel, optional initrd, and command line from a FAT partition
/// on the given block device, then boots Linux directly.
///
/// # Arguments
/// * `disk` - Any block device implementing BlockDevice
/// * `partition_first_lba` - First LBA of the boot partition
/// * `kernel_path` - FAT-style path to the kernel
/// * `initrd_fat_path` - Optional FAT-style path to the initrd
/// * `cmdline` - Kernel command line
/// * `memory_regions` - Memory map from coreboot
/// * `acpi_rsdp` - Optional ACPI RSDP address
/// * `framebuffer` - Optional framebuffer info for Linux console
///
/// # Returns
/// `true` if boot was initiated (unreachable in practice), `false` on failure
fn boot_linux_from_device(
    disk: &mut dyn crate::drivers::block::BlockDevice,
    partition_first_lba: u64,
    kernel_path: &str,
    initrd_fat_path: Option<&str>,
    cmdline: &str,
    memory_regions: &[crate::coreboot::memory::MemoryRegion],
    acpi_rsdp: Option<u64>,
    framebuffer: Option<&crate::coreboot::FramebufferInfo>,
) -> bool {
    match linux_boot::load_linux_from_disk(
        disk,
        partition_first_lba,
        kernel_path,
        initrd_fat_path,
        cmdline,
        memory_regions,
        acpi_rsdp,
        framebuffer,
        false, // Don't use EFI handover for direct boot
    ) {
        Ok(mut loaded) => {
            log::info!("Linux loaded successfully, booting...");
            unsafe {
                loaded.boot_direct();
            }
        }
        Err(e) => {
            log::error!("Failed to load Linux: {:?}", e);
            false
        }
    }
}

/// Boot a direct Linux entry (BLS Type #1 or GRUB)
///
/// This uses the linux_boot module to load and boot the kernel directly,
/// bypassing UEFI bootloaders like GRUB or systemd-boot.
fn boot_linux_entry(
    entry: &menu::BootEntry,
    linux_path: &heapless::String<128>,
    initrd_path: &heapless::String<128>,
    cmdline: &heapless::String<512>,
) {
    // Defense in depth: Direct Linux boot entries should not appear in the menu
    // when Secure Boot is active (filtered in scan_partition_for_entries), but
    // check here as well in case an entry somehow makes it through.
    // Direct boot bypasses signature verification which violates Secure Boot.
    if efi::auth::is_secure_boot_enabled() {
        log::warn!("Direct Linux boot disabled: Secure Boot is active");
        log::info!("Falling back to UEFI boot path for secure verification");
        // Fall back to UEFI boot which will verify the bootloader signature
        boot_uefi_entry(entry);
        return;
    }

    log::info!("Direct Linux boot: {}", entry.name);
    log::info!("  Kernel: {}", linux_path);
    if !initrd_path.is_empty() {
        log::info!("  Initrd: {}", initrd_path);
    }
    log::info!("  Cmdline: {}", cmdline);

    // Convert Linux-style paths (forward slashes) to FAT-style paths (backslashes)
    let kernel_path = match fs::linux_path_to_fat(linux_path) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Invalid kernel path '{}': {:?}", linux_path, e);
            return;
        }
    };
    let initrd_fat_path = if !initrd_path.is_empty() {
        match fs::linux_path_to_fat(initrd_path) {
            Ok(p) => Some(p),
            Err(e) => {
                log::error!("Invalid initrd path '{}': {:?}", initrd_path, e);
                return;
            }
        }
    } else {
        None
    };

    log::debug!("FAT kernel path: {}", kernel_path);
    if let Some(ref p) = initrd_fat_path {
        log::debug!("FAT initrd path: {}", p);
    }

    // Get memory regions and ACPI RSDP from state
    let (memory_regions, acpi_rsdp) = {
        let state = state::get();
        // Copy memory regions to a local buffer (we can't borrow across the disk operations)
        let mut regions = heapless::Vec::<crate::coreboot::memory::MemoryRegion, 64>::new();
        for region in state.drivers.memory_regions.iter() {
            let _ = regions.push(*region);
        }
        (regions, state.drivers.acpi_rsdp)
    };

    // Get framebuffer info for Linux console
    let framebuffer = coreboot::get_framebuffer();

    if memory_regions.is_empty() {
        log::error!("No memory regions available for Linux boot");
        return;
    }

    log::debug!(
        "Memory regions: {}, ACPI RSDP: {:?}, Framebuffer: {}",
        memory_regions.len(),
        acpi_rsdp,
        if framebuffer.is_some() { "yes" } else { "no" }
    );

    // Dispatch based on device type - each arm does device-specific setup,
    // then delegates to boot_linux_from_device for the shared load+boot logic.
    match entry.device_type {
        menu::DeviceType::Nvme {
            controller_id,
            nsid,
        } => {
            if !drivers::nvme::store_global_device(controller_id, nsid) {
                log::error!("Failed to store NVMe device globally");
                return;
            }

            if let Some(controller_ptr) = drivers::nvme::get_controller(controller_id) {
                // Safety: pointer valid for firmware lifetime; no overlapping &mut created
                let controller = unsafe { &mut *controller_ptr };
                log::info!("Got NVMe controller {}", controller_id);
                let mut disk = NvmeDisk::new(controller, nsid);
                boot_linux_from_device(
                    &mut disk,
                    entry.partition.first_lba,
                    &kernel_path,
                    initrd_fat_path.as_deref(),
                    cmdline,
                    &memory_regions,
                    acpi_rsdp,
                    framebuffer.as_ref(),
                );
            } else {
                log::error!("Failed to get NVMe controller {}", controller_id);
            }
        }

        menu::DeviceType::Ahci {
            controller_id,
            port,
        } => {
            if !drivers::ahci::store_global_device(controller_id, port) {
                log::error!("Failed to store AHCI device globally");
                return;
            }

            if let Some(controller_ptr) = drivers::ahci::get_controller(controller_id) {
                // Safety: pointer valid for firmware lifetime; no overlapping &mut created
                let controller = unsafe { &mut *controller_ptr };
                log::info!("Got AHCI controller {}", controller_id);
                let mut disk = AhciDisk::new(controller, port);
                boot_linux_from_device(
                    &mut disk,
                    entry.partition.first_lba,
                    &kernel_path,
                    initrd_fat_path.as_deref(),
                    cmdline,
                    &memory_regions,
                    acpi_rsdp,
                    framebuffer.as_ref(),
                );
            } else {
                log::error!("Failed to get AHCI controller {}", controller_id);
            }
        }

        menu::DeviceType::Usb {
            controller_id,
            device_addr: _,
        } => {
            let controller_ptr = match drivers::usb::get_controller_ptr(controller_id) {
                Some(ptr) => ptr,
                None => {
                    log::error!("Failed to get USB controller {}", controller_id);
                    return;
                }
            };

            if let Some(usb_device) = drivers::usb::mass_storage::get_global_device() {
                log::info!("Got USB mass storage device");
                // Safety: controller_ptr is valid for the entire boot process
                let controller = unsafe { &mut *controller_ptr };
                let mut disk = UsbDisk::new(usb_device, controller);
                boot_linux_from_device(
                    &mut disk,
                    entry.partition.first_lba,
                    &kernel_path,
                    initrd_fat_path.as_deref(),
                    cmdline,
                    &memory_regions,
                    acpi_rsdp,
                    framebuffer.as_ref(),
                );
            } else {
                log::error!("USB mass storage device not available");
            }
        }

        menu::DeviceType::Sdhci { controller_id } => {
            if !drivers::sdhci::store_global_device(controller_id) {
                log::error!("Failed to store SDHCI device globally");
                return;
            }

            if let Some(controller_ptr) = drivers::sdhci::get_controller(controller_id) {
                // Safety: pointer valid for firmware lifetime
                let controller = unsafe { &mut *controller_ptr };
                log::info!("Got SDHCI controller {}", controller_id);
                let mut disk = SdhciDisk::new(controller);
                boot_linux_from_device(
                    &mut disk,
                    entry.partition.first_lba,
                    &kernel_path,
                    initrd_fat_path.as_deref(),
                    cmdline,
                    &memory_regions,
                    acpi_rsdp,
                    framebuffer.as_ref(),
                );
            } else {
                log::error!("Failed to get SDHCI controller {}", controller_id);
            }
        }
    }

    // Note: We intentionally don't fall back to UEFI boot here.
    // If the user selected a direct Linux boot entry, they want Linux,
    // not a UEFI bootloader. If it fails, show an error and return to menu.
    log::error!("Direct Linux boot failed - returning to menu");
}

/// Boot a coreboot payload entry
///
/// This uses the payload module to load and chainload another coreboot payload.
fn boot_payload_entry(
    entry: &menu::BootEntry,
    path: &heapless::String<128>,
    format: payload::PayloadFormat,
) {
    log::info!("Chainloading payload: {}", entry.name);
    log::info!("  Path: {}", path);
    log::info!("  Format: {:?}", format);

    // TODO: Implement full payload chainloading
    // This requires:
    // 1. Mount FAT filesystem on the partition
    // 2. Create PayloadEntry from the menu entry
    // 3. Call payload::chainload_payload()
    //
    // For now, log the attempt and return
    log::warn!("Payload chainloading not yet fully implemented");
}
