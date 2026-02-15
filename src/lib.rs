//! CrabEFI - A minimal UEFI implementation as a coreboot payload
//!
//! This library provides the core functionality for a minimal UEFI environment
//! that can boot Linux via shim+GRUB2 or systemd-boot on real laptop hardware.

#![no_std]
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
pub mod boot_vars;
pub mod cfr_menu;
pub mod coreboot;
pub mod drivers;
pub mod efi;
#[cfg(feature = "fb-log")]
pub mod fb_log;
pub mod framebuffer_console;
pub mod fs;
pub mod grub;
pub mod heap;
#[cfg(target_arch = "x86_64")]
pub mod linux_boot;
pub mod logger;
pub mod menu;
pub(crate) mod menu_common;
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
        arch::halt();
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

/// Discover PCI ECAM base address from the ACPI MCFG table.
///
/// Walks the XSDT/RSDT to find the MCFG table and extracts the first
/// ECAM base address allocation entry.
fn discover_ecam_from_acpi() -> Option<u64> {
    let rsdp_addr = state::drivers().acpi_rsdp?;

    // RSDP, SDT header structs are packed — safe to reference at any alignment
    #[repr(C, packed)]
    struct Rsdp {
        signature: [u8; 8],
        _checksum: u8,
        _oem_id: [u8; 6],
        revision: u8,
        rsdt_address: u32,
        _length: u32,
        xsdt_address: u64,
    }

    #[repr(C, packed)]
    struct SdtHeader {
        signature: [u8; 4],
        length: u32,
    }

    let rsdp = unsafe { &*(rsdp_addr as *const Rsdp) };
    if &rsdp.signature != b"RSD PTR " {
        return None;
    }

    let (root_addr, is_xsdt) = if rsdp.revision >= 2 && rsdp.xsdt_address != 0 {
        (rsdp.xsdt_address, true)
    } else {
        (rsdp.rsdt_address as u64, false)
    };
    if root_addr == 0 {
        return None;
    }

    let root_header = unsafe { &*(root_addr as *const SdtHeader) };
    // Full ACPI SDT header is 36 bytes (signature, length, revision, checksum, oem fields, etc.)
    // Our SdtHeader only has the first 8 bytes we need, but entries start after the full 36.
    const ACPI_SDT_HEADER_SIZE: usize = 36;
    let entry_size = if is_xsdt { 8 } else { 4 };
    let num_entries = (root_header.length as usize - ACPI_SDT_HEADER_SIZE) / entry_size;
    let entries_base = root_addr + ACPI_SDT_HEADER_SIZE as u64;

    for i in 0..num_entries {
        let table_addr = if is_xsdt {
            unsafe { ((entries_base + (i * 8) as u64) as *const u64).read_unaligned() }
        } else {
            unsafe { ((entries_base + (i * 4) as u64) as *const u32).read_unaligned() as u64 }
        };
        if table_addr == 0 {
            continue;
        }

        let header = unsafe { &*(table_addr as *const SdtHeader) };
        if &header.signature == b"MCFG" {
            // MCFG layout: 36-byte ACPI header + 8 bytes reserved + allocation entries (16 bytes each)
            // Each entry: base_address(u64), segment(u16), start_bus(u8), end_bus(u8), reserved(u32)
            let mcfg_len = header.length as usize;
            if mcfg_len >= 44 + 16 {
                // First allocation entry base address is at offset 44
                let base = unsafe { ((table_addr + 44) as *const u64).read_unaligned() };
                if base != 0 {
                    return Some(base);
                }
            }
        }
    }

    None
}

/// Initialize the CrabEFI firmware
///
/// This is called from the entry point after switching to 64-bit mode.
///
/// # Arguments
///
/// * `coreboot_table_ptr` - Pointer to the coreboot tables
pub fn init(coreboot_table_ptr: u64) -> ! {
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
    if let Some(fb) = cb_info.framebuffer {
        coreboot::store_framebuffer(fb);
    }

    // Store the coreboot framebuffer record address so we can invalidate it
    // at ExitBootServices to prevent a race between Linux's simplefb and efifb
    if let Some(addr) = cb_info.framebuffer_record_addr {
        coreboot::store_framebuffer_record_addr(addr);
    }

    // Store SMMSTORE v2 info globally for variable persistence
    if let Some(smmstore) = cb_info.smmstorev2 {
        coreboot::store_smmstorev2(smmstore);
    }

    // Store SPI flash info globally (used for FMAP parsing)
    if let Some(ref spi_flash) = cb_info.spi_flash {
        coreboot::store_spi_flash(spi_flash.clone());
    }

    // Store boot media info globally (contains FMAP offset)
    if let Some(boot_media) = cb_info.boot_media {
        coreboot::store_boot_media(boot_media);
    }

    // NOTE: CFR parsing is deferred until after heap::init() because it
    // requires heap allocation (alloc::String, alloc::Vec). The raw data
    // pointer is saved in cb_info.cfr_raw during table parsing.

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
        drivers::serial::init_from_coreboot(serial.baseaddr, serial.baud, serial.mmio());
    }

    // Initialize logging (now that serial is set up)
    logger::init();

    // Set framebuffer for logging output (so we can see logs on screen)
    if let Some(fb) = cb_info.framebuffer {
        logger::set_framebuffer(fb);
    }

    // Initialize keyboard subsystem (PS/2 on x86, USB-only on aarch64)
    drivers::keyboard_common::init();

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
    if cb_info.cfr_raw.is_some() {
        log::info!("  CFR: raw data found (parsed after heap init)");
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
        log::error!(
            "Failed to initialize heap allocator! Secure Boot and other alloc-dependent features will be unavailable."
        );
        // Continue boot -- features requiring alloc will fail gracefully
    }

    // Parse and store CFR data now that the heap is available.
    // The raw data pointer was saved during coreboot table parsing.
    if let Some(cfr_raw) = cb_info.cfr_raw
        && let Some(cfr) = coreboot::cfr::parse_cfr(cfr_raw)
    {
        log::info!(
            "CFR: {} forms, {} options",
            cfr.forms.len(),
            cfr.total_options()
        );
        coreboot::store_cfr(cfr);
    }

    log::info!("CrabEFI initialized successfully!");
    log::info!("EFI System Table at: {:p}", efi::get_system_table());

    // Discover PCI ECAM base from ACPI MCFG table before PCI init
    if let Some(ecam_base) = discover_ecam_from_acpi() {
        log::info!("PCI ECAM base from ACPI MCFG: {:#x}", ecam_base);
        drivers::pci::set_ecam_base(ecam_base);
    }

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

    // Cache boot manager variables EARLY, before platform hooks or driver
    // binding can modify them (matches edk2 BdsEntry behavior).
    let boot_var_state = boot_vars::read_boot_var_state();

    // Initialize storage subsystem and run boot manager
    run_boot_manager(boot_var_state);

    log::info!("Press Ctrl+A X to exit QEMU");

    // Halt and wait
    loop {
        arch::halt();
    }
}

/// Initialize storage subsystem (PCI drivers, USB keyboards, etc.)
///
/// This is called once before the boot manager starts trying boot options.
fn init_storage_subsystem() {
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

    log::info!("Storage subsystem initialized");
}

/// Run the UEFI boot manager.
///
/// Implements the boot dispatch sequence from UEFI Specification Section 3.1:
///
/// 1. Initialize storage subsystem (PCI drivers)
/// 2. **BootNext** — if set, delete it and try that Boot#### entry
/// 3. **BootOrder** — iterate Boot#### entries in order, try each active one
/// 4. **Fallback** — discover boot entries from ESPs (removable media path)
/// 5. Show interactive boot menu if nothing booted automatically
fn run_boot_manager(boot_var_state: boot_vars::BootVarState) {
    init_storage_subsystem();

    // Apply timeout from the Timeout variable (if set) to the boot menu default
    let timeout_seconds = boot_var_state.timeout.unwrap_or(5) as u32;

    // ---- Phase 1: BootNext ----
    if let Some(boot_next_num) = boot_var_state.boot_next {
        log::info!("=== BootNext: attempting Boot{:04X} ===", boot_next_num);

        // Delete BootNext BEFORE attempting boot (prevents infinite loops)
        boot_vars::delete_boot_next();

        if let Some(load_option) = boot_vars::read_boot_option(boot_next_num) {
            // Match edk2 (BdsLibBootNext): skip if not active or not boot category
            if !load_option.should_boot() {
                log::warn!(
                    "BootNext Boot{:04X}: skipped (active={}, category_boot={})",
                    boot_next_num,
                    load_option.is_active(),
                    load_option.is_boot_category()
                );
            } else if let Some(file_path) = boot_vars::extract_file_path(&load_option) {
                log::info!("BootNext: '{}' -> {}", load_option.description, file_path);
                let result = try_boot_load_option(&load_option, &file_path);
                if result == boot_vars::BootAttemptResult::Success {
                    log::info!("BootNext succeeded, returning to boot manager");
                    // edk2 would show BootManagerMenu here; we fall through to menu
                }
            } else {
                log::warn!(
                    "BootNext Boot{:04X}: no file path found in device path list",
                    boot_next_num
                );
            }
        } else {
            log::warn!("BootNext Boot{:04X}: variable not found", boot_next_num);
        }
    }

    // ---- Phase 2: BootOrder ----
    if !boot_var_state.boot_order.is_empty() {
        log::info!(
            "=== BootOrder: trying {} entries ===",
            boot_var_state.boot_order.len()
        );

        for &option_num in boot_var_state.boot_order.iter() {
            let Some(load_option) = boot_vars::read_boot_option(option_num) else {
                log::debug!("Boot{:04X}: not found, skipping", option_num);
                continue;
            };

            if !load_option.should_boot() {
                log::debug!(
                    "Boot{:04X}: skipped (active={}, category_boot={})",
                    option_num,
                    load_option.is_active(),
                    load_option.is_boot_category()
                );
                continue;
            }

            let Some(file_path) = boot_vars::extract_file_path(&load_option) else {
                log::debug!("Boot{:04X}: no file path, skipping", option_num);
                continue;
            };

            log::info!(
                "BootOrder: trying Boot{:04X} '{}' -> {}",
                option_num,
                load_option.description,
                file_path
            );

            let result = try_boot_load_option(&load_option, &file_path);
            match result {
                boot_vars::BootAttemptResult::Success => {
                    log::info!("Boot{:04X} succeeded", option_num);
                    // edk2 retries the whole loop if boot succeeded then returned;
                    // we fall through to the menu instead
                    break;
                }
                boot_vars::BootAttemptResult::Failed => {
                    log::warn!(
                        "Boot{:04X} '{}' failed, trying next",
                        option_num,
                        load_option.description
                    );
                }
                boot_vars::BootAttemptResult::Skipped => {}
            }
        }
    }

    // ---- Phase 3: Fallback to device discovery and interactive menu ----
    log::info!("=== Fallback: discovering boot entries from storage ===");

    let mut boot_menu = menu::discover_boot_entries();

    if boot_menu.entry_count() == 0 {
        log::warn!("No bootable media found!");
        return;
    }

    // Apply Timeout variable to the menu
    boot_menu.set_timeout(timeout_seconds);

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

    log::info!("Boot manager finished");
}

/// Attempt to boot a Boot#### load option.
///
/// This resolves the file path from the load option's device path list and
/// attempts to find and boot the referenced EFI application from discovered
/// storage devices. Sets BootCurrent before booting and clears it after.
///
/// Currently this matches the file path against ESPs found on storage devices.
/// Full device path matching (resolving the exact disk/partition from the
/// device path) is a future enhancement.
fn try_boot_load_option(
    load_option: &boot_vars::LoadOption,
    file_path: &str,
) -> boot_vars::BootAttemptResult {
    // Set BootCurrent before attempting boot
    boot_vars::set_boot_current(load_option.option_number);

    // Try to find this file on any discovered ESP
    let result = try_boot_file_from_esps(file_path);

    // Clear BootCurrent after boot returns
    boot_vars::clear_boot_current();

    result
}

/// Try to boot a specific file path from any discovered ESP.
///
/// Scans all storage devices, looks for ESPs, and tries to find and boot
/// the specified file. This is the fallback path when we don't have full
/// device path resolution yet.
fn try_boot_file_from_esps(file_path: &str) -> boot_vars::BootAttemptResult {
    // Convert forward slashes to backslashes for FAT
    let fat_path = if file_path.contains('/') {
        match crate::fs::linux_path_to_fat(file_path) {
            Ok(p) => p,
            Err(_) => {
                let mut p = heapless::String::<128>::new();
                if p.push_str(file_path).is_err() {
                    log::warn!("boot file path truncated ({} > 128 chars)", file_path.len());
                }
                p
            }
        }
    } else {
        let mut p = heapless::String::<128>::new();
        if p.push_str(file_path).is_err() {
            log::warn!("boot file path truncated ({} > 128 chars)", file_path.len());
        }
        p
    };

    // Try NVMe devices
    if try_boot_file_on_nvme(&fat_path) {
        return boot_vars::BootAttemptResult::Success;
    }

    // Try AHCI devices
    if try_boot_file_on_ahci(&fat_path) {
        return boot_vars::BootAttemptResult::Success;
    }

    // Try USB devices
    if try_boot_file_on_usb(&fat_path) {
        return boot_vars::BootAttemptResult::Success;
    }

    // Try SDHCI devices
    if try_boot_file_on_sdhci(&fat_path) {
        return boot_vars::BootAttemptResult::Success;
    }

    boot_vars::BootAttemptResult::Failed
}

/// Try to boot a file from NVMe ESPs
fn try_boot_file_on_nvme(file_path: &str) -> bool {
    use crate::drivers::nvme;

    let Some(controller_ptr) = nvme::get_controller(0) else {
        return false;
    };
    let controller = unsafe { &mut *controller_ptr };
    let Some(ns) = controller.default_namespace() else {
        return false;
    };
    let nsid = ns.nsid;
    let pci_addr = controller.pci_address();

    if !nvme::store_global_device(0, nsid) {
        return false;
    }

    let device_type = menu::DeviceType::Nvme {
        controller_id: 0,
        nsid,
    };

    try_boot_file_on_device(&device_type, pci_addr.device, pci_addr.function, file_path)
}

/// Try to boot a file from AHCI ESPs
fn try_boot_file_on_ahci(file_path: &str) -> bool {
    use crate::drivers::ahci;

    let Some(controller_ptr) = ahci::get_controller(0) else {
        return false;
    };
    let controller = unsafe { &mut *controller_ptr };
    let pci_addr = controller.pci_address();
    let num_ports = controller.num_active_ports();

    for port_index in 0..num_ports {
        if !ahci::store_global_device(0, port_index) {
            continue;
        }
        let device_type = menu::DeviceType::Ahci {
            controller_id: 0,
            port: port_index,
        };
        if try_boot_file_on_device(&device_type, pci_addr.device, pci_addr.function, file_path) {
            return true;
        }
    }
    false
}

/// Try to boot a file from USB ESPs
fn try_boot_file_on_usb(file_path: &str) -> bool {
    use crate::drivers::usb::{self, UsbMassStorage, mass_storage};

    let Some((controller_id, device_addr)) = usb::find_mass_storage() else {
        return false;
    };
    let Some(controller_ptr) = usb::get_controller_ptr(controller_id) else {
        return false;
    };

    let device_created =
        usb::with_controller(controller_id, |controller| {
            match UsbMassStorage::new(controller, device_addr) {
                Ok(usb_device) => {
                    if usb_device.num_blocks == 0 {
                        return false;
                    }
                    unsafe {
                        mass_storage::store_global_device_with_controller_ptr(
                            usb_device,
                            controller_ptr,
                        )
                    }
                }
                Err(_) => false,
            }
        });

    if device_created != Some(true) {
        return false;
    }

    let device_type = menu::DeviceType::Usb {
        controller_id,
        device_addr,
    };
    try_boot_file_on_device(&device_type, 0, 0, file_path)
}

/// Try to boot a file from SDHCI ESPs
fn try_boot_file_on_sdhci(file_path: &str) -> bool {
    use crate::drivers::sdhci;

    for controller_id in 0..sdhci::controller_count() {
        let Some(controller_ptr) = sdhci::get_controller(controller_id) else {
            continue;
        };
        let controller = unsafe { &mut *controller_ptr };
        if !controller.is_ready() {
            continue;
        }
        let pci_addr = controller.pci_address();

        if !sdhci::store_global_device(controller_id) {
            continue;
        }

        let device_type = menu::DeviceType::Sdhci { controller_id };
        if try_boot_file_on_device(&device_type, pci_addr.device, pci_addr.function, file_path) {
            return true;
        }
    }
    false
}

/// Try to boot a specific file from ESPs on a given device.
///
/// Reads GPT, finds ESP partitions, mounts FAT, checks if the file exists,
/// and if so, boots it through the standard UEFI boot path.
fn try_boot_file_on_device(
    device_type: &menu::DeviceType,
    pci_device: u8,
    pci_function: u8,
    file_path: &str,
) -> bool {
    use crate::fs::{fat::FatFilesystem, gpt};

    // Read GPT partitions
    let partitions = with_disk(device_type, |disk| {
        if let Ok(header) = gpt::read_gpt_header(disk)
            && let Ok(parts) = gpt::read_partitions(disk, &header)
        {
            Some(parts)
        } else {
            None
        }
    })
    .flatten();

    let partitions = match partitions {
        Some(p) => p,
        None => return false,
    };

    // Look for ESPs containing the target file
    for (i, partition) in partitions.iter().enumerate() {
        if !partition.is_esp {
            continue;
        }

        let partition_num = (i + 1) as u32;

        // Try to mount FAT and check for the file
        let found = with_disk(device_type, |disk| {
            if let Ok(mut fat) = FatFilesystem::new(disk, partition.first_lba) {
                fat.file_size(file_path).is_ok()
            } else {
                false
            }
        })
        .unwrap_or(false);

        if !found {
            continue;
        }

        log::info!(
            "Found '{}' on {} partition {}",
            file_path,
            device_type.description(),
            partition_num
        );

        // Build a synthetic BootEntry and boot it through the standard path
        let entry = menu::BootEntry::new(
            file_path,
            file_path,
            *device_type,
            partition_num,
            partition.clone(),
            pci_device,
            pci_function,
        );

        boot_uefi_entry(&entry);

        // If boot_uefi_entry returned, the boot failed
        return false;
    }

    false
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
            #[cfg(target_arch = "x86_64")]
            {
                log::info!("Dispatching to direct Linux boot");
                boot_linux_entry(entry, linux_path, initrd_path, cmdline);
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                let _ = (linux_path, initrd_path, cmdline);
                log::warn!("Direct Linux boot not supported on this architecture");
            }
        }

        // Coreboot payload chainloading
        menu::BootEntryKind::Payload { path, format } => {
            log::info!("Dispatching to payload chainload");
            boot_payload_entry(entry, path, *format);
        }
    }
}

/// Store a device globally for SimpleFileSystem reads.
///
/// Each device type has its own `store_global_device()` with different parameters.
/// This dispatches to the right one based on the device type.
pub(crate) fn store_device_globally(device_type: &menu::DeviceType) -> bool {
    match *device_type {
        menu::DeviceType::Nvme {
            controller_id,
            nsid,
        } => drivers::nvme::store_global_device(controller_id, nsid),
        menu::DeviceType::Ahci {
            controller_id,
            port,
        } => drivers::ahci::store_global_device(controller_id, port),
        // USB devices are stored globally during enumeration, not here
        menu::DeviceType::Usb { .. } => true,
        menu::DeviceType::Sdhci { controller_id } => {
            drivers::sdhci::store_global_device(controller_id)
        }
    }
}

/// Convert a menu device type to a storage type for BlockIO registration.
fn storage_type_from(device_type: &menu::DeviceType) -> drivers::storage::StorageType {
    use drivers::storage::StorageType;
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
        menu::DeviceType::Usb { .. } => StorageType::Usb { slot_id: 0 },
        menu::DeviceType::Sdhci { controller_id } => StorageType::Sdhci { controller_id },
    }
}

/// Create a block device from a device type and call the provided closure with it.
///
/// This centralizes the per-device-type controller acquisition and disk creation
/// so that callers only need the generic `&mut dyn BlockDevice` interface.
///
/// # Returns
/// `Some(R)` if the device was created and the closure returned a value,
/// `None` if the device could not be created.
pub(crate) fn with_disk<R>(
    device_type: &menu::DeviceType,
    f: impl FnOnce(&mut dyn drivers::block::BlockDevice) -> R,
) -> Option<R> {
    match *device_type {
        menu::DeviceType::Nvme {
            controller_id,
            nsid,
        } => {
            let controller = unsafe { &mut *drivers::nvme::get_controller(controller_id)? };
            let mut disk = NvmeDisk::new(controller, nsid);
            Some(f(&mut disk))
        }
        menu::DeviceType::Ahci {
            controller_id,
            port,
        } => {
            let controller = unsafe { &mut *drivers::ahci::get_controller(controller_id)? };
            let mut disk = AhciDisk::new(controller, port);
            Some(f(&mut disk))
        }
        menu::DeviceType::Usb {
            controller_id,
            device_addr: _,
        } => {
            let controller_ptr = drivers::usb::get_controller_ptr(controller_id)?;
            let controller = unsafe { &mut *controller_ptr };
            let usb_device = drivers::usb::mass_storage::get_global_device()?;
            let mut disk = UsbDisk::new(usb_device, controller);
            Some(f(&mut disk))
        }
        menu::DeviceType::Sdhci { controller_id } => {
            let controller = unsafe { &mut *drivers::sdhci::get_controller(controller_id)? };
            let mut disk = SdhciDisk::new(controller);
            Some(f(&mut disk))
        }
    }
}

/// Boot a UEFI entry (EFI application or UKI)
///
/// Uses the unified boot module to handle all storage types generically.
/// Device-specific logic is encapsulated in `store_device_globally()` and
/// `with_disk()`, keeping this function device-agnostic.
fn boot_uefi_entry(entry: &menu::BootEntry) {
    use drivers::storage;

    let path_info = boot::device_path_info_from_entry(entry);

    // Phase 1: Store device globally and install BlockIO protocols
    if !store_device_globally(&entry.device_type) {
        log::error!("Failed to store device globally");
        return;
    }

    let phase1_ok = with_disk(&entry.device_type, |disk| {
        let info = disk.info();
        let storage_id = match storage::register_device(
            storage_type_from(&entry.device_type),
            info.num_blocks,
            info.block_size,
        ) {
            Some(id) => id,
            None => {
                log::error!("Failed to register device");
                return false;
            }
        };
        let _ = boot::install_block_io_protocols(
            disk,
            storage_id,
            info.block_size,
            info.num_blocks,
            &path_info,
        );
        true
    });

    if phase1_ok != Some(true) {
        log::error!("Failed to create disk for BlockIO installation");
        return;
    }

    // Phase 2: Re-create disk for ESP boot (previous borrows ended)
    let booted = with_disk(&entry.device_type, |disk| {
        let info = disk.info();
        boot::try_boot_from_esp(
            disk,
            &entry.partition,
            entry.partition_num,
            &path_info,
            &entry.device_type,
            info.num_blocks,
            info.block_size,
        )
    });

    if booted == Some(true) {
        return;
    }
    log::error!("Failed to boot UEFI entry");
}

/// Boot Linux from a block device (shared logic for all device types)
///
/// Loads the kernel, optional initrd, and command line from a FAT partition
/// on the given block device, then boots Linux directly.
///
/// This is x86-only as it uses the bzImage/x86 boot protocol.
/// On aarch64, Linux boot uses a different protocol (not yet implemented).
#[cfg(target_arch = "x86_64")]
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
///
/// x86-only: uses bzImage boot protocol.
#[cfg(target_arch = "x86_64")]
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

    // Store device globally for SimpleFileSystem reads, then create a disk
    // and delegate to boot_linux_from_device for the shared load+boot logic.
    if !store_device_globally(&entry.device_type) {
        log::error!("Failed to store device globally");
        return;
    }

    if with_disk(&entry.device_type, |disk| {
        boot_linux_from_device(
            disk,
            entry.partition.first_lba,
            &kernel_path,
            initrd_fat_path.as_deref(),
            cmdline,
            &memory_regions,
            acpi_rsdp,
            framebuffer.as_ref(),
        );
    })
    .is_none()
    {
        log::error!("Failed to create disk for Linux boot");
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
