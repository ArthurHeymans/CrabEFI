//! CrabEFI - A minimal UEFI implementation as a coreboot payload
//!
//! This library provides the core functionality for a minimal UEFI environment
//! that can boot Linux via shim+GRUB2 or systemd-boot on real laptop hardware.

#![no_std]
#![feature(never_type)] // Used for -> ! return type in payload chainloading
#![deny(unsafe_op_in_unsafe_fn)]
// Allow common firmware code patterns
#![allow(clippy::result_unit_err)] // Result<(), ()> is common in embedded code
#![allow(clippy::too_many_arguments)] // USB/hardware APIs often require many parameters
#![allow(clippy::field_reassign_with_default)] // Clearer than complex struct initializers

// Enable alloc crate for heap allocations (needed for RustCrypto)
extern crate alloc;

pub mod arch;
pub mod bls;
pub mod boot;
mod boot_manager;
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
    let rsdp_addr = state::drivers().platform.acpi_rsdp?;

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
            let _ = drivers.platform.memory_regions.push(*region);
        }
        // Store ACPI RSDP
        drivers.platform.acpi_rsdp = cb_info.acpi_rsdp;
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

    // Register the runtime services log region and dump any log from the
    // previous boot before we do anything else (so the data is visible even
    // if init fails).  init() is called after deferred writes are processed.
    #[cfg(feature = "rt-log")]
    {
        efi::rtlog::register_region();
        efi::rtlog::dump();
    }

    // Reserve the deferred variable buffer region as RuntimeServicesData.
    // The buffer is at a fixed address (0x80000) below the payload, placed
    // there by the linker script so coreboot/cbfstool never overwrites it.
    // Registering it as RuntimeServicesData ensures the OS preserves the
    // mapping and SetVirtualAddressMap adjusts the GOT-based pointer.
    {
        use efi::allocator::{MemoryType, PAGE_SIZE};
        use efi::varstore::deferred;

        let buf_base = deferred::deferred_buffer_base();
        let buf_pages = (deferred::deferred_buffer_size() as u64).div_ceil(PAGE_SIZE);

        // The buffer is outside the payload load region so it might not be in
        // the coreboot-derived memory map at all.  force_add_region creates
        // the entry unconditionally.
        if let Err(e) =
            efi::allocator::force_add_region(buf_base, buf_pages, MemoryType::RuntimeServicesData)
        {
            log::warn!(
                "Could not register deferred buffer at {:#x}: {:?}",
                buf_base,
                e
            );
        } else {
            log::info!(
                "Deferred buffer at {:#x} ({} pages) registered as RuntimeServicesData",
                buf_base,
                buf_pages
            );
        }
    }

    // Initialize variable store persistence (loads variables from SPI flash)
    match efi::varstore::init_persistence() {
        Ok(()) => {
            log::info!("Variable store persistence initialized");

            // Check for pending deferred writes from previous warm boot
            let pending_count = efi::varstore::check_deferred_pending();
            if pending_count > 0 {
                log::info!(
                    "Found {} pending deferred writes from previous boot",
                    pending_count
                );
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

    // Initialize the deferred buffer for this boot session.
    // Any pending writes from a previous warm boot were already processed
    // above; now clear the buffer so new runtime writes can be accumulated.
    efi::varstore::init_deferred_buffer();

    // Initialize the runtime log for this boot session (clears previous boot's
    // data now that it has been dumped above).
    #[cfg(feature = "rt-log")]
    efi::rtlog::init();

    // Cache boot manager variables EARLY, before platform hooks or driver
    // binding can modify them (matches edk2 BdsEntry behavior).
    let boot_var_state = boot_vars::read_boot_var_state();

    // Initialize storage subsystem and run boot manager
    boot_manager::run(boot_var_state);

    log::info!("Press Ctrl+A X to exit QEMU");

    // Halt and wait
    loop {
        arch::halt();
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
