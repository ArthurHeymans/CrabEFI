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

    // At this point, we would:
    // 1. Look for ESP (EFI System Partition) on storage devices
    // 2. Read /EFI/BOOT/BOOTX64.EFI from the ESP
    // 3. Load and execute it using pe::load_image() and pe::execute_image()
    //
    // For now, we just wait since we don't have storage drivers yet (Phase 3)

    log::info!("Waiting for storage drivers (Phase 3) to load boot applications...");
    log::info!("Press Ctrl+A X to exit QEMU");

    // Halt and wait
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
