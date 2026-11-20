//! Early serial and framebuffer logging, before EFI or the heap is available.

use crate::{memory, tables};

pub(crate) fn init_serial(cb_info: &tables::CorebootInfo) {
    if let Some(ref serial) = cb_info.serial {
        crabefi::drivers::serial::init_from_config(&crabefi::drivers::serial::SerialConfig {
            mmio: serial.mmio(),
            baseaddr: serial.baseaddr as u64,
            baud: serial.baud,
            regwidth: serial.regwidth,
            input_hertz: serial.input_hertz,
        });
    }
}

pub(crate) fn start(
    cb_info: &tables::CorebootInfo,
    framebuffer: Option<crabefi::FramebufferConfig>,
    coreboot_table_ptr: u64,
) {
    // Initialize logging (idempotent — init_platform() will call it again).
    crabefi::logger::init();
    #[cfg(not(feature = "native-only"))]
    apply_early_log_level(cb_info);

    if let Some(fb) = framebuffer {
        crabefi::logger::set_framebuffer(fb);
    } else if let Some(raw) = cb_info.framebuffer.map(crabefi::FramebufferConfig::from) {
        log::warn!(
            "Ignoring malformed framebuffer descriptor (addr={:#x}, size={} bytes)",
            raw.physical_address,
            raw.size()
        );
    }

    log::info!("CrabEFI v{} starting...", env!("CARGO_PKG_VERSION"));
    log::info!("Coreboot table pointer: {:#x}", coreboot_table_ptr);

    // Log parsed coreboot tables
    log_coreboot_info(cb_info);
}

/// Apply CrabEFI's persisted log level before normal platform initialization.
///
/// Keep this path read-only and silent: at this point the heap, SPI drivers, and
/// full EFI variable services are not initialized yet. Coreboot-specific code is
/// limited to discovering the memory-mapped SMMSTORE region; parsing the EDK2
/// variable-store format is handled by the generic CrabEFI logger helper.
#[cfg(not(feature = "native-only"))]
fn apply_early_log_level(cb_info: &tables::CorebootInfo) {
    let Some(smmstore) = cb_info.smmstorev2 else {
        return;
    };

    let Some(size) = smmstore
        .num_blocks
        .checked_mul(smmstore.block_size)
        .map(usize::try_from)
        .and_then(Result::ok)
    else {
        return;
    };

    if size == 0 || smmstore.mmap_addr == 0 {
        return;
    }

    // SAFETY: coreboot reports SMMSTORE as a memory-mapped region. We only read
    // the bounded region while still in identity-mapped physical mode.
    let region = unsafe { core::slice::from_raw_parts(smmstore.mmap_addr as *const u8, size) };
    let _ = crabefi::logger::apply_from_edk2_varstore_region(region);
}

fn log_coreboot_info(cb_info: &tables::CorebootInfo) {
    log::info!("Parsed coreboot tables:");
    if let Some(ref serial) = cb_info.serial {
        let type_str = if serial.mmio() { "MMIO" } else { "I/O" };
        log::info!(
            "  Serial: type={}, base={:#x}, baud={}, regwidth={}",
            type_str,
            serial.baseaddr,
            serial.baud,
            serial.regwidth
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
    if let Some(timestamps) = cb_info.timestamps {
        log::info!("  Timestamp table: {:#x}", timestamps);
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
    if let Some((fdt_addr, fdt_size)) = cb_info.devicetree {
        log::info!("  Devicetree: {:#x} ({} bytes)", fdt_addr, fdt_size);
    }

    // Print memory map summary
    let total_ram: u64 = cb_info
        .memory_map
        .iter()
        .filter(|r| r.region_type == memory::MemoryType::Ram)
        .map(|r| r.size)
        .sum();
    log::info!("  Total RAM: {} MB", total_ram / (1024 * 1024));
}
