//! CrabEFI Coreboot Payload
//!
//! This binary builds CrabEFI as a coreboot payload for x86_64 and aarch64.
//! It handles architecture-specific entry (32→64 mode switch on x86, MMU setup
//! on aarch64), parses coreboot tables to discover hardware, runs ACPI
//! discovery, builds a [`crabefi::PlatformConfig`], and hands off to the
//! CrabEFI library.

#![no_std]
#![no_main]
#![allow(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod acpi;

use core::panic::PanicInfo;

// ============================================================================
// Memory map size limit (matches state::MAX_MEMORY_REGIONS + MMIO headroom)
// ============================================================================

/// Maximum number of platform memory regions we can pass to init_platform().
const MAX_MEMORY_REGIONS: usize = 96;

// ============================================================================
// Statics for passing data into the post_heap_init callback
// ============================================================================

/// Raw CFR data pointer from coreboot tables (needs heap to parse).
static mut CFR_RAW_PTR: Option<&'static [u8]> = None;

// ============================================================================
// Platform trait implementations
// ============================================================================

/// Timer backed by the architecture's monotonic counter.
///
/// On x86_64 this wraps the TSC (calibrated via ACPI PM timer before
/// `init_platform()` is called). On aarch64 this reads the ARM Generic
/// Timer directly.
struct CorebootTimer {
    freq_hz: u64,
}

impl crabefi::Timer for CorebootTimer {
    fn current_ticks(&self) -> u64 {
        crabefi::time::read_counter()
    }

    fn ticks_per_second(&self) -> u64 {
        self.freq_hz
    }
}

/// Reset handler using architecture-specific reset mechanisms.
struct CorebootReset;

impl crabefi::ResetHandler for CorebootReset {
    fn reset(&self, reset_type: crabefi::ResetType) -> ! {
        #[cfg(target_arch = "x86_64")]
        {
            // Try keyboard controller reset, then triple fault as fallback.
            let _ = reset_type;
            crabefi::arch::x86_64::reset::keyboard_controller_reset();
            crabefi::time::delay_ms(100);
            crabefi::arch::x86_64::reset::triple_fault()
        }
        #[cfg(target_arch = "aarch64")]
        {
            match reset_type {
                crabefi::ResetType::Shutdown => crabefi::arch::aarch64::reset::system_off(),
                _ => crabefi::arch::aarch64::reset::system_reset(),
            }
        }
    }
}

// ============================================================================
// Post-heap initialization callback
// ============================================================================

/// Runs after `init_platform()` has initialized the EFI memory allocator and
/// heap. Performs heap-dependent discovery that the coreboot payload needs:
///
/// 1. ACPI table discovery (MADT, MCFG, SPCR, DSDT via AML interpreter)
/// 2. Platform MMIO region registration (aarch64)
/// 3. CFR (Coreboot Form Representation) parsing
fn coreboot_post_heap_init() {
    // ---- 1. ACPI platform discovery ----
    //
    // The AML interpreter allocates, so this must run after heap::init().
    // Results go into state.drivers.acpi_info which init_platform() reads
    // for ECAM base and add_platform_mmio_regions() reads for MMIO.
    if let Some(rsdp) = crabefi::state::drivers().platform.acpi_rsdp {
        let acpi_info = unsafe { acpi::discover_platform(rsdp) };
        crabefi::state::with_drivers_mut(|d| d.acpi_info = acpi_info);
    }

    // ---- 2. Platform MMIO regions (aarch64) ----
    //
    // Coreboot's lb_memory table omits MMIO regions. Add them from the
    // ACPI/FDT info we just discovered.
    #[cfg(target_arch = "aarch64")]
    crabefi::efi::add_platform_mmio_regions();

    // ---- 3. CFR parsing ----
    //
    // Parse coreboot firmware configuration options now that the heap is
    // available. The raw data pointer was saved during table parsing.
    //
    // SAFETY: single-threaded firmware; CFR_RAW_PTR set once in rust_main().
    if let Some(cfr_raw) = unsafe { CFR_RAW_PTR }
        && let Some(cfr) = crabefi::coreboot::cfr::parse_cfr(cfr_raw)
    {
        log::info!(
            "CFR: {} forms, {} options",
            cfr.forms.len(),
            cfr.total_options()
        );
        crabefi::coreboot::store_cfr(cfr);
    }
}

// ============================================================================
// Memory map conversion
// ============================================================================

/// Convert coreboot memory regions to platform format.
fn convert_memory_map(
    cb_map: &[crabefi::coreboot::MemoryRegion],
    out: &mut [crabefi::MemoryRegion; MAX_MEMORY_REGIONS],
) -> usize {
    let mut count = 0;
    for region in cb_map {
        if count >= MAX_MEMORY_REGIONS {
            break;
        }
        let region_type = match region.region_type {
            crabefi::coreboot::MemoryType::Ram => crabefi::MemoryType::Ram,
            crabefi::coreboot::MemoryType::Reserved => crabefi::MemoryType::Reserved,
            crabefi::coreboot::MemoryType::AcpiReclaimable => crabefi::MemoryType::AcpiReclaimable,
            crabefi::coreboot::MemoryType::AcpiNvs => crabefi::MemoryType::AcpiNvs,
            // Unusable, Table, and any future variants map to Reserved
            _ => crabefi::MemoryType::Reserved,
        };
        out[count] = crabefi::MemoryRegion {
            base: region.start,
            size: region.size,
            region_type,
        };
        count += 1;
    }
    count
}

// ============================================================================
// Panic handler
// ============================================================================

/// Global panic handler for the coreboot payload.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
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

    loop {
        crabefi::arch::halt();
    }
}

// ============================================================================
// Entry point
// ============================================================================

/// Rust entry point called from architecture-specific assembly after
/// 64-bit mode transition (x86) or MMU setup (aarch64).
///
/// # Arguments
///
/// * `coreboot_table_ptr` - Physical pointer to the coreboot tables
///   (passed in RDI on x86_64, X0 on aarch64).
#[unsafe(no_mangle)]
pub extern "C" fn rust_main(coreboot_table_ptr: u64) -> ! {
    // ================================================================
    // Phase 1: Initialize firmware state (needed for all state access)
    // ================================================================
    let mut firmware_state = crabefi::state::FirmwareState::new();
    // SAFETY: Single-threaded firmware entry point. The state lives on
    // this stack frame which never returns (-> !).
    unsafe {
        crabefi::state::init(&mut firmware_state);
    }

    // ================================================================
    // Phase 2: Parse coreboot tables (reads raw memory, no heap needed)
    // ================================================================
    // SAFETY: coreboot_table_ptr is passed from coreboot and points to
    // valid tables in identity-mapped physical memory.
    let cb_info = unsafe { crabefi::coreboot::tables::parse(coreboot_table_ptr as *const u8) };

    // ================================================================
    // Phase 3: Store coreboot-specific info in global state
    // ================================================================
    //
    // These fields are used by the SPI variable persistence subsystem
    // (efi::varstore::persistence.rs) and must be set before
    // init_platform() runs init_persistence_and_boot().

    if let Some(cbmem_addr) = cb_info.cbmem_console {
        crabefi::coreboot::cbmem_console::init(cbmem_addr);
    }

    if let Some(fb) = cb_info.framebuffer {
        crabefi::state::store_framebuffer(crabefi::FramebufferConfig::from(fb));
    }

    if let Some(addr) = cb_info.framebuffer_record_addr {
        crabefi::coreboot::store_framebuffer_record_addr(addr);
    }

    if let Some(smmstore) = cb_info.smmstorev2 {
        crabefi::coreboot::store_smmstorev2(smmstore);
    }

    if let Some(ref spi_flash) = cb_info.spi_flash {
        crabefi::coreboot::store_spi_flash(spi_flash.clone());
    }

    if let Some(boot_media) = cb_info.boot_media {
        crabefi::coreboot::store_boot_media(boot_media);
    }

    // Store memory regions and ACPI RSDP (used by direct Linux boot path
    // and by the post_heap_init callback for ACPI discovery).
    crabefi::state::with_drivers_mut(|drivers| {
        for region in cb_info.memory_map.iter() {
            let _ = drivers.platform.memory_regions.push(*region);
        }
        drivers.platform.acpi_rsdp = cb_info.acpi_rsdp;
    });

    // Save CFR raw data pointer for the post-heap callback.
    // SAFETY: single-threaded firmware; pointer valid for firmware lifetime.
    if let Some(cfr_raw) = cb_info.cfr_raw {
        unsafe {
            CFR_RAW_PTR = Some(cfr_raw);
        }
    }

    // ================================================================
    // Phase 4: Initialize serial and logging
    // ================================================================
    if let Some(ref serial) = cb_info.serial {
        crabefi::drivers::serial::init_from_coreboot(serial.baseaddr, serial.baud, serial.mmio());
    }

    // Initialize logging (idempotent — init_platform() will call it again).
    crabefi::logger::init();

    if let Some(fb) = cb_info.framebuffer {
        crabefi::logger::set_framebuffer(crabefi::FramebufferConfig::from(fb));
    }

    log::info!("CrabEFI v{} starting...", env!("CARGO_PKG_VERSION"));
    log::info!("Coreboot table pointer: {:#x}", coreboot_table_ptr);

    // Log parsed coreboot tables
    log_coreboot_info(&cb_info);

    // ================================================================
    // Phase 5: Calibrate timer (needs serial for logging)
    // ================================================================
    crabefi::time::init(cb_info.acpi_rsdp);

    // ================================================================
    // Phase 6: Build PlatformConfig and hand off to the library
    // ================================================================

    // Convert coreboot memory map to platform format.
    let mut memory_regions = [crabefi::MemoryRegion {
        base: 0,
        size: 0,
        region_type: crabefi::MemoryType::Reserved,
    }; MAX_MEMORY_REGIONS];
    let region_count = convert_memory_map(&cb_info.memory_map, &mut memory_regions);

    // Create timer backed by the calibrated arch counter.
    let timer = CorebootTimer {
        freq_hz: crabefi::state::drivers().timing.counter_freq_hz,
    };

    let reset = CorebootReset;

    // Extract FDT bytes slice (if coreboot provided a devicetree).
    let fdt_slice: Option<&[u8]> = cb_info.devicetree.map(|(addr, size)| {
        // SAFETY: coreboot's devicetree pointer and size are valid.
        unsafe { core::slice::from_raw_parts(addr as *const u8, size as usize) }
    });

    let config = crabefi::PlatformConfig {
        memory_map: &memory_regions[..region_count],
        timer: &timer,
        reset: &reset,
        block_devices: &mut [],
        variable_backend: None,
        debug_output: None, // Already set up via init_from_coreboot()
        console_input: None,
        framebuffer: cb_info.framebuffer.map(crabefi::FramebufferConfig::from),
        acpi_rsdp: cb_info.acpi_rsdp,
        smbios: cb_info.smbios,
        fdt: fdt_slice,
        rng: None,
        ecam_base: None,       // Discovered by post_heap_init callback via ACPI MCFG
        deferred_buffer: None, // Uses linker-symbol fallback in init_platform()
        runtime_region: None,  // Uses linker-symbol fallback (platform-entry feature)
        post_heap_init: Some(coreboot_post_heap_init),
    };

    // This never returns — the boot manager takes over.
    crabefi::init_platform(config)
}

// ============================================================================
// Logging helpers
// ============================================================================

fn log_coreboot_info(cb_info: &crabefi::coreboot::CorebootInfo) {
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
    if let Some((fdt_addr, fdt_size)) = cb_info.devicetree {
        log::info!("  Devicetree: {:#x} ({} bytes)", fdt_addr, fdt_size);
    }

    // Print memory map summary
    let total_ram: u64 = cb_info
        .memory_map
        .iter()
        .filter(|r| r.region_type == crabefi::coreboot::MemoryType::Ram)
        .map(|r| r.size)
        .sum();
    log::info!("  Total RAM: {} MB", total_ram / (1024 * 1024));
}
