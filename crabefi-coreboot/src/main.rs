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

// Host-side workspace linting checks this no_std/no_main final binary without
// linking a bare-metal target. Keep that check allocator local to the payload
// so std test harnesses never inherit CrabEFI's uninitialized firmware heap.
#[cfg(not(target_os = "none"))]
#[global_allocator]
static HOST_CHECK_ALLOCATOR: linked_list_allocator::LockedHeap =
    linked_list_allocator::LockedHeap::empty();

#[cfg(not(target_arch = "riscv64"))]
mod acpi;
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64/entry.rs"]
mod arch_entry;
#[cfg(target_arch = "riscv64")]
#[path = "arch/riscv64/entry.rs"]
mod arch_entry;
#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/entry.rs"]
mod arch_entry;
mod cbmem_console;
mod cfr;
mod cfr_menu;
mod fmap;
mod framebuffer;
mod memory;
#[cfg(feature = "external-runtime-image")]
mod runtime_blob;
mod tables;
#[cfg(target_arch = "x86_64")]
mod timestamps;

use core::panic::PanicInfo;
#[cfg(target_arch = "riscv64")]
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ============================================================================
// Memory map size limit (matches state::MAX_MEMORY_REGIONS + MMIO headroom)
// ============================================================================

/// Maximum number of platform memory regions we can pass to init_platform().
const MAX_MEMORY_REGIONS: usize = 96;

fn runtime_image_source() -> crabefi::RuntimeImageSource<'static> {
    #[cfg(feature = "bundled-runtime-image")]
    {
        crabefi::BUNDLED_RUNTIME_IMAGE
    }

    #[cfg(feature = "external-runtime-image")]
    {
        crabefi::RuntimeImageSource {
            bytes: runtime_blob::RUNTIME_IMAGE,
            expected_sha256: runtime_blob::RUNTIME_IMAGE_SHA256,
        }
    }
}

fn runtime_platform_config() -> crabefi::RuntimePlatformConfig<'static> {
    unsafe extern "C" {
        static _deferred_buffer_start: u8;
        static _deferred_buffer_end: u8;
    }

    let deferred_buffer = {
        let start = core::ptr::addr_of!(_deferred_buffer_start) as usize;
        let end = core::ptr::addr_of!(_deferred_buffer_end) as usize;
        let size = end
            .checked_sub(start)
            .expect("deferred-buffer linker symbols are reversed");
        assert!(
            start.is_multiple_of(4096) && size != 0 && size.is_multiple_of(4096),
            "deferred-buffer linker range must be nonzero and page aligned"
        );
        crabefi::DeferredBufferConfig {
            base: start as u64,
            size,
        }
    };

    #[cfg(target_arch = "x86_64")]
    let (time, reset) = (
        crabefi::RuntimeTimeConfig {
            mechanism: crabefi::time_mechanism::X86_CMOS,
            reserved: 0,
            io_or_mmio_base: 0,
        },
        crabefi::RuntimeResetConfig {
            mechanism: crabefi::reset_mechanism::X86_LEGACY,
            reserved: 0,
            io_or_mmio_base: 0xcf9,
        },
    );
    #[cfg(target_arch = "aarch64")]
    let (time, reset) = (
        crabefi::RuntimeTimeConfig {
            mechanism: crabefi::time_mechanism::UNSUPPORTED,
            reserved: 0,
            io_or_mmio_base: 0,
        },
        crabefi::RuntimeResetConfig {
            mechanism: crabefi::reset_mechanism::PSCI_SMC,
            reserved: 0,
            io_or_mmio_base: 0,
        },
    );
    #[cfg(target_arch = "riscv64")]
    let (time, reset) = (
        crabefi::RuntimeTimeConfig {
            mechanism: crabefi::time_mechanism::UNSUPPORTED,
            reserved: 0,
            io_or_mmio_base: 0,
        },
        crabefi::RuntimeResetConfig {
            mechanism: crabefi::reset_mechanism::SBI_SRST,
            reserved: 0,
            io_or_mmio_base: 0,
        },
    );
    crabefi::RuntimePlatformConfig {
        time,
        reset,
        external_ranges: &[],
        deferred_buffer,
    }
}

// ============================================================================
// Platform trait implementations
// ============================================================================

/// Timer backed by the architecture's monotonic counter.
///
/// On x86_64 this wraps the TSC (calibrated via ACPI PM timer before
/// `init_platform()` is called). On aarch64 this reads the ARM Generic
/// Timer directly. On riscv64 this reads the `rdtime` counter.
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

/// Coreboot-specific lifecycle callbacks injected into the generic core.
struct CorebootHooks;

impl crabefi::PlatformHooks for CorebootHooks {
    fn on_exit_boot_services(&self) {
        // Invalidate the coreboot framebuffer record to prevent a race between
        // Linux simplefb (coreboot) and efifb (EFI GOP).
        unsafe {
            framebuffer::invalidate_framebuffer_record();
        }

        // CBMEM console is not runtime mapped; disable it before runtime use.
        cbmem_console::disable();
    }

    fn firmware_settings_available(&self) -> bool {
        true
    }

    fn show_firmware_settings(&self) -> bool {
        cfr_menu::show_cfr_menu();
        true
    }
}

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
        #[cfg(target_arch = "riscv64")]
        {
            match reset_type {
                crabefi::ResetType::Shutdown => crabefi::arch::riscv64::reset::system_off(),
                _ => crabefi::arch::riscv64::reset::system_reset(),
            }
        }
    }
}

/// Coreboot-backed locator for CrabEFI's persistent variable store.
///
/// Coreboot can describe the store either directly via SMMSTORE v2 tables, or
/// indirectly via an FMAP region on the boot medium. Both mechanisms are
/// coreboot-specific, so they live in the coreboot payload instead of the
/// platform-agnostic CrabEFI persistence path.
struct CorebootVariableStoreLocator {
    smmstorev2: Option<tables::Smmstorev2Info>,
    boot_media: Option<tables::BootMediaInfo>,
    spi_flash: Option<tables::SpiFlashInfo>,
}

impl CorebootVariableStoreLocator {
    fn new(cb_info: &tables::CorebootInfo) -> Self {
        Self {
            smmstorev2: cb_info.smmstorev2,
            boot_media: cb_info.boot_media,
            spi_flash: cb_info.spi_flash.clone(),
        }
    }

    fn resolve_mapped_region(
        &self,
        phys_base: u64,
        size: u64,
    ) -> Option<crabefi::FirmwareStorageRegion> {
        if size == 0 {
            return None;
        }

        if let Some(spi_flash) = self.spi_flash.as_ref() {
            if let Some(region) = spi_flash.mmap_windows.iter().find_map(|window| {
                let window_phys = window.host_base as u64;
                let relative = phys_base.checked_sub(window_phys)?;
                let mapped_end = relative.checked_add(size)?;
                if mapped_end > window.size as u64 {
                    return None;
                }

                let offset = (window.flash_base as u64).checked_add(relative)?;
                let end = offset.checked_add(size)?;
                if end > spi_flash.flash_size as u64 {
                    return None;
                }

                Some(crabefi::FirmwareStorageRegion { offset, size })
            }) {
                return Some(region);
            }

            if let Some(region) =
                Self::resolve_top_of_4g_mapping(phys_base, size, spi_flash.flash_size as u64)
            {
                return Some(region);
            }
        }

        self.boot_media.and_then(|boot_media| {
            Self::resolve_top_of_4g_mapping(phys_base, size, boot_media.boot_media_size)
        })
    }

    fn resolve_top_of_4g_mapping(
        phys_base: u64,
        size: u64,
        flash_size: u64,
    ) -> Option<crabefi::FirmwareStorageRegion> {
        if flash_size == 0 {
            return None;
        }

        let mmap_base = 0x1_0000_0000u64.checked_sub(flash_size)?;
        let relative = phys_base.checked_sub(mmap_base)?;
        let end = relative.checked_add(size)?;
        if end > flash_size {
            return None;
        }

        Some(crabefi::FirmwareStorageRegion {
            offset: relative,
            size,
        })
    }
}

impl crabefi::VariableStoreLocator for CorebootVariableStoreLocator {
    fn locate_variable_store(
        &self,
        storage: &mut dyn crabefi::FirmwareStorage,
    ) -> Option<crabefi::VariableStoreRegion> {
        if let Some(smmstore) = self.smmstorev2 {
            log::info!(
                "Found SMMSTORE v2 in coreboot tables: {} blocks x {} KB at {:#x}",
                smmstore.num_blocks,
                smmstore.block_size / 1024,
                smmstore.mmap_addr
            );

            if let Some(size) = smmstore
                .num_blocks
                .checked_mul(smmstore.block_size)
                .map(u64::from)
                && size != 0
                && smmstore.mmap_addr != 0
                && let Some(region) = self.resolve_mapped_region(smmstore.mmap_addr, size)
            {
                return Some(crabefi::VariableStoreRegion::from_offset_with_mapped_read(
                    "SMMSTORE",
                    region.offset,
                    smmstore.mmap_addr,
                    region.size,
                ));
            }

            log::warn!(
                "Ignoring unresolvable SMMSTORE v2 mapping: mmap_addr={:#x}, num_blocks={}, block_size={}",
                smmstore.mmap_addr,
                smmstore.num_blocks,
                smmstore.block_size
            );
        }

        let fmap_offset = self.boot_media.map(|boot_media| boot_media.fmap_offset);
        let region = fmap::get_smmstore_from_fmap(storage, fmap_offset)?;

        log::info!(
            "Found '{}' in FMAP: offset={:#x}, size={} KB",
            region.name.as_str(),
            region.offset,
            region.size / 1024
        );

        Some(crabefi::VariableStoreRegion::from_offset(
            region.name.as_str(),
            region.offset,
            region.size as u64,
        ))
    }
}

/// Coreboot SPI/FMAP implementation of the platform capsule backend.
struct CorebootCapsuleBackend {
    firmware_info: Option<crabefi::FirmwareInfo>,
    fmap_offset: Option<u64>,
    fmap_loaded: bool,
    fmap_regions: alloc::vec::Vec<crabefi::FmapRegion>,
}

impl CorebootCapsuleBackend {
    fn new(
        firmware_info: Option<crabefi::FirmwareInfo>,
        boot_media: Option<tables::BootMediaInfo>,
    ) -> Self {
        Self {
            firmware_info,
            fmap_offset: boot_media.map(|media| media.fmap_offset),
            fmap_loaded: false,
            fmap_regions: alloc::vec::Vec::new(),
        }
    }

    fn load_fmap(&mut self) {
        if self.fmap_loaded {
            return;
        }
        self.fmap_loaded = true;
        let parsed = crabefi::state::with_storage_mut(|storage| {
            fmap::read_fmap(storage.controller_mut(), self.fmap_offset)
        })
        .flatten();
        let Some(parsed) = parsed else {
            log::warn!("Capsule backend could not load FMAP");
            return;
        };
        for area in parsed.areas {
            self.fmap_regions.push(crabefi::FmapRegion {
                name: area.name,
                offset: area.offset,
                size: area.size,
            });
        }
    }
}

impl crabefi::CapsuleBackend for CorebootCapsuleBackend {
    fn firmware_info(&self) -> Option<&crabefi::FirmwareInfo> {
        self.firmware_info.as_ref()
    }

    fn capsule_trust_store(&self) -> &[&[u8]] {
        &[]
    }

    fn write_firmware_region(
        &mut self,
        region_name: &str,
        offset: u32,
        data: &[u8],
    ) -> Result<(), crabefi::StorageError> {
        self.load_fmap();
        let region = self
            .fmap_regions
            .iter()
            .find(|region| region.name.as_str() == region_name)
            .ok_or(crabefi::StorageError::InvalidArgument)?;
        let write_offset = region
            .offset
            .checked_add(offset)
            .ok_or(crabefi::StorageError::InvalidArgument)?;
        if offset as u64 + data.len() as u64 > u64::from(region.size) {
            return Err(crabefi::StorageError::InvalidArgument);
        }
        crabefi::state::with_storage_mut(|storage| {
            let controller = storage.controller_mut();
            crabefi::FirmwareStorage::enable_writes(controller)?;
            crabefi::FirmwareStorage::erase(
                controller,
                u64::from(region.offset),
                u64::from(region.size),
            )?;
            crabefi::FirmwareStorage::write(controller, u64::from(write_offset), data)
        })
        .ok_or(crabefi::StorageError::NotInitialized)?
    }

    fn fmap_regions(&mut self) -> &[crabefi::FmapRegion] {
        self.load_fmap();
        &self.fmap_regions
    }
}

// ============================================================================
// Memory map conversion
// ============================================================================

/// Convert one coreboot memory region to platform format.
fn convert_memory_region(region: &memory::MemoryRegion) -> crabefi::MemoryRegion {
    let region_type = match region.region_type {
        memory::MemoryType::Ram => crabefi::MemoryType::Ram,
        memory::MemoryType::Reserved => crabefi::MemoryType::Reserved,
        memory::MemoryType::AcpiReclaimable => crabefi::MemoryType::AcpiReclaimable,
        memory::MemoryType::AcpiNvs => crabefi::MemoryType::AcpiNvs,
        // Unusable, Table, and any future variants map to Reserved.
        _ => crabefi::MemoryType::Reserved,
    };
    crabefi::MemoryRegion {
        base: region.start,
        size: region.size,
        region_type,
    }
}

/// Convert coreboot memory regions to platform format.
fn convert_memory_map(
    cb_map: &[memory::MemoryRegion],
    out: &mut [crabefi::MemoryRegion; MAX_MEMORY_REGIONS],
) -> usize {
    let mut count = 0;
    for region in cb_map {
        if count >= MAX_MEMORY_REGIONS {
            break;
        }
        out[count] = convert_memory_region(region);
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
// RISC-V entry point
// ============================================================================

/// RISC-V entry point called from assembly after BSS zeroing / stack setup.
///
/// On RISC-V, coreboot + OpenSBI passes:
///   - a0 = hart ID
///   - a1 = pointer to FDT (Flattened Device Tree)
///
/// The FDT contains a `/chosen/coreboot-table` property with the physical
/// address of the coreboot information tables. We extract that, then
/// call the architecture-independent `rust_main()`.
#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
pub extern "C" fn riscv_main(hart_id: u64, fdt_ptr: u64) -> ! {
    // Early console: write directly to the QEMU virt 16550 UART so we
    // get output even before logging is initialized.
    crabefi::arch::riscv64::uart_direct_write(b"CrabEFI: RISC-V entry (S-mode)\r\n");

    // Parse the FDT header to get total size, then extract the coreboot
    // table pointer from /chosen/coreboot-table.
    let (coreboot_table_ptr, fdt_size) = extract_coreboot_table_from_fdt(fdt_ptr);

    // Save hart ID and FDT pointer for later use by protocol/timer code.
    RISCV_BOOT_HARTID.store(hart_id, Ordering::Relaxed);
    // Also publish to the library so riscv_get_boot_hartid returns the real value.
    crabefi::efi::set_boot_hartid(hart_id);

    if coreboot_table_ptr != 0 {
        // We have coreboot tables — use the standard path.
        // Store FDT pointer so rust_main can use it for timer freq later.
        RISCV_FDT_PTR.store(fdt_ptr, Ordering::Relaxed);
        RISCV_FDT_SIZE.store(fdt_size, Ordering::Relaxed);
        rust_main(coreboot_table_ptr)
    } else {
        // No coreboot table pointer in FDT — run in FDT-only mode.
        riscv_fdt_only_boot(fdt_ptr, fdt_size)
    }
}

/// Boot hart ID saved at entry (from OpenSBI a0 register).
#[cfg(target_arch = "riscv64")]
static RISCV_BOOT_HARTID: AtomicU64 = AtomicU64::new(0);
/// Saved FDT pointer from RISC-V entry (used after state init).
#[cfg(target_arch = "riscv64")]
static RISCV_FDT_PTR: AtomicU64 = AtomicU64::new(0);
/// Saved FDT size from RISC-V entry.
#[cfg(target_arch = "riscv64")]
static RISCV_FDT_SIZE: AtomicU32 = AtomicU32::new(0);

/// Extract the coreboot table pointer and FDT size from an FDT blob.
#[cfg(target_arch = "riscv64")]
fn extract_coreboot_table_from_fdt(fdt_ptr: u64) -> (u64, u32) {
    if fdt_ptr == 0 {
        return (0, 0);
    }

    // Read the FDT total size from the header (offset 4, big-endian u32).
    // SAFETY: The FDT pointer comes from OpenSBI/coreboot and is valid.
    let fdt_size = unsafe {
        let header = fdt_ptr as *const u8;
        u32::from_be_bytes([
            *header.add(4),
            *header.add(5),
            *header.add(6),
            *header.add(7),
        ])
    };

    if fdt_size < 40 {
        return (0, fdt_size);
    }

    let fdt_blob = unsafe { core::slice::from_raw_parts(fdt_ptr as *const u8, fdt_size as usize) };

    let coreboot_table_ptr = if let Ok(dt) = fdt::Fdt::new(fdt_blob) {
        dt.find_node("/chosen")
            .and_then(|n| n.property("coreboot-table"))
            .and_then(|p| {
                let v = p.value;
                if v.len() >= 8 {
                    Some(u64::from_be_bytes([
                        v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
                    ]))
                } else if v.len() >= 4 {
                    // 32-bit property value
                    Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]) as u64)
                } else {
                    None
                }
            })
            .unwrap_or(0)
    } else {
        0
    };

    (coreboot_table_ptr, fdt_size)
}

/// Extract the timer frequency from the FDT and store it in driver state.
///
/// The RISC-V timer frequency is in `/cpus/timebase-frequency`.
#[cfg(target_arch = "riscv64")]
fn extract_timer_freq_from_fdt(fdt_ptr: u64, fdt_size: u32) {
    if fdt_ptr == 0 || fdt_size < 40 {
        return;
    }

    let fdt_blob = unsafe { core::slice::from_raw_parts(fdt_ptr as *const u8, fdt_size as usize) };

    if let Ok(dt) = fdt::Fdt::new(fdt_blob)
        && let Some(cpus) = dt.find_node("/cpus")
        && let Some(prop) = cpus.property("timebase-frequency")
    {
        let v = prop.value;
        let freq = if v.len() >= 8 {
            u64::from_be_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]])
        } else if v.len() >= 4 {
            u32::from_be_bytes([v[0], v[1], v[2], v[3]]) as u64
        } else {
            0
        };

        if freq > 0 {
            // SAFETY: single-threaded init, state already initialized
            unsafe {
                let t = &mut (*crabefi::state::drivers_mut_ptr()).timing;
                t.counter_freq_hz = freq;
                t.counter_cycles_per_us = (freq / 1_000_000).max(1);
            }
        }
    }
}

/// FDT-only boot path for RISC-V when coreboot tables are not available.
///
/// This builds a minimal `PlatformConfig` from FDT data and boots.
#[cfg(target_arch = "riscv64")]
fn riscv_fdt_only_boot(fdt_ptr: u64, fdt_size: u32) -> ! {
    // Initialize firmware state
    let mut firmware_state = crabefi::state::FirmwareState::new();
    unsafe {
        crabefi::state::init(&mut firmware_state);
    }

    // Initialize serial from MMIO (QEMU virt 16550 at 0x10000000)
    crabefi::drivers::serial::init_from_config(&crabefi::drivers::serial::SerialConfig {
        mmio: true,
        baseaddr: 0x1000_0000,
        baud: 115200,
        regwidth: 1,
        input_hertz: 0,
    });
    crabefi::logger::init();

    log::info!(
        "CrabEFI v{} starting (RISC-V FDT-only mode)...",
        env!("CARGO_PKG_VERSION")
    );
    log::info!(
        "FDT at {:#x} ({} bytes), no coreboot tables found",
        fdt_ptr,
        fdt_size
    );

    // Initialize timing — use 10 MHz default first, then override with the
    // actual frequency from the FDT /cpus/timebase-frequency property.
    crabefi::time::init(None);
    extract_timer_freq_from_fdt(fdt_ptr, fdt_size);

    // Build a minimal memory map from FDT
    // QEMU virt: DRAM at 0x80000000, size from FDT /memory node
    let mut memory_regions = [crabefi::MemoryRegion {
        base: 0,
        size: 0,
        region_type: crabefi::MemoryType::Reserved,
    }; MAX_MEMORY_REGIONS];

    let region_count = build_memory_map_from_fdt(fdt_ptr, fdt_size, &mut memory_regions);

    let timer = CorebootTimer {
        freq_hz: crabefi::state::drivers().timing.counter_freq_hz,
    };
    let reset = CorebootReset;
    let hooks = CorebootHooks;

    let fdt_slice = unsafe { core::slice::from_raw_parts(fdt_ptr as *const u8, fdt_size as usize) };

    let config = crabefi::PlatformConfig {
        memory_map: &memory_regions[..region_count],
        timer: &timer,
        timestamp_recorder: None,
        reset: &reset,
        block_devices: &mut [],
        variable_store_locator: None,
        debug_output: None,
        console_input: None,
        framebuffer: None,
        acpi_rsdp: None,
        smbios: None,
        fdt: Some(fdt_slice),
        firmware_info: None,
        capsule_regions: &[],
        capsule_backend: None,
        hooks: Some(&hooks),
        rng: None,
        ecam_base: None,
        ecam_size: None,
        runtime_image: runtime_image_source(),
        runtime: runtime_platform_config(),
        tpm_event_log: None,
        heap_pre_initialized: false,
    };

    crabefi::init_platform(config)
}

/// Build a memory map from FDT /memory nodes.
#[cfg(target_arch = "riscv64")]
fn build_memory_map_from_fdt(
    fdt_ptr: u64,
    fdt_size: u32,
    out: &mut [crabefi::MemoryRegion; MAX_MEMORY_REGIONS],
) -> usize {
    let mut count = 0;
    if fdt_ptr == 0 || fdt_size < 40 {
        return count;
    }

    let fdt_blob = unsafe { core::slice::from_raw_parts(fdt_ptr as *const u8, fdt_size as usize) };
    if let Ok(dt) = fdt::Fdt::new(fdt_blob) {
        // Find /memory nodes
        for node in dt.all_nodes() {
            let is_memory = node
                .compatible()
                .is_some_and(|c| c.all().any(|s| s == "memory"))
                || node.name.starts_with("memory");

            if is_memory && let Some(regs) = node.reg() {
                for reg in regs {
                    if count >= MAX_MEMORY_REGIONS {
                        break;
                    }
                    let base = reg.starting_address as u64;
                    let size = reg.size.unwrap_or(0) as u64;
                    if size > 0 {
                        out[count] = crabefi::MemoryRegion {
                            base,
                            size,
                            region_type: crabefi::MemoryType::Ram,
                        };
                        count += 1;
                    }
                }
            }
        }
    }

    // If no memory found, use QEMU virt default: 128MB at 0x80000000
    if count == 0 {
        out[0] = crabefi::MemoryRegion {
            base: 0x8000_0000,
            size: 128 * 1024 * 1024,
            region_type: crabefi::MemoryType::Ram,
        };
        count = 1;
    }

    count
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
    #[cfg(target_arch = "x86_64")]
    let entry_counter = crabefi::time::read_counter();

    let mut cbmem_output = cbmem_console::CbmemConsole::new();

    // ================================================================
    // Phase 1: Initialize firmware state (needed for all state access)
    // ================================================================
    let mut firmware_state = crabefi::state::FirmwareState::new();
    // SAFETY: Single-threaded firmware entry point. The state lives on
    // this stack frame which never returns (-> !).
    unsafe {
        crabefi::state::init(&mut firmware_state);
    }

    // On RISC-V, extract timer frequency from FDT now that state is initialized.
    #[cfg(target_arch = "riscv64")]
    {
        let fdt_ptr = RISCV_FDT_PTR.load(Ordering::Relaxed);
        let fdt_size = RISCV_FDT_SIZE.load(Ordering::Relaxed);
        if fdt_ptr != 0 && fdt_size >= 40 {
            extract_timer_freq_from_fdt(fdt_ptr, fdt_size);
        }
    }

    // ================================================================
    // Phase 2: Parse coreboot tables (reads raw memory, no heap needed)
    // ================================================================
    // SAFETY: The parser first tries the payload entry argument and falls back
    // to scanning the standard coreboot table locations if it is not valid.
    let cb_info = unsafe { tables::parse(coreboot_table_ptr as *const u8) };

    // ================================================================
    // Phase 3: Store coreboot-specific info in global state
    // ================================================================
    //
    // These fields are used by the SPI variable persistence subsystem
    // (efi::varstore::persistence.rs) and must be set before
    // init_platform() runs init_persistence_and_boot().

    let cbmem_console_available = cb_info.cbmem_console.is_some_and(cbmem_console::init);

    #[cfg(target_arch = "x86_64")]
    let timestamp_recorder = cb_info.timestamps.and_then(|table_addr| {
        let recorder = timestamps::CorebootTimestampRecorder::new(table_addr)?;
        recorder.record_counter(crabefi::timestamp::TS_CRABEFI_START, entry_counter);
        recorder.record_now(crabefi::timestamp::TS_CRABEFI_TABLES_PARSED);
        Some(recorder)
    });

    if let Some(fb) = cb_info.framebuffer {
        crabefi::state::store_framebuffer(crabefi::FramebufferConfig::from(fb));
    }

    if let Some(addr) = cb_info.framebuffer_record_addr {
        framebuffer::store_framebuffer_record_addr(addr);
    }

    if let Some(ref spi_flash) = cb_info.spi_flash
        && let Some(window) = spi_flash.mmap_windows.first()
    {
        crabefi::drivers::spi::qemu::configure_pflash(
            window.host_base as u64,
            spi_flash.flash_size,
        );
    } else if let Some(boot_media) = cb_info.boot_media
        && let Ok(flash_size) = u32::try_from(boot_media.boot_media_size)
        && let Some(host_base) = 0x1_0000_0000u64.checked_sub(boot_media.boot_media_size)
    {
        crabefi::drivers::spi::qemu::configure_pflash(host_base, flash_size);
    }

    // Store memory regions and ACPI RSDP (used by direct Linux boot path
    // and by ACPI discovery after heap init).
    crabefi::state::with_drivers_mut(|drivers| {
        for region in cb_info.memory_map.iter() {
            let _ = drivers
                .platform
                .memory_regions
                .push(convert_memory_region(region));
        }
        drivers.platform.acpi_rsdp = cb_info.acpi_rsdp;
    });

    // ================================================================
    // Phase 4: Initialize serial and logging
    // ================================================================
    if let Some(ref serial) = cb_info.serial {
        crabefi::drivers::serial::init_from_config(&crabefi::drivers::serial::SerialConfig {
            mmio: serial.mmio(),
            baseaddr: serial.baseaddr as u64,
            baud: serial.baud,
            regwidth: serial.regwidth,
            input_hertz: serial.input_hertz,
        });
    }

    if cbmem_console_available {
        let debug_output: &mut dyn crabefi::DebugOutput = &mut cbmem_output;
        // SAFETY: `rust_main()` never returns, so `cbmem_output` remains alive
        // for the entire firmware lifetime. The CBMEM module disables itself
        // before runtime when the physical-only buffer is no longer safe.
        let raw = unsafe {
            core::mem::transmute::<&mut dyn crabefi::DebugOutput, *mut dyn crabefi::DebugOutput>(
                debug_output,
            )
        };
        // SAFETY: `raw` points to `cbmem_output`, whose stack frame never
        // unwinds because this entry point is `-> !`.
        unsafe {
            crabefi::drivers::serial::add_platform_debug_sink_raw(raw);
        }
    }

    // Initialize logging (idempotent — init_platform() will call it again).
    crabefi::logger::init();
    apply_early_log_level(&cb_info);

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
    // Phase 6: Build PlatformConfig
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
    let hooks = CorebootHooks;
    let variable_store_locator = CorebootVariableStoreLocator::new(&cb_info);
    #[cfg(target_arch = "x86_64")]
    let timestamp_recorder_ref = timestamp_recorder
        .as_ref()
        .map(|recorder| recorder as &dyn crabefi::TimestampRecorder);
    #[cfg(not(target_arch = "x86_64"))]
    let timestamp_recorder_ref: Option<&dyn crabefi::TimestampRecorder> = None;

    // Extract FDT bytes slice.
    //
    // On RISC-V, use the FDT passed by OpenSBI (a1 register) rather than
    // the one from coreboot tables — the OpenSBI FDT contains the full
    // QEMU virt hardware description (UART, PLIC, PCI, memory, etc.)
    // which Linux needs to boot.
    #[cfg(target_arch = "riscv64")]
    let fdt_slice: Option<&[u8]> = {
        let fdt_ptr = RISCV_FDT_PTR.load(Ordering::Relaxed);
        let fdt_size = RISCV_FDT_SIZE.load(Ordering::Relaxed);
        if fdt_ptr != 0 && fdt_size >= 40 {
            Some(unsafe { core::slice::from_raw_parts(fdt_ptr as *const u8, fdt_size as usize) })
        } else {
            cb_info.devicetree.map(|(addr, size)| unsafe {
                core::slice::from_raw_parts(addr as *const u8, size as usize)
            })
        }
    };
    #[cfg(not(target_arch = "riscv64"))]
    let fdt_slice: Option<&[u8]> = cb_info.devicetree.map(|(addr, size)| {
        // SAFETY: coreboot's devicetree pointer and size are valid.
        unsafe { core::slice::from_raw_parts(addr as *const u8, size as usize) }
    });

    let firmware_info = cb_info.efi_fw_info.map(|fw_info| crabefi::FirmwareInfo {
        guid: fw_info.guid,
        version: fw_info.version,
        lowest_supported_version: fw_info.lowest_supported_version,
        fw_size: fw_info.fw_size,
    });

    let mut capsule_regions =
        [crabefi::CapsuleRegion { base: 0, size: 0 }; crabefi::state::MAX_CAPSULES];
    let mut capsule_count = 0;
    for capsule in cb_info.capsules.iter() {
        if capsule_count >= capsule_regions.len() {
            break;
        }
        capsule_regions[capsule_count] = crabefi::CapsuleRegion {
            base: capsule.base,
            size: capsule.size,
        };
        capsule_count += 1;
    }

    let mut capsule_backend = CorebootCapsuleBackend::new(firmware_info, cb_info.boot_media);

    let mut config = crabefi::PlatformConfig {
        memory_map: &memory_regions[..region_count],
        timer: &timer,
        timestamp_recorder: timestamp_recorder_ref,
        reset: &reset,
        block_devices: &mut [],
        variable_store_locator: Some(&variable_store_locator),
        debug_output: None, // Already set up via serial::init_from_config()
        console_input: None,
        framebuffer: cb_info.framebuffer.map(crabefi::FramebufferConfig::from),
        acpi_rsdp: cb_info.acpi_rsdp,
        smbios: cb_info.smbios,
        fdt: fdt_slice,
        firmware_info,
        capsule_regions: &capsule_regions[..capsule_count],
        capsule_backend: Some(&mut capsule_backend),
        hooks: Some(&hooks),
        rng: None,
        ecam_base: None, // May be filled from ACPI MCFG below
        ecam_size: None,
        runtime_image: runtime_image_source(),
        runtime: runtime_platform_config(),
        // Enable measured boot.
        // If coreboot provided a standard TPM event log in CBMEM, continue
        // using that log's protocol family. Without an existing standard log,
        // start fresh and install both TCG protocol families for compatibility.
        tpm_event_log: Some({
            let (existing_log, format) = match cb_info.tpm_log {
                Some(ref tpm_log) => match tpm_log.cbmem_id {
                    // TCG 2.0 crypto-agile log — continue with EFI_TCG2_PROTOCOL.
                    0x54504d32 => {
                        // SAFETY: coreboot's CBMEM region persists for the entire boot.
                        let log_data = unsafe {
                            core::slice::from_raw_parts(
                                tpm_log.address as *const u8,
                                tpm_log.size as usize,
                            )
                        };
                        (Some(log_data), crabefi::TpmLogFormat::CryptoAgile)
                    }
                    // TCG 1.2 SHA1-only log — continue with EFI_TCG_PROTOCOL.
                    0x54445041 => {
                        // SAFETY: coreboot's CBMEM region persists for the entire boot.
                        let log_data = unsafe {
                            core::slice::from_raw_parts(
                                tpm_log.address as *const u8,
                                tpm_log.size as usize,
                            )
                        };
                        (Some(log_data), crabefi::TpmLogFormat::Sha1Only)
                    }
                    // coreboot-specific format — start fresh (not directly
                    // compatible with either TCG log format).
                    _ => {
                        log::info!("Coreboot TPM log is in CB-specific format, starting fresh");
                        (None, crabefi::TpmLogFormat::Both)
                    }
                },
                None => (None, crabefi::TpmLogFormat::Both),
            };
            crabefi::TpmEventLogConfig {
                existing_log,
                format,
                // Hardware TPM transport is selected after ACPI namespace discovery.
                // Coreboot's TPM log record does not describe the transport.
                tpm2_device: crabefi::Tpm2DeviceConfig::None,
            }
        }),
        heap_pre_initialized: false, // Set to true after Phase 7
    };

    // ================================================================
    // Phase 7: Bootstrap page allocator and heap early
    //
    // We only need the page allocator (for heap::init) and the heap
    // (for ACPI AML / CFR parsing).  The full EFI environment (system
    // table, config tables, runtime reservations) is set up later by
    // init_platform() — its allocator init is idempotent so the second
    // call is a no-op.
    // ================================================================
    crabefi::efi::allocator::init_from_platform(config.memory_map);
    if !crabefi::heap::init() {
        log::error!("Failed to initialize heap allocator!");
    }
    config.heap_pre_initialized = true;

    // ================================================================
    // Phase 8: Post-heap platform discovery
    //
    // Now that the heap is available we can run ACPI AML interpretation,
    // register MMIO regions, and parse CFR options.
    // ================================================================

    // ---- ACPI platform discovery ----
    //
    // The AML interpreter allocates, so this must run after heap::init().
    // Results go into state.drivers.acpi_info which init_platform() reads
    // for ECAM base and add_platform_mmio_regions() reads for MMIO.
    // RISC-V platforms use FDT rather than ACPI, so skip this.
    #[cfg(not(target_arch = "riscv64"))]
    if let Some(rsdp) = crabefi::state::drivers().platform.acpi_rsdp {
        let acpi_info = unsafe { acpi::discover_platform(rsdp) };
        crabefi::state::with_drivers_mut(|d| d.acpi_info = acpi_info);

        #[cfg(target_arch = "x86_64")]
        if let Some(device) = ["MSFT0101", "PNP0C31"]
            .iter()
            .find_map(|hid| acpi_info.find_device(hid))
            && device.mmio_base <= 0xfed4_0000
            && device.mmio_base.saturating_add(device.mmio_size) > 0xfed4_0000
        {
            if let Some(ref mut tpm) = config.tpm_event_log {
                tpm.tpm2_device = crabefi::Tpm2DeviceConfig::TisMmio { base: 0xfed4_0000 };
            }
            log::info!("ACPI exposes an MMIO TIS TPM at 0xfed40000");
        } else {
            log::info!("No ACPI MMIO TIS TPM resource; skipping unsafe probe");
        }

        // PNP0D40 is generic SDHCI; only known AMD eMMC HIDs use this path.
        #[cfg(target_arch = "x86_64")]
        for hid in ["AMDI0040", "AMDI0041"] {
            let Some(dev) = acpi_info.find_device(hid) else {
                continue;
            };
            if crabefi::drivers::sdhci::init_mmio_device(
                dev,
                crabefi::drivers::sdhci::SdhciMedia::Emmc,
            )
            .is_ok()
            {
                break;
            }
        }
    }

    // ---- Platform MMIO regions (aarch64 / riscv64) ----
    //
    // Coreboot's lb_memory table omits MMIO regions. Add them from the
    // ACPI/FDT info we just discovered.
    #[cfg(target_arch = "aarch64")]
    crabefi::efi::add_platform_mmio_regions();

    // ---- RISC-V: parse FDT for ECAM + MMIO info, then register MMIO ----
    //
    // FDT parsing MUST happen before add_platform_mmio_regions() so the
    // FDT-derived PCIe MMIO windows are used instead of the SBSA defaults.
    // Without this, the SBSA fallback adds a bogus 1.75 GB MMIO region at
    // 0x80000000 that overlaps with DRAM and the CrabEFI runtime regions,
    // causing the Linux kernel to fail mapping RuntimeServicesData in efi_mm.
    #[cfg(target_arch = "riscv64")]
    {
        let mut ecam_found = false;
        if let Some(fdt_data) = fdt_slice
            && let Some(info) =
                unsafe { crabefi::fdt::parse(fdt_data.as_ptr() as u64, fdt_data.len() as u32) }
        {
            if let Some(ecam) = info.ecam_base {
                config.ecam_base = Some(ecam);
                config.ecam_size = info.ecam_size;
                log::info!("ECAM base from FDT: {:#x}", ecam);
                ecam_found = true;
            }
            // Store FDT info so add_platform_mmio_regions() can read it
            crabefi::state::with_drivers_mut(|d| d.fdt_info = info);
        }
        // Fallback: use coreboot's configured ECAM base for QEMU virt (0x30000000)
        if !ecam_found {
            config.ecam_base = Some(0x3000_0000);
            config.ecam_size = Some(0x1000_0000);
            log::info!("ECAM base from coreboot config: 0x30000000");
        }

        // Now that fdt_info is populated, register MMIO regions from FDT
        crabefi::efi::add_platform_mmio_regions();
    }

    // ---- CFR parsing ----
    //
    // Parse coreboot firmware configuration options now that the heap is
    // available. cb_info.cfr_raw is still in scope — no static needed.
    if let Some(cfr_raw) = cb_info.cfr_raw
        && let Some(cfr) = cfr::parse_cfr(cfr_raw)
    {
        log::info!(
            "CFR: {} forms, {} options",
            cfr.forms.len(),
            cfr.total_options()
        );
        cfr::store_cfr(cfr);
    }

    // ================================================================
    // Phase 9: Hand off to the library (never returns)
    // ================================================================
    crabefi::init_platform(config)
}

// ============================================================================
// Logging helpers
// ============================================================================

/// Apply CrabEFI's persisted log level before normal platform initialization.
///
/// Keep this path read-only and silent: at this point the heap, SPI drivers, and
/// full EFI variable services are not initialized yet. Coreboot-specific code is
/// limited to discovering the memory-mapped SMMSTORE region; parsing the EDK2
/// variable-store format is handled by the generic CrabEFI logger helper.
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
