//! OpenSBI entry and FDT-only boot.

use crate::platform::{CorebootHooks, CorebootReset, CorebootTimer, boot_policy};
use crate::runtime::{runtime_image_source, runtime_platform_config};
use crate::rust_main;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crabefi::handoff::MAX_MEMORY_REGIONS;

/// RISC-V entry point called from assembly after BSS zeroing / stack setup.
///
/// On RISC-V, coreboot + OpenSBI passes:
///   - a0 = hart ID
///   - a1 = pointer to FDT (Flattened Device Tree)
///
/// The FDT contains a `/chosen/coreboot-table` property with the physical
/// address of the coreboot information tables. We extract that, then
/// call the architecture-independent `rust_main()`.
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
static RISCV_BOOT_HARTID: AtomicU64 = AtomicU64::new(0);
/// Saved FDT pointer from RISC-V entry (used after state init).
static RISCV_FDT_PTR: AtomicU64 = AtomicU64::new(0);
/// Saved FDT size from RISC-V entry.
static RISCV_FDT_SIZE: AtomicU32 = AtomicU32::new(0);

/// Extract the coreboot table pointer and FDT size from an FDT blob.
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

    // SAFETY: OpenSBI supplies a readable FDT spanning its header's total size.
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
fn extract_timer_freq_from_fdt(fdt_ptr: u64, fdt_size: u32) {
    if fdt_ptr == 0 || fdt_size < 40 {
        return;
    }

    // SAFETY: OpenSBI supplies a readable FDT spanning its header's total size.
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
            crabefi::time::set_counter_frequency(freq);
        }
    }
}

/// FDT-only boot path for RISC-V when coreboot tables are not available.
///
/// This builds a minimal `PlatformConfig` from FDT data and boots.
fn riscv_fdt_only_boot(fdt_ptr: u64, fdt_size: u32) -> ! {
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

    if fdt_ptr == 0 || fdt_size < 40 {
        panic!("FDT-only boot requires a non-null FDT with a complete header");
    }

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
        freq_hz: crabefi::time::counter_frequency(),
    };
    let reset = CorebootReset;
    let hooks = CorebootHooks;

    // SAFETY: fdt_ptr is non-null and OpenSBI keeps the header's advertised
    // fdt_size bytes mapped and readable through handoff.
    let fdt_slice = unsafe { core::slice::from_raw_parts(fdt_ptr as *const u8, fdt_size as usize) };

    let config = crabefi::PlatformConfig {
        memory_map: &memory_regions[..region_count],
        timer: &timer,
        timestamp_recorder: None,
        reset: &reset,
        block_devices: &mut [],
        variable_storage: crabefi::VariableStorage::None,
        debug_output: None,
        console_input: None,
        peripherals: alloc::vec::Vec::new(),
        framebuffer: None,
        acpi_rsdp: None,
        smbios: None,
        fdt: Some(fdt_slice),
        acpi_info: None,
        discover_mmio: true,
        firmware_info: None,
        capsule_regions: &[],
        capsule_backend: None,
        capsule_on_disk_only: cfg!(feature = "capsule-on-disk-only"),
        boot_events: None,
        hooks: Some(&hooks),
        rng: None,
        ecam_regions: &[],
        runtime_image: runtime_image_source(),
        runtime: runtime_platform_config(),
        tpm_event_log: None,
        boot_policy: boot_policy(),
        heap_pre_initialized: false,
    };

    crabefi::init_platform(config)
}

/// Build a memory map from FDT /memory nodes.
fn build_memory_map_from_fdt(
    fdt_ptr: u64,
    fdt_size: u32,
    out: &mut [crabefi::MemoryRegion; MAX_MEMORY_REGIONS],
) -> usize {
    let mut count = 0;
    if fdt_ptr == 0 || fdt_size < 40 {
        return count;
    }

    // SAFETY: OpenSBI supplies a readable FDT spanning its header's total size.
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

/// Prefer OpenSBI's full hardware description to the coreboot table entry.
pub(crate) fn saved_fdt() -> Option<&'static [u8]> {
    let fdt_ptr = RISCV_FDT_PTR.load(Ordering::Relaxed);
    let fdt_size = RISCV_FDT_SIZE.load(Ordering::Relaxed);
    if fdt_ptr != 0 && fdt_size >= 40 {
        // SAFETY: these are the saved OpenSBI FDT and its header length.
        Some(unsafe { core::slice::from_raw_parts(fdt_ptr as *const u8, fdt_size as usize) })
    } else {
        None
    }
}

pub(crate) fn restore_timer_frequency() {
    let fdt_ptr = RISCV_FDT_PTR.load(Ordering::Relaxed);
    let fdt_size = RISCV_FDT_SIZE.load(Ordering::Relaxed);
    if fdt_ptr != 0 && fdt_size >= 40 {
        extract_timer_freq_from_fdt(fdt_ptr, fdt_size);
    }
}
