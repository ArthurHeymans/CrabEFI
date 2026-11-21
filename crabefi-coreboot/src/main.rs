//! CrabEFI Coreboot Payload
//!
//! This binary builds CrabEFI as a coreboot payload for x86_64, aarch64 and riscv64.
//! It handles architecture-specific entry (32→64 mode switch on x86, MMU setup
//! on aarch64), parses coreboot tables to discover hardware, runs ACPI
//! discovery, builds a [`crabefi::PlatformConfig`], and hands off to the
//! CrabEFI library.

#![no_std]
#![no_main]

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
#[cfg(all(feature = "payload-mm", not(feature = "ab-test-slots")))]
mod amd_ab;
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64/entry.rs"]
mod arch_entry;
#[cfg(target_arch = "riscv64")]
#[path = "arch/riscv64/entry.rs"]
mod arch_entry;
#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/entry.rs"]
mod arch_entry;
mod boot_memory;
#[cfg(not(feature = "native-only"))]
mod capsule;
mod cbmem_console;
mod discovery;
#[cfg(not(feature = "native-only"))]
mod fmap;
mod framebuffer;
mod handoff;
mod logging;
#[cfg(not(feature = "native-only"))]
mod measured_boot;
mod memory;
mod memory_map;
#[cfg(feature = "payload-mm")]
mod payload_mm;
mod platform;
#[cfg(target_arch = "riscv64")]
#[path = "arch/riscv64/boot.rs"]
mod riscv_boot;
#[cfg(not(feature = "native-only"))]
mod runtime;
#[cfg(feature = "external-runtime-image")]
mod runtime_blob;
mod tables;
#[cfg(target_arch = "x86_64")]
mod timestamps;
#[cfg(not(feature = "native-only"))]
mod varstore;

use core::panic::PanicInfo;

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

    // On RISC-V, extract timer frequency from FDT now that state is initialized.
    #[cfg(target_arch = "riscv64")]
    riscv_boot::restore_timer_frequency();

    // SAFETY: The parser first tries the payload entry argument and falls back
    // to scanning the standard coreboot table locations if it is not valid.
    let cb_info = unsafe { tables::parse(coreboot_table_ptr as *const u8) };

    let cbmem_console_available = cb_info.cbmem_console.is_some_and(cbmem_console::init);

    #[cfg(target_arch = "x86_64")]
    let recorder = platform::start_timestamps(&cb_info, entry_counter);
    #[cfg(target_arch = "x86_64")]
    let timestamp_recorder = recorder
        .as_ref()
        .map(|r| r as &dyn crabefi::TimestampRecorder);
    #[cfg(not(target_arch = "x86_64"))]
    let timestamp_recorder = None;

    // Validate once: logging, GOP and the MMIO overlay must agree.
    let framebuffer = cb_info
        .framebuffer
        .map(crabefi::FramebufferConfig::from)
        .filter(|fb| fb.size() != 0 && fb.physical_address != 0);
    #[cfg(not(feature = "native-only"))]
    if let Some(addr) = cb_info.framebuffer_record_addr {
        framebuffer::store_framebuffer_record_addr(addr);
    }
    #[cfg(not(feature = "native-only"))]
    varstore::configure_pflash(&cb_info);

    logging::init_serial(&cb_info);
    if cbmem_console_available {
        // SAFETY: this frame never returns; the sink has exclusive access to
        // cbmem_output from now on. CBMEM disables itself before runtime.
        unsafe { crabefi::drivers::serial::add_platform_debug_sink_raw(&raw mut cbmem_output) };
    }
    logging::start(&cb_info, framebuffer, coreboot_table_ptr);
    platform::calibrate_timer(&cb_info);

    #[cfg(feature = "payload-mm")]
    payload_mm::load_or_halt(&cb_info);

    let mut regions = boot_memory::EMPTY_MAP;
    let memory_map = boot_memory::platform_map(&cb_info.memory_map, framebuffer, &mut regions);
    handoff::boot(&cb_info, memory_map, framebuffer, timestamp_recorder)
}

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
