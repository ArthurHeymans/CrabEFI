//! EFI system table and services
//!
//! This module provides the UEFI system table, boot services, and runtime services
//! implementations.

pub mod allocator;
pub mod auth;
pub mod boot_services;
pub mod guid_fmt;
pub mod image_loader;
pub mod protocols;
#[cfg(feature = "rt-log")]
pub mod rtlog;
pub mod runtime_services;
pub mod system_table;
pub mod utils;
pub mod varstore;

#[cfg(target_arch = "riscv64")]
use r_efi::efi::Guid;
use r_efi::efi::{self, Status};

/// Initialize the EFI environment from platform configuration.
pub fn init_from_platform(config: &crate::platform::PlatformConfig) {
    log::info!("Initializing EFI environment (platform path)...");

    // Initialize the memory allocator from the platform memory map
    allocator::init_from_platform(config.memory_map);

    // NOTE: add_platform_mmio_regions() is NOT called here. In library mode
    // the caller's memory_map is authoritative — it must include all MMIO
    // regions (GIC, UART, PCIe windows, platform devices) as MemoryType::Mmio
    // entries. This avoids duplicate memory map entries and removes the need
    // for ACPI/FDT parsing inside the library for this purpose.
    //
    // Platforms that discover MMIO regions via ACPI (e.g., coreboot) call
    // efi::add_platform_mmio_regions() themselves before init_platform().

    // On aarch64, reserve EL2 page tables if running at EL2.
    // When called from fstart (which typically runs at EL1), this is a no-op.
    #[cfg(target_arch = "aarch64")]
    {
        let current_el: u64;
        unsafe {
            core::arch::asm!(
                "mrs {}, CurrentEL",
                out(reg) current_el,
                options(nomem, nostack, preserves_flags)
            );
        }
        let el = (current_el >> 2) & 0x3;
        if el >= 2 {
            reserve_el2_page_tables();
        } else {
            log::info!("Running at EL{} — skipping EL2 page table reservation", el);
        }
    }

    // Reserve runtime services memory regions if the platform provided them.
    if let Some(rt) = config.runtime_region {
        use allocator::MemoryType;

        let code_pages = rt.code_size.div_ceil(allocator::PAGE_SIZE);
        let data_pages = rt.data_size.div_ceil(allocator::PAGE_SIZE);
        if let Err(e) =
            allocator::reserve_region(rt.code_base, code_pages, MemoryType::RuntimeServicesCode)
        {
            log::warn!("Failed to reserve runtime code region: {:?}", e);
        }
        if let Err(e) =
            allocator::reserve_region(rt.data_base, data_pages, MemoryType::RuntimeServicesData)
        {
            log::warn!("Failed to reserve runtime data region: {:?}", e);
        }
    } else {
        // Fall back to linker-symbol-based reservation. Only available when
        // CrabEFI owns the linker script (platform-entry feature).
        #[cfg(feature = "platform-entry")]
        allocator::reserve_runtime_region();
        #[cfg(not(feature = "platform-entry"))]
        log::info!(
            "No runtime region provided and no linker symbols — runtime services may not survive ExitBootServices"
        );
    }

    // Initialize system table with boot and runtime services
    unsafe {
        system_table::init(
            boot_services::get_boot_services(),
            runtime_services::get_runtime_services(),
        );
    }

    // Install platform tables
    if let Some(rsdp) = config.acpi_rsdp {
        system_table::install_acpi_tables(rsdp);
    } else {
        log::info!("No ACPI RSDP from platform");
    }
    if let Some(smbios) = config.smbios {
        system_table::install_smbios_tables(smbios);
    }
    if let Some(fdt_bytes) = config.fdt {
        let fdt_addr = fdt_bytes.as_ptr() as u64;
        let fdt_size = fdt_bytes.len() as u32;
        system_table::install_devicetree(fdt_addr, fdt_size);
    }

    // Install standard EFI tables and protocols
    system_table::install_rt_properties_table();
    system_table::install_tpm_event_log();

    let console_handle = init_console();

    if let Some(fb) = config.framebuffer {
        // Store globally so menus and boot_manager can access it via
        // state::get_framebuffer() — works for both coreboot and platform paths.
        crate::state::store_framebuffer(fb);
        if let Some(handle) = console_handle {
            init_graphics_output_on_handle(&fb, handle);
        }
        protocols::console::init_framebuffer(fb);
    }

    // Install standard protocols and finalize tables (shared with init)
    install_standard_protocols_and_finalize();

    // Dump the full memory map for debugging (output goes directly to serial,
    // bypassing EFI ConOut — safe even if ConOut has issues).
    allocator::dump_memory_map();

    log::info!("EFI environment initialized (platform path)");
}

/// Install standard EFI protocols and finalize table checksums.
///
/// Shared by both [`init()`] and [`init_from_platform()`] — contains the
/// protocol installations and table finalization that are identical in both
/// paths.
fn install_standard_protocols_and_finalize() {
    init_unicode_collation();
    init_memory_attribute();
    init_serial_io();
    init_rng();
    init_console_control();
    init_device_path_protocols();
    init_load_file2();
    #[cfg(target_arch = "riscv64")]
    init_riscv_boot_protocol();
    system_table::install_memory_attributes_table();
    system_table::dump_configuration_tables();
    system_table::update_crc32();
}

/// Initialize console I/O
/// Returns the console handle so GOP can be installed on it
fn init_console() -> Option<efi::Handle> {
    use protocols::console::{
        SIMPLE_TEXT_INPUT_PROTOCOL_GUID, SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID, get_text_input_protocol,
        get_text_output_protocol,
    };
    use protocols::device_path::{DEVICE_PATH_PROTOCOL_GUID, create_video_device_path};

    // Create console handle
    let console_handle = match boot_services::create_handle() {
        Some(h) => h,
        None => {
            log::error!("Failed to create console handle");
            return None;
        }
    };

    // Install device path on console handle - GRUB needs this for GOP
    let device_path = create_video_device_path();
    if !device_path.is_null() {
        let status = boot_services::install_protocol(
            console_handle,
            &DEVICE_PATH_PROTOCOL_GUID,
            device_path as *mut core::ffi::c_void,
        );
        if status != Status::SUCCESS {
            log::error!("Failed to install device path on console: {:?}", status);
        }
    }

    // Install text input protocol
    let input_protocol = get_text_input_protocol();
    let status = boot_services::install_protocol(
        console_handle,
        &SIMPLE_TEXT_INPUT_PROTOCOL_GUID,
        input_protocol as *mut core::ffi::c_void,
    );
    if status != Status::SUCCESS {
        log::error!("Failed to install text input protocol: {:?}", status);
    }

    // Install text input ex protocol on the same console handle
    {
        use protocols::simple_text_input_ex::{
            SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID, create_protocol as create_text_input_ex,
        };
        let input_ex = create_text_input_ex();
        if input_ex.is_null() {
            log::error!("Failed to create SimpleTextInputEx protocol");
        } else {
            let status = boot_services::install_protocol(
                console_handle,
                &SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID,
                input_ex,
            );
            if status != Status::SUCCESS {
                log::error!("Failed to install SimpleTextInputEx protocol: {:?}", status);
            } else {
                log::debug!("SimpleTextInputEx protocol installed on console handle");
            }
        }
    }

    // Install text output protocol
    let output_protocol = get_text_output_protocol();
    let status = boot_services::install_protocol(
        console_handle,
        &SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID,
        output_protocol as *mut core::ffi::c_void,
    );
    if status != Status::SUCCESS {
        log::error!("Failed to install text output protocol: {:?}", status);
    }

    // Set up console in system table
    unsafe {
        system_table::set_console_in(console_handle, input_protocol);
        system_table::set_console_out(console_handle, output_protocol);
        system_table::set_std_err(console_handle, output_protocol);
    }

    log::debug!("Console protocols installed on handle {:?}", console_handle);
    Some(console_handle)
}

/// Initialize Unicode Collation protocol
fn init_unicode_collation() {
    use protocols::unicode_collation::{
        UNICODE_COLLATION_PROTOCOL_GUID, UNICODE_COLLATION_PROTOCOL2_GUID, get_protocol_void,
    };

    // Create a handle for Unicode Collation
    let handle = match boot_services::create_handle() {
        Some(h) => h,
        None => {
            log::error!("Failed to create Unicode Collation handle");
            return;
        }
    };

    // Install version 1 (legacy) protocol
    let protocol = get_protocol_void();
    let status =
        boot_services::install_protocol(handle, &UNICODE_COLLATION_PROTOCOL_GUID, protocol);
    if status != Status::SUCCESS {
        log::error!(
            "Failed to install Unicode Collation v1 protocol: {:?}",
            status
        );
    }

    // Install version 2 protocol
    let status =
        boot_services::install_protocol(handle, &UNICODE_COLLATION_PROTOCOL2_GUID, protocol);
    if status != Status::SUCCESS {
        log::error!(
            "Failed to install Unicode Collation v2 protocol: {:?}",
            status
        );
    }

    log::debug!("Unicode Collation protocols installed");
}

/// Initialize Memory Attribute protocol
fn init_memory_attribute() {
    use protocols::memory_attribute::{MEMORY_ATTRIBUTE_PROTOCOL_GUID, create_protocol};

    // Create a handle for Memory Attribute protocol
    let handle = match boot_services::create_handle() {
        Some(h) => h,
        None => {
            log::error!("Failed to create Memory Attribute handle");
            return;
        }
    };

    // Create and install the protocol
    let protocol = create_protocol();
    if protocol.is_null() {
        log::error!("Failed to create Memory Attribute protocol");
        return;
    }

    let status = boot_services::install_protocol(
        handle,
        &MEMORY_ATTRIBUTE_PROTOCOL_GUID,
        protocol as *mut core::ffi::c_void,
    );
    if status != Status::SUCCESS {
        log::error!("Failed to install Memory Attribute protocol: {:?}", status);
        return;
    }

    log::debug!("Memory Attribute protocol installed on handle {:?}", handle);
}

/// Initialize Serial IO protocol
fn init_serial_io() {
    use protocols::serial_io::{SERIAL_IO_PROTOCOL_GUID, create_protocol};

    // Create a handle for Serial IO protocol
    let handle = match boot_services::create_handle() {
        Some(h) => h,
        None => {
            log::error!("Failed to create Serial IO handle");
            return;
        }
    };

    // Create and install the protocol
    let protocol = create_protocol();
    if protocol.is_null() {
        log::error!("Failed to create Serial IO protocol");
        return;
    }

    let status = boot_services::install_protocol(
        handle,
        &SERIAL_IO_PROTOCOL_GUID,
        protocol as *mut core::ffi::c_void,
    );
    if status != Status::SUCCESS {
        log::error!("Failed to install Serial IO protocol: {:?}", status);
        return;
    }

    log::debug!("Serial IO protocol installed on handle {:?}", handle);
}

/// Initialize RNG protocol
fn init_rng() {
    use protocols::rng::{RNG_PROTOCOL_GUID, create_protocol, init, is_supported};

    // Initialize RDRAND support (CPUID check + broken RDRAND test)
    init();

    if !is_supported() {
        return;
    }

    // Create a handle for RNG protocol
    let handle = match boot_services::create_handle() {
        Some(h) => h,
        None => {
            log::error!("Failed to create RNG handle");
            return;
        }
    };

    // Create and install the protocol
    let protocol = create_protocol();
    if protocol.is_null() {
        log::error!("Failed to create RNG protocol");
        return;
    }

    let status = boot_services::install_protocol(
        handle,
        &RNG_PROTOCOL_GUID,
        protocol as *mut core::ffi::c_void,
    );
    if status != Status::SUCCESS {
        log::error!("Failed to install RNG protocol: {:?}", status);
        return;
    }

    log::debug!("RNG protocol installed on handle {:?}", handle);
}

/// Initialize Console Control protocol (legacy Intel EFI protocol)
fn init_console_control() {
    use protocols::console_control::{CONSOLE_CONTROL_PROTOCOL_GUID, create_protocol};

    // Create a handle for Console Control protocol
    let handle = match boot_services::create_handle() {
        Some(h) => h,
        None => {
            log::error!("Failed to create Console Control handle");
            return;
        }
    };

    // Create and install the protocol
    let protocol = create_protocol();
    if protocol.is_null() {
        log::error!("Failed to create Console Control protocol");
        return;
    }

    let status = boot_services::install_protocol(handle, &CONSOLE_CONTROL_PROTOCOL_GUID, protocol);
    if status != Status::SUCCESS {
        log::error!("Failed to install Console Control protocol: {:?}", status);
        return;
    }

    log::debug!("Console Control protocol installed on handle {:?}", handle);
}

/// Initialize Device Path utility protocols (Utilities, ToText, FromText)
///
/// All three are installed on a single shared handle, matching EDK2 behavior.
fn init_device_path_protocols() {
    use protocols::device_path_from_text::{
        DEVICE_PATH_FROM_TEXT_GUID, create_protocol as create_from_text,
    };
    use protocols::device_path_to_text::{
        DEVICE_PATH_TO_TEXT_GUID, create_protocol as create_to_text,
    };
    use protocols::device_path_utilities::{
        DEVICE_PATH_UTILITIES_GUID, create_protocol as create_utilities,
    };

    let handle = match boot_services::create_handle() {
        Some(h) => h,
        None => {
            log::error!("Failed to create Device Path Utilities handle");
            return;
        }
    };

    // Device Path Utilities
    let proto = create_utilities();
    if proto.is_null() {
        log::error!("Failed to create Device Path Utilities protocol");
        return;
    }
    let status = boot_services::install_protocol(handle, &DEVICE_PATH_UTILITIES_GUID, proto);
    if status != Status::SUCCESS {
        log::error!("Failed to install Device Path Utilities: {:?}", status);
        return;
    }

    // Device Path To Text
    let proto = create_to_text();
    if proto.is_null() {
        log::error!("Failed to create Device Path To Text protocol");
        return;
    }
    let status = boot_services::install_protocol(handle, &DEVICE_PATH_TO_TEXT_GUID, proto);
    if status != Status::SUCCESS {
        log::error!("Failed to install Device Path To Text: {:?}", status);
        return;
    }

    // Device Path From Text
    let proto = create_from_text();
    if proto.is_null() {
        log::error!("Failed to create Device Path From Text protocol");
        return;
    }
    let status = boot_services::install_protocol(handle, &DEVICE_PATH_FROM_TEXT_GUID, proto);
    if status != Status::SUCCESS {
        log::error!("Failed to install Device Path From Text: {:?}", status);
        return;
    }

    log::info!("Device Path protocols installed on handle {:?}", handle);
}

/// Initialize Load File 2 protocol with Linux initrd vendor media device path
fn init_load_file2() {
    use protocols::device_path::DEVICE_PATH_PROTOCOL_GUID;
    use protocols::load_file2::{LOAD_FILE2_GUID, create_device_path, create_protocol};

    let handle = match boot_services::create_handle() {
        Some(h) => h,
        None => {
            log::error!("Failed to create LoadFile2 handle");
            return;
        }
    };

    // Install the initrd vendor media device path on the handle
    let dp = create_device_path();
    if dp.is_null() {
        log::error!("Failed to create LoadFile2 device path");
        return;
    }
    let status = boot_services::install_protocol(
        handle,
        &DEVICE_PATH_PROTOCOL_GUID,
        dp as *mut core::ffi::c_void,
    );
    if status != Status::SUCCESS {
        log::error!("Failed to install LoadFile2 device path: {:?}", status);
        return;
    }

    // Install the protocol itself
    let proto = create_protocol();
    if proto.is_null() {
        log::error!("Failed to create LoadFile2 protocol");
        return;
    }
    let status = boot_services::install_protocol(handle, &LOAD_FILE2_GUID, proto);
    if status != Status::SUCCESS {
        log::error!("Failed to install LoadFile2 protocol: {:?}", status);
        return;
    }

    log::info!("LoadFile2 protocol installed on handle {:?}", handle);
}

/// Initialize Graphics Output Protocol (GOP) on a specific handle
/// Installing GOP on the same handle as ConOut is important for GRUB compatibility
fn init_graphics_output_on_handle(
    framebuffer: &crate::platform::FramebufferConfig,
    handle: efi::Handle,
) {
    use protocols::graphics_output::{GRAPHICS_OUTPUT_GUID, create_gop};

    // Create and install the protocol on the provided handle
    let protocol = create_gop(framebuffer);
    if protocol.is_null() {
        log::error!("Failed to create GOP protocol");
        return;
    }

    let status = boot_services::install_protocol(
        handle,
        &GRAPHICS_OUTPUT_GUID,
        protocol as *mut core::ffi::c_void,
    );
    if status != Status::SUCCESS {
        log::error!("Failed to install GOP protocol: {:?}", status);
        return;
    }

    log::debug!("GOP protocol installed on console handle {:?}", handle);
}

// ============================================================================
// RISC-V EFI Boot Protocol
// ============================================================================

/// Boot hart ID saved by the platform entry point before calling the library.
///
/// Stored as an `AtomicU64` so `riscv_get_boot_hartid` can read it without
/// `unsafe`.  Written once at entry (before any UEFI code runs) and then
/// only ever read.
#[cfg(target_arch = "riscv64")]
static RISCV_BOOT_HARTID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Set the boot hart ID from the platform entry point.
///
/// Must be called before `init_platform()` installs the RISC-V EFI Boot
/// Protocol so the correct value is visible to `riscv_get_boot_hartid`.
#[cfg(target_arch = "riscv64")]
pub fn set_boot_hartid(hartid: u64) {
    RISCV_BOOT_HARTID.store(hartid, core::sync::atomic::Ordering::Relaxed);
}

/// RISCV_EFI_BOOT_PROTOCOL GUID
/// {ccd15fec-6f73-4eec-8395-3e69e4b940bf}
#[cfg(target_arch = "riscv64")]
const RISCV_EFI_BOOT_PROTOCOL_GUID: Guid = Guid::from_fields(
    0xccd15fec,
    0x6f73,
    0x4eec,
    0x83,
    0x95,
    &[0x3e, 0x69, 0xe4, 0xb9, 0x40, 0xbf],
);

/// RISC-V EFI Boot Protocol structure.
///
/// This protocol provides the boot hart ID to the Linux EFI stub.
/// The struct layout must match what Linux expects:
///   `{ u64 revision; efi_status_t (*get_boot_hartid)(this, *hartid); }`
#[cfg(target_arch = "riscv64")]
#[repr(C)]
struct RiscvEfiBootProtocol {
    revision: u64,
    get_boot_hartid:
        extern "efiapi" fn(this: *const RiscvEfiBootProtocol, boot_hartid: *mut u64) -> Status,
}

#[cfg(target_arch = "riscv64")]
extern "efiapi" fn riscv_get_boot_hartid(
    _this: *const RiscvEfiBootProtocol,
    boot_hartid: *mut u64,
) -> Status {
    if boot_hartid.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // Read the hart ID that was saved at firmware entry from OpenSBI's a0.
    // SAFETY: caller guarantees boot_hartid is a valid pointer.
    unsafe {
        *boot_hartid = RISCV_BOOT_HARTID.load(core::sync::atomic::Ordering::Relaxed);
    }
    Status::SUCCESS
}

/// Static instance of the RISC-V boot protocol.
#[cfg(target_arch = "riscv64")]
static RISCV_BOOT_PROTOCOL: RiscvEfiBootProtocol = RiscvEfiBootProtocol {
    revision: 1,
    get_boot_hartid: riscv_get_boot_hartid,
};

/// Install the RISC-V EFI Boot Protocol.
///
/// Linux's EFI stub uses this to discover the boot hart ID.
#[cfg(target_arch = "riscv64")]
fn init_riscv_boot_protocol() {
    let handle = match boot_services::create_handle() {
        Some(h) => h,
        None => {
            log::error!("Failed to create RISC-V boot protocol handle");
            return;
        }
    };

    let protocol_ptr = &RISCV_BOOT_PROTOCOL as *const RiscvEfiBootProtocol;
    let status = boot_services::install_protocol(
        handle,
        &RISCV_EFI_BOOT_PROTOCOL_GUID,
        protocol_ptr as *mut core::ffi::c_void,
    );
    if status != Status::SUCCESS {
        log::error!("Failed to install RISC-V boot protocol: {:?}", status);
        return;
    }
    log::info!(
        "RISC-V EFI Boot Protocol installed (hart_id={})",
        RISCV_BOOT_HARTID.load(core::sync::atomic::Ordering::Relaxed)
    );
}

/// Get the EFI system table pointer
pub fn get_system_table() -> *mut efi::SystemTable {
    system_table::get_system_table_efi()
}

/// Get a firmware image handle (used as parent handle for loaded images)
/// This creates a dummy handle to represent the firmware itself
pub fn get_firmware_handle() -> efi::Handle {
    // Use a fixed value for the firmware handle
    // This is just a unique identifier, not a real pointer
    FIRMWARE_HANDLE as *mut core::ffi::c_void
}

// Constant for firmware handle (high address unlikely to conflict)
const FIRMWARE_HANDLE: usize = 0xF1F1_F1F1;

/// Allocate pages of memory (convenience function for drivers)
///
/// Returns a mutable byte slice covering the allocated pages, or None if allocation failed.
/// The slice has a `'static` lifetime since the memory remains valid until explicitly freed.
pub fn allocate_pages(num_pages: u64) -> Option<&'static mut [u8]> {
    let mut addr = 0u64;
    let status = allocator::allocate_pages(
        allocator::AllocateType::AllocateAnyPages,
        allocator::MemoryType::BootServicesData,
        num_pages,
        &mut addr,
    );
    if status == Status::SUCCESS {
        let size = (num_pages as usize) * allocator::PAGE_SIZE_USIZE;
        // Safety: allocate_pages returns a valid, aligned address for the requested
        // number of pages. The memory is exclusively owned until freed.
        Some(unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, size) })
    } else {
        None
    }
}

/// Allocate pages of memory below 4GB (for 32-bit DMA controllers like EHCI)
///
/// EHCI and other legacy controllers use 32-bit physical addresses for DMA.
/// This function ensures the allocated memory is accessible by such controllers.
///
/// Returns a mutable byte slice covering the allocated pages, or None if allocation failed.
/// The slice has a `'static` lifetime since the memory remains valid until explicitly freed.
pub fn allocate_pages_below_4g(num_pages: u64) -> Option<&'static mut [u8]> {
    // Use AllocateMaxAddress with max address of 0xFFFFFFFF (4GB - 1)
    let mut addr = 0xFFFF_FFFFu64;
    let status = allocator::allocate_pages(
        allocator::AllocateType::AllocateMaxAddress,
        allocator::MemoryType::BootServicesData,
        num_pages,
        &mut addr,
    );
    if status == Status::SUCCESS {
        let size = (num_pages as usize) * allocator::PAGE_SIZE_USIZE;
        // Safety: allocate_pages returns a valid, aligned address for the requested
        // number of pages. The memory is exclusively owned until freed.
        Some(unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, size) })
    } else {
        None
    }
}

/// Free previously allocated pages (convenience function for drivers)
///
/// Pass the slice returned by `allocate_pages` (or a subslice starting at the same address).
pub fn free_pages(memory: &mut [u8], num_pages: u64) {
    let addr = memory.as_ptr() as u64;
    let _ = allocator::free_pages(addr, num_pages);
}

/// Add platform MMIO regions to the EFI memory map (aarch64 only)
///
/// QEMU SBSA has device MMIO at addresses not covered by coreboot's memory map.
/// The Linux kernel uses the UEFI memory map to build page tables after
/// ExitBootServices — any MMIO not in the map is unmapped and inaccessible.
///
/// Critical regions:
/// - GIC distributor/redistributor (for interrupts) / PLIC (RISC-V)
/// - UART PL011/16550 (for earlycon/console)
/// - Peripherals (RTC, GPIO, etc.)
/// - PCIe MMIO windows (for PCI device access)
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
pub fn add_platform_mmio_regions() {
    use allocator::{MemoryType, PAGE_SIZE};

    // Helper: add an MMIO region, logging success/failure
    let add_mmio = |base: u64, size: u64, name: &str| {
        let pages = size.div_ceil(PAGE_SIZE);
        match allocator::force_add_region(base, pages, MemoryType::MemoryMappedIo) {
            Ok(()) => log::info!(
                "MMIO region added: {} at {:#x} ({} pages)",
                name,
                base,
                pages
            ),
            Err(e) => log::error!("Failed to add MMIO region {}: {:?}", name, e),
        }
    };

    // Try to get platform info from FDT (if available)
    let plat = crate::state::drivers().fdt_info;

    // Interrupt controller — from FDT only (GIC on aarch64, PLIC on riscv64).
    // The `gicd` field is reused for PLIC on RISC-V (see fdt.rs:extract_gic).
    // No fallback: a wrong hardcoded address is worse than a missing entry.
    if let Some((base, size)) = plat.gicd {
        let total = if let Some((rb, rsize)) = plat.gicr {
            // Cover GICD + GICR as one contiguous block if adjacent,
            // otherwise add them separately
            let gicd_end = base + size;
            if rb == gicd_end {
                size + rsize
            } else {
                add_mmio(rb, rsize, "GICR");
                size
            }
        } else {
            size
        };
        add_mmio(base, total, "GIC/PLIC");
    } else {
        log::warn!("add_platform_mmio_regions: no interrupt controller found in FDT");
    }

    // PCIe PIO — from FDT only.
    if let Some((base, size)) = plat.pcie_pio {
        add_mmio(base, size, "PCIe PIO");
    }

    // PCIe 32-bit MMIO — from FDT only.
    if let Some((base, size)) = plat.pcie_mmio32 {
        add_mmio(base, size, "PCIe MMIO32");
    }

    // PCIe 64-bit MMIO (if from FDT)
    //
    // Skip on RISC-V: OpenSBI 1.1's PMP configuration does not cover the
    // 64-bit MMIO range (e.g. 0x3_0000_0000+), so S-mode accesses there
    // fault.  All PCI BARs are placed in the 32-bit window instead.
    // Adding the (often 16 GB) region also bloats the EFI memory map.
    #[cfg(not(target_arch = "riscv64"))]
    if let Some((base, size)) = plat.pcie_mmio64 {
        add_mmio(base, size, "PCIe MMIO64");
    }

    // PCIe ECAM — from FDT
    //
    // On RISC-V QEMU virt the ECAM range (0x3000_0000-0x4000_0000) is
    // already in coreboot's memory map as Reserved.  Adding a duplicate
    // MMIO entry for the same address creates an overlap that confuses
    // the Linux kernel's early memory-map processing.  Only add ECAM
    // when the coreboot map does not already cover it (aarch64 SBSA).
    #[cfg(not(target_arch = "riscv64"))]
    if let Some(base) = plat.ecam_base
        && let Some(size) = plat.ecam_size
    {
        add_mmio(base, size, "PCIe ECAM");
    }
    // SBSA ECAM (0xF0000000-0x100000000) is already in coreboot map as Reserved
}

/// Reserve the EL2 MMU page table memory (aarch64 only)
///
/// Coreboot sets up page tables (L0/L1/L2/L3) at TTBR0_EL2 and CrabEFI
/// continues using them at EL2. The coreboot memory map reports the
/// containing RAM region as ConventionalMemory, which means our allocator
/// can hand out pages that overlap the active page tables. Once those
/// pages are overwritten, the MMU faults with a level 0/1 translation
/// error and the system crashes.
///
/// We read TTBR0_EL2 to find the L0 table base, then walk the tables
/// to determine the extent of all page table pages, and reserve them.
#[cfg(target_arch = "aarch64")]
fn reserve_el2_page_tables() {
    use allocator::PAGE_SIZE;

    let ttbr0: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, TTBR0_EL2",
            out(reg) ttbr0,
            options(nomem, nostack, preserves_flags)
        );
    }

    let base = ttbr0 & !0xFFF; // Page-align (clear ASID/CnP bits)
    if base == 0 {
        log::warn!("TTBR0_EL2 is 0 — MMU may not be enabled, skipping page table reservation");
        return;
    }

    // Walk the page tables to find all used pages.
    // On aarch64, a 4KB granule with 48-bit VA space has:
    //   L0: 1 page, 512 entries, each covering 512GB
    //   L1: up to 512 pages, each covering 1GB
    //   L2: each covering 2MB
    //   L3: each covering 4KB
    //
    // We only need to find L0+L1+L2 tables (L3 is rare in coreboot's setup
    // which prefers block mappings). Walk L0 and L1 to find table references.
    //
    // A table descriptor has bits [1:0] = 0b11, and bits [47:12] point to
    // the next-level table.

    let mut min_addr = base;
    let mut max_addr = base + PAGE_SIZE; // At least the L0 page

    // Read L0 entries
    for i in 0..512u64 {
        let entry_addr = base + i * 8;
        let entry: u64 = unsafe { core::ptr::read_volatile(entry_addr as *const u64) };

        // Check if it's a table descriptor (bits [1:0] == 0b11)
        if entry & 0x3 == 0x3 {
            let l1_table = entry & 0x0000_FFFF_FFFF_F000;
            if l1_table < min_addr {
                min_addr = l1_table;
            }
            if l1_table + PAGE_SIZE > max_addr {
                max_addr = l1_table + PAGE_SIZE;
            }

            // Walk L1 entries to find L2 tables
            for j in 0..512u64 {
                let l1_entry_addr = l1_table + j * 8;
                let l1_entry: u64 =
                    unsafe { core::ptr::read_volatile(l1_entry_addr as *const u64) };

                // L1 table descriptor -> L2 table
                if l1_entry & 0x3 == 0x3 {
                    let l2_table = l1_entry & 0x0000_FFFF_FFFF_F000;
                    if l2_table < min_addr {
                        min_addr = l2_table;
                    }
                    if l2_table + PAGE_SIZE > max_addr {
                        max_addr = l2_table + PAGE_SIZE;
                    }
                }
            }
        }
    }

    let pages = (max_addr - min_addr).div_ceil(PAGE_SIZE);
    log::info!(
        "EL2 page tables: TTBR0={:#x}, range {:#x}-{:#x} ({} pages)",
        ttbr0,
        min_addr,
        max_addr,
        pages
    );

    // Reserve these pages by carving them out of the existing ConventionalMemory
    // region. Using mark_as_reserved() (not force_add_region()) ensures the
    // ConventionalMemory entry is properly split so the allocator will never
    // hand out pages that overlap the active EL2 page tables.
    match allocator::mark_as_reserved(min_addr, pages) {
        Ok(()) => log::info!(
            "Reserved EL2 page table memory: {:#x}-{:#x}",
            min_addr,
            max_addr
        ),
        Err(e) => log::error!("Failed to reserve EL2 page tables: {:?}", e),
    }
}
