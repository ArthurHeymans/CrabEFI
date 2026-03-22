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

use crate::coreboot::tables::CorebootInfo;
use r_efi::efi::{self, Status};

/// Initialize the EFI environment
///
/// This sets up the system table, boot services, runtime services, and
/// installs the console protocols.
pub fn init(cb_info: &CorebootInfo) {
    log::info!("Initializing EFI environment...");

    // Initialize the memory allocator from coreboot memory map
    allocator::init(&cb_info.memory_map);

    // NOTE: Platform MMIO regions (GIC, UART, PCIe) are NOT added here.
    // They are added later by add_platform_mmio_regions() after ACPI table
    // discovery has run, so the addresses come from ACPI/FDT instead of
    // being hardcoded.

    // Reserve the EL2 MMU page table memory so the allocator doesn't hand it
    // out. Coreboot set up page tables starting at TTBR0_EL2 and we're still
    // using them — if they get overwritten, the MMU faults and we crash.
    #[cfg(target_arch = "aarch64")]
    reserve_el2_page_tables();

    // Reserve the runtime services memory regions using linker-provided boundaries.
    // This marks CrabEFI's code and data sections as EfiRuntimeServicesCode/Data
    // with EFI_MEMORY_RUNTIME attribute, which tells the OS to keep these regions
    // mapped after ExitBootServices.
    allocator::reserve_runtime_region();

    // Initialize system table with boot and runtime services
    unsafe {
        system_table::init(
            boot_services::get_boot_services(),
            runtime_services::get_runtime_services(),
        );
    }

    // Install ACPI tables if available
    if let Some(rsdp) = cb_info.acpi_rsdp {
        system_table::install_acpi_tables(rsdp);
    } else {
        log::warn!("No ACPI RSDP from coreboot - Linux may not have ACPI support!");
    }

    // Install SMBIOS tables if available
    if let Some(smbios) = cb_info.smbios {
        system_table::install_smbios_tables(smbios);
    } else {
        log::debug!("No SMBIOS tables from coreboot");
    }

    // Install device tree (FDT) if available
    if let Some((fdt_addr, fdt_size)) = cb_info.devicetree {
        system_table::install_devicetree(fdt_addr, fdt_size);
    }

    // Install EFI Runtime Properties Table (UEFI 2.8+)
    // This tells Linux which runtime services are supported.
    // Required for efi_pstore, efivars, and other kernel modules.
    system_table::install_rt_properties_table();

    // Install minimal TPM2 event log tables
    // Prevents kernel errors about failing to map ACPI memory for TPM log
    system_table::install_tpm_event_log();

    // Create console handle - this will also have GOP installed on it
    let console_handle = init_console();

    // Install Graphics Output protocol on the SAME handle as console
    // This is important - GRUB expects GOP and ConOut on the same handle
    if let Some(fb) = cb_info.framebuffer {
        if let Some(handle) = console_handle {
            init_graphics_output_on_handle(&fb, handle);
        }
        // Initialize EFI console framebuffer output (bootloader text goes here too)
        protocols::console::init_framebuffer(fb);
    }

    // Install Unicode Collation protocol
    init_unicode_collation();

    // Install Memory Attribute protocol
    init_memory_attribute();

    // Install Serial IO protocol
    init_serial_io();

    // Install RNG protocol (if RDRAND is available)
    init_rng();

    // Install Console Control protocol (legacy, but some bootloaders need it)
    init_console_control();

    // Install EFI Memory Attributes Table
    // Linux and Windows use this to set proper page permissions for runtime regions
    system_table::install_memory_attributes_table();

    // Dump configuration tables for debugging
    system_table::dump_configuration_tables();

    // Compute CRC32 checksums for all EFI table headers.
    // Must be done after all configuration tables and protocols are installed.
    system_table::update_crc32();

    log::info!("EFI environment initialized");
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

/// Initialize Graphics Output Protocol (GOP) on a specific handle
/// Installing GOP on the same handle as ConOut is important for GRUB compatibility
fn init_graphics_output_on_handle(
    framebuffer: &crate::coreboot::FramebufferInfo,
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
/// - GIC distributor/redistributor (for interrupts)
/// - UART PL011 (for earlycon/console)  
/// - Peripherals (RTC, GPIO, etc.)
/// - PCIe MMIO windows (for PCI device access)
#[cfg(target_arch = "aarch64")]
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

    // Platform info: FDT takes priority, ACPI fills gaps.
    // No hardcoded fallbacks — all addresses come from firmware tables.
    let fdt = crate::state::drivers().fdt_info;
    let acpi = crate::state::drivers().acpi_info;

    // GIC — from FDT, then ACPI MADT
    let gicd = fdt.gicd.or(acpi.gicd);
    let gicr = fdt.gicr.or(acpi.gicr);

    if let Some((base, size)) = gicd {
        let total = if let Some((rb, rsize)) = gicr {
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
        add_mmio(base, total, "GIC");
    }

    // Peripherals — derive from UART base (ACPI SPCR or FDT)
    // On SBSA, the peripherals (UART, RTC, GPIO, AHCI, EHCI) are in a 2MB
    // block starting at the UART base address.
    let uart_base = fdt.uart_base.or(acpi.uart_base);
    if let Some(base) = uart_base {
        add_mmio(base, 0x20_0000, "Peripherals (UART/RTC/GPIO/AHCI/EHCI)");
    }

    // PCIe PIO
    if let Some((base, size)) = fdt.pcie_pio.or(acpi.pcie_pio) {
        add_mmio(base, size, "PCIe PIO");
    }

    // PCIe 32-bit MMIO
    if let Some((base, size)) = fdt.pcie_mmio32.or(acpi.pcie_mmio32) {
        add_mmio(base, size, "PCIe MMIO32");
    }

    // PCIe 64-bit MMIO
    if let Some((base, size)) = fdt.pcie_mmio64.or(acpi.pcie_mmio64) {
        add_mmio(base, size, "PCIe MMIO64");
    }

    // PCIe ECAM — from FDT or ACPI MCFG
    if let Some(base) = fdt.ecam_base.or(acpi.ecam_base)
        && let Some(size) = fdt.ecam_size.or(acpi.ecam_size)
    {
        add_mmio(base, size, "PCIe ECAM");
    }
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
