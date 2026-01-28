//! EFI system table and services
//!
//! This module provides the UEFI system table, boot services, and runtime services
//! implementations.

pub mod allocator;
pub mod boot_services;
pub mod protocols;
pub mod runtime_services;
pub mod system_table;

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
    }

    // Create console handle - this will also have GOP installed on it
    let console_handle = init_console();

    // Install Graphics Output protocol on the SAME handle as console
    // This is important - GRUB expects GOP and ConOut on the same handle
    if let Some(ref fb) = cb_info.framebuffer {
        if let Some(handle) = console_handle {
            init_graphics_output_on_handle(fb, handle);
        }
    }

    // Install Unicode Collation protocol
    init_unicode_collation();

    // Install Memory Attribute protocol
    init_memory_attribute();

    // Install Serial IO protocol
    init_serial_io();

    log::info!("EFI environment initialized");
}

/// Initialize console I/O
/// Returns the console handle so GOP can be installed on it
fn init_console() -> Option<efi::Handle> {
    use protocols::console::{
        get_text_input_protocol, get_text_output_protocol, SIMPLE_TEXT_INPUT_PROTOCOL_GUID,
        SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID,
    };
    use protocols::device_path::{create_video_device_path, DEVICE_PATH_PROTOCOL_GUID};

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
        get_protocol_void, UNICODE_COLLATION_PROTOCOL2_GUID, UNICODE_COLLATION_PROTOCOL_GUID,
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
    use protocols::memory_attribute::{create_protocol, MEMORY_ATTRIBUTE_PROTOCOL_GUID};

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
    use protocols::serial_io::{create_protocol, SERIAL_IO_PROTOCOL_GUID};

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

/// Initialize Graphics Output Protocol (GOP) on a specific handle
/// Installing GOP on the same handle as ConOut is important for GRUB compatibility
fn init_graphics_output_on_handle(
    framebuffer: &crate::coreboot::FramebufferInfo,
    handle: efi::Handle,
) {
    use protocols::graphics_output::{create_gop, GRAPHICS_OUTPUT_GUID};

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
/// Returns the physical address of the allocated pages, or None if allocation failed.
pub fn allocate_pages(num_pages: u64) -> Option<u64> {
    let mut addr = 0u64;
    let status = allocator::allocate_pages(
        allocator::AllocateType::AllocateAnyPages,
        allocator::MemoryType::BootServicesData,
        num_pages,
        &mut addr,
    );
    if status == Status::SUCCESS {
        Some(addr)
    } else {
        None
    }
}

/// Free previously allocated pages (convenience function for drivers)
pub fn free_pages(addr: u64, num_pages: u64) {
    let _ = allocator::free_pages(addr, num_pages);
}
