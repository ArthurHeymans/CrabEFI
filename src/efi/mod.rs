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

    // Create console handles and install protocols
    init_console();

    log::info!("EFI environment initialized");
}

/// Initialize console I/O
fn init_console() {
    use protocols::console::{
        get_text_input_protocol, get_text_output_protocol, SIMPLE_TEXT_INPUT_PROTOCOL_GUID,
        SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID,
    };

    // Create console handle
    let console_handle = match boot_services::create_handle() {
        Some(h) => h,
        None => {
            log::error!("Failed to create console handle");
            return;
        }
    };

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

    log::debug!("Console protocols installed");
}

/// Get the EFI system table pointer
pub fn get_system_table() -> *mut efi::SystemTable {
    system_table::get_system_table_efi()
}
