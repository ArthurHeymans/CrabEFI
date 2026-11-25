//! Runtime Services table entries that switch to the private stack on x86-64.
//!
//! Only `SetVirtualAddressMap` and `SetVariable` exceed the 4 KiB x64 UEFI
//! caller stack floor. All other services fit within the caller's stack and
//! are installed directly from [`crate::services`]. On AArch64 and RISC-V
//! [`crate::stack::run`] calls the service directly on the caller's stack.

use core::ffi::c_void;

use crate::{efi, services, stack};

fn busy() -> efi::Status {
    efi::Status::DEVICE_ERROR
}

pub extern "efiapi" fn set_virtual_address_map(
    memory_map_size: usize,
    descriptor_size: usize,
    descriptor_version: u32,
    virtual_map: *mut efi::MemoryDescriptor,
) -> efi::Status {
    stack::run(
        || {
            services::set_virtual_address_map(
                memory_map_size,
                descriptor_size,
                descriptor_version,
                virtual_map,
            )
        },
        busy,
    )
}

pub extern "efiapi" fn set_variable(
    variable_name: *mut u16,
    vendor_guid: *mut efi::Guid,
    attributes: u32,
    data_size: usize,
    data: *mut c_void,
) -> efi::Status {
    stack::run(
        || services::set_variable(variable_name, vendor_guid, attributes, data_size, data),
        busy,
    )
}
