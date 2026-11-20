//! The Runtime Services table entries.
//!
//! Each entry runs its service on the image's private stack (see
//! [`crate::stack`]), so a caller only needs the stack UEFI guarantees. If
//! another service already runs on that stack, the entry answers on the
//! caller's stack without touching shared state: ResetSystem resets, and
//! every other service reports a device error, as UEFI does not allow it to
//! be reentered.

use core::ffi::c_void;

use crate::{efi, services, stack};

fn busy() -> efi::Status {
    efi::Status::DEVICE_ERROR
}

pub extern "efiapi" fn get_time(
    time: *mut efi::Time,
    capabilities: *mut efi::TimeCapabilities,
) -> efi::Status {
    stack::run(|| services::get_time(time, capabilities), busy)
}

pub extern "efiapi" fn set_time(time: *mut efi::Time) -> efi::Status {
    stack::run(|| services::set_time(time), busy)
}

pub extern "efiapi" fn get_wakeup_time(
    enabled: *mut efi::Boolean,
    pending: *mut efi::Boolean,
    time: *mut efi::Time,
) -> efi::Status {
    stack::run(|| services::get_wakeup_time(enabled, pending, time), busy)
}

pub extern "efiapi" fn set_wakeup_time(enable: efi::Boolean, time: *mut efi::Time) -> efi::Status {
    stack::run(|| services::set_wakeup_time(enable, time), busy)
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

pub extern "efiapi" fn convert_pointer(
    debug_disposition: usize,
    address: *mut *mut c_void,
) -> efi::Status {
    stack::run(
        || services::convert_pointer(debug_disposition, address),
        busy,
    )
}

pub extern "efiapi" fn get_variable(
    variable_name: *mut u16,
    vendor_guid: *mut efi::Guid,
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut c_void,
) -> efi::Status {
    stack::run(
        || services::get_variable(variable_name, vendor_guid, attributes, data_size, data),
        busy,
    )
}

pub extern "efiapi" fn get_next_variable_name(
    variable_name_size: *mut usize,
    variable_name: *mut u16,
    vendor_guid: *mut efi::Guid,
) -> efi::Status {
    stack::run(
        || services::get_next_variable_name(variable_name_size, variable_name, vendor_guid),
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

pub extern "efiapi" fn get_next_high_mono_count(high_count: *mut u32) -> efi::Status {
    stack::run(|| services::get_next_high_mono_count(high_count), busy)
}

pub extern "efiapi" fn reset_system(
    reset_type: efi::ResetType,
    reset_status: efi::Status,
    data_size: usize,
    reset_data: *mut c_void,
) {
    // Resetting needs no shared state, so a reentrant reset still resets.
    let reset = || services::reset_system(reset_type, reset_status, data_size, reset_data);
    stack::run(reset, reset)
}

pub extern "efiapi" fn update_capsule(
    capsule_header_array: *mut *mut efi::CapsuleHeader,
    capsule_count: usize,
    scatter_gather_list: efi::PhysicalAddress,
) -> efi::Status {
    stack::run(
        || services::update_capsule(capsule_header_array, capsule_count, scatter_gather_list),
        busy,
    )
}

pub extern "efiapi" fn query_capsule_capabilities(
    capsule_header_array: *mut *mut efi::CapsuleHeader,
    capsule_count: usize,
    maximum_capsule_size: *mut u64,
    reset_type: *mut efi::ResetType,
) -> efi::Status {
    stack::run(
        || {
            services::query_capsule_capabilities(
                capsule_header_array,
                capsule_count,
                maximum_capsule_size,
                reset_type,
            )
        },
        busy,
    )
}

pub extern "efiapi" fn query_variable_info(
    attributes: u32,
    maximum_variable_storage_size: *mut u64,
    remaining_variable_storage_size: *mut u64,
    maximum_variable_size: *mut u64,
) -> efi::Status {
    stack::run(
        || {
            services::query_variable_info(
                attributes,
                maximum_variable_storage_size,
                remaining_variable_storage_size,
                maximum_variable_size,
            )
        },
        busy,
    )
}
