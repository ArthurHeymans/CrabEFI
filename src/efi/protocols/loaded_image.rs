//! EFI Loaded Image Protocol
//!
//! This module provides the EFI_LOADED_IMAGE_PROTOCOL which allows loaded images
//! to query information about themselves (base address, size, etc.).

use core::ffi::c_void;
use r_efi::efi::{Guid, Handle, Status, SystemTable};
use r_efi::protocols::device_path::Protocol as DevicePathProtocol;
use r_efi::protocols::loaded_image;

/// Re-export the GUID for external use
pub const LOADED_IMAGE_PROTOCOL_GUID: Guid = loaded_image::PROTOCOL_GUID;

/// Unload callback - not supported
extern "efiapi" fn unload_image(_image_handle: Handle) -> Status {
    Status::UNSUPPORTED
}

/// Create a new Loaded Image Protocol instance for a loaded EFI application
///
/// # Arguments
/// * `parent_handle` - Handle of the image that loaded this image (firmware image handle)
/// * `system_table` - Pointer to the EFI system table
/// * `device_handle` - Handle of the device the image was loaded from
/// * `image_base` - Base address where the image is loaded
/// * `image_size` - Size of the loaded image in bytes
///
/// # Returns
/// A boxed LoadedImageProtocol instance (leaked for static lifetime)
pub fn create_loaded_image_protocol(
    parent_handle: Handle,
    system_table: *mut SystemTable,
    device_handle: Handle,
    image_base: u64,
    image_size: u64,
) -> *mut loaded_image::Protocol {
    // We allocate this using the EFI allocator and leak it
    // In a real implementation, this would be freed when the image is unloaded
    use crate::efi::utils::allocate_protocol_with_log;

    let ptr = allocate_protocol_with_log::<loaded_image::Protocol>("LoadedImageProtocol", |p| {
        p.revision = loaded_image::REVISION;
        p.parent_handle = parent_handle;
        p.system_table = system_table;
        p.device_handle = device_handle;
        p.file_path = core::ptr::null_mut(); // TODO: Create device path
        p.reserved = core::ptr::null_mut();
        p.load_options_size = 0;
        p.load_options = core::ptr::null_mut();
        p.image_base = image_base as *mut c_void;
        p.image_size = image_size;
        p.image_code_type = r_efi::efi::LOADER_CODE;
        p.image_data_type = r_efi::efi::LOADER_DATA;
        p.unload = Some(unload_image);
    });
    if ptr.is_null() {
        return ptr;
    }

    log::debug!(
        "Created LoadedImageProtocol: base={:#x}, size={:#x}, device_handle={:?}",
        image_base,
        image_size,
        device_handle
    );

    if device_handle.is_null() {
        log::warn!(
            "LoadedImageProtocol: DeviceHandle is NULL - bootloader won't be able to access boot device!"
        );
    }

    ptr
}

/// Set load options on a loaded image protocol
///
/// # Safety
/// The protocol pointer must be valid and the options buffer must remain valid
/// for the lifetime of the loaded image.
pub unsafe fn set_load_options(
    protocol: *mut loaded_image::Protocol,
    options: *mut c_void,
    options_size: u32,
) {
    if !protocol.is_null() {
        (*protocol).load_options = options;
        (*protocol).load_options_size = options_size;
    }
}

/// Set the file path on a loaded image protocol
///
/// # Safety
/// The protocol and device_path pointers must be valid.
pub unsafe fn set_file_path(
    protocol: *mut loaded_image::Protocol,
    device_path: *mut DevicePathProtocol,
) {
    if !protocol.is_null() {
        (*protocol).file_path = device_path;
    }
}
