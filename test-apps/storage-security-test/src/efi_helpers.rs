//! EFI Boot Services helper functions
//!
//! This module provides wrappers around common Boot Services operations.

use core::ffi::c_void;
use r_efi::efi::{Guid, Handle, Status};

use crate::boot_services;

/// Locate handles that support a given protocol
///
/// Returns zero only when the protocol is absent; enumeration errors propagate.
/// The caller supplies bounded storage (currently 16 handles per probe).
/// Exceeding it fails rather than silently claiming an incomplete probe passed.
pub fn locate_handle_buffer(protocol: &Guid, handles: &mut [Handle]) -> Result<usize, Status> {
    let bs = boot_services();
    if bs.is_null() {
        return Err(Status::DEVICE_ERROR);
    }

    // First, get the buffer size needed
    let mut buffer_size = (handles.len() * core::mem::size_of::<Handle>()) as usize;

    let status = unsafe {
        ((*bs).locate_handle)(
            r_efi::efi::BY_PROTOCOL,
            protocol as *const Guid as *mut Guid,
            core::ptr::null_mut(),
            &mut buffer_size,
            handles.as_mut_ptr(),
        )
    };

    if status == Status::NOT_FOUND {
        return Ok(0);
    }
    if status != Status::SUCCESS {
        return Err(status);
    }
    let handle_size = core::mem::size_of::<Handle>();
    if !buffer_size.is_multiple_of(handle_size) || buffer_size > core::mem::size_of_val(handles) {
        return Err(Status::COMPROMISED_DATA);
    }
    Ok(buffer_size / handle_size)
}

/// Open a protocol on a handle
///
/// Returns a pointer to the protocol interface, or null on failure.
pub fn open_protocol<T>(handle: Handle, protocol: &Guid) -> *mut T {
    let bs = boot_services();
    if bs.is_null() {
        return core::ptr::null_mut();
    }

    let mut interface: *mut c_void = core::ptr::null_mut();

    let status = unsafe {
        ((*bs).open_protocol)(
            handle,
            protocol as *const Guid as *mut Guid,
            &mut interface,
            core::ptr::null_mut(), // Agent handle - not needed for GET_PROTOCOL
            core::ptr::null_mut(), // Controller handle
            0x00000002,            // EFI_OPEN_PROTOCOL_GET_PROTOCOL
        )
    };

    if status == Status::SUCCESS {
        interface as *mut T
    } else {
        core::ptr::null_mut()
    }
}

/// Obtain the public media ID for an active device-security transfer.
#[cfg(feature = "hardware-security-probes")]
pub fn media_id(handle: Handle) -> Result<u32, Status> {
    use r_efi::protocols::block_io;
    let protocol: *mut block_io::Protocol = open_protocol(handle, &block_io::PROTOCOL_GUID);
    if protocol.is_null() {
        crate::console().print_line("    Active probe requires Block I/O on the security handle");
        return Err(Status::DEVICE_ERROR);
    }
    // SAFETY: OpenProtocol returned the interface; its media record is firmware-owned.
    let media = unsafe { (*protocol).media };
    let result = if media.is_null() {
        Err(Status::COMPROMISED_DATA)
    } else {
        Ok(unsafe { (*media).media_id })
    };
    close_protocol(handle, &block_io::PROTOCOL_GUID);
    result
}

/// Close a protocol on a handle
pub fn close_protocol(handle: Handle, protocol: &Guid) {
    let bs = boot_services();
    if bs.is_null() {
        return;
    }

    unsafe {
        ((*bs).close_protocol)(
            handle,
            protocol as *const Guid as *mut Guid,
            core::ptr::null_mut(), // Agent handle
            core::ptr::null_mut(), // Controller handle
        );
    }
}

/// Allocate pool memory
pub fn allocate_pool(size: usize) -> *mut u8 {
    let bs = boot_services();
    if bs.is_null() {
        return core::ptr::null_mut();
    }

    let mut buffer: *mut c_void = core::ptr::null_mut();

    let status = unsafe { ((*bs).allocate_pool)(r_efi::efi::LOADER_DATA, size, &mut buffer) };

    if status == Status::SUCCESS {
        buffer as *mut u8
    } else {
        core::ptr::null_mut()
    }
}

/// Free pool memory
pub fn free_pool(buffer: *mut u8) {
    let bs = boot_services();
    if bs.is_null() || buffer.is_null() {
        return;
    }

    unsafe {
        ((*bs).free_pool)(buffer as *mut c_void);
    }
}
