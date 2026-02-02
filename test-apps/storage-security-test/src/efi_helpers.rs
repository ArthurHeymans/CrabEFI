//! EFI Boot Services helper functions
//!
//! This module provides wrappers around common Boot Services operations.

use core::ffi::c_void;
use r_efi::efi::{Guid, Handle, Status};

use crate::boot_services;

/// Locate handles that support a given protocol
///
/// Returns a slice of handles, or an empty slice if none found.
/// The caller must provide a buffer to store the handles.
pub fn locate_handle_buffer(protocol: &Guid, handles: &mut [Handle]) -> usize {
    let bs = boot_services();
    if bs.is_null() {
        return 0;
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

    if status == Status::SUCCESS {
        buffer_size / core::mem::size_of::<Handle>()
    } else if status == Status::BUFFER_TOO_SMALL {
        // Buffer is too small - just return how many we could fit
        handles.len()
    } else {
        0
    }
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
