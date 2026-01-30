//! EFI utility functions
//!
//! Common utility functions used across EFI modules.

use crate::efi::allocator::{MemoryType, allocate_pool};

/// Allocate and initialize a protocol structure
///
/// This helper function allocates memory for a protocol structure of type `T`
/// and initializes it using the provided closure.
///
/// # Arguments
/// * `init` - Closure that initializes the protocol structure
///
/// # Returns
/// A pointer to the initialized protocol structure, or null on allocation failure
///
/// # Example
/// ```ignore
/// let ptr = allocate_protocol(|p| {
///     p.revision = PROTOCOL_REVISION;
///     p.reset = my_reset_fn;
///     p.read = my_read_fn;
/// });
/// ```
pub fn allocate_protocol<T>(init: impl FnOnce(&mut T)) -> *mut T {
    let size = core::mem::size_of::<T>();
    let ptr = match allocate_pool(MemoryType::BootServicesData, size) {
        Ok(p) => p as *mut T,
        Err(_) => return core::ptr::null_mut(),
    };

    // SAFETY: We just allocated this memory and have exclusive access
    unsafe {
        // Zero-initialize for safety
        core::ptr::write_bytes(ptr, 0, 1);
        init(&mut *ptr);
    }

    ptr
}

/// Allocate and initialize a protocol structure with logging
///
/// Same as `allocate_protocol` but logs an error message on failure.
///
/// # Arguments
/// * `name` - Protocol name for error logging
/// * `init` - Closure that initializes the protocol structure
///
/// # Returns
/// A pointer to the initialized protocol structure, or null on allocation failure
pub fn allocate_protocol_with_log<T>(name: &str, init: impl FnOnce(&mut T)) -> *mut T {
    let ptr = allocate_protocol(init);
    if ptr.is_null() {
        log::error!("Failed to allocate {}", name);
    }
    ptr
}
