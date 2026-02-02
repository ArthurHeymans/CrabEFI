//! EFI utility functions
//!
//! Common utility functions used across EFI modules.

use crate::efi::allocator::{allocate_pool, MemoryType};

// ============================================================================
// UCS-2 String Utilities
// ============================================================================

/// Get the effective length of a UCS-2 string slice (not including null terminator)
///
/// Returns the position of the first null terminator, or the slice length if no null found.
#[inline]
pub fn ucs2_len(s: &[u16]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

/// Compare two UCS-2 string slices for equality
///
/// Compares up to the first null terminator in each string.
/// This is the canonical implementation - all other name comparison functions
/// should delegate to this one.
///
/// # Examples
/// ```ignore
/// let a = [b'T' as u16, b'e' as u16, b's' as u16, b't' as u16, 0];
/// let b = [b'T' as u16, b'e' as u16, b's' as u16, b't' as u16, 0, 0, 0];
/// assert!(ucs2_eq(&a, &b));
/// ```
#[inline]
pub fn ucs2_eq(a: &[u16], b: &[u16]) -> bool {
    let a_len = ucs2_len(a);
    let b_len = ucs2_len(b);

    if a_len != b_len {
        return false;
    }

    a[..a_len] == b[..b_len]
}

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
