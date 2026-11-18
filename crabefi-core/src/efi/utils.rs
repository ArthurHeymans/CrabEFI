//! EFI utility functions
//!
//! Common utility functions used across EFI modules.

use crate::efi::allocator::{MemoryType, allocate_pool};

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

/// Move a fully initialized protocol value into the EFI pool.
///
/// The caller owns the allocation. Returns null on allocation failure or if
/// the pool cannot provide the alignment required by `T`.
pub fn allocate_protocol_value<T>(value: T) -> *mut T {
    let Ok(raw) = allocate_pool(MemoryType::BootServicesData, core::mem::size_of::<T>()) else {
        return core::ptr::null_mut();
    };
    let ptr = raw.cast::<T>();
    if !ptr.is_aligned() {
        let _ = crate::efi::allocator::free_pool(raw);
        return core::ptr::null_mut();
    }

    // SAFETY: The new pool allocation is exclusive, correctly aligned, and
    // large enough for T. Write the value without referring to uninitialized T.
    unsafe { ptr.write(value) };
    ptr
}

/// Like [`allocate_protocol_value`], but logs the protocol name on failure.
pub fn allocate_protocol_value_with_log<T>(name: &str, value: T) -> *mut T {
    let ptr = allocate_protocol_value(value);
    if ptr.is_null() {
        log::error!("Failed to allocate {}", name);
    }
    ptr
}
