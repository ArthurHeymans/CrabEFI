//! EFI utility functions
//!
//! Common utility functions used across EFI modules.

use r_efi::efi::Guid;

/// Compare two GUIDs for equality
///
/// This function compares two UEFI GUIDs by treating them as 16-byte arrays.
/// The comparison is done byte-by-byte which handles any potential alignment
/// or representation differences.
///
/// # Arguments
/// * `a` - First GUID to compare
/// * `b` - Second GUID to compare
///
/// # Returns
/// `true` if the GUIDs are equal, `false` otherwise
///
/// # Safety
/// This function uses unsafe code to reinterpret the GUIDs as byte arrays.
/// This is safe because:
/// 1. Guid is a repr(C) struct with a fixed 16-byte size
/// 2. We only read the bytes, never write
/// 3. The slice lifetime is bounded by the function scope
pub fn guid_eq(a: &Guid, b: &Guid) -> bool {
    // SAFETY: Guid is a 16-byte repr(C) struct. Creating a byte slice from it
    // is safe as long as we don't outlive the reference, which we don't.
    let a_bytes = unsafe { core::slice::from_raw_parts(a as *const Guid as *const u8, 16) };
    let b_bytes = unsafe { core::slice::from_raw_parts(b as *const Guid as *const u8, 16) };
    a_bytes == b_bytes
}
