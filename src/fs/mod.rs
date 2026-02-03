//! Filesystem support
//!
//! This module provides FAT, GPT, and ISO9660/El Torito support for reading
//! the EFI System Partition and booting from installation media.

pub mod fat;
pub mod gpt;
pub mod iso9660;

/// Convert a Linux-style path (forward slashes) to FAT-style path (backslashes)
///
/// - Strips leading slash
/// - Converts forward slashes to backslashes
/// - Rejects paths containing ".." (directory traversal)
///
/// # Arguments
///
/// * `path` - Linux-style path (e.g., "/boot/vmlinuz-linux")
///
/// # Returns
///
/// FAT-style path (e.g., "boot\\vmlinuz-linux") or an error if the path is invalid
pub fn linux_path_to_fat(path: &str) -> Result<heapless::String<128>, PathConversionError> {
    // Reject directory traversal attempts
    if path.contains("..") {
        return Err(PathConversionError::DirectoryTraversal);
    }

    let mut fat_path: heapless::String<128> = heapless::String::new();

    // Strip leading slash
    let path = path.trim_start_matches('/');

    // Convert forward slashes to backslashes
    for c in path.chars() {
        if c == '/' {
            fat_path
                .push('\\')
                .map_err(|_| PathConversionError::PathTooLong)?;
        } else {
            fat_path
                .push(c)
                .map_err(|_| PathConversionError::PathTooLong)?;
        }
    }

    Ok(fat_path)
}

/// Errors that can occur during path conversion
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathConversionError {
    /// Path contains ".." which could be a directory traversal attack
    DirectoryTraversal,
    /// Path is too long (exceeds 128 characters)
    PathTooLong,
}
