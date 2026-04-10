//! Capsule Result Variable Generation
//!
//! After capsule application, the firmware records the result in EFI variables
//! so the OS can query what happened.
//!
//! # Variable Format
//!
//! Result variables are named `Capsule####` (where #### is a hex index) under
//! the `EFI_CAPSULE_REPORT_GUID` namespace.
//!
//! # References
//!
//! - UEFI Specification 2.10, Section 8.5.5 — Capsule Result Variable

use r_efi::efi::Guid;

/// EFI Capsule Report GUID (vendor GUID for Capsule#### variables).
pub const EFI_CAPSULE_REPORT_GUID: Guid = Guid::from_fields(
    0x39B68C46,
    0xF7FB,
    0x441B,
    0xB6,
    0xEC,
    &[0x16, 0xB0, 0xF6, 0x98, 0x21, 0xF3],
);

/// Capsule application result status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CapsuleResultStatus {
    /// Capsule was applied successfully.
    Success = 0,
    /// Generic error.
    Error = 1,
    /// Authentication / signature verification failed.
    ErrorAuthFailed = 2,
    /// Invalid capsule image.
    ErrorInvalidImage = 3,
    /// Capsule type not supported.
    ErrorUnsupported = 4,
    /// Flash write operation failed.
    ErrorFlashWriteFailed = 5,
    /// Firmware version is below the lowest supported version.
    ErrorVersionTooLow = 6,
}

/// Result of a capsule application attempt.
#[derive(Debug, Clone)]
pub struct CapsuleResult {
    /// Overall status.
    pub status: CapsuleResultStatus,
    /// Firmware version that was attempted (from the capsule).
    pub capsule_version: u32,
}

impl CapsuleResult {
    /// Create a success result.
    pub fn success(version: u32) -> Self {
        Self {
            status: CapsuleResultStatus::Success,
            capsule_version: version,
        }
    }

    /// Create a failure result.
    pub fn failure(status: CapsuleResultStatus, version: u32) -> Self {
        Self {
            status,
            capsule_version: version,
        }
    }
}

/// Record a capsule result as an EFI variable.
///
/// Creates or updates a `Capsule####` variable in the capsule report
/// namespace. The variable contains a serialized result header.
///
/// # Arguments
///
/// - `index`: The capsule index (0, 1, 2, ...).
/// - `result`: The capsule application result.
pub fn record_capsule_result(index: usize, result: &CapsuleResult) {
    use crate::efi::varstore;

    // Build variable name: "Capsule####" in UTF-16
    let name_str = alloc::format!("Capsule{:04X}", index);
    let mut name_u16: alloc::vec::Vec<u16> = name_str.encode_utf16().collect();
    name_u16.push(0); // null terminator

    // Build the result variable data
    // EFI_CAPSULE_RESULT_VARIABLE_HEADER:
    //   VariableTotalSize: u32
    //   Reserved: u32
    //   CapsuleGuid: [u8; 16]
    //   CapsuleProcessed: EFI_TIME (unused, zeroed)
    //   CapsuleStatus: u32
    let total_size: u32 = 4 + 4 + 16 + 16 + 4; // 44 bytes
    let mut data = alloc::vec![0u8; total_size as usize];

    // VariableTotalSize
    data[0..4].copy_from_slice(&total_size.to_le_bytes());
    // Reserved = 0 (already zeroed)
    // CapsuleGuid = zeroed (we don't track per-capsule GUID here)
    // CapsuleProcessed = zeroed EFI_TIME
    // CapsuleStatus
    let status_offset = (total_size - 4) as usize;
    data[status_offset..status_offset + 4].copy_from_slice(&(result.status as u32).to_le_bytes());

    // Attributes: NV + BS + RT
    let attributes = 0x07u32; // NV | BS | RT

    // Write the variable
    if let Err(e) =
        varstore::persist_variable(&EFI_CAPSULE_REPORT_GUID, &name_u16, attributes, &data)
    {
        log::warn!(
            "Failed to record capsule result for index {}: {:?}",
            index,
            e
        );
    } else {
        log::info!(
            "Recorded capsule result: {} -> {:?}",
            name_str,
            result.status
        );
    }

    // Also update in-memory cache
    varstore::update_variable_in_memory(&EFI_CAPSULE_REPORT_GUID, &name_u16, attributes, &data);
}
