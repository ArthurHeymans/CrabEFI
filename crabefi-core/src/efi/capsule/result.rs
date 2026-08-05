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

use crabefi_runtime_abi::capsule::ESRT_LAST_ATTEMPT_VARIABLE_NAME;
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

const LAST_ATTEMPT_RECORD_VERSION: u32 = 1;

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
    /// Whether this attempt targeted the firmware resource advertised by ESRT.
    pub(crate) updates_esrt: bool,
}

impl CapsuleResult {
    /// Create a success result.
    pub fn success(version: u32) -> Self {
        Self {
            status: CapsuleResultStatus::Success,
            capsule_version: version,
            updates_esrt: true,
        }
    }

    /// Create a failure result for the ESRT firmware resource.
    pub fn failure(status: CapsuleResultStatus, version: u32) -> Self {
        Self {
            status,
            capsule_version: version,
            updates_esrt: true,
        }
    }

    /// Create a capsule report that must not change firmware-resource state.
    pub(crate) fn report_only(status: CapsuleResultStatus) -> Self {
        Self {
            status,
            capsule_version: 0,
            updates_esrt: false,
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
    use crate::efi::runtime_image::client::variables;

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

    let status = variables::set(&EFI_CAPSULE_REPORT_GUID, &name_u16, attributes, &data);
    if status == r_efi::efi::Status::SUCCESS {
        log::info!(
            "Recorded capsule result: {} -> {:?}",
            name_str,
            result.status
        );
    } else {
        log::warn!(
            "Failed to record capsule result for index {}: {:?}",
            index,
            status
        );
    }

    if result.updates_esrt {
        let attempt = encode_last_attempt(result);
        if let Err(error) = crate::efi::varstore::persistence::persist_firmware_variable(
            &EFI_CAPSULE_REPORT_GUID,
            ESRT_LAST_ATTEMPT_VARIABLE_NAME,
            attributes,
            &attempt,
        ) {
            log::warn!("Failed to persist ESRT last-attempt state: {:?}", error);
        }
    }
}

fn encode_last_attempt(result: &CapsuleResult) -> [u8; 12] {
    let mut record = [0u8; 12];
    record[..4].copy_from_slice(&LAST_ATTEMPT_RECORD_VERSION.to_le_bytes());
    record[4..8].copy_from_slice(&result.capsule_version.to_le_bytes());
    record[8..12].copy_from_slice(&(result.status as u32).to_le_bytes());
    record
}

fn decode_last_attempt(record: &[u8]) -> Option<(u32, CapsuleResultStatus)> {
    if record.len() != 12
        || u32::from_le_bytes(record[..4].try_into().ok()?) != LAST_ATTEMPT_RECORD_VERSION
    {
        return None;
    }
    let version = u32::from_le_bytes(record[4..8].try_into().ok()?);
    let status = match u32::from_le_bytes(record[8..12].try_into().ok()?) {
        0 => CapsuleResultStatus::Success,
        1 => CapsuleResultStatus::Error,
        2 => CapsuleResultStatus::ErrorAuthFailed,
        3 => CapsuleResultStatus::ErrorInvalidImage,
        4 => CapsuleResultStatus::ErrorUnsupported,
        5 => CapsuleResultStatus::ErrorFlashWriteFailed,
        6 => CapsuleResultStatus::ErrorVersionTooLow,
        _ => return None,
    };
    Some((version, status))
}

pub(crate) fn load_last_attempt() -> Option<(u32, CapsuleResultStatus)> {
    let (_, record) = crate::efi::runtime_image::client::variables::get(
        &EFI_CAPSULE_REPORT_GUID,
        ESRT_LAST_ATTEMPT_VARIABLE_NAME,
    )?;
    decode_last_attempt(&record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_report_guid_matches_runtime_protection_policy() {
        assert_eq!(
            EFI_CAPSULE_REPORT_GUID.as_bytes(),
            &crabefi_runtime_abi::capsule::CAPSULE_REPORT_VARIABLE_GUID
        );
    }

    #[test]
    fn non_firmware_capsule_reports_do_not_update_esrt() {
        let result = CapsuleResult::report_only(CapsuleResultStatus::Success);
        assert!(!result.updates_esrt);
        assert_eq!(result.capsule_version, 0);
    }

    #[test]
    fn last_attempt_record_round_trips_version_and_status() {
        for status in [
            CapsuleResultStatus::Success,
            CapsuleResultStatus::Error,
            CapsuleResultStatus::ErrorAuthFailed,
            CapsuleResultStatus::ErrorInvalidImage,
            CapsuleResultStatus::ErrorUnsupported,
            CapsuleResultStatus::ErrorFlashWriteFailed,
            CapsuleResultStatus::ErrorVersionTooLow,
        ] {
            let result = CapsuleResult::failure(status, 0x1234_5678);
            assert_eq!(
                decode_last_attempt(&encode_last_attempt(&result)),
                Some((0x1234_5678, status))
            );
        }
        assert_eq!(decode_last_attempt(&[0; 12]), None);
        assert_eq!(decode_last_attempt(&[0; 11]), None);
    }
}
