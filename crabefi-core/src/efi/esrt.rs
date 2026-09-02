//! Boot-side ESRT registration into image-owned runtime storage.

use crabefi_runtime_abi::EsrtRegistration;
use r_efi::efi::Guid;

use crate::{
    efi::capsule::{CapsuleResultStatus, header::CAPSULE_FLAGS_PERSIST_ACROSS_RESET},
    platform::FirmwareInfo,
};

pub const EFI_SYSTEM_RESOURCE_TABLE_GUID: Guid = Guid::from_fields(
    0xB122A263,
    0x3661,
    0x4F68,
    0x99,
    0x29,
    &[0x78, 0xF8, 0xB0, 0xD6, 0x21, 0x80],
);

pub const ESRT_FW_TYPE_SYSTEM_FIRMWARE: u32 = 1;
pub const LAST_ATTEMPT_STATUS_SUCCESS: u32 = 0;
pub const LAST_ATTEMPT_STATUS_ERROR_UNSUCCESSFUL: u32 = 1;
pub const LAST_ATTEMPT_STATUS_ERROR_INCORRECT_VERSION: u32 = 3;
pub const LAST_ATTEMPT_STATUS_ERROR_INVALID_FORMAT: u32 = 4;
pub const LAST_ATTEMPT_STATUS_ERROR_AUTH_ERROR: u32 = 5;

/// Copy value-only firmware metadata into runtime-image ESRT storage.
pub fn install_esrt(firmware: &FirmwareInfo, capsule_delivery_usable: bool) {
    let Some(client) = crate::state::runtime_image() else {
        log::error!("Cannot install ESRT before runtime image activation");
        return;
    };
    let (last_attempt_version, last_attempt_status) =
        crate::efi::capsule::result::load_last_attempt()
            .map_or((0, LAST_ATTEMPT_STATUS_SUCCESS), |(version, status)| {
                (version, esrt_status(status))
            });
    let registration = EsrtRegistration {
        firmware_guid: firmware.guid,
        firmware_version: firmware.version,
        lowest_supported_version: firmware.lowest_supported_version,
        capsule_flags: if capsule_delivery_usable {
            CAPSULE_FLAGS_PERSIST_ACROSS_RESET
        } else {
            0
        },
        last_attempt_version,
        last_attempt_status,
        reserved: 0,
    };
    match client.install_esrt(&registration) {
        Ok(()) => log::info!(
            "ESRT installed: version={:#x}, LSV={:#x}, last_attempt={:#x}/{:#x}",
            firmware.version,
            firmware.lowest_supported_version,
            last_attempt_version,
            last_attempt_status
        ),
        Err(status) => log::error!("Runtime image rejected ESRT: {:?}", status),
    }
}

const fn esrt_status(status: CapsuleResultStatus) -> u32 {
    match status {
        CapsuleResultStatus::Success => LAST_ATTEMPT_STATUS_SUCCESS,
        CapsuleResultStatus::ErrorVersionTooLow => LAST_ATTEMPT_STATUS_ERROR_INCORRECT_VERSION,
        CapsuleResultStatus::ErrorInvalidImage => LAST_ATTEMPT_STATUS_ERROR_INVALID_FORMAT,
        CapsuleResultStatus::ErrorAuthFailed => LAST_ATTEMPT_STATUS_ERROR_AUTH_ERROR,
        CapsuleResultStatus::Error
        | CapsuleResultStatus::ErrorUnsupported
        | CapsuleResultStatus::ErrorFlashWriteFailed => LAST_ATTEMPT_STATUS_ERROR_UNSUCCESSFUL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_capsule_results_to_standard_esrt_statuses() {
        assert_eq!(CAPSULE_FLAGS_PERSIST_ACROSS_RESET, 0x0001_0000);
        assert_eq!(esrt_status(CapsuleResultStatus::Success), 0);
        assert_eq!(
            esrt_status(CapsuleResultStatus::ErrorVersionTooLow),
            LAST_ATTEMPT_STATUS_ERROR_INCORRECT_VERSION
        );
        assert_eq!(
            esrt_status(CapsuleResultStatus::ErrorInvalidImage),
            LAST_ATTEMPT_STATUS_ERROR_INVALID_FORMAT
        );
        assert_eq!(
            esrt_status(CapsuleResultStatus::ErrorAuthFailed),
            LAST_ATTEMPT_STATUS_ERROR_AUTH_ERROR
        );
        assert_eq!(
            esrt_status(CapsuleResultStatus::ErrorFlashWriteFailed),
            LAST_ATTEMPT_STATUS_ERROR_UNSUCCESSFUL
        );
    }
}
