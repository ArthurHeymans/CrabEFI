//! Boot-side ESRT registration into image-owned runtime storage.

use crabefi_runtime_abi::EsrtRegistration;
use r_efi::efi::Guid;

use crate::platform::FirmwareInfo;

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

/// Copy value-only firmware metadata into runtime-image ESRT storage.
pub fn install_esrt(firmware: &FirmwareInfo) {
    let Some(client) = crate::state::efi().runtime_image else {
        log::error!("Cannot install ESRT before runtime image activation");
        return;
    };
    let registration = EsrtRegistration {
        firmware_guid: firmware.guid,
        firmware_version: firmware.version,
        lowest_supported_version: firmware.lowest_supported_version,
        // No capsule range is configured, so no UpdateCapsule flags are advertised.
        capsule_flags: 0,
        last_attempt_version: 0,
        last_attempt_status: LAST_ATTEMPT_STATUS_SUCCESS,
        reserved: 0,
    };
    match client.install_esrt(&registration) {
        Ok(()) => log::info!(
            "ESRT installed: version={:#x}, LSV={:#x}",
            firmware.version,
            firmware.lowest_supported_version
        ),
        Err(status) => log::error!("Runtime image rejected ESRT: {:?}", status),
    }
}
