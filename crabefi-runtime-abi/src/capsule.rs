//! Shared constants for private boot/runtime capsule handoffs.

/// Serialized size of an `EFI_CAPSULE_HEADER`.
pub const CAPSULE_HEADER_SIZE: usize = 28;

/// Capsule payload marker used as a defense-in-depth check for the retained
/// deferred-journal reservation record.
pub const RETAINED_RESERVATION_MARKER: [u8; 4] = *b"CRDJ";

/// EDK2 capsule-on-disk GUID used only as the coreboot-compatible outer
/// transport for the private retained reservation capsule.
///
/// Canonical UUID: `98c80a4f-e16b-4d11-939a-abe561260330`.
pub const RETAINED_RESERVATION_WRAPPER_GUID: [u8; 16] = [
    0x4f, 0x0a, 0xc8, 0x98, 0x6b, 0xe1, 0x11, 0x4d, 0x93, 0x9a, 0xab, 0xe5, 0x61, 0x26, 0x03, 0x30,
];

/// CrabEFI-private retained reservation capsule GUID in EFI byte order.
///
/// Canonical UUID: `7f4f8c35-5e2a-4df4-a8b3-4d1f8c2b9610`.
pub const RETAINED_RESERVATION_CAPSULE_GUID: [u8; 16] = [
    0x35, 0x8c, 0x4f, 0x7f, 0x2a, 0x5e, 0xf4, 0x4d, 0xa8, 0xb3, 0x4d, 0x1f, 0x8c, 0x2b, 0x96, 0x10,
];

/// EFI capsule-report GUID in EFI byte order.
///
/// Canonical UUID: `39b68c46-f7fb-441b-b6ec-16b0f69821f3`.
pub const CAPSULE_REPORT_VARIABLE_GUID: [u8; 16] = [
    0x46, 0x8c, 0xb6, 0x39, 0xfb, 0xf7, 0x1b, 0x44, 0xb6, 0xec, 0x16, 0xb0, 0xf6, 0x98, 0x21, 0xf3,
];

/// Firmware-private variable carrying authoritative ESRT last-attempt state.
pub const ESRT_LAST_ATTEMPT_VARIABLE_NAME: &[u16] = &[
    b'C' as u16,
    b'r' as u16,
    b'a' as u16,
    b'b' as u16,
    b'E' as u16,
    b'f' as u16,
    b'i' as u16,
    b'E' as u16,
    b's' as u16,
    b'r' as u16,
    b't' as u16,
    b'L' as u16,
    b'a' as u16,
    b's' as u16,
    b't' as u16,
    b'A' as u16,
    b't' as u16,
    b't' as u16,
    b'e' as u16,
    b'm' as u16,
    b'p' as u16,
    b't' as u16,
];

/// Return whether a variable is the firmware-private ESRT attempt record.
pub fn is_esrt_last_attempt_variable(guid: &[u8; 16], name: &[u16]) -> bool {
    if guid != &CAPSULE_REPORT_VARIABLE_GUID {
        return false;
    }
    let name_len = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    &name[..name_len] == ESRT_LAST_ATTEMPT_VARIABLE_NAME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_attempt_record_requires_exact_guid_and_name() {
        let mut terminated = ESRT_LAST_ATTEMPT_VARIABLE_NAME.to_vec();
        terminated.push(0);
        assert!(is_esrt_last_attempt_variable(
            &CAPSULE_REPORT_VARIABLE_GUID,
            ESRT_LAST_ATTEMPT_VARIABLE_NAME,
        ));
        assert!(is_esrt_last_attempt_variable(
            &CAPSULE_REPORT_VARIABLE_GUID,
            &terminated,
        ));

        let mut other_guid = CAPSULE_REPORT_VARIABLE_GUID;
        other_guid[0] ^= 1;
        assert!(!is_esrt_last_attempt_variable(
            &other_guid,
            ESRT_LAST_ATTEMPT_VARIABLE_NAME,
        ));
        let mut other_name = ESRT_LAST_ATTEMPT_VARIABLE_NAME.to_vec();
        other_name[0] = b'c' as u16;
        assert!(!is_esrt_last_attempt_variable(
            &CAPSULE_REPORT_VARIABLE_GUID,
            &other_name,
        ));
    }
}
