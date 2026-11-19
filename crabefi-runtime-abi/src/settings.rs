//! CrabEFI settings variables with rules the runtime image enforces.

/// GUID of CrabEFI's own settings variables
/// (`9e80634c-cdc7-41d5-a345-4a297f9c7d1a`), in EFI byte order.
pub const SETTINGS_GUID: [u8; 16] = [
    0x4c, 0x63, 0x80, 0x9e, 0xc7, 0xcd, 0xd5, 0x41, 0xa3, 0x45, 0x4a, 0x29, 0x7f, 0x9c, 0x7d, 0x1a,
];

/// `CrabEFIExternalBoot`, which can only tighten the external-boot policy.
pub const EXTERNAL_BOOT_NAME: &[u16] = &[
    b'C' as u16,
    b'r' as u16,
    b'a' as u16,
    b'b' as u16,
    b'E' as u16,
    b'F' as u16,
    b'I' as u16,
    b'E' as u16,
    b'x' as u16,
    b't' as u16,
    b'e' as u16,
    b'r' as u16,
    b'n' as u16,
    b'a' as u16,
    b'l' as u16,
    b'B' as u16,
    b'o' as u16,
    b'o' as u16,
    b't' as u16,
];

/// Settings only boot-time code may create, change or delete. The OS could
/// otherwise create one the firmware then reads as malformed.
pub fn is_boot_only_setting(guid: &[u8; 16], name: &[u16]) -> bool {
    let name_len = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    guid == &SETTINGS_GUID && name.get(..name_len) == Some(EXTERNAL_BOOT_NAME)
}
