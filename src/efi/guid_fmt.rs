//! GUID Formatting and Well-Known Name Lookup
//!
//! Provides human-readable display of UEFI GUIDs in log messages by matching
//! against a table of well-known protocol and table GUIDs.

use r_efi::efi::Guid;

/// Wrapper for GUID that displays name if known, raw GUID if unknown
pub struct GuidFmt(pub Guid);

impl core::fmt::Display for GuidFmt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = lookup_guid_name(&self.0);
        if name != "UNKNOWN" {
            write!(f, "{}", name)
        } else {
            // Format as standard GUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            let bytes =
                unsafe { core::slice::from_raw_parts(&self.0 as *const Guid as *const u8, 16) };
            write!(
                f,
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                bytes[3],
                bytes[2],
                bytes[1],
                bytes[0], // Data1 (LE)
                bytes[5],
                bytes[4], // Data2 (LE)
                bytes[7],
                bytes[6], // Data3 (LE)
                bytes[8],
                bytes[9], // Data4[0-1]
                bytes[10],
                bytes[11],
                bytes[12],
                bytes[13],
                bytes[14],
                bytes[15]
            )
        }
    }
}

/// Look up a well-known name for a GUID
pub fn lookup_guid_name(guid: &Guid) -> &'static str {
    /// Well-known GUID lookup table
    const GUID_NAMES: &[(Guid, &str)] = &[
        (
            Guid::from_fields(
                0x5B1B31A1,
                0x9562,
                0x11d2,
                0x8E,
                0x3F,
                &[0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
            ),
            "LOADED_IMAGE",
        ),
        (
            Guid::from_fields(
                0x09576e91,
                0x6d3f,
                0x11d2,
                0x8e,
                0x39,
                &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
            ),
            "DEVICE_PATH",
        ),
        (
            Guid::from_fields(
                0x0964e5b22,
                0x6459,
                0x11d2,
                0x8e,
                0x39,
                &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
            ),
            "SIMPLE_FILE_SYSTEM",
        ),
        (
            Guid::from_fields(
                0x9042a9de,
                0x23dc,
                0x4a38,
                0x96,
                0xfb,
                &[0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
            ),
            "GRAPHICS_OUTPUT (GOP)",
        ),
        (
            Guid::from_fields(
                0x387477c1,
                0x69c7,
                0x11d2,
                0x8e,
                0x39,
                &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
            ),
            "SIMPLE_TEXT_INPUT",
        ),
        (
            Guid::from_fields(
                0x387477c2,
                0x69c7,
                0x11d2,
                0x8e,
                0x39,
                &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
            ),
            "SIMPLE_TEXT_OUTPUT",
        ),
        (
            Guid::from_fields(
                0x964e5b21,
                0x6459,
                0x11d2,
                0x8e,
                0x39,
                &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
            ),
            "BLOCK_IO",
        ),
        (
            Guid::from_fields(
                0xCE345171,
                0xBA0B,
                0x11d2,
                0x8e,
                0x4F,
                &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
            ),
            "DISK_IO",
        ),
        (
            Guid::from_fields(
                0xeb9d2d30,
                0x2d88,
                0x11d3,
                0x9a,
                0x16,
                &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
            ),
            "ACPI_TABLE",
        ),
        (
            Guid::from_fields(
                0xeb9d2d31,
                0x2d88,
                0x11d3,
                0x9a,
                0x16,
                &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
            ),
            "SMBIOS_TABLE",
        ),
        (
            Guid::from_fields(
                0x56EC3091,
                0x954C,
                0x11d2,
                0x8e,
                0x3f,
                &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
            ),
            "LOAD_FILE",
        ),
        (
            Guid::from_fields(
                0x4006c0c1,
                0xfcb3,
                0x403e,
                0x99,
                0x6d,
                &[0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d],
            ),
            "LOAD_FILE2",
        ),
        (
            Guid::from_fields(
                0xBB25CF6F,
                0xF1D4,
                0x11D2,
                0x9a,
                0x0c,
                &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0xfd],
            ),
            "SERIAL_IO",
        ),
        (
            Guid::from_fields(
                0x03C4E603,
                0xAC28,
                0x11d3,
                0x9a,
                0x2d,
                &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
            ),
            "PXE_BASE_CODE",
        ),
        (
            Guid::from_fields(
                0xef9fc172,
                0xa1b2,
                0x4693,
                0xb3,
                0x27,
                &[0x6d, 0x32, 0xfc, 0x41, 0x60, 0x42],
            ),
            "HII_DATABASE",
        ),
        (
            Guid::from_fields(
                0x587e72d7,
                0xcc50,
                0x4f79,
                0x82,
                0x09,
                &[0xca, 0x29, 0x1f, 0xc1, 0xa1, 0x0f],
            ),
            "HII_CONFIG_ROUTING",
        ),
        (
            Guid::from_fields(
                0x1C0C34F6,
                0xD380,
                0x41FA,
                0xA0,
                0x49,
                &[0x8a, 0xd0, 0x6c, 0x1a, 0x66, 0xaa],
            ),
            "EDID_DISCOVERED",
        ),
        (
            Guid::from_fields(
                0xBD8C1056,
                0x9F36,
                0x44EC,
                0x92,
                0xA8,
                &[0xa6, 0x33, 0x7f, 0x81, 0x79, 0x86],
            ),
            "EDID_ACTIVE",
        ),
        (
            Guid::from_fields(
                0x1d85cd7f,
                0xf43d,
                0x11d2,
                0x9a,
                0x0c,
                &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
            ),
            "UNICODE_COLLATION",
        ),
        (
            Guid::from_fields(
                0x605dab50,
                0xe046,
                0x4300,
                0xab,
                0xb6,
                &[0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23],
            ),
            "SHIM_LOCK",
        ),
        (
            Guid::from_fields(
                0x752f3136,
                0x4e16,
                0x4fdc,
                0xa2,
                0x2a,
                &[0xe5, 0xf4, 0x68, 0x12, 0xf4, 0xca],
            ),
            "SHELL_PARAMETERS",
        ),
        (
            Guid::from_fields(
                0x5568e427,
                0x68fc,
                0x4f3d,
                0xac,
                0x74,
                &[0xca, 0x55, 0x52, 0x31, 0xcc, 0x68],
            ),
            "LINUX_INITRD_MEDIA",
        ),
        (
            Guid::from_fields(
                0xf42f7782,
                0x012e,
                0x4c12,
                0x99,
                0x56,
                &[0x49, 0xf9, 0x43, 0x04, 0xf7, 0x21],
            ),
            "CONSOLE_CONTROL",
        ),
        (
            Guid::from_fields(
                0xf4560cf6,
                0x40ec,
                0x4b4a,
                0xa1,
                0x92,
                &[0xbf, 0x1d, 0x57, 0xd0, 0xb1, 0x89],
            ),
            "MEMORY_ATTRIBUTE",
        ),
        (
            Guid::from_fields(
                0xf541796d,
                0xa62e,
                0x4954,
                0xa7,
                0x75,
                &[0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd],
            ),
            "TCG (TPM 1.2)",
        ),
        (
            Guid::from_fields(
                0x607f766c,
                0x7455,
                0x42be,
                0x93,
                0x0b,
                &[0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f],
            ),
            "TCG2 (TPM 2.0)",
        ),
        (
            Guid::from_fields(
                0x96751a3d,
                0x72f4,
                0x41a6,
                0xa7,
                0x94,
                &[0xed, 0x5d, 0x0e, 0x67, 0xae, 0x6b],
            ),
            "CC_MEASUREMENT",
        ),
        (
            Guid::from_fields(
                0xdd9e7534,
                0x7762,
                0x4698,
                0x8c,
                0x14,
                &[0xf5, 0x85, 0x17, 0xa6, 0x25, 0xaa],
            ),
            "SIMPLE_TEXT_INPUT_EX",
        ),
    ];

    GUID_NAMES
        .iter()
        .find(|(g, _)| *guid == *g)
        .map(|(_, name)| *name)
        .unwrap_or("UNKNOWN")
}
