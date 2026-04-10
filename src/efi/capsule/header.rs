//! EFI Capsule Header Parsing
//!
//! This module parses the UEFI capsule header structure and identifies
//! capsule types by their GUID.
//!
//! # References
//!
//! - UEFI Specification 2.10, Section 8.5.3 — EFI_CAPSULE_HEADER
//! - UEFI Specification 2.10, Table 8-11 — Capsule Header Flags

use r_efi::efi::Guid;

// ============================================================================
// Capsule Header
// ============================================================================

/// Parsed EFI capsule header.
///
/// This corresponds to `EFI_CAPSULE_HEADER` in the UEFI specification.
/// The header is followed by capsule-type-specific data.
#[derive(Debug, Clone, Copy)]
pub struct CapsuleHeader {
    /// Capsule type GUID.
    pub capsule_guid: Guid,
    /// Size of the header structure in bytes (at least 28).
    pub header_size: u32,
    /// Capsule flags (see `CAPSULE_FLAGS_*` constants).
    pub flags: u32,
    /// Total size of the capsule image including header and payload.
    pub capsule_image_size: u32,
}

/// Capsule must persist across a system reset.
pub const CAPSULE_FLAGS_PERSIST_ACROSS_RESET: u32 = 0x0001_0000;

/// Capsule should be placed in the EFI system table after processing.
pub const CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE: u32 = 0x0002_0000;

/// Firmware should initiate a reset after processing the capsule.
pub const CAPSULE_FLAGS_INITIATE_RESET: u32 = 0x0004_0000;

// ============================================================================
// Well-Known Capsule GUIDs
// ============================================================================

/// EFI Firmware Management Protocol (FMP) Capsule GUID.
///
/// Capsules with this GUID contain firmware update images processed via
/// the Firmware Management Protocol.
pub const EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID: Guid = Guid::from_fields(
    0x6DCBD5ED,
    0xE82D,
    0x4C44,
    0xBD,
    0xA1,
    &[0x71, 0x94, 0x19, 0x9A, 0xD9, 0x2A],
);

/// Windows UX Capsule GUID.
///
/// Contains a bitmap image displayed during firmware update.
/// Informational only — CrabEFI logs and skips these.
pub const WINDOWS_UX_CAPSULE_GUID: Guid = Guid::from_fields(
    0x3B8C8162,
    0x188C,
    0x46A4,
    0xAE,
    0xC9,
    &[0x8F, 0xCB, 0x51, 0x00, 0x65, 0xEB],
);

/// EDK2 Capsule-on-Disk wrapper GUID.
///
/// When EDK2 reads capsule files from `\EFI\UpdateCapsule\` on the ESP,
/// it wraps them with this GUID before submitting via UpdateCapsule().
/// The inner payload is the actual capsule.
pub const EDK2_CAPSULE_ON_DISK_GUID: Guid = Guid::from_fields(
    0x98C80A4F,
    0xE16B,
    0x4D11,
    0x93,
    0x9A,
    &[0xAB, 0xE5, 0x61, 0x26, 0x03, 0x30],
);

// ============================================================================
// Capsule Type Classification
// ============================================================================

/// Identified capsule type based on the capsule GUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleType {
    /// FMP capsule containing firmware update image(s).
    Fmp,
    /// Windows UX capsule (bitmap splash screen during update).
    WindowsUx,
    /// EDK2 capsule-on-disk wrapper (inner capsule needs unwrapping).
    CapsuleOnDisk,
    /// Unknown capsule type.
    Unknown,
}

// ============================================================================
// Parsing
// ============================================================================

/// Minimum valid capsule header size (4 GUIDs fields + 3 u32 fields).
const MIN_CAPSULE_HEADER_SIZE: usize = 16 + 4 + 4 + 4; // 28 bytes

/// Errors that can occur during capsule header parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleError {
    /// Input buffer is too small to contain a capsule header.
    BufferTooSmall,
    /// Header size field is smaller than the minimum header size.
    InvalidHeaderSize,
    /// Capsule image size is smaller than the header size.
    InvalidImageSize,
    /// Capsule image size exceeds the provided buffer.
    ImageSizeExceedsBuffer,
    /// Capsule is missing the PERSIST_ACROSS_RESET flag.
    MissingPersistFlag,
    /// Unrecognized capsule GUID.
    UnrecognizedGuid,
    /// FMP capsule header is invalid.
    InvalidFmpHeader,
    /// FMP capsule image header is invalid.
    InvalidFmpImageHeader,
    /// Capsule signature verification failed.
    AuthenticationFailed,
    /// Firmware version is below the lowest supported version.
    VersionTooLow,
    /// Firmware GUID doesn't match the expected firmware class.
    GuidMismatch,
    /// RMAP manifest is missing or invalid.
    InvalidRmap,
    /// Flash region write failed.
    FlashWriteFailed,
}

/// Parse an EFI capsule header from a byte buffer.
///
/// The buffer must contain at least 28 bytes. On success, returns the
/// parsed header. The caller should verify `capsule_image_size` bytes
/// are available starting from the buffer base.
pub fn parse_capsule_header(data: &[u8]) -> Result<CapsuleHeader, CapsuleError> {
    if data.len() < MIN_CAPSULE_HEADER_SIZE {
        return Err(CapsuleError::BufferTooSmall);
    }

    // Parse GUID (mixed-endian: first 3 fields LE, last 2 fields BE)
    let capsule_guid = Guid::from_fields(
        u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        u16::from_le_bytes([data[4], data[5]]),
        u16::from_le_bytes([data[6], data[7]]),
        data[8],
        data[9],
        &[data[10], data[11], data[12], data[13], data[14], data[15]],
    );

    let header_size = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let capsule_image_size = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

    if header_size < MIN_CAPSULE_HEADER_SIZE as u32 {
        return Err(CapsuleError::InvalidHeaderSize);
    }

    if capsule_image_size < header_size {
        return Err(CapsuleError::InvalidImageSize);
    }

    Ok(CapsuleHeader {
        capsule_guid,
        header_size,
        flags,
        capsule_image_size,
    })
}

/// Identify the capsule type from its GUID.
pub fn identify_capsule_type(guid: &Guid) -> CapsuleType {
    if guids_equal(guid, &EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID) {
        CapsuleType::Fmp
    } else if guids_equal(guid, &WINDOWS_UX_CAPSULE_GUID) {
        CapsuleType::WindowsUx
    } else if guids_equal(guid, &EDK2_CAPSULE_ON_DISK_GUID) {
        CapsuleType::CapsuleOnDisk
    } else {
        CapsuleType::Unknown
    }
}

/// Validate that a capsule header is well-formed and the data buffer is
/// large enough to hold the entire capsule image.
pub fn validate_capsule(header: &CapsuleHeader, data_len: usize) -> Result<(), CapsuleError> {
    if header.capsule_image_size as usize > data_len {
        return Err(CapsuleError::ImageSizeExceedsBuffer);
    }

    Ok(())
}

/// Compare two GUIDs for equality.
fn guids_equal(a: &Guid, b: &Guid) -> bool {
    a.as_bytes() == b.as_bytes()
}
