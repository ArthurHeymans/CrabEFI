//! Firmware Management Protocol (FMP) Capsule Parsing
//!
//! This module parses the internal structure of FMP capsules, which contain
//! one or more firmware update images.
//!
//! # FMP Capsule Structure
//!
//! ```text
//! +------------------------------------------+
//! | EFI_CAPSULE_HEADER                       |  (28 bytes, parsed by header.rs)
//! +------------------------------------------+
//! | EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER   |  (8 bytes + offset array)
//! |   version: u32                           |
//! |   embedded_driver_count: u16             |
//! |   payload_item_count: u16                |
//! |   item_offset_list[]: u64[]              |  (one per driver + payload)
//! +------------------------------------------+
//! | Embedded Driver #0 (optional)            |
//! +------------------------------------------+
//! | ...                                      |
//! +------------------------------------------+
//! | EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER #0  |
//! |   version: u32                           |
//! |   update_image_type_id: GUID             |
//! |   update_image_index: u8                 |
//! |   reserved[3]: u8                        |
//! |   update_image_size: u32                 |
//! |   update_vendor_code_size: u32           |
//! |   (v2) update_hardware_instance: u64     |
//! |   (v3) image_capsule_support: u64        |
//! +------------------------------------------+
//! | EFI_FIRMWARE_IMAGE_AUTHENTICATION        |  (PKCS#7 signature)
//! |   monotonic_count: u64                   |
//! |   auth_info: WIN_CERTIFICATE_UEFI_GUID   |
//! +------------------------------------------+
//! | Firmware Image Payload                   |
//! +------------------------------------------+
//! | Vendor Code (optional)                   |
//! +------------------------------------------+
//! ```
//!
//! # References
//!
//! - UEFI Specification 2.10, Section 23.1 — Firmware Management Protocol
//! - EDK2 `MdePkg/Include/Guid/FmpCapsule.h`

use r_efi::efi::Guid;

use super::header::CapsuleError;

// ============================================================================
// FMP Capsule Header
// ============================================================================

/// Parsed FMP capsule header.
#[derive(Debug, Clone)]
pub struct FmpCapsuleHeader {
    /// Header version (must be 1).
    pub version: u32,
    /// Number of embedded EFI drivers in the capsule.
    pub embedded_driver_count: u16,
    /// Number of firmware update payload items.
    pub payload_item_count: u16,
    /// Offsets to each item (drivers first, then payloads).
    /// Offsets are relative to the start of the FMP capsule header.
    pub item_offsets: alloc::vec::Vec<u64>,
}

/// Minimum FMP capsule header size (version + counts, no offsets).
const FMP_CAPSULE_HEADER_MIN_SIZE: usize = 4 + 2 + 2; // 8 bytes

// ============================================================================
// FMP Capsule Image Header
// ============================================================================

/// Parsed FMP capsule image header (per-payload).
#[derive(Debug, Clone)]
pub struct FmpImageHeader {
    /// Header version (1, 2, or 3).
    pub version: u32,
    /// GUID identifying the target firmware component.
    pub update_image_type_id: Guid,
    /// Index of the firmware image within its device (usually 1).
    pub update_image_index: u8,
    /// Size of the update image (including auth header if present).
    pub update_image_size: u32,
    /// Size of vendor-specific update data after the image.
    pub update_vendor_code_size: u32,
    /// Hardware instance (v2+), 0 = all instances.
    pub update_hardware_instance: u64,
    /// Capsule support flags (v3+).
    pub image_capsule_support: u64,
}

/// Minimum FMP image header size (v1: 4+16+1+3+4+4 = 32 bytes).
const FMP_IMAGE_HEADER_V1_SIZE: usize = 4 + 16 + 1 + 3 + 4 + 4; // 32 bytes
/// FMP image header v2 size (v1 + u64 hardware instance).
const FMP_IMAGE_HEADER_V2_SIZE: usize = FMP_IMAGE_HEADER_V1_SIZE + 8; // 40 bytes
/// FMP image header v3 size (v2 + u64 capsule support).
const FMP_IMAGE_HEADER_V3_SIZE: usize = FMP_IMAGE_HEADER_V2_SIZE + 8; // 48 bytes

// ============================================================================
// EFI_FIRMWARE_IMAGE_AUTHENTICATION
// ============================================================================

/// Parsed authentication header wrapping an FMP update image.
///
/// This corresponds to `EFI_FIRMWARE_IMAGE_AUTHENTICATION` in the UEFI spec.
/// It contains a `WIN_CERTIFICATE_UEFI_GUID` with PKCS#7 signed data.
#[derive(Debug, Clone)]
pub struct FirmwareImageAuth {
    /// Monotonic count value (for anti-replay).
    pub monotonic_count: u64,
    /// Size of the entire WIN_CERTIFICATE (including header).
    pub auth_info_size: u32,
    /// PKCS#7 DER-encoded signed data.
    pub pkcs7_data: alloc::vec::Vec<u8>,
}

/// WIN_CERTIFICATE header size: dwLength(4) + wRevision(2) + wCertificateType(2) = 8 bytes.
const WIN_CERT_HEADER_SIZE: usize = 8;

/// WIN_CERTIFICATE_UEFI_GUID header: WIN_CERT(8) + CertType GUID(16) = 24 bytes.
const WIN_CERT_UEFI_GUID_HEADER_SIZE: usize = WIN_CERT_HEADER_SIZE + 16;

/// EFI_FIRMWARE_IMAGE_AUTHENTICATION: monotonic_count(8) + WIN_CERT_UEFI_GUID.
const AUTH_HEADER_MIN_SIZE: usize = 8 + WIN_CERT_UEFI_GUID_HEADER_SIZE; // 32 bytes

/// Expected certificate type for PKCS#7 signed data.
const WIN_CERT_TYPE_EFI_GUID: u16 = 0x0EF1;

/// GUID identifying a PKCS#7 certificate in WIN_CERTIFICATE_UEFI_GUID.
const EFI_CERT_TYPE_PKCS7_GUID: Guid = Guid::from_fields(
    0x4AAFD29D,
    0x68DF,
    0x49EE,
    0x8A,
    0xA9,
    &[0x34, 0x7D, 0x37, 0x56, 0x65, 0xA7],
);

// ============================================================================
// Parsing Functions
// ============================================================================

/// Parse the FMP capsule header from the capsule payload (after EFI_CAPSULE_HEADER).
///
/// `data` should start at the first byte after the `EFI_CAPSULE_HEADER`.
pub fn parse_fmp_capsule_header(data: &[u8]) -> Result<FmpCapsuleHeader, CapsuleError> {
    if data.len() < FMP_CAPSULE_HEADER_MIN_SIZE {
        return Err(CapsuleError::InvalidFmpHeader);
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if version != 1 {
        log::warn!("FMP capsule header version {} (expected 1)", version);
        return Err(CapsuleError::InvalidFmpHeader);
    }

    let embedded_driver_count = u16::from_le_bytes([data[4], data[5]]);
    let payload_item_count = u16::from_le_bytes([data[6], data[7]]);

    let total_items = embedded_driver_count as usize + payload_item_count as usize;
    let offsets_size = total_items * 8; // u64 per item
    let required_size = FMP_CAPSULE_HEADER_MIN_SIZE + offsets_size;

    if data.len() < required_size {
        log::warn!(
            "FMP header too small for {} items: need {} bytes, have {}",
            total_items,
            required_size,
            data.len()
        );
        return Err(CapsuleError::InvalidFmpHeader);
    }

    let mut item_offsets = alloc::vec::Vec::with_capacity(total_items);
    for i in 0..total_items {
        let off = FMP_CAPSULE_HEADER_MIN_SIZE + i * 8;
        let offset = u64::from_le_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
            data[off + 4],
            data[off + 5],
            data[off + 6],
            data[off + 7],
        ]);
        item_offsets.push(offset);
    }

    log::info!(
        "FMP capsule: {} embedded drivers, {} payload items",
        embedded_driver_count,
        payload_item_count
    );

    Ok(FmpCapsuleHeader {
        version,
        embedded_driver_count,
        payload_item_count,
        item_offsets,
    })
}

/// Parse an FMP capsule image header at the given offset within the FMP payload.
///
/// `data` should start at the beginning of the `EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER`.
pub fn parse_fmp_image_header(data: &[u8]) -> Result<FmpImageHeader, CapsuleError> {
    if data.len() < FMP_IMAGE_HEADER_V1_SIZE {
        return Err(CapsuleError::InvalidFmpImageHeader);
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if version == 0 || version > 3 {
        log::warn!("FMP image header version {} (expected 1-3)", version);
        return Err(CapsuleError::InvalidFmpImageHeader);
    }

    let update_image_type_id = Guid::from_fields(
        u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        u16::from_le_bytes([data[8], data[9]]),
        u16::from_le_bytes([data[10], data[11]]),
        data[12],
        data[13],
        &[data[14], data[15], data[16], data[17], data[18], data[19]],
    );

    let update_image_index = data[20];
    // data[21..24] are reserved

    let update_image_size = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
    let update_vendor_code_size = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

    let update_hardware_instance = if version >= 2 && data.len() >= FMP_IMAGE_HEADER_V2_SIZE {
        u64::from_le_bytes([
            data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
        ])
    } else {
        0
    };

    let image_capsule_support = if version >= 3 && data.len() >= FMP_IMAGE_HEADER_V3_SIZE {
        u64::from_le_bytes([
            data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
        ])
    } else {
        0
    };

    log::info!(
        "FMP image: index={}, image_size={}, vendor_code_size={}",
        update_image_index,
        update_image_size,
        update_vendor_code_size
    );

    Ok(FmpImageHeader {
        version,
        update_image_type_id,
        update_image_index,
        update_image_size,
        update_vendor_code_size,
        update_hardware_instance,
        image_capsule_support,
    })
}

/// Get the size of the FMP image header based on its version.
pub fn fmp_image_header_size(version: u32) -> usize {
    match version {
        3.. => FMP_IMAGE_HEADER_V3_SIZE,
        2 => FMP_IMAGE_HEADER_V2_SIZE,
        _ => FMP_IMAGE_HEADER_V1_SIZE,
    }
}

/// Parse the authentication header from the start of an FMP update image.
///
/// `data` should start at the first byte of the update image payload
/// (i.e., immediately after the FMP image header).
///
/// Returns the parsed auth header and the offset of the actual firmware
/// image data within `data` (after the auth header).
pub fn parse_firmware_image_auth(data: &[u8]) -> Result<(FirmwareImageAuth, usize), CapsuleError> {
    if data.len() < AUTH_HEADER_MIN_SIZE {
        log::warn!(
            "Auth header too small: {} bytes (need {})",
            data.len(),
            AUTH_HEADER_MIN_SIZE
        );
        return Err(CapsuleError::AuthenticationFailed);
    }

    // EFI_FIRMWARE_IMAGE_AUTHENTICATION.MonotonicCount
    let monotonic_count = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);

    // WIN_CERTIFICATE.dwLength (total size of WIN_CERTIFICATE including header)
    let dw_length = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    // WIN_CERTIFICATE.wRevision
    let _revision = u16::from_le_bytes([data[12], data[13]]);

    // WIN_CERTIFICATE.wCertificateType
    let cert_type = u16::from_le_bytes([data[14], data[15]]);
    if cert_type != WIN_CERT_TYPE_EFI_GUID {
        log::warn!("Unexpected certificate type: {:#06x}", cert_type);
        return Err(CapsuleError::AuthenticationFailed);
    }

    // WIN_CERTIFICATE_UEFI_GUID.CertType (GUID)
    let cert_type_guid = Guid::from_fields(
        u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
        u16::from_le_bytes([data[20], data[21]]),
        u16::from_le_bytes([data[22], data[23]]),
        data[24],
        data[25],
        &[data[26], data[27], data[28], data[29], data[30], data[31]],
    );

    if cert_type_guid.as_bytes() != EFI_CERT_TYPE_PKCS7_GUID.as_bytes() {
        log::warn!("Auth header CertType is not PKCS#7");
        return Err(CapsuleError::AuthenticationFailed);
    }

    // PKCS#7 data follows the WIN_CERTIFICATE_UEFI_GUID header
    let pkcs7_offset = 8 + WIN_CERT_UEFI_GUID_HEADER_SIZE; // monotonic_count + cert header
    let pkcs7_size = dw_length as usize - WIN_CERT_UEFI_GUID_HEADER_SIZE;
    let pkcs7_end = pkcs7_offset + pkcs7_size;

    if pkcs7_end > data.len() {
        log::warn!(
            "PKCS#7 data extends beyond buffer: offset={}, size={}, buf_len={}",
            pkcs7_offset,
            pkcs7_size,
            data.len()
        );
        return Err(CapsuleError::AuthenticationFailed);
    }

    let pkcs7_data = data[pkcs7_offset..pkcs7_end].to_vec();

    // Total auth header size = monotonic_count(8) + WIN_CERTIFICATE(dwLength)
    let auth_total_size = 8 + dw_length as usize;

    Ok((
        FirmwareImageAuth {
            monotonic_count,
            auth_info_size: dw_length,
            pkcs7_data,
        },
        auth_total_size,
    ))
}
