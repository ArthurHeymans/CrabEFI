//! Capsule Application (Flash Write Orchestration)
//!
//! This module handles the actual application of validated capsule images
//! to SPI flash, using the platform's `CapsuleBackend`.
//!
//! # Application Flow
//!
//! 1. Parse outer `EFI_CAPSULE_HEADER` and identify type
//! 2. For FMP capsules: parse `FMP_CAPSULE_HEADER`, iterate payload items
//! 3. For each payload item:
//!    a. Parse `FMP_CAPSULE_IMAGE_HEADER`
//!    b. Verify firmware GUID matches expected
//!    c. Parse and verify PKCS#7 authentication header
//!    d. Check firmware version >= LSV
//!    e. Parse RMAP manifest, validate against FMAP
//!    f. Write firmware image to approved flash regions
//! 4. Record result

use crate::platform::CapsuleBackend;

use super::auth;
use super::fmp;
use super::header::{self, CapsuleHeader, CapsuleType};
use super::result::{CapsuleResult, CapsuleResultStatus};
use super::rmap;

/// Apply a single capsule from a raw byte buffer.
///
/// `data` must contain the entire capsule image starting from the
/// `EFI_CAPSULE_HEADER`.
///
/// Returns a `CapsuleResult` describing the outcome (success or failure).
pub fn apply_capsule(data: &[u8], backend: &mut dyn CapsuleBackend) -> CapsuleResult {
    let hdr = match header::parse_capsule_header(data) {
        Ok(h) => h,
        Err(e) => {
            log::error!("Failed to parse capsule header: {:?}", e);
            return CapsuleResult::report_only(CapsuleResultStatus::ErrorInvalidImage);
        }
    };
    let capsule_type = header::identify_capsule_type(&hdr.capsule_guid);

    if let Err(e) = header::validate_capsule(&hdr, data.len()) {
        log::error!("Capsule validation failed: {:?}", e);
        return if capsule_type == CapsuleType::Fmp {
            CapsuleResult::failure(CapsuleResultStatus::ErrorInvalidImage, 0)
        } else {
            CapsuleResult::report_only(CapsuleResultStatus::ErrorInvalidImage)
        };
    }

    log::info!(
        "Processing capsule: type={:?}, size={}, flags={:#x}",
        capsule_type,
        hdr.capsule_image_size,
        hdr.flags
    );

    match capsule_type {
        CapsuleType::Fmp => apply_fmp_capsule(&hdr, data, backend),
        CapsuleType::WindowsUx => {
            log::info!("Skipping Windows UX capsule (informational only)");
            CapsuleResult::report_only(CapsuleResultStatus::Success)
        }
        CapsuleType::CapsuleOnDisk => {
            // Capsule-on-disk wrapper: the inner payload starts after the
            // outer capsule header.
            log::info!("Unwrapping capsule-on-disk wrapper");
            let inner_offset = hdr.header_size as usize;
            if inner_offset >= data.len() {
                log::error!("Capsule-on-disk wrapper has no inner payload");
                return CapsuleResult::report_only(CapsuleResultStatus::ErrorInvalidImage);
            }
            apply_capsule(&data[inner_offset..], backend)
        }
        CapsuleType::Unknown => {
            log::warn!("Unknown capsule GUID — skipping");
            CapsuleResult::report_only(CapsuleResultStatus::ErrorUnsupported)
        }
    }
}

/// Apply an FMP capsule.
fn apply_fmp_capsule(
    outer_hdr: &CapsuleHeader,
    data: &[u8],
    backend: &mut dyn CapsuleBackend,
) -> CapsuleResult {
    let fmp_payload_offset = outer_hdr.header_size as usize;
    let fmp_data = &data[fmp_payload_offset..outer_hdr.capsule_image_size as usize];

    let fmp_hdr = match fmp::parse_fmp_capsule_header(fmp_data) {
        Ok(h) => h,
        Err(e) => {
            log::error!("Failed to parse FMP capsule header: {:?}", e);
            return CapsuleResult::failure(CapsuleResultStatus::ErrorInvalidImage, 0);
        }
    };

    if fmp_hdr.embedded_driver_count > 0 {
        log::warn!(
            "Capsule contains {} embedded drivers — skipping (not supported)",
            fmp_hdr.embedded_driver_count
        );
    }
    if fmp_hdr.payload_item_count == 0 {
        log::error!("FMP capsule contains no firmware payload items");
        return CapsuleResult::failure(CapsuleResultStatus::ErrorInvalidImage, 0);
    }

    // Process each payload item
    let driver_count = fmp_hdr.embedded_driver_count as usize;
    let mut last_result = CapsuleResult::success(0);

    for i in 0..fmp_hdr.payload_item_count as usize {
        let item_index = driver_count + i;
        if item_index >= fmp_hdr.item_offsets.len() {
            log::error!("Payload index {} out of bounds", item_index);
            return CapsuleResult::failure(CapsuleResultStatus::ErrorInvalidImage, 0);
        }

        let item_offset = fmp_hdr.item_offsets[item_index] as usize;
        if item_offset >= fmp_data.len() {
            log::error!("Payload offset {:#x} out of bounds", item_offset);
            return CapsuleResult::failure(CapsuleResultStatus::ErrorInvalidImage, 0);
        }

        let item_data = &fmp_data[item_offset..];
        last_result = apply_fmp_payload_item(item_data, i, backend);

        if last_result.status != CapsuleResultStatus::Success {
            log::error!("FMP payload item {} failed", i);
            return last_result;
        }
    }

    last_result
}

/// Apply a single FMP payload item (one firmware image).
fn apply_fmp_payload_item(
    data: &[u8],
    item_index: usize,
    backend: &mut dyn CapsuleBackend,
) -> CapsuleResult {
    // Parse the FMP image header
    let img_hdr = match fmp::parse_fmp_image_header(data) {
        Ok(h) => h,
        Err(e) => {
            log::error!(
                "Failed to parse FMP image header for item {}: {:?}",
                item_index,
                e
            );
            return CapsuleResult::failure(CapsuleResultStatus::ErrorInvalidImage, 0);
        }
    };

    // Verify firmware GUID matches
    // Copy firmware info to avoid holding an immutable borrow on backend
    // while we later need it mutably for write_firmware_region().
    let fw_info = match backend.firmware_info() {
        Some(info) => *info,
        None => {
            log::error!("No firmware info available — cannot validate capsule");
            return CapsuleResult::failure(CapsuleResultStatus::ErrorUnsupported, 0);
        }
    };

    if !guid_matches(&img_hdr.update_image_type_id, &fw_info.guid) {
        log::error!("Capsule firmware GUID does not match installed firmware");
        return CapsuleResult::failure(CapsuleResultStatus::ErrorInvalidImage, 0);
    }

    // Locate the update image payload (after FMP image header)
    let hdr_size = fmp::fmp_image_header_size(img_hdr.version);
    if hdr_size + img_hdr.update_image_size as usize > data.len() {
        log::error!("FMP image payload extends beyond buffer");
        return CapsuleResult::failure(CapsuleResultStatus::ErrorInvalidImage, 0);
    }
    let update_image = &data[hdr_size..hdr_size + img_hdr.update_image_size as usize];

    // Parse authentication header and verify signature
    let (auth_hdr, image_payload_offset) = match fmp::parse_firmware_image_auth(update_image) {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to parse auth header: {:?}", e);
            return CapsuleResult::failure(CapsuleResultStatus::ErrorAuthFailed, 0);
        }
    };

    let signed_firmware_image = &update_image[image_payload_offset..];
    let (payload_header, firmware_image) =
        match fmp::parse_fmp_payload_header(signed_firmware_image) {
            Ok(payload) => payload,
            Err(error) => {
                log::error!("Failed to parse signed FMP payload header: {:?}", error);
                return CapsuleResult::failure(CapsuleResultStatus::ErrorInvalidImage, 0);
            }
        };
    let attempted_version = payload_header.firmware_version;

    // Authenticate the version metadata together with the firmware bytes before
    // using it for rollback policy. It is still useful for failure reporting if
    // signature verification fails.
    let trust_store = backend.capsule_trust_store();
    if let Err(e) = auth::verify_capsule_signature(&auth_hdr, signed_firmware_image, trust_store) {
        log::error!("Capsule signature verification failed: {:?}", e);
        return CapsuleResult::failure(CapsuleResultStatus::ErrorAuthFailed, attempted_version);
    }

    log::info!(
        "Firmware version check: attempted={:#x}, current={:#x}, LSV={:#x}, incoming LSV={:#x}",
        attempted_version,
        fw_info.version,
        fw_info.lowest_supported_version,
        payload_header.lowest_supported_version,
    );
    if let Some(failure) = version_failure(attempted_version, fw_info.lowest_supported_version) {
        return failure;
    }

    // Parse RMAP manifest and validate against FMAP
    let fmap_regions = backend.fmap_regions();
    let approved_regions = match rmap::parse_and_validate_rmap(firmware_image, fmap_regions) {
        Ok(regions) => regions,
        Err(e) => {
            log::error!("RMAP validation failed: {:?}", e);
            return CapsuleResult::failure(
                CapsuleResultStatus::ErrorInvalidImage,
                attempted_version,
            );
        }
    };

    // Strip the RMAP manifest to get the pure firmware image data
    let clean_image = rmap::strip_rmap_manifest(firmware_image);

    let required_size = match approved_regions.iter().try_fold(0usize, |total, region| {
        total.checked_add(region.size as usize)
    }) {
        Some(size) => size,
        None => {
            log::error!("Approved RMAP regions exceed addressable image size");
            return CapsuleResult::failure(
                CapsuleResultStatus::ErrorInvalidImage,
                attempted_version,
            );
        }
    };

    if clean_image.len() < required_size {
        log::error!(
            "Image data too small for approved regions: need {} bytes, have {}",
            required_size,
            clean_image.len()
        );
        return CapsuleResult::failure(CapsuleResultStatus::ErrorInvalidImage, attempted_version);
    }

    // Write firmware image to approved flash regions.
    // The signed image is laid out as the concatenation of the approved regions
    // in manifest order; never truncate a region silently.
    let mut total_written = 0usize;
    for region in &approved_regions {
        if region.offset.checked_add(region.size).is_none() {
            log::error!(
                "RMAP region '{}' overflows flash address space: offset={:#x}, size={:#x}",
                region.name,
                region.offset,
                region.size
            );
            return CapsuleResult::failure(
                CapsuleResultStatus::ErrorInvalidImage,
                attempted_version,
            );
        }

        let write_size = region.size as usize;
        let write_start = total_written;
        let write_end = write_start + write_size;
        let region_data = &clean_image[write_start..write_end];

        log::info!(
            "Writing {} bytes to region '{}' at flash offset {:#x}",
            region_data.len(),
            region.name,
            region.offset
        );

        if let Err(e) = backend.write_firmware_region(region.name.as_str(), 0, region_data) {
            log::error!("Flash write failed for region '{}': {:?}", region.name, e);
            return CapsuleResult::failure(
                CapsuleResultStatus::ErrorFlashWriteFailed,
                attempted_version,
            );
        }

        total_written += write_size;
    }

    log::info!(
        "Capsule applied successfully: {} bytes written to {} region(s)",
        total_written,
        approved_regions.len()
    );

    CapsuleResult::success(attempted_version)
}

fn version_failure(attempted_version: u32, lowest_supported_version: u32) -> Option<CapsuleResult> {
    (attempted_version < lowest_supported_version).then(|| {
        log::error!(
            "Capsule firmware version {:#x} is below LSV {:#x}",
            attempted_version,
            lowest_supported_version
        );
        CapsuleResult::failure(CapsuleResultStatus::ErrorVersionTooLow, attempted_version)
    })
}

/// Check if a GUID matches a 16-byte array.
fn guid_matches(guid: &r_efi::efi::Guid, bytes: &[u8; 16]) -> bool {
    guid.as_bytes() == bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_failure_reports_the_attempted_capsule_version() {
        let failure = version_failure(0x0001_0001, 0x0002_0000).unwrap();
        assert_eq!(failure.status, CapsuleResultStatus::ErrorVersionTooLow);
        assert_eq!(failure.capsule_version, 0x0001_0001);
        assert!(version_failure(0x0002_0000, 0x0002_0000).is_none());
        assert!(version_failure(0x0002_0001, 0x0002_0000).is_none());
    }
}
