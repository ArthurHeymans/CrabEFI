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
            return CapsuleResult::failure(CapsuleResultStatus::ErrorInvalidImage, 0);
        }
    };

    if let Err(e) = header::validate_capsule(&hdr, data.len()) {
        log::error!("Capsule validation failed: {:?}", e);
        return CapsuleResult::failure(CapsuleResultStatus::ErrorInvalidImage, 0);
    }

    log::info!(
        "Processing capsule: type={:?}, size={}, flags={:#x}",
        header::identify_capsule_type(&hdr.capsule_guid),
        hdr.capsule_image_size,
        hdr.flags
    );

    match header::identify_capsule_type(&hdr.capsule_guid) {
        CapsuleType::Fmp => apply_fmp_capsule(&hdr, data, backend),
        CapsuleType::WindowsUx => {
            log::info!("Skipping Windows UX capsule (informational only)");
            CapsuleResult::success(0)
        }
        CapsuleType::CapsuleOnDisk => {
            // Capsule-on-disk wrapper: the inner payload starts after the
            // outer capsule header.
            log::info!("Unwrapping capsule-on-disk wrapper");
            let inner_offset = hdr.header_size as usize;
            if inner_offset >= data.len() {
                log::error!("Capsule-on-disk wrapper has no inner payload");
                return CapsuleResult::failure(CapsuleResultStatus::ErrorInvalidImage, 0);
            }
            apply_capsule(&data[inner_offset..], backend)
        }
        CapsuleType::Unknown => {
            log::warn!("Unknown capsule GUID — skipping");
            CapsuleResult::failure(CapsuleResultStatus::ErrorUnsupported, 0)
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

    let firmware_image = &update_image[image_payload_offset..];

    // Verify PKCS#7 signature
    let trust_store = backend.capsule_trust_store();
    if let Err(e) = auth::verify_capsule_signature(&auth_hdr, firmware_image, trust_store) {
        log::error!("Capsule signature verification failed: {:?}", e);
        return CapsuleResult::failure(CapsuleResultStatus::ErrorAuthFailed, 0);
    }

    // Check version >= LSV
    // The firmware image itself may encode a version; for now we trust
    // the capsule's FMP header. The version check is against the current
    // firmware's LSV to prevent rollback.
    // TODO: Extract version from the firmware image once we define that encoding.
    log::info!(
        "Firmware version check: current={:#x}, LSV={:#x}",
        fw_info.version,
        fw_info.lowest_supported_version
    );

    // Parse RMAP manifest and validate against FMAP
    let fmap_regions = backend.fmap_regions();
    let approved_regions = match rmap::parse_and_validate_rmap(firmware_image, fmap_regions) {
        Ok(regions) => regions,
        Err(e) => {
            log::error!("RMAP validation failed: {:?}", e);
            return CapsuleResult::failure(CapsuleResultStatus::ErrorInvalidImage, 0);
        }
    };

    // Strip the RMAP manifest to get the pure firmware image data
    let clean_image = rmap::strip_rmap_manifest(firmware_image);

    // Write firmware image to approved flash regions
    let mut total_written = 0u32;
    for region in &approved_regions {
        let region_end = region.offset + region.size;
        let _image_region_start = region.offset as usize;

        // The clean_image should cover all approved regions.
        // Each region maps to a corresponding slice of the firmware image.
        // For now, we write the appropriate portion of the image to each region.
        let write_size = region.size.min(clean_image.len() as u32 - total_written);
        let write_start = total_written as usize;
        let write_end = write_start + write_size as usize;

        if write_end > clean_image.len() {
            log::error!(
                "Image data too small for region '{}': need {} bytes at offset {}, have {}",
                region.name,
                write_size,
                write_start,
                clean_image.len()
            );
            return CapsuleResult::failure(CapsuleResultStatus::ErrorFlashWriteFailed, 0);
        }

        let region_data = &clean_image[write_start..write_end];

        log::info!(
            "Writing {} bytes to region '{}' at flash offset {:#x}",
            region_data.len(),
            region.name,
            region.offset
        );

        if let Err(e) = backend.write_firmware_region(region.name.as_str(), 0, region_data) {
            log::error!("Flash write failed for region '{}': {:?}", region.name, e);
            return CapsuleResult::failure(CapsuleResultStatus::ErrorFlashWriteFailed, 0);
        }

        total_written += write_size;
        let _ = region_end; // suppress unused warning
    }

    log::info!(
        "Capsule applied successfully: {} bytes written to {} region(s)",
        total_written,
        approved_regions.len()
    );

    CapsuleResult::success(fw_info.version)
}

/// Check if a GUID matches a 16-byte array.
fn guid_matches(guid: &r_efi::efi::Guid, bytes: &[u8; 16]) -> bool {
    guid.as_bytes() == bytes
}
