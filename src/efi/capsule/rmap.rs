//! RMAP (Region Map) Manifest Parsing
//!
//! Coreboot's `AppendRmapManifest.py` embeds a manifest at the end of the
//! firmware image within a capsule. This manifest lists the FMAP region
//! names that the capsule is allowed to write.
//!
//! # Manifest Format
//!
//! The manifest is appended to the firmware image as:
//! ```text
//! <firmware_image><manifest_data><manifest_length:u32>
//! ```
//!
//! Where `manifest_data` is a newline-separated list of FMAP region names.
//! The last 4 bytes of the image are the length of the manifest (little-endian u32).
//!
//! # Validation
//!
//! Each region name in the manifest is cross-checked against the actual FMAP
//! on flash. Only regions that exist in both the manifest and the FMAP are
//! approved for writing.

use alloc::vec::Vec;

use crate::platform::FmapRegion;

use super::header::CapsuleError;

/// An approved write region after RMAP + FMAP validation.
#[derive(Debug, Clone)]
pub struct ApprovedRegion {
    /// FMAP region name.
    pub name: heapless::String<32>,
    /// Flash offset of the region.
    pub offset: u32,
    /// Size of the region in bytes.
    pub size: u32,
}

/// Parse the RMAP manifest from a firmware image and validate against FMAP.
///
/// # Arguments
///
/// - `image_data`: The complete firmware image (including the appended manifest).
/// - `fmap_regions`: The actual FMAP regions on the flash.
///
/// # Returns
///
/// A list of approved regions that the capsule is allowed to write,
/// or an error if the manifest is missing or invalid.
pub fn parse_and_validate_rmap(
    image_data: &[u8],
    fmap_regions: &[FmapRegion],
) -> Result<Vec<ApprovedRegion>, CapsuleError> {
    // The manifest length is in the last 4 bytes of the image
    if image_data.len() < 4 {
        log::warn!("Image too small to contain RMAP manifest");
        return Err(CapsuleError::InvalidRmap);
    }

    let len_offset = image_data.len() - 4;
    let manifest_len = u32::from_le_bytes([
        image_data[len_offset],
        image_data[len_offset + 1],
        image_data[len_offset + 2],
        image_data[len_offset + 3],
    ]) as usize;

    if manifest_len == 0 || manifest_len + 4 > image_data.len() {
        log::warn!(
            "Invalid RMAP manifest length: {} (image size: {})",
            manifest_len,
            image_data.len()
        );
        return Err(CapsuleError::InvalidRmap);
    }

    let manifest_start = len_offset - manifest_len;
    let manifest_bytes = &image_data[manifest_start..len_offset];

    // Parse the manifest as UTF-8 lines of region names
    let manifest_str = core::str::from_utf8(manifest_bytes).map_err(|_| {
        log::warn!("RMAP manifest is not valid UTF-8");
        CapsuleError::InvalidRmap
    })?;

    let mut approved = Vec::new();

    for line in manifest_str.lines() {
        let region_name = line.trim();
        if region_name.is_empty() {
            continue;
        }

        // Look up this region in the actual FMAP
        if let Some(fmap_region) = fmap_regions.iter().find(|r| r.name.as_str() == region_name) {
            log::info!(
                "RMAP: approved region '{}' at offset {:#x}, size {} KB",
                region_name,
                fmap_region.offset,
                fmap_region.size / 1024
            );

            let mut name = heapless::String::new();
            // Truncate if needed
            for c in region_name.chars() {
                if name.push(c).is_err() {
                    break;
                }
            }

            approved.push(ApprovedRegion {
                name,
                offset: fmap_region.offset,
                size: fmap_region.size,
            });
        } else {
            log::warn!(
                "RMAP: region '{}' not found in FMAP — skipping",
                region_name
            );
        }
    }

    if approved.is_empty() {
        log::error!("RMAP: no approved regions found");
        return Err(CapsuleError::InvalidRmap);
    }

    log::info!("RMAP: {} region(s) approved for writing", approved.len());
    Ok(approved)
}

/// Get the firmware image data without the RMAP manifest trailer.
///
/// Returns the image bytes up to (but not including) the manifest,
/// or the full image if no valid manifest is found.
pub fn strip_rmap_manifest(image_data: &[u8]) -> &[u8] {
    if image_data.len() < 4 {
        return image_data;
    }

    let len_offset = image_data.len() - 4;
    let manifest_len = u32::from_le_bytes([
        image_data[len_offset],
        image_data[len_offset + 1],
        image_data[len_offset + 2],
        image_data[len_offset + 3],
    ]) as usize;

    if manifest_len == 0 || manifest_len + 4 > image_data.len() {
        return image_data;
    }

    &image_data[..len_offset - manifest_len]
}
