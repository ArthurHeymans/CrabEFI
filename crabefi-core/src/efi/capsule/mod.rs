//! EFI Capsule Update Support
//!
//! This module implements boot-time capsule processing as a platform-agnostic
//! library. It handles capsules supplied in platform-reserved memory and files
//! discovered on the EFI System Partition. The separate runtime image stages
//! standard post-EBS `UpdateCapsule()` requests in its retained deferred
//! variable journal; this module remains boot-only and consumes the resulting
//! platform capsule handoff on a later boot.
//!
//! # Usage
//!
//! Call [`process_pending_capsules()`] during boot initialization, after
//! the variable store is initialized but before launching the OS.

pub mod apply;
pub mod auth;
pub mod disk;
pub mod fmp;
pub mod header;
pub mod result;
pub mod rmap;

use crabefi_runtime_abi::capsule::{
    CAPSULE_HEADER_SIZE, RETAINED_RESERVATION_CAPSULE_GUID, RETAINED_RESERVATION_MARKER,
    RETAINED_RESERVATION_WRAPPER_GUID,
};

use crate::platform::CapsuleBackend;

pub use header::{CapsuleError, CapsuleType};
pub use result::{CapsuleResult, CapsuleResultStatus};

/// Process all pending capsules from both delivery paths.
///
/// This is the main entry point called during boot initialization.
///
/// # Capsule Sources
///
/// 1. **Coreboot table capsules** (`LB_TAG_CAPSULE`): Capsules that were
///    delivered via `UpdateCapsule()` on the previous boot, stored in
///    `CapsuleUpdateData*` variables, and coalesced by coreboot.
///
/// 2. **ESP capsule files**: Capsule files placed in `\EFI\UpdateCapsule\`
///    on the EFI System Partition by the OS.
///
/// # Arguments
///
/// - `backend`: Platform-specific capsule operations (flash writes, trust store, etc.)
///
/// # Returns
///
/// The number of capsules successfully applied. If any capsule was applied,
/// the caller should trigger a system reset.
pub fn process_pending_capsules(backend: &mut dyn CapsuleBackend) -> usize {
    let mut applied_count = 0;

    // Source 1: Capsules from platform-provided reserved memory regions.
    let platform_capsules = &crate::state::drivers().platform.capsule_regions;
    let platform_capsule_count = platform_capsules.len();
    if platform_capsule_count > 0 {
        log::info!("Processing {} platform capsule(s)", platform_capsule_count);

        for (i, region) in platform_capsules.iter().enumerate() {
            log::info!(
                "Processing platform capsule {}: base={:#x}, size={}",
                i,
                region.base,
                region.size
            );

            // Safety: Platform code validated and coalesced this capsule data
            // into a contiguous reserved memory region.
            let capsule_data = unsafe {
                core::slice::from_raw_parts(region.base as *const u8, region.size as usize)
            };

            if is_retained_reservation_capsule(capsule_data) {
                log::info!("Recognized retained-journal reservation capsule; skipping application");
                continue;
            }

            let result = apply::apply_capsule(capsule_data, backend);
            result::record_capsule_result(i, &result);

            if result.status == CapsuleResultStatus::Success && result.updates_esrt {
                applied_count += 1;
            }
        }
    }

    // Source 2: ESP capsule files (capsule-on-disk)
    let mut disk_capsule_count = 0;
    let file_capsule_delivery_requested = disk::is_file_capsule_delivery_requested();
    if file_capsule_delivery_requested {
        log::info!("File-based capsule delivery requested via OsIndications");

        let disk_capsules = disk::scan_esp_for_capsules();
        disk_capsule_count = disk_capsules.len();
        for (i, capsule) in disk_capsules.iter().enumerate() {
            log::info!(
                "Processing ESP capsule '{}' ({} bytes)",
                capsule.filename,
                capsule.data.len()
            );

            let result_index = platform_capsule_count + i;
            let result = apply::apply_capsule(&capsule.data, backend);
            result::record_capsule_result(result_index, &result);

            if result.status == CapsuleResultStatus::Success && result.updates_esrt {
                applied_count += 1;
            }
        }

        // Clear OsIndications bits to prevent re-processing
        disk::clear_os_indications_capsule_bits();
    }

    if applied_count > 0 {
        log::info!(
            "Capsule processing complete: {}/{} capsule(s) applied successfully",
            applied_count,
            platform_capsule_count + disk_capsule_count
        );
    }

    applied_count
}

fn is_retained_reservation_capsule(data: &[u8]) -> bool {
    let Ok(wrapper) = header::parse_capsule_header(data) else {
        return false;
    };
    if wrapper.capsule_guid.as_bytes() != &RETAINED_RESERVATION_WRAPPER_GUID
        || wrapper.header_size as usize != CAPSULE_HEADER_SIZE
        || wrapper.flags != header::CAPSULE_FLAGS_PERSIST_ACROSS_RESET
        || header::validate_capsule(&wrapper, data.len()).is_err()
    {
        return false;
    }
    let Some(private_data) =
        data.get(wrapper.header_size as usize..wrapper.capsule_image_size as usize)
    else {
        return false;
    };
    let Ok(private) = header::parse_capsule_header(private_data) else {
        return false;
    };
    private.capsule_guid.as_bytes() == &RETAINED_RESERVATION_CAPSULE_GUID
        && private.header_size as usize == CAPSULE_HEADER_SIZE
        && private.flags == header::CAPSULE_FLAGS_PERSIST_ACROSS_RESET
        && private.capsule_image_size as usize == private_data.len()
        && header::validate_capsule(&private, private_data.len()).is_ok()
        && private_data
            .get(CAPSULE_HEADER_SIZE..CAPSULE_HEADER_SIZE + RETAINED_RESERVATION_MARKER.len())
            == Some(RETAINED_RESERVATION_MARKER.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reservation(inner_guid: &[u8; 16], marker: &[u8; 4]) -> [u8; 64] {
        let mut data = [0u8; 64];
        let wrapper_size = data.len() as u32;
        data[..16].copy_from_slice(&RETAINED_RESERVATION_WRAPPER_GUID);
        data[16..20].copy_from_slice(&(CAPSULE_HEADER_SIZE as u32).to_le_bytes());
        data[20..24].copy_from_slice(&header::CAPSULE_FLAGS_PERSIST_ACROSS_RESET.to_le_bytes());
        data[24..28].copy_from_slice(&wrapper_size.to_le_bytes());
        let private = &mut data[CAPSULE_HEADER_SIZE..];
        let private_size = private.len() as u32;
        private[..16].copy_from_slice(inner_guid);
        private[16..20].copy_from_slice(&(CAPSULE_HEADER_SIZE as u32).to_le_bytes());
        private[20..24].copy_from_slice(&header::CAPSULE_FLAGS_PERSIST_ACROSS_RESET.to_le_bytes());
        private[24..28].copy_from_slice(&private_size.to_le_bytes());
        private[CAPSULE_HEADER_SIZE..CAPSULE_HEADER_SIZE + marker.len()].copy_from_slice(marker);
        data
    }

    #[test]
    fn retained_reservation_requires_wrapper_private_guid_and_marker() {
        assert_eq!(
            &RETAINED_RESERVATION_WRAPPER_GUID,
            header::EDK2_CAPSULE_ON_DISK_GUID.as_bytes()
        );
        assert!(is_retained_reservation_capsule(&reservation(
            &RETAINED_RESERVATION_CAPSULE_GUID,
            &RETAINED_RESERVATION_MARKER,
        )));
        assert!(!is_retained_reservation_capsule(&reservation(
            header::WINDOWS_UX_CAPSULE_GUID.as_bytes(),
            &RETAINED_RESERVATION_MARKER,
        )));
        assert!(!is_retained_reservation_capsule(&reservation(
            &RETAINED_RESERVATION_CAPSULE_GUID,
            b"NOPE",
        )));
        let mut wrong_wrapper = reservation(
            &RETAINED_RESERVATION_CAPSULE_GUID,
            &RETAINED_RESERVATION_MARKER,
        );
        wrong_wrapper[..16].copy_from_slice(header::WINDOWS_UX_CAPSULE_GUID.as_bytes());
        assert!(!is_retained_reservation_capsule(&wrong_wrapper));
        let mut truncated_private = reservation(
            &RETAINED_RESERVATION_CAPSULE_GUID,
            &RETAINED_RESERVATION_MARKER,
        );
        let private_image_size = CAPSULE_HEADER_SIZE + 24;
        truncated_private[private_image_size..private_image_size + 4]
            .copy_from_slice(&32u32.to_le_bytes());
        assert!(!is_retained_reservation_capsule(&truncated_private));
    }
}
