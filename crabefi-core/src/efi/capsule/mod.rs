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
                log::debug!("Consumed retained-journal reservation capsule");
                continue;
            }

            let result = apply::apply_capsule(capsule_data, backend);
            result::record_capsule_result(i, &result);

            if result.status == CapsuleResultStatus::Success {
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

            if result.status == CapsuleResultStatus::Success {
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
    let Ok(header) = header::parse_capsule_header(data) else {
        return false;
    };
    header.capsule_guid.as_bytes() == header::WINDOWS_UX_CAPSULE_GUID.as_bytes()
        && data.get(header.header_size as usize..header.header_size as usize + 4) == Some(b"CRDJ")
}
