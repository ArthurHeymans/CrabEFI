//! EFI Capsule Update Support
//!
//! This module implements UEFI capsule update processing as a platform-agnostic
//! library. It handles both runtime-delivered capsules (via `UpdateCapsule()`)
//! and file-based capsules (from the EFI System Partition).
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────┐  ┌──────────────────────────┐
//! │  Runtime UpdateCapsule │  │  ESP \EFI\UpdateCapsule\  │
//! │  (deferred → SMMSTORE  │  │  (disk.rs scanner)        │
//! │   → coreboot → LB_TAG) │  │                          │
//! └───────────┬────────────┘  └────────────┬─────────────┘
//!             │                             │
//!             └──────────┬──────────────────┘
//!                        ▼
//!              ┌─────────────────────┐
//!              │  process_capsules() │  (this module)
//!              │                     │
//!              │  header → fmp →     │
//!              │  auth → rmap →      │
//!              │  apply → result     │
//!              └─────────────────────┘
//! ```
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

    // Source 1: Capsules from coreboot tables (LB_TAG_CAPSULE)
    let cb_capsule_count = crate::coreboot::capsule_count();
    if cb_capsule_count > 0 {
        log::info!(
            "Processing {} capsule(s) from coreboot tables",
            cb_capsule_count
        );

        for i in 0..cb_capsule_count {
            if let Some(region) = crate::coreboot::get_capsule(i) {
                log::info!(
                    "Processing coreboot capsule {}: base={:#x}, size={}",
                    i,
                    region.base,
                    region.size
                );

                // Safety: coreboot has validated and coalesced this capsule data
                // into a contiguous memory region that is reserved in bootmem.
                let capsule_data = unsafe {
                    core::slice::from_raw_parts(region.base as *const u8, region.size as usize)
                };

                let result = apply::apply_capsule(capsule_data, backend);
                result::record_capsule_result(i, &result);

                if result.status == CapsuleResultStatus::Success {
                    applied_count += 1;
                }
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

            let result_index = cb_capsule_count + i;
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
            cb_capsule_count + disk_capsule_count
        );
    }

    applied_count
}

/// Stage capsules for processing on the next reboot (runtime path).
///
/// Called by `UpdateCapsule()` after `ExitBootServices`. Stores the
/// scatter-gather list pointer as `CapsuleUpdateData*` variables in the
/// deferred write buffer.
///
/// The variables will be applied to SMMSTORE on the next boot, where
/// coreboot will discover and coalesce them.
pub fn stage_capsule_for_reboot(
    scatter_gather_list: u64,
    capsule_index: usize,
) -> Result<(), CapsuleError> {
    use crate::efi::auth;
    use crate::efi::varstore;

    // Variable name: "CapsuleUpdateData" or "CapsuleUpdateData1", etc.
    let name_str = if capsule_index == 0 {
        alloc::string::String::from("CapsuleUpdateData")
    } else {
        alloc::format!("CapsuleUpdateData{}", capsule_index)
    };

    let mut name_u16: alloc::vec::Vec<u16> = name_str.encode_utf16().collect();
    name_u16.push(0); // null terminator

    // Vendor GUID for CapsuleUpdateData* variables
    // {711C703F-C285-4B10-A3B0-36ECBD3C8BE2}
    let capsule_vendor_guid = r_efi::efi::Guid::from_fields(
        0x711C703F,
        0xC285,
        0x4B10,
        0xA3,
        0xB0,
        &[0x36, 0xEC, 0xBD, 0x3C, 0x8B, 0xE2],
    );

    // Data is the physical address of the scatter-gather list (u64)
    let data = scatter_gather_list.to_le_bytes();

    // Attributes: NV + BS + RT
    let attributes = auth::attributes::NON_VOLATILE
        | auth::attributes::BOOTSERVICE_ACCESS
        | auth::attributes::RUNTIME_ACCESS;

    // Write via the deferred path (we're after ExitBootServices)
    varstore::persist_variable(&capsule_vendor_guid, name_u16.as_slice(), attributes, &data)
        .map_err(|_| CapsuleError::FlashWriteFailed)?;

    log::info!(
        "Staged {} at SG list {:#x} for next boot",
        name_str,
        scatter_gather_list
    );

    Ok(())
}
