//! EFI System Resource Table (ESRT)
//!
//! The ESRT advertises firmware components and their versions to the OS,
//! enabling tools like fwupd/LVFS to discover and manage firmware updates.
//!
//! # References
//!
//! - UEFI Specification 2.10, Section 23.4 — EFI System Resource Table

use r_efi::efi::Guid;

use crate::platform::FirmwareInfo;

// ============================================================================
// ESRT GUIDs and Constants
// ============================================================================

/// GUID for the EFI System Resource Table configuration table entry.
pub const EFI_SYSTEM_RESOURCE_TABLE_GUID: Guid = Guid::from_fields(
    0xB122A263,
    0x3661,
    0x4F68,
    0x99,
    0x29,
    &[0x78, 0xF8, 0xB0, 0xD6, 0x21, 0x80],
);

/// Firmware type: System firmware (BIOS/UEFI).
pub const ESRT_FW_TYPE_SYSTEM_FIRMWARE: u32 = 1;

/// Last attempt status: success.
pub const LAST_ATTEMPT_STATUS_SUCCESS: u32 = 0;

// ============================================================================
// ESRT Table Structures
// ============================================================================

/// EFI System Resource Table header.
///
/// Installed as an EFI Configuration Table so the OS can discover it.
#[repr(C)]
pub struct EfiSystemResourceTable {
    /// Number of firmware resource entries.
    pub fw_resource_count: u32,
    /// Maximum number of entries the table can hold.
    pub fw_resource_count_max: u32,
    /// ESRT version (currently 1).
    pub fw_resource_version: u64,
    // Entries follow immediately after this header.
}

/// A single firmware resource entry in the ESRT.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EfiSystemResourceEntry {
    /// Firmware class GUID (identifies this firmware component).
    pub fw_class: Guid,
    /// Firmware type (see `ESRT_FW_TYPE_*` constants).
    pub fw_type: u32,
    /// Current firmware version.
    pub fw_version: u32,
    /// Lowest supported firmware version (rollback prevention).
    pub lowest_supported_fw_version: u32,
    /// Flags for `UpdateCapsule()` (typically `PERSIST_ACROSS_RESET`).
    pub capsule_flags: u32,
    /// Version of the last update attempt.
    pub last_attempt_version: u32,
    /// Status of the last update attempt.
    pub last_attempt_status: u32,
}

/// Size of the ESRT header (without entries).
const ESRT_HEADER_SIZE: usize = core::mem::size_of::<EfiSystemResourceTable>();

/// Size of a single ESRT entry.
const ESRT_ENTRY_SIZE: usize = core::mem::size_of::<EfiSystemResourceEntry>();

// ============================================================================
// Static ESRT Storage
// ============================================================================

/// Maximum number of ESRT entries we support.
const MAX_ESRT_ENTRIES: usize = 4;

/// Static buffer for the ESRT table (header + entries).
/// Must be aligned to 8 bytes for the configuration table pointer.
#[repr(C, align(8))]
struct EsrtBuffer {
    header: EfiSystemResourceTable,
    entries: [EfiSystemResourceEntry; MAX_ESRT_ENTRIES],
}

static mut ESRT_TABLE: EsrtBuffer = EsrtBuffer {
    header: EfiSystemResourceTable {
        fw_resource_count: 0,
        fw_resource_count_max: MAX_ESRT_ENTRIES as u32,
        fw_resource_version: 1,
    },
    entries: [EfiSystemResourceEntry {
        fw_class: Guid::from_fields(0, 0, 0, 0, 0, &[0; 6]),
        fw_type: 0,
        fw_version: 0,
        lowest_supported_fw_version: 0,
        capsule_flags: 0,
        last_attempt_version: 0,
        last_attempt_status: 0,
    }; MAX_ESRT_ENTRIES],
};

// ============================================================================
// Public API
// ============================================================================

/// Build and install the ESRT as an EFI Configuration Table.
///
/// Call this during boot initialization after coreboot table parsing
/// has populated the firmware info.
///
/// # Arguments
///
/// - `fw_info`: Firmware identity and version from `LB_TAG_EFI_FW_INFO`.
pub fn install_esrt(fw_info: &FirmwareInfo) {
    let guid = guid_from_bytes(&fw_info.guid);

    // Safety: ESRT_TABLE is only written during single-threaded boot init.
    unsafe {
        ESRT_TABLE.header.fw_resource_count = 1;
        ESRT_TABLE.entries[0] = EfiSystemResourceEntry {
            fw_class: guid,
            fw_type: ESRT_FW_TYPE_SYSTEM_FIRMWARE,
            fw_version: fw_info.version,
            lowest_supported_fw_version: fw_info.lowest_supported_version,
            capsule_flags: 0x0001_0000, // PERSIST_ACROSS_RESET
            last_attempt_version: 0,
            last_attempt_status: LAST_ATTEMPT_STATUS_SUCCESS,
        };

        let esrt_ptr = &raw const ESRT_TABLE as *mut core::ffi::c_void;
        crate::efi::system_table::install_configuration_table(
            &EFI_SYSTEM_RESOURCE_TABLE_GUID,
            esrt_ptr,
        );
    }

    log::info!(
        "ESRT installed: fw_version={:#x}, LSV={:#x}, size={} KB",
        fw_info.version,
        fw_info.lowest_supported_version,
        fw_info.fw_size / 1024
    );
}

/// Convert a 16-byte GUID array to an `r_efi::efi::Guid`.
fn guid_from_bytes(bytes: &[u8; 16]) -> Guid {
    Guid::from_fields(
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        bytes[8],
        bytes[9],
        &[
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ],
    )
}
