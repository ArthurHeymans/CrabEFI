//! EDK2-compatible UEFI Firmware Volume variable store format
//!
//! This module implements the on-disk format used by UEFI firmware (EDK2/TianoCore)
//! for storing UEFI variables, matching what coreboot's `get_uint_option()` reads.
//!
//! # On-disk layout
//!
//! ```text
//! +--------------------------------------------+ offset 0x0000
//! |  EFI_FIRMWARE_VOLUME_HEADER  (72 bytes)    |
//! +--------------------------------------------+ offset 0x0048
//! |  VARIABLE_STORE_HEADER       (28 bytes)    |
//! +--------------------------------------------+ offset 0x0064
//! |  Variable Record #1 (header + name + data) |
//! |  (padded to 4-byte alignment)              |
//! +--------------------------------------------+
//! |  Variable Record #2                        |
//! +--------------------------------------------+
//! |  ...                                       |
//! +--------------------------------------------+
//! |  Free space (0xFF)                         |
//! +--------------------------------------------+
//! ```

use alloc::vec;
use alloc::vec::Vec;

// ============================================================================
// Constants
// ============================================================================

/// EFI Firmware Volume Header signature: "_FVH"
const FV_SIGNATURE: u32 = 0x4856_465F;

/// FV header revision
const FV_REVISION: u8 = 0x02;

/// Firmware Volume header length (including one block map entry + terminator)
pub const FV_HEADER_LENGTH: usize = 0x48; // 72 bytes

/// Variable Store header length
pub const VS_HEADER_LENGTH: usize = 0x1C; // 28 bytes

/// Offset where variable records begin (FV header + VS header)
pub const VARIABLE_DATA_OFFSET: u32 = (FV_HEADER_LENGTH + VS_HEADER_LENGTH) as u32;

/// Variable record start marker
const VARIABLE_DATA: u16 = 0x55AA;

/// Variable record alignment
const HEADER_ALIGNMENT: u32 = 4;

/// Variable store format byte: formatted
const VARIABLE_STORE_FORMATTED: u8 = 0x5A;

/// Variable store state byte: healthy
const VARIABLE_STORE_HEALTHY: u8 = 0xFE;

// Variable states (bits cleared in 0xFF flash):
/// Variable is fully valid (bits 7 and 6 cleared)
pub const VAR_ADDED: u8 = 0x3F;
/// Header written, data may not be complete (bit 7 cleared)
const VAR_HEADER_VALID_ONLY: u8 = 0x7F;
/// Variable is being deleted (bit 0 cleared from VAR_ADDED)
const _VAR_IN_DELETED_TRANSITION: u8 = 0xFE;
/// Variable is deleted
const VAR_DELETED: u8 = 0xFD;

/// Non-authenticated variable header size
pub const VAR_HEADER_SIZE: usize = 32;

/// Authenticated variable header size (not currently used for writing, but
/// needed for reading stores created by EDK2 which uses auth format)
pub const AUTH_VAR_HEADER_SIZE: usize = 60;

// ============================================================================
// GUID constants (as raw LE bytes, matching coreboot's layout)
// ============================================================================

/// EFI System NV Data FV GUID: {fff12b8d-7696-4c8b-a985-2747075b4f50}
/// Used in the Firmware Volume header's FileSystemGuid field.
const EFI_SYSTEM_NV_DATA_FV_GUID: [u8; 16] = [
    0x8d, 0x2b, 0xf1, 0xff, 0x96, 0x76, 0x8b, 0x4c, 0xa9, 0x85, 0x27, 0x47, 0x07, 0x5b, 0x4f, 0x50,
];

/// EFI Variable GUID (non-authenticated format): {ddcf3616-3275-4164-98b6-fe85707ffe7d}
/// Used in the Variable Store header's Signature field.
const EFI_VARIABLE_GUID: [u8; 16] = [
    0x16, 0x36, 0xcf, 0xdd, 0x75, 0x32, 0x64, 0x41, 0x98, 0xb6, 0xfe, 0x85, 0x70, 0x7f, 0xfe, 0x7d,
];

/// EFI Authenticated Variable GUID: {aaf32c78-947b-439a-a180-2e144ec37792}
/// Indicates the variable store uses authenticated variable headers.
const EFI_AUTH_VARIABLE_GUID: [u8; 16] = [
    0x78, 0x2c, 0xf3, 0xaa, 0x7b, 0x94, 0x9a, 0x43, 0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92,
];

// ============================================================================
// FV header construction / validation
// ============================================================================

/// Build a complete EDK2 Firmware Volume header + Variable Store header.
///
/// `region_size` is the total SMMSTORE region size in bytes.
/// Returns the header bytes (FV_HEADER_LENGTH + VS_HEADER_LENGTH).
pub fn build_fv_headers(region_size: u32) -> [u8; FV_HEADER_LENGTH + VS_HEADER_LENGTH] {
    let mut buf = [0u8; FV_HEADER_LENGTH + VS_HEADER_LENGTH];

    // --- EFI_FIRMWARE_VOLUME_HEADER (72 bytes) ---
    // ZeroVector[16] at offset 0x00: already zero
    // FileSystemGuid at offset 0x10
    buf[0x10..0x20].copy_from_slice(&EFI_SYSTEM_NV_DATA_FV_GUID);
    // FvLength (u64 LE) at offset 0x20
    buf[0x20..0x28].copy_from_slice(&(region_size as u64).to_le_bytes());
    // Signature at offset 0x28
    buf[0x28..0x2C].copy_from_slice(&FV_SIGNATURE.to_le_bytes());
    // Attributes at offset 0x2C (standard NV variable store attributes)
    buf[0x2C..0x30].copy_from_slice(&0x0004_FEFFu32.to_le_bytes());
    // HeaderLength at offset 0x30
    buf[0x30..0x32].copy_from_slice(&(FV_HEADER_LENGTH as u16).to_le_bytes());
    // Checksum at offset 0x32: computed below
    // ExtHeaderOffset at offset 0x34: 0
    // Reserved at offset 0x36: 0
    // Revision at offset 0x37
    buf[0x37] = FV_REVISION;
    // BlockMap[0]: {NumBlocks=1, Length=region_size} at offset 0x38
    buf[0x38..0x3C].copy_from_slice(&1u32.to_le_bytes());
    buf[0x3C..0x40].copy_from_slice(&region_size.to_le_bytes());
    // BlockMap[1]: terminator {0, 0} at offset 0x40 — already zero

    // Compute FV header checksum (sum of all u16 words over HeaderLength must be 0)
    let checksum = compute_fv_checksum(&buf[..FV_HEADER_LENGTH]);
    buf[0x32..0x34].copy_from_slice(&checksum.to_le_bytes());

    // --- VARIABLE_STORE_HEADER (28 bytes) at offset 0x48 ---
    let vs_off = FV_HEADER_LENGTH;
    // Signature (GUID) — use non-authenticated format
    buf[vs_off..vs_off + 16].copy_from_slice(&EFI_VARIABLE_GUID);
    // Size (u32 LE): size of the variable data area (after both FV and VS headers).
    //
    // Coreboot's efivars.c:199 does:
    //   rdev_chain(rdev, rdev, HeaderLength + sizeof(VS_HEADER), hdr.Size)
    // For this to fit within the region: HeaderLength + sizeof(VS_HEADER) + Size <= region_size
    // Therefore Size must be region_size - FV_HEADER - VS_HEADER.
    let vs_size = region_size - FV_HEADER_LENGTH as u32 - VS_HEADER_LENGTH as u32;
    buf[vs_off + 0x10..vs_off + 0x14].copy_from_slice(&vs_size.to_le_bytes());
    // Format
    buf[vs_off + 0x14] = VARIABLE_STORE_FORMATTED;
    // State
    buf[vs_off + 0x15] = VARIABLE_STORE_HEALTHY;
    // Reserved (2 + 4 bytes): already zero

    buf
}

/// Compute the 16-bit checksum for the FV header.
///
/// Returns the value to store at the Checksum field such that the sum of
/// all u16 words across the header equals 0.
fn compute_fv_checksum(header: &[u8]) -> u16 {
    // First zero out the checksum field (at offset 0x32-0x33)
    let mut sum: u16 = 0;
    for i in (0..header.len()).step_by(2) {
        if i == 0x32 {
            continue; // skip the checksum field itself
        }
        let lo = header[i] as u16;
        let hi = if i + 1 < header.len() {
            header[i + 1] as u16
        } else {
            0
        };
        sum = sum.wrapping_add(lo | (hi << 8));
    }
    // Checksum must make the total 0
    0u16.wrapping_sub(sum)
}

/// Validation result for an existing FV region
pub struct FvValidation {
    /// Whether the region has a valid FV + VS header
    pub valid: bool,
    /// Whether the variable store uses authenticated headers
    pub auth_format: bool,
    /// Size of the variable store data area (after VS header)
    pub data_size: u32,
}

/// Validate an existing Firmware Volume in a flash region.
///
/// `header_bytes` must be at least `FV_HEADER_LENGTH + VS_HEADER_LENGTH` bytes,
/// read from offset 0 of the SMMSTORE region.
///
/// Returns validation result with format details needed for reading.
pub fn validate_fv(header_bytes: &[u8], region_size: u32) -> FvValidation {
    let invalid = FvValidation {
        valid: false,
        auth_format: false,
        data_size: 0,
    };

    if header_bytes.len() < FV_HEADER_LENGTH + VS_HEADER_LENGTH {
        return invalid;
    }

    // Check FV signature at offset 0x28
    let sig = u32::from_le_bytes([
        header_bytes[0x28],
        header_bytes[0x29],
        header_bytes[0x2A],
        header_bytes[0x2B],
    ]);
    if sig != FV_SIGNATURE {
        log::debug!(
            "FV signature mismatch: {:#x} (expected {:#x})",
            sig,
            FV_SIGNATURE
        );
        return invalid;
    }

    // Check revision at offset 0x37
    if header_bytes[0x37] != FV_REVISION {
        log::debug!("FV revision mismatch: {}", header_bytes[0x37]);
        return invalid;
    }

    // Check FileSystemGuid at offset 0x10
    if header_bytes[0x10..0x20] != EFI_SYSTEM_NV_DATA_FV_GUID {
        log::debug!("FV FileSystemGuid mismatch");
        return invalid;
    }

    // Check FV header checksum
    let header_length = u16::from_le_bytes([header_bytes[0x30], header_bytes[0x31]]) as usize;
    if header_length > header_bytes.len()
        || header_length < 0x38
        || !header_length.is_multiple_of(2)
    {
        log::debug!("FV header length invalid: {}", header_length);
        return invalid;
    }
    let mut checksum: u16 = 0;
    for i in (0..header_length).step_by(2) {
        let lo = header_bytes[i] as u16;
        let hi = header_bytes[i + 1] as u16;
        checksum = checksum.wrapping_add(lo | (hi << 8));
    }
    if checksum != 0 {
        log::debug!("FV header checksum failed: {:#x}", checksum);
        return invalid;
    }

    // Check variable store header at FV_HEADER_LENGTH
    let vs = &header_bytes[FV_HEADER_LENGTH..];

    // Determine auth vs non-auth format from VS Signature GUID
    let auth_format = if vs[..16] == EFI_VARIABLE_GUID {
        false
    } else if vs[..16] == EFI_AUTH_VARIABLE_GUID {
        true
    } else {
        log::debug!("VS Signature GUID not recognized");
        return invalid;
    };

    // Check Format and State
    if vs[0x14] != VARIABLE_STORE_FORMATTED || vs[0x15] != VARIABLE_STORE_HEALTHY {
        log::debug!(
            "VS format/state invalid: format={:#x} state={:#x}",
            vs[0x14],
            vs[0x15]
        );
        return invalid;
    }

    let vs_size = u32::from_le_bytes([vs[0x10], vs[0x11], vs[0x12], vs[0x13]]);
    if vs_size > region_size - FV_HEADER_LENGTH as u32 {
        log::debug!("VS size exceeds region");
        return invalid;
    }

    // In coreboot's convention (efivars.c:199), the VS Size field represents the
    // size of the variable data area — i.e., the space AFTER both the FV header
    // and VS header. This is what coreboot passes directly to rdev_chain as the
    // size of the child region.
    //
    // For stores created by EDK2 (where Size may include the VS header per the
    // spec comment), vs_size could be slightly larger than the actual data area.
    // This is harmless because walk_variables stops at 0xFF (erased flash).
    let data_size = vs_size;

    FvValidation {
        valid: true,
        auth_format,
        data_size,
    }
}

// ============================================================================
// Variable record reading
// ============================================================================

/// A parsed variable from the FV store
pub struct FvVariable {
    /// EFI_GUID as raw 16-byte LE (mixed-endian)
    pub guid: [u8; 16],
    /// Variable name (UTF-16LE, with null terminator)
    pub name: Vec<u16>,
    /// Variable attributes
    pub attributes: u32,
    /// Variable data
    pub data: Vec<u8>,
    /// Variable state
    pub state: u8,
    /// Offset of this record's State byte in the storage region
    /// (relative to storage base, i.e., absolute within the region)
    pub state_offset: u32,
}

/// Walk all variable records in the FV data area.
///
/// `read_fn` reads bytes from the storage region at the given offset.
/// `auth_format` indicates whether to use authenticated variable headers.
/// `data_size` is the size of the variable data area (from `FvValidation`).
///
/// Returns all parsed variables (including deleted ones — caller filters).
pub fn walk_variables<F>(read_fn: &mut F, auth_format: bool, data_size: u32) -> Vec<FvVariable>
where
    F: FnMut(u32, &mut [u8]) -> bool,
{
    let mut vars = Vec::new();
    let hdr_size = if auth_format {
        AUTH_VAR_HEADER_SIZE
    } else {
        VAR_HEADER_SIZE
    } as u32;

    let mut offset = VARIABLE_DATA_OFFSET;
    let end = VARIABLE_DATA_OFFSET + data_size;

    while offset + hdr_size <= end {
        // Read the variable header
        let mut hdr_buf = vec![0u8; hdr_size as usize];
        if !read_fn(offset, &mut hdr_buf) {
            break;
        }

        // Check StartId
        let start_id = u16::from_le_bytes([hdr_buf[0], hdr_buf[1]]);
        if start_id != VARIABLE_DATA {
            break; // End of variable records (free space)
        }

        let state = hdr_buf[2];

        // Check for erased/corrupt entry
        if state == 0xFF {
            break;
        }

        // Parse fields based on format
        let (attributes, name_size, data_size_field, guid_offset) = if auth_format {
            // Authenticated: attributes at 0x04, name_size at 0x24, data_size at 0x28,
            // guid at 0x2C
            let attrs =
                u32::from_le_bytes([hdr_buf[0x04], hdr_buf[0x05], hdr_buf[0x06], hdr_buf[0x07]]);
            let ns =
                u32::from_le_bytes([hdr_buf[0x24], hdr_buf[0x25], hdr_buf[0x26], hdr_buf[0x27]]);
            let ds =
                u32::from_le_bytes([hdr_buf[0x28], hdr_buf[0x29], hdr_buf[0x2A], hdr_buf[0x2B]]);
            (attrs, ns, ds, 0x2Cu32)
        } else {
            // Non-auth: attributes at 0x04, name_size at 0x08, data_size at 0x0C,
            // guid at 0x10
            let attrs =
                u32::from_le_bytes([hdr_buf[0x04], hdr_buf[0x05], hdr_buf[0x06], hdr_buf[0x07]]);
            let ns =
                u32::from_le_bytes([hdr_buf[0x08], hdr_buf[0x09], hdr_buf[0x0A], hdr_buf[0x0B]]);
            let ds =
                u32::from_le_bytes([hdr_buf[0x0C], hdr_buf[0x0D], hdr_buf[0x0E], hdr_buf[0x0F]]);
            (attrs, ns, ds, 0x10u32)
        };

        // Sanity check sizes — 0xFFFFFFFF means uninitialized
        if name_size == 0xFFFFFFFF || data_size_field == 0xFFFFFFFF || attributes == 0xFFFFFFFF {
            // Corrupt/uninitialized — skip with zero sizes
            let var_size = align_up(hdr_size, HEADER_ALIGNMENT);
            offset += var_size;
            continue;
        }

        // Read GUID
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&hdr_buf[guid_offset as usize..guid_offset as usize + 16]);

        // Read name (UTF-16LE)
        let name_offset = offset + hdr_size;
        if name_offset + name_size > end {
            break;
        }
        let mut name_bytes = vec![0u8; name_size as usize];
        if !read_fn(name_offset, &mut name_bytes) {
            break;
        }
        // Convert to Vec<u16>
        let name: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();

        // Read data
        let data_offset = name_offset + name_size;
        if data_offset + data_size_field > end {
            break;
        }
        let mut data = vec![0u8; data_size_field as usize];
        if !read_fn(data_offset, &mut data) {
            break;
        }

        // State byte offset (relative to storage region base)
        let state_offset = offset + 2; // State is at offset 2 within the header

        vars.push(FvVariable {
            guid,
            name,
            attributes,
            data,
            state,
            state_offset,
        });

        // Advance to next record (aligned)
        let total_size = hdr_size + name_size + data_size_field;
        offset += align_up(total_size, HEADER_ALIGNMENT);
    }

    vars
}

/// Find the write offset (first free byte) in the variable data area.
pub fn find_write_offset<F>(read_fn: &mut F, auth_format: bool, data_size: u32) -> u32
where
    F: FnMut(u32, &mut [u8]) -> bool,
{
    let hdr_size = if auth_format {
        AUTH_VAR_HEADER_SIZE
    } else {
        VAR_HEADER_SIZE
    } as u32;

    let mut offset = VARIABLE_DATA_OFFSET;
    let end = VARIABLE_DATA_OFFSET + data_size;

    while offset + hdr_size <= end {
        let mut start_id_buf = [0u8; 2];
        if !read_fn(offset, &mut start_id_buf) {
            break;
        }
        let start_id = u16::from_le_bytes(start_id_buf);
        if start_id != VARIABLE_DATA {
            break;
        }

        // Read header to get sizes
        let mut hdr_buf = vec![0u8; hdr_size as usize];
        if !read_fn(offset, &mut hdr_buf) {
            break;
        }

        let state = hdr_buf[2];
        if state == 0xFF {
            break;
        }

        let (name_size, data_size_field) = if auth_format {
            let ns =
                u32::from_le_bytes([hdr_buf[0x24], hdr_buf[0x25], hdr_buf[0x26], hdr_buf[0x27]]);
            let ds =
                u32::from_le_bytes([hdr_buf[0x28], hdr_buf[0x29], hdr_buf[0x2A], hdr_buf[0x2B]]);
            (ns, ds)
        } else {
            let ns =
                u32::from_le_bytes([hdr_buf[0x08], hdr_buf[0x09], hdr_buf[0x0A], hdr_buf[0x0B]]);
            let ds =
                u32::from_le_bytes([hdr_buf[0x0C], hdr_buf[0x0D], hdr_buf[0x0E], hdr_buf[0x0F]]);
            (ns, ds)
        };

        if name_size == 0xFFFFFFFF || data_size_field == 0xFFFFFFFF {
            let var_size = align_up(hdr_size, HEADER_ALIGNMENT);
            offset += var_size;
            continue;
        }

        let total_size = hdr_size + name_size + data_size_field;
        offset += align_up(total_size, HEADER_ALIGNMENT);
    }

    offset
}

// ============================================================================
// Variable record writing
// ============================================================================

/// Build a non-authenticated variable record (header + name bytes + data).
///
/// `guid_bytes` is the 16-byte mixed-endian EFI_GUID.
/// `name` is the UTF-16LE variable name including null terminator.
/// `data` is the raw variable data.
///
/// The returned bytes include the full record, aligned to HEADER_ALIGNMENT.
/// The State byte is initially 0xFF (will be written in stages).
pub fn build_variable_record(
    guid_bytes: &[u8; 16],
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Vec<u8> {
    let name_bytes_len = name.len() * 2; // UTF-16LE
    let total_raw = VAR_HEADER_SIZE + name_bytes_len + data.len();
    let total_aligned = align_up(total_raw as u32, HEADER_ALIGNMENT) as usize;

    let mut buf = vec![0xFF; total_aligned]; // Start with 0xFF (erased flash pattern)

    // VARIABLE_HEADER (32 bytes):
    // StartId at 0x00
    buf[0..2].copy_from_slice(&VARIABLE_DATA.to_le_bytes());
    // State at 0x02: leave as 0xFF (written separately in stages)
    // Reserved at 0x03: leave as 0xFF (or 0x00 — doesn't matter)
    buf[0x03] = 0x00;
    // Attributes at 0x04
    buf[0x04..0x08].copy_from_slice(&attributes.to_le_bytes());
    // NameSize at 0x08
    buf[0x08..0x0C].copy_from_slice(&(name_bytes_len as u32).to_le_bytes());
    // DataSize at 0x0C
    buf[0x0C..0x10].copy_from_slice(&(data.len() as u32).to_le_bytes());
    // VendorGuid at 0x10
    buf[0x10..0x20].copy_from_slice(guid_bytes);

    // Name (UTF-16LE) at offset VAR_HEADER_SIZE
    let name_offset = VAR_HEADER_SIZE;
    for (i, &ch) in name.iter().enumerate() {
        let off = name_offset + i * 2;
        buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
    }

    // Data at offset VAR_HEADER_SIZE + name_bytes_len
    let data_offset = name_offset + name_bytes_len;
    buf[data_offset..data_offset + data.len()].copy_from_slice(data);

    // Padding bytes between end of data and total_aligned remain 0xFF

    buf
}

/// Write a new variable record to the FV store using the multi-stage protocol.
///
/// `write_fn` writes bytes at the given offset in the storage region.
/// `write_offset` is where the new record will be written.
///
/// The protocol:
/// 1. Write full header + name + data (State byte = 0xFF)
/// 2. Write State = VAR_HEADER_VALID_ONLY (0x7F)
/// 3. (Name + data already written in step 1)
/// 4. Write State = VAR_ADDED (0x3F)
///
/// Returns the new write_offset after the record, or None on failure.
pub fn write_variable<F>(
    write_fn: &mut F,
    write_offset: u32,
    guid_bytes: &[u8; 16],
    name: &[u16],
    attributes: u32,
    data: &[u8],
) -> Option<u32>
where
    F: FnMut(u32, &[u8]) -> bool,
{
    let record = build_variable_record(guid_bytes, name, attributes, data);
    let record_len = record.len() as u32;

    // Step 1: Write entire record (State = 0xFF from build)
    if !write_fn(write_offset, &record) {
        return None;
    }

    // Step 2: Write State = VAR_HEADER_VALID_ONLY
    let state_offset = write_offset + 2;
    if !write_fn(state_offset, &[VAR_HEADER_VALID_ONLY]) {
        return None;
    }

    // Step 3: Name + data already written in step 1

    // Step 4: Write State = VAR_ADDED
    if !write_fn(state_offset, &[VAR_ADDED]) {
        return None;
    }

    Some(write_offset + record_len)
}

/// Mark an existing variable as deleted by writing to its State byte.
///
/// On NOR flash, writes can only clear bits (1→0). The current state is
/// `VAR_ADDED` (0x3F). Writing `VAR_DELETED` (0xFD) results in the flash
/// performing `0x3F & 0xFD = 0x3D`, which clears bit 1. The result (0x3D)
/// is neither `VAR_ADDED` (0x3F) nor `VAR_IN_DELETED_TRANSITION & VAR_ADDED`
/// (0x3E), so coreboot's `match()` correctly skips it.
///
/// Note: coreboot's own `efi_fv_set_option()` uses a two-step deletion
/// (first 0xFE → 0x3E, then 0xFD → 0x3C) for power-failure robustness.
/// Our single-step approach is functionally equivalent for the reader.
pub fn mark_deleted<F>(write_fn: &mut F, state_offset: u32) -> bool
where
    F: FnMut(u32, &[u8]) -> bool,
{
    write_fn(state_offset, &[VAR_DELETED])
}

/// Check if a variable is in the "added" (valid) state.
pub fn is_var_added(state: u8) -> bool {
    state == VAR_ADDED
}

// ============================================================================
// Helpers
// ============================================================================

/// Align a value up to the given alignment (must be a power of 2).
fn align_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

/// Convert an `r_efi::efi::Guid` to the 16-byte mixed-endian representation
/// used in EDK2 on-disk format.
pub fn guid_to_bytes(guid: &r_efi::efi::Guid) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(guid.as_bytes());
    bytes
}

/// Compare a 16-byte GUID from a variable record against an `r_efi::efi::Guid`.
pub fn guid_matches(on_disk: &[u8; 16], guid: &r_efi::efi::Guid) -> bool {
    *on_disk == guid_to_bytes(guid)
}

/// Compare variable names (UTF-16, case-sensitive, including null terminator).
pub fn name_matches(on_disk: &[u16], name: &[u16]) -> bool {
    // Strip trailing nulls for comparison
    fn strip(n: &[u16]) -> &[u16] {
        let len = n.iter().position(|&c| c == 0).unwrap_or(n.len());
        &n[..len]
    }
    strip(on_disk) == strip(name)
}
