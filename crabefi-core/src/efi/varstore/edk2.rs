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

use crabefi_efi_types::varstore::{
    self, EFI_AUTH_VARIABLE_GUID, EFI_SYSTEM_NV_DATA_FV_GUID, FV_REVISION, FV_SIGNATURE,
    HEADER_ALIGNMENT, VAR_DELETED, VAR_HEADER_VALID_ONLY, VARIABLE_DATA, VARIABLE_STORE_FORMATTED,
    VARIABLE_STORE_HEALTHY, align_up, checked_align_up,
};
pub use crabefi_efi_types::varstore::{
    AUTH_VAR_HEADER_SIZE, FV_HEADER_LENGTH, FvValidation, VAR_ADDED, VAR_HEADER_SIZE,
    VARIABLE_DATA_OFFSET, VS_HEADER_LENGTH, read_variable_data_from_region,
};
use crabefi_runtime_abi::VariableTimestamp;
use zerocopy::byteorder::{I16, LittleEndian, U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
struct EfiTimeLe {
    year: U16<LittleEndian>,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    pad1: u8,
    nanosecond: U32<LittleEndian>,
    timezone: I16<LittleEndian>,
    daylight: u8,
    pad2: u8,
}

/// Fixed-width EDK2 authenticated-variable record header.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
struct AuthenticatedVariableHeader {
    start_id: U16<LittleEndian>,
    state: u8,
    reserved: u8,
    attributes: U32<LittleEndian>,
    monotonic_count: U64<LittleEndian>,
    timestamp: EfiTimeLe,
    pub_key_index: U32<LittleEndian>,
    name_size: U32<LittleEndian>,
    data_size: U32<LittleEndian>,
    vendor_guid: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<EfiTimeLe>() == 16);
const _: () = assert!(core::mem::size_of::<AuthenticatedVariableHeader>() == AUTH_VAR_HEADER_SIZE);
const _: () = assert!(core::mem::offset_of!(AuthenticatedVariableHeader, start_id) == 0x00);
const _: () = assert!(core::mem::offset_of!(AuthenticatedVariableHeader, attributes) == 0x04);
const _: () = assert!(core::mem::offset_of!(AuthenticatedVariableHeader, timestamp) == 0x10);
const _: () = assert!(core::mem::offset_of!(AuthenticatedVariableHeader, name_size) == 0x24);
const _: () = assert!(core::mem::offset_of!(AuthenticatedVariableHeader, data_size) == 0x28);
const _: () = assert!(core::mem::offset_of!(AuthenticatedVariableHeader, vendor_guid) == 0x2c);

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
    // Signature (GUID) — authenticated headers durably carry replay floors.
    buf[vs_off..vs_off + 16].copy_from_slice(&EFI_AUTH_VARIABLE_GUID);
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

/// Validate an existing Firmware Volume in a flash region.
///
/// `header_bytes` must be at least `FV_HEADER_LENGTH + VS_HEADER_LENGTH` bytes,
/// read from offset 0 of the SMMSTORE region.
///
/// Returns validation result with format details needed for reading.
pub fn validate_fv(header_bytes: &[u8], region_size: u32) -> FvValidation {
    varstore::validate(header_bytes, region_size).unwrap_or_else(|| {
        log::debug!("FV or variable store header invalid");
        FvValidation {
            valid: false,
            auth_format: false,
            data_size: 0,
        }
    })
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
    /// Timestamp from an authenticated-format record header, when present.
    pub timestamp: Option<VariableTimestamp>,
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
    let Some(end) = VARIABLE_DATA_OFFSET.checked_add(data_size) else {
        return vars;
    };

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
        let (attributes, name_size, data_size_field, guid_offset, timestamp) = if auth_format {
            // Authenticated: attributes at 0x04, name_size at 0x24, data_size at 0x28,
            // guid at 0x2C
            let attrs =
                u32::from_le_bytes([hdr_buf[0x04], hdr_buf[0x05], hdr_buf[0x06], hdr_buf[0x07]]);
            let ns =
                u32::from_le_bytes([hdr_buf[0x24], hdr_buf[0x25], hdr_buf[0x26], hdr_buf[0x27]]);
            let ds =
                u32::from_le_bytes([hdr_buf[0x28], hdr_buf[0x29], hdr_buf[0x2A], hdr_buf[0x2B]]);
            let timestamp = VariableTimestamp {
                year: u16::from_le_bytes([hdr_buf[0x10], hdr_buf[0x11]]),
                month: hdr_buf[0x12],
                day: hdr_buf[0x13],
                hour: hdr_buf[0x14],
                minute: hdr_buf[0x15],
                second: hdr_buf[0x16],
                pad1: hdr_buf[0x17],
                nanosecond: u32::from_le_bytes([
                    hdr_buf[0x18],
                    hdr_buf[0x19],
                    hdr_buf[0x1a],
                    hdr_buf[0x1b],
                ]),
                timezone: i16::from_le_bytes([hdr_buf[0x1c], hdr_buf[0x1d]]),
                daylight: hdr_buf[0x1e],
                pad2: hdr_buf[0x1f],
            };
            (attrs, ns, ds, 0x2Cu32, Some(timestamp))
        } else {
            // Non-auth: attributes at 0x04, name_size at 0x08, data_size at 0x0C,
            // guid at 0x10
            let attrs =
                u32::from_le_bytes([hdr_buf[0x04], hdr_buf[0x05], hdr_buf[0x06], hdr_buf[0x07]]);
            let ns =
                u32::from_le_bytes([hdr_buf[0x08], hdr_buf[0x09], hdr_buf[0x0A], hdr_buf[0x0B]]);
            let ds =
                u32::from_le_bytes([hdr_buf[0x0C], hdr_buf[0x0D], hdr_buf[0x0E], hdr_buf[0x0F]]);
            (attrs, ns, ds, 0x10u32, None)
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

        // Read name (UTF-16LE). Every size comes from the untrusted flash
        // image, so each addition is checked: a wrapping comparison would
        // pass the bounds check and go on to allocate and read out of the
        // variable region.
        let Some(name_offset) = offset.checked_add(hdr_size) else {
            break;
        };
        let Some(name_end) = name_offset.checked_add(name_size) else {
            break;
        };
        if name_end > end {
            break;
        }
        let mut name_bytes = vec![0u8; name_size as usize];
        if !read_fn(name_offset, &mut name_bytes) {
            break;
        }
        // Convert to Vec<u16>
        let name: Vec<u16> = name_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();

        // Read data
        let data_offset = name_end;
        let Some(data_end) = data_offset.checked_add(data_size_field) else {
            break;
        };
        if data_end > end {
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
            timestamp,
            state,
            state_offset,
        });

        // Advance to next record (aligned)
        let Some(total_size) = hdr_size
            .checked_add(name_size)
            .and_then(|size| size.checked_add(data_size_field))
        else {
            break;
        };
        let Some(aligned) = checked_align_up(total_size, HEADER_ALIGNMENT) else {
            break;
        };
        let Some(next) = offset.checked_add(aligned) else {
            break;
        };
        offset = next;
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
    let Some(end) = VARIABLE_DATA_OFFSET.checked_add(data_size) else {
        return offset;
    };

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

        let Some(total_size) = hdr_size
            .checked_add(name_size)
            .and_then(|size| size.checked_add(data_size_field))
        else {
            break;
        };
        let Some(aligned) = checked_align_up(total_size, HEADER_ALIGNMENT) else {
            break;
        };
        let Some(next) = offset.checked_add(aligned) else {
            break;
        };
        offset = next;
    }

    offset
}

// ============================================================================
// Variable record writing
// ============================================================================

/// Build an authenticated-header variable record (header + name + data).
///
/// `name` must be a non-empty UTF-16 variable name followed by exactly one NUL
/// terminator. `NameSize` includes that required terminator. A zero timestamp
/// is used for ordinary variables; Secure Boot database writes carry the
/// verified timestamp in the same staged record as their value.
pub fn build_variable_record(
    guid_bytes: &[u8; 16],
    name: &[u16],
    attributes: u32,
    data: &[u8],
    timestamp: Option<VariableTimestamp>,
) -> Option<Vec<u8>> {
    let (terminator, characters) = name.split_last()?;
    if *terminator != 0 || characters.is_empty() || characters.contains(&0) {
        return None;
    }
    let name_bytes_len = name.len().checked_mul(2)?;
    let total_raw = AUTH_VAR_HEADER_SIZE
        .checked_add(name_bytes_len)?
        .checked_add(data.len())?;
    let total_raw = u32::try_from(total_raw).ok()?;
    let total_aligned = usize::try_from(checked_align_up(total_raw, HEADER_ALIGNMENT)?).ok()?;
    let mut buf = vec![0xFF; total_aligned];

    let timestamp = timestamp.unwrap_or_default();
    let header = AuthenticatedVariableHeader {
        start_id: U16::new(VARIABLE_DATA),
        state: 0xff,
        reserved: 0,
        attributes: U32::new(attributes),
        monotonic_count: U64::new(0),
        timestamp: EfiTimeLe {
            year: U16::new(timestamp.year),
            month: timestamp.month,
            day: timestamp.day,
            hour: timestamp.hour,
            minute: timestamp.minute,
            second: timestamp.second,
            pad1: 0,
            nanosecond: U32::new(timestamp.nanosecond),
            timezone: I16::new(timestamp.timezone),
            daylight: timestamp.daylight,
            pad2: 0,
        },
        pub_key_index: U32::new(0),
        name_size: U32::new(u32::try_from(name_bytes_len).ok()?),
        data_size: U32::new(u32::try_from(data.len()).ok()?),
        vendor_guid: *guid_bytes,
    };
    buf[..AUTH_VAR_HEADER_SIZE].copy_from_slice(header.as_bytes());

    let name_offset = AUTH_VAR_HEADER_SIZE;
    for (index, &unit) in name.iter().enumerate() {
        let offset = name_offset + index * 2;
        buf[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    let data_offset = name_offset + name_bytes_len;
    buf[data_offset..data_offset + data.len()].copy_from_slice(data);
    Some(buf)
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
    timestamp: Option<VariableTimestamp>,
) -> Option<u32>
where
    F: FnMut(u32, &[u8]) -> bool,
{
    let record = build_variable_record(guid_bytes, name, attributes, data, timestamp)?;
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

/// Compare variable names case-sensitively with an optional UTF-16 NUL terminator.
pub fn name_matches(on_disk: &[u16], name: &[u16]) -> bool {
    crabefi_efi_types::secure_boot::name_matches(on_disk, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crabefi_efi_types::varstore::EFI_VARIABLE_GUID;

    fn timestamp() -> VariableTimestamp {
        VariableTimestamp {
            year: 2025,
            month: 12,
            day: 31,
            hour: 23,
            minute: 58,
            second: 57,
            pad1: 0,
            nanosecond: 0x1234_5678,
            timezone: -60,
            daylight: 3,
            pad2: 0,
        }
    }

    /// A data area holding one non-auth header with attacker-chosen
    /// name/data sizes at the variable-data offset.
    fn region_with_sizes(name_size: u32, data_size: u32) -> alloc::vec::Vec<u8> {
        let mut region = alloc::vec![0u8; VARIABLE_DATA_OFFSET as usize + 0x100];
        let base = VARIABLE_DATA_OFFSET as usize;
        region[base..base + 2].copy_from_slice(&VARIABLE_DATA.to_le_bytes());
        region[base + 2] = 0x3F; // state: valid
        region[base + 4..base + 8].copy_from_slice(&7u32.to_le_bytes());
        region[base + 8..base + 12].copy_from_slice(&name_size.to_le_bytes());
        region[base + 12..base + 16].copy_from_slice(&data_size.to_le_bytes());
        region
    }

    #[test]
    fn walk_rejects_wrapping_record_sizes() {
        // name_size near u32::MAX used to wrap the bounds comparison and
        // reach an infallible multi-GiB allocation.
        let region = region_with_sizes(0xFFFF_FFF0, 0x40);
        let mut read = |offset: u32, buf: &mut [u8]| {
            let start = offset as usize;
            let Some(end) = start.checked_add(buf.len()) else {
                return false;
            };
            if end > region.len() {
                return false;
            }
            buf.copy_from_slice(&region[start..end]);
            true
        };
        assert!(walk_variables(&mut read, false, 0x100).is_empty());
        // The same wrap in find_write_offset must not move the offset.
        assert_eq!(
            find_write_offset(&mut read, false, 0x100),
            VARIABLE_DATA_OFFSET
        );
    }

    #[test]
    fn authenticated_header_has_golden_layout_and_terminated_name_size() {
        let guid = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let record = build_variable_record(
            &guid,
            &[b'A' as u16, 0],
            0x1122_3344,
            &[0xde, 0xad],
            Some(timestamp()),
        )
        .unwrap();
        assert_eq!(record.len(), 68);
        assert_eq!(&record[0x00..0x04], &[0xaa, 0x55, 0xff, 0x00]);
        assert_eq!(&record[0x04..0x08], &0x1122_3344u32.to_le_bytes());
        assert_eq!(&record[0x08..0x10], &[0; 8]);
        assert_eq!(&record[0x10..0x12], &2025u16.to_le_bytes());
        assert_eq!(&record[0x12..0x18], &[12, 31, 23, 58, 57, 0]);
        assert_eq!(&record[0x18..0x1c], &0x1234_5678u32.to_le_bytes());
        assert_eq!(&record[0x1c..0x1e], &(-60i16).to_le_bytes());
        assert_eq!(&record[0x1e..0x20], &[3, 0]);
        assert_eq!(&record[0x24..0x28], &4u32.to_le_bytes());
        assert_eq!(&record[0x28..0x2c], &2u32.to_le_bytes());
        assert_eq!(&record[0x2c..0x3c], &guid);
        assert_eq!(&record[0x3c..0x40], &[b'A', 0, 0, 0]);
        assert_eq!(&record[0x40..0x42], &[0xde, 0xad]);
    }

    #[test]
    fn record_builder_rejects_unterminated_or_embedded_nul_names() {
        assert!(build_variable_record(&[0; 16], &[b'A' as u16], 7, &[], None).is_none());
        assert!(
            build_variable_record(&[0; 16], &[b'A' as u16, 0, b'B' as u16, 0], 7, &[], None)
                .is_none()
        );
    }

    #[test]
    fn standard_edk2_store_size_reopens_legacy_records_without_mutation() {
        let region_size = 4096u32;
        let headers = build_fv_headers(region_size);
        let mut region = vec![0xff; region_size as usize];
        region[..headers.len()].copy_from_slice(&headers);

        // Legacy EDK2 stores use non-authenticated records and define Size as
        // including the variable-store header.
        let vs_offset = FV_HEADER_LENGTH;
        region[vs_offset..vs_offset + 16].copy_from_slice(&EFI_VARIABLE_GUID);
        let standard_size = region_size - FV_HEADER_LENGTH as u32;
        region[vs_offset + 0x10..vs_offset + 0x14].copy_from_slice(&standard_size.to_le_bytes());

        let validation = validate_fv(&region[..VARIABLE_DATA_OFFSET as usize], region_size);
        assert!(validation.valid);
        assert!(!validation.auth_format);
        assert_eq!(validation.data_size, region_size - VARIABLE_DATA_OFFSET);

        let guid = [0x3c; 16];
        let name = [b'L' as u16, b'e' as u16, b'g' as u16, 0];
        let mut record = [0xffu8; 48];
        record[..2].copy_from_slice(&VARIABLE_DATA.to_le_bytes());
        record[2] = VAR_ADDED;
        record[3] = 0;
        record[4..8].copy_from_slice(&7u32.to_le_bytes());
        record[8..12].copy_from_slice(&8u32.to_le_bytes());
        record[12..16].copy_from_slice(&6u32.to_le_bytes());
        record[16..32].copy_from_slice(&guid);
        for (index, unit) in name.iter().enumerate() {
            let offset = 32 + index * 2;
            record[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        record[40..46].copy_from_slice(b"policy");
        let start = VARIABLE_DATA_OFFSET as usize;
        for (target, value) in region[start..start + record.len()].iter_mut().zip(record) {
            *target &= value;
        }

        let preserved = region.clone();
        let variables = {
            let mut read_fn = |offset: u32, output: &mut [u8]| {
                let start = offset as usize;
                let Some(source) = region.get(start..start + output.len()) else {
                    return false;
                };
                output.copy_from_slice(source);
                true
            };
            walk_variables(&mut read_fn, validation.auth_format, validation.data_size)
        };
        assert_eq!(region, preserved);
        assert_eq!(variables.len(), 1);
        assert_eq!(variables[0].guid, guid);
        assert_eq!(variables[0].name, name);
        assert_eq!(variables[0].data, b"policy");
    }

    #[test]
    fn built_record_walks_back_with_exact_timestamp() {
        let region_size = 4096u32;
        let headers = build_fv_headers(region_size);
        let guid = [0x5a; 16];
        let mut record = build_variable_record(
            &guid,
            &[b'R' as u16, b'T' as u16, 0],
            7,
            b"data",
            Some(timestamp()),
        )
        .unwrap();
        record[2] = VAR_ADDED;
        let mut region = vec![0xff; region_size as usize];
        region[..headers.len()].copy_from_slice(&headers);
        let start = VARIABLE_DATA_OFFSET as usize;
        region[start..start + record.len()].copy_from_slice(&record);
        let mut read_fn = |offset: u32, output: &mut [u8]| {
            let offset = offset as usize;
            let Some(source) = region.get(offset..offset + output.len()) else {
                return false;
            };
            output.copy_from_slice(source);
            true
        };
        let variables = walk_variables(&mut read_fn, true, region_size - VARIABLE_DATA_OFFSET);
        assert_eq!(variables.len(), 1);
        assert_eq!(variables[0].guid, guid);
        assert_eq!(variables[0].name, [b'R' as u16, b'T' as u16, 0]);
        assert_eq!(variables[0].data, b"data");
        assert_eq!(variables[0].timestamp, Some(timestamp()));
    }
}
