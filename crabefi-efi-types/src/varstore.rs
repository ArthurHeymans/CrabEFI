//! The EDK2 variable store, read-only and allocation-free: header
//! validation and variable lookup in a memory-mapped region, for early
//! firmware that reads options before a UEFI implementation runs. The
//! layout is coreboot's and EDK2's (`get_uint_option()` reads the same).
//!
//! ```text
//! +--------------------------------------------+ offset 0x0000
//! |  EFI_FIRMWARE_VOLUME_HEADER  (72 bytes)    |
//! +--------------------------------------------+ offset 0x0048
//! |  VARIABLE_STORE_HEADER       (28 bytes)    |
//! +--------------------------------------------+ offset 0x0064
//! |  Variable records, 4-byte aligned          |
//! +--------------------------------------------+
//! |  Free space (0xFF)                         |
//! +--------------------------------------------+
//! ```

/// CFR options: coreboot's `EficorebootNvDataGuid`
/// {ceae4c1d-335b-4685-a4a0-fc4a94eea085}, mixed-endian.
pub const COREBOOT_CFR_GUID: [u8; 16] = [
    0x1d, 0x4c, 0xae, 0xce, 0x5b, 0x33, 0x85, 0x46, 0xa4, 0xa0, 0xfc, 0x4a, 0x94, 0xee, 0xa0, 0x85,
];

/// EFI Firmware Volume Header signature: "_FVH"
pub const FV_SIGNATURE: u32 = 0x4856_465F;

/// FV header revision
pub const FV_REVISION: u8 = 0x02;

/// Firmware Volume header length (including one block map entry + terminator)
pub const FV_HEADER_LENGTH: usize = 0x48; // 72 bytes

/// Variable Store header length
pub const VS_HEADER_LENGTH: usize = 0x1C; // 28 bytes

/// Offset where variable records begin (FV header + VS header)
pub const VARIABLE_DATA_OFFSET: u32 = (FV_HEADER_LENGTH + VS_HEADER_LENGTH) as u32;

/// Variable record start marker
pub const VARIABLE_DATA: u16 = 0x55AA;

/// Variable record alignment
pub const HEADER_ALIGNMENT: u32 = 4;

/// Variable store format byte: formatted
pub const VARIABLE_STORE_FORMATTED: u8 = 0x5A;

/// Variable store state byte: healthy
pub const VARIABLE_STORE_HEALTHY: u8 = 0xFE;

// Variable states (bits cleared in 0xFF flash):
/// Variable is fully valid (bits 7 and 6 cleared)
pub const VAR_ADDED: u8 = 0x3F;
/// Header written, data may not be complete (bit 7 cleared)
pub const VAR_HEADER_VALID_ONLY: u8 = 0x7F;
/// Variable is being deleted (bit 0 cleared from VAR_ADDED)
pub const VAR_IN_DELETED_TRANSITION: u8 = 0xFE;
/// Variable is deleted
pub const VAR_DELETED: u8 = 0xFD;

/// Non-authenticated variable header size
pub const VAR_HEADER_SIZE: usize = 32;

/// Authenticated variable header size used for all newly written records.
pub const AUTH_VAR_HEADER_SIZE: usize = 60;

/// EFI System NV Data FV GUID: {fff12b8d-7696-4c8b-a985-2747075b4f50}
/// Used in the Firmware Volume header's FileSystemGuid field.
pub const EFI_SYSTEM_NV_DATA_FV_GUID: [u8; 16] = [
    0x8d, 0x2b, 0xf1, 0xff, 0x96, 0x76, 0x8b, 0x4c, 0xa9, 0x85, 0x27, 0x47, 0x07, 0x5b, 0x4f, 0x50,
];

/// EFI Variable GUID (non-authenticated format): {ddcf3616-3275-4164-98b6-fe85707ffe7d}
/// Used in the Variable Store header's Signature field.
pub const EFI_VARIABLE_GUID: [u8; 16] = [
    0x16, 0x36, 0xcf, 0xdd, 0x75, 0x32, 0x64, 0x41, 0x98, 0xb6, 0xfe, 0x85, 0x70, 0x7f, 0xfe, 0x7d,
];

/// EFI Authenticated Variable GUID: {aaf32c78-947b-439a-a180-2e144ec37792}
/// Indicates the variable store uses authenticated variable headers.
pub const EFI_AUTH_VARIABLE_GUID: [u8; 16] = [
    0x78, 0x2c, 0xf3, 0xaa, 0x7b, 0x94, 0x9a, 0x43, 0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92,
];

/// Validation result for an existing FV region
pub struct FvValidation {
    /// Whether the region has a valid FV + VS header
    pub valid: bool,
    /// Whether the variable store uses authenticated headers
    pub auth_format: bool,
    /// Size of the variable store data area (after VS header)
    pub data_size: u32,
}

/// The data-area size of a store whose header says `vs_size`.
///
/// PI/EDK2 includes the variable-store header in Size. Older CrabEFI images
/// instead wrote the full FV data capacity, excluding that header. Recognize
/// that exact legacy value only; smaller stores use the PI convention. A
/// partial legacy data-only store cannot be distinguished from a PI store.
pub fn variable_data_size(vs_size: u32, region_size: u32) -> Option<u32> {
    let data_capacity = region_size.checked_sub(VARIABLE_DATA_OFFSET)?;
    if vs_size == data_capacity {
        return Some(data_capacity);
    }

    // Select the PI convention before calculating the data bound. In
    // particular, a partial store must not gain 28 bytes of readable data.
    let store_capacity = region_size.checked_sub(FV_HEADER_LENGTH as u32)?;
    (vs_size <= store_capacity)
        .then(|| vs_size.checked_sub(VS_HEADER_LENGTH as u32))
        .flatten()
        .filter(|size| *size <= data_capacity)
}

/// Read one variable's data from an EDK2-compatible variable-store region.
///
/// This helper is intentionally allocation-free and silent so platforms can use
/// it during early boot before the heap and normal logging policy are ready.
/// If multiple active records match, the last one wins.
///
/// # Arguments
/// * `region` - Full EDK2 FV variable-store region bytes.
/// * `guid_bytes` - EFI variable GUID in mixed-endian UEFI byte order.
/// * `name` - UTF-16 variable name, with or without a trailing NUL. Stored
///   EDK2 names are matched with their required trailing NUL.
/// * `data_out` - Buffer that receives the variable data.
///
/// # Returns
/// The number of bytes copied into `data_out`, or `None` if the store is
/// invalid, the variable was not found, or the output buffer is too small.
pub fn read_variable_data_from_region(
    region: &[u8],
    guid_bytes: &[u8; 16],
    name: &[u16],
    data_out: &mut [u8],
) -> Option<usize> {
    if region.len() > u32::MAX as usize {
        return None;
    }

    let validation = validate(region, region.len() as u32)?;
    let mut read_fn = |offset: u32, buf: &mut [u8]| -> bool {
        let offset = offset as usize;
        let Some(end) = offset.checked_add(buf.len()) else {
            return false;
        };
        let Some(src) = region.get(offset..end) else {
            return false;
        };
        buf.copy_from_slice(src);
        true
    };

    read_variable_data(
        &mut read_fn,
        validation.auth_format,
        validation.data_size,
        guid_bytes,
        name,
        data_out,
    )
}

/// Validate the FV and variable-store headers at the start of a region of
/// `region_size` bytes; `None` if they are not a healthy store.
pub fn validate(header_bytes: &[u8], region_size: u32) -> Option<FvValidation> {
    if header_bytes.len() < FV_HEADER_LENGTH + VS_HEADER_LENGTH {
        return None;
    }

    let sig = u32::from_le_bytes([
        header_bytes[0x28],
        header_bytes[0x29],
        header_bytes[0x2A],
        header_bytes[0x2B],
    ]);
    if sig != FV_SIGNATURE || header_bytes[0x37] != FV_REVISION {
        return None;
    }

    if header_bytes[0x10..0x20] != EFI_SYSTEM_NV_DATA_FV_GUID {
        return None;
    }

    let header_length = u16::from_le_bytes([header_bytes[0x30], header_bytes[0x31]]) as usize;
    // The record reader below uses fixed offsets for this 72-byte FV layout.
    // Do not accept another HeaderLength and then read its VS at offset 72.
    if header_length != FV_HEADER_LENGTH {
        return None;
    }

    let fv_length = u64::from_le_bytes(header_bytes[0x20..0x28].try_into().ok()?);
    let fv_length = u32::try_from(fv_length).ok()?;
    if fv_length > region_size || fv_length < VARIABLE_DATA_OFFSET {
        return None;
    }

    let mut checksum: u16 = 0;
    for i in (0..header_length).step_by(2) {
        let lo = header_bytes[i] as u16;
        let hi = header_bytes[i + 1] as u16;
        checksum = checksum.wrapping_add(lo | (hi << 8));
    }
    if checksum != 0 {
        return None;
    }

    let vs = &header_bytes[FV_HEADER_LENGTH..];
    let auth_format = if vs[..16] == EFI_VARIABLE_GUID {
        false
    } else if vs[..16] == EFI_AUTH_VARIABLE_GUID {
        true
    } else {
        return None;
    };

    if vs[0x14] != VARIABLE_STORE_FORMATTED || vs[0x15] != VARIABLE_STORE_HEALTHY {
        return None;
    }

    let vs_size = u32::from_le_bytes([vs[0x10], vs[0x11], vs[0x12], vs[0x13]]);
    let data_size = variable_data_size(vs_size, fv_length)?;

    Some(FvValidation {
        valid: true,
        auth_format,
        data_size,
    })
}

/// Find the last added record of `name` under `guid_bytes` through
/// `read_fn` and copy its data into `data_out`.
pub fn read_variable_data<F>(
    read_fn: &mut F,
    auth_format: bool,
    data_area_size: u32,
    guid_bytes: &[u8; 16],
    name: &[u16],
    data_out: &mut [u8],
) -> Option<usize>
where
    F: FnMut(u32, &mut [u8]) -> bool,
{
    let hdr_size = if auth_format {
        AUTH_VAR_HEADER_SIZE
    } else {
        VAR_HEADER_SIZE
    } as u32;

    let target_name_chars = name.iter().position(|&ch| ch == 0).unwrap_or(name.len());
    if target_name_chars == 0 {
        return None;
    }
    let stored_name_size = target_name_chars
        .checked_add(1)?
        .checked_mul(2)
        .and_then(|len| u32::try_from(len).ok())?;

    let mut found = None;
    let mut offset = VARIABLE_DATA_OFFSET;
    let end = VARIABLE_DATA_OFFSET.checked_add(data_area_size)?;
    let end_with_header = end.checked_add(hdr_size)?;
    let mut hdr_buf = [0u8; AUTH_VAR_HEADER_SIZE];

    while offset
        .checked_add(hdr_size)
        .is_some_and(|header_end| header_end <= end)
    {
        let hdr = &mut hdr_buf[..hdr_size as usize];
        if !read_fn(offset, hdr) {
            break;
        }

        let start_id = u16::from_le_bytes([hdr[0], hdr[1]]);
        let state = hdr[2];
        if start_id != VARIABLE_DATA || state == 0xFF {
            break;
        }

        let (name_size, data_size, guid_offset) = if auth_format {
            let attributes = u32::from_le_bytes([hdr[0x04], hdr[0x05], hdr[0x06], hdr[0x07]]);
            let name_size = u32::from_le_bytes([hdr[0x24], hdr[0x25], hdr[0x26], hdr[0x27]]);
            let data_size = u32::from_le_bytes([hdr[0x28], hdr[0x29], hdr[0x2A], hdr[0x2B]]);
            if attributes == 0xFFFF_FFFF || name_size == 0xFFFF_FFFF || data_size == 0xFFFF_FFFF {
                break;
            }
            (name_size, data_size, 0x2Cusize)
        } else {
            let attributes = u32::from_le_bytes([hdr[0x04], hdr[0x05], hdr[0x06], hdr[0x07]]);
            let name_size = u32::from_le_bytes([hdr[0x08], hdr[0x09], hdr[0x0A], hdr[0x0B]]);
            let data_size = u32::from_le_bytes([hdr[0x0C], hdr[0x0D], hdr[0x0E], hdr[0x0F]]);
            if attributes == 0xFFFF_FFFF || name_size == 0xFFFF_FFFF || data_size == 0xFFFF_FFFF {
                break;
            }
            (name_size, data_size, 0x10usize)
        };

        let name_offset = offset.checked_add(hdr_size)?;
        let data_offset = name_offset.checked_add(name_size)?;
        let record_size = hdr_size.checked_add(name_size)?.checked_add(data_size)?;
        let next_offset = offset.checked_add(checked_align_up(record_size, HEADER_ALIGNMENT)?)?;
        if data_offset.checked_add(data_size)? > end || next_offset > end_with_header {
            break;
        }

        if state == VAR_ADDED
            && hdr[guid_offset..guid_offset + 16] == *guid_bytes
            && name_size == stored_name_size
            && variable_name_matches(read_fn, name_offset, name, target_name_chars)
        {
            found = Some((data_offset, data_size as usize));
        }

        offset = next_offset;
    }

    let (data_offset, data_len) = found?;
    let output = data_out.get_mut(..data_len)?;
    read_fn(data_offset, output).then_some(data_len)
}

fn variable_name_matches<F>(
    read_fn: &mut F,
    name_offset: u32,
    name: &[u16],
    target_name_chars: usize,
) -> bool
where
    F: FnMut(u32, &mut [u8]) -> bool,
{
    let mut buf = [0u8; 2];
    for (idx, &expected) in name.iter().take(target_name_chars).enumerate() {
        let Some(offset) = idx
            .checked_mul(2)
            .and_then(|offset| u32::try_from(offset).ok())
            .and_then(|offset| name_offset.checked_add(offset))
        else {
            return false;
        };

        if !read_fn(offset, &mut buf) {
            return false;
        }
        if u16::from_le_bytes(buf) != expected {
            return false;
        }
    }

    let Some(terminator_offset) = target_name_chars
        .checked_mul(2)
        .and_then(|offset| u32::try_from(offset).ok())
        .and_then(|offset| name_offset.checked_add(offset))
    else {
        return false;
    };

    if !read_fn(terminator_offset, &mut buf) {
        return false;
    }
    u16::from_le_bytes(buf) == 0
}

/// Align a value up to the given alignment (must be a power of 2).
pub fn align_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

/// Checked variant of [`align_up`] for parsing untrusted variable records.
pub fn checked_align_up(value: u32, alignment: u32) -> Option<u32> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|value| value & !(alignment - 1))
}
