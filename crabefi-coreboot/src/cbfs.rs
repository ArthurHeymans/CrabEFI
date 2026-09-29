//! CBFS payload discovery.
//!
//! Walks the file headers of a CBFS region and reports the coreboot payloads
//! stored in it, so the boot menu can offer them next to disk boot entries.
//! Only headers are read; payload data is never touched.
//!
//! # References
//!
//! - coreboot/src/commonlib/bsd/include/commonlib/bsd/cbfs_serialized.h

use core::ffi::CStr;
use zerocopy::byteorder::{BigEndian, U32};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Magic at the start of every CBFS file header.
const FILE_MAGIC: [u8; 8] = *b"LARCHIVE";

/// File headers start on multiples of this many bytes from the region start.
const ALIGNMENT: u64 = 64;

/// File type of a coreboot payload (`CBFS_TYPE_SELF`).
const TYPE_SELF: u32 = 0x20;

/// CBFS name CrabEFI itself is installed under; offering it would only
/// chainload ourselves.
const OWN_PAYLOAD: &str = "fallback/payload";

/// Longest file name (including the terminating NUL) that is reported; this is
/// the capacity of the boot menu names.
pub const MAX_NAME_LEN: usize = 64;

/// `struct cbfs_file`: the fixed part of a file header. The NUL-terminated
/// name follows it, then the attributes, then the file data.
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct FileHeader {
    magic: [u8; 8],
    /// Size of the file data in bytes.
    len: U32<BigEndian>,
    file_type: U32<BigEndian>,
    /// Offset of the attributes from the header start, or 0 if there are none.
    attributes_offset: U32<BigEndian>,
    /// Offset of the file data from the header start.
    offset: U32<BigEndian>,
}

const HEADER_LEN: usize = size_of::<FileHeader>();

fn align_up(value: u64) -> Option<u64> {
    Some(value.checked_add(ALIGNMENT - 1)? & !(ALIGNMENT - 1))
}

/// Call `visit` with the name of every payload in a CBFS region.
///
/// `read(offset, buf)` fills `buf` from the region at `offset` (relative to the
/// region start) and returns whether it succeeded. Names that do not fit in
/// [`MAX_NAME_LEN`] bytes or are not UTF-8 are skipped. The walk stops at the
/// end of the region, on a read error, or at the first header that points
/// outside the region.
pub fn for_each_payload(
    region_size: u64,
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
    mut visit: impl FnMut(&str),
) {
    let mut offset = 0u64;
    while offset
        .checked_add(HEADER_LEN as u64)
        .is_some_and(|end| end <= region_size)
    {
        let mut raw = [0u8; HEADER_LEN];
        if !read(offset, &mut raw) {
            return;
        }
        let Ok(header) = FileHeader::read_from_bytes(&raw) else {
            return;
        };
        // Gaps between files are legal; headers only start on aligned offsets.
        if header.magic != FILE_MAGIC {
            offset += ALIGNMENT;
            continue;
        }

        let data_offset = u64::from(header.offset.get());
        let Some(next) = offset
            .checked_add(data_offset)
            .and_then(|data| data.checked_add(u64::from(header.len.get())))
            .filter(|&end| data_offset >= HEADER_LEN as u64 && end <= region_size)
        else {
            return;
        };

        if header.file_type.get() == TYPE_SELF {
            // The NUL-terminated name sits between the header and the data.
            let mut name = [0u8; MAX_NAME_LEN];
            let name_len = ((data_offset - HEADER_LEN as u64) as usize).min(name.len());
            if read(offset + HEADER_LEN as u64, &mut name[..name_len])
                && let Ok(name) = CStr::from_bytes_until_nul(&name[..name_len])
                && let Ok(name) = name.to_str()
                && name != OWN_PAYLOAD
            {
                visit(name);
            }
        }

        let Some(aligned) = align_up(next) else {
            return;
        };
        offset = aligned;
    }
}
