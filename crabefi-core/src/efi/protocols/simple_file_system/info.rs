//! Byte-oriented EFI file-information encoding, including flexible UTF-16 tails.
//! The headers have explicit layout and initialized padding; callers need not
//! provide buffers aligned for the corresponding EFI C structures.

use core::ffi::c_void;
use core::mem::{offset_of, size_of};
use r_efi::efi::Status;
use r_efi::protocols::file as efi_file;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct FileInfoHeader {
    size: u64,
    file_size: u64,
    physical_size: u64,
    create_time: [u8; 16],
    last_access_time: [u8; 16],
    modification_time: [u8; 16],
    attribute: u64,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct SystemInfoHeader {
    size: u64,
    read_only: u8,
    reserved: [u8; 7],
    volume_size: u64,
    free_space: u64,
    block_size: u32,
}

const _: () = assert!(size_of::<FileInfoHeader>() == offset_of!(efi_file::Info, file_name));
const _: () =
    assert!(size_of::<SystemInfoHeader>() == offset_of!(efi_file::SystemInfo, volume_label));

fn info_size(header: usize, name: &str) -> usize {
    header + (name.encode_utf16().count() + 1) * 2
}

pub(super) fn system_info_size(label: &str) -> usize {
    info_size(size_of::<SystemInfoHeader>(), label)
}

pub(super) struct FileInfoUpdate {
    pub(super) file_size: u64,
    pub(super) attributes: u64,
}

/// Decode SetInfo without aligned references or trusting the flexible tail.
/// A header-only request retains the current name, as existing callers expect.
pub(super) fn read_file_info(buffer: &[u8], current_name: &str) -> Result<FileInfoUpdate, Status> {
    let (header, _) =
        FileInfoHeader::read_from_prefix(buffer).map_err(|_| Status::BAD_BUFFER_SIZE)?;
    let declared = if header.size == 0 {
        buffer.len()
    } else {
        usize::try_from(header.size).map_err(|_| Status::BAD_BUFFER_SIZE)?
    };
    if !(size_of::<FileInfoHeader>()..=buffer.len()).contains(&declared) {
        return Err(Status::BAD_BUFFER_SIZE);
    }
    let name = &buffer[size_of::<FileInfoHeader>()..declared];
    if !name.len().is_multiple_of(2) {
        return Err(Status::BAD_BUFFER_SIZE);
    }
    if !requested_name_matches(name, current_name)
        || header.create_time != [0; 16]
        || header.last_access_time != [0; 16]
        || header.modification_time != [0; 16]
    {
        return Err(Status::UNSUPPORTED);
    }
    Ok(FileInfoUpdate {
        file_size: header.file_size,
        attributes: header.attribute,
    })
}

fn requested_name_matches(name: &[u8], current_name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    let mut current = current_name.encode_utf16();
    for (index, bytes) in name.as_chunks::<2>().0.iter().enumerate() {
        let unit = u16::from_ne_bytes(*bytes);
        if unit == 0 {
            return index == 0 || current.next().is_none();
        }
        if current.next() != Some(unit) {
            return false;
        }
    }
    false
}

/// # Safety
/// `buffer_size` must point to a writable `usize`. A non-null `buffer` must
/// cover the number of writable bytes declared by `buffer_size`.
pub(super) unsafe fn write_file_info(
    buffer: *mut c_void,
    buffer_size: *mut usize,
    file_size: u64,
    attributes: u64,
    name: &str,
) -> Status {
    let header = FileInfoHeader {
        size: info_size(size_of::<FileInfoHeader>(), name) as u64,
        file_size,
        physical_size: file_size,
        create_time: [0; 16],
        last_access_time: [0; 16],
        modification_time: [0; 16],
        attribute: attributes,
    };
    unsafe { write_info(buffer, buffer_size, header.as_bytes(), name) }
}

/// # Safety
/// `buffer_size` must point to a writable `usize`. A non-null `buffer` must
/// cover the number of writable bytes declared by `buffer_size`.
pub(super) unsafe fn write_system_info(
    buffer: *mut c_void,
    buffer_size: *mut usize,
    read_only: bool,
    volume_size: u64,
    free_space: u64,
    block_size: u32,
    label: &str,
) -> Status {
    let header = SystemInfoHeader {
        size: info_size(size_of::<SystemInfoHeader>(), label) as u64,
        read_only: u8::from(read_only),
        reserved: [0; 7],
        volume_size,
        free_space,
        block_size,
    };
    unsafe { write_info(buffer, buffer_size, header.as_bytes(), label) }
}

/// Encode EFI_FILE_SYSTEM_VOLUME_LABEL: only a terminated UTF-16 string,
/// with no Size field or filesystem-information header.
///
/// # Safety
/// `buffer_size` must point to a writable `usize`. A non-null `buffer` must
/// cover the number of writable bytes declared by `buffer_size`.
pub(super) unsafe fn write_volume_label(
    buffer: *mut c_void,
    buffer_size: *mut usize,
    label: &str,
) -> Status {
    unsafe { write_info(buffer, buffer_size, &[], label) }
}

unsafe fn write_info(
    buffer: *mut c_void,
    buffer_size: *mut usize,
    header: &[u8],
    name: &str,
) -> Status {
    if buffer_size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let required = info_size(header.len(), name);
    if unsafe { *buffer_size } < required {
        unsafe { *buffer_size = required };
        return Status::BUFFER_TOO_SMALL;
    }
    if buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let output = unsafe { core::slice::from_raw_parts_mut(buffer.cast::<u8>(), required) };
    output[..header.len()].copy_from_slice(header);
    for (slot, unit) in output[header.len()..]
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(name.encode_utf16().chain(core::iter::once(0)))
    {
        slot.copy_from_slice(&unit.to_ne_bytes());
    }
    unsafe { *buffer_size = required };
    Status::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn set_info_matches_only_bounded_terminated_names() {
        let name = "é.txt";
        let required = info_size(size_of::<FileInfoHeader>(), name);
        let mut output = vec![0; required + 1];
        let mut size = required;
        assert_eq!(
            unsafe {
                write_file_info(
                    output.as_mut_ptr().add(1).cast(),
                    &mut size,
                    7,
                    efi_file::ARCHIVE,
                    name,
                )
            },
            Status::SUCCESS
        );
        let update = read_file_info(&output[1..], name).unwrap();
        assert_eq!(update.file_size, 7);
        assert_eq!(update.attributes, efi_file::ARCHIVE);
        assert!(matches!(
            read_file_info(&output[1..], "other"),
            Err(Status::UNSUPPORTED)
        ));
        let unterminated = required - 2;
        output[1..9].copy_from_slice(&(unterminated as u64).to_ne_bytes());
        assert!(matches!(
            read_file_info(&output[1..1 + unterminated], name),
            Err(Status::UNSUPPORTED)
        ));
        output[1..9].copy_from_slice(&(required as u64 + 1).to_ne_bytes());
        assert!(matches!(
            read_file_info(&output[1..], name),
            Err(Status::BAD_BUFFER_SIZE)
        ));
        // Existing header-only SetInfo callers leave Size zero and retain the name.
        output[1..9].fill(0);
        assert_eq!(
            read_file_info(&output[1..1 + size_of::<FileInfoHeader>()], name)
                .unwrap()
                .file_size,
            7
        );
    }

    #[test]
    fn file_info_has_exact_size_and_works_unaligned() {
        let long_name = "界".repeat(255);
        for name in ["", "a😀.txt", &long_name] {
            let required =
                offset_of!(efi_file::Info, file_name) + (name.encode_utf16().count() + 1) * 2;
            let mut size = 0;
            assert_eq!(
                unsafe { write_file_info(core::ptr::null_mut(), &mut size, 123, 7, name) },
                Status::BUFFER_TOO_SMALL
            );
            assert_eq!(size, required);
            let mut output = vec![0xa5; required + 2];
            assert_eq!(
                unsafe {
                    write_file_info(output.as_mut_ptr().add(1).cast(), &mut size, 123, 7, name)
                },
                Status::SUCCESS
            );
            let (header, tail) =
                FileInfoHeader::read_from_prefix(&output[1..1 + required]).unwrap();
            assert_eq!(header.size, required as u64);
            assert_eq!(header.file_size, 123);
            assert_eq!(header.attribute, 7);
            assert_eq!(header.create_time, [0; 16]);
            let units: Vec<_> = tail
                .as_chunks::<2>()
                .0
                .iter()
                .map(|unit| u16::from_ne_bytes([unit[0], unit[1]]))
                .collect();
            assert_eq!(
                units,
                name.encode_utf16()
                    .chain(core::iter::once(0))
                    .collect::<Vec<_>>()
            );
            assert_eq!(output[0], 0xa5);
            assert_eq!(output[required + 1], 0xa5);
        }
    }

    #[test]
    fn dedicated_volume_label_is_bounded_terminated_utf16() {
        for label in ["", "EFI", "a😀"] {
            let required = (label.encode_utf16().count() + 1) * 2;
            let mut size = 0;
            assert_eq!(
                unsafe { write_volume_label(core::ptr::null_mut(), &mut size, label) },
                Status::BUFFER_TOO_SMALL
            );
            assert_eq!(size, required);
            assert_eq!(
                unsafe { write_volume_label(core::ptr::null_mut(), &mut size, label) },
                Status::INVALID_PARAMETER
            );
            let mut output = vec![0xa5; required + 2];
            size = required - 1;
            assert_eq!(
                unsafe { write_volume_label(output.as_mut_ptr().add(1).cast(), &mut size, label) },
                Status::BUFFER_TOO_SMALL
            );
            assert_eq!(size, required);
            assert!(output.iter().all(|&byte| byte == 0xa5));
            size = required + 1;
            assert_eq!(
                unsafe { write_volume_label(output.as_mut_ptr().add(1).cast(), &mut size, label) },
                Status::SUCCESS
            );
            assert_eq!(size, required);
            let expected: Vec<_> = label
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_ne_bytes)
                .collect();
            assert_eq!(&output[1..1 + required], expected);
            assert_eq!(output[0], 0xa5);
            assert_eq!(output[required + 1], 0xa5);
        }
    }

    #[test]
    fn volume_label_uses_the_flexible_member_not_structure_padding() {
        for label in ["", "EFI"] {
            let required = offset_of!(efi_file::SystemInfo, volume_label)
                + (label.encode_utf16().count() + 1) * 2;
            let mut size = required;
            let mut output = vec![0xa5; required + 2];
            assert_eq!(
                unsafe {
                    write_system_info(
                        output.as_mut_ptr().add(1).cast(),
                        &mut size,
                        true,
                        4096,
                        512,
                        1024,
                        label,
                    )
                },
                Status::SUCCESS
            );
            let (header, tail) =
                SystemInfoHeader::read_from_prefix(&output[1..1 + required]).unwrap();
            let reported_size = header.size;
            let volume_size = header.volume_size;
            assert_eq!(reported_size, required as u64);
            assert_eq!(volume_size, 4096);
            assert_eq!(header.read_only, 1);
            assert_eq!(header.reserved, [0; 7]);
            let units: Vec<_> = tail
                .as_chunks::<2>()
                .0
                .iter()
                .map(|unit| u16::from_ne_bytes([unit[0], unit[1]]))
                .collect();
            assert_eq!(
                units,
                label
                    .encode_utf16()
                    .chain(core::iter::once(0))
                    .collect::<Vec<_>>()
            );
            assert_eq!(output[0], 0xa5);
            assert_eq!(output[required + 1], 0xa5);
        }
    }
}
