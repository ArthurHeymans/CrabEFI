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
