//! EFI Load File 2 Protocol
//!
//! Implements `EFI_LOAD_FILE2_PROTOCOL` which is used by the Linux EFI stub
//! to load the initrd via the `LINUX_EFI_INITRD_MEDIA_GUID` vendor device path.
//! GRUB dynamically installs its own LoadFile2 for initrd; this implementation
//! provides a stub that returns `NOT_FOUND` so the protocol is discoverable
//! but defers actual initrd loading to the bootloader.
//!
//! Reference: UEFI Specification 2.10, Section 13.1
//! Reference: Linux `drivers/firmware/efi/libstub/efi-stub-helper.c`

use core::ffi::c_void;
use core::ptr;

use r_efi::efi::{Boolean, Guid, Status};
use r_efi::protocols::device_path;
use r_efi::protocols::load_file2;

use crate::efi::allocator::{self, MemoryType};
use crate::efi::utils::allocate_protocol_with_log;

pub const LOAD_FILE2_GUID: Guid = load_file2::PROTOCOL_GUID;

/// Vendor media device path GUID for Linux initrd loading.
///
/// Linux's EFI stub searches for a handle with LoadFile2 and this device path
/// to load the initrd without going through the filesystem.
pub const LINUX_INITRD_MEDIA_GUID: Guid = Guid::from_fields(
    0x5568e427,
    0x68fc,
    0x4f3d,
    0xac,
    0x74,
    &[0xca, 0x55, 0x52, 0x31, 0xcc, 0x68],
);

/// Device path node types
const TYPE_MEDIA: u8 = 0x04;
const MEDIA_SUBTYPE_VENDOR: u8 = 0x03;
const TYPE_END: u8 = 0x7F;
const END_SUBTYPE_ENTIRE: u8 = 0xFF;

/// Vendor media device path for Linux initrd
///
/// Layout: Vendor Media node (header + GUID = 20 bytes) + End node (4 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct InitrdDevicePath {
    vendor_type: u8,
    vendor_subtype: u8,
    vendor_length: [u8; 2],
    vendor_guid: [u8; 16],
    end_type: u8,
    end_subtype: u8,
    end_length: [u8; 2],
}

/// Create the Linux initrd vendor media device path.
///
/// Returns a pointer to an allocated device path, or null on failure.
fn create_initrd_device_path() -> *mut device_path::Protocol {
    let size = core::mem::size_of::<InitrdDevicePath>();
    let buf = match allocator::allocate_pool(MemoryType::BootServicesData, size) {
        Ok(p) => p,
        Err(_) => return ptr::null_mut(),
    };

    let dp = InitrdDevicePath {
        vendor_type: TYPE_MEDIA,
        vendor_subtype: MEDIA_SUBTYPE_VENDOR,
        vendor_length: 20u16.to_le_bytes(), // header(4) + GUID(16) = 20
        vendor_guid: guid_to_bytes(&LINUX_INITRD_MEDIA_GUID),
        end_type: TYPE_END,
        end_subtype: END_SUBTYPE_ENTIRE,
        end_length: 4u16.to_le_bytes(),
    };

    unsafe {
        ptr::write(buf as *mut InitrdDevicePath, dp);
    }
    buf as *mut device_path::Protocol
}

/// Convert a GUID to its raw byte representation.
fn guid_to_bytes(guid: &Guid) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    // Safety: a Guid is 16 bytes; we just copy the raw bytes.
    unsafe {
        ptr::copy_nonoverlapping(guid as *const Guid as *const u8, bytes.as_mut_ptr(), 16);
    }
    bytes
}

// ============================================================================
// Protocol function implementation
// ============================================================================

/// `LoadFile` — stub implementation that returns `NOT_FOUND`.
///
/// CrabEFI does not pre-load an initrd. Bootloaders like GRUB install their
/// own LoadFile2 protocol dynamically when they have an initrd to provide.
/// This stub exists so the protocol handle is discoverable and bootloaders
/// that query for it get a clean `NOT_FOUND` rather than failing to locate
/// the protocol entirely.
///
/// Per the UEFI spec, `BootPolicy` must be `FALSE` for LoadFile2.
extern "efiapi" fn load_file(
    _this: *mut load_file2::Protocol,
    _file_path: *mut device_path::Protocol,
    boot_policy: Boolean,
    buffer_size: *mut usize,
    _buffer: *mut c_void,
) -> Status {
    // LoadFile2 must reject BootPolicy=TRUE
    if boot_policy != Boolean::FALSE {
        return Status::UNSUPPORTED;
    }

    if buffer_size.is_null() {
        return Status::INVALID_PARAMETER;
    }

    log::debug!("LoadFile2.LoadFile called — no initrd available, returning NOT_FOUND");
    Status::NOT_FOUND
}

// ============================================================================
// Protocol creation and installation
// ============================================================================

/// Create a Load File 2 protocol instance.
///
/// Returns a pointer suitable for `install_protocol`, or null on allocation failure.
pub fn create_protocol() -> *mut c_void {
    let proto = allocate_protocol_with_log::<load_file2::Protocol>("LoadFile2", |p| {
        p.load_file = load_file;
    });
    proto as *mut c_void
}

/// Create the initrd vendor media device path for the LoadFile2 handle.
///
/// Returns a pointer to the device path, or null on failure.
pub fn create_device_path() -> *mut device_path::Protocol {
    create_initrd_device_path()
}
