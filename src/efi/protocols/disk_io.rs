//! EFI Disk I/O Protocol
//!
//! Provides byte-granular read/write access on top of the Block I/O protocol.
//! The UEFI specification requires firmware to install this protocol on every
//! handle that carries Block I/O. Windows Boot Manager uses Disk I/O to read
//! the BCD registry hive at arbitrary byte offsets.

use core::ffi::c_void;
use r_efi::efi::{Handle, Status};

use super::block_io::{BLOCK_IO_PROTOCOL_GUID, BlockIoProtocol};
use crate::efi::boot_services;
use crate::efi::utils::allocate_protocol_with_log;

/// Disk I/O Protocol GUID
pub const DISK_IO_PROTOCOL_GUID: r_efi::efi::Guid = r_efi::efi::Guid::from_fields(
    0xCE345171,
    0xBA0B,
    0x11d2,
    0x8E,
    0x4F,
    &[0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
);

/// Disk I/O Protocol revision
const DISK_IO_REVISION: u64 = 0x0001_0000;

/// Disk I/O Protocol structure (matches r_efi::protocols::disk_io::Protocol)
#[repr(C)]
pub struct DiskIoProtocol {
    pub revision: u64,
    pub read_disk: extern "efiapi" fn(
        this: *mut DiskIoProtocol,
        media_id: u32,
        offset: u64,
        buffer_size: usize,
        buffer: *mut c_void,
    ) -> Status,
    pub write_disk: extern "efiapi" fn(
        this: *mut DiskIoProtocol,
        media_id: u32,
        offset: u64,
        buffer_size: usize,
        buffer: *mut c_void,
    ) -> Status,
}

/// Maximum number of DiskIO instances (must match MAX_BLOCK_IO_INSTANCES)
const MAX_DISK_IO_INSTANCES: usize = 16;

/// DiskIO context: stores the handle so we can find BlockIO at read time
struct DiskIoContext {
    /// Handle on which both DiskIO and BlockIO are installed
    handle: Handle,
}

/// Global storage for DiskIO contexts
static mut DISK_IO_CONTEXTS: [Option<DiskIoContext>; MAX_DISK_IO_INSTANCES] =
    [const { None }; MAX_DISK_IO_INSTANCES];

/// Protocol instance to context mapping
static mut PROTOCOL_TO_CONTEXT: [Option<*mut DiskIoProtocol>; MAX_DISK_IO_INSTANCES] =
    [const { None }; MAX_DISK_IO_INSTANCES];

/// Find context index for a protocol instance
fn find_context_index(protocol: *mut DiskIoProtocol) -> Option<usize> {
    unsafe {
        let map = core::ptr::addr_of!(PROTOCOL_TO_CONTEXT);
        for (i, p) in (*map).iter().enumerate() {
            if let Some(ptr) = p
                && *ptr == protocol
            {
                return Some(i);
            }
        }
    }
    None
}

/// Read from the disk at a byte offset
///
/// This reads `buffer_size` bytes starting at byte `offset` from the beginning
/// of the partition/disk. Internally it converts to block-aligned reads via BlockIO.
extern "efiapi" fn disk_io_read_disk(
    this: *mut DiskIoProtocol,
    media_id: u32,
    offset: u64,
    buffer_size: usize,
    buffer: *mut c_void,
) -> Status {
    if this.is_null() || buffer.is_null() || buffer_size == 0 {
        return Status::INVALID_PARAMETER;
    }

    log::trace!(
        "DiskIO.ReadDisk(media={}, offset={:#x}, size={})",
        media_id,
        offset,
        buffer_size
    );

    let ctx_idx = match find_context_index(this) {
        Some(idx) => idx,
        None => {
            log::error!("DiskIO.ReadDisk: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    let handle = unsafe {
        let contexts = core::ptr::addr_of!(DISK_IO_CONTEXTS);
        match &(*contexts)[ctx_idx] {
            Some(c) => c.handle,
            None => return Status::INVALID_PARAMETER,
        }
    };

    // Get the BlockIO protocol from the same handle
    let block_io_ptr = boot_services::get_protocol_on_handle(handle, &BLOCK_IO_PROTOCOL_GUID);
    if block_io_ptr.is_null() {
        log::error!("DiskIO.ReadDisk: no BlockIO on handle {:?}", handle);
        return Status::DEVICE_ERROR;
    }

    let block_io = block_io_ptr as *mut BlockIoProtocol;
    let media = unsafe { &*(*block_io).media };
    let block_size = media.block_size as u64;

    if block_size == 0 {
        return Status::DEVICE_ERROR;
    }

    // Verify media ID
    if media_id != media.media_id {
        return Status::MEDIA_CHANGED;
    }

    // Calculate block-aligned read parameters
    let start_lba = offset / block_size;
    let start_offset = (offset % block_size) as usize;
    let end_byte = offset + buffer_size as u64;
    let end_lba = end_byte.div_ceil(block_size);
    let total_blocks = end_lba - start_lba;
    let aligned_size = (total_blocks * block_size) as usize;

    // If already block-aligned, read directly into buffer
    if start_offset == 0 && buffer_size == aligned_size {
        let status = unsafe {
            ((*block_io).read_blocks)(block_io, media_id, start_lba, buffer_size, buffer)
        };
        return status;
    }

    // Unaligned: allocate a temporary buffer for block-aligned read
    let temp_buf = match crate::efi::allocator::allocate_pool(
        crate::efi::allocator::MemoryType::BootServicesData,
        aligned_size,
    ) {
        Ok(ptr) => ptr,
        Err(_) => {
            log::error!(
                "DiskIO.ReadDisk: failed to allocate {} bytes for temp buffer",
                aligned_size
            );
            return Status::OUT_OF_RESOURCES;
        }
    };

    let status = unsafe {
        ((*block_io).read_blocks)(
            block_io,
            media_id,
            start_lba,
            aligned_size,
            temp_buf as *mut c_void,
        )
    };

    if status == Status::SUCCESS {
        // Copy the requested portion from the aligned buffer
        unsafe {
            core::ptr::copy_nonoverlapping(
                temp_buf.add(start_offset),
                buffer as *mut u8,
                buffer_size,
            );
        }
    }

    let _ = crate::efi::allocator::free_pool(temp_buf);
    status
}

/// Write to the disk (not supported - read only for boot)
extern "efiapi" fn disk_io_write_disk(
    _this: *mut DiskIoProtocol,
    _media_id: u32,
    _offset: u64,
    _buffer_size: usize,
    _buffer: *mut c_void,
) -> Status {
    log::debug!("DiskIO.WriteDisk: not supported (read-only)");
    Status::WRITE_PROTECTED
}

/// Install DiskIO protocol on a handle that already has BlockIO
///
/// # Arguments
/// * `handle` - Handle with BlockIO protocol already installed
pub fn install_disk_io_on_handle(handle: Handle) {
    if handle.is_null() {
        return;
    }

    // Verify BlockIO is present
    let block_io_ptr = boot_services::get_protocol_on_handle(handle, &BLOCK_IO_PROTOCOL_GUID);
    if block_io_ptr.is_null() {
        log::warn!(
            "DiskIO: skipping handle {:?} — no BlockIO installed",
            handle
        );
        return;
    }

    // Find a free context slot
    let ctx_idx = unsafe {
        let mut found = None;
        let contexts = core::ptr::addr_of!(DISK_IO_CONTEXTS);
        for (i, slot) in (*contexts).iter().enumerate() {
            if slot.is_none() {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => {
                log::error!("DiskIO: no free context slots");
                return;
            }
        }
    };

    // Allocate the protocol structure
    let protocol_ptr = allocate_protocol_with_log::<DiskIoProtocol>("DiskIoProtocol", |p| {
        p.revision = DISK_IO_REVISION;
        p.read_disk = disk_io_read_disk;
        p.write_disk = disk_io_write_disk;
    });

    if protocol_ptr.is_null() {
        return;
    }

    // Store context
    unsafe {
        let contexts = core::ptr::addr_of_mut!(DISK_IO_CONTEXTS);
        (*contexts)[ctx_idx] = Some(DiskIoContext { handle });
        let proto_map = core::ptr::addr_of_mut!(PROTOCOL_TO_CONTEXT);
        (*proto_map)[ctx_idx] = Some(protocol_ptr);
    }

    // Install on the handle
    let status = boot_services::install_protocol(
        handle,
        &DISK_IO_PROTOCOL_GUID,
        protocol_ptr as *mut c_void,
    );

    if status == Status::SUCCESS {
        log::info!("DiskIO protocol installed on handle {:?}", handle);
    } else {
        log::error!(
            "DiskIO: failed to install on handle {:?}: {:?}",
            handle,
            status
        );
    }
}
