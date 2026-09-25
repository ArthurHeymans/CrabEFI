//! EFI Disk I/O Protocol
//!
//! Provides byte-granular read/write access on top of the Block I/O protocol.
//! The UEFI specification requires firmware to install this protocol on every
//! handle that carries Block I/O. Windows Boot Manager uses Disk I/O to read
//! the BCD registry hive at arbitrary byte offsets.

use core::ffi::c_void;
use r_efi::efi::{Handle, Status};
use r_efi::protocols::disk_io;

use super::block_io::{BLOCK_IO_PROTOCOL_GUID, BlockIoProtocol};
use super::instance::Registry;
use crate::efi::boot_services;

/// Disk I/O Protocol GUID supplied by `r-efi`.
pub const DISK_IO_PROTOCOL_GUID: r_efi::efi::Guid = disk_io::PROTOCOL_GUID;

/// Disk I/O Protocol revision supplied by `r-efi`.
const DISK_IO_REVISION: u64 = disk_io::REVISION;

/// Disk I/O protocol ABI supplied by `r-efi`.
pub type DiskIoProtocol = disk_io::Protocol;

/// DiskIO context: stores the handle so we can find BlockIO at read time
#[derive(Clone, Copy)]
struct DiskIoContext {
    /// Handle on which both DiskIO and BlockIO are installed
    handle: Handle,
}

static INSTANCES: Registry<DiskIoProtocol, DiskIoContext> = Registry::new();

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

    let handle = match INSTANCES.get(this) {
        Some(c) => c.handle,
        None => {
            log::error!("DiskIO.ReadDisk: unknown protocol instance");
            return Status::INVALID_PARAMETER;
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
        let status = boot_services::with_image_callback(|| unsafe {
            ((*block_io).read_blocks)(block_io, media_id, start_lba, buffer_size, buffer)
        });
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

    let status = boot_services::with_image_callback(|| unsafe {
        ((*block_io).read_blocks)(
            block_io,
            media_id,
            start_lba,
            aligned_size,
            temp_buf as *mut c_void,
        )
    });

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

    // Repeated boot attempts may revisit a handle. Do not allocate another
    // instance when DiskIO is already present.
    if !boot_services::get_protocol_on_handle(handle, &DISK_IO_PROTOCOL_GUID).is_null() {
        return;
    }

    // Allocate the protocol structure and its handle context together.
    let protocol_ptr = INSTANCES.allocate("DiskIoProtocol", DiskIoContext { handle }, |p| {
        p.revision = DISK_IO_REVISION;
        p.read_disk = disk_io_read_disk;
        p.write_disk = disk_io_write_disk;
    });

    if protocol_ptr.is_null() {
        return;
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
        // A failed installation never publishes the protocol pointer. Release
        // the instance so retries cannot exhaust the firmware's boot-time heap.
        let _ = INSTANCES.remove(protocol_ptr);
        log::error!(
            "DiskIO: failed to install on handle {:?}: {:?}",
            handle,
            status
        );
    }
}
