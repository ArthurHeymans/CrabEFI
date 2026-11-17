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

#[derive(Debug, PartialEq, Eq)]
struct ReadSpan {
    start_lba: u64,
    start_offset: usize,
    aligned_size: usize,
}

impl ReadSpan {
    fn checked(offset: u64, len: usize, block_size: u64, last_block: u64) -> Option<Self> {
        if block_size == 0 || len == 0 {
            return None;
        }
        let end = offset.checked_add(u64::try_from(len).ok()?)?;
        let start_lba = offset / block_size;
        let end_lba = end.div_ceil(block_size);
        if end_lba.checked_sub(1)? > last_block {
            return None;
        }
        let blocks = end_lba.checked_sub(start_lba)?;
        let aligned_size = usize::try_from(blocks.checked_mul(block_size)?).ok()?;
        let start_offset = usize::try_from(offset % block_size).ok()?;
        // Keep the BlockIO buffer and the copy within one representable span.
        if aligned_size > isize::MAX as usize || start_offset.checked_add(len)? > aligned_size {
            return None;
        }
        Some(Self {
            start_lba,
            start_offset,
            aligned_size,
        })
    }
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
    let Some(media) = (unsafe { (*block_io).media.as_ref() }) else {
        return Status::DEVICE_ERROR;
    };
    let block_size = u64::from(media.block_size);

    if block_size == 0 {
        return Status::DEVICE_ERROR;
    }

    // Verify media ID
    if media_id != media.media_id {
        return Status::MEDIA_CHANGED;
    }

    let Some(ReadSpan {
        start_lba,
        start_offset,
        aligned_size,
    }) = ReadSpan::checked(offset, buffer_size, block_size, media.last_block)
    else {
        return Status::INVALID_PARAMETER;
    };

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

#[cfg(test)]
mod tests {
    use super::ReadSpan;

    #[test]
    fn rounds_unaligned_reads_up_to_full_blocks() {
        assert_eq!(
            ReadSpan::checked(4095, 2, 4096, 1),
            Some(ReadSpan {
                start_lba: 0,
                start_offset: 4095,
                aligned_size: 8192,
            })
        );
        assert_eq!(
            ReadSpan::checked(4096, 4096, 4096, 1),
            Some(ReadSpan {
                start_lba: 1,
                start_offset: 0,
                aligned_size: 4096,
            })
        );
    }

    #[test]
    fn rejects_invalid_or_unrepresentable_spans() {
        assert!(ReadSpan::checked(4095, 2, 4096, 0).is_none());
        assert!(ReadSpan::checked(4096, 1, 4096, 0).is_none());
        assert!(ReadSpan::checked(u64::MAX, 1, 512, u64::MAX).is_none());
        assert!(ReadSpan::checked(0, isize::MAX as usize, 512, u64::MAX).is_none());
        assert!(ReadSpan::checked(0, 1, 0, 0).is_none());
        assert!(ReadSpan::checked(0, 0, 512, 0).is_none());
    }
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
