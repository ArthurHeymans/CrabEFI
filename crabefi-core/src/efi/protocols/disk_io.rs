//! EFI Disk I/O Protocol
//!
//! Provides byte-granular read/write access on top of the Block I/O protocol.
//! The UEFI specification requires firmware to install this protocol on every
//! handle that carries Block I/O. Windows Boot Manager uses Disk I/O to read
//! the BCD registry hive at arbitrary byte offsets.

use core::ffi::c_void;
use r_efi::efi::{Handle, Status};
use r_efi::protocols::disk_io;

use super::block_io::{BLOCK_IO_PROTOCOL_GUID, BlockIoMedia, BlockIoProtocol};
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

/// The fields present even in revision 1 of EFI_BLOCK_IO_MEDIA.
#[repr(C)]
#[derive(Clone, Copy)]
struct MediaPrefix {
    media_id: u32,
    removable_media: u8,
    media_present: u8,
    logical_partition: u8,
    read_only: u8,
    write_caching: u8,
    block_size: u32,
    io_align: u32,
    last_block: u64,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(offset_of!(MediaPrefix, block_size) == offset_of!(BlockIoMedia, block_size));
    assert!(offset_of!(MediaPrefix, last_block) == offset_of!(BlockIoMedia, last_block));
    assert!(size_of::<MediaPrefix>() == offset_of!(BlockIoMedia, lowest_aligned_lba));
};

/// Largest bounce buffer used for whole blocks that cannot go straight into
/// the caller's buffer. Larger misaligned reads are bounced in chunks.
const MAX_BOUNCE_BYTES: usize = 64 * 1024;

/// How a byte-granular read maps onto BlockIO transfers.
///
/// Like EDK2's DiskIo, a read is split into an optional partial head block,
/// whole middle blocks, and an optional partial tail block. Middle blocks
/// are read straight into the caller's buffer when it satisfies `IoAlign`.
/// Partial blocks, and middle blocks the caller's buffer cannot receive,
/// pass through a bounce buffer of at most `MAX_BOUNCE_BYTES` (or one block,
/// if that is larger), so temporary memory does not grow with the request.
#[derive(Debug, PartialEq, Eq)]
struct ReadPlan {
    /// First LBA the read touches.
    lba: u64,
    /// Offset of the first requested byte within the head block.
    head_offset: usize,
    /// Bytes copied out of the partially requested first block.
    head_len: usize,
    /// Whole blocks between the head and the tail.
    middle_blocks: usize,
    /// Whether the middle blocks must pass through the bounce buffer.
    bounce_middle: bool,
    /// Bytes copied out of the partially requested last block.
    tail_len: usize,
    /// Blocks in the bounce buffer; zero when every transfer is direct.
    bounce_blocks: usize,
}

impl ReadPlan {
    /// Plan a read of `len` bytes at byte `offset` into the buffer at address
    /// `buffer`. `last_block` bounds the request when the media size is
    /// known; otherwise BlockIO validates each transfer.
    fn new(
        offset: u64,
        len: usize,
        block_size: u32,
        buffer: usize,
        io_align: usize,
        last_block: Option<u64>,
    ) -> Option<Self> {
        let block = usize::try_from(block_size).ok().filter(|&size| size != 0)?;
        let block_size = u64::from(block_size);
        if len == 0 || io_align == 0 {
            return None;
        }
        let end = offset.checked_add(u64::try_from(len).ok()?)?;
        if last_block.is_some_and(|last| (end - 1) / block_size > last) {
            return None;
        }
        buffer.checked_add(len)?;

        let head_offset = usize::try_from(offset % block_size).ok()?;
        let head_len = if head_offset == 0 {
            0
        } else {
            (block - head_offset).min(len)
        };
        let middle_blocks = (len - head_len) / block;
        let tail_len = (len - head_len) % block;
        let bounce_middle = middle_blocks != 0 && !(buffer + head_len).is_multiple_of(io_align);
        let bounce_blocks = if bounce_middle {
            middle_blocks.min((MAX_BOUNCE_BYTES / block).max(1))
        } else {
            usize::from(head_len != 0 || tail_len != 0)
        };
        Some(Self {
            lba: offset / block_size,
            head_offset,
            head_len,
            middle_blocks,
            bounce_middle,
            tail_len,
            bounce_blocks,
        })
    }
}

/// A pool allocation with an `IoAlign`-aligned window, freed on drop.
struct Bounce {
    pool: *mut u8,
    data: *mut u8,
}

impl Bounce {
    fn new(size: usize, io_align: usize) -> Option<Self> {
        let pool_size = size
            .checked_add(io_align - 1)
            .filter(|size| *size <= isize::MAX as usize)?;
        let pool = crate::efi::allocator::allocate_pool(
            crate::efi::allocator::MemoryType::BootServicesData,
            pool_size,
        )
        .ok()?;
        let padding = pool.addr().next_multiple_of(io_align) - pool.addr();
        // SAFETY: padding < io_align, so the aligned window of `size` bytes
        // stays inside the `size + io_align - 1` byte allocation.
        let data = unsafe { pool.add(padding) };
        Some(Self { pool, data })
    }
}

impl Drop for Bounce {
    fn drop(&mut self) {
        let _ = crate::efi::allocator::free_pool(self.pool);
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
    if this.is_null() || (buffer.is_null() && buffer_size != 0) {
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
    let media = unsafe { (*block_io).media.cast::<MediaPrefix>() };
    if media.is_null() {
        return Status::DEVICE_ERROR;
    }
    // Copy the revision-1 prefix; the provider may update it during ReadBlocks.
    let media = unsafe { media.read() };
    if media.block_size == 0 {
        return Status::DEVICE_ERROR;
    }

    // Verify media ID
    if media_id != media.media_id {
        return Status::MEDIA_CHANGED;
    }

    // An empty read transfers nothing; the UEFI interface does not reject it.
    if buffer_size == 0 {
        return Status::SUCCESS;
    }

    // IoAlign is zero or one for unrestricted buffers, otherwise a power of two.
    let io_align = media.io_align.max(1) as usize;
    if !io_align.is_power_of_two() {
        return Status::DEVICE_ERROR;
    }

    // Removable devices can discover removal or replacement in ReadBlocks.
    // Let them report media status before checking their current LBA bounds.
    let last_block =
        (media.removable_media == 0 && media.media_present != 0).then_some(media.last_block);
    let Some(plan) = ReadPlan::new(
        offset,
        buffer_size,
        media.block_size,
        buffer.addr(),
        io_align,
        last_block,
    ) else {
        return Status::INVALID_PARAMETER;
    };

    let block = media.block_size as usize;
    let bounce = if plan.bounce_blocks == 0 {
        None
    } else {
        // bounce_blocks * block cannot overflow: it is at most one block or
        // MAX_BOUNCE_BYTES.
        let size = plan.bounce_blocks * block;
        let Some(bounce) = Bounce::new(size, io_align) else {
            log::error!(
                "DiskIO.ReadDisk: failed to allocate {} bytes for bounce buffer",
                size
            );
            return Status::OUT_OF_RESOURCES;
        };
        Some(bounce)
    };
    let scratch = bounce.as_ref().map_or(core::ptr::null_mut(), |b| b.data);
    let read = |lba: u64, size: usize, dest: *mut u8| {
        boot_services::with_image_callback(|| unsafe {
            ((*block_io).read_blocks)(block_io, media_id, lba, size, dest.cast())
        })
    };

    let dest = buffer.cast::<u8>();
    let mut lba = plan.lba;
    let mut done = 0usize;

    if plan.head_len != 0 {
        let status = read(lba, block, scratch);
        if status != Status::SUCCESS {
            return status;
        }
        // SAFETY: the bounce buffer holds a whole block and the caller's
        // buffer holds buffer_size >= head_len bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(scratch.add(plan.head_offset), dest, plan.head_len);
        }
        done = plan.head_len;
        lba += 1;
    }

    let mut remaining = plan.middle_blocks;
    while remaining != 0 {
        let blocks = if plan.bounce_middle {
            remaining.min(plan.bounce_blocks)
        } else {
            remaining
        };
        let size = blocks * block;
        // SAFETY: done + size <= buffer_size.
        let target = unsafe { dest.add(done) };
        let status = read(lba, size, if plan.bounce_middle { scratch } else { target });
        if status != Status::SUCCESS {
            return status;
        }
        if plan.bounce_middle {
            // SAFETY: the bounce buffer holds bounce_blocks >= blocks blocks.
            unsafe { core::ptr::copy_nonoverlapping(scratch, target, size) };
        }
        done += size;
        lba += blocks as u64;
        remaining -= blocks;
    }

    if plan.tail_len != 0 {
        let status = read(lba, block, scratch);
        if status != Status::SUCCESS {
            return status;
        }
        // SAFETY: done + tail_len == buffer_size, and the bounce buffer holds
        // a whole block.
        unsafe { core::ptr::copy_nonoverlapping(scratch, dest.add(done), plan.tail_len) };
    }

    Status::SUCCESS
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

#[cfg(test)]
mod tests {
    use super::{MAX_BOUNCE_BYTES, ReadPlan};

    #[test]
    fn direct_reads_need_no_bounce_buffer() {
        assert_eq!(
            ReadPlan::new(512, 1024, 512, 0x1000, 512, Some(2)),
            Some(ReadPlan {
                lba: 1,
                head_offset: 0,
                head_len: 0,
                middle_blocks: 2,
                bounce_middle: false,
                tail_len: 0,
                bounce_blocks: 0,
            })
        );
    }

    #[test]
    fn partial_blocks_bounce_one_block_and_middles_stay_direct() {
        // The middle starts at 0x1200, which satisfies IoAlign.
        assert_eq!(
            ReadPlan::new(100, 2000, 512, 0x1064, 512, Some(4)),
            Some(ReadPlan {
                lba: 0,
                head_offset: 100,
                head_len: 412,
                middle_blocks: 3,
                bounce_middle: false,
                tail_len: 52,
                bounce_blocks: 1,
            })
        );
        // A read inside one block is all head.
        assert_eq!(
            ReadPlan::new(4095, 1, 4096, 0x1000, 1, Some(0)),
            Some(ReadPlan {
                lba: 0,
                head_offset: 4095,
                head_len: 1,
                middle_blocks: 0,
                bounce_middle: false,
                tail_len: 0,
                bounce_blocks: 1,
            })
        );
    }

    #[test]
    fn misaligned_middles_bounce_in_bounded_chunks() {
        let plan = ReadPlan::new(0, 512 * 1000, 512, 0x1001, 512, None).unwrap();
        assert!(plan.bounce_middle);
        assert_eq!(plan.middle_blocks, 1000);
        assert_eq!(plan.bounce_blocks, MAX_BOUNCE_BYTES / 512);
        // A block larger than the cap still bounces one block at a time.
        let plan = ReadPlan::new(0, 1 << 20, 1 << 18, 0x1001, 16, None).unwrap();
        assert_eq!(plan.bounce_blocks, 1);
    }

    #[test]
    fn rejects_invalid_or_unrepresentable_spans() {
        assert!(ReadPlan::new(4095, 2, 4096, 0x1000, 1, Some(0)).is_none());
        assert!(ReadPlan::new(4096, 1, 4096, 0x1000, 1, Some(0)).is_none());
        assert!(ReadPlan::new(u64::MAX, 1, 512, 0x1000, 1, None).is_none());
        assert!(ReadPlan::new(0, 2, 512, usize::MAX, 1, None).is_none());
        assert!(ReadPlan::new(0, 1, 0, 0x1000, 1, None).is_none());
        assert!(ReadPlan::new(0, 0, 512, 0x1000, 1, None).is_none());
    }
}
