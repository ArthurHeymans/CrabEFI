//! EFI Block I/O Protocol implementation
//!
//! This module provides block-level access to storage devices, allowing GRUB to
//! use its built-in filesystem drivers (ISO9660, ext4, etc.) to read partitions.

use core::ffi::c_void;
use r_efi::efi::{Boolean, Status};
use r_efi::protocols::block_io;

use super::instance::Registry;
use crate::drivers::storage::{self, StorageId};
use crate::efi::utils::allocate_protocol_with_log;

/// Block I/O Protocol GUID.
pub const BLOCK_IO_PROTOCOL_GUID: r_efi::efi::Guid = block_io::PROTOCOL_GUID;

/// Block I/O Protocol revision.
pub const BLOCK_IO_REVISION: u64 = block_io::REVISION;

/// Block I/O media structure supplied by `r-efi`.
pub type BlockIoMedia = block_io::Media;

/// Block I/O protocol ABI supplied by `r-efi`.
pub type BlockIoProtocol = block_io::Protocol;

/// Internal context for BlockIO protocol instance
#[derive(Clone, Copy)]
struct BlockIoContext {
    /// Media ID (matches BlockIoMedia.media_id)
    media_id: u32,
    /// Backing storage device
    storage: StorageId,
    /// Starting LBA (0 for raw disk, partition start for partitions)
    start_lba: u64,
    /// Number of blocks
    num_blocks: u64,
    /// Block size
    block_size: u32,
}

static INSTANCES: Registry<BlockIoProtocol, BlockIoContext> = Registry::new();

/// Reset the block device
extern "efiapi" fn block_io_reset(
    _this: *mut BlockIoProtocol,
    _extended_verification: Boolean,
) -> Status {
    log::debug!("BlockIO.Reset()");
    Status::SUCCESS
}

/// Read blocks from the device
extern "efiapi" fn block_io_read_blocks(
    this: *mut BlockIoProtocol,
    media_id: u32,
    lba: u64,
    buffer_size: usize,
    buffer: *mut c_void,
) -> Status {
    if this.is_null() || buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx = match INSTANCES.get(this) {
        Some(c) => c,
        None => {
            log::error!("BlockIO.ReadBlocks: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    // Verify media ID
    if media_id != ctx.media_id {
        log::debug!(
            "BlockIO.ReadBlocks: media_id mismatch ({} vs {})",
            media_id,
            ctx.media_id
        );
        return Status::MEDIA_CHANGED;
    }

    // Calculate number of blocks to read
    let block_size = ctx.block_size as usize;
    if !buffer_size.is_multiple_of(block_size) {
        log::debug!(
            "BlockIO.ReadBlocks: buffer_size {} not multiple of block_size {}",
            buffer_size,
            block_size
        );
        return Status::BAD_BUFFER_SIZE;
    }

    let num_blocks = buffer_size / block_size;

    let Some(absolute_lba) = crate::efi::block_range::checked_absolute_lba(
        ctx.start_lba,
        lba,
        num_blocks as u64,
        ctx.num_blocks,
    ) else {
        log::debug!(
            "BlockIO.ReadBlocks: invalid LBA {} + {} blocks for device size {}",
            lba,
            num_blocks,
            ctx.num_blocks
        );
        return Status::INVALID_PARAMETER;
    };

    log::trace!(
        "BlockIO.ReadBlocks(media={}, lba={}, blocks={}, size={})",
        ctx.media_id,
        lba,
        num_blocks,
        buffer_size
    );

    // Read all blocks in a single call — the drivers support multi-sector reads
    // and chunk internally at optimal sizes (e.g., 128 sectors / 64KB per SCSI
    // command for USB). This avoids the massive overhead of issuing one BOT
    // transaction (CBW + data + CSW) per 512-byte sector.
    let buffer_slice = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, buffer_size) };
    let Ok(count) = u32::try_from(num_blocks) else {
        return Status::INVALID_PARAMETER;
    };

    match storage::with_disk(ctx.storage, |disk| {
        disk.read_blocks(absolute_lba, count, buffer_slice)
    })
    .and_then(|read| read)
    {
        Ok(()) => Status::SUCCESS,
        Err(error) => {
            log::error!(
                "BlockIO.ReadBlocks: read failed at LBA {} ({} blocks): {}",
                absolute_lba,
                num_blocks,
                error
            );
            Status::DEVICE_ERROR
        }
    }
}

/// Write blocks to the device (not supported - read only for boot)
extern "efiapi" fn block_io_write_blocks(
    _this: *mut BlockIoProtocol,
    _media_id: u32,
    _lba: u64,
    _buffer_size: usize,
    _buffer: *mut c_void,
) -> Status {
    log::debug!("BlockIO.WriteBlocks: not supported (read-only)");
    Status::WRITE_PROTECTED
}

/// Flush blocks (no-op for read-only device)
extern "efiapi" fn block_io_flush_blocks(_this: *mut BlockIoProtocol) -> Status {
    log::debug!("BlockIO.FlushBlocks()");
    Status::SUCCESS
}

/// Create a BlockIO protocol for the raw disk
///
/// # Arguments
/// * `storage` - Backing storage device
/// * `num_blocks` - Total number of blocks on the disk
/// * `block_size` - Size of each block in bytes
///
/// # Returns
/// Pointer to BlockIoProtocol, or null on failure
pub fn create_disk_block_io(
    storage: StorageId,
    num_blocks: u64,
    block_size: u32,
) -> *mut BlockIoProtocol {
    create_block_io_internal(storage, 0, 0, num_blocks, block_size, false)
}

/// Create a BlockIO protocol for a partition
///
/// # Arguments
/// * `storage` - Backing storage device
/// * `partition_num` - Partition number (1-based)
/// * `start_lba` - Starting LBA of the partition
/// * `num_blocks` - Number of blocks in the partition
/// * `block_size` - Size of each block in bytes
///
/// # Returns
/// Pointer to BlockIoProtocol, or null on failure
pub fn create_partition_block_io(
    storage: StorageId,
    partition_num: u32,
    start_lba: u64,
    num_blocks: u64,
    block_size: u32,
) -> *mut BlockIoProtocol {
    create_block_io_internal(
        storage,
        partition_num,
        start_lba,
        num_blocks,
        block_size,
        true,
    )
}

/// Internal function to create BlockIO protocol
fn create_block_io_internal(
    storage: StorageId,
    media_id: u32,
    start_lba: u64,
    num_blocks: u64,
    block_size: u32,
    is_partition: bool,
) -> *mut BlockIoProtocol {
    // Allocate media structure
    let media_ptr = allocate_protocol_with_log::<BlockIoMedia>("BlockIoMedia", |m| {
        m.media_id = media_id;
        m.removable_media = true; // Assume removable for now
        m.media_present = true;
        m.logical_partition = is_partition;
        m.read_only = true; // We only support read for booting
        m.write_caching = false;
        m.block_size = block_size;
        m.io_align = 0;
        m.last_block = num_blocks.saturating_sub(1);
        m.lowest_aligned_lba = 0;
        m.logical_blocks_per_physical_block = 1;
        m.optimal_transfer_length_granularity = 0;
    });
    if media_ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Allocate protocol structure
    let protocol_ptr = INSTANCES.allocate(
        "BlockIoProtocol",
        BlockIoContext {
            media_id,
            storage,
            start_lba,
            num_blocks,
            block_size,
        },
        |p| {
            p.revision = BLOCK_IO_REVISION;
            p.media = media_ptr;
            p.reset = block_io_reset;
            p.read_blocks = block_io_read_blocks;
            p.write_blocks = block_io_write_blocks;
            p.flush_blocks = block_io_flush_blocks;
        },
    );
    if protocol_ptr.is_null() {
        crate::efi::allocator::free_pool(media_ptr as *mut u8);
        return core::ptr::null_mut();
    }

    let kind = if is_partition { "partition" } else { "disk" };
    log::info!(
        "BlockIO: created {} protocol (media={}, storage={:?}, start={}, blocks={}, bs={})",
        kind,
        media_id,
        storage,
        start_lba,
        num_blocks,
        block_size
    );

    protocol_ptr
}
