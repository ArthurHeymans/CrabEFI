//! EFI Block I/O Protocol implementation
//!
//! This module provides block-level access to storage devices, allowing GRUB to
//! use its built-in filesystem drivers (ISO9660, ext4, etc.) to read partitions.

use core::ffi::c_void;
use r_efi::efi::{Guid, Status};

use crate::efi::utils::allocate_protocol_with_log;

/// Block I/O Protocol GUID
pub const BLOCK_IO_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x964e5b21,
    0x6459,
    0x11d2,
    0x8e,
    0x39,
    &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);

/// Block I/O Protocol revision
pub const BLOCK_IO_REVISION: u64 = 0x00010000; // EFI_BLOCK_IO_PROTOCOL_REVISION

/// Block I/O Media structure
#[repr(C)]
pub struct BlockIoMedia {
    /// Media ID - changes when media is changed
    pub media_id: u32,
    /// True if media is removable
    pub removable_media: bool,
    /// True if media is present
    pub media_present: bool,
    /// True if this is a logical partition
    pub logical_partition: bool,
    /// True if media is read-only
    pub read_only: bool,
    /// True if WriteBlocks() must be called with entire blocks
    pub write_caching: bool,
    /// Block size in bytes
    pub block_size: u32,
    /// IO alignment requirement (0 or power of 2)
    pub io_align: u32,
    /// Padding for alignment
    _pad: u32,
    /// Last logical block address
    pub last_block: u64,
}
/// Block I/O Protocol structure
#[repr(C)]
pub struct BlockIoProtocol {
    /// Protocol revision
    pub revision: u64,
    /// Pointer to BlockIoMedia
    pub media: *mut BlockIoMedia,
    /// Reset function
    pub reset:
        extern "efiapi" fn(this: *mut BlockIoProtocol, extended_verification: bool) -> Status,
    /// Read blocks function
    pub read_blocks: extern "efiapi" fn(
        this: *mut BlockIoProtocol,
        media_id: u32,
        lba: u64,
        buffer_size: usize,
        buffer: *mut c_void,
    ) -> Status,
    /// Write blocks function
    pub write_blocks: extern "efiapi" fn(
        this: *mut BlockIoProtocol,
        media_id: u32,
        lba: u64,
        buffer_size: usize,
        buffer: *mut c_void,
    ) -> Status,
    /// Flush blocks function
    pub flush_blocks: extern "efiapi" fn(this: *mut BlockIoProtocol) -> Status,
}

/// Internal context for BlockIO protocol instance
struct BlockIoContext {
    /// Media ID (matches BlockIoMedia.media_id)
    media_id: u32,
    /// Storage device ID from the storage registry
    storage_device_id: u32,
    /// Starting LBA (0 for raw disk, partition start for partitions)
    start_lba: u64,
    /// Number of blocks
    num_blocks: u64,
    /// Block size
    block_size: u32,
}

/// Maximum number of BlockIO instances
const MAX_BLOCK_IO_INSTANCES: usize = 16;

/// Global storage for BlockIO contexts
static mut BLOCK_IO_CONTEXTS: [Option<BlockIoContext>; MAX_BLOCK_IO_INSTANCES] =
    [const { None }; MAX_BLOCK_IO_INSTANCES];

/// Protocol instance to context mapping
static mut PROTOCOL_TO_CONTEXT: [Option<*mut BlockIoProtocol>; MAX_BLOCK_IO_INSTANCES] =
    [const { None }; MAX_BLOCK_IO_INSTANCES];

/// Find context index for a protocol instance
fn find_context_index(protocol: *mut BlockIoProtocol) -> Option<usize> {
    unsafe {
        let contexts = core::ptr::addr_of!(PROTOCOL_TO_CONTEXT);
        for (i, p) in (*contexts).iter().enumerate() {
            if let Some(ptr) = p
                && *ptr == protocol
            {
                return Some(i);
            }
        }
    }
    None
}

/// Reset the block device
extern "efiapi" fn block_io_reset(
    _this: *mut BlockIoProtocol,
    _extended_verification: bool,
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
    use crate::drivers::storage;

    if this.is_null() || buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx_idx = match find_context_index(this) {
        Some(idx) => idx,
        None => {
            log::error!("BlockIO.ReadBlocks: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    let ctx = unsafe {
        let contexts = core::ptr::addr_of!(BLOCK_IO_CONTEXTS);
        match &(*contexts)[ctx_idx] {
            Some(c) => c,
            None => return Status::INVALID_PARAMETER,
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

    // Check bounds
    if lba + num_blocks as u64 > ctx.num_blocks {
        log::debug!(
            "BlockIO.ReadBlocks: LBA {} + {} blocks exceeds device size {}",
            lba,
            num_blocks,
            ctx.num_blocks
        );
        return Status::INVALID_PARAMETER;
    }

    log::trace!(
        "BlockIO.ReadBlocks(media={}, lba={}, blocks={}, size={})",
        ctx.media_id,
        lba,
        num_blocks,
        buffer_size
    );

    // Read each block using the storage abstraction
    let buffer_slice = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, buffer_size) };

    for i in 0..num_blocks {
        let absolute_lba = ctx.start_lba + lba + i as u64;
        let offset = i * block_size;
        let block_buf = &mut buffer_slice[offset..offset + block_size];

        if storage::read_sectors(ctx.storage_device_id, absolute_lba, block_buf).is_err() {
            log::error!("BlockIO.ReadBlocks: read failed at LBA {}", absolute_lba);
            return Status::DEVICE_ERROR;
        }
    }

    Status::SUCCESS
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
/// * `storage_device_id` - Device ID from the storage registry
/// * `num_blocks` - Total number of blocks on the disk
/// * `block_size` - Size of each block in bytes
///
/// # Returns
/// Pointer to BlockIoProtocol, or null on failure
pub fn create_disk_block_io(
    storage_device_id: u32,
    num_blocks: u64,
    block_size: u32,
) -> *mut BlockIoProtocol {
    create_block_io_internal(storage_device_id, 0, 0, num_blocks, block_size, false)
}

/// Create a BlockIO protocol for a partition
///
/// # Arguments
/// * `storage_device_id` - Device ID from the storage registry
/// * `partition_num` - Partition number (1-based)
/// * `start_lba` - Starting LBA of the partition
/// * `num_blocks` - Number of blocks in the partition
/// * `block_size` - Size of each block in bytes
///
/// # Returns
/// Pointer to BlockIoProtocol, or null on failure
pub fn create_partition_block_io(
    storage_device_id: u32,
    partition_num: u32,
    start_lba: u64,
    num_blocks: u64,
    block_size: u32,
) -> *mut BlockIoProtocol {
    create_block_io_internal(
        storage_device_id,
        partition_num,
        start_lba,
        num_blocks,
        block_size,
        true,
    )
}

/// Internal function to create BlockIO protocol
fn create_block_io_internal(
    storage_device_id: u32,
    media_id: u32,
    start_lba: u64,
    num_blocks: u64,
    block_size: u32,
    is_partition: bool,
) -> *mut BlockIoProtocol {
    // Find a free context slot
    let ctx_idx = unsafe {
        let mut found = None;
        let contexts = core::ptr::addr_of!(BLOCK_IO_CONTEXTS);
        for (i, slot) in (*contexts).iter().enumerate() {
            if slot.is_none() {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => {
                log::error!("BlockIO: no free context slots");
                return core::ptr::null_mut();
            }
        }
    };

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
        m._pad = 0;
        m.last_block = num_blocks.saturating_sub(1);
    });
    if media_ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Allocate protocol structure
    let protocol_ptr = allocate_protocol_with_log::<BlockIoProtocol>("BlockIoProtocol", |p| {
        p.revision = BLOCK_IO_REVISION;
        p.media = media_ptr;
        p.reset = block_io_reset;
        p.read_blocks = block_io_read_blocks;
        p.write_blocks = block_io_write_blocks;
        p.flush_blocks = block_io_flush_blocks;
    });
    if protocol_ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Store context
    unsafe {
        let contexts = core::ptr::addr_of_mut!(BLOCK_IO_CONTEXTS);
        (*contexts)[ctx_idx] = Some(BlockIoContext {
            media_id,
            storage_device_id,
            start_lba,
            num_blocks,
            block_size,
        });
        let proto_map = core::ptr::addr_of_mut!(PROTOCOL_TO_CONTEXT);
        (*proto_map)[ctx_idx] = Some(protocol_ptr);
    }

    let kind = if is_partition { "partition" } else { "disk" };
    log::info!(
        "BlockIO: created {} protocol (media={}, storage={}, start={}, blocks={}, bs={})",
        kind,
        media_id,
        storage_device_id,
        start_lba,
        num_blocks,
        block_size
    );

    protocol_ptr
}
