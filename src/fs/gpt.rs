//! GPT (GUID Partition Table) parser
//!
//! This module provides parsing of GPT partitioned disks to find the EFI
//! System Partition (ESP).

use crate::drivers::block::{BlockDevice, BlockError};

/// Maximum supported block size (4KB - handles most devices including CD-ROMs)
const MAX_BLOCK_SIZE: usize = 4096;

/// Minimum block size for GPT calculations
const MIN_BLOCK_SIZE: usize = 512;

/// GPT header signature "EFI PART"
const GPT_SIGNATURE: u64 = 0x5452415020494645;

/// EFI System Partition type GUID (C12A7328-F81F-11D2-BA4B-00A0C93EC93B)
/// Stored in mixed-endian format
const ESP_TYPE_GUID: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, // LE: C12A7328
    0x1f, 0xf8, // LE: F81F
    0xd2, 0x11, // LE: 11D2
    0xba, 0x4b, // BE: BA4B
    0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b, // BE: 00A0C93EC93B
];

/// GPT Header structure
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct GptHeader {
    /// Signature ("EFI PART")
    pub signature: u64,
    /// Revision (usually 0x00010000)
    pub revision: u32,
    /// Header size (usually 92 bytes)
    pub header_size: u32,
    /// CRC32 of header
    pub header_crc32: u32,
    /// Reserved (must be zero)
    pub reserved: u32,
    /// Current LBA (location of this header)
    pub current_lba: u64,
    /// Backup LBA (location of the backup header)
    pub backup_lba: u64,
    /// First usable LBA for partitions
    pub first_usable_lba: u64,
    /// Last usable LBA for partitions
    pub last_usable_lba: u64,
    /// Disk GUID
    pub disk_guid: [u8; 16],
    /// Starting LBA of partition entry array
    pub partition_entry_lba: u64,
    /// Number of partition entries
    pub num_partition_entries: u32,
    /// Size of each partition entry (usually 128 bytes)
    pub partition_entry_size: u32,
    /// CRC32 of partition entry array
    pub partition_entry_crc32: u32,
}

impl GptHeader {
    /// Validate the GPT header
    pub fn is_valid(&self) -> bool {
        self.signature == GPT_SIGNATURE
    }
}

/// GPT Partition Entry
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct GptPartitionEntry {
    /// Partition type GUID
    pub type_guid: [u8; 16],
    /// Unique partition GUID
    pub partition_guid: [u8; 16],
    /// First LBA
    pub first_lba: u64,
    /// Last LBA (inclusive)
    pub last_lba: u64,
    /// Attribute flags
    pub attributes: u64,
    /// Partition name (UTF-16LE, 36 characters)
    pub name: [u16; 36],
}

impl Default for GptPartitionEntry {
    fn default() -> Self {
        Self {
            type_guid: [0u8; 16],
            partition_guid: [0u8; 16],
            first_lba: 0,
            last_lba: 0,
            attributes: 0,
            name: [0u16; 36],
        }
    }
}

impl GptPartitionEntry {
    /// Check if this is an empty entry
    pub fn is_empty(&self) -> bool {
        self.type_guid == [0u8; 16]
    }

    /// Check if this is an EFI System Partition
    pub fn is_esp(&self) -> bool {
        self.type_guid == ESP_TYPE_GUID
    }

    /// Get partition size in sectors
    pub fn size_sectors(&self) -> u64 {
        if self.last_lba >= self.first_lba {
            self.last_lba - self.first_lba + 1
        } else {
            0
        }
    }

    /// Get partition size in bytes (assumes 512-byte sectors)
    ///
    /// Note: For devices with larger block sizes (e.g., CD-ROMs with 2048-byte blocks),
    /// this will underestimate the actual size. The LBA values are relative to the
    /// device's native block size.
    pub fn size_bytes(&self) -> u64 {
        self.size_sectors() * MIN_BLOCK_SIZE as u64
    }

    /// Get partition name as ASCII (for display)
    pub fn name_ascii(&self) -> heapless::String<72> {
        let mut s = heapless::String::new();
        // Read name bytes avoiding alignment issues with packed struct
        let ptr = self as *const Self as *const u8;
        // Name field is at offset 56 (16+16+8+8+8)
        let name_ptr = unsafe { ptr.add(56) as *const u16 };

        (0..36)
            .map(|i| unsafe { core::ptr::read_unaligned(name_ptr.add(i)) })
            .take_while(|&c| c != 0)
            .for_each(|c| {
                // Convert UTF-16LE to ASCII (simple conversion)
                let _ = s.push(if c < 128 { c as u8 as char } else { '?' });
            });
        s
    }
}

/// Parsed partition information
#[derive(Debug, Clone)]
pub struct Partition {
    /// Partition type GUID
    pub type_guid: [u8; 16],
    /// Unique partition GUID
    pub partition_guid: [u8; 16],
    /// First LBA (in device block terms)
    pub first_lba: u64,
    /// Last LBA (inclusive, in device block terms)
    pub last_lba: u64,
    /// Attributes
    pub attributes: u64,
    /// Is this the EFI System Partition?
    pub is_esp: bool,
    /// Block size of the device (for size calculations)
    pub block_size: u32,
}

impl Partition {
    /// Get partition size in blocks
    pub fn size_sectors(&self) -> u64 {
        if self.last_lba >= self.first_lba {
            self.last_lba - self.first_lba + 1
        } else {
            0
        }
    }

    /// Get partition size in bytes
    pub fn size_bytes(&self) -> u64 {
        self.size_sectors() * self.block_size as u64
    }
}

/// Error type for GPT operations
#[derive(Debug)]
pub enum GptError {
    /// Read error from storage device
    ReadError,
    /// Invalid GPT header
    InvalidHeader,
    /// No partitions found
    NoPartitions,
    /// No EFI System Partition found
    NoEsp,
    /// Buffer too small
    BufferTooSmall,
}

impl From<BlockError> for GptError {
    fn from(e: BlockError) -> Self {
        match e {
            BlockError::InvalidParameter => GptError::BufferTooSmall,
            _ => GptError::ReadError,
        }
    }
}

/// Read and parse the GPT header
///
/// Handles both standard disks (512-byte sectors) and hybrid ISOs on CD-ROMs
/// (2048-byte sectors with GPT embedded at byte offset 512).
pub fn read_gpt_header<D: BlockDevice>(device: &mut D) -> Result<GptHeader, GptError> {
    // Use device's actual block size, capped at MAX_BLOCK_SIZE
    let info = device.info();
    let block_size = (info.block_size as usize).min(MAX_BLOCK_SIZE);

    // Allocate buffer large enough for any supported block size
    let mut buffer = [0u8; MAX_BLOCK_SIZE];

    // For devices with block sizes > 512 bytes (like CD-ROMs), the GPT on hybrid
    // ISOs is at byte offset 512, which is inside the first block (LBA 0).
    // For standard 512-byte sector devices, GPT is at LBA 1.
    let (lba, gpt_offset) = if block_size > MIN_BLOCK_SIZE {
        // Hybrid ISO: GPT header at byte 512 (inside LBA 0)
        (0, MIN_BLOCK_SIZE)
    } else {
        // Standard disk: GPT header at LBA 1
        (1, 0)
    };

    log::debug!(
        "Reading GPT header from LBA {} offset {} (block_size={})...",
        lba,
        gpt_offset,
        block_size
    );

    device.read_block(lba, &mut buffer[..block_size])?;

    // Parse header from the appropriate offset
    let header =
        unsafe { core::ptr::read_unaligned(buffer[gpt_offset..].as_ptr() as *const GptHeader) };

    // Copy fields to avoid alignment issues with packed struct
    let signature = header.signature;
    let revision = header.revision;
    let num_partition_entries = header.num_partition_entries;
    let partition_entry_size = header.partition_entry_size;

    if !header.is_valid() {
        log::error!("Invalid GPT signature: {:#018x}", signature);
        return Err(GptError::InvalidHeader);
    }

    log::debug!(
        "GPT Header: revision={:#x}, entries={}, entry_size={}",
        revision,
        num_partition_entries,
        partition_entry_size
    );

    Ok(header)
}

/// Read partition entries from GPT
///
/// Handles both standard disks (512-byte sectors) and hybrid ISOs on CD-ROMs
/// (2048-byte sectors with GPT written assuming 512-byte blocks).
pub fn read_partitions<D: BlockDevice>(
    device: &mut D,
    header: &GptHeader,
) -> Result<heapless::Vec<Partition, 16>, GptError> {
    let mut partitions = heapless::Vec::new();

    // Use device's actual block size, capped at MAX_BLOCK_SIZE
    let info = device.info();
    let block_size = (info.block_size as usize).clamp(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);

    let mut buffer = [0u8; MAX_BLOCK_SIZE];

    // For hybrid ISOs on large-block devices, the GPT's LBA values are in 512-byte terms.
    // We need to translate to actual device blocks.
    let is_hybrid = block_size > MIN_BLOCK_SIZE;

    // Calculate where partition entries start in byte terms
    // For hybrid ISOs, partition_entry_lba is in 512-byte terms
    let entries_byte_offset = if is_hybrid {
        header.partition_entry_lba as usize * MIN_BLOCK_SIZE
    } else {
        header.partition_entry_lba as usize * block_size
    };

    let entry_size = header.partition_entry_size as usize;
    let total_entries = header.num_partition_entries as usize;
    let total_bytes_needed = total_entries * entry_size;

    let mut entry_index = 0u32;
    let mut consecutive_empty = 0u32;
    let mut bytes_read = 0usize;

    'outer: while bytes_read < total_bytes_needed {
        // Calculate which device block to read
        let current_byte_offset = entries_byte_offset + bytes_read;
        let lba = (current_byte_offset / block_size) as u64;
        let offset_in_block = current_byte_offset % block_size;

        // Try to read the block
        if let Err(e) = device.read_block(lba, &mut buffer[..block_size]) {
            if !partitions.is_empty() {
                log::debug!(
                    "Stopping partition scan at LBA {} (read error after finding {} partitions): {:?}",
                    lba,
                    partitions.len(),
                    e
                );
                break;
            }
            return Err(e.into());
        }

        // Process entries from this block
        let mut pos = offset_in_block;
        while pos + entry_size <= block_size && entry_index < header.num_partition_entries {
            let entry = unsafe {
                core::ptr::read_unaligned(buffer[pos..].as_ptr() as *const GptPartitionEntry)
            };

            if !entry.is_empty() {
                consecutive_empty = 0;

                // For hybrid ISOs, translate GPT LBAs (512-byte terms) to device LBAs
                let (first_lba, last_lba) = if is_hybrid {
                    // GPT LBA * 512 / block_size = device LBA
                    // This works because hybrid ISO partitions are aligned to 2048 bytes
                    let first = entry.first_lba * MIN_BLOCK_SIZE as u64 / block_size as u64;
                    let last = entry.last_lba * MIN_BLOCK_SIZE as u64 / block_size as u64;
                    (first, last)
                } else {
                    (entry.first_lba, entry.last_lba)
                };

                let partition = Partition {
                    type_guid: entry.type_guid,
                    partition_guid: entry.partition_guid,
                    first_lba,
                    last_lba,
                    attributes: entry.attributes,
                    is_esp: entry.is_esp(),
                    block_size: block_size as u32,
                };

                log::debug!(
                    "Partition {}: LBA {}-{} ({} MB) ESP={}{}",
                    entry_index,
                    partition.first_lba,
                    partition.last_lba,
                    partition.size_bytes() / (1024 * 1024),
                    partition.is_esp,
                    if is_hybrid { " [hybrid]" } else { "" }
                );

                if partitions.push(partition).is_err() {
                    log::warn!("Too many partitions, ignoring remaining");
                    break 'outer;
                }
            } else {
                consecutive_empty += 1;
                // Stop scanning after 8 consecutive empty entries (2 blocks worth)
                // This handles truncated partition tables in ISOs
                if consecutive_empty >= 8 && !partitions.is_empty() {
                    log::debug!(
                        "Stopping partition scan after {} consecutive empty entries",
                        consecutive_empty
                    );
                    break 'outer;
                }
            }

            pos += entry_size;
            bytes_read += entry_size;
            entry_index += 1;
        }

        // If we didn't process any entries, move to next block
        if pos == offset_in_block {
            bytes_read += block_size - offset_in_block;
        }
    }

    if partitions.is_empty() {
        return Err(GptError::NoPartitions);
    }

    Ok(partitions)
}

/// Find the EFI System Partition
pub fn find_esp<D: BlockDevice>(device: &mut D) -> Result<Partition, GptError> {
    let header = read_gpt_header(device)?;
    let partitions = read_partitions(device, &header)?;

    partitions
        .into_iter()
        .find(|partition| partition.is_esp)
        .inspect(|partition| {
            log::info!(
                "Found EFI System Partition: LBA {}-{} ({} MB)",
                partition.first_lba,
                partition.last_lba,
                partition.size_bytes() / (1024 * 1024)
            );
        })
        .ok_or(GptError::NoEsp)
}
