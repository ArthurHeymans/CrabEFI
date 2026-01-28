//! GPT (GUID Partition Table) parser
//!
//! This module provides parsing of GPT partitioned disks to find the EFI
//! System Partition (ESP).

use crate::drivers::nvme::NvmeController;

/// Sector size (standard for most disks)
pub const SECTOR_SIZE: usize = 512;

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

    /// Get partition size in bytes
    pub fn size_bytes(&self) -> u64 {
        self.size_sectors() * SECTOR_SIZE as u64
    }

    /// Get partition name as ASCII (for display)
    pub fn name_ascii(&self) -> heapless::String<72> {
        let mut s = heapless::String::new();
        // Read name bytes avoiding alignment issues with packed struct
        let ptr = self as *const Self as *const u8;
        // Name field is at offset 56 (16+16+8+8+8)
        let name_ptr = unsafe { ptr.add(56) as *const u16 };
        for i in 0..36 {
            let c = unsafe { core::ptr::read_unaligned(name_ptr.add(i)) };
            if c == 0 {
                break;
            }
            // Convert UTF-16LE to ASCII (simple conversion)
            if c < 128 {
                let _ = s.push(c as u8 as char);
            } else {
                let _ = s.push('?');
            }
        }
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
    /// First LBA
    pub first_lba: u64,
    /// Last LBA (inclusive)
    pub last_lba: u64,
    /// Attributes
    pub attributes: u64,
    /// Is this the EFI System Partition?
    pub is_esp: bool,
}

impl Partition {
    /// Get partition size in sectors
    pub fn size_sectors(&self) -> u64 {
        if self.last_lba >= self.first_lba {
            self.last_lba - self.first_lba + 1
        } else {
            0
        }
    }

    /// Get partition size in bytes
    pub fn size_bytes(&self) -> u64 {
        self.size_sectors() * SECTOR_SIZE as u64
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

/// Sector read trait for abstracting block devices
pub trait SectorRead {
    /// Read a single sector
    fn read_sector(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), GptError>;
}

/// Wrapper around NVMe controller for SectorRead trait
pub struct NvmeDisk<'a> {
    controller: &'a mut NvmeController,
    nsid: u32,
}

impl<'a> NvmeDisk<'a> {
    pub fn new(controller: &'a mut NvmeController, nsid: u32) -> Self {
        Self { controller, nsid }
    }
}

impl<'a> SectorRead for NvmeDisk<'a> {
    fn read_sector(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), GptError> {
        if buffer.len() < SECTOR_SIZE {
            return Err(GptError::BufferTooSmall);
        }

        self.controller
            .read_sector(self.nsid, lba, buffer)
            .map_err(|_| GptError::ReadError)
    }
}

/// Read and parse the GPT header
pub fn read_gpt_header<R: SectorRead>(reader: &mut R) -> Result<GptHeader, GptError> {
    let mut buffer = [0u8; SECTOR_SIZE];

    // GPT header is at LBA 1 (sector 1)
    reader.read_sector(1, &mut buffer)?;

    // Parse header (copy to avoid alignment issues with packed struct)
    let header = unsafe { core::ptr::read_unaligned(buffer.as_ptr() as *const GptHeader) };

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
pub fn read_partitions<R: SectorRead>(
    reader: &mut R,
    header: &GptHeader,
) -> Result<heapless::Vec<Partition, 16>, GptError> {
    let mut partitions = heapless::Vec::new();
    let mut buffer = [0u8; SECTOR_SIZE];

    let entries_per_sector = SECTOR_SIZE / header.partition_entry_size as usize;
    let num_sectors =
        (header.num_partition_entries as usize + entries_per_sector - 1) / entries_per_sector;

    let mut entry_index = 0u32;

    for sector_offset in 0..num_sectors {
        let lba = header.partition_entry_lba + sector_offset as u64;
        reader.read_sector(lba, &mut buffer)?;

        for i in 0..entries_per_sector {
            if entry_index >= header.num_partition_entries {
                break;
            }

            let offset = i * header.partition_entry_size as usize;
            let entry = unsafe {
                core::ptr::read_unaligned(buffer[offset..].as_ptr() as *const GptPartitionEntry)
            };

            if !entry.is_empty() {
                let partition = Partition {
                    type_guid: entry.type_guid,
                    partition_guid: entry.partition_guid,
                    first_lba: entry.first_lba,
                    last_lba: entry.last_lba,
                    attributes: entry.attributes,
                    is_esp: entry.is_esp(),
                };

                log::debug!(
                    "Partition {}: LBA {}-{} ({} MB) ESP={}",
                    entry_index,
                    partition.first_lba,
                    partition.last_lba,
                    partition.size_bytes() / (1024 * 1024),
                    partition.is_esp
                );

                if partitions.push(partition).is_err() {
                    log::warn!("Too many partitions, ignoring remaining");
                    break;
                }
            }

            entry_index += 1;
        }
    }

    if partitions.is_empty() {
        return Err(GptError::NoPartitions);
    }

    Ok(partitions)
}

/// Find the EFI System Partition
pub fn find_esp<R: SectorRead>(reader: &mut R) -> Result<Partition, GptError> {
    let header = read_gpt_header(reader)?;
    let partitions = read_partitions(reader, &header)?;

    for partition in partitions {
        if partition.is_esp {
            log::info!(
                "Found EFI System Partition: LBA {}-{} ({} MB)",
                partition.first_lba,
                partition.last_lba,
                partition.size_bytes() / (1024 * 1024)
            );
            return Ok(partition);
        }
    }

    Err(GptError::NoEsp)
}

/// Find ESP on an NVMe controller
pub fn find_esp_on_nvme(controller: &mut NvmeController) -> Result<Partition, GptError> {
    let nsid = controller
        .default_namespace()
        .map(|ns| ns.nsid)
        .ok_or(GptError::ReadError)?;

    let mut disk = NvmeDisk::new(controller, nsid);
    find_esp(&mut disk)
}
