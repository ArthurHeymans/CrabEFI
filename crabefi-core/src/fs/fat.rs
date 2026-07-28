//! FAT filesystem driver
//!
//! This module provides read support for FAT12/16/32 filesystems.
//! Used to read files from the EFI System Partition.

use crate::drivers::block::BlockDevice;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Standard sector size (512 bytes) - used for FAT calculations
pub const SECTOR_SIZE: usize = 512;

/// Maximum block size we support (4KB - handles CD-ROMs with 2048-byte blocks)
const MAX_BLOCK_SIZE: usize = 4096;

/// FAT Boot Parameter Block (BPB) - common fields
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Clone, Copy, Debug)]
struct BiosParameterBlock {
    /// Jump instruction (3 bytes)
    jmp: [u8; 3],
    /// OEM name (8 bytes)
    oem_name: [u8; 8],
    /// Bytes per sector
    bytes_per_sector: u16,
    /// Sectors per cluster
    sectors_per_cluster: u8,
    /// Reserved sectors (before first FAT)
    reserved_sectors: u16,
    /// Number of FATs
    num_fats: u8,
    /// Root entry count (0 for FAT32)
    root_entry_count: u16,
    /// Total sectors (16-bit, 0 if over 65535)
    total_sectors_16: u16,
    /// Media type
    media_type: u8,
    /// Sectors per FAT (FAT12/16, 0 for FAT32)
    sectors_per_fat_16: u16,
    /// Sectors per track
    sectors_per_track: u16,
    /// Number of heads
    num_heads: u16,
    /// Hidden sectors
    hidden_sectors: u32,
    /// Total sectors (32-bit)
    total_sectors_32: u32,
}

/// FAT32 Extended Boot Record
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Clone, Copy, Debug)]
struct Fat32Ebr {
    /// Sectors per FAT (32-bit)
    sectors_per_fat_32: u32,
    /// Extended flags
    ext_flags: u16,
    /// Filesystem version
    fs_version: u16,
    /// Root directory cluster
    root_cluster: u32,
    /// FSInfo sector
    fs_info: u16,
    /// Backup boot sector
    backup_boot_sector: u16,
    /// Reserved
    reserved: [u8; 12],
    /// Drive number
    drive_number: u8,
    /// Reserved
    reserved1: u8,
    /// Extended boot signature
    boot_sig: u8,
    /// Volume serial number
    volume_serial: u32,
    /// Volume label
    volume_label: [u8; 11],
    /// Filesystem type string
    fs_type: [u8; 8],
}

/// FAT directory entry
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Clone, Copy, Debug)]
pub struct DirectoryEntry {
    /// Short name (8 characters)
    name: [u8; 8],
    /// Extension (3 characters)
    ext: [u8; 3],
    /// Attributes
    attr: u8,
    /// Reserved for Windows NT
    nt_reserved: u8,
    /// Creation time tenths
    creation_time_tenths: u8,
    /// Creation time
    creation_time: u16,
    /// Creation date
    creation_date: u16,
    /// Last access date
    last_access_date: u16,
    /// First cluster high (FAT32)
    first_cluster_hi: u16,
    /// Last modification time
    modification_time: u16,
    /// Last modification date
    modification_date: u16,
    /// First cluster low
    first_cluster_lo: u16,
    /// File size
    file_size: u32,
}

impl DirectoryEntry {
    /// Get the first cluster number
    pub fn first_cluster(&self) -> u32 {
        ((self.first_cluster_hi as u32) << 16) | (self.first_cluster_lo as u32)
    }

    /// Check if this is a directory
    pub fn is_directory(&self) -> bool {
        (self.attr & ATTR_DIRECTORY) != 0
    }

    /// Check if this is a file
    pub fn is_file(&self) -> bool {
        !self.is_directory() && !self.is_volume_id() && !self.is_lfn()
    }

    /// Check if this is a volume ID
    pub fn is_volume_id(&self) -> bool {
        (self.attr & ATTR_VOLUME_ID) != 0
    }

    /// Check if this is a long filename entry
    pub fn is_lfn(&self) -> bool {
        (self.attr & ATTR_LFN) == ATTR_LFN
    }

    /// Check if this is a free entry
    pub fn is_free(&self) -> bool {
        self.name[0] == 0x00 || self.name[0] == 0xE5
    }

    /// Check if this is the end of directory marker
    pub fn is_end(&self) -> bool {
        self.name[0] == 0x00
    }

    /// Get the short name as a string
    pub fn short_name(&self) -> heapless::String<12> {
        let mut s = heapless::String::new();

        // Add name part
        self.name.iter().take_while(|&&c| c != 0x20).for_each(|&c| {
            let _ = s.push(c as char);
        });

        // Check if there's an extension
        if self.ext[0] != 0x20 {
            let _ = s.push('.');
            self.ext.iter().take_while(|&&c| c != 0x20).for_each(|&c| {
                let _ = s.push(c as char);
            });
        }

        s
    }

    /// Check if this entry matches a short name (case-insensitive)
    pub fn matches_name(&self, name: &str) -> bool {
        let entry_name = self.short_name();
        entry_name.len() == name.len()
            && entry_name
                .bytes()
                .zip(name.bytes())
                .all(|(a, b)| a.eq_ignore_ascii_case(&b))
    }

    /// Get the file size in bytes
    pub fn file_size(&self) -> u32 {
        self.file_size
    }
}

/// Directory entry attributes
const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_HIDDEN: u8 = 0x02;
const ATTR_SYSTEM: u8 = 0x04;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_LFN: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

/// Maximum length of a long filename we support (255 chars as per VFAT spec)
const MAX_LFN_LENGTH: usize = 255;

/// Long File Name (LFN) entry structure
///
/// LFN entries store up to 13 UTF-16 characters each and precede the 8.3 entry.
/// They are stored in reverse order (last part first).
#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct LfnEntry {
    /// Sequence number (0x40 | n for last, n for others)
    seq: u8,
    /// Characters 1-5 (UTF-16LE)
    name1: [u8; 10],
    /// Attributes (always 0x0F)
    attr: u8,
    /// Type (always 0x00)
    entry_type: u8,
    /// Checksum of 8.3 name
    checksum: u8,
    /// Characters 6-11 (UTF-16LE)
    name2: [u8; 12],
    /// First cluster (always 0)
    first_cluster: u16,
    /// Characters 12-13 (UTF-16LE)
    name3: [u8; 4],
}

impl LfnEntry {
    /// Check if this is the last (first encountered) LFN entry
    fn is_last(&self) -> bool {
        (self.seq & 0x40) != 0
    }

    /// Get the sequence number (1-based, without the last flag)
    fn sequence_number(&self) -> u8 {
        self.seq & 0x1F
    }

    /// Extract the 13 UTF-16 characters from this entry into a buffer
    /// Returns the number of valid characters (may be less than 13 if null-terminated)
    fn extract_chars(&self, out: &mut [u16; 13]) -> usize {
        self.name1
            .as_chunks::<2>()
            .0
            .iter()
            .chain(self.name2.as_chunks::<2>().0.iter())
            .chain(self.name3.as_chunks::<2>().0.iter())
            .map(|pair| u16::from_le_bytes(*pair))
            .take_while(|&ch| ch != 0x0000 && ch != 0xFFFF)
            .zip(out.iter_mut())
            .map(|(ch, slot)| *slot = ch)
            .count()
    }
}

/// Buffer for accumulating Long File Name characters
struct LfnBuffer {
    /// UTF-16 characters (stored in correct order after reconstruction)
    chars: [u16; MAX_LFN_LENGTH],
    /// Number of valid characters
    len: usize,
    /// Whether we're currently collecting an LFN
    active: bool,
    /// Expected next sequence number
    expected_seq: u8,
}

impl LfnBuffer {
    const fn new() -> Self {
        Self {
            chars: [0; MAX_LFN_LENGTH],
            len: 0,
            active: false,
            expected_seq: 0,
        }
    }

    /// Reset the buffer
    fn reset(&mut self) {
        self.len = 0;
        self.active = false;
        self.expected_seq = 0;
    }

    /// Process an LFN entry
    fn process_lfn(&mut self, entry: &LfnEntry) {
        let seq = entry.sequence_number();

        if entry.is_last() {
            // Start of a new LFN sequence (entries are in reverse order)
            self.reset();
            self.active = true;
            self.expected_seq = seq;
        } else if !self.active || seq != self.expected_seq - 1 {
            // Sequence broken, reset
            self.reset();
            return;
        }

        self.expected_seq = seq;

        // Extract characters from this entry
        let mut chars = [0u16; 13];
        let char_count = entry.extract_chars(&mut chars);

        // Calculate position in final string (seq is 1-based)
        let start_pos = (seq as usize - 1) * 13;
        let end_pos = start_pos + char_count;

        if end_pos <= MAX_LFN_LENGTH {
            self.chars[start_pos..end_pos].copy_from_slice(&chars[..char_count]);
            if end_pos > self.len {
                self.len = end_pos;
            }
        }
    }

    /// Check if the accumulated LFN matches a name (case-insensitive)
    fn matches(&self, name: &str) -> bool {
        if !self.active || self.len == 0 {
            return false;
        }

        // Compare UTF-16 LFN with UTF-8 name (case-insensitive)
        let mut lfn_idx = 0;
        for ch in name.chars() {
            if lfn_idx >= self.len {
                return false;
            }

            let lfn_ch = self.chars[lfn_idx];
            // Simple ASCII case-insensitive comparison
            // For full Unicode support, we'd need more complex normalization
            let matches = if lfn_ch < 128 && ch.is_ascii() {
                (lfn_ch as u8 as char).eq_ignore_ascii_case(&ch)
            } else {
                lfn_ch == ch as u16
            };

            if !matches {
                return false;
            }
            lfn_idx += 1;
        }

        // Check that we consumed the entire LFN
        lfn_idx == self.len
    }
}

/// FAT filesystem type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

/// FAT filesystem error
#[derive(Debug)]
pub enum FatError {
    /// Invalid BPB
    InvalidBpb,
    /// Read error
    ReadError,
    /// Not a FAT filesystem
    NotFat,
    /// File not found
    NotFound,
    /// Not a file
    NotAFile,
    /// Not a directory
    NotADirectory,
    /// End of file
    EndOfFile,
    /// Invalid cluster
    InvalidCluster,
    /// Buffer too small
    BufferTooSmall,
    /// Mutation is only implemented for FAT32
    ReadOnly,
    /// Block-device write failed
    WriteError,
    /// Entry already exists
    AlreadyExists,
    /// Directory is not empty
    DirectoryNotEmpty,
    /// Invalid filename
    InvalidName,
    /// No free clusters or directory slots
    NoSpace,
}

impl core::fmt::Display for FatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FatError::InvalidBpb => write!(f, "invalid BPB"),
            FatError::ReadError => write!(f, "read error"),
            FatError::NotFat => write!(f, "not a FAT filesystem"),
            FatError::NotFound => write!(f, "file not found"),
            FatError::NotAFile => write!(f, "not a file"),
            FatError::NotADirectory => write!(f, "not a directory"),
            FatError::EndOfFile => write!(f, "end of file"),
            FatError::InvalidCluster => write!(f, "invalid cluster"),
            FatError::BufferTooSmall => write!(f, "buffer too small"),
            FatError::ReadOnly => write!(f, "read-only FAT filesystem"),
            FatError::WriteError => write!(f, "write error"),
            FatError::AlreadyExists => write!(f, "entry already exists"),
            FatError::DirectoryNotEmpty => write!(f, "directory not empty"),
            FatError::InvalidName => write!(f, "invalid filename"),
            FatError::NoSpace => write!(f, "filesystem full"),
        }
    }
}

/// FAT filesystem instance
pub struct FatFilesystem<'a> {
    /// Block device
    device: &'a mut dyn BlockDevice,
    /// First sector of partition
    partition_start: u64,
    /// FAT type
    fat_type: FatType,
    /// Bytes per sector (from FAT BPB)
    bytes_per_sector: u16,
    /// Device block size (for buffer allocation)
    device_block_size: u32,
    /// Sectors per cluster
    sectors_per_cluster: u8,
    /// First FAT sector (relative to partition start)
    fat_start: u32,
    /// Number of FAT copies
    num_fats: u8,
    /// Sectors occupied by one FAT copy
    sectors_per_fat: u32,
    /// First data sector (relative to partition start)
    data_start: u32,
    /// Root directory first cluster (FAT32) or sector count (FAT12/16)
    root_cluster: u32,
    /// Root directory sector start (FAT12/16 only)
    root_dir_start: u32,
    /// Root directory sector count (FAT12/16 only)
    root_dir_sectors: u32,
    /// Total data clusters
    data_clusters: u32,
    /// Cached FAT block for faster chain traversal
    fat_block_cache: [u8; MAX_BLOCK_SIZE],
    /// Block number currently in cache (u64::MAX = invalid)
    fat_block_cached: u64,
}

impl<'a> FatFilesystem<'a> {
    /// Create a new FAT filesystem instance
    pub fn new(device: &'a mut dyn BlockDevice, partition_start: u64) -> Result<Self, FatError> {
        // Use device's actual block size for reading
        let info = device.info();
        let block_size = (info.block_size as usize).min(MAX_BLOCK_SIZE);
        let mut buffer = [0u8; MAX_BLOCK_SIZE];

        // Read the boot sector
        device
            .read_block(partition_start, &mut buffer[..block_size])
            .map_err(|_| FatError::ReadError)?;

        // Parse BPB using zerocopy
        let bpb = BiosParameterBlock::read_from_prefix(&buffer)
            .map_err(|_| FatError::InvalidBpb)?
            .0;

        // With zerocopy's Unaligned derive, we can safely access packed fields
        let bpb_bytes_per_sector = bpb.bytes_per_sector;
        let bpb_sectors_per_cluster = bpb.sectors_per_cluster;
        let bpb_num_fats = bpb.num_fats;
        let bpb_reserved_sectors = bpb.reserved_sectors;

        // Validate BPB with strict checks
        // bytes_per_sector must be 512, 1024, 2048, or 4096
        let valid_sector_sizes = [512u16, 1024, 2048, 4096];
        if !valid_sector_sizes.contains(&bpb_bytes_per_sector) {
            log::debug!(
                "Invalid bytes_per_sector: {} (expected 512/1024/2048/4096)",
                bpb_bytes_per_sector
            );
            return Err(FatError::InvalidBpb);
        }

        // sectors_per_cluster must be a power of 2 between 1 and 128
        if bpb_sectors_per_cluster == 0
            || bpb_sectors_per_cluster > 128
            || !bpb_sectors_per_cluster.is_power_of_two()
        {
            log::debug!(
                "Invalid sectors_per_cluster: {} (expected power of 2, 1-128)",
                bpb_sectors_per_cluster
            );
            return Err(FatError::InvalidBpb);
        }

        // num_fats must be 1 or 2
        if bpb_num_fats == 0 || bpb_num_fats > 2 {
            log::debug!("Invalid num_fats: {} (expected 1 or 2)", bpb_num_fats);
            return Err(FatError::InvalidBpb);
        }

        // reserved_sectors must be at least 1 (boot sector)
        if bpb_reserved_sectors == 0 {
            log::debug!("Invalid reserved_sectors: 0 (expected >= 1)");
            return Err(FatError::InvalidBpb);
        }

        // Calculate key values
        let bytes_per_sector = bpb.bytes_per_sector;
        let sectors_per_cluster = bpb.sectors_per_cluster;
        let reserved_sectors = bpb.reserved_sectors as u32;
        let num_fats = bpb.num_fats as u32;
        let root_entry_count = bpb.root_entry_count as u32;

        // Root directory sectors (FAT12/16)
        let root_dir_sectors = (root_entry_count * 32).div_ceil(bytes_per_sector as u32);

        // Sectors per FAT
        let sectors_per_fat = if bpb.sectors_per_fat_16 != 0 {
            bpb.sectors_per_fat_16 as u32
        } else {
            // FAT32: read extended BPB using zerocopy
            let ebr = Fat32Ebr::read_from_prefix(&buffer[36..])
                .map_err(|_| FatError::InvalidBpb)?
                .0;
            ebr.sectors_per_fat_32
        };

        // Total sectors
        let total_sectors = if bpb.total_sectors_16 != 0 {
            bpb.total_sectors_16 as u32
        } else {
            bpb.total_sectors_32
        };

        // Calculate first data sector
        let fat_start = reserved_sectors;
        let root_dir_start = fat_start + (num_fats * sectors_per_fat);
        let data_start = root_dir_start + root_dir_sectors;

        // Calculate total data clusters (with underflow protection for malformed BPBs)
        let data_sectors = total_sectors
            .checked_sub(data_start)
            .ok_or(FatError::InvalidBpb)?;
        let data_clusters = data_sectors / sectors_per_cluster as u32;

        // Determine FAT type
        let fat_type = if data_clusters < 4085 {
            FatType::Fat12
        } else if data_clusters < 65525 {
            FatType::Fat16
        } else {
            FatType::Fat32
        };

        // Root cluster (FAT32 only)
        let root_cluster = if fat_type == FatType::Fat32 {
            // Already parsed ebr above, but re-read for clarity
            let ebr = Fat32Ebr::read_from_prefix(&buffer[36..])
                .map_err(|_| FatError::InvalidBpb)?
                .0;
            ebr.root_cluster
        } else {
            0
        };

        log::info!(
            "FAT filesystem: {:?}, {} clusters, {} bytes/cluster",
            fat_type,
            data_clusters,
            sectors_per_cluster as u32 * bytes_per_sector as u32
        );
        log::debug!(
            "FAT layout: bytes_per_sector={}, sectors_per_cluster={}, device_block_size={}",
            bytes_per_sector,
            sectors_per_cluster,
            block_size
        );
        log::debug!(
            "FAT layout: fat_start={}, root_dir_start={}, root_dir_sectors={}, data_start={}",
            fat_start,
            root_dir_start,
            root_dir_sectors,
            data_start
        );

        Ok(Self {
            device,
            partition_start,
            fat_type,
            bytes_per_sector,
            device_block_size: block_size as u32,
            sectors_per_cluster,
            fat_start,
            num_fats: bpb_num_fats,
            sectors_per_fat,
            data_start,
            root_cluster,
            root_dir_start,
            root_dir_sectors,
            data_clusters,
            fat_block_cache: [0u8; MAX_BLOCK_SIZE],
            fat_block_cached: u64::MAX, // Invalid, forces first read
        })
    }

    /// Get the device block and byte offset for a cluster
    ///
    /// # Returns
    /// Returns `None` if the cluster number is invalid (< 2 or beyond data region)
    /// Otherwise returns `Some((device_block, offset_in_block))`
    fn cluster_to_device_block(&self, cluster: u32) -> Option<(u64, usize)> {
        // Clusters 0 and 1 are reserved in FAT
        if cluster < 2 {
            return None;
        }
        // Check cluster is within valid range
        if cluster - 2 >= self.data_clusters {
            return None;
        }
        // Calculate FAT sector with overflow check
        let cluster_offset = (cluster - 2).checked_mul(self.sectors_per_cluster as u32)?;
        let fat_sector = self.data_start.checked_add(cluster_offset)?;
        // Translate to device block and offset
        let (device_block, offset) = self.fat_sector_to_device_block(fat_sector as u64);
        Some((self.partition_start.checked_add(device_block)?, offset))
    }

    /// Read the next cluster from the FAT (with single-block caching)
    fn next_cluster(&mut self, cluster: u32) -> Result<Option<u32>, FatError> {
        // Validate cluster number is in valid range (clusters 0 and 1 are reserved)
        if cluster < 2 {
            return Err(FatError::InvalidCluster);
        }

        // Use device block size for buffer to avoid overflow
        let device_block_size = self.device_block_size as usize;
        let bytes_per_sector = self.bytes_per_sector as u64;

        // Calculate byte offset of FAT entry from partition start
        let entry_byte_offset = match self.fat_type {
            FatType::Fat12 => {
                // offset = cluster * 1.5
                let fat_byte_offset = (cluster as u64 * 3) / 2;
                (self.fat_start as u64 * bytes_per_sector) + fat_byte_offset
            }
            FatType::Fat16 => {
                let fat_byte_offset = cluster as u64 * 2;
                (self.fat_start as u64 * bytes_per_sector) + fat_byte_offset
            }
            FatType::Fat32 => {
                let fat_byte_offset = cluster as u64 * 4;
                (self.fat_start as u64 * bytes_per_sector) + fat_byte_offset
            }
        };

        // Translate byte offset to device block
        let device_block = entry_byte_offset / device_block_size as u64;
        let offset_in_block = (entry_byte_offset % device_block_size as u64) as usize;

        // Check if we need to read this block (cache miss)
        let abs_block = self.partition_start + device_block;
        if self.fat_block_cached != abs_block {
            self.device
                .read_block(abs_block, &mut self.fat_block_cache[..device_block_size])
                .map_err(|_| FatError::ReadError)?;
            self.fat_block_cached = abs_block;
        }

        let next = match self.fat_type {
            FatType::Fat12 => {
                let entry = if offset_in_block + 1 < device_block_size {
                    self.fat_block_cache[offset_in_block] as u16
                        | ((self.fat_block_cache[offset_in_block + 1] as u16) << 8)
                } else {
                    // Entry spans device blocks - need to read next block
                    let low = self.fat_block_cache[offset_in_block] as u16;
                    // Read next block (invalidates cache for current block)
                    self.device
                        .read_block(
                            self.partition_start + device_block + 1,
                            &mut self.fat_block_cache[..device_block_size],
                        )
                        .map_err(|_| FatError::ReadError)?;
                    self.fat_block_cached = self.partition_start + device_block + 1;
                    low | ((self.fat_block_cache[0] as u16) << 8)
                };

                let val = if cluster & 1 != 0 {
                    entry >> 4
                } else {
                    entry & 0x0FFF
                };

                if val >= 0x0FF8 {
                    None
                } else if val >= 0x0FF0 {
                    return Err(FatError::InvalidCluster);
                } else {
                    Some(val as u32)
                }
            }
            FatType::Fat16 => {
                let entry = if offset_in_block + 1 < device_block_size {
                    u16::from_le_bytes([
                        self.fat_block_cache[offset_in_block],
                        self.fat_block_cache[offset_in_block + 1],
                    ])
                } else {
                    // Entry spans device blocks - need to read next block
                    let low = self.fat_block_cache[offset_in_block];
                    self.device
                        .read_block(
                            self.partition_start + device_block + 1,
                            &mut self.fat_block_cache[..device_block_size],
                        )
                        .map_err(|_| FatError::ReadError)?;
                    self.fat_block_cached = self.partition_start + device_block + 1;
                    u16::from_le_bytes([low, self.fat_block_cache[0]])
                };

                if entry >= 0xFFF8 {
                    None
                } else if entry >= 0xFFF0 {
                    return Err(FatError::InvalidCluster);
                } else {
                    Some(entry as u32)
                }
            }
            FatType::Fat32 => {
                let entry = if offset_in_block + 3 < device_block_size {
                    u32::from_le_bytes([
                        self.fat_block_cache[offset_in_block],
                        self.fat_block_cache[offset_in_block + 1],
                        self.fat_block_cache[offset_in_block + 2],
                        self.fat_block_cache[offset_in_block + 3],
                    ])
                } else {
                    // Entry spans device blocks - read bytes from current and next block
                    let bytes_in_current = device_block_size - offset_in_block;
                    let mut entry_bytes = [0u8; 4];
                    entry_bytes[..bytes_in_current].copy_from_slice(
                        &self.fat_block_cache[offset_in_block..offset_in_block + bytes_in_current],
                    );
                    self.device
                        .read_block(
                            self.partition_start + device_block + 1,
                            &mut self.fat_block_cache[..device_block_size],
                        )
                        .map_err(|_| FatError::ReadError)?;
                    self.fat_block_cached = self.partition_start + device_block + 1;
                    entry_bytes[bytes_in_current..4]
                        .copy_from_slice(&self.fat_block_cache[..4 - bytes_in_current]);
                    u32::from_le_bytes(entry_bytes)
                } & 0x0FFFFFFF;

                if entry >= 0x0FFFFFF8 {
                    None
                } else if entry >= 0x0FFFFFF0 {
                    return Err(FatError::InvalidCluster);
                } else {
                    Some(entry)
                }
            }
        };

        Ok(next)
    }

    /// Read a cluster into a buffer
    fn read_cluster(&mut self, cluster: u32, buffer: &mut [u8]) -> Result<(), FatError> {
        let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
        if buffer.len() < cluster_size {
            return Err(FatError::BufferTooSmall);
        }

        let (start_device_block, start_offset) = self
            .cluster_to_device_block(cluster)
            .ok_or(FatError::InvalidCluster)?;

        let device_block_size = self.device_block_size as usize;

        // Unaligned clusters need per-block copying so preceding bytes are skipped.
        if cluster_size <= device_block_size || start_offset != 0 {
            // Cluster fits within one or more device blocks
            let mut temp_buffer = [0u8; MAX_BLOCK_SIZE];
            let mut bytes_copied = 0usize;
            let mut current_block = start_device_block;
            let mut current_offset = start_offset;

            while bytes_copied < cluster_size {
                self.device
                    .read_block(current_block, &mut temp_buffer[..device_block_size])
                    .map_err(|_| FatError::ReadError)?;

                let bytes_available = device_block_size - current_offset;
                let bytes_to_copy = bytes_available.min(cluster_size - bytes_copied);
                buffer[bytes_copied..bytes_copied + bytes_to_copy]
                    .copy_from_slice(&temp_buffer[current_offset..current_offset + bytes_to_copy]);

                bytes_copied += bytes_to_copy;
                current_block += 1;
                current_offset = 0; // Subsequent blocks start at offset 0
            }
        } else {
            // Cluster spans multiple device blocks (cluster_size > device_block_size)
            // Read all blocks in a single call for performance — avoids per-block
            // USB BOT overhead (CBW + data + CSW per 512-byte sector).
            let device_blocks_per_cluster = cluster_size.div_ceil(device_block_size);

            self.device
                .read_blocks(
                    start_device_block,
                    device_blocks_per_cluster as u32,
                    &mut buffer[..cluster_size],
                )
                .map_err(|_| FatError::ReadError)?;
        }
        Ok(())
    }

    /// Read a contiguous run of clusters directly into a buffer
    ///
    /// Given a starting cluster and a count of physically-contiguous clusters,
    /// issues a single multi-block read to the device. This amortizes USB BOT
    /// overhead (CBW + CSW) across many clusters instead of paying it per-cluster.
    fn read_contiguous_clusters(
        &mut self,
        start_cluster: u32,
        count: u32,
        buffer: &mut [u8],
    ) -> Result<(), FatError> {
        let sectors_per_cluster = self.sectors_per_cluster as u32;
        let device_block_size = self.device_block_size as usize;
        let cluster_size = sectors_per_cluster as usize * self.bytes_per_sector as usize;
        let total_bytes = count as usize * cluster_size;

        if buffer.len() < total_bytes {
            return Err(FatError::BufferTooSmall);
        }

        let (start_device_block, start_offset) = self
            .cluster_to_device_block(start_cluster)
            .ok_or(FatError::InvalidCluster)?;

        if start_offset != 0 {
            // Cluster not aligned to device block — fall back to per-cluster reads
            for i in 0..count {
                let offset = i as usize * cluster_size;
                self.read_cluster(
                    start_cluster + i,
                    &mut buffer[offset..offset + cluster_size],
                )?;
            }
            return Ok(());
        }

        // Read the device-block-aligned portion in a single multi-block read.
        // When cluster_size < device_block_size, the total bytes may not fill
        // a whole number of device blocks. We can only pass a buffer that is
        // at least `device_blocks * device_block_size` bytes to read_blocks,
        // so read the aligned prefix in bulk and the trailing clusters one by
        // one (read_cluster handles sub-block reads via a temp buffer).
        let aligned_bytes = (total_bytes / device_block_size) * device_block_size;
        let aligned_device_blocks = (aligned_bytes / device_block_size) as u32;

        if aligned_device_blocks > 0 {
            self.device
                .read_blocks(
                    start_device_block,
                    aligned_device_blocks,
                    &mut buffer[..aligned_bytes],
                )
                .map_err(|_| FatError::ReadError)?;
        }

        // Read remaining clusters that don't fill a complete device block
        if aligned_bytes < total_bytes {
            let first_tail_cluster = (aligned_bytes / cluster_size) as u32;
            for i in first_tail_cluster..count {
                let offset = i as usize * cluster_size;
                self.read_cluster(
                    start_cluster + i,
                    &mut buffer[offset..offset + cluster_size],
                )?;
            }
        }

        Ok(())
    }

    /// Find a file by path
    pub fn find_file(&mut self, path: &str) -> Result<DirectoryEntry, FatError> {
        let path = path.trim_start_matches('/').trim_start_matches('\\');
        log::debug!("FAT: looking for path '{}'", path);

        let mut current_dir_cluster = if self.fat_type == FatType::Fat32 {
            self.root_cluster
        } else {
            0 // Special case for FAT12/16 root directory
        };

        let parts: heapless::Vec<&str, 16> =
            path.split(['/', '\\']).filter(|s| !s.is_empty()).collect();

        log::debug!(
            "FAT: path has {} components, starting at cluster {}",
            parts.len(),
            current_dir_cluster
        );

        for (i, part) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;

            let entry = self.find_in_directory(current_dir_cluster, part)?;

            if is_last {
                return Ok(entry);
            }

            if !entry.is_directory() {
                return Err(FatError::NotADirectory);
            }

            current_dir_cluster = entry.first_cluster();
        }

        Err(FatError::NotFound)
    }

    /// Translate a FAT sector offset to a device block and byte offset within that block
    ///
    /// When the device block size differs from FAT's bytes_per_sector,
    /// we need to translate FAT sector numbers to device block numbers and
    /// calculate the byte offset within the device block.
    ///
    /// # Returns
    /// (device_block, offset_in_block) tuple
    fn fat_sector_to_device_block(&self, fat_sector: u64) -> (u64, usize) {
        let bytes_per_sector = self.bytes_per_sector as u64;
        let device_block_size = self.device_block_size as u64;

        if bytes_per_sector == device_block_size {
            (fat_sector, 0)
        } else {
            // Convert FAT sector to byte offset, then to device block and offset
            let byte_offset = fat_sector * bytes_per_sector;
            let device_block = byte_offset / device_block_size;
            let offset_in_block = (byte_offset % device_block_size) as usize;
            (device_block, offset_in_block)
        }
    }

    /// Iterate over all directory entries in a directory, calling `visitor` for each
    /// non-free, non-LFN, non-volume-label entry.
    ///
    /// The visitor receives `(&DirectoryEntry, &LfnBuffer)` and returns
    /// `ControlFlow::Continue(())` to keep iterating or `ControlFlow::Break(value)`
    /// to stop early with a result.
    ///
    /// Handles both FAT12/16 fixed root directories and cluster-chain directories.
    fn for_each_dir_entry<T>(
        &mut self,
        cluster: u32,
        mut visitor: impl FnMut(&DirectoryEntry, &LfnBuffer) -> core::ops::ControlFlow<T>,
    ) -> Result<core::ops::ControlFlow<T>, FatError> {
        let mut buffer = [0u8; 65536]; // Max cluster size
        let mut lfn_buffer = LfnBuffer::new();

        if cluster == 0 && self.fat_type != FatType::Fat32 {
            // FAT12/16 root directory (fixed location)
            let root_dir_bytes = self.root_dir_sectors as usize * self.bytes_per_sector as usize;
            let device_block_size = self.device_block_size as usize;
            let root_dir_byte_start = self.root_dir_start as usize * self.bytes_per_sector as usize;
            let mut bytes_processed = 0usize;

            while bytes_processed < root_dir_bytes {
                let current_byte_pos = root_dir_byte_start + bytes_processed;
                let device_block = current_byte_pos / device_block_size;
                let offset_in_block = current_byte_pos % device_block_size;

                self.device
                    .read_block(
                        self.partition_start + device_block as u64,
                        &mut buffer[..device_block_size],
                    )
                    .map_err(|_| FatError::ReadError)?;

                let mut pos = offset_in_block;
                while pos + 32 <= device_block_size && bytes_processed < root_dir_bytes {
                    let entry = match DirectoryEntry::read_from_prefix(&buffer[pos..]) {
                        Ok((e, _)) => e,
                        Err(_) => break,
                    };

                    if entry.is_end() {
                        return Ok(core::ops::ControlFlow::Continue(()));
                    }
                    if entry.is_free() {
                        lfn_buffer.reset();
                        pos += 32;
                        bytes_processed += 32;
                        continue;
                    }
                    if entry.is_lfn() {
                        if let Ok((lfn_entry, _)) = LfnEntry::read_from_prefix(&buffer[pos..]) {
                            lfn_buffer.process_lfn(&lfn_entry);
                        }
                        pos += 32;
                        bytes_processed += 32;
                        continue;
                    }
                    if entry.is_volume_id() {
                        lfn_buffer.reset();
                        pos += 32;
                        bytes_processed += 32;
                        continue;
                    }

                    if let core::ops::ControlFlow::Break(val) = visitor(&entry, &lfn_buffer) {
                        return Ok(core::ops::ControlFlow::Break(val));
                    }

                    lfn_buffer.reset();
                    pos += 32;
                    bytes_processed += 32;
                }

                if pos == offset_in_block {
                    bytes_processed = (device_block + 1) * device_block_size - root_dir_byte_start;
                }
            }
        } else {
            // Cluster-chain directory
            let mut current_cluster = cluster;
            let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
            let entries_per_cluster = cluster_size / 32;

            loop {
                self.read_cluster(current_cluster, &mut buffer[..cluster_size])?;

                for i in 0..entries_per_cluster {
                    let offset = i * 32;
                    let entry = match DirectoryEntry::read_from_prefix(&buffer[offset..]) {
                        Ok((e, _)) => e,
                        Err(_) => break,
                    };

                    if entry.is_end() {
                        return Ok(core::ops::ControlFlow::Continue(()));
                    }
                    if entry.is_free() {
                        lfn_buffer.reset();
                        continue;
                    }
                    if entry.is_lfn() {
                        if let Ok((lfn_entry, _)) = LfnEntry::read_from_prefix(&buffer[offset..]) {
                            lfn_buffer.process_lfn(&lfn_entry);
                        }
                        continue;
                    }
                    if entry.is_volume_id() {
                        lfn_buffer.reset();
                        continue;
                    }

                    if let core::ops::ControlFlow::Break(val) = visitor(&entry, &lfn_buffer) {
                        return Ok(core::ops::ControlFlow::Break(val));
                    }

                    lfn_buffer.reset();
                }

                match self.next_cluster(current_cluster)? {
                    Some(next) => current_cluster = next,
                    None => break,
                }
            }
        }

        Ok(core::ops::ControlFlow::Continue(()))
    }

    /// Resolve a directory path to its starting cluster number.
    ///
    /// Returns 0 for FAT12/16 root directories, `root_cluster` for FAT32 root,
    /// or the first cluster of the named directory.
    fn resolve_dir_cluster(&mut self, dir_path: &str) -> Result<u32, FatError> {
        if dir_path.is_empty() || dir_path == "\\" || dir_path == "/" {
            if self.fat_type == FatType::Fat32 {
                Ok(self.root_cluster)
            } else {
                Ok(0)
            }
        } else {
            let dir_entry = self.find_file(dir_path)?;
            if !dir_entry.is_directory() {
                return Err(FatError::NotADirectory);
            }
            Ok(dir_entry.first_cluster())
        }
    }

    /// Find an entry in a directory
    fn find_in_directory(&mut self, cluster: u32, name: &str) -> Result<DirectoryEntry, FatError> {
        use core::ops::ControlFlow;

        match self.for_each_dir_entry(cluster, |entry, lfn_buf| {
            if lfn_buf.matches(name) || entry.matches_name(name) {
                ControlFlow::Break(*entry)
            } else {
                ControlFlow::Continue(())
            }
        })? {
            ControlFlow::Break(entry) => Ok(entry),
            ControlFlow::Continue(()) => Err(FatError::NotFound),
        }
    }

    /// Read a file into a buffer
    pub fn read_file(
        &mut self,
        entry: &DirectoryEntry,
        offset: u32,
        buffer: &mut [u8],
    ) -> Result<usize, FatError> {
        if entry.is_directory() {
            return Err(FatError::NotAFile);
        }

        let file_size = entry.file_size;
        if offset >= file_size {
            return Ok(0);
        }

        let bytes_to_read = core::cmp::min(buffer.len() as u32, file_size - offset) as usize;
        let cluster_size = self.sectors_per_cluster as u32 * self.bytes_per_sector as u32;

        let mut cluster = entry.first_cluster();
        let skip_clusters = offset / cluster_size;
        let cluster_offset = (offset % cluster_size) as usize;

        // Skip to starting cluster
        for _ in 0..skip_clusters {
            match self.next_cluster(cluster)? {
                Some(next) => cluster = next,
                None => return Ok(0),
            }
        }

        let mut cluster_buffer = [0u8; 65536]; // Max cluster size (128 sectors * 512 bytes)
        let mut bytes_read = 0;

        // Read first (potentially partial) cluster
        if cluster_offset > 0 || bytes_to_read < cluster_size as usize {
            self.read_cluster(cluster, &mut cluster_buffer[..cluster_size as usize])?;

            let copy_len = core::cmp::min(bytes_to_read, cluster_size as usize - cluster_offset);
            buffer[..copy_len]
                .copy_from_slice(&cluster_buffer[cluster_offset..cluster_offset + copy_len]);
            bytes_read += copy_len;

            match self.next_cluster(cluster)? {
                Some(next) => cluster = next,
                None => return Ok(bytes_read),
            }
        }

        // Read full clusters — coalesce contiguous runs for performance.
        // Instead of reading one cluster at a time (each requiring a separate USB
        // BOT transaction), detect runs of physically-contiguous clusters and read
        // them in a single multi-block device call.
        while bytes_read + cluster_size as usize <= bytes_to_read {
            let run_start = cluster;
            let mut run_len: u32 = 1;

            // Follow cluster chain, counting contiguous clusters
            let mut current = cluster;
            loop {
                // Check if we have enough remaining data for another cluster in this run
                if bytes_read + (run_len as usize + 1) * cluster_size as usize > bytes_to_read {
                    break;
                }
                match self.next_cluster(current)? {
                    Some(next) if next == current + 1 => {
                        run_len += 1;
                        current = next;
                    }
                    _ => break,
                }
            }

            // Read entire contiguous run in one call
            let run_bytes = run_len as usize * cluster_size as usize;
            self.read_contiguous_clusters(
                run_start,
                run_len,
                &mut buffer[bytes_read..bytes_read + run_bytes],
            )?;
            bytes_read += run_bytes;

            // Advance to the next cluster after the run
            match self.next_cluster(current)? {
                Some(next) => cluster = next,
                None => return Ok(bytes_read),
            }
        }

        // Read last partial cluster
        if bytes_read < bytes_to_read {
            self.read_cluster(cluster, &mut cluster_buffer[..cluster_size as usize])?;
            let remaining = bytes_to_read - bytes_read;
            buffer[bytes_read..bytes_read + remaining]
                .copy_from_slice(&cluster_buffer[..remaining]);
            bytes_read += remaining;
        }

        Ok(bytes_read)
    }

    fn require_fat32(&self) -> Result<(), FatError> {
        if self.fat_type == FatType::Fat32 {
            Ok(())
        } else {
            Err(FatError::ReadOnly)
        }
    }

    fn partition_read(&mut self, byte_offset: u64, output: &mut [u8]) -> Result<(), FatError> {
        let block_size = self.device_block_size as usize;
        let mut block = [0u8; MAX_BLOCK_SIZE];
        let mut done = 0;
        while done < output.len() {
            let position = byte_offset + done as u64;
            let lba = self.partition_start + position / block_size as u64;
            let within = position as usize % block_size;
            self.device
                .read_block(lba, &mut block[..block_size])
                .map_err(|_| FatError::ReadError)?;
            let count = (block_size - within).min(output.len() - done);
            output[done..done + count].copy_from_slice(&block[within..within + count]);
            done += count;
        }
        Ok(())
    }

    fn partition_write(&mut self, byte_offset: u64, input: &[u8]) -> Result<(), FatError> {
        self.require_fat32()?;
        let block_size = self.device_block_size as usize;
        let mut block = [0u8; MAX_BLOCK_SIZE];
        let mut done = 0;
        while done < input.len() {
            let position = byte_offset + done as u64;
            let lba = self.partition_start + position / block_size as u64;
            let within = position as usize % block_size;
            let count = (block_size - within).min(input.len() - done);
            if within != 0 || count != block_size {
                self.device
                    .read_block(lba, &mut block[..block_size])
                    .map_err(|_| FatError::ReadError)?;
            }
            block[within..within + count].copy_from_slice(&input[done..done + count]);
            self.device
                .write_block(lba, &block[..block_size])
                .map_err(|_| FatError::WriteError)?;
            done += count;
        }
        self.fat_block_cached = u64::MAX;
        Ok(())
    }

    fn cluster_byte_offset(&self, cluster: u32) -> Result<u64, FatError> {
        if cluster < 2 || cluster - 2 >= self.data_clusters {
            return Err(FatError::InvalidCluster);
        }
        Ok(self.data_start as u64 * self.bytes_per_sector as u64
            + (cluster - 2) as u64 * self.sectors_per_cluster as u64 * self.bytes_per_sector as u64)
    }

    fn fat32_value(&mut self, cluster: u32) -> Result<u32, FatError> {
        self.require_fat32()?;
        let mut bytes = [0u8; 4];
        let offset = self.fat_start as u64 * self.bytes_per_sector as u64 + cluster as u64 * 4;
        self.partition_read(offset, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes) & 0x0fff_ffff)
    }

    fn set_fat32_value(&mut self, cluster: u32, value: u32) -> Result<(), FatError> {
        self.require_fat32()?;
        let copies = self.num_fats as usize;
        let mut offsets = [0u64; 2];
        let mut old_values = [0u32; 2];

        for copy in 0..copies {
            offsets[copy] = (self.fat_start + copy as u32 * self.sectors_per_fat) as u64
                * self.bytes_per_sector as u64
                + cluster as u64 * 4;
            let mut bytes = [0u8; 4];
            self.partition_read(offsets[copy], &mut bytes)?;
            old_values[copy] = u32::from_le_bytes(bytes);
        }

        for copy in 0..copies {
            let bytes = ((old_values[copy] & 0xf000_0000) | (value & 0x0fff_ffff)).to_le_bytes();
            if let Err(error) = self.partition_write(offsets[copy], &bytes) {
                for rollback in 0..copy {
                    let _ = self
                        .partition_write(offsets[rollback], &old_values[rollback].to_le_bytes());
                }
                return Err(error);
            }
        }
        Ok(())
    }

    /// Zero a whole cluster using a block-sized scratch buffer.
    ///
    /// Deliberately avoids a max-cluster-sized (64 KiB) stack buffer: this
    /// firmware runs on a small fixed stack and these helpers nest.
    fn zero_cluster(&mut self, cluster: u32) -> Result<(), FatError> {
        let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
        let base = self.cluster_byte_offset(cluster)?;
        let zero = [0u8; MAX_BLOCK_SIZE];
        for done in (0..cluster_size).step_by(MAX_BLOCK_SIZE) {
            let count = MAX_BLOCK_SIZE.min(cluster_size - done);
            self.partition_write(base + done as u64, &zero[..count])?;
        }
        Ok(())
    }

    fn allocate_cluster(&mut self) -> Result<u32, FatError> {
        self.require_fat32()?;
        let sector_size = self.bytes_per_sector as usize;
        let entries_per_sector = sector_size / 4;
        let mut sector = [0u8; MAX_BLOCK_SIZE];
        let cluster_limit = self.data_clusters + 2;
        let fat_offset = self.fat_start as u64 * self.bytes_per_sector as u64;

        for first_cluster in (0..cluster_limit).step_by(entries_per_sector) {
            self.partition_read(
                fat_offset + first_cluster as u64 * 4,
                &mut sector[..sector_size],
            )?;
            for index in 0..entries_per_sector {
                let cluster = first_cluster + index as u32;
                if cluster < 2 || cluster >= cluster_limit {
                    continue;
                }
                let offset = index * 4;
                let value = u32::from_le_bytes(
                    sector[offset..offset + 4]
                        .try_into()
                        .map_err(|_| FatError::ReadError)?,
                ) & 0x0fff_ffff;
                if value == 0 {
                    self.zero_cluster(cluster)?;
                    self.set_fat32_value(cluster, 0x0fff_ffff)?;
                    return Ok(cluster);
                }
            }
        }
        Err(FatError::NoSpace)
    }

    fn free_chain(&mut self, first: u32) -> Result<(), FatError> {
        let mut cluster = first;
        while cluster >= 2 {
            let next = self.fat32_value(cluster)?;
            self.set_fat32_value(cluster, 0)?;
            if !(2..0x0fff_fff8).contains(&next) {
                break;
            }
            cluster = next;
        }
        Ok(())
    }

    fn append_cluster(&mut self, last: u32) -> Result<u32, FatError> {
        let new = self.allocate_cluster()?;
        if let Err(error) = self.set_fat32_value(last, new) {
            let _ = self.set_fat32_value(new, 0);
            return Err(error);
        }
        Ok(new)
    }

    fn find_record_in_directory(
        &mut self,
        directory: u32,
        name: &str,
    ) -> Result<(DirectoryEntry, u64, u64), FatError> {
        let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
        let chunk = MAX_BLOCK_SIZE.min(cluster_size);
        let mut data = [0u8; MAX_BLOCK_SIZE];
        let mut cluster = directory;
        let mut lfn = LfnBuffer::new();
        let mut lfn_start = 0;
        loop {
            let base = self.cluster_byte_offset(cluster)?;
            for chunk_start in (0..cluster_size).step_by(chunk) {
                self.partition_read(base + chunk_start as u64, &mut data[..chunk])?;
                for (entry_index, raw) in data[..chunk].as_chunks::<32>().0.iter().enumerate() {
                    let position = base + (chunk_start + entry_index * 32) as u64;
                    let entry =
                        DirectoryEntry::read_from_bytes(raw).map_err(|_| FatError::ReadError)?;
                    if entry.is_end() {
                        return Err(FatError::NotFound);
                    }
                    if entry.is_free() {
                        lfn.reset();
                        continue;
                    }
                    if entry.is_lfn() {
                        if !lfn.active {
                            lfn_start = position;
                        }
                        let part =
                            LfnEntry::read_from_bytes(raw).map_err(|_| FatError::ReadError)?;
                        lfn.process_lfn(&part);
                        continue;
                    }
                    let start = if lfn.active { lfn_start } else { position };
                    if (lfn.matches(name) || entry.matches_name(name)) && !entry.is_volume_id() {
                        return Ok((entry, position, start));
                    }
                    lfn.reset();
                }
            }
            cluster = match self.next_cluster(cluster)? {
                Some(next) => next,
                None => return Err(FatError::NotFound),
            };
        }
    }

    fn split_parent<'p>(&mut self, path: &'p str) -> Result<(u32, &'p str), FatError> {
        let path = path.trim_matches(['/', '\\']);
        let (parent, name) = path
            .rsplit_once(['/', '\\'])
            .map_or(("", path), |(parent, name)| (parent, name));
        if name.is_empty() || name == "." || name == ".." {
            return Err(FatError::InvalidName);
        }
        Ok((self.resolve_dir_cluster(parent)?, name))
    }

    fn short_name_exists(&mut self, directory: u32, short: &[u8; 11]) -> Result<bool, FatError> {
        let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
        let chunk = MAX_BLOCK_SIZE.min(cluster_size);
        let mut data = [0u8; MAX_BLOCK_SIZE];
        let mut cluster = directory;
        loop {
            let base = self.cluster_byte_offset(cluster)?;
            for chunk_start in (0..cluster_size).step_by(chunk) {
                self.partition_read(base + chunk_start as u64, &mut data[..chunk])?;
                for raw in data[..chunk].as_chunks::<32>().0 {
                    if raw[0] == 0 {
                        return Ok(false);
                    }
                    if raw[0] != 0xe5 && raw[11] != ATTR_LFN && raw[..11] == short[..] {
                        return Ok(true);
                    }
                }
            }
            cluster = match self.next_cluster(cluster)? {
                Some(next) => next,
                None => return Ok(false),
            };
        }
    }

    fn make_short_name(
        &mut self,
        directory: u32,
        name: &str,
    ) -> Result<([u8; 11], bool), FatError> {
        let (stem, extension) = name.rsplit_once('.').unwrap_or((name, ""));
        let valid = !stem.is_empty()
            && stem.len() <= 8
            && extension.len() <= 3
            && stem
                .bytes()
                .chain(extension.bytes())
                .all(is_short_name_char);
        if valid {
            let mut short = [b' '; 11];
            for (slot, byte) in short[..8].iter_mut().zip(stem.bytes()) {
                *slot = byte.to_ascii_uppercase();
            }
            for (slot, byte) in short[8..].iter_mut().zip(extension.bytes()) {
                *slot = byte.to_ascii_uppercase();
            }
            if !self.short_name_exists(directory, &short)? {
                // FAT short-name lookup is case-insensitive; mixed-case 8.3
                // names do not require an LFN entry for correct resolution.
                return Ok((short, false));
            }
        }

        let cleaned: heapless::Vec<u8, 64> = stem
            .bytes()
            .filter(|byte| byte.is_ascii_alphanumeric())
            .map(|byte| byte.to_ascii_uppercase())
            .collect();
        if cleaned.is_empty() {
            return Err(FatError::InvalidName);
        }
        for number in 1u16..=9999 {
            let mut digits = [0u8; 4];
            let digit_count = decimal(number, &mut digits);
            let prefix_len = (7usize.saturating_sub(digit_count)).min(cleaned.len());
            let mut short = [b' '; 11];
            short[..prefix_len].copy_from_slice(&cleaned[..prefix_len]);
            short[prefix_len] = b'~';
            short[prefix_len + 1..prefix_len + 1 + digit_count]
                .copy_from_slice(&digits[..digit_count]);
            for (slot, byte) in short[8..].iter_mut().zip(extension.bytes().take(3)) {
                *slot = if is_short_name_char(byte) {
                    byte.to_ascii_uppercase()
                } else {
                    b'_'
                };
            }
            if !self.short_name_exists(directory, &short)? {
                return Ok((short, true));
            }
        }
        Err(FatError::NoSpace)
    }

    fn find_free_slots(&mut self, directory: u32, count: usize) -> Result<u64, FatError> {
        let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
        // A run of slots is written with contiguous byte offsets, so it must fit
        // inside a single cluster: clusters are not necessarily adjacent on disk.
        if count == 0 || count * 32 > cluster_size {
            return Err(FatError::NoSpace);
        }
        let chunk = MAX_BLOCK_SIZE.min(cluster_size);
        let mut data = [0u8; MAX_BLOCK_SIZE];
        let mut cluster = directory;
        loop {
            let base = self.cluster_byte_offset(cluster)?;
            let mut run = 0;
            for chunk_start in (0..cluster_size).step_by(chunk) {
                self.partition_read(base + chunk_start as u64, &mut data[..chunk])?;
                for (entry_index, raw) in data[..chunk].as_chunks::<32>().0.iter().enumerate() {
                    if raw[0] == 0 || raw[0] == 0xe5 {
                        run += 1;
                        if run == count {
                            let end = chunk_start + (entry_index + 1) * 32;
                            return Ok(base + (end - count * 32) as u64);
                        }
                    } else {
                        run = 0;
                    }
                }
            }
            match self.next_cluster(cluster)? {
                Some(next) => cluster = next,
                None => {
                    // Once a directory is extended, zero-valued end markers in
                    // the old tail must become deleted entries. Otherwise readers
                    // stop at the old marker and never follow the new FAT link.
                    for chunk_start in (0..cluster_size).step_by(chunk) {
                        self.partition_read(base + chunk_start as u64, &mut data[..chunk])?;
                        for (entry_index, raw) in
                            data[..chunk].as_chunks::<32>().0.iter().enumerate()
                        {
                            if raw[0] == 0 {
                                self.partition_write(
                                    base + (chunk_start + entry_index * 32) as u64,
                                    &[0xe5],
                                )?;
                            }
                        }
                    }
                    let new = self.append_cluster(cluster)?;
                    // `count * 32 <= cluster_size` was checked above, so the run
                    // fits in the freshly zeroed cluster.
                    return self.cluster_byte_offset(new);
                }
            }
        }
    }

    fn insert_entry(
        &mut self,
        directory: u32,
        name: &str,
        attributes: u8,
        first_cluster: u32,
    ) -> Result<DirectoryEntry, FatError> {
        if self.find_record_in_directory(directory, name).is_ok() {
            return Err(FatError::AlreadyExists);
        }
        let (short, needs_lfn) = self.make_short_name(directory, name)?;
        let utf16: heapless::Vec<u16, 255> = name.chars().map(|ch| ch as u16).collect();
        let lfn_count = if needs_lfn {
            utf16.len().div_ceil(13)
        } else {
            0
        };
        let start = self.find_free_slots(directory, lfn_count + 1)?;
        let checksum = lfn_checksum(&short);
        for disk_index in 0..lfn_count {
            let sequence = lfn_count - disk_index;
            let mut raw = [0xffu8; 32];
            raw[0] = sequence as u8 | if sequence == lfn_count { 0x40 } else { 0 };
            raw[11] = ATTR_LFN;
            raw[12] = 0;
            raw[13] = checksum;
            raw[26] = 0;
            raw[27] = 0;
            let first = (sequence - 1) * 13;
            let mut chars = [0xffffu16; 13];
            for (index, slot) in chars.iter_mut().enumerate() {
                if let Some(character) = utf16.get(first + index) {
                    *slot = *character;
                } else if first + index == utf16.len() {
                    *slot = 0;
                }
            }
            write_lfn_chars(&mut raw, &chars);
            self.partition_write(start + disk_index as u64 * 32, &raw)?;
        }
        let mut raw = [0u8; 32];
        raw[..11].copy_from_slice(&short);
        raw[11] = attributes;
        raw[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
        raw[26..28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
        self.partition_write(start + lfn_count as u64 * 32, &raw)?;
        DirectoryEntry::read_from_bytes(&raw).map_err(|_| FatError::WriteError)
    }

    pub fn create(&mut self, path: &str, directory: bool) -> Result<DirectoryEntry, FatError> {
        self.require_fat32()?;
        let (parent, name) = self.split_parent(path)?;
        if self.find_record_in_directory(parent, name).is_ok() {
            return Err(FatError::AlreadyExists);
        }
        let cluster = self.allocate_cluster()?;
        if directory {
            // `allocate_cluster` already zeroed the cluster, so only the two
            // leading records have to be written.
            let mut block = [0u8; 64];
            block[..11].fill(b' ');
            block[0] = b'.';
            block[11] = ATTR_DIRECTORY;
            block[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
            block[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
            block[32..43].fill(b' ');
            block[32] = b'.';
            block[33] = b'.';
            block[43] = ATTR_DIRECTORY;
            // Per the FAT specification, `..` records first cluster 0 when the
            // parent is the root directory.
            let parent_value = if parent == self.root_cluster {
                0
            } else {
                parent
            };
            block[52..54].copy_from_slice(&((parent_value >> 16) as u16).to_le_bytes());
            block[58..60].copy_from_slice(&(parent_value as u16).to_le_bytes());
            let offset = self.cluster_byte_offset(cluster)?;
            self.partition_write(offset, &block)?;
        }
        match self.insert_entry(
            parent,
            name,
            if directory { ATTR_DIRECTORY } else { 0 },
            cluster,
        ) {
            Ok(entry) => Ok(entry),
            Err(error) => {
                let _ = self.free_chain(cluster);
                Err(error)
            }
        }
    }

    fn update_record(
        &mut self,
        offset: u64,
        first_cluster: u32,
        size: u32,
    ) -> Result<(), FatError> {
        let mut raw = [0u8; 32];
        self.partition_read(offset, &mut raw)?;
        raw[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
        raw[26..28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
        raw[28..32].copy_from_slice(&size.to_le_bytes());
        self.partition_write(offset, &raw)
    }

    pub fn write_path(
        &mut self,
        path: &str,
        offset: u32,
        input: &[u8],
    ) -> Result<(u32, u32), FatError> {
        self.require_fat32()?;
        let (entry, record_offset, _) = self.find_record(path)?;
        if entry.is_directory() {
            return Err(FatError::NotAFile);
        }
        if input.is_empty() {
            return Ok((entry.file_size(), entry.first_cluster()));
        }
        let end = offset
            .checked_add(input.len() as u32)
            .ok_or(FatError::NoSpace)?;
        let cluster_size = self.sectors_per_cluster as u32 * self.bytes_per_sector as u32;
        let required = end.div_ceil(cluster_size);
        let mut first = entry.first_cluster();
        if first < 2 {
            first = self.allocate_cluster()?;
        }
        let mut cluster = first;
        let mut existing = 1;
        while let Some(next) = self.next_cluster(cluster)? {
            cluster = next;
            existing += 1;
        }
        while existing < required {
            cluster = self.append_cluster(cluster)?;
            existing += 1;
        }
        cluster = first;
        for _ in 0..offset / cluster_size {
            cluster = self
                .next_cluster(cluster)?
                .ok_or(FatError::InvalidCluster)?;
        }
        let mut within = (offset % cluster_size) as usize;
        let mut consumed = 0;
        while consumed < input.len() {
            // `partition_write` performs the block read-modify-write itself, so
            // no max-cluster-sized stack buffer is needed here.
            let base = self.cluster_byte_offset(cluster)?;
            let count = (cluster_size as usize - within).min(input.len() - consumed);
            self.partition_write(base + within as u64, &input[consumed..consumed + count])?;
            consumed += count;
            within = 0;
            if consumed < input.len() {
                cluster = self
                    .next_cluster(cluster)?
                    .ok_or(FatError::InvalidCluster)?;
            }
        }
        let size = entry.file_size().max(end);
        self.update_record(record_offset, first, size)?;
        Ok((size, first))
    }

    fn find_record(&mut self, path: &str) -> Result<(DirectoryEntry, u64, u64), FatError> {
        let (parent, name) = self.split_parent(path)?;
        self.find_record_in_directory(parent, name)
    }

    pub fn truncate_path(&mut self, path: &str, size: u32) -> Result<(), FatError> {
        self.require_fat32()?;
        let (entry, offset, _) = self.find_record(path)?;
        if entry.is_directory() {
            return Err(FatError::NotAFile);
        }
        if size >= entry.file_size() {
            return Ok(());
        }
        let first = entry.first_cluster();
        if size == 0 {
            if first >= 2 {
                self.free_chain(first)?;
            }
            return self.update_record(offset, 0, 0);
        }
        let cluster_size = self.sectors_per_cluster as u32 * self.bytes_per_sector as u32;
        let keep = size.div_ceil(cluster_size);
        let mut last = first;
        for _ in 1..keep {
            last = self.next_cluster(last)?.ok_or(FatError::InvalidCluster)?;
        }
        let tail = self.next_cluster(last)?;
        self.set_fat32_value(last, 0x0fff_ffff)?;
        if let Some(tail) = tail {
            self.free_chain(tail)?;
        }
        self.update_record(offset, first, size)
    }

    /// Mark a directory record run (optional LFN chain plus its short entry) as
    /// deleted.
    ///
    /// The run is walked through the directory's cluster chain rather than by
    /// bumping raw partition offsets: clusters need not be adjacent on disk, so
    /// an LFN chain straddling a cluster boundary would otherwise write `0xe5`
    /// into unrelated clusters.
    fn erase_entry_run(
        &mut self,
        directory: u32,
        first_offset: u64,
        short_offset: u64,
    ) -> Result<(), FatError> {
        let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
        let mut cluster = directory;
        let mut erasing = false;
        loop {
            let base = self.cluster_byte_offset(cluster)?;
            for offset in (0..cluster_size).step_by(32) {
                let position = base + offset as u64;
                if position == first_offset {
                    erasing = true;
                }
                if erasing {
                    self.partition_write(position, &[0xe5])?;
                    if position == short_offset {
                        return Ok(());
                    }
                }
            }
            cluster = self.next_cluster(cluster)?.ok_or(FatError::NotFound)?;
        }
    }

    pub fn delete_path(&mut self, path: &str) -> Result<(), FatError> {
        self.require_fat32()?;
        let (parent, name) = self.split_parent(path)?;
        let (entry, short_offset, first_offset) = self.find_record_in_directory(parent, name)?;
        if entry.is_directory() {
            let cluster = entry.first_cluster();
            let mut nonempty = false;
            let _ = self.for_each_dir_entry(cluster, |child, _| {
                let name = child.short_name();
                if name != "." && name != ".." {
                    nonempty = true;
                    core::ops::ControlFlow::Break(())
                } else {
                    core::ops::ControlFlow::Continue(())
                }
            })?;
            if nonempty {
                return Err(FatError::DirectoryNotEmpty);
            }
        }
        self.erase_entry_run(parent, first_offset, short_offset)?;
        if entry.first_cluster() >= 2 {
            self.free_chain(entry.first_cluster())?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), FatError> {
        self.device.flush().map_err(|_| FatError::WriteError)
    }

    /// Read entire file into a buffer (convenience method)
    pub fn read_file_all(&mut self, path: &str, buffer: &mut [u8]) -> Result<usize, FatError> {
        let entry = self.find_file(path)?;

        if entry.file_size as usize > buffer.len() {
            return Err(FatError::BufferTooSmall);
        }

        self.read_file(&entry, 0, buffer)
    }

    /// Get file size
    pub fn file_size(&mut self, path: &str) -> Result<u32, FatError> {
        let entry = self.find_file(path)?;
        Ok(entry.file_size)
    }

    /// Get root directory cluster
    pub fn root_cluster(&self) -> u32 {
        self.root_cluster
    }

    /// Get the FAT type (12, 16, or 32)
    pub fn fat_type(&self) -> FatType {
        self.fat_type
    }

    /// List filenames in a directory that match a suffix filter
    ///
    /// Enumerates all entries in the specified directory and returns the names
    /// of files (not subdirectories) whose names end with the given suffix.
    /// Uses Long File Names when available, falling back to 8.3 short names.
    ///
    /// # Arguments
    /// * `dir_path` - Path to the directory (e.g., "loader\\entries")
    /// * `suffix` - File name suffix filter (e.g., ".conf"), case-insensitive
    ///
    /// # Returns
    /// A vector of matching filenames (just the name, not the full path)
    pub fn list_directory_files(
        &mut self,
        dir_path: &str,
        suffix: &str,
    ) -> Result<heapless::Vec<heapless::String<256>, 32>, FatError> {
        use core::ops::ControlFlow;

        let dir_cluster = self.resolve_dir_cluster(dir_path)?;
        let mut results: heapless::Vec<heapless::String<256>, 32> = heapless::Vec::new();

        let _ = self.for_each_dir_entry(dir_cluster, |entry, lfn_buf| {
            if entry.is_directory() {
                return ControlFlow::Continue(());
            }
            let name = Self::entry_display_name(entry, lfn_buf);
            if suffix_matches(&name, suffix) && results.push(name).is_err() {
                return ControlFlow::Break(()); // Full
            }
            ControlFlow::Continue(())
        })?;

        Ok(results)
    }

    /// Extract the display name from a directory entry, preferring LFN over short name
    fn entry_display_name(entry: &DirectoryEntry, lfn: &LfnBuffer) -> heapless::String<256> {
        let mut name = heapless::String::<256>::new();

        if lfn.active && lfn.len > 0 {
            // Use LFN - convert UTF-16 to UTF-8
            for i in 0..lfn.len {
                let ch = lfn.chars[i];
                if ch == 0 {
                    break;
                }
                // Simple BMP-only conversion (sufficient for filenames)
                if let Some(c) = char::from_u32(ch as u32)
                    && name.push(c).is_err()
                {
                    break; // Name too long
                }
            }
        }

        if name.is_empty() {
            // Fall back to short name
            let short = entry.short_name();
            let _ = name.push_str(&short);
        }

        name
    }

    /// List subdirectory names in a directory
    ///
    /// Enumerates all entries in the specified directory and returns the names
    /// of subdirectories (not files). Uses Long File Names when available.
    ///
    /// # Arguments
    /// * `dir_path` - Path to the directory (e.g., "EFI")
    ///
    /// # Returns
    /// A vector of subdirectory names
    pub fn list_subdirectories(
        &mut self,
        dir_path: &str,
    ) -> Result<heapless::Vec<heapless::String<256>, 16>, FatError> {
        use core::ops::ControlFlow;

        let dir_cluster = self.resolve_dir_cluster(dir_path)?;
        let mut results: heapless::Vec<heapless::String<256>, 16> = heapless::Vec::new();

        let _ = self.for_each_dir_entry(dir_cluster, |entry, lfn_buf| {
            if !entry.is_directory() {
                return ControlFlow::Continue(());
            }
            let name = Self::entry_display_name(entry, lfn_buf);
            if name != "." && name != ".." && results.push(name).is_err() {
                return ControlFlow::Break(()); // Full
            }
            ControlFlow::Continue(())
        })?;

        Ok(results)
    }

    /// Get a directory entry at a specific position (for directory enumeration)
    ///
    /// Returns both the entry and its display name (preferring LFN over 8.3).
    ///
    /// # Arguments
    /// * `cluster` - First cluster of directory (0 for FAT12/16 root directory)
    /// * `position` - Entry index (skipping deleted/LFN/volume entries)
    ///
    /// # Returns
    /// * `Ok(Some((entry, name)))` - The entry and display name at the given position
    /// * `Ok(None)` - End of directory reached
    /// * `Err(e)` - Read error
    pub fn get_directory_entry_at_position(
        &mut self,
        cluster: u32,
        position: usize,
    ) -> Result<Option<(DirectoryEntry, heapless::String<256>)>, FatError> {
        use core::ops::ControlFlow;

        let mut current_position = 0usize;

        match self.for_each_dir_entry(cluster, |entry, lfn_buf| {
            if current_position == position {
                let name = Self::entry_display_name(entry, lfn_buf);
                ControlFlow::Break((*entry, name))
            } else {
                current_position += 1;
                ControlFlow::Continue(())
            }
        })? {
            ControlFlow::Break(result) => Ok(Some(result)),
            ControlFlow::Continue(()) => Ok(None),
        }
    }
}

fn is_short_name_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'$' | b'%'
                | b'\''
                | b'-'
                | b'_'
                | b'@'
                | b'~'
                | b'`'
                | b'!'
                | b'('
                | b')'
                | b'{'
                | b'}'
                | b'^'
                | b'#'
                | b'&'
        )
}

fn decimal(mut value: u16, output: &mut [u8; 4]) -> usize {
    let mut reversed = [0u8; 4];
    let mut length = 0;
    while value != 0 {
        reversed[length] = b'0' + (value % 10) as u8;
        value /= 10;
        length += 1;
    }
    for index in 0..length {
        output[index] = reversed[length - index - 1];
    }
    length
}

fn lfn_checksum(short: &[u8; 11]) -> u8 {
    short
        .iter()
        .fold(0u8, |sum, byte| sum.rotate_right(1).wrapping_add(*byte))
}

fn write_lfn_chars(raw: &mut [u8; 32], chars: &[u16; 13]) {
    const OFFSETS: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    for (offset, character) in OFFSETS.into_iter().zip(chars) {
        raw[offset..offset + 2].copy_from_slice(&character.to_le_bytes());
    }
}

/// Check if a filename ends with a given suffix (case-insensitive)
fn suffix_matches(name: &str, suffix: &str) -> bool {
    if name.len() < suffix.len() {
        return false;
    }
    let name_end = &name[name.len() - suffix.len()..];
    name_end
        .bytes()
        .zip(suffix.bytes())
        .all(|(a, b)| a.eq_ignore_ascii_case(&b))
}
