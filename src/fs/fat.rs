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

        // Case-insensitive comparison
        if entry_name.len() != name.len() {
            return false;
        }

        for (a, b) in entry_name.bytes().zip(name.bytes()) {
            if !a.eq_ignore_ascii_case(&b) {
                return false;
            }
        }

        true
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
}

/// FAT filesystem instance
pub struct FatFilesystem<'a, D: BlockDevice> {
    /// Block device
    device: &'a mut D,
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
    /// Sectors per FAT (kept for filesystem completeness)
    #[allow(dead_code)]
    sectors_per_fat: u32,
    /// First data sector (relative to partition start)
    data_start: u32,
    /// Root directory first cluster (FAT32) or sector count (FAT12/16)
    root_cluster: u32,
    /// Root directory sector start (FAT12/16 only)
    root_dir_start: u32,
    /// Root directory sector count (FAT12/16 only)
    root_dir_sectors: u32,
    /// Total data clusters (kept for filesystem completeness)
    #[allow(dead_code)]
    data_clusters: u32,
}

impl<'a, D: BlockDevice> FatFilesystem<'a, D> {
    /// Create a new FAT filesystem instance
    pub fn new(device: &'a mut D, partition_start: u64) -> Result<Self, FatError> {
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

        // Calculate total data clusters
        let data_sectors = total_sectors - data_start;
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
            sectors_per_fat,
            data_start,
            root_cluster,
            root_dir_start,
            root_dir_sectors,
            data_clusters,
        })
    }

    /// Get the first device block of a cluster
    ///
    /// # Returns
    /// Returns `None` if the cluster number is invalid (< 2 or beyond data region)
    fn cluster_to_device_block(&self, cluster: u32) -> Option<u64> {
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
        // Translate to device block
        let device_block = self.fat_sector_to_device_block(fat_sector as u64);
        self.partition_start.checked_add(device_block)
    }

    /// Read the next cluster from the FAT
    fn next_cluster(&mut self, cluster: u32) -> Result<Option<u32>, FatError> {
        // Validate cluster number is in valid range (clusters 0 and 1 are reserved)
        if cluster < 2 {
            return Err(FatError::InvalidCluster);
        }

        // Use device block size for buffer to avoid overflow
        let device_block_size = self.device_block_size as usize;
        let mut buffer = [0u8; MAX_BLOCK_SIZE];
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

        self.device
            .read_block(
                self.partition_start + device_block,
                &mut buffer[..device_block_size],
            )
            .map_err(|_| FatError::ReadError)?;

        let next = match self.fat_type {
            FatType::Fat12 => {
                let entry = if offset_in_block + 1 < device_block_size {
                    buffer[offset_in_block] as u16 | ((buffer[offset_in_block + 1] as u16) << 8)
                } else {
                    // Entry spans device blocks - need to read next block
                    let low = buffer[offset_in_block] as u16;
                    self.device
                        .read_block(
                            self.partition_start + device_block + 1,
                            &mut buffer[..device_block_size],
                        )
                        .map_err(|_| FatError::ReadError)?;
                    low | ((buffer[0] as u16) << 8)
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
                    u16::from_le_bytes([buffer[offset_in_block], buffer[offset_in_block + 1]])
                } else {
                    // Entry spans device blocks - need to read next block
                    let low = buffer[offset_in_block];
                    self.device
                        .read_block(
                            self.partition_start + device_block + 1,
                            &mut buffer[..device_block_size],
                        )
                        .map_err(|_| FatError::ReadError)?;
                    u16::from_le_bytes([low, buffer[0]])
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
                        buffer[offset_in_block],
                        buffer[offset_in_block + 1],
                        buffer[offset_in_block + 2],
                        buffer[offset_in_block + 3],
                    ])
                } else {
                    // Entry spans device blocks - read bytes from current and next block
                    let bytes_in_current = device_block_size - offset_in_block;
                    let mut entry_bytes = [0u8; 4];
                    entry_bytes[..bytes_in_current].copy_from_slice(
                        &buffer[offset_in_block..offset_in_block + bytes_in_current],
                    );
                    self.device
                        .read_block(
                            self.partition_start + device_block + 1,
                            &mut buffer[..device_block_size],
                        )
                        .map_err(|_| FatError::ReadError)?;
                    entry_bytes[bytes_in_current..4]
                        .copy_from_slice(&buffer[..4 - bytes_in_current]);
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

        let start_device_block = self
            .cluster_to_device_block(cluster)
            .ok_or(FatError::InvalidCluster)?;

        // Calculate how many device blocks make up one cluster
        let device_block_size = self.device_block_size as usize;
        let device_blocks_per_cluster = cluster_size.div_ceil(device_block_size);

        for i in 0..device_blocks_per_cluster {
            let offset = i * device_block_size;
            let read_size = device_block_size.min(cluster_size - offset);
            self.device
                .read_block(
                    start_device_block + i as u64,
                    &mut buffer[offset..offset + read_size],
                )
                .map_err(|_| FatError::ReadError)?;
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

    /// Translate a FAT sector offset to a device block offset
    ///
    /// When the device block size differs from FAT's bytes_per_sector,
    /// we need to translate FAT sector numbers to device block numbers.
    fn fat_sector_to_device_block(&self, fat_sector: u64) -> u64 {
        let bytes_per_sector = self.bytes_per_sector as u64;
        let device_block_size = self.device_block_size as u64;

        if bytes_per_sector == device_block_size {
            fat_sector
        } else {
            // Convert FAT sector to byte offset, then to device block
            (fat_sector * bytes_per_sector) / device_block_size
        }
    }

    /// Find an entry in a directory
    fn find_in_directory(&mut self, cluster: u32, name: &str) -> Result<DirectoryEntry, FatError> {
        // FAT cluster sizes can be up to 128 sectors * 512 bytes = 65536 bytes
        let mut buffer = [0u8; 65536]; // Max cluster size (128 sectors * 512 bytes)
        let entries_per_sector = self.bytes_per_sector as usize / 32;
        // Use the larger of FAT sector size or device block size for reads
        let read_size = (self.bytes_per_sector as usize).max(self.device_block_size as usize);

        if cluster == 0 && self.fat_type != FatType::Fat32 {
            // FAT12/16 root directory (fixed location)
            // Translate FAT sectors to device blocks
            let root_dir_device_block = self.fat_sector_to_device_block(self.root_dir_start as u64);
            let sectors_per_device_block =
                self.device_block_size as usize / self.bytes_per_sector as usize;
            let entries_per_device_block = entries_per_sector * sectors_per_device_block.max(1);
            let device_blocks_for_root =
                (self.root_dir_sectors as usize).div_ceil(sectors_per_device_block.max(1));

            for block_idx in 0..device_blocks_for_root as u64 {
                let device_block = self.partition_start + root_dir_device_block + block_idx;
                self.device
                    .read_block(device_block, &mut buffer[..read_size])
                    .map_err(|_| FatError::ReadError)?;

                for i in 0..entries_per_device_block {
                    let offset = i * 32;
                    if offset + 32 > read_size {
                        break;
                    }
                    // Parse directory entry using zerocopy
                    let entry = match DirectoryEntry::read_from_prefix(&buffer[offset..]) {
                        Ok((e, _)) => e,
                        Err(_) => break,
                    };

                    if entry.is_end() {
                        log::debug!("FAT: end of directory, '{}' not found", name);
                        return Err(FatError::NotFound);
                    }

                    if entry.is_free() || entry.is_lfn() || entry.is_volume_id() {
                        continue;
                    }

                    log::debug!(
                        "FAT: found entry '{}' (looking for '{}')",
                        entry.short_name(),
                        name
                    );

                    if entry.matches_name(name) {
                        return Ok(entry);
                    }
                }
            }
        } else {
            // Cluster chain directory
            let mut current_cluster = cluster;
            let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
            let entries_per_cluster = cluster_size / 32;

            loop {
                self.read_cluster(current_cluster, &mut buffer[..cluster_size])?;

                for i in 0..entries_per_cluster {
                    let offset = i * 32;
                    // Parse directory entry using zerocopy
                    let entry = match DirectoryEntry::read_from_prefix(&buffer[offset..]) {
                        Ok((e, _)) => e,
                        Err(_) => break,
                    };

                    if entry.is_end() {
                        log::debug!(
                            "FAT: end of directory in cluster {}, '{}' not found",
                            current_cluster,
                            name
                        );
                        return Err(FatError::NotFound);
                    }

                    if entry.is_free() || entry.is_lfn() || entry.is_volume_id() {
                        continue;
                    }

                    log::debug!(
                        "FAT: found entry '{}' in cluster {} (looking for '{}')",
                        entry.short_name(),
                        current_cluster,
                        name
                    );

                    if entry.matches_name(name) {
                        return Ok(entry);
                    }
                }

                match self.next_cluster(current_cluster)? {
                    Some(next) => current_cluster = next,
                    None => {
                        log::debug!("FAT: end of cluster chain, '{}' not found", name);
                        return Err(FatError::NotFound);
                    }
                }
            }
        }

        Err(FatError::NotFound)
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

        // Read full clusters
        while bytes_read + cluster_size as usize <= bytes_to_read {
            self.read_cluster(
                cluster,
                &mut buffer[bytes_read..bytes_read + cluster_size as usize],
            )?;
            bytes_read += cluster_size as usize;

            match self.next_cluster(cluster)? {
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

    /// Get a directory entry at a specific position (for directory enumeration)
    ///
    /// # Arguments
    /// * `cluster` - First cluster of directory (0 for FAT12/16 root directory)
    /// * `position` - Entry index (skipping deleted/LFN/volume entries)
    ///
    /// # Returns
    /// * `Ok(Some(entry))` - The entry at the given position
    /// * `Ok(None)` - End of directory reached
    /// * `Err(e)` - Read error
    pub fn get_directory_entry_at_position(
        &mut self,
        cluster: u32,
        position: usize,
    ) -> Result<Option<DirectoryEntry>, FatError> {
        let mut buffer = [0u8; 65536]; // Max cluster size
        let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
        let entries_per_cluster = cluster_size / 32;
        let mut current_position = 0usize;

        if cluster == 0 && self.fat_type != FatType::Fat32 {
            // FAT12/16 root directory (fixed location)
            let root_dir_device_block = self.fat_sector_to_device_block(self.root_dir_start as u64);
            let device_block_size = self.device_block_size as usize;
            let sectors_per_device_block = device_block_size / self.bytes_per_sector as usize;
            let entries_per_device_block =
                (self.bytes_per_sector as usize / 32) * sectors_per_device_block.max(1);
            let device_blocks_for_root =
                (self.root_dir_sectors as usize).div_ceil(sectors_per_device_block.max(1));

            for block_idx in 0..device_blocks_for_root as u64 {
                let device_block = self.partition_start + root_dir_device_block + block_idx;
                self.device
                    .read_block(device_block, &mut buffer[..device_block_size])
                    .map_err(|_| FatError::ReadError)?;

                for i in 0..entries_per_device_block {
                    let offset = i * 32;
                    if offset + 32 > device_block_size {
                        break;
                    }
                    // Parse directory entry using zerocopy
                    let entry = match DirectoryEntry::read_from_prefix(&buffer[offset..]) {
                        Ok((e, _)) => e,
                        Err(_) => break,
                    };

                    if entry.is_end() {
                        return Ok(None);
                    }
                    if entry.is_free() || entry.is_lfn() || entry.is_volume_id() {
                        continue;
                    }

                    if current_position == position {
                        return Ok(Some(entry));
                    }
                    current_position += 1;
                }
            }
            return Ok(None);
        }

        // Cluster chain directory
        let mut current_cluster = cluster;

        loop {
            self.read_cluster(current_cluster, &mut buffer[..cluster_size])?;

            // Search entries
            for i in 0..entries_per_cluster {
                let offset = i * 32;
                // Parse directory entry using zerocopy
                let entry = match DirectoryEntry::read_from_prefix(&buffer[offset..]) {
                    Ok((e, _)) => e,
                    Err(_) => break,
                };

                if entry.is_end() {
                    return Ok(None);
                }
                if entry.is_free() || entry.is_lfn() || entry.is_volume_id() {
                    continue;
                }

                if current_position == position {
                    return Ok(Some(entry));
                }
                current_position += 1;
            }

            // Get next cluster
            current_cluster = match self.next_cluster(current_cluster)? {
                Some(c) => c,
                None => return Ok(None),
            };
        }
    }
}
