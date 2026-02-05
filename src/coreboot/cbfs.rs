//! CBFS (Coreboot File System) parsing
//!
//! This module provides read-only access to files stored in CBFS.
//! CBFS location is obtained from coreboot's `LB_TAG_BOOT_MEDIA_PARAMS`
//! table entry, which provides the exact offset and size in flash.
//!
//! On x86, the SPI flash is memory-mapped at the end of the 4GB address space,
//! so we can directly read CBFS contents from memory.
//!
//! # References
//!
//! - coreboot/src/commonlib/bsd/include/commonlib/bsd/cbfs_serialized.h
//! - coreboot/payloads/libpayload/libcbfs/cbfs.c

use alloc::string::String;
use alloc::vec::Vec;
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// CBFS file magic: "LARCHIVE"
pub const CBFS_FILE_MAGIC: &[u8; 8] = b"LARCHIVE";

/// CBFS header magic: 0x4F524243 ("ORBC" in big-endian)
pub const CBFS_HEADER_MAGIC: u32 = 0x4F524243;

/// CBFS file alignment (all files are aligned to this boundary)
pub const CBFS_ALIGNMENT: usize = 64;

/// Maximum metadata size (filename + attributes)
pub const CBFS_METADATA_MAX_SIZE: usize = 256;

/// CBFS compression types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CbfsCompression {
    None = 0,
    Lzma = 1,
    Lz4 = 2,
    Zstd = 3,
}

impl CbfsCompression {
    fn from_be(value: u32) -> Self {
        match u32::from_be(value) {
            0 => Self::None,
            1 => Self::Lzma,
            2 => Self::Lz4,
            3 => Self::Zstd,
            _ => Self::None,
        }
    }
}

/// CBFS file types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CbfsType {
    Deleted = 0x00000000,
    Null = 0xffffffff,
    Bootblock = 0x01,
    CbfsHeader = 0x02,
    LegacyStage = 0x10,
    Stage = 0x11,
    Self_ = 0x20,
    FitPayload = 0x21,
    OptionRom = 0x30,
    BootSplash = 0x40,
    Raw = 0x50,
    Vsa = 0x51,
    Mbi = 0x52,
    Microcode = 0x53,
    IntelFit = 0x54,
    Fsp = 0x60,
    Mrc = 0x61,
    Mma = 0x62,
    Efi = 0x63,
    Struct = 0x70,
    AmdFw = 0x80,
    CmosDefault = 0xaa,
    Spd = 0xab,
    MrcCache = 0xac,
    CmosLayout = 0x01aa,
    Unknown(u32),
}

impl CbfsType {
    fn from_be(value: u32) -> Self {
        match u32::from_be(value) {
            0x00000000 => Self::Deleted,
            0xffffffff => Self::Null,
            0x01 => Self::Bootblock,
            0x02 => Self::CbfsHeader,
            0x10 => Self::LegacyStage,
            0x11 => Self::Stage,
            0x20 => Self::Self_,
            0x21 => Self::FitPayload,
            0x30 => Self::OptionRom,
            0x40 => Self::BootSplash,
            0x50 => Self::Raw,
            0x51 => Self::Vsa,
            0x52 => Self::Mbi,
            0x53 => Self::Microcode,
            0x54 => Self::IntelFit,
            0x60 => Self::Fsp,
            0x61 => Self::Mrc,
            0x62 => Self::Mma,
            0x63 => Self::Efi,
            0x70 => Self::Struct,
            0x80 => Self::AmdFw,
            0xaa => Self::CmosDefault,
            0xab => Self::Spd,
            0xac => Self::MrcCache,
            0x01aa => Self::CmosLayout,
            v => Self::Unknown(v),
        }
    }
}

/// CBFS file attribute tags
#[allow(dead_code)]
mod attr_tags {
    pub const UNUSED: u32 = 0;
    pub const UNUSED2: u32 = 0xffffffff;
    pub const COMPRESSION: u32 = 0x42435a4c; // "BCZL" in BE
    pub const HASH: u32 = 0x68736148; // "hsaH" in BE
    pub const POSITION: u32 = 0x42435350; // "BCSP" in BE
    pub const ALIGNMENT: u32 = 0x42434c41; // "BCLA" in BE
    pub const IBB: u32 = 0x32494242; // "2IBB" in BE
    pub const PADDING: u32 = 0x47444150; // "GNDP" in BE
    pub const STAGEHEADER: u32 = 0x53746748; // "StgH" in BE
}

/// CBFS file header (on-disk format, all fields big-endian)
///
/// Layout in flash:
/// ```text
/// [CbfsFileHeader]     <- offset 0
/// [filename string]    <- offset sizeof(CbfsFileHeader)
/// [attributes]         <- offset attributes_offset (if non-zero)
/// [file data]          <- offset `offset` field
/// ```
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
pub struct CbfsFileHeader {
    /// Magic: "LARCHIVE"
    pub magic: [u8; 8],
    /// Length of file data (big-endian)
    pub len: u32,
    /// File type (big-endian)
    pub type_: u32,
    /// Offset to attributes from start of header, 0 if none (big-endian)
    pub attributes_offset: u32,
    /// Offset to file data from start of header (big-endian)
    pub offset: u32,
    // filename follows (variable length, null-terminated)
}

/// CBFS file attribute header
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
pub struct CbfsFileAttribute {
    /// Attribute tag (big-endian)
    pub tag: u32,
    /// Total attribute length including header (big-endian)
    pub len: u32,
    // attribute data follows
}

/// CBFS compression attribute
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
pub struct CbfsAttrCompression {
    /// Tag: CBFS_FILE_ATTR_TAG_COMPRESSION
    pub tag: u32,
    /// Length of this attribute
    pub len: u32,
    /// Compression algorithm (big-endian)
    pub compression: u32,
    /// Decompressed size (big-endian)
    pub decompressed_size: u32,
}

/// CBFS stage header attribute (for stages like ramstage, postcar)
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
pub struct CbfsAttrStageHeader {
    /// Tag: CBFS_FILE_ATTR_TAG_STAGEHEADER
    pub tag: u32,
    /// Length of this attribute
    pub len: u32,
    /// Memory address to load the code to (big-endian)
    pub loadaddr: u64,
    /// Offset of entry point from loadaddr (big-endian)
    pub entry_offset: u32,
    /// Total length (including BSS) in memory (big-endian)
    pub memlen: u32,
}

/// CBFS payload segment header (for self-extracting payloads)
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
pub struct CbfsPayloadSegment {
    /// Segment type (CODE, DATA, BSS, ENTRY, PARAMS)
    pub seg_type: u32,
    /// Compression algorithm (big-endian)
    pub compression: u32,
    /// Offset of segment data within payload (big-endian)
    pub offset: u32,
    /// Memory address to load this segment (big-endian)
    pub load_addr: u64,
    /// Length of compressed data (big-endian)
    pub len: u32,
    /// Length in memory after decompression (big-endian)
    pub mem_len: u32,
}

/// Payload segment types
#[allow(dead_code)]
mod payload_segment_types {
    pub const CODE: u32 = 0x434F4445; // "CODE" in BE
    pub const DATA: u32 = 0x44415441; // "DATA" in BE
    pub const BSS: u32 = 0x42535320; // "BSS " in BE
    pub const PARAMS: u32 = 0x50415241; // "PARA" in BE
    pub const ENTRY: u32 = 0x454E5452; // "ENTR" in BE
}

/// Information about a CBFS file
#[derive(Debug, Clone)]
pub struct CbfsFileInfo {
    /// File name
    pub name: String,
    /// File type
    pub file_type: CbfsType,
    /// Compression algorithm
    pub compression: CbfsCompression,
    /// Compressed size (size on flash)
    pub compressed_size: u32,
    /// Decompressed size (actual data size)
    pub decompressed_size: u32,
    /// Host memory address where file data starts
    pub data_addr: u64,
    /// Flash offset where file data starts
    pub flash_offset: u64,
    /// Stage/payload load information (if available)
    pub load_info: Option<CbfsLoadInfo>,
}

/// Load information for stages and payloads
#[derive(Debug, Clone, Copy)]
pub struct CbfsLoadInfo {
    /// Memory address to load the code to
    pub load_addr: u64,
    /// Entry point address (load_addr + entry_offset)
    pub entry_point: u64,
    /// Total memory size needed (including BSS)
    pub mem_size: u32,
}

/// CBFS access handle
///
/// Provides access to CBFS contents using information from coreboot tables.
#[derive(Debug)]
pub struct Cbfs {
    /// Base host address of CBFS region
    cbfs_host_base: u64,
    /// Size of CBFS region
    cbfs_size: u64,
    /// Flash offset of CBFS region
    cbfs_flash_offset: u64,
}

impl Cbfs {
    /// Create a new CBFS accessor using boot media info from coreboot tables
    ///
    /// Returns None if boot media info is not available.
    pub fn new() -> Option<Self> {
        let boot_media = super::get_boot_media()?;

        // Calculate host base address for CBFS
        // Flash is memory-mapped at end of 4GB: host_addr = 0x100000000 - boot_media_size + flash_offset
        let cbfs_host_base = flash_to_host_addr(boot_media.cbfs_offset, boot_media.boot_media_size);

        log::info!(
            "CBFS: flash offset {:#x}, size {} KB, host base {:#x}",
            boot_media.cbfs_offset,
            boot_media.cbfs_size / 1024,
            cbfs_host_base
        );

        Some(Self {
            cbfs_host_base,
            cbfs_size: boot_media.cbfs_size,
            cbfs_flash_offset: boot_media.cbfs_offset,
        })
    }

    /// Find a file in CBFS by name
    ///
    /// # Arguments
    ///
    /// * `name` - The file name to search for
    ///
    /// # Returns
    ///
    /// File info if found, None otherwise.
    pub fn find(&self, name: &str) -> Option<CbfsFileInfo> {
        let mut offset = 0usize;

        while offset + size_of::<CbfsFileHeader>() < self.cbfs_size as usize {
            // Read file header
            let header_ptr = (self.cbfs_host_base + offset as u64) as *const u8;
            let header_bytes =
                unsafe { core::slice::from_raw_parts(header_ptr, size_of::<CbfsFileHeader>()) };

            let Ok((header, _)) = CbfsFileHeader::read_from_prefix(header_bytes) else {
                offset += CBFS_ALIGNMENT;
                continue;
            };

            // Check for LARCHIVE magic
            if &header.magic != CBFS_FILE_MAGIC {
                offset += CBFS_ALIGNMENT;
                continue;
            }

            // Parse header fields (convert from big-endian)
            let data_offset = u32::from_be(header.offset) as usize;
            let data_len = u32::from_be(header.len);
            let file_type = CbfsType::from_be(header.type_);
            let attr_offset = u32::from_be(header.attributes_offset) as usize;

            // Validate offsets
            if data_offset > CBFS_METADATA_MAX_SIZE || data_offset < size_of::<CbfsFileHeader>() {
                log::warn!("CBFS: invalid data offset {} at {:#x}", data_offset, offset);
                offset += CBFS_ALIGNMENT;
                continue;
            }

            // Skip deleted/null entries
            if matches!(file_type, CbfsType::Deleted | CbfsType::Null) {
                offset = align_up(offset + data_offset + data_len as usize, CBFS_ALIGNMENT);
                continue;
            }

            // Read filename (starts after header, null-terminated)
            let filename_start = header_ptr as usize + size_of::<CbfsFileHeader>();
            let filename_max_len = if attr_offset > size_of::<CbfsFileHeader>() {
                attr_offset - size_of::<CbfsFileHeader>()
            } else {
                data_offset - size_of::<CbfsFileHeader>()
            };

            let filename = unsafe {
                let filename_bytes =
                    core::slice::from_raw_parts(filename_start as *const u8, filename_max_len);
                let len = filename_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(filename_max_len);
                core::str::from_utf8(&filename_bytes[..len]).unwrap_or("")
            };

            log::trace!(
                "CBFS file: '{}' type={:?} at offset {:#x}",
                filename,
                file_type,
                offset
            );

            // Check if this is the file we're looking for
            if filename == name {
                // Parse attributes if present
                let (compression, decompressed_size, load_info) = if attr_offset > 0 {
                    self.parse_attributes(header_ptr, attr_offset, data_offset)
                } else {
                    (CbfsCompression::None, data_len, None)
                };

                let data_host_addr = self.cbfs_host_base + offset as u64 + data_offset as u64;
                let data_flash_offset = self.cbfs_flash_offset + offset as u64 + data_offset as u64;

                // Use data_len as fallback if decompressed_size is 0
                let final_decompressed_size = if decompressed_size > 0 {
                    decompressed_size
                } else {
                    data_len
                };

                log::info!(
                    "CBFS: found '{}' at {:#x}, {} bytes (compressed: {} bytes, {:?})",
                    name,
                    data_flash_offset,
                    final_decompressed_size,
                    data_len,
                    compression
                );

                if let Some(ref info) = load_info {
                    log::info!(
                        "CBFS: load_addr={:#x}, entry={:#x}, mem_size={}",
                        info.load_addr,
                        info.entry_point,
                        info.mem_size
                    );
                }

                return Some(CbfsFileInfo {
                    name: String::from(filename),
                    file_type,
                    compression,
                    compressed_size: data_len,
                    decompressed_size: final_decompressed_size,
                    data_addr: data_host_addr,
                    flash_offset: data_flash_offset,
                    load_info,
                });
            }

            // Move to next file (aligned)
            offset = align_up(offset + data_offset + data_len as usize, CBFS_ALIGNMENT);
        }

        log::debug!("CBFS: file '{}' not found", name);
        None
    }

    /// Parse all attributes from file metadata
    ///
    /// Returns (compression, decompressed_size, load_info)
    fn parse_attributes(
        &self,
        header_ptr: *const u8,
        attr_offset: usize,
        data_offset: usize,
    ) -> (CbfsCompression, u32, Option<CbfsLoadInfo>) {
        let mut offset = attr_offset;
        let mut compression = CbfsCompression::None;
        let mut decompressed_size = 0u32;
        let mut load_info: Option<CbfsLoadInfo> = None;

        while offset + size_of::<CbfsFileAttribute>() <= data_offset {
            let attr_ptr = unsafe { header_ptr.add(offset) };
            let attr_bytes =
                unsafe { core::slice::from_raw_parts(attr_ptr, size_of::<CbfsFileAttribute>()) };

            let Ok((attr, _)) = CbfsFileAttribute::read_from_prefix(attr_bytes) else {
                break;
            };

            let tag = u32::from_be(attr.tag);
            let len = u32::from_be(attr.len) as usize;

            if len < size_of::<CbfsFileAttribute>() || offset + len > data_offset {
                break;
            }

            match tag {
                attr_tags::COMPRESSION => {
                    // Read compression attribute
                    let comp_bytes = unsafe {
                        core::slice::from_raw_parts(attr_ptr, size_of::<CbfsAttrCompression>())
                    };

                    if let Ok((comp_attr, _)) = CbfsAttrCompression::read_from_prefix(comp_bytes) {
                        compression = CbfsCompression::from_be(comp_attr.compression);
                        decompressed_size = u32::from_be(comp_attr.decompressed_size);
                    }
                }
                attr_tags::STAGEHEADER => {
                    // Read stage header attribute
                    let stage_bytes = unsafe {
                        core::slice::from_raw_parts(attr_ptr, size_of::<CbfsAttrStageHeader>())
                    };

                    if let Ok((stage_attr, _)) = CbfsAttrStageHeader::read_from_prefix(stage_bytes)
                    {
                        let loadaddr = u64::from_be(stage_attr.loadaddr);
                        let entry_offset = u32::from_be(stage_attr.entry_offset);
                        let memlen = u32::from_be(stage_attr.memlen);

                        load_info = Some(CbfsLoadInfo {
                            load_addr: loadaddr,
                            entry_point: loadaddr + entry_offset as u64,
                            mem_size: memlen,
                        });
                    }
                }
                attr_tags::UNUSED | attr_tags::UNUSED2 => {
                    // End of attributes
                    break;
                }
                _ => {
                    // Unknown attribute, skip it
                }
            }

            offset += len;
        }

        (compression, decompressed_size, load_info)
    }

    /// Read file data into a buffer
    ///
    /// # Arguments
    ///
    /// * `file` - File info from `find()`
    /// * `buffer` - Buffer to read into (must be at least `decompressed_size` bytes)
    ///
    /// # Returns
    ///
    /// Number of bytes read, or error.
    pub fn read(&self, file: &CbfsFileInfo, buffer: &mut [u8]) -> Result<usize, CbfsError> {
        if buffer.len() < file.decompressed_size as usize {
            return Err(CbfsError::BufferTooSmall);
        }

        match file.compression {
            CbfsCompression::None => {
                // Direct copy from memory-mapped flash
                let src = unsafe {
                    core::slice::from_raw_parts(
                        file.data_addr as *const u8,
                        file.compressed_size as usize,
                    )
                };
                buffer[..file.compressed_size as usize].copy_from_slice(src);
                Ok(file.compressed_size as usize)
            }
            CbfsCompression::Lzma => {
                // LZMA decompression using lzma-rs
                let src = unsafe {
                    core::slice::from_raw_parts(
                        file.data_addr as *const u8,
                        file.compressed_size as usize,
                    )
                };
                decompress_lzma(src, buffer)
            }
            CbfsCompression::Lz4 => {
                // LZ4 decompression using lz4_flex
                let src = unsafe {
                    core::slice::from_raw_parts(
                        file.data_addr as *const u8,
                        file.compressed_size as usize,
                    )
                };
                decompress_lz4(src, buffer, file.decompressed_size as usize)
            }
            CbfsCompression::Zstd => {
                // ZSTD decompression using ruzstd
                let src = unsafe {
                    core::slice::from_raw_parts(
                        file.data_addr as *const u8,
                        file.compressed_size as usize,
                    )
                };
                decompress_zstd(src, buffer)
            }
        }
    }

    /// Read file data into a newly allocated buffer
    ///
    /// # Arguments
    ///
    /// * `file` - File info from `find()`
    ///
    /// # Returns
    ///
    /// Vector containing file data, or error.
    pub fn read_alloc(&self, file: &CbfsFileInfo) -> Result<Vec<u8>, CbfsError> {
        let mut buffer = alloc::vec![0u8; file.decompressed_size as usize];
        let size = self.read(file, &mut buffer)?;
        buffer.truncate(size);
        Ok(buffer)
    }

    /// Load a stage/payload directly to its target memory address
    ///
    /// This function decompresses the file directly into the memory address
    /// specified in the stage header, avoiding intermediate buffer allocation.
    /// It also zeroes the BSS section if mem_size > decompressed_size.
    ///
    /// If the target address conflicts with CrabEFI's own memory, this function
    /// uses a bounce buffer and trampoline to safely relocate the payload.
    ///
    /// # Arguments
    ///
    /// * `file` - File info from `find()` (must have load_info)
    ///
    /// # Returns
    ///
    /// The entry point address on success, or error.
    /// Note: If a trampoline is used, this function never returns.
    ///
    /// # Safety
    ///
    /// This function writes directly to the target memory address specified
    /// in the file's load_info. The caller must ensure:
    /// - The target memory region is valid and writable
    /// - The memory region is large enough (at least mem_size bytes)
    /// - No other code is using that memory region
    pub unsafe fn load_to_target(&self, file: &CbfsFileInfo) -> Result<u64, CbfsError> {
        let load_info = file.load_info.ok_or_else(|| {
            log::error!("CBFS: file '{}' has no load info", file.name);
            CbfsError::InvalidFormat
        })?;

        // Check if target conflicts with CrabEFI's own memory
        let conflicts_with_crabefi = crate::efi::allocator::conflicts_with_runtime(
            load_info.load_addr,
            load_info.mem_size as u64,
        );

        if conflicts_with_crabefi {
            // Use bounce buffer + trampoline approach
            return self.load_with_trampoline(file, &load_info);
        }

        // Direct loading path - target doesn't conflict with CrabEFI

        // Check that target is in usable RAM (not MMIO, reserved, or ACPI regions)
        if !crate::efi::allocator::is_usable_memory(load_info.load_addr, load_info.mem_size as u64)
        {
            log::error!(
                "CBFS: target region {:#x}-{:#x} is not in usable RAM",
                load_info.load_addr,
                load_info.load_addr + load_info.mem_size as u64
            );
            return Err(CbfsError::InvalidTarget);
        }

        log::info!(
            "CBFS: loading '{}' to {:#x} ({} bytes, entry={:#x})",
            file.name,
            load_info.load_addr,
            load_info.mem_size,
            load_info.entry_point
        );

        // Create a slice for the target memory region
        let target = unsafe {
            core::slice::from_raw_parts_mut(
                load_info.load_addr as *mut u8,
                load_info.mem_size as usize,
            )
        };

        // Decompress directly into target
        let decompressed_size = self.read(file, target)?;

        // Zero BSS (memory beyond decompressed data up to mem_size)
        if decompressed_size < load_info.mem_size as usize {
            let bss_start = decompressed_size;
            let bss_size = load_info.mem_size as usize - decompressed_size;
            log::debug!(
                "CBFS: zeroing BSS at {:#x}, {} bytes",
                load_info.load_addr + bss_start as u64,
                bss_size
            );
            target[bss_start..].fill(0);
        }

        log::info!(
            "CBFS: loaded '{}', entry point at {:#x}",
            file.name,
            load_info.entry_point
        );

        Ok(load_info.entry_point)
    }

    /// Load a payload using bounce buffer and trampoline
    ///
    /// This is used when the target address conflicts with CrabEFI's memory.
    /// The payload is decompressed to a bounce buffer, then a trampoline
    /// copies it to the final location and jumps to the entry point.
    ///
    /// # Safety
    ///
    /// This function never returns - it jumps to the trampoline which
    /// eventually jumps to the payload entry point.
    unsafe fn load_with_trampoline(
        &self,
        file: &CbfsFileInfo,
        load_info: &CbfsLoadInfo,
    ) -> Result<u64, CbfsError> {
        use super::trampoline::{self, TrampolineParams};

        let (runtime_start, runtime_end) = crate::efi::allocator::get_runtime_bounds();
        log::warn!(
            "CBFS: target {:#x}-{:#x} conflicts with CrabEFI ({:#x}-{:#x}), using trampoline",
            load_info.load_addr,
            load_info.load_addr + load_info.mem_size as u64,
            runtime_start,
            runtime_end
        );

        // Allocate bounce buffer for decompression
        let bounce_buffer = trampoline::allocate_bounce_buffer(file.decompressed_size as usize)
            .ok_or_else(|| {
                log::error!("CBFS: failed to allocate bounce buffer");
                CbfsError::AllocationFailed
            })?;

        log::info!(
            "CBFS: decompressing '{}' to bounce buffer at {:#x}",
            file.name,
            bounce_buffer.as_ptr() as u64
        );

        // Decompress to bounce buffer
        let decompressed_size = self.read(file, bounce_buffer)?;

        // Calculate BSS size
        let bss_size = (load_info.mem_size as usize).saturating_sub(decompressed_size);

        // Get coreboot table pointer for passing to payload
        let cbtable_ptr = crate::state::get_coreboot_table_ptr().unwrap_or(0);

        // Set up trampoline parameters
        let params = TrampolineParams {
            src_addr: bounce_buffer.as_ptr() as u64,
            dst_addr: load_info.load_addr,
            copy_size: decompressed_size as u64,
            bss_size: bss_size as u64,
            entry_point: load_info.entry_point,
            coreboot_table_ptr: cbtable_ptr,
        };

        // Execute the trampoline - this never returns
        // The bounce buffer was allocated via EFI pages, so it stays allocated
        match trampoline::execute_trampoline(&params) {
            // execute_trampoline returns ! on success, so this is unreachable
            Err(e) => {
                log::error!("CBFS: trampoline setup failed: {:?}", e);
                Err(CbfsError::TrampolineFailed)
            }
        }
    }

    /// Iterate over all files in CBFS
    ///
    /// # Arguments
    ///
    /// * `callback` - Function to call for each file. Return `false` to stop iteration.
    pub fn for_each<F>(&self, mut callback: F)
    where
        F: FnMut(&CbfsFileInfo) -> bool,
    {
        let mut offset = 0usize;

        while offset + size_of::<CbfsFileHeader>() < self.cbfs_size as usize {
            let header_ptr = (self.cbfs_host_base + offset as u64) as *const u8;
            let header_bytes =
                unsafe { core::slice::from_raw_parts(header_ptr, size_of::<CbfsFileHeader>()) };

            let Ok((header, _)) = CbfsFileHeader::read_from_prefix(header_bytes) else {
                offset += CBFS_ALIGNMENT;
                continue;
            };

            if &header.magic != CBFS_FILE_MAGIC {
                offset += CBFS_ALIGNMENT;
                continue;
            }

            let data_offset = u32::from_be(header.offset) as usize;
            let data_len = u32::from_be(header.len);
            let file_type = CbfsType::from_be(header.type_);
            let attr_offset = u32::from_be(header.attributes_offset) as usize;

            if data_offset > CBFS_METADATA_MAX_SIZE || data_offset < size_of::<CbfsFileHeader>() {
                offset += CBFS_ALIGNMENT;
                continue;
            }

            // Skip deleted/null entries
            if matches!(file_type, CbfsType::Deleted | CbfsType::Null) {
                offset = align_up(offset + data_offset + data_len as usize, CBFS_ALIGNMENT);
                continue;
            }

            // Read filename
            let filename_start = header_ptr as usize + size_of::<CbfsFileHeader>();
            let filename_max_len = if attr_offset > size_of::<CbfsFileHeader>() {
                attr_offset - size_of::<CbfsFileHeader>()
            } else {
                data_offset - size_of::<CbfsFileHeader>()
            };

            let filename = unsafe {
                let filename_bytes =
                    core::slice::from_raw_parts(filename_start as *const u8, filename_max_len);
                let len = filename_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(filename_max_len);
                core::str::from_utf8(&filename_bytes[..len]).unwrap_or("")
            };

            // Parse attributes
            let (compression, decompressed_size, load_info) = if attr_offset > 0 {
                self.parse_attributes(header_ptr, attr_offset, data_offset)
            } else {
                (CbfsCompression::None, data_len, None)
            };

            let file_info = CbfsFileInfo {
                name: String::from(filename),
                file_type,
                compression,
                compressed_size: data_len,
                decompressed_size: if decompressed_size > 0 {
                    decompressed_size
                } else {
                    data_len
                },
                data_addr: self.cbfs_host_base + offset as u64 + data_offset as u64,
                flash_offset: self.cbfs_flash_offset + offset as u64 + data_offset as u64,
                load_info,
            };

            if !callback(&file_info) {
                return;
            }

            offset = align_up(offset + data_offset + data_len as usize, CBFS_ALIGNMENT);
        }
    }

    /// List all files in CBFS (for debugging)
    pub fn list(&self) {
        log::info!("CBFS file listing:");
        self.for_each(|file| {
            log::info!(
                "  {:40} {:10?} {:8} bytes @ {:#x}",
                file.name,
                file.file_type,
                file.decompressed_size,
                file.flash_offset
            );
            true
        });
    }
}

/// Decompress LZ4 data
///
/// # Arguments
///
/// * `src` - Compressed data
/// * `dst` - Output buffer (must be large enough for decompressed data)
/// * `decompressed_size` - Expected decompressed size
///
/// # Returns
///
/// Number of bytes written to dst, or error.
fn decompress_lz4(
    src: &[u8],
    dst: &mut [u8],
    decompressed_size: usize,
) -> Result<usize, CbfsError> {
    log::debug!(
        "CBFS: LZ4 decompress {} bytes -> {} bytes",
        src.len(),
        decompressed_size
    );

    match lz4_flex::block::decompress_into(src, &mut dst[..decompressed_size]) {
        Ok(size) => {
            log::debug!("CBFS: LZ4 decompressed {} bytes", size);
            Ok(size)
        }
        Err(e) => {
            log::error!("CBFS: LZ4 decompression failed: {:?}", e);
            Err(CbfsError::DecompressionError)
        }
    }
}

/// Decompress ZSTD data
///
/// # Arguments
///
/// * `src` - Compressed data
/// * `dst` - Output buffer (must be large enough for decompressed data)
///
/// # Returns
///
/// Number of bytes written to dst, or error.
fn decompress_zstd(src: &[u8], dst: &mut [u8]) -> Result<usize, CbfsError> {
    log::debug!(
        "CBFS: ZSTD decompress {} bytes -> {} bytes max",
        src.len(),
        dst.len()
    );

    let mut decoder = ruzstd::decoding::FrameDecoder::new();
    match decoder.decode_all(src, dst) {
        Ok(size) => {
            log::debug!("CBFS: ZSTD decompressed {} bytes", size);
            Ok(size)
        }
        Err(e) => {
            log::error!("CBFS: ZSTD decompression failed: {:?}", e);
            Err(CbfsError::DecompressionError)
        }
    }
}

/// Decompress LZMA data
///
/// # Arguments
///
/// * `src` - Compressed data
/// * `dst` - Output buffer (must be large enough for decompressed data)
///
/// # Returns
///
/// Number of bytes written to dst, or error.
fn decompress_lzma(src: &[u8], dst: &mut [u8]) -> Result<usize, CbfsError> {
    use lzma_rust2::{LzmaReader, Read};

    log::debug!(
        "CBFS: LZMA decompress {} bytes -> {} bytes max",
        src.len(),
        dst.len()
    );

    // Create LZMA reader from source slice
    // u32::MAX for mem_limit allows any dictionary size
    let mut reader = match LzmaReader::new_mem_limit(src, u32::MAX, None) {
        Ok(r) => r,
        Err(e) => {
            log::error!("CBFS: LZMA reader creation failed: {:?}", e);
            return Err(CbfsError::DecompressionError);
        }
    };

    // Read decompressed data into destination buffer
    let mut total_read = 0;
    loop {
        match reader.read(&mut dst[total_read..]) {
            Ok(0) => break, // EOF
            Ok(n) => total_read += n,
            Err(e) => {
                log::error!("CBFS: LZMA decompression failed: {:?}", e);
                return Err(CbfsError::DecompressionError);
            }
        }
    }

    log::debug!("CBFS: LZMA decompressed {} bytes", total_read);
    Ok(total_read)
}

/// CBFS errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CbfsError {
    /// File not found
    NotFound,
    /// Buffer too small
    BufferTooSmall,
    /// Decompression failed
    DecompressionError,
    /// IO error
    IoError,
    /// Invalid CBFS structure
    InvalidFormat,
    /// Target address conflicts with CrabEFI's memory (handled via trampoline)
    TargetConflict,
    /// Target address is not in usable RAM
    InvalidTarget,
    /// Failed to allocate bounce buffer
    AllocationFailed,
    /// Trampoline setup or execution failed
    TrampolineFailed,
}

/// Convert flash offset to host memory address
///
/// On x86, flash is memory-mapped at the end of the 4GB address space:
/// `host_addr = 0x100000000 - boot_media_size + flash_offset`
///
/// For example, an 8MB flash would be mapped at:
/// `0x100000000 - 0x800000 = 0xFF800000`
#[inline]
fn flash_to_host_addr(flash_offset: u64, boot_media_size: u64) -> u64 {
    // Flash is mapped just below 4GB (0x100000000)
    // This gives addresses like 0xFF800000 for 8MB flash
    0x100000000u64 - boot_media_size + flash_offset
}

/// Align value up to alignment boundary
#[inline]
const fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

/// Load a stage/payload directly to its target memory address
///
/// This function finds a file by name and decompresses it directly
/// into the memory address specified in its stage header.
///
/// # Arguments
///
/// * `name` - File name to find and load
///
/// # Returns
///
/// The entry point address on success, or None if not found or error.
///
/// # Safety
///
/// See [`Cbfs::load_to_target`] for safety requirements.
pub unsafe fn load_file(name: &str) -> Option<u64> {
    let cbfs = Cbfs::new()?;
    let file = cbfs.find(name)?;
    match cbfs.load_to_target(&file) {
        Ok(entry) => Some(entry),
        Err(e) => {
            log::error!("CBFS: failed to load '{}': {:?}", name, e);
            None
        }
    }
}

/// Parsed self-extracting payload (CBFS_TYPE_SELF)
///
/// Contains all segments that need to be loaded and the entry point.
#[derive(Debug)]
pub struct SelfPayload {
    /// Segments to load (CODE, DATA, BSS)
    pub segments: heapless::Vec<PayloadSegmentInfo, 16>,
    /// Entry point address
    pub entry_point: u64,
}

/// Parsed payload segment information
#[derive(Debug, Clone)]
pub struct PayloadSegmentInfo {
    /// Segment type (CODE, DATA, BSS)
    pub seg_type: PayloadSegmentType,
    /// Compression algorithm
    pub compression: CbfsCompression,
    /// Offset of segment data within the payload file
    pub file_offset: u32,
    /// Memory address to load this segment
    pub load_addr: u64,
    /// Length of compressed data in file
    pub compressed_len: u32,
    /// Length in memory after decompression (includes BSS)
    pub mem_len: u32,
}

/// Payload segment type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadSegmentType {
    Code,
    Data,
    Bss,
    Params,
    Entry,
    Unknown(u32),
}

impl PayloadSegmentType {
    fn from_be(value: u32) -> Self {
        let type_val = u32::from_be(value);
        match type_val {
            payload_segment_types::CODE => Self::Code,
            payload_segment_types::DATA => Self::Data,
            payload_segment_types::BSS => Self::Bss,
            payload_segment_types::PARAMS => Self::Params,
            payload_segment_types::ENTRY => Self::Entry,
            _ => Self::Unknown(type_val),
        }
    }
}

impl Cbfs {
    /// Parse a self-extracting payload (CBFS_TYPE_SELF)
    ///
    /// Self-extracting payloads contain an array of segment headers followed by
    /// the segment data. Each segment can have its own compression.
    ///
    /// # Arguments
    ///
    /// * `file` - File info from `find()` (must be CBFS_TYPE_SELF)
    ///
    /// # Returns
    ///
    /// Parsed payload information including all segments and entry point.
    pub fn parse_self_payload(&self, file: &CbfsFileInfo) -> Result<SelfPayload, CbfsError> {
        if !matches!(file.file_type, CbfsType::Self_) {
            log::error!("CBFS: {} is not a self-extracting payload", file.name);
            return Err(CbfsError::InvalidFormat);
        }

        let mut payload = SelfPayload {
            segments: heapless::Vec::new(),
            entry_point: 0,
        };

        // Read segment headers from the file data
        let data_ptr = file.data_addr as *const u8;
        let mut offset = 0usize;
        let segment_size = size_of::<CbfsPayloadSegment>();

        log::debug!("CBFS: parsing self-extracting payload '{}'", file.name);

        loop {
            if offset + segment_size > file.compressed_size as usize {
                log::error!("CBFS: payload segment header extends beyond file");
                return Err(CbfsError::InvalidFormat);
            }

            let seg_bytes =
                unsafe { core::slice::from_raw_parts(data_ptr.add(offset), segment_size) };

            let Ok((segment, _)) = CbfsPayloadSegment::read_from_prefix(seg_bytes) else {
                log::error!("CBFS: failed to parse payload segment header");
                return Err(CbfsError::InvalidFormat);
            };

            let seg_type = PayloadSegmentType::from_be(segment.seg_type);
            let compression = CbfsCompression::from_be(segment.compression);
            let file_offset = u32::from_be(segment.offset);
            let load_addr = u64::from_be(segment.load_addr);
            let compressed_len = u32::from_be(segment.len);
            let mem_len = u32::from_be(segment.mem_len);

            log::debug!(
                "  Segment {:?}: load={:#x}, file_off={:#x}, len={}, mem={}",
                seg_type,
                load_addr,
                file_offset,
                compressed_len,
                mem_len
            );

            match seg_type {
                PayloadSegmentType::Entry => {
                    // Entry segment - load_addr is the entry point
                    payload.entry_point = load_addr;
                    log::debug!("  Entry point: {:#x}", load_addr);
                    break; // ENTRY is always the last segment
                }
                PayloadSegmentType::Code | PayloadSegmentType::Data => {
                    let seg_info = PayloadSegmentInfo {
                        seg_type,
                        compression,
                        file_offset,
                        load_addr,
                        compressed_len,
                        mem_len,
                    };
                    if payload.segments.push(seg_info).is_err() {
                        log::error!("CBFS: too many payload segments");
                        return Err(CbfsError::InvalidFormat);
                    }
                }
                PayloadSegmentType::Bss => {
                    // BSS segment - just zero memory, no data to copy
                    let seg_info = PayloadSegmentInfo {
                        seg_type,
                        compression: CbfsCompression::None,
                        file_offset: 0,
                        load_addr,
                        compressed_len: 0,
                        mem_len,
                    };
                    if payload.segments.push(seg_info).is_err() {
                        log::error!("CBFS: too many payload segments");
                        return Err(CbfsError::InvalidFormat);
                    }
                }
                PayloadSegmentType::Params => {
                    // PARAMS segment - optional, skip for now
                    log::debug!("  Skipping PARAMS segment");
                }
                PayloadSegmentType::Unknown(t) => {
                    log::warn!("  Unknown segment type: {:#x}", t);
                }
            }

            offset += segment_size;
        }

        if payload.entry_point == 0 {
            log::error!("CBFS: payload has no entry point");
            return Err(CbfsError::InvalidFormat);
        }

        log::info!(
            "CBFS: parsed payload '{}': {} segments, entry={:#x}",
            file.name,
            payload.segments.len(),
            payload.entry_point
        );

        Ok(payload)
    }

    /// Load a self-extracting payload to memory and return entry point
    ///
    /// This loads all CODE/DATA segments (decompressing if needed) and zeroes
    /// BSS segments. If any segment conflicts with CrabEFI's memory, it uses
    /// the trampoline approach.
    ///
    /// # Arguments
    ///
    /// * `file` - File info from `find()` (must be CBFS_TYPE_SELF)
    ///
    /// # Returns
    ///
    /// The entry point address on success, or error.
    /// Note: If a trampoline is used, this function never returns.
    ///
    /// # Safety
    ///
    /// This function writes directly to the target memory addresses.
    pub unsafe fn load_self_payload(&self, file: &CbfsFileInfo) -> Result<u64, CbfsError> {
        let payload = self.parse_self_payload(file)?;

        // Check if any segment conflicts with CrabEFI
        let has_conflict = payload.segments.iter().any(|seg| {
            crate::efi::allocator::conflicts_with_runtime(seg.load_addr, seg.mem_len as u64)
        });

        if has_conflict {
            return self.load_self_payload_with_trampoline(file, &payload);
        }

        // Direct loading - load each segment
        let data_ptr = file.data_addr as *const u8;

        for seg in &payload.segments {
            // Check target is usable
            if !crate::efi::allocator::is_usable_memory(seg.load_addr, seg.mem_len as u64) {
                log::error!(
                    "CBFS: segment target {:#x}-{:#x} is not usable",
                    seg.load_addr,
                    seg.load_addr + seg.mem_len as u64
                );
                return Err(CbfsError::InvalidTarget);
            }

            let target =
                core::slice::from_raw_parts_mut(seg.load_addr as *mut u8, seg.mem_len as usize);

            match seg.seg_type {
                PayloadSegmentType::Bss => {
                    // Just zero the memory
                    log::debug!(
                        "  Zeroing BSS at {:#x}, {} bytes",
                        seg.load_addr,
                        seg.mem_len
                    );
                    target.fill(0);
                }
                PayloadSegmentType::Code | PayloadSegmentType::Data => {
                    let src = core::slice::from_raw_parts(
                        data_ptr.add(seg.file_offset as usize),
                        seg.compressed_len as usize,
                    );

                    let decompressed_size = match seg.compression {
                        CbfsCompression::None => {
                            target[..seg.compressed_len as usize].copy_from_slice(src);
                            seg.compressed_len as usize
                        }
                        CbfsCompression::Lz4 => decompress_lz4(src, target, seg.mem_len as usize)?,
                        CbfsCompression::Lzma => decompress_lzma(src, target)?,
                        CbfsCompression::Zstd => decompress_zstd(src, target)?,
                    };

                    // Zero any BSS (mem_len > decompressed_size)
                    if decompressed_size < seg.mem_len as usize {
                        target[decompressed_size..].fill(0);
                    }

                    log::debug!(
                        "  Loaded {:?} to {:#x}, {} bytes",
                        seg.seg_type,
                        seg.load_addr,
                        decompressed_size
                    );
                }
                _ => {}
            }
        }

        log::info!(
            "CBFS: loaded payload, entry point {:#x}",
            payload.entry_point
        );
        Ok(payload.entry_point)
    }

    /// Load a self-extracting payload using trampoline (when segments conflict)
    ///
    /// This is called when one or more segments would overwrite CrabEFI's memory.
    /// The entire payload is decompressed to a bounce buffer, then the trampoline
    /// copies it to the final location.
    unsafe fn load_self_payload_with_trampoline(
        &self,
        file: &CbfsFileInfo,
        payload: &SelfPayload,
    ) -> Result<u64, CbfsError> {
        use super::trampoline::{self, TrampolineParams};

        let (runtime_start, runtime_end) = crate::efi::allocator::get_runtime_bounds();
        log::warn!(
            "CBFS: payload segments conflict with CrabEFI ({:#x}-{:#x}), using trampoline",
            runtime_start,
            runtime_end
        );

        // For multi-segment payloads with conflicts, we need to:
        // 1. Find the lowest and highest load addresses
        // 2. Allocate a contiguous bounce buffer
        // 3. Load all segments into the bounce buffer at their relative offsets
        // 4. Use trampoline to copy the entire region

        let lowest_addr = payload
            .segments
            .iter()
            .map(|s| s.load_addr)
            .min()
            .unwrap_or(0);
        let highest_end = payload
            .segments
            .iter()
            .map(|s| s.load_addr + s.mem_len as u64)
            .max()
            .unwrap_or(0);
        let total_size = (highest_end - lowest_addr) as usize;

        log::info!(
            "CBFS: payload range {:#x}-{:#x} ({} bytes)",
            lowest_addr,
            highest_end,
            total_size
        );

        // Allocate bounce buffer
        let bounce_buffer = trampoline::allocate_bounce_buffer(total_size).ok_or_else(|| {
            log::error!("CBFS: failed to allocate bounce buffer");
            CbfsError::AllocationFailed
        })?;

        // Zero the entire buffer first (for BSS and gaps)
        bounce_buffer.fill(0);

        // Load each segment into the bounce buffer
        let data_ptr = file.data_addr as *const u8;

        for seg in &payload.segments {
            let offset_in_buffer = (seg.load_addr - lowest_addr) as usize;
            let target =
                &mut bounce_buffer[offset_in_buffer..offset_in_buffer + seg.mem_len as usize];

            match seg.seg_type {
                PayloadSegmentType::Bss => {
                    // Already zeroed
                }
                PayloadSegmentType::Code | PayloadSegmentType::Data => {
                    let src = core::slice::from_raw_parts(
                        data_ptr.add(seg.file_offset as usize),
                        seg.compressed_len as usize,
                    );

                    let decompressed_size = match seg.compression {
                        CbfsCompression::None => {
                            target[..seg.compressed_len as usize].copy_from_slice(src);
                            seg.compressed_len as usize
                        }
                        CbfsCompression::Lz4 => decompress_lz4(src, target, seg.mem_len as usize)?,
                        CbfsCompression::Lzma => decompress_lzma(src, target)?,
                        CbfsCompression::Zstd => decompress_zstd(src, target)?,
                    };

                    log::debug!(
                        "  Loaded {:?} to bounce buffer offset {:#x}, {} bytes",
                        seg.seg_type,
                        offset_in_buffer,
                        decompressed_size
                    );
                }
                _ => {}
            }
        }

        // Get coreboot table pointer for passing to payload
        let cbtable_ptr = crate::state::get_coreboot_table_ptr().unwrap_or(0);

        // Set up trampoline parameters
        let params = TrampolineParams {
            src_addr: bounce_buffer.as_ptr() as u64,
            dst_addr: lowest_addr,
            copy_size: total_size as u64,
            bss_size: 0, // Already zeroed in bounce buffer
            entry_point: payload.entry_point,
            coreboot_table_ptr: cbtable_ptr,
        };

        // Execute the trampoline - this never returns
        // The bounce buffer was allocated via EFI pages, so it stays allocated
        match trampoline::execute_trampoline(&params) {
            Err(e) => {
                log::error!("CBFS: trampoline setup failed: {:?}", e);
                Err(CbfsError::TrampolineFailed)
            }
        }
    }
}

/// Load and execute a self-extracting payload from CBFS
///
/// This is a convenience function that finds a payload by name and executes it.
///
/// # Arguments
///
/// * `name` - Name of the payload file in CBFS
/// * `cbtable_ptr` - Pointer to coreboot tables (passed to payload in RDI)
///
/// # Returns
///
/// This function does not return on success (jumps to payload).
/// Returns an error if the payload cannot be loaded.
///
/// # Safety
///
/// Jumps to the payload entry point and does not return.
pub unsafe fn load_and_execute_payload(name: &str, cbtable_ptr: *const u8) -> Result<!, CbfsError> {
    let cbfs = Cbfs::new().ok_or(CbfsError::NotFound)?;
    let file = cbfs.find(name).ok_or(CbfsError::NotFound)?;

    // Dispatch based on file type
    let entry_point = match file.file_type {
        CbfsType::Self_ => {
            // Self-extracting payload with segments
            cbfs.load_self_payload(&file)?
        }
        CbfsType::Stage => {
            // Stage format - use load_to_target
            cbfs.load_to_target(&file)?
        }
        _ => {
            log::error!("CBFS: {} is not a loadable payload type", name);
            return Err(CbfsError::InvalidFormat);
        }
    };

    log::info!("CBFS: jumping to payload at {:#x}", entry_point);

    // Jump to the payload (switches to 32-bit mode since coreboot payloads expect it)
    jump_to_payload_32bit(entry_point, cbtable_ptr as u64);
}

/// Jump to a 32-bit payload, switching from 64-bit long mode to 32-bit protected mode
///
/// Coreboot payloads (SeaBIOS, etc.) expect to be entered in 32-bit protected mode
/// with the coreboot table pointer in EBX.
///
/// # Safety
///
/// This function never returns. It switches CPU mode and jumps to the entry point.
unsafe fn jump_to_payload_32bit(entry_point: u64, cbtable_ptr: u64) -> ! {
    // We reuse the trampoline's mode-switching code
    // Create params that don't need to copy anything (src=dst, size=0)
    use super::trampoline::{self, TrampolineParams};

    let params = TrampolineParams {
        src_addr: 0,
        dst_addr: 0,
        copy_size: 0,
        bss_size: 0,
        entry_point,
        coreboot_table_ptr: cbtable_ptr,
    };

    // This never returns
    match trampoline::execute_trampoline(&params) {
        Err(e) => {
            log::error!("Failed to jump to payload: {:?}", e);
            panic!("Failed to execute payload");
        }
    }
}

/// Discovered CBFS payload entry for the boot menu
#[derive(Debug, Clone)]
pub struct CbfsPayloadEntry {
    /// Display name for the menu
    pub name: String,
    /// File name in CBFS
    pub cbfs_name: String,
    /// File type
    pub file_type: CbfsType,
    /// File size (compressed)
    pub size: u32,
}

/// Discover bootable payloads in CBFS
///
/// Scans CBFS for files that can be chainloaded:
/// - CBFS_TYPE_SELF (self-extracting payloads like SeaBIOS)
/// - CBFS_TYPE_STAGE (stage files with stage headers)
/// - CBFS_TYPE_FIT_PAYLOAD (Flat Image Tree payloads)
///
/// # Returns
///
/// A vector of discovered payload entries.
pub fn discover_payloads() -> heapless::Vec<CbfsPayloadEntry, 16> {
    let mut entries = heapless::Vec::new();

    let Some(cbfs) = Cbfs::new() else {
        log::debug!("CBFS not available for payload discovery");
        return entries;
    };

    cbfs.for_each(|file| {
        // Log all files found (INFO for now to debug discovery)
        log::info!(
            "CBFS file: '{}' type={:?} size={}",
            file.name,
            file.file_type,
            file.decompressed_size
        );

        // Check if this is a bootable payload type
        // - Self_ = self-extracting payloads (SeaBIOS, etc.)
        // - FitPayload = Flat Image Tree payloads
        // Note: Stage type is for internal coreboot stages (romstage, ramstage, etc.), not user payloads
        let is_bootable = matches!(file.file_type, CbfsType::Self_ | CbfsType::FitPayload);

        if !is_bootable {
            log::debug!("  -> skipped (type {:?} is not bootable)", file.file_type);
            return true; // Continue
        }

        if is_bootable {
            // Create a display name from the file name
            let display_name = create_display_name(&file.name, file.file_type);

            let entry = CbfsPayloadEntry {
                name: display_name,
                cbfs_name: file.name.clone(),
                file_type: file.file_type,
                size: file.decompressed_size,
            };

            log::info!(
                "CBFS: discovered payload '{}' ({:?}, {} KB)",
                entry.name,
                file.file_type,
                file.decompressed_size / 1024
            );

            let _ = entries.push(entry);
        }

        true // Continue iterating
    });

    // Count total files for logging
    let mut total_files = 0;
    cbfs.for_each(|_| {
        total_files += 1;
        true
    });

    log::info!(
        "CBFS: {} total files, {} bootable payloads",
        total_files,
        entries.len()
    );
    entries
}

/// Create a user-friendly display name from a CBFS file name
fn create_display_name(cbfs_name: &str, file_type: CbfsType) -> String {
    let mut name = String::new();

    // Known payload names with friendly descriptions
    let known_payloads = [
        ("seabios", "SeaBIOS (Legacy BIOS)"),
        ("coreinfo", "Coreinfo (Diagnostics)"),
        ("nvramcui", "NVRAM Configuration"),
        ("tint", "TINT Game"),
        ("memtest", "Memtest86+"),
        ("linuxboot", "LinuxBoot"),
        ("uroot", "u-root"),
        ("edk2", "EDK2 UEFI"),
        ("tianocore", "TianoCore UEFI"),
        ("grub", "GRUB2 Bootloader"),
        ("depthcharge", "Depthcharge"),
    ];

    let lower_name = cbfs_name.to_ascii_lowercase();
    for (pattern, friendly_name) in known_payloads {
        if lower_name.contains(pattern) {
            name.push_str(friendly_name);
            return name;
        }
    }

    // Generate a name from the file name
    name.push_str("Payload: ");
    name.push_str(cbfs_name);

    // Add type suffix if not obvious
    match file_type {
        CbfsType::Self_ => {
            // Usually obvious
        }
        CbfsType::Stage => {
            name.push_str(" (Stage)");
        }
        CbfsType::FitPayload => {
            name.push_str(" (FIT)");
        }
        _ => {}
    }

    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flash_to_host_addr() {
        // 16MB flash, CBFS at offset 0x200000
        let boot_media_size = 16 * 1024 * 1024;
        let flash_offset = 0x200000;

        let host_addr = flash_to_host_addr(flash_offset, boot_media_size);

        // Expected: 0x100000000 - 0x1000000 + 0x200000 = 0xFF200000
        assert_eq!(host_addr, 0xFF200000);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 64), 0);
        assert_eq!(align_up(1, 64), 64);
        assert_eq!(align_up(63, 64), 64);
        assert_eq!(align_up(64, 64), 64);
        assert_eq!(align_up(65, 64), 128);
    }
}
