//! FMAP (Flash Map) parsing
//!
//! This module parses the FMAP structure from SPI flash to locate regions
//! like SMMSTORE. FMAP is used by coreboot and ChromeOS to describe the
//! layout of the SPI flash.
//!
//! The FMAP location is obtained from coreboot's LB_TAG_BOOT_MEDIA_PARAMS
//! table entry, which provides the exact offset in flash.
//!
//! # References
//!
//! - https://chromium.googlesource.com/chromiumos/third_party/flashmap/
//! - coreboot/src/commonlib/bsd/include/commonlib/bsd/fmap_serialized.h

use heapless::{String, Vec};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use crate::drivers::spi::{AnySpiController, SpiController};

/// FMAP signature: "__FMAP__"
pub const FMAP_SIGNATURE: &[u8; 8] = b"__FMAP__";

/// Maximum number of FMAP areas we support
pub const MAX_FMAP_AREAS: usize = 64;

/// FMAP header name length
pub const FMAP_NAME_LEN: usize = 32;

/// FMAP version we support
pub const FMAP_VER_MAJOR: u8 = 1;

/// FMAP header structure
///
/// Reference: coreboot/src/commonlib/bsd/include/commonlib/bsd/fmap_serialized.h
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone)]
pub struct FmapHeader {
    /// Signature: "__FMAP__"
    pub signature: [u8; 8],
    /// Major version (should be 1)
    pub ver_major: u8,
    /// Minor version
    pub ver_minor: u8,
    /// Base address of the firmware binary
    pub base: u64,
    /// Size of firmware binary in bytes
    pub size: u32,
    /// ASCII name of the firmware binary
    pub name: [u8; FMAP_NAME_LEN],
    /// Number of areas described by this FMAP
    pub nareas: u16,
}

/// FMAP area descriptor
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone)]
pub struct FmapArea {
    /// Offset of the area from flash base (in bytes)
    pub offset: u32,
    /// Size of the area in bytes
    pub size: u32,
    /// ASCII name of the area
    pub name: [u8; FMAP_NAME_LEN],
    /// Flags (see FMAP_AREA_* constants)
    pub flags: u16,
}

/// FMAP area flag: area is static (not updated after initial programming)
pub const FMAP_AREA_STATIC: u16 = 1 << 0;
/// FMAP area flag: area is compressed
pub const FMAP_AREA_COMPRESSED: u16 = 1 << 1;
/// FMAP area flag: area is read-only
pub const FMAP_AREA_RO: u16 = 1 << 2;
/// FMAP area flag: area is preserved across updates
pub const FMAP_AREA_PRESERVE: u16 = 1 << 3;

/// Size of FMAP header in bytes
pub const FMAP_HEADER_SIZE: usize = core::mem::size_of::<FmapHeader>();

/// Size of FMAP area descriptor in bytes
pub const FMAP_AREA_SIZE: usize = core::mem::size_of::<FmapArea>();

/// Parsed FMAP information
#[derive(Debug, Clone)]
pub struct FmapInfo {
    /// Base address of the firmware
    pub base: u64,
    /// Total size of the firmware
    pub size: u32,
    /// Name of the firmware
    pub name: String<FMAP_NAME_LEN>,
    /// List of areas
    pub areas: Vec<FmapAreaInfo, MAX_FMAP_AREAS>,
}

/// Parsed FMAP area information
#[derive(Debug, Clone)]
pub struct FmapAreaInfo {
    /// Offset from flash base
    pub offset: u32,
    /// Size in bytes
    pub size: u32,
    /// Area name
    pub name: String<FMAP_NAME_LEN>,
    /// Flags
    pub flags: u16,
}

impl FmapHeader {
    /// Check if the signature is valid
    pub fn is_valid(&self) -> bool {
        &self.signature == FMAP_SIGNATURE && self.ver_major == FMAP_VER_MAJOR
    }
}

impl FmapArea {
    /// Get the area name as a string (trimmed of null bytes)
    pub fn name_str(&self) -> &str {
        let len = self
            .name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }
}

/// Convert a byte slice to a heapless String, truncating at null or max length
fn bytes_to_string(bytes: &[u8]) -> String<FMAP_NAME_LEN> {
    let len = bytes
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(bytes.len())
        .min(FMAP_NAME_LEN);

    let mut s = String::new();
    if let Ok(str_slice) = core::str::from_utf8(&bytes[..len]) {
        // heapless::String::push_str returns Err if capacity exceeded, but we've
        // already ensured len <= FMAP_NAME_LEN
        let _ = s.push_str(str_slice);
    }
    s
}

/// Read and parse FMAP from SPI flash
///
/// This function first tries to get the FMAP offset from LB_TAG_BOOT_MEDIA_PARAMS,
/// then falls back to probing at common offsets (0x0 is most common for coreboot).
///
/// # Arguments
///
/// * `spi` - The SPI controller to use for reading flash
///
/// # Returns
///
/// The parsed FMAP info if found, or None if not available.
pub fn read_fmap(spi: &mut AnySpiController) -> Option<FmapInfo> {
    // First try to get FMAP offset from coreboot's boot media params
    if let Some(boot_media) = super::get_boot_media() {
        let fmap_offset = boot_media.fmap_offset as u32;
        log::debug!("Reading FMAP from boot_media offset {:#x}", fmap_offset);
        if let Some(fmap) = parse_fmap_at(spi, fmap_offset) {
            return Some(fmap);
        }
    }

    // Fallback: probe at common FMAP locations
    // FMAP is typically at offset 0 in coreboot flash images
    const FMAP_PROBE_OFFSETS: &[u32] = &[
        0x0,     // Most common: FMAP at start of flash
        0x20000, // Some layouts put FMAP after bootblock
        0x1000,  // Alternative location
    ];

    log::debug!("No boot_media params, probing for FMAP at common offsets...");

    for &offset in FMAP_PROBE_OFFSETS {
        log::trace!("Probing for FMAP at offset {:#x}", offset);
        if let Some(fmap) = parse_fmap_at(spi, offset) {
            log::info!("Found FMAP by probing at offset {:#x}", offset);
            return Some(fmap);
        }
    }

    log::warn!("FMAP not found at any probed offset");
    None
}

/// Parse FMAP at a specific offset in flash
fn parse_fmap_at(spi: &mut AnySpiController, offset: u32) -> Option<FmapInfo> {
    // Read the header
    let mut header_bytes = [0u8; FMAP_HEADER_SIZE];
    if spi.read(offset, &mut header_bytes).is_err() {
        log::warn!("Failed to read FMAP header at {:#x}", offset);
        return None;
    }

    // Parse header
    let Ok((header, _)) = FmapHeader::read_from_prefix(&header_bytes) else {
        log::warn!("Failed to parse FMAP header");
        return None;
    };

    // Check signature and version
    if !header.is_valid() {
        log::warn!("Invalid FMAP signature or version at {:#x}", offset);
        return None;
    }

    let nareas = header.nareas as usize;
    if nareas > MAX_FMAP_AREAS {
        log::warn!("FMAP has too many areas: {}", nareas);
        return None;
    }

    // Copy packed fields to local variables to avoid unaligned access in log macros
    let header_base = header.base;
    let header_size = header.size;

    log::info!(
        "FMAP found at {:#x}: {} areas, base={:#x}, size={} MB",
        offset,
        nareas,
        header_base,
        header_size / (1024 * 1024)
    );

    // Read all area descriptors
    let Some(areas_size) = nareas.checked_mul(FMAP_AREA_SIZE) else {
        log::warn!("FMAP areas size overflow");
        return None;
    };
    let mut areas_bytes = alloc::vec![0u8; areas_size];

    let Some(areas_offset) = offset.checked_add(FMAP_HEADER_SIZE as u32) else {
        log::warn!("FMAP areas offset overflow");
        return None;
    };
    if spi.read(areas_offset, &mut areas_bytes).is_err() {
        log::warn!("Failed to read FMAP areas");
        return None;
    }

    // Parse areas
    let mut areas: Vec<FmapAreaInfo, MAX_FMAP_AREAS> = Vec::new();
    let mut remaining = areas_bytes.as_slice();

    for _ in 0..nareas {
        let Ok((area, rest)) = FmapArea::read_from_prefix(remaining) else {
            break;
        };

        // Copy packed fields to local variables to avoid unaligned access
        let area_offset = area.offset;
        let area_size = area.size;
        let area_flags = area.flags;
        let name = bytes_to_string(&area.name);

        log::trace!(
            "  FMAP area: {} at {:#x}, size {} KB",
            name.as_str(),
            area_offset,
            area_size / 1024
        );

        let area_info = FmapAreaInfo {
            offset: area_offset,
            size: area_size,
            name,
            flags: area_flags,
        };

        if areas.push(area_info).is_err() {
            log::warn!("Too many FMAP areas, truncating");
            break;
        }

        remaining = rest;
    }

    // Get firmware name
    let name = bytes_to_string(&header.name);

    Some(FmapInfo {
        base: header_base,
        size: header_size,
        name,
        areas,
    })
}

/// Find a specific region in the FMAP by name
///
/// Common region names include:
/// - "SMMSTORE" - UEFI variable storage
/// - "RW_NVRAM" - Alternate name for variable storage
/// - "COREBOOT" - Main coreboot region
/// - "FMAP" - The FMAP itself
///
/// # Arguments
///
/// * `fmap` - The parsed FMAP info
/// * `name` - The region name to search for (case-insensitive)
///
/// # Returns
///
/// The area info if found, or None if not found.
pub fn find_region<'a>(fmap: &'a FmapInfo, name: &str) -> Option<&'a FmapAreaInfo> {
    fmap.areas
        .iter()
        .find(|area| area.name.as_str().eq_ignore_ascii_case(name))
}

/// Find the SMMSTORE region in the FMAP
///
/// This function searches for common names used for the UEFI variable store:
/// - "SMMSTORE" (standard coreboot name)
/// - "RW_NVRAM" (ChromeOS name)
/// - "NVRAM" (alternative name)
///
/// # Arguments
///
/// * `fmap` - The parsed FMAP info
///
/// # Returns
///
/// The SMMSTORE area info if found, or None if not found.
pub fn find_smmstore_region(fmap: &FmapInfo) -> Option<&FmapAreaInfo> {
    // Try common names for the SMMSTORE region
    const SMMSTORE_NAMES: &[&str] = &["SMMSTORE", "RW_NVRAM", "NVRAM", "RW_ELOG"];

    for name in SMMSTORE_NAMES {
        if let Some(area) = find_region(fmap, name) {
            log::info!(
                "Found SMMSTORE region '{}' at {:#x}, size {} KB",
                area.name.as_str(),
                area.offset,
                area.size / 1024
            );
            return Some(area);
        }
    }

    None
}

/// SMMSTORE information derived from FMAP
///
/// This is a simpler structure specifically for the SMMSTORE region,
/// compatible with what the persistence layer needs.
#[derive(Debug, Clone)]
pub struct FmapSmmstoreInfo {
    /// Offset in flash where SMMSTORE starts
    pub offset: u32,
    /// Size of the SMMSTORE region in bytes
    pub size: u32,
    /// Name of the region (for logging)
    pub name: String<FMAP_NAME_LEN>,
}

/// Find and return SMMSTORE info from FMAP
///
/// This function reads the FMAP from flash (using the offset from coreboot tables)
/// and looks for the SMMSTORE region.
///
/// # Arguments
///
/// * `spi` - The SPI controller to use for reading flash
///
/// # Returns
///
/// SMMSTORE info if found, or None if FMAP not available or SMMSTORE region not present.
pub fn get_smmstore_from_fmap(spi: &mut AnySpiController) -> Option<FmapSmmstoreInfo> {
    // Read and parse FMAP using offset from coreboot tables
    let fmap = read_fmap(spi)?;

    // Find SMMSTORE region
    let region = find_smmstore_region(&fmap)?;

    Some(FmapSmmstoreInfo {
        offset: region.offset,
        size: region.size,
        name: region.name.clone(),
    })
}
