//! ISO9660 / El Torito Boot Support
//!
//! This module provides parsing of ISO9660 images to find the EFI boot image
//! via the El Torito boot specification. This enables booting from Windows/Linux
//! installation ISOs that use El Torito for UEFI boot support.
//!
//! # El Torito Structure
//!
//! - Boot Record Volume Descriptor at sector 17 (byte offset 34816)
//! - Boot Catalog at a sector specified in the BRVD
//! - EFI boot image referenced in the boot catalog (platform ID 0xEF)

use crate::drivers::block::{BlockDevice, BlockError};

/// ISO9660 sector size (always 2048 bytes)
pub const ISO_SECTOR_SIZE: usize = 2048;

/// El Torito boot record volume descriptor sector
const BOOT_RECORD_SECTOR: u64 = 17;

/// El Torito signature
const EL_TORITO_SIGNATURE: &[u8] = b"EL TORITO SPECIFICATION";

/// CD001 signature for volume descriptors
const CD001_SIGNATURE: &[u8] = b"CD001";

/// EFI platform ID in El Torito
const PLATFORM_EFI: u8 = 0xEF;

/// El Torito boot catalog entry - Validation Entry
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct ValidationEntry {
    header_id: u8,   // Must be 0x01
    platform_id: u8, // 0 = x86, 1 = PowerPC, 2 = Mac, 0xEF = EFI
    reserved: u16,
    manufacturer: [u8; 24],
    checksum: u16,
    key55: u8, // Must be 0x55
    keyaa: u8, // Must be 0xAA
}

/// El Torito boot catalog entry - Initial/Default or Section Entry
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct BootEntry {
    boot_indicator: u8,  // 0x88 = bootable, 0x00 = not bootable
    boot_media_type: u8, // 0 = no emulation, 1 = 1.2M floppy, etc.
    load_segment: u16,
    system_type: u8,
    reserved: u8,
    sector_count: u16,
    load_rba: u32, // LBA of boot image (in 2048-byte sectors)
    reserved2: [u8; 20],
}

/// El Torito section header
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct SectionHeader {
    header_indicator: u8, // 0x90 = more sections, 0x91 = final section
    platform_id: u8,
    section_entries: u16,
    section_id: [u8; 28],
}

/// Information about an El Torito EFI boot image
#[derive(Debug, Clone, Copy)]
pub struct EfiBootImage {
    /// Starting sector of the EFI boot image (in device blocks)
    pub start_sector: u64,
    /// Size in sectors (in device blocks) - may be 0 if not specified
    pub sector_count: u32,
    /// Size in bytes of the boot image
    pub size_bytes: u64,
}

/// Error type for ISO9660/El Torito operations
#[derive(Debug)]
pub enum IsoError {
    /// Read error from storage device
    ReadError,
    /// Not an ISO9660 image
    NotIso9660,
    /// No El Torito boot record found
    NoElTorito,
    /// No EFI boot entry found
    NoEfiEntry,
    /// Invalid boot catalog
    InvalidCatalog,
}

impl From<BlockError> for IsoError {
    fn from(_: BlockError) -> Self {
        IsoError::ReadError
    }
}

/// Read the FAT BPB from the start of a boot image to determine its actual size.
///
/// El Torito `sector_count` is often 0 or 1 for EFI images (meaning "entire image").
/// The real size must be determined from the embedded FAT filesystem's BPB.
///
/// # Arguments
/// * `device` - Block device to read from
/// * `image_start_device_block` - Start of the boot image in device blocks
///
/// # Returns
/// The image size in bytes, or `None` if the BPB couldn't be read/parsed.
fn probe_fat_image_size(
    device: &mut dyn BlockDevice,
    image_start_device_block: u64,
) -> Option<u64> {
    let block_size = device.info().block_size as usize;
    let mut buf = [0u8; ISO_SECTOR_SIZE];

    // Read enough to cover the BPB (first 512 bytes minimum)
    if block_size <= ISO_SECTOR_SIZE {
        let blocks_needed = ISO_SECTOR_SIZE / block_size;
        for i in 0..blocks_needed {
            let offset = i * block_size;
            if device
                .read_block(
                    image_start_device_block + i as u64,
                    &mut buf[offset..offset + block_size],
                )
                .is_err()
            {
                return None;
            }
        }
    } else {
        let mut big_buf = [0u8; 4096];
        if device
            .read_block(image_start_device_block, &mut big_buf[..block_size])
            .is_err()
        {
            return None;
        }
        buf.copy_from_slice(&big_buf[..ISO_SECTOR_SIZE]);
    }

    // Parse BPB fields directly (bytes_per_sector at offset 11, total_sectors_16 at 19, total_sectors_32 at 32)
    let bytes_per_sector = u16::from_le_bytes([buf[11], buf[12]]) as u64;
    let total_sectors_16 = u16::from_le_bytes([buf[19], buf[20]]) as u64;
    let total_sectors_32 = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]) as u64;

    // Sanity check
    if bytes_per_sector == 0 || (bytes_per_sector & (bytes_per_sector - 1)) != 0 {
        return None;
    }

    let total_sectors = if total_sectors_16 != 0 {
        total_sectors_16
    } else {
        total_sectors_32
    };

    if total_sectors == 0 {
        return None;
    }

    let size = total_sectors * bytes_per_sector;
    log::debug!(
        "El Torito: FAT BPB probe: {} sectors x {} bytes = {} bytes",
        total_sectors,
        bytes_per_sector,
        size
    );
    Some(size)
}

/// Check if a device contains an ISO9660 image with El Torito EFI boot support
///
/// Returns the EFI boot image location if found.
pub fn find_efi_boot_image(device: &mut dyn BlockDevice) -> Result<EfiBootImage, IsoError> {
    let info = device.info();
    let block_size = info.block_size as usize;

    // For non-2048 byte devices, we need to calculate the right sector
    let sectors_per_iso_sector = ISO_SECTOR_SIZE / block_size;

    // Read the Boot Record Volume Descriptor (sector 17 in ISO terms)
    let brvd_device_sector = BOOT_RECORD_SECTOR * sectors_per_iso_sector as u64;

    let mut buffer = [0u8; ISO_SECTOR_SIZE];

    // Read the BRVD - may need multiple device sectors for 512-byte devices
    if block_size < ISO_SECTOR_SIZE {
        for i in 0..sectors_per_iso_sector {
            let offset = i * block_size;
            device.read_block(
                brvd_device_sector + i as u64,
                &mut buffer[offset..offset + block_size],
            )?;
        }
    } else {
        device.read_block(brvd_device_sector, &mut buffer[..block_size])?;
    }

    // Check for CD001 signature at offset 1
    if &buffer[1..6] != CD001_SIGNATURE {
        log::debug!("ISO9660: No CD001 signature at sector 17");
        return Err(IsoError::NotIso9660);
    }

    // Check boot record type (0) and El Torito signature
    if buffer[0] != 0 {
        log::debug!("ISO9660: Not a boot record volume descriptor");
        return Err(IsoError::NoElTorito);
    }

    if &buffer[7..7 + EL_TORITO_SIGNATURE.len()] != EL_TORITO_SIGNATURE {
        log::debug!("ISO9660: No El Torito signature");
        return Err(IsoError::NoElTorito);
    }

    // Get boot catalog sector (little-endian 32-bit at offset 0x47)
    let catalog_sector =
        u32::from_le_bytes([buffer[0x47], buffer[0x48], buffer[0x49], buffer[0x4A]]);
    log::debug!("El Torito: Boot catalog at ISO sector {}", catalog_sector);

    // Read the boot catalog
    let catalog_device_sector = catalog_sector as u64 * sectors_per_iso_sector as u64;

    if block_size < ISO_SECTOR_SIZE {
        for i in 0..sectors_per_iso_sector {
            let offset = i * block_size;
            device.read_block(
                catalog_device_sector + i as u64,
                &mut buffer[offset..offset + block_size],
            )?;
        }
    } else {
        device.read_block(catalog_device_sector, &mut buffer[..block_size])?;
    }

    // Parse validation entry (first 32 bytes)
    let validation = unsafe { &*(buffer.as_ptr() as *const ValidationEntry) };

    if validation.header_id != 0x01 || validation.key55 != 0x55 || validation.keyaa != 0xAA {
        log::debug!("El Torito: Invalid validation entry");
        return Err(IsoError::InvalidCatalog);
    }

    log::debug!(
        "El Torito: Validation entry OK, platform={:#x}",
        validation.platform_id
    );

    // Check if the initial/default entry is EFI
    let default_entry = unsafe { &*(buffer.as_ptr().add(32) as *const BootEntry) };

    if validation.platform_id == PLATFORM_EFI && default_entry.boot_indicator == 0x88 {
        let load_rba = default_entry.load_rba;
        let sector_count = default_entry.sector_count as u32;

        log::info!(
            "El Torito: Found EFI boot image at ISO sector {}, count={}",
            load_rba,
            sector_count
        );

        return Ok(build_efi_boot_image(
            device,
            load_rba,
            sector_count,
            sectors_per_iso_sector,
            block_size,
        ));
    }

    // Scan section entries for EFI platform
    let mut offset = 64usize; // Start after validation + default entry

    while offset + 32 <= ISO_SECTOR_SIZE {
        let header = unsafe { &*(buffer.as_ptr().add(offset) as *const SectionHeader) };

        // Check if this is a section header
        let indicator = header.header_indicator;
        if indicator != 0x90 && indicator != 0x91 {
            // Not a section header, might be end of catalog
            break;
        }

        let platform = header.platform_id;
        let num_entries = header.section_entries;

        log::debug!(
            "El Torito: Section header at offset {}: platform={:#x}, entries={}",
            offset,
            platform,
            num_entries
        );

        offset += 32;

        // Check entries in this section
        for _ in 0..num_entries {
            if offset + 32 > ISO_SECTOR_SIZE {
                break;
            }

            let entry = unsafe { &*(buffer.as_ptr().add(offset) as *const BootEntry) };

            if platform == PLATFORM_EFI && entry.boot_indicator == 0x88 {
                let load_rba = entry.load_rba;
                let sector_count = entry.sector_count as u32;

                log::info!(
                    "El Torito: Found EFI boot image at ISO sector {}, count={}",
                    load_rba,
                    sector_count
                );

                return Ok(build_efi_boot_image(
                    device,
                    load_rba,
                    sector_count,
                    sectors_per_iso_sector,
                    block_size,
                ));
            }

            offset += 32;
        }

        // If this was the last section, stop
        if indicator == 0x91 {
            break;
        }
    }

    log::debug!("El Torito: No EFI boot entry found");
    Err(IsoError::NoEfiEntry)
}

/// Build an [`EfiBootImage`] from El Torito catalog fields.
///
/// When the catalog's `sector_count` is 0 or 1, the El Torito spec says the
/// entry covers "the entire image" — the actual size must be determined by
/// probing the FAT BPB at the start of the boot image.
fn build_efi_boot_image(
    device: &mut dyn BlockDevice,
    load_rba: u32,
    sector_count: u32,
    sectors_per_iso_sector: usize,
    block_size: usize,
) -> EfiBootImage {
    let start_device_block = load_rba as u64 * sectors_per_iso_sector as u64;

    if sector_count > 1 {
        // Catalog gives a trustworthy size
        return EfiBootImage {
            start_sector: start_device_block,
            sector_count: sector_count * sectors_per_iso_sector as u32,
            size_bytes: sector_count as u64 * ISO_SECTOR_SIZE as u64,
        };
    }

    // sector_count is 0 or 1 — probe the embedded FAT image for its real size
    if let Some(size_bytes) = probe_fat_image_size(device, start_device_block) {
        // Round up to whole device blocks
        let device_blocks = size_bytes.div_ceil(block_size as u64);
        log::info!(
            "El Torito: probed FAT image size = {} bytes ({} device blocks)",
            size_bytes,
            device_blocks
        );
        return EfiBootImage {
            start_sector: start_device_block,
            sector_count: device_blocks as u32,
            size_bytes,
        };
    }

    // Couldn't probe — fall back to the catalog value (best effort)
    log::warn!(
        "El Torito: could not probe FAT image size, using catalog sector_count={}",
        sector_count
    );
    EfiBootImage {
        start_sector: start_device_block,
        sector_count: if sector_count > 0 {
            sector_count * sectors_per_iso_sector as u32
        } else {
            0
        },
        size_bytes: sector_count as u64 * ISO_SECTOR_SIZE as u64,
    }
}

/// Check if a device looks like an ISO9660 image
pub fn is_iso9660(device: &mut dyn BlockDevice) -> bool {
    let info = device.info();
    let block_size = info.block_size as usize;
    let sectors_per_iso_sector = ISO_SECTOR_SIZE / block_size;

    // Check for Primary Volume Descriptor at sector 16
    let pvd_sector = 16 * sectors_per_iso_sector as u64;

    let mut buffer = [0u8; 8];

    // Just read enough to check the signature
    if device.read_block(pvd_sector, &mut buffer).is_err() {
        return false;
    }

    // Check for CD001 signature at offset 1
    &buffer[1..6] == CD001_SIGNATURE
}
