//! PE32+ loader
//!
//! This module provides a loader for PE32+ executables (EFI applications).
//! It supports loading, relocating, and executing UEFI applications.
//!
//! # Security
//!
//! This loader validates all bounds before accessing untrusted PE data to prevent:
//! - Out-of-bounds reads from malformed headers
//! - Arbitrary memory writes via crafted relocations
//! - Integer overflows in size calculations

use crate::efi::allocator::{self, AllocateType, MemoryType, PAGE_SIZE};
use r_efi::efi::{Handle, Status, SystemTable};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// DOS header magic "MZ"
const DOS_MAGIC: u16 = 0x5A4D;

/// PE signature "PE\0\0"
const PE_SIGNATURE: u32 = 0x00004550;

/// PE32+ magic
const PE32_PLUS_MAGIC: u16 = 0x020B;

/// Machine type: AMD64
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// Relocation types
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64: u16 = 10;

/// Data directory index for base relocations
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

/// Size of base relocation block header
const BASE_RELOCATION_HEADER_SIZE: usize = 8;

/// Maximum reasonable image size (256 MB) to prevent DoS
const MAX_IMAGE_SIZE: u32 = 256 * 1024 * 1024;

/// Maximum number of sections (reasonable limit)
const MAX_SECTIONS: u16 = 96;

/// Maximum number of data directories
const MAX_DATA_DIRECTORIES: u32 = 16;

/// DOS Header
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct DosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: u32,
}

/// COFF File Header
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CoffHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

/// Optional Header (PE32+)
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct OptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    // Data directories follow
}

/// Data Directory entry
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

/// Section Header
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

/// Base Relocation Block
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct BaseRelocation {
    virtual_address: u32,
    size_of_block: u32,
    // Followed by array of u16 type/offset values
}

/// EFI application entry point type
pub type EfiEntryPoint = extern "efiapi" fn(Handle, *mut SystemTable) -> Status;

/// Loaded PE image information
pub struct LoadedImage {
    /// Base address where image was loaded
    pub image_base: u64,
    /// Size of the loaded image in bytes
    pub image_size: u64,
    /// Entry point address
    pub entry_point: u64,
    /// Number of pages allocated
    pub num_pages: u64,
}

/// Load a PE32+ image from memory
///
/// # Arguments
/// * `data` - Raw PE file data
///
/// # Returns
/// * `Ok(LoadedImage)` - Successfully loaded image info
/// * `Err(Status)` - Error status
///
/// # Security
/// All header fields are validated before use to prevent out-of-bounds access.
pub fn load_image(data: &[u8]) -> Result<LoadedImage, Status> {
    // Parse DOS header using zerocopy
    let dos_header = match DosHeader::ref_from_prefix(data) {
        Ok((h, _)) => h,
        Err(_) => {
            log::error!("PE: Data too small for DOS header");
            return Err(Status::INVALID_PARAMETER);
        }
    };

    // Copy fields to avoid reference to packed struct in log macro
    let dos_magic = dos_header.e_magic;
    let pe_offset_val = dos_header.e_lfanew;

    if dos_magic != DOS_MAGIC {
        log::error!("PE: Invalid DOS magic: {:#x}", dos_magic);
        return Err(Status::INVALID_PARAMETER);
    }

    let pe_offset = pe_offset_val as usize;

    // Validate PE offset doesn't overflow and points within data
    let pe_sig_end = pe_offset.checked_add(4).ok_or_else(|| {
        log::error!("PE: PE offset overflow");
        Status::INVALID_PARAMETER
    })?;
    if pe_sig_end > data.len() {
        log::error!("PE: Invalid PE offset: {}", pe_offset);
        return Err(Status::INVALID_PARAMETER);
    }

    // Check PE signature
    // Safety: We verified pe_offset + 4 <= data.len()
    let pe_sig = unsafe { *(data.as_ptr().add(pe_offset) as *const u32) };
    if pe_sig != PE_SIGNATURE {
        log::error!("PE: Invalid PE signature: {:#x}", pe_sig);
        return Err(Status::INVALID_PARAMETER);
    }

    // Parse COFF header using zerocopy
    let coff_offset = pe_offset.checked_add(4).ok_or(Status::INVALID_PARAMETER)?;
    let coff_header = match CoffHeader::ref_from_prefix(&data[coff_offset..]) {
        Ok((h, _)) => h,
        Err(_) => {
            log::error!("PE: COFF header extends beyond data");
            return Err(Status::INVALID_PARAMETER);
        }
    };
    let coff_end = coff_offset
        .checked_add(core::mem::size_of::<CoffHeader>())
        .ok_or(Status::INVALID_PARAMETER)?;

    // Copy fields to avoid reference to packed struct in log macro
    let machine = coff_header.machine;
    let num_sections = coff_header.number_of_sections;
    let opt_header_size = coff_header.size_of_optional_header;

    if machine != IMAGE_FILE_MACHINE_AMD64 {
        log::error!("PE: Unsupported machine type: {:#x}", machine);
        return Err(Status::UNSUPPORTED);
    }

    // Validate section count is reasonable
    if num_sections > MAX_SECTIONS {
        log::error!("PE: Too many sections: {}", num_sections);
        return Err(Status::INVALID_PARAMETER);
    }

    // Validate optional header is large enough for PE32+
    let opt_offset = coff_end;
    if (opt_header_size as usize) < core::mem::size_of::<OptionalHeader64>() {
        log::error!("PE: Optional header too small for PE32+");
        return Err(Status::INVALID_PARAMETER);
    }

    // Parse optional header using zerocopy
    let opt_header = match OptionalHeader64::ref_from_prefix(&data[opt_offset..]) {
        Ok((h, _)) => h,
        Err(_) => {
            log::error!("PE: Optional header extends beyond data");
            return Err(Status::INVALID_PARAMETER);
        }
    };
    let _opt_end = opt_offset
        .checked_add(opt_header_size as usize)
        .ok_or(Status::INVALID_PARAMETER)?;

    // Copy fields to avoid reference to packed struct in log macro
    let magic = opt_header.magic;
    let image_size = opt_header.size_of_image;
    let image_base_preferred = opt_header.image_base;
    let entry_point_rva = opt_header.address_of_entry_point;
    let size_of_headers = opt_header.size_of_headers;
    let num_data_dirs = opt_header.number_of_rva_and_sizes;

    if magic != PE32_PLUS_MAGIC {
        log::error!("PE: Not a PE32+ image: {:#x}", magic);
        return Err(Status::UNSUPPORTED);
    }

    // Validate image size is reasonable
    if image_size == 0 || image_size > MAX_IMAGE_SIZE {
        log::error!("PE: Invalid image size: {}", image_size);
        return Err(Status::INVALID_PARAMETER);
    }

    // Validate entry point is within image
    if entry_point_rva as u64 >= image_size as u64 {
        log::error!("PE: Entry point outside image bounds");
        return Err(Status::INVALID_PARAMETER);
    }

    // Validate headers size
    if size_of_headers > image_size || size_of_headers as usize > data.len() {
        log::error!("PE: Invalid headers size: {}", size_of_headers);
        return Err(Status::INVALID_PARAMETER);
    }

    // Validate data directories count
    if num_data_dirs > MAX_DATA_DIRECTORIES {
        log::error!("PE: Too many data directories: {}", num_data_dirs);
        return Err(Status::INVALID_PARAMETER);
    }

    log::debug!(
        "PE: image_base={:#x}, size={:#x}, entry_rva={:#x}",
        image_base_preferred,
        image_size,
        entry_point_rva
    );

    // Validate section headers fit within data
    let sections_offset = opt_offset
        .checked_add(opt_header_size as usize)
        .ok_or(Status::INVALID_PARAMETER)?;
    let section_headers_size = (num_sections as usize)
        .checked_mul(core::mem::size_of::<SectionHeader>())
        .ok_or(Status::INVALID_PARAMETER)?;
    let sections_end = sections_offset
        .checked_add(section_headers_size)
        .ok_or(Status::INVALID_PARAMETER)?;
    if sections_end > data.len() {
        log::error!(
            "PE: Section headers extend beyond data (offset={}, size={}, data_len={})",
            sections_offset,
            section_headers_size,
            data.len()
        );
        return Err(Status::INVALID_PARAMETER);
    }

    // Allocate memory for the image
    let num_pages = (image_size as u64).div_ceil(PAGE_SIZE);
    let mut load_addr = 0u64;

    let status = allocator::allocate_pages(
        AllocateType::AllocateAnyPages,
        MemoryType::LoaderCode,
        num_pages,
        &mut load_addr,
    );

    if status != Status::SUCCESS {
        log::error!("PE: Failed to allocate memory: {:?}", status);
        return Err(status);
    }

    log::debug!("PE: Allocated {} pages at {:#x}", num_pages, load_addr);

    // Zero the memory
    // Safety: load_addr is valid and we allocated image_size bytes
    unsafe { core::slice::from_raw_parts_mut(load_addr as *mut u8, image_size as usize).fill(0) };

    // Copy headers (already validated size_of_headers fits in both source and dest)
    // Safety: We validated size_of_headers <= data.len() and <= image_size
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            load_addr as *mut u8,
            size_of_headers as usize,
        );
    }

    // Parse section headers using zerocopy
    // We iterate and parse each section header individually
    let section_data = &data[sections_offset..sections_end];

    // Copy sections with full bounds validation
    for i in 0..num_sections as usize {
        let section_offset = i * core::mem::size_of::<SectionHeader>();
        let section = match SectionHeader::ref_from_prefix(&section_data[section_offset..]) {
            Ok((s, _)) => s,
            Err(_) => break,
        };
        let virt_addr = section.virtual_address;
        let virt_size = section.virtual_size;
        let raw_data_ptr = section.pointer_to_raw_data;
        let raw_data_size = section.size_of_raw_data;

        if raw_data_size == 0 || raw_data_ptr == 0 {
            continue;
        }

        let copy_size = raw_data_size.min(virt_size) as usize;

        // Validate source bounds
        let src_start = raw_data_ptr as usize;
        let src_end = src_start.checked_add(copy_size).ok_or_else(|| {
            log::error!("PE: Section {} source offset overflow", i);
            Status::INVALID_PARAMETER
        })?;
        if src_end > data.len() {
            log::error!(
                "PE: Section {} raw data extends beyond file (ptr={}, size={}, file_len={})",
                i,
                raw_data_ptr,
                copy_size,
                data.len()
            );
            continue; // Skip this section rather than fail entirely
        }

        // Validate destination bounds
        let dst_start = virt_addr as usize;
        let dst_end = dst_start.checked_add(copy_size).ok_or_else(|| {
            log::error!("PE: Section {} destination offset overflow", i);
            Status::INVALID_PARAMETER
        })?;
        if dst_end > image_size as usize {
            log::error!(
                "PE: Section {} extends beyond image (vaddr={}, size={}, image_size={})",
                i,
                virt_addr,
                copy_size,
                image_size
            );
            // Free allocated memory and return error
            let _ = allocator::free_pages(load_addr, num_pages);
            return Err(Status::INVALID_PARAMETER);
        }

        // Safety: We validated both source and destination bounds
        unsafe {
            let src = data.as_ptr().add(src_start);
            let dst = (load_addr as *mut u8).add(dst_start);
            core::ptr::copy_nonoverlapping(src, dst, copy_size);
        }
    }

    // Apply relocations if we loaded at a different address
    let delta = load_addr as i64 - image_base_preferred as i64;
    if delta != 0 {
        // Validate data directories fit within optional header
        let data_dirs_offset = opt_offset
            .checked_add(core::mem::size_of::<OptionalHeader64>())
            .ok_or(Status::INVALID_PARAMETER)?;
        let data_dirs_size = (num_data_dirs as usize)
            .checked_mul(core::mem::size_of::<DataDirectory>())
            .ok_or(Status::INVALID_PARAMETER)?;
        let data_dirs_end = data_dirs_offset
            .checked_add(data_dirs_size)
            .ok_or(Status::INVALID_PARAMETER)?;

        if data_dirs_end > data.len() {
            log::error!("PE: Data directories extend beyond file");
            let _ = allocator::free_pages(load_addr, num_pages);
            return Err(Status::INVALID_PARAMETER);
        }

        // Parse data directories using zerocopy
        let data_dirs_data = &data[data_dirs_offset..data_dirs_end];

        // Apply relocations if the relocation directory exists
        if num_data_dirs as usize > IMAGE_DIRECTORY_ENTRY_BASERELOC {
            let reloc_dir_offset =
                IMAGE_DIRECTORY_ENTRY_BASERELOC * core::mem::size_of::<DataDirectory>();
            let reloc_dir =
                match DataDirectory::ref_from_prefix(&data_dirs_data[reloc_dir_offset..]) {
                    Ok((d, _)) => d,
                    Err(_) => {
                        let _ = allocator::free_pages(load_addr, num_pages);
                        return Err(Status::INVALID_PARAMETER);
                    }
                };
            let reloc_rva = reloc_dir.virtual_address;
            let reloc_size = reloc_dir.size;

            if reloc_rva > 0
                && reloc_size > 0
                && let Err(e) =
                    apply_relocations(load_addr, image_size, reloc_rva, reloc_size, delta)
            {
                log::error!("PE: Failed to apply relocations");
                let _ = allocator::free_pages(load_addr, num_pages);
                return Err(e);
            }
        }
    }

    let entry_point = load_addr + entry_point_rva as u64;

    log::info!(
        "PE: Loaded image at {:#x}, entry point at {:#x}",
        load_addr,
        entry_point
    );

    Ok(LoadedImage {
        image_base: load_addr,
        image_size: image_size as u64,
        entry_point,
        num_pages,
    })
}

/// Apply base relocations with full bounds validation
///
/// # Arguments
/// * `image_base` - Base address where image is loaded
/// * `image_size` - Size of the loaded image
/// * `reloc_rva` - RVA of the relocation directory
/// * `reloc_size` - Size of the relocation directory
/// * `delta` - Difference between preferred and actual load address
fn apply_relocations(
    image_base: u64,
    image_size: u32,
    reloc_rva: u32,
    reloc_size: u32,
    delta: i64,
) -> Result<(), Status> {
    // Validate relocation directory is within image bounds
    let reloc_end = reloc_rva.checked_add(reloc_size).ok_or_else(|| {
        log::error!("PE: Relocation directory size overflow");
        Status::INVALID_PARAMETER
    })?;
    if reloc_end > image_size {
        log::error!(
            "PE: Relocation directory extends beyond image (rva={}, size={}, image_size={})",
            reloc_rva,
            reloc_size,
            image_size
        );
        return Err(Status::INVALID_PARAMETER);
    }

    let mut offset = 0u32;
    // Create a slice from the relocation data in the loaded image
    let reloc_slice = unsafe {
        core::slice::from_raw_parts(
            (image_base + reloc_rva as u64) as *const u8,
            reloc_size as usize,
        )
    };

    while offset < reloc_size {
        // Validate we can read the block header
        let remaining = reloc_size - offset;
        if (remaining as usize) < BASE_RELOCATION_HEADER_SIZE {
            log::warn!("PE: Truncated relocation block header");
            break;
        }

        // Parse relocation block using zerocopy
        let block = match BaseRelocation::ref_from_prefix(&reloc_slice[offset as usize..]) {
            Ok((b, _)) => b,
            Err(_) => {
                log::warn!("PE: Failed to parse relocation block");
                break;
            }
        };
        let block_rva = block.virtual_address;
        let block_size = block.size_of_block;

        if block_size == 0 {
            break;
        }

        // Validate block size is reasonable
        if block_size < BASE_RELOCATION_HEADER_SIZE as u32 {
            log::error!("PE: Relocation block size too small: {}", block_size);
            return Err(Status::INVALID_PARAMETER);
        }

        if block_size > remaining {
            log::error!(
                "PE: Relocation block extends beyond directory (size={}, remaining={})",
                block_size,
                remaining
            );
            return Err(Status::INVALID_PARAMETER);
        }

        let num_entries = (block_size as usize - BASE_RELOCATION_HEADER_SIZE) / 2;

        // Safety: We verified the block fits within the relocation directory
        let entries_start = offset as usize + BASE_RELOCATION_HEADER_SIZE;
        let entries = unsafe {
            core::slice::from_raw_parts(
                reloc_slice[entries_start..].as_ptr() as *const u16,
                num_entries,
            )
        };

        for &entry in entries {
            let reloc_type = entry >> 12;
            let reloc_offset = (entry & 0x0FFF) as u32;

            match reloc_type {
                IMAGE_REL_BASED_ABSOLUTE => {
                    // Padding entry, skip
                }
                IMAGE_REL_BASED_DIR64 => {
                    // Calculate target address and validate it's within image bounds
                    let target_rva = block_rva.checked_add(reloc_offset).ok_or_else(|| {
                        log::error!("PE: Relocation target RVA overflow");
                        Status::INVALID_PARAMETER
                    })?;

                    // Ensure the 8-byte value we're modifying is within bounds
                    let target_end = target_rva.checked_add(8).ok_or_else(|| {
                        log::error!("PE: Relocation target end overflow");
                        Status::INVALID_PARAMETER
                    })?;

                    if target_end > image_size {
                        log::error!(
                            "PE: Relocation target outside image bounds (rva={}, image_size={})",
                            target_rva,
                            image_size
                        );
                        return Err(Status::INVALID_PARAMETER);
                    }

                    let addr = image_base + target_rva as u64;
                    // Safety: We validated addr + 8 is within the image
                    unsafe {
                        let ptr = addr as *mut u64;
                        let value = ptr.read_unaligned();
                        ptr.write_unaligned((value as i64 + delta) as u64);
                    }
                }
                _ => {
                    log::warn!("PE: Unknown relocation type: {}", reloc_type);
                }
            }
        }

        offset += block_size;
    }

    Ok(())
}

/// Execute a loaded PE image
///
/// # Arguments
/// * `image` - The loaded image info
/// * `image_handle` - Handle to pass to the image
/// * `system_table` - System table pointer to pass to the image
///
/// # Returns
/// * Status returned by the image
pub fn execute_image(
    image: &LoadedImage,
    image_handle: Handle,
    system_table: *mut SystemTable,
) -> Status {
    log::info!("PE: Executing image at {:#x}", image.entry_point);

    // Safety: entry_point was validated to be within the image during load_image
    let entry: EfiEntryPoint = unsafe { core::mem::transmute(image.entry_point) };

    // Call the entry point
    let status = entry(image_handle, system_table);

    log::info!("PE: Image returned with status: {:?}", status);

    status
}

/// Unload a PE image and free its memory
pub fn unload_image(image: &LoadedImage) -> Status {
    allocator::free_pages(image.image_base, image.num_pages)
}

#[cfg(test)]
mod tests {
    // Tests would go here
}
