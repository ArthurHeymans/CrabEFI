//! PE32+ loader
//!
//! This module provides a loader for PE32+ executables (EFI applications).
//! It supports loading, relocating, and executing UEFI applications.

use crate::efi::allocator::{self, AllocateType, MemoryType, PAGE_SIZE};
use r_efi::efi::{Handle, Status, SystemTable};

/// DOS header magic "MZ"
const DOS_MAGIC: u16 = 0x5A4D;

/// PE signature "PE\0\0"
const PE_SIGNATURE: u32 = 0x00004550;

/// PE32+ magic
const PE32_PLUS_MAGIC: u16 = 0x020B;

/// Machine type: AMD64
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// Section characteristics
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

/// Relocation types
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64: u16 = 10;

/// DOS Header
#[repr(C, packed)]
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
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

/// Section Header
#[repr(C, packed)]
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
pub fn load_image(data: &[u8]) -> Result<LoadedImage, Status> {
    if data.len() < core::mem::size_of::<DosHeader>() {
        log::error!("PE: Data too small for DOS header");
        return Err(Status::INVALID_PARAMETER);
    }

    // Parse DOS header
    let dos_header = unsafe { &*(data.as_ptr() as *const DosHeader) };

    let dos_magic = unsafe { core::ptr::addr_of!(dos_header.e_magic).read_unaligned() };
    if dos_magic != DOS_MAGIC {
        log::error!("PE: Invalid DOS magic: {:#x}", dos_magic);
        return Err(Status::INVALID_PARAMETER);
    }

    let pe_offset = unsafe { core::ptr::addr_of!(dos_header.e_lfanew).read_unaligned() } as usize;
    if pe_offset + 4 > data.len() {
        log::error!("PE: Invalid PE offset");
        return Err(Status::INVALID_PARAMETER);
    }

    // Check PE signature
    let pe_sig = unsafe { *(data.as_ptr().add(pe_offset) as *const u32) };
    if pe_sig != PE_SIGNATURE {
        log::error!("PE: Invalid PE signature: {:#x}", pe_sig);
        return Err(Status::INVALID_PARAMETER);
    }

    // Parse COFF header
    let coff_offset = pe_offset + 4;
    let coff_header = unsafe { &*(data.as_ptr().add(coff_offset) as *const CoffHeader) };

    let machine = unsafe { core::ptr::addr_of!(coff_header.machine).read_unaligned() };
    if machine != IMAGE_FILE_MACHINE_AMD64 {
        log::error!("PE: Unsupported machine type: {:#x}", machine);
        return Err(Status::UNSUPPORTED);
    }

    let num_sections =
        unsafe { core::ptr::addr_of!(coff_header.number_of_sections).read_unaligned() };
    let opt_header_size =
        unsafe { core::ptr::addr_of!(coff_header.size_of_optional_header).read_unaligned() };

    // Parse optional header
    let opt_offset = coff_offset + core::mem::size_of::<CoffHeader>();
    if opt_offset + (opt_header_size as usize) > data.len() {
        log::error!("PE: Optional header extends beyond data");
        return Err(Status::INVALID_PARAMETER);
    }

    let opt_header = unsafe { &*(data.as_ptr().add(opt_offset) as *const OptionalHeader64) };

    let magic = unsafe { core::ptr::addr_of!(opt_header.magic).read_unaligned() };
    if magic != PE32_PLUS_MAGIC {
        log::error!("PE: Not a PE32+ image: {:#x}", magic);
        return Err(Status::UNSUPPORTED);
    }

    let image_size = unsafe { core::ptr::addr_of!(opt_header.size_of_image).read_unaligned() };
    let image_base = unsafe { core::ptr::addr_of!(opt_header.image_base).read_unaligned() };
    let entry_point_rva =
        unsafe { core::ptr::addr_of!(opt_header.address_of_entry_point).read_unaligned() };
    let _section_alignment =
        unsafe { core::ptr::addr_of!(opt_header.section_alignment).read_unaligned() };
    let size_of_headers =
        unsafe { core::ptr::addr_of!(opt_header.size_of_headers).read_unaligned() };
    let num_data_dirs =
        unsafe { core::ptr::addr_of!(opt_header.number_of_rva_and_sizes).read_unaligned() };

    log::debug!(
        "PE: image_base={:#x}, size={:#x}, entry_rva={:#x}",
        image_base,
        image_size,
        entry_point_rva
    );

    // Allocate memory for the image
    let num_pages = ((image_size as u64) + PAGE_SIZE - 1) / PAGE_SIZE;
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
    unsafe {
        core::ptr::write_bytes(load_addr as *mut u8, 0, image_size as usize);
    }

    // Copy headers
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            load_addr as *mut u8,
            size_of_headers as usize,
        );
    }

    // Parse section headers and copy sections
    let sections_offset = opt_offset + (opt_header_size as usize);
    let section_headers = unsafe {
        core::slice::from_raw_parts(
            data.as_ptr().add(sections_offset) as *const SectionHeader,
            num_sections as usize,
        )
    };

    for section in section_headers {
        let virt_addr = unsafe { core::ptr::addr_of!(section.virtual_address).read_unaligned() };
        let virt_size = unsafe { core::ptr::addr_of!(section.virtual_size).read_unaligned() };
        let raw_data_ptr =
            unsafe { core::ptr::addr_of!(section.pointer_to_raw_data).read_unaligned() };
        let raw_data_size =
            unsafe { core::ptr::addr_of!(section.size_of_raw_data).read_unaligned() };

        if raw_data_size > 0 && raw_data_ptr > 0 {
            let src = data.as_ptr() as usize + raw_data_ptr as usize;
            let dst = load_addr as usize + virt_addr as usize;
            let copy_size = raw_data_size.min(virt_size) as usize;

            if src + copy_size <= data.as_ptr() as usize + data.len() {
                unsafe {
                    core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, copy_size);
                }
            }
        }
    }

    // Apply relocations if we loaded at a different address
    let delta = load_addr as i64 - image_base as i64;
    if delta != 0 {
        // Get relocation data directory
        let data_dirs_offset = opt_offset + core::mem::size_of::<OptionalHeader64>();
        let data_dirs = unsafe {
            core::slice::from_raw_parts(
                data.as_ptr().add(data_dirs_offset) as *const DataDirectory,
                num_data_dirs as usize,
            )
        };

        // Relocation directory is index 5
        if num_data_dirs > 5 {
            let reloc_dir = &data_dirs[5];
            let reloc_rva =
                unsafe { core::ptr::addr_of!(reloc_dir.virtual_address).read_unaligned() };
            let reloc_size = unsafe { core::ptr::addr_of!(reloc_dir.size).read_unaligned() };

            if reloc_rva > 0 && reloc_size > 0 {
                apply_relocations(load_addr, reloc_rva, reloc_size, delta)?;
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

/// Apply base relocations
fn apply_relocations(
    image_base: u64,
    reloc_rva: u32,
    reloc_size: u32,
    delta: i64,
) -> Result<(), Status> {
    let mut offset = 0u32;
    let reloc_data = (image_base + reloc_rva as u64) as *const u8;

    while offset < reloc_size {
        let block = unsafe { &*(reloc_data.add(offset as usize) as *const BaseRelocation) };
        let block_rva = unsafe { core::ptr::addr_of!(block.virtual_address).read_unaligned() };
        let block_size = unsafe { core::ptr::addr_of!(block.size_of_block).read_unaligned() };

        if block_size == 0 {
            break;
        }

        let num_entries = (block_size as usize - 8) / 2;
        let entries = unsafe {
            core::slice::from_raw_parts(
                reloc_data.add(offset as usize + 8) as *const u16,
                num_entries,
            )
        };

        for &entry in entries {
            let reloc_type = entry >> 12;
            let reloc_offset = (entry & 0x0FFF) as u32;

            match reloc_type {
                IMAGE_REL_BASED_ABSOLUTE => {
                    // Skip padding entries
                }
                IMAGE_REL_BASED_DIR64 => {
                    let addr = image_base + block_rva as u64 + reloc_offset as u64;
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
