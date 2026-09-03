//! EFI Boot Services memory allocation.
//!
//! Thin wrappers translating the EFI allocator API onto
//! [`super::super::allocator`].

use super::super::allocator::{self, AllocateType, MemoryDescriptor, MemoryType};
use core::ffi::c_void;
use r_efi::efi::{self, Status};

// ============================================================================
// Memory Allocation Functions
// ============================================================================

pub(super) extern "efiapi" fn allocate_pages(
    alloc_type: efi::AllocateType,
    memory_type: efi::MemoryType,
    pages: usize,
    memory: *mut efi::PhysicalAddress,
) -> Status {
    log::debug!(
        "BS.AllocatePages(type={}, mem_type={}, pages={}, addr={:#x})",
        alloc_type,
        memory_type,
        pages,
        if memory.is_null() {
            0
        } else {
            unsafe { *memory }
        }
    );

    if memory.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let alloc_type = match AllocateType::try_from(alloc_type) {
        Ok(t) => t,
        Err(e) => {
            log::debug!("BS.AllocatePages: {e}");
            return Status::INVALID_PARAMETER;
        }
    };

    let mem_type = match MemoryType::try_from(memory_type) {
        Ok(t) => t,
        Err(e) => {
            log::debug!("BS.AllocatePages: {e}");
            return Status::INVALID_PARAMETER;
        }
    };

    let mut addr = unsafe { *memory };
    let status = allocator::allocate_pages(alloc_type, mem_type, pages as u64, &mut addr);

    if status == Status::SUCCESS {
        unsafe { *memory = addr };
        log::debug!("  -> allocated at {:#x}", addr);
    } else {
        log::warn!("  -> failed: {:?}", status);
    }

    status
}

pub(super) extern "efiapi" fn free_pages(memory: efi::PhysicalAddress, pages: usize) -> Status {
    allocator::free_pages(memory, pages as u64)
}

pub(super) extern "efiapi" fn get_memory_map(
    memory_map_size: *mut usize,
    memory_map: *mut efi::MemoryDescriptor,
    map_key: *mut usize,
    descriptor_size: *mut usize,
    descriptor_version: *mut u32,
) -> Status {
    log::debug!(
        "BS.GetMemoryMap(buf_size={:?}, map={:?})",
        if memory_map_size.is_null() {
            0
        } else {
            unsafe { *memory_map_size }
        },
        memory_map
    );

    if memory_map_size.is_null()
        || map_key.is_null()
        || descriptor_size.is_null()
        || descriptor_version.is_null()
    {
        return Status::INVALID_PARAMETER;
    }

    let mut size = unsafe { *memory_map_size };
    let mut key = 0usize;
    let mut desc_size = 0usize;
    let mut desc_version = 0u32;

    // Convert memory_map pointer to a slice if not null
    let map_opt = if memory_map.is_null() {
        None
    } else {
        let num_entries = size / core::mem::size_of::<MemoryDescriptor>();
        Some(unsafe {
            core::slice::from_raw_parts_mut(memory_map as *mut MemoryDescriptor, num_entries)
        })
    };

    let status = allocator::get_memory_map(
        &mut size,
        map_opt,
        &mut key,
        &mut desc_size,
        &mut desc_version,
    );

    unsafe {
        *memory_map_size = size;
        *map_key = key;
        *descriptor_size = desc_size;
        *descriptor_version = desc_version;
    }

    log::debug!("  -> {:?} (size={}, key={:#x})", status, size, key);
    status
}

pub(super) extern "efiapi" fn allocate_pool(
    pool_type: efi::MemoryType,
    size: usize,
    buffer: *mut *mut c_void,
) -> Status {
    log::trace!("BS.AllocatePool(type={}, size={})", pool_type, size);

    if buffer.is_null() || size == 0 {
        return Status::INVALID_PARAMETER;
    }

    let mem_type = match MemoryType::try_from(pool_type) {
        Ok(t) => t,
        Err(e) => {
            log::debug!("BS.AllocatePool: {e}");
            return Status::INVALID_PARAMETER;
        }
    };

    match allocator::allocate_pool(mem_type, size) {
        Ok(ptr) => {
            unsafe { *buffer = ptr as *mut c_void };
            Status::SUCCESS
        }
        Err(status) => status,
    }
}

pub(super) extern "efiapi" fn free_pool(buffer: *mut c_void) -> Status {
    log::trace!("BS.FreePool({:?})", buffer);
    if buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }

    allocator::free_pool(buffer as *mut u8)
}
