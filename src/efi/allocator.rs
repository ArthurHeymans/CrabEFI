//! EFI Memory Allocator
//!
//! This module implements page-granular memory allocation compatible with the
//! EFI AllocatePages/FreePages API. Memory is tracked using a sorted list of
//! memory descriptors.

use crate::coreboot::memory::{MemoryRegion, MemoryType as CbMemoryType};
use heapless::Vec;
use r_efi::efi;
use spin::Mutex;

/// Maximum number of memory map entries we can track
const MAX_MEMORY_ENTRIES: usize = 256;

/// Page size (4KB)
pub const PAGE_SIZE: u64 = 4096;

/// EFI memory allocation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AllocateType {
    /// Allocate any available pages
    AllocateAnyPages = 0,
    /// Allocate pages below specified address
    AllocateMaxAddress = 1,
    /// Allocate pages at exact specified address
    AllocateAddress = 2,
}

/// EFI memory types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryType {
    ReservedMemoryType = 0,
    LoaderCode = 1,
    LoaderData = 2,
    BootServicesCode = 3,
    BootServicesData = 4,
    RuntimeServicesCode = 5,
    RuntimeServicesData = 6,
    ConventionalMemory = 7,
    UnusableMemory = 8,
    AcpiReclaimMemory = 9,
    AcpiMemoryNvs = 10,
    MemoryMappedIo = 11,
    MemoryMappedIoPortSpace = 12,
    PalCode = 13,
    PersistentMemory = 14,
}

impl MemoryType {
    /// Check if this memory type is available for allocation
    pub fn is_allocatable(&self) -> bool {
        matches!(self, MemoryType::ConventionalMemory)
    }

    /// Check if this memory type should be freed after ExitBootServices
    pub fn is_boot_services(&self) -> bool {
        matches!(
            self,
            MemoryType::BootServicesCode
                | MemoryType::BootServicesData
                | MemoryType::LoaderCode
                | MemoryType::LoaderData
        )
    }

    /// Convert from u32 (for FFI)
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(MemoryType::ReservedMemoryType),
            1 => Some(MemoryType::LoaderCode),
            2 => Some(MemoryType::LoaderData),
            3 => Some(MemoryType::BootServicesCode),
            4 => Some(MemoryType::BootServicesData),
            5 => Some(MemoryType::RuntimeServicesCode),
            6 => Some(MemoryType::RuntimeServicesData),
            7 => Some(MemoryType::ConventionalMemory),
            8 => Some(MemoryType::UnusableMemory),
            9 => Some(MemoryType::AcpiReclaimMemory),
            10 => Some(MemoryType::AcpiMemoryNvs),
            11 => Some(MemoryType::MemoryMappedIo),
            12 => Some(MemoryType::MemoryMappedIoPortSpace),
            13 => Some(MemoryType::PalCode),
            14 => Some(MemoryType::PersistentMemory),
            _ => None,
        }
    }
}

/// Convert coreboot memory type to EFI memory type
fn cb_to_efi_memory_type(cb_type: CbMemoryType) -> MemoryType {
    match cb_type {
        CbMemoryType::Ram => MemoryType::ConventionalMemory,
        CbMemoryType::Reserved => MemoryType::ReservedMemoryType,
        CbMemoryType::AcpiReclaimable => MemoryType::AcpiReclaimMemory,
        CbMemoryType::AcpiNvs => MemoryType::AcpiMemoryNvs,
        CbMemoryType::Unusable => MemoryType::UnusableMemory,
        CbMemoryType::Table => MemoryType::BootServicesData,
    }
}

/// Memory attributes (as defined in UEFI spec)
pub mod attributes {
    pub const EFI_MEMORY_UC: u64 = 0x0000000000000001; // Uncacheable
    pub const EFI_MEMORY_WC: u64 = 0x0000000000000002; // Write-Combining
    pub const EFI_MEMORY_WT: u64 = 0x0000000000000004; // Write-Through
    pub const EFI_MEMORY_WB: u64 = 0x0000000000000008; // Write-Back
    pub const EFI_MEMORY_UCE: u64 = 0x0000000000000010; // Uncacheable, exported
    pub const EFI_MEMORY_WP: u64 = 0x0000000000001000; // Write-Protected
    pub const EFI_MEMORY_RP: u64 = 0x0000000000002000; // Read-Protected
    pub const EFI_MEMORY_XP: u64 = 0x0000000000004000; // Execute-Protected
    pub const EFI_MEMORY_NV: u64 = 0x0000000000008000; // Non-Volatile
    pub const EFI_MEMORY_MORE_RELIABLE: u64 = 0x0000000000010000;
    pub const EFI_MEMORY_RO: u64 = 0x0000000000020000; // Read-Only
    pub const EFI_MEMORY_SP: u64 = 0x0000000000040000; // Specific Purpose
    pub const EFI_MEMORY_CPU_CRYPTO: u64 = 0x0000000000080000;
    pub const EFI_MEMORY_RUNTIME: u64 = 0x8000000000000000; // Runtime accessible
}

/// EFI Memory Descriptor
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryDescriptor {
    /// Type of memory region
    pub memory_type: u32,
    /// Reserved padding
    pub padding: u32,
    /// Physical start address (must be 4KB aligned)
    pub physical_start: u64,
    /// Virtual start address
    pub virtual_start: u64,
    /// Number of 4KB pages
    pub number_of_pages: u64,
    /// Memory attributes
    pub attribute: u64,
}

impl MemoryDescriptor {
    /// Create a new memory descriptor
    pub fn new(
        memory_type: MemoryType,
        physical_start: u64,
        number_of_pages: u64,
        attribute: u64,
    ) -> Self {
        Self {
            memory_type: memory_type as u32,
            padding: 0,
            physical_start,
            virtual_start: 0,
            number_of_pages,
            attribute,
        }
    }

    /// Get the end address (exclusive)
    pub fn end(&self) -> u64 {
        self.physical_start + self.number_of_pages * PAGE_SIZE
    }

    /// Get the memory type as enum
    pub fn get_memory_type(&self) -> Option<MemoryType> {
        MemoryType::from_u32(self.memory_type)
    }
}

/// Memory allocator state
pub struct MemoryAllocator {
    /// Memory map entries, sorted by physical address (ascending)
    entries: Vec<MemoryDescriptor, MAX_MEMORY_ENTRIES>,
    /// Memory map key (incremented on every change)
    map_key: usize,
    /// Whether boot services have exited
    boot_services_exited: bool,
}

impl MemoryAllocator {
    /// Create a new allocator (const fn for static initialization)
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            map_key: 1,
            boot_services_exited: false,
        }
    }

    /// Initialize the allocator from a coreboot memory map
    pub fn init_from_coreboot(&mut self, regions: &[MemoryRegion]) {
        self.entries.clear();
        self.map_key = 1;

        for region in regions {
            let memory_type = cb_to_efi_memory_type(region.region_type);
            let num_pages = (region.size + PAGE_SIZE - 1) / PAGE_SIZE;

            // Default attributes: Write-Back for RAM, uncacheable for others
            let attribute = match memory_type {
                MemoryType::ConventionalMemory
                | MemoryType::BootServicesCode
                | MemoryType::BootServicesData
                | MemoryType::RuntimeServicesCode
                | MemoryType::RuntimeServicesData
                | MemoryType::LoaderCode
                | MemoryType::LoaderData
                | MemoryType::AcpiReclaimMemory => attributes::EFI_MEMORY_WB,
                MemoryType::MemoryMappedIo | MemoryType::MemoryMappedIoPortSpace => {
                    attributes::EFI_MEMORY_UC
                }
                _ => attributes::EFI_MEMORY_WB,
            };

            let desc = MemoryDescriptor::new(memory_type, region.start, num_pages, attribute);

            if self.entries.push(desc).is_err() {
                log::warn!("Memory map full, ignoring region at {:#x}", region.start);
            }
        }

        // Sort by physical address
        self.sort_entries();
        // Merge adjacent regions of the same type
        self.merge_entries();

        log::debug!(
            "Memory allocator initialized with {} entries",
            self.entries.len()
        );
    }

    /// Reserve a region of memory (mark it as a specific type)
    /// This is used to mark our own code/data regions
    pub fn reserve_region(
        &mut self,
        physical_start: u64,
        num_pages: u64,
        memory_type: MemoryType,
    ) -> Result<(), efi::Status> {
        self.carve_out(physical_start, num_pages, memory_type)
    }

    /// Allocate pages of memory
    pub fn allocate_pages(
        &mut self,
        alloc_type: AllocateType,
        memory_type: MemoryType,
        num_pages: u64,
        memory: &mut u64,
    ) -> efi::Status {
        if num_pages == 0 {
            return efi::Status::INVALID_PARAMETER;
        }

        if self.boot_services_exited {
            return efi::Status::UNSUPPORTED;
        }

        let size = num_pages * PAGE_SIZE;

        match alloc_type {
            AllocateType::AllocateAnyPages => {
                // Find any free region that fits
                if let Some(addr) = self.find_free_pages(num_pages, u64::MAX) {
                    match self.carve_out(addr, num_pages, memory_type) {
                        Ok(()) => {
                            *memory = addr;
                            efi::Status::SUCCESS
                        }
                        Err(status) => status,
                    }
                } else {
                    efi::Status::OUT_OF_RESOURCES
                }
            }
            AllocateType::AllocateMaxAddress => {
                // Find free region below the specified address
                let max_addr = *memory;
                if let Some(addr) = self.find_free_pages(num_pages, max_addr) {
                    match self.carve_out(addr, num_pages, memory_type) {
                        Ok(()) => {
                            *memory = addr;
                            efi::Status::SUCCESS
                        }
                        Err(status) => status,
                    }
                } else {
                    efi::Status::OUT_OF_RESOURCES
                }
            }
            AllocateType::AllocateAddress => {
                // Allocate at exact address
                let addr = *memory;
                if addr % PAGE_SIZE != 0 {
                    return efi::Status::INVALID_PARAMETER;
                }

                // Check if the region is available
                if self.is_region_free(addr, size) {
                    match self.carve_out(addr, num_pages, memory_type) {
                        Ok(()) => efi::Status::SUCCESS,
                        Err(status) => status,
                    }
                } else {
                    efi::Status::NOT_FOUND
                }
            }
        }
    }

    /// Free previously allocated pages
    pub fn free_pages(&mut self, memory: u64, num_pages: u64) -> efi::Status {
        if memory % PAGE_SIZE != 0 {
            return efi::Status::INVALID_PARAMETER;
        }

        if num_pages == 0 {
            return efi::Status::INVALID_PARAMETER;
        }

        if self.boot_services_exited {
            return efi::Status::UNSUPPORTED;
        }

        // Find the entry containing this allocation
        let mut found_idx = None;
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.physical_start == memory && entry.number_of_pages == num_pages {
                // Check if this is a type that can be freed
                if let Some(mem_type) = entry.get_memory_type() {
                    if mem_type.is_boot_services() || mem_type == MemoryType::ConventionalMemory {
                        found_idx = Some(idx);
                        break;
                    }
                }
            }
        }

        if let Some(idx) = found_idx {
            // Change the type back to conventional memory
            self.entries[idx].memory_type = MemoryType::ConventionalMemory as u32;
            self.map_key += 1;
            self.merge_entries();
            efi::Status::SUCCESS
        } else {
            efi::Status::NOT_FOUND
        }
    }

    /// Get the current memory map
    pub fn get_memory_map(
        &self,
        memory_map_size: &mut usize,
        memory_map: Option<&mut [MemoryDescriptor]>,
        map_key: &mut usize,
        descriptor_size: &mut usize,
        descriptor_version: &mut u32,
    ) -> efi::Status {
        let entry_size = core::mem::size_of::<MemoryDescriptor>();
        let required_size = self.entries.len() * entry_size;

        *descriptor_size = entry_size;
        *descriptor_version = 1;
        *map_key = self.map_key;

        if let Some(map) = memory_map {
            if map.len() * entry_size < required_size {
                *memory_map_size = required_size;
                return efi::Status::BUFFER_TOO_SMALL;
            }

            for (i, entry) in self.entries.iter().enumerate() {
                if i < map.len() {
                    map[i] = *entry;
                }
            }

            *memory_map_size = required_size;
            efi::Status::SUCCESS
        } else {
            *memory_map_size = required_size;
            efi::Status::BUFFER_TOO_SMALL
        }
    }

    /// Get the current map key
    pub fn map_key(&self) -> usize {
        self.map_key
    }

    /// Get the number of entries
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Mark boot services as exited
    pub fn exit_boot_services(&mut self, provided_map_key: usize) -> efi::Status {
        if provided_map_key != self.map_key {
            return efi::Status::INVALID_PARAMETER;
        }

        self.boot_services_exited = true;

        // Convert boot services memory to conventional memory
        for entry in self.entries.iter_mut() {
            if let Some(mem_type) = entry.get_memory_type() {
                if mem_type.is_boot_services() {
                    entry.memory_type = MemoryType::ConventionalMemory as u32;
                }
            }
        }

        self.map_key += 1;
        self.merge_entries();

        efi::Status::SUCCESS
    }

    /// Find free pages that fit the requirements
    fn find_free_pages(&self, num_pages: u64, max_addr: u64) -> Option<u64> {
        let size = num_pages * PAGE_SIZE;

        // Search from high to low addresses (prefer high memory)
        for entry in self.entries.iter().rev() {
            if entry.get_memory_type() != Some(MemoryType::ConventionalMemory) {
                continue;
            }

            let entry_end = entry.end();
            if entry_end > max_addr {
                // Can we fit below max_addr within this entry?
                let usable_end = max_addr.min(entry_end);
                if usable_end >= entry.physical_start + size {
                    let addr = (usable_end - size) & !(PAGE_SIZE - 1);
                    if addr >= entry.physical_start {
                        return Some(addr);
                    }
                }
            } else if entry.number_of_pages >= num_pages {
                // Allocate from the end of the region
                let addr = entry_end - size;
                if addr >= entry.physical_start {
                    return Some(addr);
                }
            }
        }

        None
    }

    /// Check if a region is free (all pages are ConventionalMemory)
    fn is_region_free(&self, start: u64, size: u64) -> bool {
        let end = start + size;

        for entry in self.entries.iter() {
            if entry.get_memory_type() != Some(MemoryType::ConventionalMemory) {
                continue;
            }

            if entry.physical_start <= start && entry.end() >= end {
                return true;
            }
        }

        false
    }

    /// Carve out a region from conventional memory and mark it as a new type
    fn carve_out(
        &mut self,
        addr: u64,
        num_pages: u64,
        memory_type: MemoryType,
    ) -> Result<(), efi::Status> {
        let size = num_pages * PAGE_SIZE;
        let end = addr + size;

        // Find the entry containing this region
        let mut found_idx = None;
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.get_memory_type() == Some(MemoryType::ConventionalMemory)
                && entry.physical_start <= addr
                && entry.end() >= end
            {
                found_idx = Some(idx);
                break;
            }
        }

        let idx = found_idx.ok_or(efi::Status::NOT_FOUND)?;
        let entry = self.entries[idx];

        // Remove the old entry
        self.entries.remove(idx);

        // Add up to 3 new entries: before, carved, after
        let attribute = entry.attribute;

        // Region before the carved out portion
        if entry.physical_start < addr {
            let before_pages = (addr - entry.physical_start) / PAGE_SIZE;
            let before = MemoryDescriptor::new(
                MemoryType::ConventionalMemory,
                entry.physical_start,
                before_pages,
                attribute,
            );
            if self.entries.push(before).is_err() {
                return Err(efi::Status::OUT_OF_RESOURCES);
            }
        }

        // The carved out region
        let carved = MemoryDescriptor::new(memory_type, addr, num_pages, attribute);
        if self.entries.push(carved).is_err() {
            return Err(efi::Status::OUT_OF_RESOURCES);
        }

        // Region after the carved out portion
        if entry.end() > end {
            let after_pages = (entry.end() - end) / PAGE_SIZE;
            let after =
                MemoryDescriptor::new(MemoryType::ConventionalMemory, end, after_pages, attribute);
            if self.entries.push(after).is_err() {
                return Err(efi::Status::OUT_OF_RESOURCES);
            }
        }

        self.map_key += 1;
        self.sort_entries();

        Ok(())
    }

    /// Sort entries by physical address (ascending)
    fn sort_entries(&mut self) {
        // Simple insertion sort (entries are mostly sorted already)
        for i in 1..self.entries.len() {
            let mut j = i;
            while j > 0 && self.entries[j - 1].physical_start > self.entries[j].physical_start {
                self.entries.swap(j - 1, j);
                j -= 1;
            }
        }
    }

    /// Merge adjacent entries of the same type and attributes
    fn merge_entries(&mut self) {
        if self.entries.len() < 2 {
            return;
        }

        let mut i = 0;
        while i < self.entries.len() - 1 {
            let current_end = self.entries[i].end();
            let next_start = self.entries[i + 1].physical_start;

            // Check if entries are adjacent and have same type/attributes
            if current_end == next_start
                && self.entries[i].memory_type == self.entries[i + 1].memory_type
                && self.entries[i].attribute == self.entries[i + 1].attribute
            {
                // Merge: extend current entry and remove next
                self.entries[i].number_of_pages += self.entries[i + 1].number_of_pages;
                self.entries.remove(i + 1);
                // Don't increment i, check if we can merge more
            } else {
                i += 1;
            }
        }
    }
}

/// Global memory allocator instance
static ALLOCATOR: Mutex<MemoryAllocator> = Mutex::new(MemoryAllocator::new());

/// Initialize the global allocator from coreboot memory map
pub fn init(regions: &[MemoryRegion]) {
    let mut alloc = ALLOCATOR.lock();
    alloc.init_from_coreboot(regions);
}

/// Reserve a region of memory
pub fn reserve_region(
    physical_start: u64,
    num_pages: u64,
    memory_type: MemoryType,
) -> Result<(), efi::Status> {
    let mut alloc = ALLOCATOR.lock();
    alloc.reserve_region(physical_start, num_pages, memory_type)
}

/// Allocate pages of memory
pub fn allocate_pages(
    alloc_type: AllocateType,
    memory_type: MemoryType,
    num_pages: u64,
    memory: &mut u64,
) -> efi::Status {
    let mut alloc = ALLOCATOR.lock();
    alloc.allocate_pages(alloc_type, memory_type, num_pages, memory)
}

/// Free previously allocated pages
pub fn free_pages(memory: u64, num_pages: u64) -> efi::Status {
    let mut alloc = ALLOCATOR.lock();
    alloc.free_pages(memory, num_pages)
}

/// Get the memory map size
pub fn get_memory_map_size() -> usize {
    let alloc = ALLOCATOR.lock();
    alloc.entry_count() * core::mem::size_of::<MemoryDescriptor>()
}

/// Get current map key
pub fn get_map_key() -> usize {
    let alloc = ALLOCATOR.lock();
    alloc.map_key()
}

/// Get the memory map
pub fn get_memory_map(
    memory_map_size: &mut usize,
    memory_map: Option<&mut [MemoryDescriptor]>,
    map_key: &mut usize,
    descriptor_size: &mut usize,
    descriptor_version: &mut u32,
) -> efi::Status {
    let alloc = ALLOCATOR.lock();
    alloc.get_memory_map(
        memory_map_size,
        memory_map,
        map_key,
        descriptor_size,
        descriptor_version,
    )
}

/// Exit boot services
pub fn exit_boot_services(map_key: usize) -> efi::Status {
    let mut alloc = ALLOCATOR.lock();
    alloc.exit_boot_services(map_key)
}

/// Pool allocation header (for AllocatePool/FreePool)
#[repr(C)]
struct PoolHeader {
    /// Number of pages allocated
    num_pages: u64,
    /// Magic number for validation
    magic: u64,
}

const POOL_MAGIC: u64 = 0x504F4F4C_48445200; // "POOLHDR\0"

/// Allocate pool memory (arbitrary size)
pub fn allocate_pool(memory_type: MemoryType, size: usize) -> Result<*mut u8, efi::Status> {
    if size == 0 {
        return Err(efi::Status::INVALID_PARAMETER);
    }

    // Calculate total size including header, round up to pages
    let total_size = size + core::mem::size_of::<PoolHeader>();
    let num_pages = (total_size as u64 + PAGE_SIZE - 1) / PAGE_SIZE;

    let mut addr = 0u64;
    let status = allocate_pages(
        AllocateType::AllocateAnyPages,
        memory_type,
        num_pages,
        &mut addr,
    );

    if status != efi::Status::SUCCESS {
        return Err(status);
    }

    // Write the header
    let header = addr as *mut PoolHeader;
    unsafe {
        (*header).num_pages = num_pages;
        (*header).magic = POOL_MAGIC;
    }

    // Return pointer to data after header
    let data = unsafe { (header as *mut u8).add(core::mem::size_of::<PoolHeader>()) };
    Ok(data)
}

/// Free pool memory
pub fn free_pool(buffer: *mut u8) -> efi::Status {
    if buffer.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }

    // Get the header
    let header = unsafe { (buffer as *mut PoolHeader).sub(1) };

    // Validate magic
    let magic = unsafe { (*header).magic };
    if magic != POOL_MAGIC {
        return efi::Status::INVALID_PARAMETER;
    }

    let num_pages = unsafe { (*header).num_pages };
    let addr = header as u64;

    free_pages(addr, num_pages)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would go here
}
