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

/// Page size as usize for convenience
pub const PAGE_SIZE_USIZE: usize = 4096;

/// Maximum address that is identity-mapped in page tables
/// Our assembly code sets up identity mapping for the first 64GB (64 PDPTs * 512 PDs * 2MB each)
/// Allocations above this address will cause page faults!
const MAX_IDENTITY_MAPPED_ADDRESS: u64 = 0x10_0000_0000; // 64GB

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

        log::info!("Importing coreboot memory map ({} regions):", regions.len());
        for region in regions {
            let memory_type = cb_to_efi_memory_type(region.region_type);
            let num_pages = (region.size + PAGE_SIZE - 1) / PAGE_SIZE;

            log::info!(
                "  {:#010x}-{:#010x} {:?} -> {:?}",
                region.start,
                region.start + region.size,
                region.region_type,
                memory_type
            );

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

        log::info!(
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

    /// Force-add a memory region to the map
    ///
    /// This is used when the region isn't in the coreboot map at all.
    /// It adds the region directly without trying to carve from existing memory.
    pub fn force_add_region(
        &mut self,
        physical_start: u64,
        num_pages: u64,
        memory_type: MemoryType,
    ) -> Result<(), efi::Status> {
        let mut attribute = attributes::EFI_MEMORY_WB;

        // RuntimeServicesCode/Data must have EFI_MEMORY_RUNTIME attribute
        if memory_type == MemoryType::RuntimeServicesCode {
            attribute |= attributes::EFI_MEMORY_RUNTIME;
            attribute &= !attributes::EFI_MEMORY_XP;
        } else if memory_type == MemoryType::RuntimeServicesData {
            attribute |= attributes::EFI_MEMORY_RUNTIME;
            attribute |= attributes::EFI_MEMORY_XP;
        }

        let desc = MemoryDescriptor::new(memory_type, physical_start, num_pages, attribute);

        if self.entries.push(desc).is_err() {
            return Err(efi::Status::OUT_OF_RESOURCES);
        }

        self.map_key += 1;
        self.sort_entries();

        Ok(())
    }

    /// Mark a memory region as ACPI Reclaim Memory
    ///
    /// This function finds the region containing the address (any memory type),
    /// splits it if necessary, and marks the specified range as AcpiReclaimMemory.
    /// Unlike carve_out, this works on any memory type, not just ConventionalMemory.
    pub fn mark_as_acpi_reclaim(&mut self, addr: u64, num_pages: u64) -> Result<(), efi::Status> {
        let size = num_pages * PAGE_SIZE;
        let end = addr + size;

        // Find the entry containing this region (any memory type)
        let mut found_idx = None;
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.physical_start <= addr && entry.end() >= end {
                found_idx = Some(idx);
                break;
            }
        }

        let idx = match found_idx {
            Some(i) => i,
            None => {
                // Region not found - check if it overlaps with any existing region
                for entry in self.entries.iter() {
                    let entry_end = entry.end();
                    // Check for overlap
                    if addr < entry_end && end > entry.physical_start {
                        // Overlaps - this is complex, skip for now
                        return Err(efi::Status::INVALID_PARAMETER);
                    }
                }
                // No overlap, we can add it as a new region
                let desc = MemoryDescriptor::new(
                    MemoryType::AcpiReclaimMemory,
                    addr,
                    num_pages,
                    attributes::EFI_MEMORY_WB,
                );
                if self.entries.push(desc).is_err() {
                    return Err(efi::Status::OUT_OF_RESOURCES);
                }
                self.map_key += 1;
                self.sort_entries();
                return Ok(());
            }
        };

        let entry = self.entries[idx];
        let original_type = entry
            .get_memory_type()
            .unwrap_or(MemoryType::ReservedMemoryType);

        // If already ACPI reclaim, nothing to do
        if original_type == MemoryType::AcpiReclaimMemory {
            return Ok(());
        }

        // If already ACPI NVS, don't change it
        if original_type == MemoryType::AcpiMemoryNvs {
            return Ok(());
        }

        let attribute = entry.attribute;

        // Remove the old entry
        self.entries.remove(idx);

        // Add up to 3 new entries: before, acpi, after
        // Region before the ACPI portion (keep original type)
        if entry.physical_start < addr {
            let before_pages = (addr - entry.physical_start) / PAGE_SIZE;
            let before =
                MemoryDescriptor::new(original_type, entry.physical_start, before_pages, attribute);
            if self.entries.push(before).is_err() {
                return Err(efi::Status::OUT_OF_RESOURCES);
            }
        }

        // The ACPI reclaim region
        let acpi = MemoryDescriptor::new(MemoryType::AcpiReclaimMemory, addr, num_pages, attribute);
        if self.entries.push(acpi).is_err() {
            return Err(efi::Status::OUT_OF_RESOURCES);
        }

        // Region after the ACPI portion (keep original type)
        if entry.end() > end {
            let after_pages = (entry.end() - end) / PAGE_SIZE;
            let after = MemoryDescriptor::new(original_type, end, after_pages, attribute);
            if self.entries.push(after).is_err() {
                return Err(efi::Status::OUT_OF_RESOURCES);
            }
        }

        self.map_key += 1;
        self.sort_entries();

        Ok(())
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
        log::debug!(
            "exit_boot_services: provided_key={:#x}, current_key={:#x}",
            provided_map_key,
            self.map_key
        );

        if provided_map_key != self.map_key {
            log::warn!(
                "exit_boot_services: map_key mismatch! expected {:#x}, got {:#x}",
                self.map_key,
                provided_map_key
            );
            return efi::Status::INVALID_PARAMETER;
        }

        self.boot_services_exited = true;

        // Log runtime services regions (these must have EFI_MEMORY_RUNTIME attribute)
        log::debug!(
            "Memory map at ExitBootServices ({} entries):",
            self.entries.len()
        );
        for entry in self.entries.iter() {
            let mem_type = entry
                .get_memory_type()
                .unwrap_or(MemoryType::ReservedMemoryType);
            let has_runtime = (entry.attribute & attributes::EFI_MEMORY_RUNTIME) != 0;
            if matches!(
                mem_type,
                MemoryType::RuntimeServicesCode | MemoryType::RuntimeServicesData
            ) {
                log::info!(
                    "  RuntimeServices: {:#x}-{:#x} type={:?} attr={:#x} RUNTIME={}",
                    entry.physical_start,
                    entry.end(),
                    mem_type,
                    entry.attribute,
                    has_runtime
                );
            }
        }

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

        log::info!("ExitBootServices complete, new map_key={:#x}", self.map_key);
        efi::Status::SUCCESS
    }

    /// Find free pages that fit the requirements
    fn find_free_pages(&self, num_pages: u64, max_addr: u64) -> Option<u64> {
        let size = num_pages * PAGE_SIZE;

        // Limit max_addr to the identity-mapped region
        // Our page tables only cover the first 4GB, so allocating above that
        // would cause page faults when the memory is accessed
        let max_addr = max_addr.min(MAX_IDENTITY_MAPPED_ADDRESS);

        // Search from high to low addresses (prefer high memory within mapped region)
        for entry in self.entries.iter().rev() {
            if entry.get_memory_type() != Some(MemoryType::ConventionalMemory) {
                continue;
            }

            // Skip entries entirely above our limit
            if entry.physical_start >= max_addr {
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
        let mut attribute = entry.attribute;

        // RuntimeServicesCode/Data must have EFI_MEMORY_RUNTIME attribute
        // so the OS knows to keep them mapped after ExitBootServices
        if memory_type == MemoryType::RuntimeServicesCode {
            // Code must be executable: clear EFI_MEMORY_XP (NX bit)
            attribute |= attributes::EFI_MEMORY_RUNTIME;
            attribute &= !attributes::EFI_MEMORY_XP;
        } else if memory_type == MemoryType::RuntimeServicesData {
            // Data should not be executable: set EFI_MEMORY_XP (NX bit)
            attribute |= attributes::EFI_MEMORY_RUNTIME;
            attribute |= attributes::EFI_MEMORY_XP;
        }

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

/// Force-add a memory region to the map
///
/// This is used when the region isn't in the coreboot map at all.
pub fn force_add_region(
    physical_start: u64,
    num_pages: u64,
    memory_type: MemoryType,
) -> Result<(), efi::Status> {
    let mut alloc = ALLOCATOR.lock();
    alloc.force_add_region(physical_start, num_pages, memory_type)
}

/// Mark a memory region as ACPI Reclaim Memory
///
/// This properly splits existing regions and marks the specified range as AcpiReclaimMemory.
pub fn mark_as_acpi_reclaim(addr: u64, num_pages: u64) -> Result<(), efi::Status> {
    let mut alloc = ALLOCATOR.lock();
    alloc.mark_as_acpi_reclaim(addr, num_pages)
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

/// Find the memory type for a given physical address
///
/// Returns the memory type if the address is within a known memory region,
/// or None if the address is not in any known region.
pub fn get_memory_type_at(address: u64) -> Option<MemoryType> {
    let alloc = ALLOCATOR.lock();
    for entry in alloc.entries.iter() {
        if address >= entry.physical_start && address < entry.end() {
            return MemoryType::from_u32(entry.memory_type);
        }
    }
    None
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

// Linker symbols for section boundaries
unsafe extern "C" {
    static __runtime_code_start: u8;
    static __runtime_code_end: u8;
    static __runtime_data_start: u8;
    static __runtime_data_end: u8;
}

/// Reserve the CrabEFI runtime regions using linker-provided section boundaries
///
/// This marks the memory containing our code and data sections so that the OS
/// keeps them mapped after ExitBootServices. The boundaries come from the
/// linker script symbols.
pub fn reserve_runtime_region() {
    // Get section boundaries from linker symbols
    let code_start = unsafe { &__runtime_code_start as *const u8 as u64 };
    let code_end = unsafe { &__runtime_code_end as *const u8 as u64 };
    let data_start = unsafe { &__runtime_data_start as *const u8 as u64 };
    let data_end = unsafe { &__runtime_data_end as *const u8 as u64 };

    // Align to page boundaries
    // Code region: round start down, round end up
    let code_start_aligned = code_start & !(PAGE_SIZE - 1);
    let code_end_aligned = (code_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // Data region: start where code ends (to avoid overlap), round end up
    // The linker places data_start immediately after code_end, but when we
    // page-align them separately, rounding code_end UP and data_start DOWN
    // can create an overlap. Instead, always start data at code_end_aligned.
    let data_start_aligned = if data_start < code_end_aligned {
        // Data would overlap with code region, start at code_end instead
        code_end_aligned
    } else {
        data_start & !(PAGE_SIZE - 1)
    };
    let data_end_aligned = (data_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let code_pages = (code_end_aligned - code_start_aligned) / PAGE_SIZE;
    let data_pages = if data_end_aligned > data_start_aligned {
        (data_end_aligned - data_start_aligned) / PAGE_SIZE
    } else {
        0
    };

    log::info!(
        "Runtime code region from linker: {:#x}-{:#x} ({} pages)",
        code_start_aligned,
        code_end_aligned,
        code_pages
    );
    log::info!(
        "Runtime data region from linker: {:#x}-{:#x} ({} pages)",
        data_start_aligned,
        data_end_aligned,
        data_pages
    );

    // Reserve the CODE region (executable, no XP attribute)
    match reserve_region(
        code_start_aligned,
        code_pages,
        MemoryType::RuntimeServicesCode,
    ) {
        Ok(()) => {
            log::info!(
                "Reserved runtime services code region: {:#x}-{:#x}",
                code_start_aligned,
                code_end_aligned
            );
        }
        Err(status) => {
            log::warn!(
                "carve_out failed for code region: {:?}, trying force_add",
                status
            );
            // The region might not be in the memory map at all - force add it
            match force_add_region(
                code_start_aligned,
                code_pages,
                MemoryType::RuntimeServicesCode,
            ) {
                Ok(()) => {
                    log::info!(
                        "Force-added runtime services code region: {:#x}-{:#x}",
                        code_start_aligned,
                        code_end_aligned
                    );
                }
                Err(e) => {
                    log::error!("CRITICAL: Failed to add runtime code region: {:?}", e);
                }
            }
        }
    }

    // Reserve the DATA region (non-executable, XP attribute set)
    // Skip if there are no pages to reserve
    if data_pages > 0 {
        match reserve_region(
            data_start_aligned,
            data_pages,
            MemoryType::RuntimeServicesData,
        ) {
            Ok(()) => {
                log::info!(
                    "Reserved runtime services data region: {:#x}-{:#x}",
                    data_start_aligned,
                    data_end_aligned
                );
            }
            Err(status) => {
                log::warn!(
                    "carve_out failed for data region: {:?}, trying force_add",
                    status
                );
                // The region might not be in the memory map at all - force add it
                match force_add_region(
                    data_start_aligned,
                    data_pages,
                    MemoryType::RuntimeServicesData,
                ) {
                    Ok(()) => {
                        log::info!(
                            "Force-added runtime services data region: {:#x}-{:#x}",
                            data_start_aligned,
                            data_end_aligned
                        );
                    }
                    Err(e) => {
                        log::error!("CRITICAL: Failed to add runtime data region: {:?}", e);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would go here
}
