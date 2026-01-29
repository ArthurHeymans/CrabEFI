//! Memory map handling for coreboot
//!
//! This module defines the memory region types and provides utilities
//! for working with the memory map from coreboot.

/// Memory region types from coreboot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryType {
    /// Usable RAM
    Ram = 1,
    /// Reserved memory
    Reserved = 2,
    /// ACPI reclaimable memory
    AcpiReclaimable = 3,
    /// ACPI NVS (Non-Volatile Storage)
    AcpiNvs = 4,
    /// Unusable memory
    Unusable = 5,
    /// Coreboot tables
    Table = 16,
}

impl MemoryType {
    /// Check if this memory type is usable as general RAM
    pub fn is_usable(&self) -> bool {
        matches!(self, MemoryType::Ram)
    }

    /// Check if this memory can be reclaimed after boot
    pub fn is_reclaimable(&self) -> bool {
        matches!(self, MemoryType::Ram | MemoryType::AcpiReclaimable)
    }

    /// Convert to EFI memory type
    pub fn to_efi_type(&self) -> u32 {
        use r_efi::efi;
        match self {
            MemoryType::Ram => efi::CONVENTIONAL_MEMORY,
            MemoryType::Reserved => efi::RESERVED_MEMORY_TYPE,
            MemoryType::AcpiReclaimable => efi::ACPI_RECLAIM_MEMORY,
            MemoryType::AcpiNvs => efi::ACPI_MEMORY_NVS,
            MemoryType::Unusable => efi::UNUSABLE_MEMORY,
            MemoryType::Table => efi::BOOT_SERVICES_DATA,
        }
    }
}

/// A memory region descriptor
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    /// Starting physical address
    pub start: u64,
    /// Size in bytes
    pub size: u64,
    /// Type of memory
    pub region_type: MemoryType,
}

impl MemoryRegion {
    /// Get the ending address (exclusive)
    pub fn end(&self) -> u64 {
        self.start + self.size
    }

    /// Check if this region contains the given address
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }

    /// Check if this region overlaps with another
    pub fn overlaps(&self, other: &MemoryRegion) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    /// Get the number of 4KB pages in this region
    pub fn page_count(&self) -> u64 {
        self.size.div_ceil(0x1000)
    }
}

/// Find usable RAM regions from a memory map
pub fn find_usable_ram(regions: &[MemoryRegion]) -> impl Iterator<Item = &MemoryRegion> {
    regions.iter().filter(|r| r.region_type.is_usable())
}

/// Calculate total usable RAM
pub fn total_usable_ram(regions: &[MemoryRegion]) -> u64 {
    find_usable_ram(regions).map(|r| r.size).sum()
}

/// Find the highest usable address
pub fn highest_usable_address(regions: &[MemoryRegion]) -> u64 {
    find_usable_ram(regions).map(|r| r.end()).max().unwrap_or(0)
}

/// Find a free region of at least the given size
pub fn find_free_region(regions: &[MemoryRegion], size: u64, alignment: u64) -> Option<u64> {
    for region in find_usable_ram(regions) {
        let aligned_start = (region.start + alignment - 1) & !(alignment - 1);
        if aligned_start + size <= region.end() {
            return Some(aligned_start);
        }
    }
    None
}
