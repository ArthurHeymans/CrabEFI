//! Page table management for x86_64
//!
//! This module handles setting up and managing the 4-level page tables
//! required for x86_64 long mode. Initial setup is done in assembly,
//! but this module can modify the page tables later.

use crate::coreboot::memory::MemoryRegion;

/// Page table entry flags
pub mod flags {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const WRITE_THROUGH: u64 = 1 << 3;
    pub const CACHE_DISABLE: u64 = 1 << 4;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    pub const HUGE_PAGE: u64 = 1 << 7;
    pub const GLOBAL: u64 = 1 << 8;
    pub const NO_EXECUTE: u64 = 1 << 63;
}

/// Page sizes
pub const PAGE_SIZE_4K: u64 = 4096;
pub const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;
pub const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

/// A page table entry
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// Create an empty (not present) entry
    pub const fn empty() -> Self {
        PageTableEntry(0)
    }

    /// Create a new entry with the given physical address and flags
    pub const fn new(phys_addr: u64, flags: u64) -> Self {
        PageTableEntry((phys_addr & 0x000F_FFFF_FFFF_F000) | flags)
    }

    /// Check if the entry is present
    pub fn is_present(&self) -> bool {
        self.0 & flags::PRESENT != 0
    }

    /// Get the physical address from this entry
    pub fn phys_addr(&self) -> u64 {
        self.0 & 0x000F_FFFF_FFFF_F000
    }

    /// Get the raw value
    pub fn raw(&self) -> u64 {
        self.0
    }
}

/// A page table (512 entries)
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [PageTableEntry; 512],
}

impl PageTable {
    /// Create an empty page table
    pub const fn empty() -> Self {
        PageTable {
            entries: [PageTableEntry::empty(); 512],
        }
    }

    /// Get a mutable reference to an entry
    pub fn entry_mut(&mut self, index: usize) -> &mut PageTableEntry {
        &mut self.entries[index]
    }

    /// Get a reference to an entry
    pub fn entry(&self, index: usize) -> &PageTableEntry {
        &self.entries[index]
    }
}

/// Initialize paging based on the memory map
///
/// The initial page tables set up in assembly identity-map the first 4GB.
/// This function can be used to refine the mapping based on the actual
/// memory map from coreboot.
pub fn init(memory_map: &[MemoryRegion]) {
    log::debug!(
        "Paging initialized with {} memory regions",
        memory_map.len()
    );

    // For now, we rely on the identity mapping set up in assembly.
    // Future improvements could:
    // - Mark non-RAM regions as non-cacheable
    // - Mark ACPI regions appropriately
    // - Set up a proper kernel mapping

    for region in memory_map {
        log::trace!(
            "  {:#x}-{:#x}: {:?}",
            region.start,
            region.start + region.size,
            region.region_type
        );
    }
}

/// Flush the TLB for a single page
#[inline]
pub fn flush_tlb_page(addr: u64) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) addr, options(nostack, preserves_flags));
    }
}

/// Flush the entire TLB by reloading CR3
#[inline]
pub fn flush_tlb_all() {
    unsafe {
        let cr3 = super::read_cr3();
        super::write_cr3(cr3);
    }
}

/// Virtual to physical address translation (identity mapped)
///
/// Since we use identity mapping, this is trivial.
#[inline]
pub fn virt_to_phys(virt: u64) -> u64 {
    virt
}

/// Physical to virtual address translation (identity mapped)
#[inline]
pub fn phys_to_virt(phys: u64) -> u64 {
    phys
}
