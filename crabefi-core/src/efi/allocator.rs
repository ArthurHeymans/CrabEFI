//! EFI Memory Allocator
//!
//! This module implements page-granular memory allocation compatible with the
//! EFI AllocatePages/FreePages API. Memory is tracked using a sorted list of
//! memory descriptors. Pool allocations are suballocated from page-backed
//! chunks grouped by EFI memory type. Pool chunks are intentionally retained
//! until `ExitBootServices`; individual pool frees never return pages to the
//! page allocator.
//!
//! # State Management
//!
//! The allocator state is stored in the centralized `FirmwareState` structure.
//! Access it via `crate::state::allocator()` or `crate::state::allocator_mut()`.

use core::sync::atomic::{AtomicBool, Ordering};

pub use crabefi_runtime_abi::MemoryDescriptor;
use heapless::Vec;
use r_efi::efi;

use crate::state;

// Keep these dependency-free helpers in flat files so the CI regression job
// can compile and execute them directly with `rustc --test`.
#[path = "page_ownership.rs"]
mod page_ownership;
#[path = "pool_free_list.rs"]
mod pool_free_list;
pub use page_ownership::PAGE_SIZE;
use page_ownership::{
    PageCount, PageRange, RangeSplit, exact_cover, fits_after_replacement, split_allocation,
};
use pool_free_list::{
    POOL_ALLOCATED_MAGIC, POOL_FREE_MAGIC, PoolHeader, PoolListError, PoolState, align_pool_size,
};

type PageAllocation = page_ownership::PageAllocation<MemoryType>;

/// Maximum number of memory map entries we can track.
///
/// SCT exceeded the previous 512-entry table while loading dozens of PE/COFF
/// images. The map is compacted after each mutation; 2048 entries provide
/// headroom for genuinely live descriptors at a static cost of about 80 KiB.
const MAX_MEMORY_ENTRIES: usize = 2048;

/// Maximum number of live page allocations.
///
/// Pool requests are suballocated from chunks, so they consume one record per
/// chunk rather than one record per EFI pool allocation. Keeping this metadata
/// inline avoids depending on the heap that the page allocator bootstraps.
/// The table occupies about 64 KiB with the ownership metadata below.
const MAX_PAGE_ALLOCATIONS: usize = 2048;

/// Page size as usize for convenience
pub const PAGE_SIZE_USIZE: usize = PAGE_SIZE as usize;

/// Maximum address that is identity-mapped in page tables.
/// On x86_64: Our assembly code sets up identity mapping for the first 64GB
/// (64 PDPTs * 512 PDs * 2MB each). Allocations above this will cause page faults.
/// On aarch64: coreboot/TF-A sets up the MMU covering the full address space,
/// including DRAM at 1TB+ on QEMU SBSA. No artificial cap needed.
#[cfg(target_arch = "x86_64")]
const MAX_IDENTITY_MAPPED_ADDRESS: u64 = 0x0f_ffff_ffff; // Last byte below 64GB
#[cfg(target_arch = "aarch64")]
const MAX_IDENTITY_MAPPED_ADDRESS: u64 = u64::MAX;
/// On riscv64: No MMU (satp=0), identity mapped — no limit needed.
#[cfg(target_arch = "riscv64")]
const MAX_IDENTITY_MAPPED_ADDRESS: u64 = u64::MAX;

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

impl TryFrom<u32> for AllocateType {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AllocateType::AllocateAnyPages),
            1 => Ok(AllocateType::AllocateMaxAddress),
            2 => Ok(AllocateType::AllocateAddress),
            other => Err(other),
        }
    }
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
    /// Check whether UEFI allocation services may allocate this memory type.
    pub const fn is_valid_allocation_type(self) -> bool {
        !matches!(
            self,
            MemoryType::ConventionalMemory | MemoryType::PersistentMemory
        )
    }

    /// Default EFI memory attributes (cache capabilities) for this type.
    ///
    /// DRAM-backed types support WC|WT|WB caching. MMIO types are UC only.
    pub fn default_attributes(&self) -> u64 {
        match self {
            MemoryType::MemoryMappedIo | MemoryType::MemoryMappedIoPortSpace => {
                attributes::EFI_MEMORY_UC
            }
            _ => attributes::EFI_MEMORY_RAM_CAPS,
        }
    }
}

impl TryFrom<u32> for MemoryType {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MemoryType::ReservedMemoryType),
            1 => Ok(MemoryType::LoaderCode),
            2 => Ok(MemoryType::LoaderData),
            3 => Ok(MemoryType::BootServicesCode),
            4 => Ok(MemoryType::BootServicesData),
            5 => Ok(MemoryType::RuntimeServicesCode),
            6 => Ok(MemoryType::RuntimeServicesData),
            7 => Ok(MemoryType::ConventionalMemory),
            8 => Ok(MemoryType::UnusableMemory),
            9 => Ok(MemoryType::AcpiReclaimMemory),
            10 => Ok(MemoryType::AcpiMemoryNvs),
            11 => Ok(MemoryType::MemoryMappedIo),
            12 => Ok(MemoryType::MemoryMappedIoPortSpace),
            13 => Ok(MemoryType::PalCode),
            14 => Ok(MemoryType::PersistentMemory),
            other => Err(other),
        }
    }
}

/// Memory attributes (as defined in UEFI spec)
///
/// The Attribute field in EFI_MEMORY_DESCRIPTOR describes the **capabilities**
/// of the memory region — i.e. which caching modes the hardware supports —
/// not the current setting. See UEFI Spec 2.10 §7.2.
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

    /// Cache capability set for normal DRAM.
    ///
    /// DRAM supports write-combining, write-through, and write-back caching.
    /// This matches what EDK2 reports via GCD capabilities (0xE).
    /// The OS uses these bits to know which caching modes it may select
    /// for any given page (e.g. WC for GPU buffers, WT for DMA).
    pub const EFI_MEMORY_RAM_CAPS: u64 = EFI_MEMORY_WC | EFI_MEMORY_WT | EFI_MEMORY_WB;
}

trait MemoryDescriptorExt {
    fn page_range(&self) -> Option<PageRange>;
    fn get_memory_type(&self) -> Option<MemoryType>;
}

impl MemoryDescriptorExt for MemoryDescriptor {
    fn page_range(&self) -> Option<PageRange> {
        PageRange::from_bytes(self.physical_start, self.number_of_pages)
    }

    fn get_memory_type(&self) -> Option<MemoryType> {
        MemoryType::try_from(self.memory_type).ok()
    }
}

fn memory_descriptor(
    memory_type: MemoryType,
    physical_start: u64,
    number_of_pages: u64,
    attribute: u64,
) -> MemoryDescriptor {
    MemoryDescriptor::new(
        memory_type as u32,
        physical_start,
        number_of_pages,
        attribute,
    )
}

fn descriptor_for_range(
    memory_type: MemoryType,
    range: PageRange,
    attribute: u64,
) -> MemoryDescriptor {
    memory_descriptor(
        memory_type,
        range.start_bytes(),
        range.pages().get(),
        attribute,
    )
}

fn can_merge(left: &MemoryDescriptor, right: &MemoryDescriptor) -> bool {
    left.memory_type == right.memory_type
        && left.attribute == right.attribute
        && left
            .page_range()
            .zip(right.page_range())
            .is_some_and(|(left, right)| left.is_adjacent_to(right))
}

/// Memory allocator state
pub struct MemoryAllocator {
    /// Memory map entries, sorted by physical address (ascending)
    entries: Vec<MemoryDescriptor, MAX_MEMORY_ENTRIES>,
    /// Exact page allocations, retained even when adjacent map descriptors merge.
    allocations: Vec<PageAllocation, MAX_PAGE_ALLOCATIONS>,
    /// Memory map key (incremented on every change)
    map_key: usize,
    /// Whether boot services have exited
    boot_services_exited: bool,
}

impl Default for MemoryAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryAllocator {
    /// Create a new allocator (const fn for static initialization)
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            allocations: Vec::new(),
            map_key: 1,
            boot_services_exited: false,
        }
    }

    fn find_allocation(&self, range: PageRange) -> Option<(usize, PageAllocation)> {
        self.allocations
            .iter()
            .copied()
            .enumerate()
            .find(|(_, allocation)| allocation.contains(range))
    }

    fn find_descriptor(&self, range: PageRange, types: &[MemoryType]) -> Option<usize> {
        self.entries.iter().position(|entry| {
            entry
                .get_memory_type()
                .is_some_and(|memory_type| types.contains(&memory_type))
                && entry
                    .page_range()
                    .is_some_and(|entry| entry.contains(range))
        })
    }

    /// How the descriptor at `descriptor_index` splits around `range`.
    fn descriptor_split(
        &self,
        descriptor_index: usize,
        range: PageRange,
    ) -> Result<RangeSplit, efi::Status> {
        self.entries[descriptor_index]
            .page_range()
            .and_then(|descriptor| descriptor.split_around(range))
            .ok_or(efi::Status::NOT_FOUND)
    }

    fn record_allocation(&mut self, allocation: PageAllocation) -> Result<(), efi::Status> {
        self.allocations.push(allocation).map_err(|_| {
            log::error!("Page allocation ownership table is full");
            efi::Status::OUT_OF_RESOURCES
        })
    }

    fn insert_descriptor_prechecked(&mut self, index: usize, descriptor: MemoryDescriptor) {
        self.entries
            .insert(index, descriptor)
            .expect("memory map capacity was pre-checked");
    }

    fn allocation_replacement_fits(
        &self,
        allocation: PageAllocation,
        range: PageRange,
        replacement: Option<PageAllocation>,
    ) -> bool {
        split_allocation(allocation, range, replacement).is_ok_and(|parts| {
            fits_after_replacement(
                self.allocations.len(),
                1,
                parts.iter().flatten().count(),
                MAX_PAGE_ALLOCATIONS,
            )
        })
    }

    fn replace_allocation_range(
        &mut self,
        allocation_index: usize,
        range: PageRange,
        replacement: Option<PageAllocation>,
    ) -> Result<(), efi::Status> {
        let parts = split_allocation(self.allocations[allocation_index], range, replacement)
            .map_err(|_| efi::Status::NOT_FOUND)?;
        if !fits_after_replacement(
            self.allocations.len(),
            1,
            parts.iter().flatten().count(),
            MAX_PAGE_ALLOCATIONS,
        ) {
            return Err(efi::Status::OUT_OF_RESOURCES);
        }

        self.allocations.swap_remove(allocation_index);
        for allocation in parts.into_iter().flatten() {
            self.record_allocation(allocation)?;
        }
        Ok(())
    }

    /// Compact the whole map so that splitting `range` fits again.
    ///
    /// The compacted outcome is evaluated before anything is mutated, so a
    /// retry that still would not fit leaves the exported map untouched.
    fn compact_for_split(
        &mut self,
        descriptor_index: usize,
        range: PageRange,
    ) -> Result<(), efi::Status> {
        let mut merged_start = descriptor_index;
        while merged_start > 0
            && can_merge(&self.entries[merged_start - 1], &self.entries[merged_start])
        {
            merged_start -= 1;
        }
        let mut merged_end = descriptor_index;
        while merged_end + 1 < self.entries.len()
            && can_merge(&self.entries[merged_end], &self.entries[merged_end + 1])
        {
            merged_end += 1;
        }

        let merged = self.entries[merged_start]
            .page_range()
            .zip(self.entries[merged_end].page_range())
            .and_then(|(first, last)| PageRange::spanning(first.start(), last.end()))
            .ok_or(efi::Status::NOT_FOUND)?;
        let split = merged.split_around(range).ok_or(efi::Status::NOT_FOUND)?;

        let compacted_len = self.count_merged_entries();
        if !fits_after_replacement(
            compacted_len,
            1,
            split.replacement_count(),
            MAX_MEMORY_ENTRIES,
        ) {
            log::warn!(
                "Memory map full ({} entries, {} after compaction), cannot split descriptor",
                self.entries.len(),
                compacted_len
            );
            return Err(efi::Status::OUT_OF_RESOURCES);
        }
        self.merge_entries();
        Ok(())
    }

    /// Retype a range inside one descriptor while preserving its head and tail.
    fn retype_range(
        &mut self,
        mut descriptor_index: usize,
        range: PageRange,
        memory_type: MemoryType,
        attribute: u64,
    ) -> Result<(), efi::Status> {
        let mut split = self.descriptor_split(descriptor_index, range)?;
        let original = self.entries[descriptor_index];
        let original_type = original.get_memory_type().ok_or(efi::Status::NOT_FOUND)?;

        if !fits_after_replacement(
            self.entries.len(),
            1,
            split.replacement_count(),
            MAX_MEMORY_ENTRIES,
        ) {
            self.compact_for_split(descriptor_index, range)?;
            descriptor_index = self
                .find_descriptor(range, &[original_type])
                .ok_or(efi::Status::NOT_FOUND)?;
            split = self.descriptor_split(descriptor_index, range)?;
            debug_assert!(fits_after_replacement(
                self.entries.len(),
                1,
                split.replacement_count(),
                MAX_MEMORY_ENTRIES
            ));
        }

        // The residual head and tail keep the original type and attributes;
        // only the middle part takes the requested ones.
        let retyped_index = descriptor_index + split.head.is_some() as usize;
        self.entries.remove(descriptor_index);
        for (offset, part) in split.parts().enumerate() {
            let descriptor = if part == split.middle {
                descriptor_for_range(memory_type, part, attribute)
            } else {
                descriptor_for_range(original_type, part, original.attribute)
            };
            self.insert_descriptor_prechecked(descriptor_index + offset, descriptor);
        }

        self.merge_near(retyped_index);
        Ok(())
    }

    /// Initialize the allocator from a platform-provided memory map.
    ///
    /// Converts `platform::MemoryRegion` entries into EFI memory descriptors.
    ///
    /// Idempotent: if the allocator already has entries (e.g., the caller
    /// bootstrapped the page allocator before [`crate::init_platform()`] to
    /// get a heap), this is a no-op.
    pub fn init_from_platform(&mut self, regions: &[crate::platform::MemoryRegion]) {
        if !self.entries.is_empty() {
            log::info!("Page allocator already initialized, skipping re-init");
            return;
        }

        use crate::platform::MemoryType as PlatMemType;

        self.entries.clear();
        self.allocations.clear();
        self.map_key = 1;

        log::info!("Importing platform memory map ({} regions):", regions.len());
        for region in regions {
            let memory_type = match region.region_type {
                PlatMemType::Ram => MemoryType::ConventionalMemory,
                PlatMemType::Reserved => MemoryType::ReservedMemoryType,
                PlatMemType::AcpiReclaimable => MemoryType::AcpiReclaimMemory,
                PlatMemType::AcpiNvs => MemoryType::AcpiMemoryNvs,
                PlatMemType::Mmio => MemoryType::MemoryMappedIo,
                PlatMemType::BootServicesData => MemoryType::BootServicesData,
            };

            let num_pages = PageCount::covering_bytes(region.size);

            log::info!(
                "  {:#010x}-{:#010x} {:?} -> {:?}",
                region.base,
                region.base + region.size,
                region.region_type,
                memory_type
            );

            let attribute = memory_type.default_attributes();

            let Some(range) = PageRange::from_bytes(region.base, num_pages.get()) else {
                log::warn!(
                    "Region at {:#x} is misaligned or overflows, skipping",
                    region.base
                );
                continue;
            };

            if self
                .entries
                .push(descriptor_for_range(memory_type, range, attribute))
                .is_err()
            {
                log::warn!("Memory map full, ignoring region at {:#x}", region.base);
            }
        }

        self.sort_entries();
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

    /// Reserve all ConventionalMemory fragments within a range.
    ///
    /// Platform-provided ACPI/SMBIOS reservations may intentionally split the
    /// firmware's linker-described runtime data range.  Runtime data still
    /// has to be preserved for the OS, but those pre-typed holes should keep
    /// their more specific memory types.  This helper carves every overlapping
    /// ConventionalMemory fragment and skips existing non-conventional holes.
    pub fn reserve_region_fragments(
        &mut self,
        physical_start: u64,
        num_pages: u64,
        memory_type: MemoryType,
    ) -> Result<(), efi::Status> {
        let range = PageRange::from_bytes(physical_start, num_pages)
            .ok_or(efi::Status::INVALID_PARAMETER)?;

        let mut fragments: heapless::Vec<PageRange, MAX_MEMORY_ENTRIES> = heapless::Vec::new();
        for entry in &self.entries {
            if entry.get_memory_type() != Some(MemoryType::ConventionalMemory) {
                continue;
            }
            let Some(fragment) = entry
                .page_range()
                .and_then(|entry| entry.intersection(range))
            else {
                continue;
            };
            fragments
                .push(fragment)
                .map_err(|_| efi::Status::OUT_OF_RESOURCES)?;
        }

        for fragment in fragments {
            self.carve_out(fragment.start_bytes(), fragment.pages().get(), memory_type)?;
        }

        Ok(())
    }

    /// Force-add a memory region to the map
    ///
    /// This is used when the region isn't in the coreboot map at all.
    /// It adds the region directly without trying to carve from existing memory.
    /// Memory attributes are set automatically based on type:
    /// - `MemoryMappedIo` / `MemoryMappedIoPortSpace` → `EFI_MEMORY_UC` (uncacheable)
    /// - `RuntimeServicesCode/Data` → `EFI_MEMORY_RAM_CAPS | EFI_MEMORY_RUNTIME`
    /// - Everything else → `EFI_MEMORY_RAM_CAPS`
    pub fn force_add_region(
        &mut self,
        physical_start: u64,
        num_pages: u64,
        memory_type: MemoryType,
    ) -> Result<(), efi::Status> {
        let mut attribute = match memory_type {
            MemoryType::MemoryMappedIo | MemoryType::MemoryMappedIoPortSpace => {
                attributes::EFI_MEMORY_UC
            }
            _ => attributes::EFI_MEMORY_RAM_CAPS,
        };

        // RuntimeServicesCode/Data must have EFI_MEMORY_RUNTIME attribute
        if memory_type == MemoryType::RuntimeServicesCode {
            attribute |= attributes::EFI_MEMORY_RUNTIME;
            attribute &= !attributes::EFI_MEMORY_XP;
        } else if memory_type == MemoryType::RuntimeServicesData {
            attribute |= attributes::EFI_MEMORY_RUNTIME;
            attribute |= attributes::EFI_MEMORY_XP;
        }

        let desc = memory_descriptor(memory_type, physical_start, num_pages, attribute);

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
    /// Re-type a memory region, splitting the containing entry as needed.
    ///
    /// Finds the entry containing `[addr, addr + num_pages * PAGE_SIZE)`,
    /// splits it into up to 3 parts (before, target, after), and changes the
    /// target portion to `target_type`. If the region is not found inside an
    /// existing entry, it is added as a new entry with the target type.
    ///
    /// `skip_types` lists memory types that should NOT be re-typed (the
    /// function returns `Ok(())` immediately if the region already has one
    /// of these types).
    fn mark_region_as(
        &mut self,
        addr: u64,
        num_pages: u64,
        target_type: MemoryType,
        skip_types: &[MemoryType],
    ) -> Result<(), efi::Status> {
        let range = PageRange::from_bytes(addr, num_pages).ok_or(efi::Status::INVALID_PARAMETER)?;

        // Unlike carve_out this accepts any source type, so it cannot reuse
        // find_descriptor's type filter.
        let containing = self.entries.iter().position(|entry| {
            entry
                .page_range()
                .is_some_and(|entry| entry.contains(range))
        });
        let Some(descriptor_index) = containing else {
            // Region not found — check for overlaps (only for ACPI reclaim
            // which has stricter validation)
            if target_type == MemoryType::AcpiReclaimMemory
                && self.entries.iter().any(|entry| {
                    entry
                        .page_range()
                        .is_some_and(|entry| entry.overlaps(range))
                })
            {
                return Err(efi::Status::INVALID_PARAMETER);
            }
            // No containing entry — add as a new entry
            self.entries
                .push(descriptor_for_range(
                    target_type,
                    range,
                    attributes::EFI_MEMORY_RAM_CAPS,
                ))
                .map_err(|_| efi::Status::OUT_OF_RESOURCES)?;
            self.map_key += 1;
            self.sort_entries();
            return Ok(());
        };

        let descriptor = self.entries[descriptor_index];
        let original_type = descriptor
            .get_memory_type()
            .unwrap_or(MemoryType::ReservedMemoryType);

        // If already the target type or a type we should skip, nothing to do
        if original_type == target_type || skip_types.contains(&original_type) {
            return Ok(());
        }

        self.retype_range(descriptor_index, range, target_type, descriptor.attribute)?;

        self.map_key += 1;
        Ok(())
    }

    /// Mark a memory region as ACPI Reclaim Memory.
    ///
    /// Splits the containing entry as needed. Skips regions already typed as
    /// `AcpiReclaimMemory` or `AcpiMemoryNvs`.
    pub fn mark_as_acpi_reclaim(&mut self, addr: u64, num_pages: u64) -> Result<(), efi::Status> {
        self.mark_region_as(
            addr,
            num_pages,
            MemoryType::AcpiReclaimMemory,
            &[
                MemoryType::ReservedMemoryType,
                MemoryType::AcpiReclaimMemory,
                MemoryType::AcpiMemoryNvs,
            ],
        )
    }

    /// Mark a memory region as Reserved Memory.
    ///
    /// This is the correct way to reserve pages that are already part of a
    /// ConventionalMemory region (e.g. EL2 page tables that coreboot set up
    /// inside a RAM region). Splits the containing entry as needed.
    pub fn mark_as_reserved(&mut self, addr: u64, num_pages: u64) -> Result<(), efi::Status> {
        self.mark_region_as(
            addr,
            num_pages,
            MemoryType::ReservedMemoryType,
            &[MemoryType::ReservedMemoryType],
        )
    }

    fn allocation_attribute(memory_type: MemoryType, source_attribute: u64) -> u64 {
        match memory_type {
            MemoryType::RuntimeServicesCode => {
                (source_attribute | attributes::EFI_MEMORY_RUNTIME) & !attributes::EFI_MEMORY_XP
            }
            MemoryType::RuntimeServicesData => {
                source_attribute | attributes::EFI_MEMORY_RUNTIME | attributes::EFI_MEMORY_XP
            }
            _ => source_attribute,
        }
    }

    fn allocate_conventional_range(
        &mut self,
        range: PageRange,
        memory_type: MemoryType,
    ) -> Result<(), efi::Status> {
        let descriptor_index = self
            .find_descriptor(range, &[MemoryType::ConventionalMemory])
            .ok_or(efi::Status::NOT_FOUND)?;
        let restore_attribute = self.entries[descriptor_index].attribute;
        let attribute = Self::allocation_attribute(memory_type, restore_attribute);
        self.retype_range(descriptor_index, range, memory_type, attribute)?;
        self.record_allocation(PageAllocation {
            range,
            memory_type,
            restore_attribute,
        })?;
        self.map_key += 1;
        Ok(())
    }

    /// Split the leading code pages from one newly allocated private runtime
    /// image. Public AllocateAddress deliberately cannot claim runtime data.
    fn retype_runtime_image_code(
        &mut self,
        image_range: PageRange,
        code_range: PageRange,
    ) -> Result<(), efi::Status> {
        if code_range.start() != image_range.start() || !image_range.contains(code_range) {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        let (allocation_index, _) = self
            .find_allocation(code_range)
            .filter(|(_, allocation)| {
                allocation.range == image_range
                    && allocation.memory_type == MemoryType::RuntimeServicesData
            })
            .ok_or(efi::Status::NOT_FOUND)?;
        let descriptor_index = self
            .find_descriptor(code_range, &[MemoryType::RuntimeServicesData])
            .ok_or(efi::Status::NOT_FOUND)?;
        let descriptor = self.entries[descriptor_index];
        let attribute =
            Self::allocation_attribute(MemoryType::RuntimeServicesCode, descriptor.attribute);
        self.retype_range(
            descriptor_index,
            code_range,
            MemoryType::RuntimeServicesCode,
            attribute,
        )?;
        // The mandatory image has firmware lifetime and is not a public page
        // allocation. Drop its temporary ownership record after the private
        // split so neither its code nor data can be independently FreePages'd.
        self.allocations.swap_remove(allocation_index);
        self.map_key += 1;
        Ok(())
    }

    /// Allocate pages of memory.
    pub fn allocate_pages(
        &mut self,
        alloc_type: AllocateType,
        memory_type: MemoryType,
        num_pages: u64,
        memory: &mut u64,
    ) -> efi::Status {
        if num_pages == 0 || !memory_type.is_valid_allocation_type() {
            return efi::Status::INVALID_PARAMETER;
        }
        if self.boot_services_exited {
            return efi::Status::UNSUPPORTED;
        }
        let address = match alloc_type {
            AllocateType::AllocateAnyPages => self.find_free_pages(num_pages, 0, u64::MAX),
            AllocateType::AllocateMaxAddress => self.find_free_pages(num_pages, 0, *memory),
            AllocateType::AllocateAddress => {
                if !memory.is_multiple_of(PAGE_SIZE) {
                    return efi::Status::INVALID_PARAMETER;
                }
                Some(*memory)
            }
        };
        let Some(range) = address.and_then(|address| PageRange::from_bytes(address, num_pages))
        else {
            return efi::Status::OUT_OF_RESOURCES;
        };

        let result = if self
            .find_descriptor(range, &[MemoryType::ConventionalMemory])
            .is_some()
        {
            if self.allocations.is_full() {
                return efi::Status::OUT_OF_RESOURCES;
            }
            self.allocate_conventional_range(range, memory_type)
        } else if alloc_type == AllocateType::AllocateAddress {
            // Some loaders claim a subrange of their image allocation. Split
            // both the descriptor and ownership record so the three ranges can
            // subsequently be freed independently.
            let claimable_types = [MemoryType::LoaderCode, MemoryType::LoaderData];
            let descriptor_index = match self.find_descriptor(range, &claimable_types) {
                Some(index) => index,
                None => return efi::Status::NOT_FOUND,
            };
            let descriptor = self.entries[descriptor_index];
            let containing_allocation = self.find_allocation(range);
            log::debug!(
                "AllocateAddress loader claim: range={:#x?}, type={:?}, parent={:?}",
                range,
                memory_type,
                containing_allocation.map(|(_, allocation)| allocation.range)
            );
            let replacement = PageAllocation {
                range,
                memory_type,
                restore_attribute: descriptor.attribute,
            };
            if let Some((_, allocation)) = containing_allocation {
                if !self.allocation_replacement_fits(allocation, range, Some(replacement)) {
                    return efi::Status::OUT_OF_RESOURCES;
                }
            } else if self.allocations.is_full() {
                return efi::Status::OUT_OF_RESOURCES;
            }

            let attribute = Self::allocation_attribute(memory_type, descriptor.attribute);
            self.retype_range(descriptor_index, range, memory_type, attribute)
                .and_then(|()| {
                    if let Some((allocation_index, _)) = containing_allocation {
                        self.replace_allocation_range(allocation_index, range, Some(replacement))
                    } else {
                        self.record_allocation(replacement)
                    }
                })
                .map(|()| self.map_key += 1)
        } else {
            Err(efi::Status::NOT_FOUND)
        };

        match result {
            Ok(()) => {
                *memory = range.start_bytes();
                efi::Status::SUCCESS
            }
            Err(status) => status,
        }
    }

    /// Free a page allocation or an allocated subrange.
    ///
    /// Subrange frees split the ownership record so the residual ranges remain
    /// independently freeable, matching the behavior expected by common UEFI
    /// loaders.
    ///
    /// A whole-range free may span multiple ownership records only when their
    /// memory type and restore attributes match. A range crossing a differently
    /// typed loader subclaim has no single memory descriptor to restore and
    /// returns [`efi::Status::NOT_FOUND`].
    pub fn free_pages(&mut self, memory: u64, num_pages: u64) -> efi::Status {
        if self.boot_services_exited {
            return efi::Status::UNSUPPORTED;
        }
        // Rejects misaligned addresses, zero page counts, and ranges that would
        // leave the address space in one construction.
        let Some(range) = PageRange::from_bytes(memory, num_pages) else {
            return efi::Status::INVALID_PARAMETER;
        };
        let allocation = self.find_allocation(range);
        let cover = allocation
            .map(|(_, allocation)| allocation)
            .or_else(|| exact_cover(self.allocations.as_slice(), range));
        let Some(cover) = cover else {
            return efi::Status::NOT_FOUND;
        };
        let Some(descriptor_index) = self.find_descriptor(range, &[cover.memory_type]) else {
            return efi::Status::NOT_FOUND;
        };
        if let Some((_, allocation)) = allocation
            && !self.allocation_replacement_fits(allocation, range, None)
        {
            return efi::Status::OUT_OF_RESOURCES;
        }

        if let Err(status) = self.retype_range(
            descriptor_index,
            range,
            MemoryType::ConventionalMemory,
            cover.restore_attribute,
        ) {
            return status;
        }
        if let Some((allocation_index, _)) = allocation {
            if let Err(status) = self.replace_allocation_range(allocation_index, range, None) {
                return status;
            }
        } else {
            for index in (0..self.allocations.len()).rev() {
                if range.contains(self.allocations[index].range) {
                    self.allocations.swap_remove(index);
                }
            }
        }
        self.map_key += 1;
        efi::Status::SUCCESS
    }

    /// Get the current memory map
    ///
    /// Adjacent entries with the same type and attributes are merged in the
    /// output to produce a compact map. The internal map is also kept compact;
    /// this output pass protects against any adjacent entries introduced by
    /// platform map construction.
    pub fn get_memory_map(
        &self,
        memory_map_size: &mut usize,
        memory_map: Option<&mut [MemoryDescriptor]>,
        map_key: &mut usize,
        descriptor_size: &mut usize,
        descriptor_version: &mut u32,
    ) -> efi::Status {
        let entry_size = core::mem::size_of::<MemoryDescriptor>();

        *descriptor_size = entry_size;
        *descriptor_version = 1;
        *map_key = self.map_key;

        let merged_count = self.count_merged_entries();
        let required_size = merged_count * entry_size;

        if let Some(map) = memory_map {
            if core::mem::size_of_val(map) < required_size {
                *memory_map_size = required_size;
                return efi::Status::BUFFER_TOO_SMALL;
            }

            // Merge adjacent same-type/attribute entries into the output buffer
            let out_count = self.entries.iter().fold(0usize, |out_idx, entry| {
                if out_idx > 0 && can_merge(&map[out_idx - 1], entry) {
                    map[out_idx - 1].number_of_pages += entry.number_of_pages;
                    out_idx
                } else {
                    map[out_idx] = *entry;
                    out_idx + 1
                }
            });

            // Strip memory protection attributes (RO, XP, RP) from returned
            // descriptors.  EDK2's CoreGetMemoryMap does the same.  Some OSes
            // (notably Windows) treat these as mandatory page-table attributes
            // and will set NX or read-only on runtime memory — causing crashes
            // when calling runtime services.  The separate Memory Attributes
            // Table carries the authoritative protection info instead.
            const STRIP_MASK: u64 = !(attributes::EFI_MEMORY_RO
                | attributes::EFI_MEMORY_XP
                | attributes::EFI_MEMORY_RP);
            for desc in map[..out_count].iter_mut() {
                desc.attribute &= STRIP_MASK;
            }

            *memory_map_size = out_count * entry_size;
            efi::Status::SUCCESS
        } else {
            *memory_map_size = required_size;
            efi::Status::BUFFER_TOO_SMALL
        }
    }

    /// Count how many entries the memory map has after merging adjacent regions
    fn count_merged_entries(&self) -> usize {
        self.entries
            .windows(2)
            .filter(|pair| !can_merge(&pair[0], &pair[1]))
            .count()
            + if self.entries.is_empty() { 0 } else { 1 }
    }

    /// Get the current map key
    pub fn map_key(&self) -> usize {
        self.map_key
    }

    /// Get the number of entries
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Dump all memory map entries to the log (for debugging).
    ///
    /// This prints every entry in the internal sorted list, which is the
    /// pre-merge view. The EFI GetMemoryMap merges adjacent same-type
    /// entries, so the actual EFI map may have fewer entries.
    pub fn dump_entries(&self) {
        let type_name = |t: u32| -> &'static str {
            match t {
                0 => "Reserved",
                1 => "LoaderCode",
                2 => "LoaderData",
                3 => "BSCode",
                4 => "BSData",
                5 => "RTCode",
                6 => "RTData",
                7 => "Conventional",
                8 => "Unusable",
                9 => "ACPIReclaim",
                10 => "ACPINvs",
                11 => "MMIO",
                12 => "MMIOPort",
                13 => "PalCode",
                14 => "Persistent",
                _ => "Unknown",
            }
        };
        log::info!(
            "Memory map dump ({} entries, {} after merge):",
            self.entries.len(),
            self.count_merged_entries()
        );
        for (i, e) in self.entries.iter().enumerate() {
            let pages = PageCount::new(e.number_of_pages);
            let size_mb = pages.bytes().unwrap_or(u64::MAX) >> 20;
            log::info!(
                "  [{:2}] {:#012x}-{:#012x} {:>12} {:6} pages ({} MB) attr={:#x}",
                i,
                e.physical_start,
                e.page_range().map_or(u64::MAX, PageRange::end_bytes),
                type_name(e.memory_type),
                e.number_of_pages,
                size_mb,
                e.attribute
            );
        }
    }

    pub fn validate_map_key(&self, provided_map_key: usize) -> efi::Status {
        if provided_map_key == self.map_key && !self.boot_services_exited {
            efi::Status::SUCCESS
        } else {
            log::warn!(
                "exit_boot_services: map_key mismatch or inactive allocator; expected {:#x}, got {:#x}",
                self.map_key,
                provided_map_key
            );
            efi::Status::INVALID_PARAMETER
        }
    }

    /// Mark boot services as exited
    pub fn exit_boot_services(&mut self, provided_map_key: usize) -> efi::Status {
        log::debug!(
            "exit_boot_services: provided_key={:#x}, current_key={:#x}",
            provided_map_key,
            self.map_key
        );

        let key_status = self.validate_map_key(provided_map_key);
        if key_status != efi::Status::SUCCESS {
            return key_status;
        }

        self.boot_services_exited = true;
        disable_pool_allocator();

        // Log handoff-critical regions: runtime services must keep the
        // RUNTIME attribute, and loader regions must remain reserved for the
        // OS loader / EFI stub across ExitBootServices.
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
                MemoryType::RuntimeServicesCode
                    | MemoryType::RuntimeServicesData
                    | MemoryType::LoaderCode
                    | MemoryType::LoaderData
            ) {
                log::info!(
                    "  Handoff: {:#x}-{:#x} type={:?} attr={:#x} RUNTIME={}",
                    entry.physical_start,
                    entry.end(),
                    mem_type,
                    entry.attribute,
                    has_runtime
                );
            }
        }

        // Convert only firmware-owned BootServicesCode/Data to conventional
        // memory. LoaderCode/Data belongs to the OS loader and may contain the
        // loaded kernel, initrd, command line, PE memory-map buffers, or other
        // handoff data. If firmware reclaims LoaderData here, Linux can reuse
        // those ranges during early boot before it has consumed/reserved them,
        // causing corruption (e.g. NODE_DATA over initrd/handoff memory).
        for entry in self.entries.iter_mut() {
            if matches!(
                entry.get_memory_type(),
                Some(MemoryType::BootServicesCode | MemoryType::BootServicesData)
            ) {
                entry.memory_type = MemoryType::ConventionalMemory as u32;
            }
        }

        // Ownership records are a Boot Services implementation detail. They
        // must not retain stale claims on memory handed to the OS.
        self.allocations.clear();
        self.map_key += 1;
        self.merge_entries();

        log::info!("ExitBootServices complete, new map_key={:#x}", self.map_key);
        efi::Status::SUCCESS
    }

    /// Find free pages that fit the requirements
    fn find_free_pages(&self, num_pages: u64, min_addr: u64, max_addr: u64) -> Option<u64> {
        let size = num_pages.checked_mul(PAGE_SIZE)?;
        let min_addr = min_addr.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);

        // EFI AllocateMaxAddress is inclusive: the final byte of the entire
        // allocation must be no greater than the caller's maximum address.
        #[allow(clippy::unnecessary_min_or_max)]
        let max_addr = max_addr.min(MAX_IDENTITY_MAPPED_ADDRESS);
        let max_end = max_addr.checked_add(1);

        // Search from high to low addresses (prefer high memory within the limit).
        for entry in self.entries.iter().rev() {
            if entry.get_memory_type() != Some(MemoryType::ConventionalMemory)
                || entry.physical_start > max_addr
                || entry.end() <= min_addr
            {
                continue;
            }

            let usable_end = max_end.map_or(entry.end(), |end| entry.end().min(end));
            let usable_start = entry.physical_start.max(min_addr);
            let minimum_end = usable_start.checked_add(size)?;
            if usable_end < minimum_end {
                continue;
            }

            let address = (usable_end - size) & !(PAGE_SIZE - 1);
            if address >= usable_start {
                return Some(address);
            }
        }

        None
    }

    /// Carve out a region from existing memory and mark it as a new type
    ///
    /// By default, carves from ConventionalMemory. Use `carve_out_from` to
    /// specify which source types are acceptable.
    fn carve_out(
        &mut self,
        addr: u64,
        num_pages: u64,
        memory_type: MemoryType,
    ) -> Result<(), efi::Status> {
        self.carve_out_from(
            addr,
            num_pages,
            memory_type,
            &[MemoryType::ConventionalMemory],
        )
    }

    /// Carve out a region from memory of any of the given source types
    ///
    /// Splits the containing entry (which must be one of `source_types`) into
    /// up to 3 entries: a prefix of the original type, the carved region with
    /// `memory_type`, and a suffix of the original type.
    fn carve_out_from(
        &mut self,
        addr: u64,
        num_pages: u64,
        memory_type: MemoryType,
        source_types: &[MemoryType],
    ) -> Result<(), efi::Status> {
        let range = PageRange::from_bytes(addr, num_pages).ok_or(efi::Status::INVALID_PARAMETER)?;
        let descriptor_index = self
            .find_descriptor(range, source_types)
            .ok_or(efi::Status::NOT_FOUND)?;
        let attribute =
            Self::allocation_attribute(memory_type, self.entries[descriptor_index].attribute);
        self.retype_range(descriptor_index, range, memory_type, attribute)?;
        self.map_key += 1;
        Ok(())
    }

    /// Sort entries by physical address (ascending)
    fn sort_entries(&mut self) {
        self.entries
            .as_mut_slice()
            .sort_unstable_by_key(|entry| entry.physical_start);
    }

    /// Merge entries around a recently replaced descriptor while preserving sort order.
    fn merge_near(&mut self, index: usize) {
        if self.entries.len() < 2 {
            return;
        }
        // A retype inserts at most three descriptors. Only the replacement's
        // two internal boundaries and its immediate outer neighbours can merge.
        let mut current = index.saturating_sub(1);
        let mut end = (index + 3).min(self.entries.len());
        while current + 1 < end {
            if can_merge(&self.entries[current], &self.entries[current + 1]) {
                self.entries[current].number_of_pages += self.entries[current + 1].number_of_pages;
                self.entries.remove(current + 1);
                end -= 1;
            } else {
                current += 1;
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
            if can_merge(&self.entries[i], &self.entries[i + 1]) {
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

/// Initialize the global allocator from a platform-provided memory map.
pub fn init_from_platform(regions: &[crate::platform::MemoryRegion]) {
    state::with_allocator_mut(|alloc| {
        alloc.init_from_platform(regions);
    });
}

/// Reserve a region of memory
pub fn reserve_region(
    physical_start: u64,
    num_pages: u64,
    memory_type: MemoryType,
) -> Result<(), efi::Status> {
    state::with_allocator_mut(|alloc| alloc.reserve_region(physical_start, num_pages, memory_type))
}

/// Reserve all ConventionalMemory fragments in a range while preserving
/// pre-typed holes such as ACPI reclaim and SMBIOS reserved pages.
pub fn reserve_region_fragments(
    physical_start: u64,
    num_pages: u64,
    memory_type: MemoryType,
) -> Result<(), efi::Status> {
    state::with_allocator_mut(|alloc| {
        alloc.reserve_region_fragments(physical_start, num_pages, memory_type)
    })
}

/// Force-add a memory region to the map
///
/// This is used when the region isn't in the coreboot map at all.
pub fn force_add_region(
    physical_start: u64,
    num_pages: u64,
    memory_type: MemoryType,
) -> Result<(), efi::Status> {
    state::with_allocator_mut(|alloc| {
        alloc.force_add_region(physical_start, num_pages, memory_type)
    })
}

/// Carve a physical range out of its containing map entry as `memory_type`.
///
/// Unlike `force_add_region`, this splits the containing Reserved/Conventional
/// entry and never creates overlapping memory map entries (which confuse the
/// Linux kernel's EFI mapping code).
pub fn carve_out_region(
    physical_start: u64,
    num_pages: u64,
    memory_type: MemoryType,
) -> Result<(), efi::Status> {
    let source_types = &[
        MemoryType::ReservedMemoryType,
        MemoryType::ConventionalMemory,
        MemoryType::BootServicesData,
    ];
    state::with_allocator_mut(|alloc| {
        alloc.carve_out_from(physical_start, num_pages, memory_type, source_types)
    })
}

/// Mark a memory region as ACPI Reclaim Memory
///
/// This properly splits existing regions and marks the specified range as AcpiReclaimMemory.
pub fn mark_as_acpi_reclaim(addr: u64, num_pages: u64) -> Result<(), efi::Status> {
    state::with_allocator_mut(|alloc| alloc.mark_as_acpi_reclaim(addr, num_pages))
}

/// Mark a memory region as Reserved Memory
///
/// This properly splits existing regions and marks the specified range as ReservedMemoryType.
pub fn mark_as_reserved(addr: u64, num_pages: u64) -> Result<(), efi::Status> {
    state::with_allocator_mut(|alloc| alloc.mark_as_reserved(addr, num_pages))
}

/// Allocate pages of memory
pub fn allocate_pages(
    alloc_type: AllocateType,
    memory_type: MemoryType,
    num_pages: u64,
    memory: &mut u64,
) -> efi::Status {
    state::with_allocator_mut(|alloc| {
        alloc.allocate_pages(alloc_type, memory_type, num_pages, memory)
    })
}

/// Allocate pages wholly contained in an inclusive physical-address range.
pub fn allocate_pages_in_range(
    memory_type: MemoryType,
    num_pages: u64,
    min_address: u64,
    max_address: u64,
    memory: &mut u64,
) -> efi::Status {
    state::with_allocator_mut(|allocator| {
        let Some(address) = allocator.find_free_pages(num_pages, min_address, max_address) else {
            return efi::Status::OUT_OF_RESOURCES;
        };
        *memory = address;
        allocator.allocate_pages(
            AllocateType::AllocateAddress,
            memory_type,
            num_pages,
            memory,
        )
    })
}

/// Free previously allocated pages
pub fn free_pages(memory: u64, num_pages: u64) -> efi::Status {
    state::with_allocator_mut(|alloc| alloc.free_pages(memory, num_pages))
}

/// Dump the full memory map to the log (for debugging).
pub fn dump_memory_map() {
    let alloc = state::allocator();
    alloc.dump_entries();
}

/// Get the memory map size
pub fn get_memory_map_size() -> usize {
    let alloc = state::allocator();
    alloc.entry_count() * core::mem::size_of::<MemoryDescriptor>()
}

/// Get current map key
pub fn get_map_key() -> usize {
    let alloc = state::allocator();
    alloc.map_key()
}

/// Find the memory type for a given physical address
///
/// Returns the memory type if the address is within a known memory region,
/// or None if the address is not in any known region.
pub fn copy_runtime_descriptors(output: &mut [MemoryDescriptor]) -> Result<usize, efi::Status> {
    let allocator = state::allocator();
    let runtime = allocator
        .entries
        .iter()
        .filter(|entry| entry.attribute & attributes::EFI_MEMORY_RUNTIME != 0);
    let mut count = 0usize;
    for descriptor in runtime {
        let Some(slot) = output.get_mut(count) else {
            return Err(efi::Status::BUFFER_TOO_SMALL);
        };
        *slot = *descriptor;
        count += 1;
    }
    Ok(count)
}

/// Find the memory type for a given physical address.
pub fn get_memory_type_at(address: u64) -> Option<MemoryType> {
    let alloc = state::allocator();
    alloc
        .entries
        .iter()
        .find(|entry| address >= entry.physical_start && address < entry.end())
        .and_then(|entry| MemoryType::try_from(entry.memory_type).ok())
}

/// Verify complete, gap-free descriptor coverage of a physical interval.
pub fn range_has_memory_type(base: u64, size: u64, memory_type: MemoryType) -> bool {
    let Some(end) = base.checked_add(size) else {
        return false;
    };
    if size == 0 {
        return false;
    }
    let allocator = state::allocator();
    let mut covered = base;
    for descriptor in allocator.entries.iter() {
        if descriptor.end() <= covered {
            continue;
        }
        if descriptor.physical_start > covered
            || MemoryType::try_from(descriptor.memory_type).ok() != Some(memory_type)
        {
            return false;
        }
        covered = descriptor.end().min(end);
        if covered == end {
            return true;
        }
    }
    false
}

/// Get the memory map
pub fn get_memory_map(
    memory_map_size: &mut usize,
    memory_map: Option<&mut [MemoryDescriptor]>,
    map_key: &mut usize,
    descriptor_size: &mut usize,
    descriptor_version: &mut u32,
) -> efi::Status {
    let alloc = state::allocator();
    alloc.get_memory_map(
        memory_map_size,
        memory_map,
        map_key,
        descriptor_size,
        descriptor_version,
    )
}

/// Validate an ExitBootServices map key without changing allocator state.
pub fn validate_map_key(map_key: usize) -> efi::Status {
    state::allocator().validate_map_key(map_key)
}

/// Exit boot services
pub fn exit_boot_services(map_key: usize) -> efi::Status {
    state::with_allocator_mut(|alloc| alloc.exit_boot_services(map_key))
}

/// Allocate one contiguous runtime image and privately split its leading code
/// domain without exposing RuntimeServicesData to public AllocateAddress claims.
pub fn allocate_runtime_image_layout(
    image_pages: u64,
    code_pages: u64,
) -> Result<u64, efi::Status> {
    if image_pages == 0 || code_pages == 0 || code_pages > image_pages {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    state::with_allocator_mut(|allocator| {
        let mut base = 0;
        let status = allocator.allocate_pages(
            AllocateType::AllocateAnyPages,
            MemoryType::RuntimeServicesData,
            image_pages,
            &mut base,
        );
        if status != efi::Status::SUCCESS {
            return Err(status);
        }
        let image_range =
            PageRange::from_bytes(base, image_pages).ok_or(efi::Status::OUT_OF_RESOURCES)?;
        let code_range =
            PageRange::from_bytes(base, code_pages).ok_or(efi::Status::OUT_OF_RESOURCES)?;
        if let Err(status) = allocator.retype_runtime_image_code(image_range, code_range) {
            let _ = allocator.free_pages(base, image_pages);
            return Err(status);
        }
        Ok(base)
    })
}

// Lock ordering: never hold POOL_STATE while entering the page allocator. Pool
// growth deliberately drops this lock before AllocatePages to avoid re-entry.
static POOL_STATE: spin::Mutex<PoolState> = spin::Mutex::new(PoolState::new());
static POOL_DISABLED: AtomicBool = AtomicBool::new(false);
const BOOT_POOL_CHUNK_PAGES: u64 = 64;
const RUNTIME_POOL_CHUNK_PAGES: u64 = 4;

fn pool_chunk_pages(memory_type: MemoryType) -> u64 {
    if matches!(
        memory_type,
        MemoryType::RuntimeServicesCode | MemoryType::RuntimeServicesData
    ) {
        RUNTIME_POOL_CHUNK_PAGES
    } else {
        BOOT_POOL_CHUNK_PAGES
    }
}

fn disable_pool_allocator() {
    POOL_DISABLED.store(true, Ordering::Release);
    POOL_STATE.lock().disable();
}

fn take_pool_block(memory_type: MemoryType, size: usize) -> Option<(*mut u8, usize)> {
    match POOL_STATE.lock().take(memory_type as u32, size) {
        Ok(block) => block,
        Err(PoolListError::InvalidMagic) => {
            log::error!("Pool free list contains a node with invalid magic; truncating list");
            None
        }
        Err(PoolListError::BlockSizeOverflow) => {
            log::error!("Pool free-list block size does not fit usize; truncating list");
            None
        }
    }
}

/// Insert an owned range into the pool free list.
///
/// # Safety
///
/// See [`PoolState::insert`]. POOL_STATE must not already be locked.
unsafe fn insert_pool_block(address: *mut u8, size: usize, memory_type: u32) {
    // Safety: forwarded from the caller under the documented contract.
    unsafe { POOL_STATE.lock().insert(address, size, memory_type) };
}

/// Allocate pool memory from reusable page-backed chunks.
pub fn allocate_pool(memory_type: MemoryType, size: usize) -> Result<*mut u8, efi::Status> {
    if size == 0 || !memory_type.is_valid_allocation_type() {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    if POOL_DISABLED.load(Ordering::Acquire) {
        return Err(efi::Status::UNSUPPORTED);
    }
    let total_size = align_pool_size(
        size.checked_add(core::mem::size_of::<PoolHeader>())
            .ok_or(efi::Status::OUT_OF_RESOURCES)?,
    )
    .ok_or(efi::Status::OUT_OF_RESOURCES)?;

    let (address, block_size) = match take_pool_block(memory_type, total_size) {
        Some(block) => block,
        None => {
            let requested_pages = (total_size as u64).div_ceil(PAGE_SIZE);
            let pages = requested_pages.max(pool_chunk_pages(memory_type));
            let mut address = 0;
            let status = allocate_pages(
                AllocateType::AllocateAnyPages,
                memory_type,
                pages,
                &mut address,
            );
            if status != efi::Status::SUCCESS {
                return Err(status);
            }
            // Safety: AllocatePages returned exclusive writable pages.
            unsafe {
                insert_pool_block(
                    address as *mut u8,
                    (pages * PAGE_SIZE) as usize,
                    memory_type as u32,
                )
            };
            take_pool_block(memory_type, total_size).ok_or(efi::Status::OUT_OF_RESOURCES)?
        }
    };

    let header = address.cast::<PoolHeader>();
    // Safety: take_pool_block returned an exclusively owned aligned block.
    unsafe {
        header.write(PoolHeader {
            magic: POOL_ALLOCATED_MAGIC,
            block_size: block_size as u64,
            memory_type: memory_type as u32,
            reserved: 0,
            padding: 0,
        });
        Ok(address.add(core::mem::size_of::<PoolHeader>()))
    }
}

/// Return a pool block to the reusable free list.
///
/// `buffer` must be a pointer previously returned by [`allocate_pool`], as
/// required by the UEFI `FreePool` contract.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn free_pool(buffer: *mut u8) -> efi::Status {
    if buffer.is_null() || POOL_DISABLED.load(Ordering::Acquire) {
        return efi::Status::INVALID_PARAMETER;
    }
    // Safety: the UEFI contract requires buffer to be a live AllocatePool result.
    let header = unsafe {
        buffer
            .sub(core::mem::size_of::<PoolHeader>())
            .cast::<PoolHeader>()
    };
    // Safety: header is readable under the FreePool caller contract.
    let header_ref = unsafe { &mut *header };
    if header_ref.magic != POOL_ALLOCATED_MAGIC {
        return efi::Status::INVALID_PARAMETER;
    }
    let Ok(block_size) = usize::try_from(header_ref.block_size) else {
        return efi::Status::INVALID_PARAMETER;
    };
    let memory_type = header_ref.memory_type;
    header_ref.magic = POOL_FREE_MAGIC;
    // Safety: this allocation exclusively owns the complete recorded block.
    unsafe { insert_pool_block(header.cast::<u8>(), block_size, memory_type) };
    efi::Status::SUCCESS
}

// Linker symbols for section boundaries (only when CrabEFI owns the binary layout).
#[cfg(feature = "platform-entry")]
unsafe extern "C" {
    static __boot_code_start: u8;
    static __boot_code_end: u8;
    static __boot_data_start: u8;
    static __boot_data_end: u8;
}

/// Reserve the CrabEFI boot image regions using linker-provided section boundaries.
///
/// Only available with the `platform-entry` feature (when CrabEFI owns
/// the linker script). Library consumers describe the embedding image as
/// BootServices memory in the platform memory map.
///
/// The complete payload, including stack and page tables, is reclaimed after
/// ExitBootServices. Only the independent runtime image survives.
#[cfg(feature = "platform-entry")]
pub fn reserve_boot_image_region() {
    // Get section boundaries from linker symbols
    let code_start = unsafe { &__boot_code_start as *const u8 as u64 };
    let code_end = unsafe { &__boot_code_end as *const u8 as u64 };
    let data_start = unsafe { &__boot_data_start as *const u8 as u64 };
    let data_end = unsafe { &__boot_data_end as *const u8 as u64 };

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
        "Boot code region from linker: {:#x}-{:#x} ({} pages)",
        code_start_aligned,
        code_end_aligned,
        code_pages
    );
    log::info!(
        "Boot data region from linker: {:#x}-{:#x} ({} pages)",
        data_start_aligned,
        data_end_aligned,
        data_pages
    );

    // Types we can carve boot image regions from: the payload sits in either
    // a Reserved region (coreboot marks the payload area as CB_MEM_RESERVED)
    // or ConventionalMemory (if the mapping differs).
    let source_types = &[
        MemoryType::ReservedMemoryType,
        MemoryType::ConventionalMemory,
    ];

    // Reserve the CODE region (executable, no XP attribute)
    match state::with_allocator_mut(|alloc| {
        alloc.carve_out_from(
            code_start_aligned,
            code_pages,
            MemoryType::BootServicesCode,
            source_types,
        )
    }) {
        Ok(()) => {
            log::info!(
                "Reserved boot image code region: {:#x}-{:#x}",
                code_start_aligned,
                code_end_aligned
            );
        }
        Err(e) => {
            log::error!("CRITICAL: Failed to reserve boot code region: {:?}", e);
        }
    }

    // Reserve the DATA region (non-executable, XP attribute set)
    // Skip if there are no pages to reserve
    if data_pages > 0 {
        match state::with_allocator_mut(|alloc| {
            alloc.carve_out_from(
                data_start_aligned,
                data_pages,
                MemoryType::BootServicesData,
                source_types,
            )
        }) {
            Ok(()) => {
                log::info!(
                    "Reserved boot image data region: {:#x}-{:#x}",
                    data_start_aligned,
                    data_end_aligned
                );
            }
            Err(e) => {
                log::error!("CRITICAL: Failed to reserve boot data region: {:?}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocator_with_ram() -> MemoryAllocator {
        let mut allocator = MemoryAllocator::new();
        allocator
            .entries
            .push(memory_descriptor(
                MemoryType::ConventionalMemory,
                0x10_0000,
                32,
                attributes::EFI_MEMORY_RAM_CAPS,
            ))
            .unwrap();
        allocator
    }

    #[test]
    fn acpi_marking_preserves_platform_reserved_memory() {
        let mut allocator = allocator_with_ram();
        let reserved_start = 0x20_0000;
        allocator
            .entries
            .push(memory_descriptor(
                MemoryType::ReservedMemoryType,
                reserved_start,
                4,
                attributes::EFI_MEMORY_RAM_CAPS,
            ))
            .unwrap();

        allocator.mark_as_acpi_reclaim(reserved_start, 4).unwrap();
        allocator.mark_as_acpi_reclaim(0x10_0000, 4).unwrap();

        assert_eq!(
            allocator
                .entries
                .iter()
                .find(|entry| entry.physical_start == reserved_start)
                .and_then(MemoryDescriptorExt::get_memory_type),
            Some(MemoryType::ReservedMemoryType)
        );
        assert_eq!(
            allocator
                .entries
                .iter()
                .find(|entry| entry.physical_start == 0x10_0000)
                .and_then(MemoryDescriptorExt::get_memory_type),
            Some(MemoryType::AcpiReclaimMemory)
        );
    }

    #[test]
    fn public_allocate_address_cannot_subclaim_runtime_image_data() {
        let mut allocator = allocator_with_ram();
        let mut base = 0;
        assert_eq!(
            allocator.allocate_pages(
                AllocateType::AllocateAnyPages,
                MemoryType::RuntimeServicesData,
                4,
                &mut base,
            ),
            efi::Status::SUCCESS
        );
        let mut claim = base;
        assert_eq!(
            allocator.allocate_pages(
                AllocateType::AllocateAddress,
                MemoryType::RuntimeServicesCode,
                1,
                &mut claim,
            ),
            efi::Status::NOT_FOUND
        );
    }

    #[test]
    fn private_runtime_layout_split_preserves_runtime_attributes() {
        let mut allocator = allocator_with_ram();
        let mut base = 0;
        assert_eq!(
            allocator.allocate_pages(
                AllocateType::AllocateAnyPages,
                MemoryType::RuntimeServicesData,
                4,
                &mut base,
            ),
            efi::Status::SUCCESS
        );
        let image = PageRange::from_bytes(base, 4).unwrap();
        let code = PageRange::from_bytes(base, 1).unwrap();
        allocator.retype_runtime_image_code(image, code).unwrap();
        let code_descriptor = allocator
            .entries
            .iter()
            .find(|entry| entry.physical_start == base)
            .unwrap();
        assert_eq!(
            code_descriptor.get_memory_type(),
            Some(MemoryType::RuntimeServicesCode)
        );
        assert_ne!(
            code_descriptor.attribute & attributes::EFI_MEMORY_RUNTIME,
            0
        );
        assert_eq!(code_descriptor.attribute & attributes::EFI_MEMORY_XP, 0);
        let data_descriptor = allocator
            .entries
            .iter()
            .find(|entry| entry.physical_start == base + PAGE_SIZE)
            .unwrap();
        assert_eq!(
            data_descriptor.get_memory_type(),
            Some(MemoryType::RuntimeServicesData)
        );
        assert_ne!(data_descriptor.attribute & attributes::EFI_MEMORY_XP, 0);
        assert_eq!(allocator.free_pages(base, 1), efi::Status::NOT_FOUND);
        assert_eq!(
            allocator.free_pages(base + PAGE_SIZE, 3),
            efi::Status::NOT_FOUND
        );
        assert_eq!(
            allocator
                .entries
                .iter()
                .find(|entry| entry.physical_start == base)
                .and_then(MemoryDescriptorExt::get_memory_type),
            Some(MemoryType::RuntimeServicesCode)
        );
    }

    #[test]
    fn invalid_exit_map_key_leaves_boot_services_active() {
        let mut allocator = allocator_with_ram();
        let current = allocator.map_key();
        assert_eq!(
            allocator.exit_boot_services(current.wrapping_add(1)),
            efi::Status::INVALID_PARAMETER
        );
        assert!(!allocator.boot_services_exited);
        assert_eq!(allocator.exit_boot_services(current), efi::Status::SUCCESS);
        assert!(allocator.boot_services_exited);
    }

    #[test]
    fn loader_subclaims_remain_supported() {
        let mut allocator = allocator_with_ram();
        let mut base = 0;
        assert_eq!(
            allocator.allocate_pages(
                AllocateType::AllocateAnyPages,
                MemoryType::LoaderData,
                4,
                &mut base,
            ),
            efi::Status::SUCCESS
        );
        let mut claim = base;
        assert_eq!(
            allocator.allocate_pages(
                AllocateType::AllocateAddress,
                MemoryType::LoaderCode,
                1,
                &mut claim,
            ),
            efi::Status::SUCCESS
        );
    }
}
