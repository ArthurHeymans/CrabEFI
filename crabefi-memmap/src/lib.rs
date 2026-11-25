//! EFI memory map and page ownership.
//!
//! [`MemoryMap`] implements the page-granular half of EFI AllocatePages,
//! FreePages, GetMemoryMap and ExitBootServices as plain data: a sorted list
//! of memory descriptors plus exact ownership records for live allocations.
//! It has no global state, no hardware access and no allocator, so the same
//! code runs in firmware, in host tests and under Kani.
//!
//! Table capacities are const generics. Firmware instantiates the production
//! sizes; unit and property tests instantiate the same code with small tables.
//!
//! [`MemoryMap::check_well_formed`] states the invariant every public page
//! operation preserves (excluding trusted platform construction). Property
//! tests check it after every step; Kani proves the underlying range-splitting
//! and exact-cover arithmetic over all 64-bit inputs.

#![no_std]
#![deny(unsafe_code)]

// Logging is diagnostics only. Kani does not model the `log` crate's atomic
// level check, and `core::fmt` would dominate every proof, so proofs build
// without it.
macro_rules! log_at {
    ($level:ident, $($arg:tt)*) => {{
        #[cfg(not(kani))]
        log::$level!($($arg)*);
    }};
}
macro_rules! error { ($($arg:tt)*) => { log_at!(error, $($arg)*) }; }
macro_rules! warn { ($($arg:tt)*) => { log_at!(warn, $($arg)*) }; }
macro_rules! info { ($($arg:tt)*) => { log_at!(info, $($arg)*) }; }
macro_rules! debug { ($($arg:tt)*) => { log_at!(debug, $($arg)*) }; }

use core::ops::RangeInclusive;

use heapless::Vec;
use r_efi::efi;

pub use crabefi_runtime_abi::MemoryDescriptor;

pub mod page_ownership;
mod region;

pub use page_ownership::PAGE_SIZE;
pub use region::{MemoryRegion, RegionType};

use page_ownership::{
    PageCount, PageRange, RangeSplit, exact_cover, fits_after_replacement, split_allocation,
};

/// Exact ownership record of one live page allocation.
pub type PageAllocation = page_ownership::PageAllocation<MemoryType>;

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

/// End of the allowed range that [`MemoryMap::allocate_pages_in_range`] fills first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// Lowest fitting address.
    Lowest,
    /// Highest fitting address, as for AllocateAnyPages.
    Highest,
}

/// Rejected [`AllocateType`] value from an EFI caller.
///
/// Carries the offending raw value so callers can log it instead of
/// silently dropping it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidAllocateType(pub u32);

impl core::fmt::Display for InvalidAllocateType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid AllocateType value {}", self.0)
    }
}

impl TryFrom<u32> for AllocateType {
    type Error = InvalidAllocateType;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AllocateType::AllocateAnyPages),
            1 => Ok(AllocateType::AllocateMaxAddress),
            2 => Ok(AllocateType::AllocateAddress),
            other => Err(InvalidAllocateType(other)),
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
    type Error = InvalidMemoryType;

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
            other => Err(InvalidMemoryType(other)),
        }
    }
}

/// Rejected [`MemoryType`] value from an EFI caller.
///
/// Carries the offending raw value so callers can log it instead of
/// silently dropping it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMemoryType(pub u32);

impl core::fmt::Display for InvalidMemoryType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid MemoryType value {}", self.0)
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

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum BootServicesState {
    Active = 0,
    Exiting = 1,
    Exited = 2,
}

/// EFI memory map with exact page ownership.
///
/// `ADDRESS_LIMIT` is the highest byte address (inclusive) that searching
/// allocations (`AllocateAnyPages` / `AllocateMaxAddress`) may return, for
/// example the last identity-mapped byte. `AllocateAddress` is not limited.
/// Keeping the limit as a const generic and storing the map key zero-based
/// leaves a fresh `MemoryMap` all-zero so production statics live in `.bss`.
pub struct MemoryMap<
    const ENTRIES: usize,
    const OWNERS: usize,
    const ADDRESS_LIMIT: u64 = { u64::MAX },
> {
    /// Memory map entries, sorted by physical address (ascending)
    entries: Vec<MemoryDescriptor, ENTRIES>,
    /// Exact page allocations, retained even when adjacent map descriptors merge.
    allocations: Vec<PageAllocation, OWNERS>,
    /// Offset from the initial key (`1`), incremented on every change.
    map_key_offset: usize,
    boot_services: BootServicesState,
}

impl<const ENTRIES: usize, const OWNERS: usize, const ADDRESS_LIMIT: u64> Default
    for MemoryMap<ENTRIES, OWNERS, ADDRESS_LIMIT>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const ENTRIES: usize, const OWNERS: usize, const ADDRESS_LIMIT: u64>
    MemoryMap<ENTRIES, OWNERS, ADDRESS_LIMIT>
{
    /// Create an empty map whose searching allocations end at or below
    /// `ADDRESS_LIMIT` (inclusive).
    pub const fn new() -> Self {
        const {
            assert!(ENTRIES >= 1 && OWNERS >= 1);
        }
        Self {
            entries: Vec::new(),
            allocations: Vec::new(),
            map_key_offset: 0,
            boot_services: BootServicesState::Active,
        }
    }

    /// The internal descriptors, sorted and coalesced, with protection attributes intact.
    pub fn descriptors(&self) -> &[MemoryDescriptor] {
        &self.entries
    }

    /// The live ownership records.
    pub fn allocations(&self) -> &[PageAllocation] {
        &self.allocations
    }

    /// Whether ExitBootServices has committed.
    pub fn boot_services_exited(&self) -> bool {
        self.boot_services == BootServicesState::Exited
    }

    /// The OS's map key has been accepted, but DMA has not necessarily stopped.
    pub fn boot_services_exiting(&self) -> bool {
        self.boot_services == BootServicesState::Exiting
    }

    fn require_active(&self) -> Result<(), efi::Status> {
        if self.boot_services == BootServicesState::Active {
            Ok(())
        } else {
            Err(efi::Status::UNSUPPORTED)
        }
    }

    /// Check the invariant that AllocatePages, FreePages and the private
    /// image retyping operations preserve:
    ///
    /// - every descriptor is a non-empty, page-aligned range that fits in the
    ///   address space and has a known EFI memory type;
    /// - descriptors are sorted, pairwise disjoint and coalesced;
    /// - every ownership record is non-empty, has an allocatable type and lies
    ///   inside one descriptor of that type, whose attribute is the one
    ///   allocation derives from the record's restore attribute;
    /// - ownership records are pairwise disjoint;
    /// - no ownership record survives ExitBootServices.
    ///
    /// Platform map construction ([`Self::force_add_region`],
    /// [`Self::mark_as_reserved`], ...) runs before any allocation and is
    /// trusted input, not covered by this contract.
    pub fn check_well_formed(&self) -> Result<(), &'static str> {
        let mut previous_end = None;
        for entry in &self.entries {
            let range = entry
                .page_range()
                .ok_or("descriptor is empty, misaligned or overflows")?;
            entry
                .get_memory_type()
                .ok_or("descriptor has an unknown memory type")?;
            if previous_end.is_some_and(|end| range.start() < end) {
                return Err("descriptors overlap or are unsorted");
            }
            previous_end = Some(range.end());
        }
        if self
            .entries
            .windows(2)
            .any(|pair| can_merge(&pair[0], &pair[1]))
        {
            return Err("adjacent compatible descriptors are not coalesced");
        }
        if self.boot_services_exited() && !self.allocations.is_empty() {
            return Err("ownership survived ExitBootServices");
        }
        for (index, allocation) in self.allocations.iter().enumerate() {
            if allocation.range.is_empty() {
                return Err("ownership record is empty");
            }
            if !allocation.memory_type.is_valid_allocation_type() {
                return Err("ownership record has a non-allocatable type");
            }
            let descriptor = self
                .entries
                .iter()
                .find(|entry| {
                    entry
                        .page_range()
                        .is_some_and(|range| range.contains(allocation.range))
                })
                .ok_or("ownership record is not inside one descriptor")?;
            if descriptor.get_memory_type() != Some(allocation.memory_type) {
                return Err("ownership record type differs from its descriptor");
            }
            if descriptor.attribute
                != Self::allocation_attribute(allocation.memory_type, allocation.restore_attribute)
            {
                return Err("descriptor attribute does not derive from its owner");
            }
            if self.allocations[index + 1..]
                .iter()
                .any(|other| other.range.overlaps(allocation.range))
            {
                return Err("ownership records overlap");
            }
        }
        Ok(())
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
            error!("Page allocation ownership table is full");
            efi::Status::OUT_OF_RESOURCES
        })
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
                OWNERS,
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
            OWNERS,
        ) {
            return Err(efi::Status::OUT_OF_RESOURCES);
        }

        self.allocations.swap_remove(allocation_index);
        for allocation in parts.into_iter().flatten() {
            self.record_allocation(allocation)?;
        }
        Ok(())
    }

    /// Plan the coalesced replacement before editing the map. The immediate
    /// neighbours suffice because entries outside the edit are coalesced.
    /// The plan holds a head, up to two middle parts, a tail and two neighbours.
    fn replace_descriptors(
        &mut self,
        old: core::ops::Range<usize>,
        replacement: impl IntoIterator<Item = MemoryDescriptor>,
    ) -> Result<(), efi::Status> {
        let start = old.start.saturating_sub(1);
        let end = (old.end + 1).min(self.entries.len());
        let mut planned = Vec::<MemoryDescriptor, 6>::new();
        for descriptor in self.entries[start..old.start]
            .iter()
            .copied()
            .chain(replacement)
            .chain(self.entries[old.end..end].iter().copied())
        {
            if let Some(last) = planned.last_mut()
                && can_merge(last, &descriptor)
            {
                last.number_of_pages += descriptor.number_of_pages;
            } else {
                planned
                    .push(descriptor)
                    .expect("local descriptor plan fits");
            }
        }
        if !fits_after_replacement(self.entries.len(), end - start, planned.len(), ENTRIES) {
            return Err(efi::Status::OUT_OF_RESOURCES);
        }

        for index in (start..end).rev() {
            self.entries.remove(index);
        }
        for (offset, descriptor) in planned.into_iter().enumerate() {
            self.entries
                .insert(start + offset, descriptor)
                .expect("memory map capacity was pre-checked");
        }
        Ok(())
    }

    /// Add a descriptor in address order, coalescing it before charging a slot.
    fn insert_descriptor(&mut self, descriptor: MemoryDescriptor) -> Result<(), efi::Status> {
        let index = self
            .entries
            .partition_point(|entry| entry.physical_start < descriptor.physical_start);
        self.replace_descriptors(index..index, [descriptor])
    }

    /// Replace `range` inside one descriptor, preserving its head and tail.
    fn replace_descriptor_middle(
        &mut self,
        index: usize,
        range: PageRange,
        middle: &[MemoryDescriptor],
    ) -> Result<(), efi::Status> {
        let split = self.descriptor_split(index, range)?;
        let original = self.entries[index];
        let original_type = original.get_memory_type().ok_or(efi::Status::NOT_FOUND)?;
        let residual = |range| descriptor_for_range(original_type, range, original.attribute);
        self.replace_descriptors(
            index..index + 1,
            split
                .head
                .map(residual)
                .into_iter()
                .chain(middle.iter().copied())
                .chain(split.tail.map(residual)),
        )
    }

    /// Retype a range inside one descriptor while preserving its head and tail.
    fn retype_range(
        &mut self,
        descriptor_index: usize,
        range: PageRange,
        memory_type: MemoryType,
        attribute: u64,
    ) -> Result<(), efi::Status> {
        let middle = [descriptor_for_range(memory_type, range, attribute)];
        self.replace_descriptor_middle(descriptor_index, range, &middle)
    }

    /// Initialize the allocator from a platform-provided memory map.
    ///
    /// Converts `platform::MemoryRegion` entries into EFI memory descriptors.
    ///
    /// Idempotent: if the allocator already has entries (e.g., the caller
    /// bootstrapped the page allocator before platform initialization to
    /// get a heap), this is a no-op.
    pub fn init_from_platform(&mut self, regions: &[MemoryRegion]) {
        if self.require_active().is_err() || !self.entries.is_empty() {
            info!("Page allocator already initialized or inactive, skipping re-init");
            return;
        }

        use RegionType as PlatMemType;

        self.entries.clear();
        self.allocations.clear();
        self.map_key_offset = 0;

        info!("Importing platform memory map ({} regions):", regions.len());
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

            info!(
                "  {:#010x}-{:#010x} {:?} -> {:?}",
                region.base,
                region.base + region.size,
                region.region_type,
                memory_type
            );

            let attribute = memory_type.default_attributes();

            let Some(range) = PageRange::from_bytes(region.base, num_pages.get()) else {
                warn!(
                    "Region at {:#x} is misaligned or overflows, skipping",
                    region.base
                );
                continue;
            };

            if self
                .insert_descriptor(descriptor_for_range(memory_type, range, attribute))
                .is_err()
            {
                warn!("Memory map full, ignoring region at {:#x}", region.base);
            }
        }

        info!(
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
        self.require_active()?;
        let range = PageRange::from_bytes(physical_start, num_pages)
            .ok_or(efi::Status::INVALID_PARAMETER)?;

        let mut fragments: heapless::Vec<PageRange, ENTRIES> = heapless::Vec::new();
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
        self.require_active()?;
        let range = PageRange::from_bytes(physical_start, num_pages)
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        let attribute = Self::allocation_attribute(memory_type, memory_type.default_attributes());
        self.insert_descriptor(descriptor_for_range(memory_type, range, attribute))?;
        self.map_key_offset += 1;

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
        self.require_active()?;
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
            self.insert_descriptor(descriptor_for_range(
                target_type,
                range,
                attributes::EFI_MEMORY_RAM_CAPS,
            ))?;
            self.map_key_offset += 1;
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

        self.map_key_offset += 1;
        Ok(())
    }

    /// Mark a memory region as ACPI Reclaim Memory.
    ///
    /// Splits the containing entry as needed. Coreboot commonly places ACPI
    /// tables inside a broadly reserved CBMEM range, so verified table pages
    /// must override `ReservedMemoryType`. Preserve only existing ACPI types.
    pub fn mark_as_acpi_reclaim(&mut self, addr: u64, num_pages: u64) -> Result<(), efi::Status> {
        self.mark_region_as(
            addr,
            num_pages,
            MemoryType::AcpiReclaimMemory,
            &[MemoryType::AcpiReclaimMemory, MemoryType::AcpiMemoryNvs],
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
        self.map_key_offset += 1;
        Ok(())
    }

    /// Retype an exclusively owned LoaderCode PE staging allocation before
    /// publication. Code offsets are sorted, coalesced page ranges relative to
    /// `base`: consecutive ranges must be separated by at least one data page.
    pub fn retype_pe_image(
        &mut self,
        base: u64,
        pages: u64,
        code_type: MemoryType,
        data_type: MemoryType,
        code: &[core::ops::Range<u64>],
    ) -> Result<(), efi::Status> {
        self.require_active()?;
        // Only matching code/data pairs describe a loaded image.
        if !matches!(
            (code_type, data_type),
            (MemoryType::LoaderCode, MemoryType::LoaderData)
                | (MemoryType::BootServicesCode, MemoryType::BootServicesData)
                | (
                    MemoryType::RuntimeServicesCode,
                    MemoryType::RuntimeServicesData
                )
        ) {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        let image = PageRange::from_bytes(base, pages).ok_or(efi::Status::INVALID_PARAMETER)?;
        let (index, allocation) = self
            .find_allocation(image)
            .filter(|(_, allocation)| {
                allocation.range == image && allocation.memory_type == MemoryType::LoaderCode
            })
            .ok_or(efi::Status::NOT_FOUND)?;
        let descriptor = self
            .find_descriptor(image, &[MemoryType::LoaderCode])
            .ok_or(efi::Status::NOT_FOUND)?;
        let mut previous_end = None;
        for range in code {
            if previous_end.is_some_and(|end| range.start <= end)
                || range.start >= range.end
                || range.end > pages
            {
                return Err(efi::Status::INVALID_PARAMETER);
            }
            previous_end = Some(range.end);
        }
        // Each split adds at most two descriptors and ownership records. Reserve
        // all capacity before changing anything so failure leaves staging intact.
        let extra = code
            .len()
            .checked_mul(2)
            .and_then(|n| n.checked_add(2))
            .ok_or(efi::Status::OUT_OF_RESOURCES)?;
        if extra > ENTRIES - self.entries.len() || extra > OWNERS - self.allocations.len() {
            return Err(efi::Status::OUT_OF_RESOURCES);
        }
        let attribute = Self::allocation_attribute(data_type, allocation.restore_attribute);
        self.retype_range(descriptor, image, data_type, attribute)?;
        self.allocations[index].memory_type = data_type;
        for offset in code {
            let range =
                PageRange::from_bytes(base + offset.start * PAGE_SIZE, offset.end - offset.start)
                    .ok_or(efi::Status::INVALID_PARAMETER)?;
            let (index, _) = self.find_allocation(range).ok_or(efi::Status::NOT_FOUND)?;
            let descriptor = self
                .find_descriptor(range, &[data_type])
                .ok_or(efi::Status::NOT_FOUND)?;
            let attribute = Self::allocation_attribute(code_type, allocation.restore_attribute);
            self.retype_range(descriptor, range, code_type, attribute)?;
            self.replace_allocation_range(
                index,
                range,
                Some(PageAllocation {
                    range,
                    memory_type: code_type,
                    restore_attribute: allocation.restore_attribute,
                }),
            )?;
        }
        self.map_key_offset += 1;
        Ok(())
    }

    /// Free the complete PE allocation across its private code/data splits.
    /// Public FreePages keeps its stricter same-type ownership contract.
    pub fn free_pe_image(&mut self, base: u64, pages: u64) -> efi::Status {
        if let Err(status) = self.require_active() {
            return status;
        }
        let Some(image) = PageRange::from_bytes(base, pages) else {
            return efi::Status::INVALID_PARAMETER;
        };
        let mut covered = 0;
        let mut restore = None;
        for allocation in self.allocations.iter().filter(|a| a.range.overlaps(image)) {
            if !image.contains(allocation.range)
                || restore.is_some_and(|attribute| attribute != allocation.restore_attribute)
            {
                return efi::Status::NOT_FOUND;
            }
            restore = Some(allocation.restore_attribute);
            covered += allocation.range.pages().get();
        }
        if covered != pages {
            return efi::Status::NOT_FOUND;
        }
        if ENTRIES - self.entries.len() < 2 {
            return efi::Status::OUT_OF_RESOURCES;
        }
        // Free in address order so the released prefix merges rather than
        // introducing unbounded fragmentation in the descriptor table.
        while let Some(allocation) = self
            .allocations
            .iter()
            .copied()
            .filter(|a| image.contains(a.range))
            .min_by_key(|a| a.range.start())
        {
            let status = self.free_pages(
                allocation.range.start_bytes(),
                allocation.range.pages().get(),
            );
            if status != efi::Status::SUCCESS {
                return status;
            }
        }
        efi::Status::SUCCESS
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
        if let Err(status) = self.require_active() {
            return status;
        }
        let address = match alloc_type {
            AllocateType::AllocateAnyPages => {
                self.find_free_pages(num_pages, 0..=u64::MAX, PAGE_SIZE, Placement::Highest)
            }
            AllocateType::AllocateMaxAddress => {
                self.find_free_pages(num_pages, 0..=*memory, PAGE_SIZE, Placement::Highest)
            }
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
            debug!(
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
            } else if self
                .allocations
                .iter()
                .any(|allocation| allocation.range.overlaps(range))
            {
                // Adjacent loader allocations share one merged descriptor. A
                // claim across them belongs to no single owner and would hand
                // out their pages a second time.
                return efi::Status::NOT_FOUND;
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
                .map(|()| self.map_key_offset += 1)
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
        if let Err(status) = self.require_active() {
            return status;
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
        self.map_key_offset += 1;
        efi::Status::SUCCESS
    }

    /// Get the current memory map
    ///
    /// Descriptors are already coalesced in the internal map. The exported
    /// descriptors omit page-protection attributes, which belong in the MAT.
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
        *map_key = self.map_key();

        let required_size = self.entries.len() * entry_size;

        // An undersized null buffer is still a size query, even when the
        // supplied size is nonzero. Reject null only once it could fit the map.
        if memory_map.is_none() && *memory_map_size >= required_size {
            return efi::Status::INVALID_PARAMETER;
        }

        if let Some(map) = memory_map {
            if core::mem::size_of_val(map) < required_size {
                *memory_map_size = required_size;
                return efi::Status::BUFFER_TOO_SMALL;
            }

            let output = &mut map[..self.entries.len()];
            output.copy_from_slice(&self.entries);

            // Strip memory protection attributes (RO, XP, RP) from returned
            // descriptors.  EDK2's CoreGetMemoryMap does the same.  Some OSes
            // (notably Windows) treat these as mandatory page-table attributes
            // and will set NX or read-only on runtime memory — causing crashes
            // when calling runtime services.  The separate Memory Attributes
            // Table carries the authoritative protection info instead.
            const STRIP_MASK: u64 = !(attributes::EFI_MEMORY_RO
                | attributes::EFI_MEMORY_XP
                | attributes::EFI_MEMORY_RP);
            for desc in output {
                desc.attribute &= STRIP_MASK;
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
        self.map_key_offset.wrapping_add(1)
    }

    /// Get the number of entries
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Dump all memory map entries to the log (for debugging).
    ///
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
        info!("Memory map dump ({} entries):", self.entries.len());
        for (i, e) in self.entries.iter().enumerate() {
            let pages = PageCount::new(e.number_of_pages);
            let size_mb = pages.bytes().unwrap_or(u64::MAX) >> 20;
            info!(
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
        let expected = self.map_key();
        if provided_map_key == expected && self.boot_services == BootServicesState::Active {
            efi::Status::SUCCESS
        } else {
            warn!(
                "exit_boot_services: map_key mismatch or inactive allocator; expected {:#x}, got {:#x}",
                expected, provided_map_key
            );
            efi::Status::INVALID_PARAMETER
        }
    }

    /// Accept the OS's key and freeze the map before exit callbacks and DMA
    /// shutdown. Boot Services pages retain their types until the final commit.
    pub fn begin_exit_boot_services(&mut self, key: usize) -> Result<(), efi::Status> {
        let status = self.validate_map_key(key);
        if status != efi::Status::SUCCESS {
            return Err(status);
        }
        self.boot_services = BootServicesState::Exiting;
        Ok(())
    }

    /// Reclaim Boot Services pages after starting exit and quiescing DMA.
    /// No fallible key check is needed: the accepted map has been frozen.
    pub fn finish_exit_boot_services(&mut self) {
        assert!(
            self.boot_services_exiting(),
            "ExitBootServices has not begun"
        );
        self.boot_services = BootServicesState::Exited;

        // Log handoff-critical regions: runtime services must keep the
        // RUNTIME attribute, and loader regions must remain reserved for the
        // OS loader / EFI stub across ExitBootServices.
        debug!(
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
                info!(
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
        self.map_key_offset += 1;
        self.merge_entries();

        info!(
            "ExitBootServices complete, new map_key={:#x}",
            self.map_key()
        );
    }

    /// Exit directly when there are no callbacks or hardware to quiesce.
    pub fn exit_boot_services(&mut self, key: usize) -> efi::Status {
        match self.begin_exit_boot_services(key) {
            Ok(()) => {
                self.finish_exit_boot_services();
                efi::Status::SUCCESS
            }
            Err(status) => status,
        }
    }

    /// Allocate pages wholly contained in an inclusive physical-address range,
    /// starting at a multiple of `alignment` (a power of two; at least a page).
    pub fn allocate_pages_in_range(
        &mut self,
        memory_type: MemoryType,
        num_pages: u64,
        range: RangeInclusive<u64>,
        alignment: u64,
        placement: Placement,
    ) -> Result<u64, efi::Status> {
        if !alignment.is_power_of_two() {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        self.require_active()?;
        let mut address = self
            .find_free_pages(num_pages, range, alignment, placement)
            .ok_or(efi::Status::OUT_OF_RESOURCES)?;
        match self.allocate_pages(
            AllocateType::AllocateAddress,
            memory_type,
            num_pages,
            &mut address,
        ) {
            efi::Status::SUCCESS => Ok(address),
            status => Err(status),
        }
    }

    /// Allocate one contiguous runtime image and privately split its leading
    /// code domain without exposing RuntimeServicesData to public
    /// AllocateAddress claims.
    ///
    /// Performs the placement and code/data split as one atomic descriptor
    /// replacement with no ownership record (firmware lifetime), so a failure
    /// changes nothing—not even `map_key`.
    pub fn allocate_runtime_image_layout(
        &mut self,
        image_pages: u64,
        code_pages: u64,
    ) -> Result<u64, efi::Status> {
        self.allocate_runtime_image_layout_preferring_below(image_pages, code_pages, u64::MAX)
    }

    /// Like [`Self::allocate_runtime_image_layout`], but place the image in
    /// the highest free range below `preferred_max` (inclusive) when one
    /// exists and its split fits the descriptor table. Otherwise fall back
    /// to the highest free range anywhere.
    pub fn allocate_runtime_image_layout_preferring_below(
        &mut self,
        image_pages: u64,
        code_pages: u64,
        preferred_max: u64,
    ) -> Result<u64, efi::Status> {
        if image_pages == 0 || code_pages == 0 || code_pages > image_pages {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        self.require_active()?;
        if preferred_max != u64::MAX {
            // A failed attempt leaves the map unchanged, so if the preferred
            // placement does not fit the descriptor table, retry without it.
            let preferred = self
                .find_free_pages(
                    image_pages,
                    0..=preferred_max,
                    PAGE_SIZE,
                    Placement::Highest,
                )
                .and_then(|address| {
                    self.place_runtime_image(address, image_pages, code_pages)
                        .ok()
                });
            if let Some(base) = preferred {
                return Ok(base);
            }
        }
        let address = self
            .find_free_pages(image_pages, 0..=u64::MAX, PAGE_SIZE, Placement::Highest)
            .ok_or(efi::Status::OUT_OF_RESOURCES)?;
        self.place_runtime_image(address, image_pages, code_pages)
    }

    /// Split the runtime image at `address` out of conventional memory.
    /// Returns an error without changing the map when the split does not fit
    /// the descriptor table.
    fn place_runtime_image(
        &mut self,
        address: u64,
        image_pages: u64,
        code_pages: u64,
    ) -> Result<u64, efi::Status> {
        let placement =
            PageRange::from_bytes(address, image_pages).ok_or(efi::Status::OUT_OF_RESOURCES)?;
        let source = self
            .find_descriptor(placement, &[MemoryType::ConventionalMemory])
            .ok_or(efi::Status::OUT_OF_RESOURCES)?;
        let source_attr = self.entries[source].attribute;
        let base = placement.start_bytes();
        let code_range =
            PageRange::from_bytes(base, code_pages).ok_or(efi::Status::OUT_OF_RESOURCES)?;
        let code_desc = descriptor_for_range(
            MemoryType::RuntimeServicesCode,
            code_range,
            Self::allocation_attribute(MemoryType::RuntimeServicesCode, source_attr),
        );
        if code_pages == image_pages {
            self.replace_descriptor_middle(source, placement, &[code_desc])?;
        } else {
            let data_range =
                PageRange::from_bytes(base + code_pages * PAGE_SIZE, image_pages - code_pages)
                    .ok_or(efi::Status::OUT_OF_RESOURCES)?;
            let data_desc = descriptor_for_range(
                MemoryType::RuntimeServicesData,
                data_range,
                Self::allocation_attribute(MemoryType::RuntimeServicesData, source_attr),
            );
            self.replace_descriptor_middle(source, placement, &[code_desc, data_desc])?;
        }
        self.map_key_offset += 1;
        Ok(base)
    }

    /// Copy every descriptor carrying `EFI_MEMORY_RUNTIME` into `output`.
    pub fn copy_runtime_descriptors(
        &self,
        output: &mut [MemoryDescriptor],
    ) -> Result<usize, efi::Status> {
        let runtime = self
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

    /// The memory type of the descriptor containing `address`.
    pub fn memory_type_at(&self, address: u64) -> Option<MemoryType> {
        self.entries
            .iter()
            .find(|entry| address >= entry.physical_start && address < entry.end())
            .and_then(MemoryDescriptorExt::get_memory_type)
    }

    /// Verify complete, gap-free descriptor coverage of a physical interval.
    pub fn range_has_memory_type(&self, base: u64, size: u64, memory_type: MemoryType) -> bool {
        let Some(end) = base.checked_add(size) else {
            return false;
        };
        if size == 0 {
            return false;
        }
        let mut covered = base;
        for descriptor in self.entries.iter() {
            if descriptor.end() <= covered {
                continue;
            }
            if descriptor.physical_start > covered
                || descriptor.get_memory_type() != Some(memory_type)
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

    /// Find `num_pages` of free memory wholly inside the inclusive `range`,
    /// starting at a multiple of the power-of-two `alignment`.
    fn find_free_pages(
        &self,
        num_pages: u64,
        range: RangeInclusive<u64>,
        alignment: u64,
        placement: Placement,
    ) -> Option<u64> {
        let mask = alignment.max(PAGE_SIZE) - 1;
        let size = num_pages.checked_mul(PAGE_SIZE)?;

        // EFI AllocateMaxAddress is inclusive: the final byte of the entire
        // allocation must be no greater than the caller's maximum address.
        let max_addr = (*range.end()).min(ADDRESS_LIMIT);
        let max_end = max_addr.checked_add(1);

        let fit = |entry: &MemoryDescriptor| {
            if entry.get_memory_type() != Some(MemoryType::ConventionalMemory) {
                return None;
            }
            let start = entry.physical_start.max(*range.start()).checked_add(mask)? & !mask;
            let end = max_end.map_or(entry.end(), |end| entry.end().min(end));
            if start.checked_add(size)? > end {
                return None;
            }
            Some(match placement {
                Placement::Lowest => start,
                Placement::Highest => (end - size) & !mask,
            })
        };
        match placement {
            Placement::Lowest => self.entries.iter().find_map(fit),
            Placement::Highest => self.entries.iter().rev().find_map(fit),
        }
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
    pub fn carve_out_from(
        &mut self,
        addr: u64,
        num_pages: u64,
        memory_type: MemoryType,
        source_types: &[MemoryType],
    ) -> Result<(), efi::Status> {
        self.require_active()?;
        let range = PageRange::from_bytes(addr, num_pages).ok_or(efi::Status::INVALID_PARAMETER)?;
        let descriptor_index = self
            .find_descriptor(range, source_types)
            .ok_or(efi::Status::NOT_FOUND)?;
        let attribute =
            Self::allocation_attribute(memory_type, self.entries[descriptor_index].attribute);
        self.retype_range(descriptor_index, range, memory_type, attribute)?;
        self.map_key_offset += 1;
        Ok(())
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

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proofs;
