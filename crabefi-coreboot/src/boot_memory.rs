//! Translate coreboot's memory map for the platform handoff, before heap init.

use crate::{memory, memory_map};
use crabefi::handoff::MAX_MEMORY_REGIONS;

pub(crate) const EMPTY_MAP: [crabefi::MemoryRegion; MAX_MEMORY_REGIONS] = [crabefi::MemoryRegion {
    base: 0,
    size: 0,
    region_type: crabefi::MemoryType::Reserved,
}; MAX_MEMORY_REGIONS];

impl memory_map::Region for crabefi::MemoryRegion {
    type Kind = crabefi::MemoryType;

    fn base(self) -> u64 {
        self.base
    }

    fn size(self) -> u64 {
        self.size
    }

    fn kind(self) -> Self::Kind {
        self.region_type
    }

    fn from_parts(base: u64, size: u64, region_type: Self::Kind) -> Self {
        Self {
            base,
            size,
            region_type,
        }
    }
}

/// Whether `start..start + length` lies in one region coreboot reserved
/// (CBMEM tables or reserved memory).
pub(crate) fn in_table_memory(map: &[memory::MemoryRegion], start: u64, length: u64) -> bool {
    let Some(end) = start.checked_add(length) else {
        return false;
    };
    map.iter().any(|region| {
        matches!(
            region.region_type,
            memory::MemoryType::Reserved | memory::MemoryType::Table
        ) && start >= region.start
            && end <= region.start.saturating_add(region.size)
    })
}

/// Convert one coreboot memory region to platform format.
fn convert_memory_region(region: &memory::MemoryRegion) -> crabefi::MemoryRegion {
    let region_type = match region.region_type {
        memory::MemoryType::Ram => crabefi::MemoryType::Ram,
        memory::MemoryType::Reserved => crabefi::MemoryType::Reserved,
        memory::MemoryType::AcpiReclaimable => crabefi::MemoryType::AcpiReclaimable,
        memory::MemoryType::AcpiNvs => crabefi::MemoryType::AcpiNvs,
        // Unusable, Table, and any future variants map to Reserved.
        _ => crabefi::MemoryType::Reserved,
    };
    crabefi::MemoryRegion {
        base: region.start,
        size: region.size,
        region_type,
    }
}

/// Convert coreboot memory regions to platform format.
fn convert_memory_map(
    cb_map: &[memory::MemoryRegion],
    out: &mut [crabefi::MemoryRegion; MAX_MEMORY_REGIONS],
) -> usize {
    let mut count = 0;
    for region in cb_map {
        if count >= MAX_MEMORY_REGIONS {
            log::warn!(
                "Coreboot memory map has {} regions but only {} fit; truncating the remainder",
                cb_map.len(),
                MAX_MEMORY_REGIONS
            );
            break;
        }
        out[count] = convert_memory_region(region);
        count += 1;
    }
    count
}

pub(crate) fn platform_map<'a>(
    cb_map: &[memory::MemoryRegion],
    framebuffer: Option<crabefi::FramebufferConfig>,
    out: &'a mut [crabefi::MemoryRegion; MAX_MEMORY_REGIONS],
) -> &'a [crabefi::MemoryRegion] {
    let region_count = convert_memory_map(cb_map, out);
    let region_count = match framebuffer {
        Some(framebuffer) => {
            match memory_map::overlay_framebuffer_region(
                out,
                region_count,
                framebuffer.physical_address,
                framebuffer.size(),
                crabefi::MemoryType::Mmio,
            ) {
                Ok(count) => {
                    log::info!(
                        "Reported framebuffer MMIO region at {:#x} ({} bytes)",
                        framebuffer.physical_address,
                        framebuffer.size()
                    );
                    count
                }
                // EmptyFramebuffer is unreachable: malformed descriptors are
                // filtered into `None` above. Continuing after any other error
                // could leave the framebuffer aperture classified as allocatable
                // RAM, so fail closed instead of publishing an unsafe map.
                Err(error) => panic!("Framebuffer MMIO overlay rejected: {error:?}"),
            }
        }
        None => region_count,
    };
    &out[..region_count]
}
