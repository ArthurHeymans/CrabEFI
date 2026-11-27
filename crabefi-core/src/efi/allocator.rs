//! EFI Memory Allocator
//!
//! Page-granular allocation and the EFI memory map are implemented by
//! [`crabefi_memmap::MemoryMap`], which is plain data and checked by Kani and
//! property tests. This module owns the firmware instance and the
//! platform-specific limits, and implements pool allocation on top: pool
//! requests are suballocated from page-backed chunks grouped by EFI memory
//! type. Pool chunks are intentionally retained until `ExitBootServices`;
//! individual pool frees never return pages to the page allocator.
//!
//! # State Management
//!
//! The allocator lives in a module-private cell; the free functions below are
//! its only public surface.

use core::sync::atomic::{AtomicBool, Ordering};

pub use crabefi_memmap::{
    AllocateType, InvalidAllocateType, InvalidMemoryType, MemoryDescriptor, MemoryType, PAGE_SIZE,
    Placement, attributes,
};
use r_efi::efi;

use crate::cell::Local;

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

/// The firmware's memory map at production capacity.
pub type MemoryAllocator = crabefi_memmap::MemoryMap<
    MAX_MEMORY_ENTRIES,
    MAX_PAGE_ALLOCATIONS,
    MAX_IDENTITY_MAPPED_ADDRESS,
>;

/// Page allocator and memory map.
static ALLOCATOR: Local<MemoryAllocator> = Local::new(MemoryAllocator::new());

// Keep this dependency-free helper in a flat file so the CI regression job
// can compile and execute it directly with `rustc --test`.
#[path = "pool_free_list.rs"]
mod pool_free_list;
pub use pool_free_list::POOL_ALIGNMENT;
use pool_free_list::{
    POOL_ALLOCATED_MAGIC, POOL_FREE_MAGIC, PoolHeader, PoolListError, PoolState, align_pool_size,
};

/// Page size as usize for convenience
pub const PAGE_SIZE_USIZE: usize = PAGE_SIZE as usize;

/// Maximum address that is identity-mapped in page tables.
/// On x86_64: Our assembly code sets up identity mapping for the first 64GB
/// (64 PDPTs * 512 PDs * 2MB each). Allocations above this will cause page faults.
/// On aarch64: coreboot/TF-A sets up the MMU covering the full address space,
/// including DRAM at 1TB+ on QEMU SBSA. No artificial cap needed.
#[cfg(all(target_arch = "x86_64", not(test)))]
const MAX_IDENTITY_MAPPED_ADDRESS: u64 = 0x0f_ffff_ffff; // Last byte below 64GB
/// Host unit tests run on the host's page tables, and [`with_host_pages`]
/// RAM lies wherever the host allocator put it.
#[cfg(any(not(target_arch = "x86_64"), test))]
const MAX_IDENTITY_MAPPED_ADDRESS: u64 = u64::MAX;

/// Initialize the global allocator from a platform-provided memory map.
pub fn init_from_platform(regions: &[crate::platform::MemoryRegion]) {
    ALLOCATOR.with_mut(|alloc| {
        alloc.init_from_platform(regions);
    });
}

/// Reserve a region of memory
pub fn reserve_region(
    physical_start: u64,
    num_pages: u64,
    memory_type: MemoryType,
) -> Result<(), efi::Status> {
    ALLOCATOR.with_mut(|alloc| alloc.reserve_region(physical_start, num_pages, memory_type))
}

/// Reserve all ConventionalMemory fragments in a range while preserving
/// pre-typed holes such as ACPI reclaim and SMBIOS reserved pages.
pub fn reserve_region_fragments(
    physical_start: u64,
    num_pages: u64,
    memory_type: MemoryType,
) -> Result<(), efi::Status> {
    ALLOCATOR
        .with_mut(|alloc| alloc.reserve_region_fragments(physical_start, num_pages, memory_type))
}

/// Force-add a memory region to the map
///
/// This is used when the region isn't in the coreboot map at all.
pub fn force_add_region(
    physical_start: u64,
    num_pages: u64,
    memory_type: MemoryType,
) -> Result<(), efi::Status> {
    ALLOCATOR.with_mut(|alloc| alloc.force_add_region(physical_start, num_pages, memory_type))
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
    ALLOCATOR.with_mut(|alloc| {
        alloc.carve_out_from(physical_start, num_pages, memory_type, source_types)
    })
}

/// Mark a memory region as ACPI Reclaim Memory
///
/// This properly splits existing regions and marks the specified range as AcpiReclaimMemory.
pub fn mark_as_acpi_reclaim(addr: u64, num_pages: u64) -> Result<(), efi::Status> {
    ALLOCATOR.with_mut(|alloc| alloc.mark_as_acpi_reclaim(addr, num_pages))
}

/// Mark a memory region as Reserved Memory
///
/// This properly splits existing regions and marks the specified range as ReservedMemoryType.
pub fn mark_as_reserved(addr: u64, num_pages: u64) -> Result<(), efi::Status> {
    ALLOCATOR.with_mut(|alloc| alloc.mark_as_reserved(addr, num_pages))
}

/// Allocate pages of memory
pub fn allocate_pages(
    alloc_type: AllocateType,
    memory_type: MemoryType,
    num_pages: u64,
    memory: &mut u64,
) -> efi::Status {
    ALLOCATOR.with_mut(|alloc| alloc.allocate_pages(alloc_type, memory_type, num_pages, memory))
}

/// Allocate pages wholly contained in an inclusive physical-address range,
/// starting at a multiple of the power-of-two `alignment`.
pub fn allocate_pages_in_range(
    memory_type: MemoryType,
    num_pages: u64,
    range: core::ops::RangeInclusive<u64>,
    alignment: u64,
    placement: Placement,
) -> Result<u64, efi::Status> {
    ALLOCATOR.with_mut(|allocator| {
        allocator.allocate_pages_in_range(memory_type, num_pages, range, alignment, placement)
    })
}

/// Free previously allocated pages
pub fn free_pages(memory: u64, num_pages: u64) -> efi::Status {
    ALLOCATOR.with_mut(|alloc| alloc.free_pages(memory, num_pages))
}

/// Dump the full memory map to the log (for debugging).
pub fn dump_memory_map() {
    let alloc = ALLOCATOR.borrow();
    alloc.dump_entries();
}

/// Get the memory map size
pub fn get_memory_map_size() -> usize {
    let alloc = ALLOCATOR.borrow();
    alloc.entry_count() * core::mem::size_of::<MemoryDescriptor>()
}

/// Get current map key
pub fn get_map_key() -> usize {
    let alloc = ALLOCATOR.borrow();
    alloc.map_key()
}

/// Inspect the effective EFI memory map.
///
/// The descriptors remain borrowed only for the duration of `f`; callers must
/// not invoke code that can mutate the allocator from inside the callback.
///
/// # Arguments
/// * `f` - Callback receiving every current memory descriptor
///
/// # Returns
/// The value returned by `f`.
pub fn with_descriptors<R>(f: impl FnOnce(&[MemoryDescriptor]) -> R) -> R {
    let allocator = ALLOCATOR.borrow();
    f(allocator.descriptors())
}

pub fn copy_runtime_descriptors(output: &mut [MemoryDescriptor]) -> Result<usize, efi::Status> {
    ALLOCATOR.borrow().copy_runtime_descriptors(output)
}

/// Find the memory type for a given physical address.
pub fn get_memory_type_at(address: u64) -> Option<MemoryType> {
    ALLOCATOR.borrow().memory_type_at(address)
}

/// Verify complete, gap-free descriptor coverage of a physical interval.
pub fn range_has_memory_type(base: u64, size: u64, memory_type: MemoryType) -> bool {
    ALLOCATOR
        .borrow()
        .range_has_memory_type(base, size, memory_type)
}

/// Get the memory map
pub fn get_memory_map(
    memory_map_size: &mut usize,
    memory_map: Option<&mut [MemoryDescriptor]>,
    map_key: &mut usize,
    descriptor_size: &mut usize,
    descriptor_version: &mut u32,
) -> efi::Status {
    let alloc = ALLOCATOR.borrow();
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
    ALLOCATOR.borrow().validate_map_key(map_key)
}

/// Exit directly when the caller has no exit callbacks or DMA to quiesce.
pub fn exit_boot_services(key: usize) -> efi::Status {
    match begin_exit_boot_services(key) {
        Ok(()) => {
            finish_exit_boot_services();
            efi::Status::SUCCESS
        }
        Err(status) => status,
    }
}

/// Accept the loader's key and prevent further edits while drivers shut down.
pub(crate) fn begin_exit_boot_services(key: usize) -> Result<(), efi::Status> {
    ALLOCATOR.with_mut(|alloc| alloc.begin_exit_boot_services(key))
}

/// Reclaim Boot Services memory only after DMA has stopped.
pub(crate) fn finish_exit_boot_services() {
    ALLOCATOR.with_mut(MemoryAllocator::finish_exit_boot_services);
    disable_pool_allocator();
}

pub(crate) fn exit_in_progress() -> bool {
    ALLOCATOR.borrow().boot_services_exiting()
}

/// Drop a firmware-owned BootServicesData allocation. During handoff its
/// pages stay typed until commit, which reclaims them without editing the
/// loader's accepted map while DMA is still active.
pub(crate) fn release_boot_services_pages(address: u64, pages: u64) -> efi::Status {
    ALLOCATOR.with_mut(|alloc| {
        if alloc.boot_services_exiting() {
            efi::Status::SUCCESS
        } else {
            alloc.free_pages(address, pages)
        }
    })
}

/// Allocate one contiguous runtime image and privately split its leading code
/// domain without exposing RuntimeServicesData to public AllocateAddress claims.
pub fn allocate_runtime_image_layout(
    image_pages: u64,
    code_pages: u64,
) -> Result<u64, efi::Status> {
    ALLOCATOR.with_mut(|allocator| allocator.allocate_runtime_image_layout(image_pages, code_pages))
}

/// Finalize the PE staging allocation's subsystem-specific memory map.
pub(crate) fn retype_pe_image(
    base: u64,
    pages: u64,
    code_type: MemoryType,
    data_type: MemoryType,
    code: &[core::ops::Range<u64>],
) -> Result<(), efi::Status> {
    ALLOCATOR.with_mut(|a| a.retype_pe_image(base, pages, code_type, data_type, code))
}

pub(crate) fn free_pe_image(base: u64, pages: u64) -> efi::Status {
    ALLOCATOR.with_mut(|a| a.free_pe_image(base, pages))
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

/// Keep the native payload, stack, and page tables out of the E820 RAM map
/// and out of the allocator. Already reserved fragments are left alone, so
/// this is safe to call both before platform discovery and at library entry.
#[cfg(feature = "platform-entry")]
pub(crate) fn reserve_native_boot_image() {
    let start = &raw const __boot_code_start as u64 & !(PAGE_SIZE - 1);
    let end = (&raw const __boot_data_end as u64).next_multiple_of(PAGE_SIZE);
    assert!(end > start, "invalid native boot image linker range");
    reserve_region_fragments(
        start,
        (end - start) / PAGE_SIZE,
        MemoryType::BootServicesData,
    )
    .expect("could not reserve the native boot image");
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
    match ALLOCATOR.with_mut(|alloc| {
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
        match ALLOCATOR.with_mut(|alloc| {
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

/// Test the real commit without closing the global allocator for other host tests.
#[cfg(test)]
pub(crate) fn with_exit_test_allocator<R>(f: impl FnOnce() -> R) -> R {
    struct Restore(MemoryAllocator, PoolState, bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            ALLOCATOR.with_mut(|alloc| core::mem::swap(alloc, &mut self.0));
            *POOL_STATE.lock() = core::mem::replace(&mut self.1, PoolState::new());
            POOL_DISABLED.store(self.2, Ordering::Release);
        }
    }

    let _state = crate::efi::boot_services::IMAGE_EXECUTION_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _restore = Restore(
        ALLOCATOR.with_mut(core::mem::take),
        core::mem::replace(&mut *POOL_STATE.lock(), PoolState::new()),
        POOL_DISABLED.swap(false, Ordering::AcqRel),
    );
    f()
}

#[cfg(test)]
pub(crate) const HOST_TEST_PAGES: u64 = 2048;

/// Give host tests a page allocator backed by leaked host memory.
///
/// Runs `f` with the global EFI state lock held, after importing one 8 MiB RAM
/// region on first use. The pages stay allocated between tests; callers free
/// what they allocate.
#[cfg(test)]
pub(crate) fn with_host_pages<R>(f: impl FnOnce() -> R) -> R {
    const HOST_BYTES: usize = HOST_TEST_PAGES as usize * PAGE_SIZE_USIZE;
    static INIT: std::sync::Once = std::sync::Once::new();

    let _state = crate::efi::boot_services::IMAGE_EXECUTION_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    INIT.call_once(|| {
        let layout = std::alloc::Layout::from_size_align(HOST_BYTES, PAGE_SIZE_USIZE).unwrap();
        // SAFETY: nonzero layout; the region is leaked for the process lifetime.
        let base = unsafe { std::alloc::alloc(layout) };
        assert!(!base.is_null());
        init_from_platform(&[crate::platform::MemoryRegion {
            base: base as u64,
            size: HOST_BYTES as u64,
            region_type: crate::platform::MemoryType::Ram,
        }]);
    });
    f()
}
