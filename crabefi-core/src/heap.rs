//! Global Allocator for CrabEFI
//!
//! This module provides the global allocator used by `alloc`. Its backing pages
//! are RuntimeServicesData, so allocations remain available to EFI runtime
//! services after ExitBootServices.

use core::sync::atomic::{AtomicBool, Ordering};

use linked_list_allocator::LockedHeap;

/// Heap size (2 MB should be sufficient for crypto operations and EFI state).
const HEAP_SIZE: usize = 4 * 1024 * 1024;

/// Page size (4KB).
const PAGE_SIZE: usize = 4096;

/// Number of pages for the heap.
const HEAP_PAGES: u64 = (HEAP_SIZE / PAGE_SIZE) as u64;

/// Whether [`ALLOCATOR`] has been initialized.
static HEAP_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Global allocator instance.
///
/// When the `global-allocator` feature is enabled, this is registered as the
/// allocator. External firmware that provides its own allocator should not
/// enable that feature.
#[cfg_attr(feature = "global-allocator", global_allocator)]
pub static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Initialize the global allocator.
///
/// This must be called early in the boot process, after the EFI page allocator
/// is initialized and before code that uses `alloc`.
///
/// # Returns
///
/// `true` if initialization succeeded, `false` otherwise.
pub fn init() -> bool {
    use crate::efi::allocator::{AllocateType, MemoryType, allocate_pages};
    use r_efi::efi::Status;

    if HEAP_INITIALIZED.swap(true, Ordering::AcqRel) {
        log::error!("Global allocator is already initialized");
        return false;
    }

    // RuntimeServicesData remains mapped after ExitBootServices, including the
    // linked-list allocator's in-band free-list metadata.
    let mut heap_addr = 0;
    let status = allocate_pages(
        AllocateType::AllocateAnyPages,
        MemoryType::RuntimeServicesData,
        HEAP_PAGES,
        &mut heap_addr,
    );
    if status != Status::SUCCESS {
        HEAP_INITIALIZED.store(false, Ordering::Release);
        log::error!("Failed to allocate heap memory: {:?}", status);
        return false;
    }

    // SAFETY: `heap_addr` is a newly allocated, page-aligned RuntimeServicesData
    // range, and this is the sole initialization guarded by HEAP_INITIALIZED.
    unsafe {
        ALLOCATOR.lock().init(heap_addr as *mut u8, HEAP_SIZE);
    }

    log::info!(
        "Global allocator initialized: heap at {:#x}, size {} KB",
        heap_addr,
        HEAP_SIZE / 1024
    );
    true
}

/// Check if the allocator is initialized.
pub fn is_initialized() -> bool {
    HEAP_INITIALIZED.load(Ordering::Acquire)
}

/// Get heap usage statistics.
pub fn stats() -> (usize, usize) {
    let heap = ALLOCATOR.lock();
    (heap.used(), heap.size())
}
