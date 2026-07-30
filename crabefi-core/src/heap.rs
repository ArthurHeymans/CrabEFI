//! Global Allocator for CrabEFI
//!
//! The boot heap is backed by `BootServicesData` and must not survive
//! `SetVirtualAddressMap`. Runtime code is allocation-free; the allocator is
//! frozen at the transition so accidental use fails deterministically instead
//! of following stale physical free-list pointers.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use linked_list_allocator::LockedHeap;

/// Heap size (4 MiB should be sufficient for crypto operations and EFI state).
const HEAP_SIZE: usize = 4 * 1024 * 1024;

/// Page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Number of pages for the heap.
const HEAP_PAGES: u64 = (HEAP_SIZE / PAGE_SIZE) as u64;

/// Whether [`ALLOCATOR`] has been initialized.
static HEAP_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// A boot-only allocator with an explicit SVAM freeze tripwire.
pub struct FirmwareAllocator {
    heap: LockedHeap,
    frozen: AtomicBool,
}

impl FirmwareAllocator {
    const fn empty() -> Self {
        Self {
            heap: LockedHeap::empty(),
            frozen: AtomicBool::new(false),
        }
    }

    /// Prevent all subsequent allocations and deallocations.
    fn freeze(&self) {
        self.frozen.store(true, Ordering::Release);
    }

    fn is_frozen(&self) -> bool {
        self.frozen.load(Ordering::Acquire)
    }
}

// SAFETY: before freezing, allocation is delegated to LockedHeap, which
// serializes access internally. After freezing, no allocator metadata is
// touched, because its in-band links still contain physical addresses.
unsafe impl GlobalAlloc for FirmwareAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if self.is_frozen() {
            return ptr::null_mut();
        }
        // SAFETY: delegated under the same GlobalAlloc contract.
        unsafe { GlobalAlloc::alloc(&self.heap, layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if self.is_frozen() {
            // Objects allocated before SVAM may no longer be addressable by
            // their physical pointer. Leak rather than corrupt stale metadata.
            return;
        }
        // SAFETY: delegated under the same GlobalAlloc contract.
        unsafe { GlobalAlloc::dealloc(&self.heap, ptr, layout) }
    }
}

/// Global allocator instance.
///
/// When the `global-allocator` feature is enabled, this is registered as the
/// allocator. External firmware that provides its own allocator should not
/// enable that feature.
#[cfg_attr(feature = "global-allocator", global_allocator)]
pub static ALLOCATOR: FirmwareAllocator = FirmwareAllocator::empty();

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

    let mut heap_addr = 0;
    let status = allocate_pages(
        AllocateType::AllocateAnyPages,
        MemoryType::BootServicesData,
        HEAP_PAGES,
        &mut heap_addr,
    );
    if status != Status::SUCCESS {
        HEAP_INITIALIZED.store(false, Ordering::Release);
        log::error!("Failed to allocate heap memory: {:?}", status);
        return false;
    }

    // SAFETY: `heap_addr` is a newly allocated, page-aligned BootServicesData
    // range, and this is the sole initialization guarded by HEAP_INITIALIZED.
    unsafe {
        ALLOCATOR.heap.lock().init(heap_addr as *mut u8, HEAP_SIZE);
    }

    log::info!(
        "Global allocator initialized: heap at {:#x}, size {} KB",
        heap_addr,
        HEAP_SIZE / 1024
    );
    true
}

/// Freeze the boot heap before virtual address conversion.
///
/// Once frozen, allocations return null and deallocations are ignored. The
/// operation is one-way because the heap's in-band links are physical pointers.
pub fn freeze_for_virtual_address_map() {
    ALLOCATOR.freeze();
}

/// Check if the allocator is initialized.
pub fn is_initialized() -> bool {
    HEAP_INITIALIZED.load(Ordering::Acquire)
}

/// Get heap usage statistics.
pub fn stats() -> (usize, usize) {
    let heap = ALLOCATOR.heap.lock();
    (heap.used(), heap.size())
}
