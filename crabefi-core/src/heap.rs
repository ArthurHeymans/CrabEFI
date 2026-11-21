//! Global Allocator for CrabEFI
//!
//! This module provides the global allocator used by `alloc`. Its backing pages
//! are BootServicesData and intentionally disappear after ExitBootServices.
//! The separate runtime image uses fixed stack buffers instead and never
//! reaches this boot allocator.

use core::sync::atomic::{AtomicBool, Ordering};

use core::alloc::{GlobalAlloc, Layout};

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
// Host workspace tests can unify this feature through the coreboot package;
// never replace the test harness allocator outside bare-metal targets.
#[cfg_attr(
    all(feature = "global-allocator", target_os = "none"),
    global_allocator
)]
pub static ALLOCATOR: Heap = Heap(LockedHeap::empty());

/// The firmware heap. With `luks` it clears every block when it is freed,
/// so data freed earlier (decrypted file contents, filesystem caches,
/// parsed key material) never lingers in free memory.
pub struct Heap(LockedHeap);

impl Heap {
    /// Lock the underlying heap.
    pub fn lock(&self) -> impl core::ops::DerefMut<Target = linked_list_allocator::Heap> + '_ {
        self.0.lock()
    }
}

// SAFETY: allocation is forwarded unchanged; deallocation only clears the
// block, which the caller gives up, before forwarding. `realloc` uses the
// default alloc-copy-dealloc, so moved-from blocks are cleared too.
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded with the caller's guarantees.
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        #[cfg(all(feature = "luks", target_arch = "x86_64"))]
        // SAFETY: the caller owns the whole block until this call returns;
        // as MaybeUninit it need not be initialized (spare capacity, padding).
        zeroize::Zeroize::zeroize(unsafe {
            core::slice::from_raw_parts_mut(ptr.cast::<core::mem::MaybeUninit<u8>>(), layout.size())
        });
        // SAFETY: forwarded with the caller's guarantees.
        unsafe { self.0.dealloc(ptr, layout) }
    }
}

/// Failure to initialize the global allocator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapInitError {
    /// [`init()`] was already called successfully.
    AlreadyInitialized,
    /// The backing page allocation failed with the given EFI status.
    PageAllocation(r_efi::efi::Status),
}

impl core::fmt::Display for HeapInitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HeapInitError::AlreadyInitialized => {
                write!(f, "global allocator is already initialized")
            }
            HeapInitError::PageAllocation(status) => {
                write!(f, "failed to allocate heap memory: {status:?}")
            }
        }
    }
}

/// Initialize the global allocator.
///
/// This must be called early in the boot process, after the EFI page allocator
/// is initialized and before code that uses `alloc`.
///
/// # Errors
///
/// Returns [`HeapInitError::AlreadyInitialized`] if already initialized, or
/// [`HeapInitError::PageAllocation`] if the backing pages cannot be allocated.
pub fn init() -> Result<(), HeapInitError> {
    use crate::efi::allocator::{AllocateType, MemoryType, allocate_pages};

    if HEAP_INITIALIZED.swap(true, Ordering::AcqRel) {
        return Err(HeapInitError::AlreadyInitialized);
    }

    // The global heap and its in-band free-list metadata are boot-only.
    let mut heap_addr = 0;
    let status = allocate_pages(
        AllocateType::AllocateAnyPages,
        MemoryType::BootServicesData,
        HEAP_PAGES,
        &mut heap_addr,
    );
    if status != r_efi::efi::Status::SUCCESS {
        HEAP_INITIALIZED.store(false, Ordering::Release);
        return Err(HeapInitError::PageAllocation(status));
    }

    // SAFETY: `heap_addr` is a newly allocated, page-aligned BootServicesData
    // range, and this is the sole initialization guarded by HEAP_INITIALIZED.
    unsafe {
        ALLOCATOR.lock().init(heap_addr as *mut u8, HEAP_SIZE);
    }

    log::info!(
        "Global allocator initialized: heap at {:#x}, size {} KB",
        heap_addr,
        HEAP_SIZE / 1024
    );
    Ok(())
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
