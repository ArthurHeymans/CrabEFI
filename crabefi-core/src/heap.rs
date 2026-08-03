//! Global Allocator for CrabEFI
//!
//! The boot heap is backed by `BootServicesData` and must not survive
//! `SetVirtualAddressMap`. Runtime code uses a bounded, pointer-free workspace;
//! the boot allocator is disabled at ExitBootServices and never reused after
//! the physical-to-virtual transition.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use linked_list_allocator::LockedHeap;

/// Bounded workspace for allocations made by authenticated runtime writes.
///
/// It is placed in the runtime section and uses an atomic bump cursor, so it
/// has no physical free-list pointers to relocate. Each runtime SetVariable
/// operation consumes temporary allocations only; the cursor is reset before
/// the next operation.
pub const RUNTIME_HEAP_SIZE: usize = 512 * 1024;

#[repr(align(16))]
struct RuntimeHeapStorage([u8; RUNTIME_HEAP_SIZE]);

#[unsafe(link_section = ".runtime_state")]
static mut RUNTIME_HEAP_STORAGE: RuntimeHeapStorage = RuntimeHeapStorage([0; RUNTIME_HEAP_SIZE]);

#[unsafe(link_section = ".runtime_state")]
static RUNTIME_HEAP_OFFSET: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

static RUNTIME_OPERATION_ACTIVE: AtomicBool = AtomicBool::new(false);

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
    runtime_enabled: AtomicBool,
}

impl FirmwareAllocator {
    const fn empty() -> Self {
        Self {
            heap: LockedHeap::empty(),
            frozen: AtomicBool::new(false),
            runtime_enabled: AtomicBool::new(false),
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

impl FirmwareAllocator {
    fn runtime_alloc(&self, layout: Layout) -> *mut u8 {
        if !self.runtime_enabled.load(Ordering::Acquire)
            || !RUNTIME_OPERATION_ACTIVE.load(Ordering::Acquire)
        {
            // Runtime allocations are valid only while an EFI operation owns
            // the resettable arena. This prevents callbacks or retained global
            // objects from outliving the next cursor reset.
            return ptr::null_mut();
        }
        if layout.size() == 0 {
            return layout.align() as *mut u8;
        }

        // SAFETY: the runtime workspace is a dedicated serialized bump arena.
        let base = unsafe { &raw mut RUNTIME_HEAP_STORAGE.0 as *mut u8 as usize };
        let mask = layout.align().saturating_sub(1);
        let mut current = RUNTIME_HEAP_OFFSET.load(Ordering::Relaxed);
        loop {
            let Some(start) = base
                .checked_add(current)
                .and_then(|address| address.checked_add(mask))
                .map(|address| address & !mask)
            else {
                return ptr::null_mut();
            };
            let Some(end) = start.checked_add(layout.size()) else {
                return ptr::null_mut();
            };
            let Some(next) = end.checked_sub(base) else {
                return ptr::null_mut();
            };
            if next > RUNTIME_HEAP_SIZE {
                return ptr::null_mut();
            }
            match RUNTIME_HEAP_OFFSET.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return start as *mut u8,
                Err(observed) => current = observed,
            }
        }
    }
}

// SAFETY: before freezing, allocation is delegated to LockedHeap, which
// serializes access internally. After freezing, only the runtime bump cursor
// is touched; it contains no physical free-list pointers.
unsafe impl GlobalAlloc for FirmwareAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if self.is_frozen() || self.runtime_enabled.load(Ordering::Acquire) {
            return self.runtime_alloc(layout);
        }
        // SAFETY: delegated under the same GlobalAlloc contract.
        unsafe { GlobalAlloc::alloc(&self.heap, layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if self.is_frozen() || self.runtime_enabled.load(Ordering::Acquire) {
            // Runtime allocations are operation-scoped and reclaimed by
            // resetting the bump cursor; no stale free-list is touched.
            let _ = (ptr, layout);
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

/// Enable the bounded runtime allocation workspace after a successful
/// ExitBootServices transition.
pub fn enable_runtime_allocations() {
    RUNTIME_HEAP_OFFSET.store(0, Ordering::Release);
    ALLOCATOR.runtime_enabled.store(true, Ordering::Release);
}

/// Guard for exclusive use of the resettable runtime allocation workspace.
pub struct RuntimeOperation;

impl Drop for RuntimeOperation {
    fn drop(&mut self) {
        RUNTIME_OPERATION_ACTIVE.store(false, Ordering::Release);
    }
}

/// Start one allocation-scoped runtime operation.
///
/// Returns `None` instead of resetting storage that is still in use by a
/// concurrent or re-entrant runtime call.
pub fn begin_runtime_operation() -> Option<RuntimeOperation> {
    if !ALLOCATOR.runtime_enabled.load(Ordering::Acquire)
        || RUNTIME_OPERATION_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return None;
    }
    RUNTIME_HEAP_OFFSET.store(0, Ordering::Release);
    Some(RuntimeOperation)
}

/// Physical ranges that must remain mapped for runtime allocation.
pub fn runtime_workspace_ranges() -> [(u64, u64); 2] {
    // SAFETY: taking a raw address does not access the mutable static.
    let storage_start = unsafe { &raw const RUNTIME_HEAP_STORAGE.0 as u64 };
    let storage_end = storage_start + RUNTIME_HEAP_SIZE as u64;
    let cursor_start = &raw const RUNTIME_HEAP_OFFSET as u64;
    let cursor_end = cursor_start + core::mem::size_of_val(&RUNTIME_HEAP_OFFSET) as u64;
    [(storage_start, storage_end), (cursor_start, cursor_end)]
}

/// Bytes left in the current bounded runtime allocation operation.
pub fn runtime_bytes_remaining() -> usize {
    RUNTIME_HEAP_SIZE.saturating_sub(RUNTIME_HEAP_OFFSET.load(Ordering::Acquire))
}

/// Freeze the boot heap before virtual address conversion.
///
/// Once frozen, allocations use only the bounded runtime workspace and
/// deallocations are ignored. The boot heap is one-way because its in-band
/// links are physical pointers.
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
