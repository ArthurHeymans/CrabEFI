//! Global Allocator for CrabEFI
//!
//! This module provides a global allocator implementation that enables the use of
//! the `alloc` crate for heap allocations. This is required for cryptographic
//! operations in the RustCrypto crates (RSA, X.509, etc.).
//!
//! # Design
//!
//! We use a simple bump allocator backed by a pre-allocated heap region. The heap
//! is allocated from the EFI memory allocator during initialization.
//!
//! # Memory Management
//!
//! - Heap is allocated as `BootServicesData` memory type
//! - Allocations are bump-pointer style (fast allocation)
//! - Deallocation is a no-op (memory is released when boot services exit)
//! - This is appropriate for firmware where allocations are temporary

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Heap size (2 MB should be sufficient for crypto operations)
const HEAP_SIZE: usize = 2 * 1024 * 1024;

/// Page size (4KB)
const PAGE_SIZE: usize = 4096;

/// Number of pages for the heap
const HEAP_PAGES: u64 = (HEAP_SIZE / PAGE_SIZE) as u64;

/// Global heap state
struct BumpAllocator {
    /// Start of the heap
    heap_start: UnsafeCell<usize>,
    /// Current allocation pointer (offset from heap_start)
    offset: AtomicUsize,
    /// Heap size
    heap_size: usize,
    /// Whether the allocator has been initialized
    initialized: AtomicBool,
}

// SAFETY: BumpAllocator is thread-safe because:
// 1. CrabEFI is single-threaded firmware
// 2. We use atomic operations for offset updates
// 3. heap_start is only written once during initialization
unsafe impl Sync for BumpAllocator {}

impl BumpAllocator {
    const fn new() -> Self {
        Self {
            heap_start: UnsafeCell::new(0),
            offset: AtomicUsize::new(0),
            heap_size: 0,
            initialized: AtomicBool::new(false),
        }
    }

    /// Initialize the allocator with a heap region
    ///
    /// # Safety
    ///
    /// Must be called only once, before any allocations.
    unsafe fn init(&self, heap_start: usize, heap_size: usize) {
        // Store the heap start address
        *self.heap_start.get() = heap_start;

        // We need to update heap_size, but it's not mutable.
        // Since we're single-threaded and this is called before any allocations,
        // we can use a pointer cast to update it.
        let self_mut = self as *const Self as *mut Self;
        (*self_mut).heap_size = heap_size;

        // Reset the offset
        self.offset.store(0, Ordering::Release);
        self.initialized.store(true, Ordering::Release);

        log::info!(
            "Global allocator initialized: heap at {:#x}, size {} KB",
            heap_start,
            heap_size / 1024
        );
    }

    /// Check if the allocator is initialized
    fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }
}

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !self.is_initialized() {
            // Allocator not initialized yet - this shouldn't happen in normal operation
            return null_mut();
        }

        let heap_start = *self.heap_start.get();
        let size = layout.size();
        let align = layout.align();

        // Use a CAS loop to atomically bump the offset
        loop {
            let current_offset = self.offset.load(Ordering::Acquire);

            // Calculate aligned offset
            let alloc_start = heap_start + current_offset;
            let aligned_start = (alloc_start + align - 1) & !(align - 1);
            let padding = aligned_start - alloc_start;
            let new_offset = current_offset + padding + size;

            // Check if we have enough space
            if new_offset > self.heap_size {
                log::error!(
                    "Heap exhausted: requested {} bytes, offset {}, heap_size {}",
                    size,
                    current_offset,
                    self.heap_size
                );
                return null_mut();
            }

            // Try to update the offset atomically
            match self.offset.compare_exchange_weak(
                current_offset,
                new_offset,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return aligned_start as *mut u8,
                Err(_) => continue, // Another allocation happened, retry
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator doesn't deallocate individual allocations.
        // Memory is freed when boot services exit (all BootServicesData is released).
        // This is acceptable for firmware where allocations are temporary.
    }
}

/// Global allocator instance
#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator::new();

/// Initialize the global allocator
///
/// This must be called early in the boot process, after the EFI memory allocator
/// is initialized but before any code that uses `alloc`.
///
/// # Returns
///
/// `true` if initialization succeeded, `false` otherwise.
pub fn init() -> bool {
    use crate::efi::allocator::{allocate_pages, AllocateType, MemoryType};
    use r_efi::efi::Status;

    // Allocate heap pages from the EFI allocator
    let mut heap_addr: u64 = 0;
    let status = allocate_pages(
        AllocateType::AllocateAnyPages,
        MemoryType::BootServicesData,
        HEAP_PAGES,
        &mut heap_addr,
    );

    if status != Status::SUCCESS {
        log::error!("Failed to allocate heap memory: {:?}", status);
        return false;
    }

    // Initialize the bump allocator
    // SAFETY: Called once before any allocations
    unsafe {
        ALLOCATOR.init(heap_addr as usize, HEAP_SIZE);
    }

    true
}

/// Check if the allocator is initialized
pub fn is_initialized() -> bool {
    ALLOCATOR.is_initialized()
}

/// Get heap usage statistics
pub fn stats() -> (usize, usize) {
    let used = ALLOCATOR.offset.load(Ordering::Acquire);
    let total = ALLOCATOR.heap_size;
    (used, total)
}
