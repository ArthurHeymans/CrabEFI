//! Global Allocator for CrabEFI
//!
//! This module provides a global allocator implementation that enables the use of
//! the `alloc` crate for heap allocations. This is required for cryptographic
//! operations in the RustCrypto crates (RSA, X.509, etc.) and for ratatui's
//! terminal UI rendering.
//!
//! # Design
//!
//! We use `talc`, a lightweight allocator with proper deallocation support,
//! backed by a pre-allocated heap region from the EFI page allocator.
//!
//! # Memory Management
//!
//! - Heap is allocated as `RuntimeServicesData` with EFI_MEMORY_RUNTIME attribute
//! - This ensures the OS preserves the heap after ExitBootServices, so runtime
//!   services (SetVariable, etc.) can continue to use heap allocations for
//!   authenticated variable verification, varstore persistence, etc.
//! - Proper alloc/dealloc via talc's bucketed linked-list algorithm

use talc::{ErrOnOom, Span, Talc, Talck};

/// Heap size (2 MB should be sufficient for crypto operations + UI)
const HEAP_SIZE: usize = 2 * 1024 * 1024;

/// Page size (4KB)
const PAGE_SIZE: usize = 4096;

/// Number of pages for the heap
const HEAP_PAGES: u64 = (HEAP_SIZE / PAGE_SIZE) as u64;

/// Global allocator instance
///
/// Uses `spin::Mutex` for locking (CrabEFI is single-threaded but GlobalAlloc
/// requires Sync). `ErrOnOom` causes allocation failure to return null rather
/// than panic.
#[global_allocator]
static ALLOCATOR: Talck<spin::Mutex<()>, ErrOnOom> = Talc::new(ErrOnOom).lock();

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

    // Allocate heap pages as RuntimeServicesData so the OS preserves them
    // after ExitBootServices. Runtime services (SetVariable, etc.) need
    // heap allocations for authenticated variable verification, varstore
    // persistence, and crypto operations.
    let mut heap_addr: u64 = 0;
    let status = allocate_pages(
        AllocateType::AllocateAnyPages,
        MemoryType::RuntimeServicesData,
        HEAP_PAGES,
        &mut heap_addr,
    );

    if status != Status::SUCCESS {
        log::error!("Failed to allocate heap memory: {:?}", status);
        return false;
    }

    let heap_start = heap_addr as *mut u8;
    // Safety: heap_start is a valid pointer to HEAP_SIZE bytes of EFI-allocated memory.
    // This is called once before any allocations.
    unsafe {
        let heap_span = Span::new(heap_start, heap_start.add(HEAP_SIZE));
        ALLOCATOR
            .lock()
            .claim(heap_span)
            .expect("Failed to claim heap memory for allocator");
    }

    log::info!(
        "Global allocator initialized: heap at {:#x}, size {} KB",
        heap_addr,
        HEAP_SIZE / 1024
    );

    true
}
