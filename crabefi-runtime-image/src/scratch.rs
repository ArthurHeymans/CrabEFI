//! Bounded image-local scratch allocation for authenticated runtime operations.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;
#[cfg(not(test))]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicUsize, Ordering};

pub const SCRATCH_SIZE: usize = 512 * 1024;

#[repr(C, align(4096))]
struct ScratchBytes([u8; SCRATCH_SIZE]);

struct ScratchCell(UnsafeCell<ScratchBytes>);

// SAFETY: the runtime operation lease serializes all allocator use. The atomic
// cursor also keeps accidental re-entrant allocation from overlapping blocks.
unsafe impl Sync for ScratchCell {}

static SCRATCH: ScratchCell = ScratchCell(UnsafeCell::new(ScratchBytes([0; SCRATCH_SIZE])));
#[cfg(not(test))]
static ACTIVE: AtomicBool = AtomicBool::new(false);
static OFFSET: AtomicUsize = AtomicUsize::new(0);
static HIGH_WATER: AtomicUsize = AtomicUsize::new(0);
static LIMIT: AtomicUsize = AtomicUsize::new(SCRATCH_SIZE);

pub struct ScratchAllocator;

#[global_allocator]
static ALLOCATOR: ScratchAllocator = ScratchAllocator;

#[cfg(test)]
std::thread_local! {
    static TEST_ACTIVE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

fn active() -> bool {
    #[cfg(not(test))]
    return ACTIVE.load(Ordering::Acquire);
    #[cfg(test)]
    return TEST_ACTIVE.with(core::cell::Cell::get);
}

// SAFETY: allocations are handed out monotonically from the aligned BSS arena
// only while the sole runtime operation lease is active. Deallocation is a
// no-op; the complete arena is cleared when that lease is released.
unsafe impl GlobalAlloc for ScratchAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        #[cfg(test)]
        if !active() {
            // SAFETY: inactive host-test allocations belong to the system
            // allocator and are returned to it by the matching deallocator.
            return unsafe { std::alloc::System.alloc(layout) };
        }
        if !active() || layout.size() == 0 {
            return ptr::null_mut();
        }
        let align = layout.align();
        let limit = LIMIT.load(Ordering::Relaxed).min(SCRATCH_SIZE);
        let mut current = OFFSET.load(Ordering::Relaxed);
        loop {
            let Some(aligned) = current
                .checked_add(align - 1)
                .map(|value| value & !(align - 1))
            else {
                return ptr::null_mut();
            };
            let Some(end) = aligned.checked_add(layout.size()) else {
                return ptr::null_mut();
            };
            if end > limit {
                return ptr::null_mut();
            }
            match OFFSET.compare_exchange_weak(current, end, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => {
                    HIGH_WATER.fetch_max(end, Ordering::Relaxed);
                    // SAFETY: `aligned..end` was reserved atomically inside the
                    // arena and its base alignment is at least one page.
                    return unsafe { (*SCRATCH.0.get()).0.as_mut_ptr().add(aligned) };
                }
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        #[cfg(test)]
        {
            let base = unsafe { (*SCRATCH.0.get()).0.as_ptr() as usize };
            if !(base..base + SCRATCH_SIZE).contains(&(pointer as usize)) {
                // SAFETY: pointers outside the scratch arena were allocated by
                // the host system fallback above.
                unsafe { std::alloc::System.dealloc(pointer, layout) };
            }
        }
        #[cfg(not(test))]
        let _ = (pointer, layout);
    }
}

/// Activate allocation after the runtime operation lock has been acquired.
pub fn activate() {
    OFFSET.store(0, Ordering::Relaxed);
    HIGH_WATER.store(0, Ordering::Relaxed);
    #[cfg(not(test))]
    ACTIVE.store(true, Ordering::Release);
    #[cfg(test)]
    TEST_ACTIVE.with(|active| active.set(true));
}

/// Return whether at least `required` bytes remain in the bounded arena.
pub fn preflight(required: usize) -> bool {
    if !active() {
        return false;
    }
    OFFSET
        .load(Ordering::Relaxed)
        .checked_add(required)
        .is_some_and(|end| end <= LIMIT.load(Ordering::Relaxed).min(SCRATCH_SIZE))
}

/// Snapshot the cursor for one nested cryptographic verification.
pub fn checkpoint() -> usize {
    OFFSET.load(Ordering::Relaxed)
}

/// Release and scrub allocations made after a checkpoint.
pub fn rewind(checkpoint: usize) {
    let current = OFFSET.load(Ordering::Relaxed);
    if !active() || checkpoint > current {
        return;
    }
    // SAFETY: the crypto caller dropped every allocation made after this
    // checkpoint and still owns the runtime operation lease.
    unsafe {
        ptr::write_bytes(
            (*SCRATCH.0.get()).0.as_mut_ptr().add(checkpoint),
            0,
            current - checkpoint,
        )
    };
    OFFSET.store(checkpoint, Ordering::Relaxed);
}

/// Zero and deactivate the complete arena at operation end.
pub fn reset() {
    #[cfg(not(test))]
    ACTIVE.store(false, Ordering::Release);
    #[cfg(test)]
    TEST_ACTIVE.with(|active| active.set(false));
    // SAFETY: the operation lease is still held, so no allocator user can race
    // the required full-arena scrub.
    unsafe { ptr::write_bytes((*SCRATCH.0.get()).0.as_mut_ptr(), 0, SCRATCH_SIZE) };
    OFFSET.store(0, Ordering::Relaxed);
}

#[cfg(test)]
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap()
}

#[cfg(test)]
pub fn set_limit_for_test(limit: usize) {
    LIMIT.store(limit.min(SCRATCH_SIZE), Ordering::Relaxed);
}

#[cfg(test)]
pub fn high_water_for_test() -> usize {
    HIGH_WATER.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_arena_reports_high_water_and_exhaustion() {
        let _guard = test_lock();
        activate();
        set_limit_for_test(64);
        let first = unsafe { ALLOCATOR.alloc(Layout::from_size_align(32, 16).unwrap()) };
        assert!(!first.is_null());
        let exhausted = unsafe { ALLOCATOR.alloc(Layout::from_size_align(40, 8).unwrap()) };
        assert!(exhausted.is_null());
        assert_eq!(high_water_for_test(), 32);
        reset();
        set_limit_for_test(SCRATCH_SIZE);
    }
}
