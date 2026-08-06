//! Bounded image-local scratch allocation for authenticated runtime operations.

use allocator_api2::alloc::{AllocError, Allocator};
use core::alloc::Layout;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
static SCOPE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Lifetime brand for explicit allocations made within a scratch scope.
#[derive(Clone, Copy)]
pub struct ScratchAlloc<'scope> {
    _scope: PhantomData<&'scope Scope>,
}

/// Rewinds all scoped allocations when dropped.
struct Scope {
    checkpoint: usize,
}

impl Scope {
    fn allocator(&self) -> ScratchAlloc<'_> {
        ScratchAlloc {
            _scope: PhantomData,
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        rewind(self.checkpoint);
        SCOPE_ACTIVE.store(false, Ordering::Release);
    }
}

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

fn allocate(layout: Layout) -> *mut u8 {
    if !active() || layout.size() == 0 || layout.align() > core::mem::align_of::<ScratchBytes>() {
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

// SAFETY: the lifetime brand prevents containers using this allocator from
// outliving their scope. Clones share the same monotonic arena and remain valid
// until the scope is dropped after all branded containers.
unsafe impl Allocator for ScratchAlloc<'_> {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        if layout.size() == 0 {
            let pointer = NonNull::new(layout.align() as *mut u8).ok_or(AllocError)?;
            return Ok(NonNull::slice_from_raw_parts(pointer, 0));
        }
        let pointer = NonNull::new(allocate(layout)).ok_or(AllocError)?;
        Ok(NonNull::slice_from_raw_parts(pointer, layout.size()))
    }

    unsafe fn deallocate(&self, pointer: NonNull<u8>, layout: Layout) {
        let _ = (pointer, layout);
    }
}

/// Activate allocation after the runtime operation lock has been acquired.
pub fn activate() {
    let scope_active = SCOPE_ACTIVE.load(Ordering::Acquire);
    debug_assert!(
        !scope_active,
        "cannot activate scratch during an active scope"
    );
    if scope_active {
        return;
    }
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

/// Run `body` in an allocation scope which rewinds on return.
///
/// Returns `None` rather than nesting scopes. An outer allocator could otherwise
/// allocate after the inner checkpoint and retain aliased storage after rewind.
pub fn with_scope<R>(body: impl for<'scope> FnOnce(ScratchAlloc<'scope>) -> R) -> Option<R> {
    if SCOPE_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return None;
    }
    let scope = Scope {
        checkpoint: checkpoint(),
    };
    Some(body(scope.allocator()))
}

fn checkpoint() -> usize {
    OFFSET.load(Ordering::Relaxed)
}

fn rewind(checkpoint: usize) {
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
    let scope_active = SCOPE_ACTIVE.load(Ordering::Acquire);
    debug_assert!(!scope_active, "cannot reset scratch during an active scope");
    if scope_active {
        return;
    }
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
pub fn checkpoint_for_test() -> usize {
    checkpoint()
}

/// Rewind test-only scratch allocations after all users have been dropped.
///
/// # Safety
/// No allocation at or above `checkpoint` may still be live.
#[cfg(test)]
pub unsafe fn rewind_for_test(checkpoint: usize) {
    rewind(checkpoint);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_arena_reports_high_water_and_exhaustion() {
        let _guard = test_lock();
        activate();
        set_limit_for_test(64);
        with_scope(|allocator| {
            let first = allocator
                .allocate(Layout::from_size_align(32, 16).unwrap())
                .unwrap();
            assert_eq!(first.cast::<u8>().as_ptr() as usize % 16, 0);
            assert!(
                allocator
                    .allocate(Layout::from_size_align(40, 8).unwrap())
                    .is_err()
            );
            assert_eq!(high_water_for_test(), 32);
        })
        .unwrap();
        reset();
        set_limit_for_test(SCRATCH_SIZE);
    }

    #[test]
    fn explicit_allocator_is_bounded_by_scope() {
        let _guard = test_lock();
        activate();
        with_scope(|allocator| {
            let value =
                crypto_bigint::BoxedUintIn::try_from_be_slice_vartime(&[0x5a; 128], allocator)
                    .unwrap();
            assert_eq!(value.bits_vartime(), 1023);
            assert!(high_water_for_test() >= 128);
        })
        .unwrap();
        assert_eq!(checkpoint_for_test(), 0);
        reset();
    }

    #[test]
    fn nested_scopes_are_rejected() {
        let _guard = test_lock();
        activate();
        with_scope(|_allocator| {
            assert!(with_scope(|_nested| ()).is_none());
        })
        .unwrap();
        reset();
    }

    #[test]
    fn explicit_allocator_reports_exhaustion() {
        let _guard = test_lock();
        activate();
        set_limit_for_test(64);
        with_scope(|allocator| {
            assert!(
                crypto_bigint::BoxedUintIn::try_from_be_slice_vartime(&[0x5a; 128], allocator)
                    .is_err()
            );
        })
        .unwrap();
        reset();
        set_limit_for_test(SCRATCH_SIZE);
    }

    #[test]
    fn arena_rejects_alignment_above_its_base_alignment() {
        let _guard = test_lock();
        activate();
        with_scope(|allocator| {
            for alignment in [1, 16, 4096] {
                let pointer = allocator
                    .allocate(Layout::from_size_align(1, alignment).expect("valid layout"))
                    .unwrap();
                assert_eq!(pointer.cast::<u8>().as_ptr() as usize % alignment, 0);
            }
            let before = high_water_for_test();
            assert!(
                allocator
                    .allocate(Layout::from_size_align(1, 8192).expect("valid layout"))
                    .is_err()
            );
            assert_eq!(high_water_for_test(), before);
        })
        .unwrap();
        reset();
    }
}
