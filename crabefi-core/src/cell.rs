//! Interior-mutable cells for single-hart firmware
//!
//! CrabEFI runs on one hart and never touches firmware state from interrupt
//! context. That is the only reason these cells can be `Sync` and live in
//! `static`s. All access is safe code: a conflicting borrow panics with a
//! source location instead of silently aliasing.
//!
//! Never hold a borrow across a call into foreign code: a loaded image entry
//! point, an event notify function, or a protocol another image installed.
//! Foreign code may call any Boot Service, which may borrow the same cell.
//! Copy what is needed out of the cell, drop the borrow, then call. In debug
//! builds, including host tests, every `Local` borrow is counted, and
//! `boot_services::with_image_callback` and `StartImage` check
//! [`assert_no_live_borrows`] before entering foreign code. A violation then
//! fails the first test that reaches the call instead of only the rare
//! reentrant path that would hit the conflicting borrow.
//!
//! The check covers `Local` borrows at those boundaries only: a wrapper that
//! makes several foreign calls checks once, on entry, so code that takes
//! borrows between the calls, like the `LoadImage` file reader, must check
//! before each call.
//!
//! [`StaticMut`] covers the remaining case: firmware-lifetime singletons
//! (EFI protocol tables, the Boot Services table) that are shared with EFI
//! callers as `*mut` and therefore cannot go through borrow-checked `Local`.

use core::cell::{Cell, Ref, RefCell, RefMut, UnsafeCell};
use core::ops::{Deref, DerefMut};

// Firmware runs on one hart. Unit tests run on many threads, so each test
// thread counts only its own borrows. Integration tests link the library as
// firmware does and share one counter; they must not overlap borrows of
// unrelated cells with a foreign call on another thread.
#[cfg(all(debug_assertions, not(test)))]
static LIVE_BORROWS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
#[cfg(all(debug_assertions, test))]
std::thread_local! {
    static LIVE_BORROWS: Cell<usize> = const { Cell::new(0) };
}

#[cfg(debug_assertions)]
fn live_borrows(change: isize) -> usize {
    #[cfg(not(test))]
    {
        use core::sync::atomic::Ordering::Relaxed;
        let old = LIVE_BORROWS.fetch_add(change as usize, Relaxed);
        old.wrapping_add(change as usize)
    }
    #[cfg(test)]
    LIVE_BORROWS.with(|live| {
        live.set(live.get().wrapping_add(change as usize));
        live.get()
    })
}

/// Counts one live `Local` borrow in debug builds.
struct Live;

impl Live {
    #[inline]
    fn new() -> Self {
        #[cfg(debug_assertions)]
        live_borrows(1);
        Self
    }
}

impl Drop for Live {
    #[inline]
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        live_borrows(-1);
    }
}

/// Panic in debug builds if a [`Local`] borrow is live.
#[inline]
#[track_caller]
pub fn assert_no_live_borrows() {
    #[cfg(debug_assertions)]
    {
        let live = live_borrows(0);
        assert!(
            live == 0,
            "{live} firmware cell borrow(s) live across a foreign call"
        );
    }
}

/// A shared borrow of a [`Local`].
pub struct Borrowed<'a, T> {
    value: Ref<'a, T>,
    _live: Live,
}

impl<T> Deref for Borrowed<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.value
    }
}

/// An exclusive borrow of a [`Local`].
pub struct BorrowedMut<'a, T> {
    value: RefMut<'a, T>,
    _live: Live,
}

impl<T> Deref for BorrowedMut<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> DerefMut for BorrowedMut<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

/// Interior-mutable cell for single-hart firmware.
///
/// A `RefCell` that is `Sync` so it can live in a `static`.
pub struct Local<T>(RefCell<T>);

// SAFETY: CrabEFI runs on one hart and never accesses firmware state from
// interrupt context, so the `RefCell` borrow counters can never be raced.
// See the module documentation.
unsafe impl<T> Sync for Local<T> {}

impl<T> Local<T> {
    /// Wrap a value.
    pub const fn new(value: T) -> Self {
        Self(RefCell::new(value))
    }

    /// Borrow the value immutably. Panics if it is mutably borrowed.
    #[inline]
    #[track_caller]
    pub fn borrow(&self) -> Borrowed<'_, T> {
        Borrowed {
            value: self.0.borrow(),
            _live: Live::new(),
        }
    }

    /// Borrow the value mutably. Panics if it is already borrowed.
    #[inline]
    #[track_caller]
    pub fn borrow_mut(&self) -> BorrowedMut<'_, T> {
        BorrowedMut {
            value: self.0.borrow_mut(),
            _live: Live::new(),
        }
    }

    /// Borrow the value mutably, or `None` if it is already borrowed.
    #[inline]
    pub fn try_borrow_mut(&self) -> Option<BorrowedMut<'_, T>> {
        Some(BorrowedMut {
            value: self.0.try_borrow_mut().ok()?,
            _live: Live::new(),
        })
    }

    /// Run `f` on a mutable borrow that ends when `f` returns.
    #[inline]
    #[track_caller]
    pub fn with_mut<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut self.borrow_mut())
    }
}

/// Interior-mutable cell for `Copy` values in single-hart firmware.
///
/// A `Cell` that is `Sync` so it can live in a `static`. Reads and writes copy
/// the value, so this can never conflict with any other access.
pub struct LocalCell<T>(Cell<T>);

// SAFETY: See `Local`.
unsafe impl<T> Sync for LocalCell<T> {}

impl<T: Copy> LocalCell<T> {
    /// Wrap a value.
    pub const fn new(value: T) -> Self {
        Self(Cell::new(value))
    }

    /// Copy the value out.
    #[inline]
    pub fn get(&self) -> T {
        self.0.get()
    }

    /// Replace the value.
    #[inline]
    pub fn set(&self, value: T) {
        self.0.set(value)
    }

    /// Modify the value in place through a copy.
    #[inline]
    pub fn update(&self, f: impl FnOnce(&mut T)) {
        let mut value = self.get();
        f(&mut value);
        self.set(value);
    }

    /// Replace the value and return a guard that restores the previous value
    /// when dropped.
    #[inline]
    #[must_use = "the previous value is restored immediately if the guard is dropped"]
    pub fn scoped_set(&self, value: T) -> core::mem::DropGuard<T, impl FnOnce(T) + '_> {
        let previous = self.get();
        self.set(value);
        core::mem::DropGuard::new(previous, |previous| self.set(previous))
    }

    /// Raw pointer to the value, for protocol structures that expose a
    /// firmware-owned mode block to EFI applications.
    #[inline]
    pub fn as_ptr(&self) -> *mut T {
        self.0.as_ptr()
    }
}

/// Raw mutable cell for firmware-lifetime singletons shared as `*mut`.
///
/// Unlike [`Local`], this performs no borrow checking: callers get a raw
/// pointer and must uphold the usual single-hart discipline (no concurrent
/// access, no aliasing `&mut`). Use it only for objects that EFI callers
/// require as `*mut` — protocol tables, the Boot Services table — where a
/// borrow-checked cell cannot be held across the foreign call anyway.
///
/// `repr(transparent)` guarantees the payload lives at offset zero: AArch64
/// assembly computes `_exc_stack_top` as `EXC_STACK + size`, which is only
/// sound if the wrapper adds no padding or reordering.
#[repr(transparent)]
pub struct StaticMut<T>(UnsafeCell<T>);

// SAFETY: same single-hart invariant as `Local`; all access is serialized by
// firmware control flow, never from interrupt context or a second hart.
unsafe impl<T> Send for StaticMut<T> {}
unsafe impl<T> Sync for StaticMut<T> {}

impl<T> StaticMut<T> {
    /// Wrap a value.
    pub const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    /// Raw pointer to the value, valid for the firmware lifetime.
    #[inline]
    pub const fn get(&self) -> *mut T {
        self.0.get()
    }
}

#[cfg(test)]
mod tests {
    use super::LocalCell;

    #[test]
    fn scoped_set_restores_previous_value_on_drop_and_nesting() {
        let cell = LocalCell::new(1u32);
        {
            let _outer = cell.scoped_set(2);
            assert_eq!(cell.get(), 2);
            {
                let _inner = cell.scoped_set(3);
                assert_eq!(cell.get(), 3);
            }
            assert_eq!(cell.get(), 2);
        }
        assert_eq!(cell.get(), 1);
    }

    #[test]
    fn scoped_set_restores_previous_value_on_unwind() {
        let cell = LocalCell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cell.scoped_set(true);
            assert!(cell.get());
            panic!("simulated failure");
        }));
        assert!(result.is_err());
        assert!(!cell.get());
    }
}
