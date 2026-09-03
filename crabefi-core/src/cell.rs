//! Interior-mutable cells for single-hart firmware
//!
//! CrabEFI runs on one hart and never touches firmware state from interrupt
//! context. That is the only reason these cells can be `Sync` and live in
//! `static`s. All access is safe code: a conflicting borrow panics with a
//! source location instead of silently aliasing.
//!
//! Never hold a borrow across a call into foreign code: a loaded image entry
//! point, an event notify function, or a platform trait object. Copy what is
//! needed out of the cell, drop the borrow, then call.
//!
//! [`StaticMut`] covers the remaining case: firmware-lifetime singletons
//! (EFI protocol tables, the Boot Services table) that are shared with EFI
//! callers as `*mut` and therefore cannot go through borrow-checked `Local`.

use core::cell::{Cell, Ref, RefCell, RefMut, UnsafeCell};

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
    pub fn borrow(&self) -> Ref<'_, T> {
        self.0.borrow()
    }

    /// Borrow the value mutably. Panics if it is already borrowed.
    #[inline]
    #[track_caller]
    pub fn borrow_mut(&self) -> RefMut<'_, T> {
        self.0.borrow_mut()
    }

    /// Borrow the value mutably, or `None` if it is already borrowed.
    #[inline]
    pub fn try_borrow_mut(&self) -> Option<RefMut<'_, T>> {
        self.0.try_borrow_mut().ok()
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
