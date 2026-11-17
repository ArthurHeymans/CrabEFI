//! Host-only allocation fault injection, scoped to the calling test thread.

use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};

struct FailingAllocator;

#[derive(Clone, Copy)]
struct Budget {
    remaining: usize,
    attempts: usize,
}

std::thread_local! {
    static BUDGET: Cell<Option<Budget>> = const { Cell::new(None) };
}

fn denied() -> bool {
    BUDGET
        .try_with(|state| {
            let Some(mut budget) = state.get() else {
                return false;
            };
            budget.attempts += 1;
            let denied = budget.remaining == 0;
            budget.remaining = budget.remaining.saturating_sub(1);
            state.set(Some(budget));
            denied
        })
        .unwrap_or(false)
}

// SAFETY: successful operations and all deallocations are forwarded unchanged
// to System. Returning null on denial follows the GlobalAlloc failure contract.
unsafe impl GlobalAlloc for FailingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if denied() {
            core::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if denied() {
            core::ptr::null_mut()
        } else {
            unsafe { System.alloc_zeroed(layout) }
        }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if denied() {
            core::ptr::null_mut()
        } else {
            unsafe { System.realloc(pointer, layout, size) }
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: FailingAllocator = FailingAllocator;

/// Allow this many allocation/reallocation attempts, then return null. Restore
/// the previous budget even on unwind, and report how many attempts were made.
pub(crate) fn with_budget<R>(allocations: usize, f: impl FnOnce() -> R) -> (R, usize) {
    struct Reset(Option<Budget>);
    impl Drop for Reset {
        fn drop(&mut self) {
            BUDGET.set(self.0);
        }
    }
    let _reset = Reset(BUDGET.replace(Some(Budget {
        remaining: allocations,
        attempts: 0,
    })));
    let result = f();
    (result, BUDGET.get().unwrap().attempts)
}
