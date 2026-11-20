//! A private stack for runtime services.
//!
//! UEFI only guarantees a runtime caller 4 KiB of stack on x64 and 8 KiB on
//! AArch64 and RISC-V. Authenticated variable writes need more than that
//! (RSA, certificate chains), so every service entry switches to this
//! image's own stack, which lives in runtime data the OS must preserve and
//! map. The caller's stack then only holds the entry frame and the switch.
//!
//! The link-time stack audit (`xtask/src/runtime/stack.rs`) bounds both
//! halves: the caller's stack up to [`trampoline`] against the ABI minimum,
//! and everything [`trampoline`] reaches against [`PRIVATE_STACK_SIZE`].
//!
//! UEFI allows ResetSystem to be called while another service runs, so the
//! stack can be in use. A reentrant call then runs `busy` on the caller's
//! stack instead; every entry passes a `busy` path that touches no shared
//! state.

use core::cell::UnsafeCell;
use core::mem::{ManuallyDrop, MaybeUninit};
#[cfg(not(test))]
use core::sync::atomic::{AtomicBool, Ordering};

/// Bytes of private stack. The audit fails the build if any service needs
/// more.
pub const PRIVATE_STACK_SIZE: usize = 32 * 1024;

#[repr(C, align(16))]
struct Stack(UnsafeCell<[u8; PRIVATE_STACK_SIZE]>);

// SAFETY: only the holder of `IN_USE` touches the bytes, through the stack
// pointer.
unsafe impl Sync for Stack {}

static STACK: Stack = Stack(UnsafeCell::new([0; PRIVATE_STACK_SIZE]));

#[cfg(not(test))]
static IN_USE: AtomicBool = AtomicBool::new(false);

/// Claim the private stack; false if a service is already running on it.
#[cfg(not(test))]
fn claim() -> bool {
    !IN_USE.swap(true, Ordering::Acquire)
}

#[cfg(not(test))]
fn release() {
    IN_USE.store(false, Ordering::Release);
}

// Host tests call services from many threads at once; each thread models
// its own CPU.
#[cfg(test)]
std::thread_local! {
    static IN_USE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[cfg(test)]
fn claim() -> bool {
    !IN_USE.with(|in_use| in_use.replace(true))
}

#[cfg(test)]
fn release() {
    IN_USE.with(|in_use| in_use.set(false));
}

/// Run `service` on the private stack, or `busy` on the caller's stack if a
/// service is already running on it.
#[inline(always)]
pub fn run<R>(service: impl FnOnce() -> R, busy: impl FnOnce() -> R) -> R {
    if !claim() {
        return busy();
    }
    let result = on_stack(service);
    release();
    result
}

struct Call<F, R> {
    service: ManuallyDrop<F>,
    result: MaybeUninit<R>,
}

/// Called on the private stack. The audit recognizes this symbol as the
/// boundary between the two stacks.
extern "C" fn trampoline<F: FnOnce() -> R, R>(call: *mut Call<F, R>) {
    // SAFETY: `on_stack` passes a valid, exclusive pointer and calls the
    // trampoline exactly once, so the service is taken exactly once.
    let call = unsafe { &mut *call };
    let service = unsafe { ManuallyDrop::take(&mut call.service) };
    call.result.write(service());
}

/// Run the trampoline (through `enter`) and return the service's result.
fn with_call<F: FnOnce() -> R, R>(service: F, enter: impl FnOnce(*mut Call<F, R>)) -> R {
    let mut call = Call {
        service: ManuallyDrop::new(service),
        result: MaybeUninit::uninit(),
    };
    enter(&raw mut call);
    // SAFETY: `enter` returns only after the trampoline wrote the result.
    unsafe { call.result.assume_init() }
}

#[cfg(not(any(test, kani, miri)))]
fn on_stack<F: FnOnce() -> R, R>(service: F) -> R {
    with_call(service, |call_pointer| switch::<F, R>(call_pointer))
}

#[cfg(not(any(test, kani, miri)))]
#[inline(always)]
fn switch<F: FnOnce() -> R, R>(call_pointer: *mut Call<F, R>) {
    let top = STACK.0.get().cast::<u8>().wrapping_add(PRIVATE_STACK_SIZE);
    // SAFETY: `IN_USE` grants exclusive use of the 16-byte-aligned stack.
    // The assembly saves the caller's stack pointer in a callee-saved
    // register, calls the trampoline on the private stack under the C ABI,
    // and restores the stack pointer before the block ends.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "mov r12, rsp",
            "mov rsp, {top}",
            "call {trampoline}",
            "mov rsp, r12",
            top = in(reg) top,
            trampoline = sym trampoline::<F, R>,
            inout("rdi") call_pointer => _,
            out("r12") _,
            clobber_abi("C"),
        );
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "mov x20, sp",
            "mov sp, {top}",
            "bl {trampoline}",
            "mov sp, x20",
            top = in(reg) top,
            trampoline = sym trampoline::<F, R>,
            inout("x0") call_pointer => _,
            out("x20") _,
            clobber_abi("C"),
        );
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!(
            "mv s2, sp",
            "mv sp, {top}",
            "call {trampoline}",
            "mv sp, s2",
            top = in(reg) top,
            trampoline = sym trampoline::<F, R>,
            inout("a0") call_pointer => _,
            out("s2") _,
            clobber_abi("C"),
        );
    }
}

/// Host tests, Kani and Miri run services on the test thread's stack.
#[cfg(any(test, kani, miri))]
fn on_stack<F: FnOnce() -> R, R>(service: F) -> R {
    let _ = &STACK;
    with_call(service, |call_pointer| trampoline(call_pointer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reentrant_calls_take_the_busy_path() {
        let inner = run(|| run(|| "service", || "busy"), || "outer busy");
        assert_eq!(inner, "busy");
        assert_eq!(run(|| 1, || 2), 1, "the stack is free again");
    }
}
