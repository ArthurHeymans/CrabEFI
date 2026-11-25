//! A private stack for x86-64 runtime services that exceed the 4 KiB UEFI
//! caller stack floor.
//!
//! UEFI guarantees a runtime caller only 4 KiB of stack on x64 and 8 KiB on
//! AArch64 and RISC-V. On x64, `SetVariable` (RSA + certificate chains) and
//! `SetVirtualAddressMap` exceed 4 KiB, so those two entries switch to this
//! image's private stack in runtime data. Every other entry fits within the
//! caller's stack and runs directly without switching.
//!
//! AArch64 and RISC-V never switch stacks: all services fit within their 8 KiB
//! UEFI caller stack floor, and Linux's arm64/riscv64 kernel exception entry
//! checks `SP & (1 << THREAD_SHIFT)` for kernel stack overflow and panics if a
//! runtime service switches to an arbitrarily aligned static stack while IRQs
//! are enabled.
//!
//! Because only `SetVariable` and `SetVirtualAddressMap` use the private stack
//! on x64, every `IN_USE` collision is a concurrent combination already
//! forbidden by UEFI 2.10 Table 8.1 (neither service may run concurrently with
//! itself or with the other). Unrelated services such as `GetTime` and
//! `GetVariable` never touch `IN_USE` and remain free to run concurrently.
//!
//! The link-time stack audit (`xtask/src/runtime/stack.rs`) bounds both
//! halves: the caller's stack up to [`trampoline`] against the ABI minimum,
//! and everything [`trampoline`] reaches against `PRIVATE_STACK_SIZE` minus
//! reserved OS interrupt-frame headroom.

#[cfg(target_arch = "x86_64")]
use core::cell::UnsafeCell;
#[cfg(target_arch = "x86_64")]
use core::mem::{ManuallyDrop, MaybeUninit};
#[cfg(all(target_arch = "x86_64", not(test)))]
use core::sync::atomic::{AtomicBool, Ordering};

/// Bytes of private stack on x86-64. The audit reserves explicit interrupt-frame
/// headroom below this size and fails the build if any service exceeds the
/// remaining budget.
#[cfg(target_arch = "x86_64")]
pub const PRIVATE_STACK_SIZE: usize = 32 * 1024;

#[cfg(target_arch = "x86_64")]
#[repr(C, align(16))]
struct Stack(UnsafeCell<[u8; PRIVATE_STACK_SIZE]>);

// SAFETY: only the holder of `IN_USE` touches the bytes, through the stack
// pointer.
#[cfg(target_arch = "x86_64")]
unsafe impl Sync for Stack {}

#[cfg(target_arch = "x86_64")]
static STACK: Stack = Stack(UnsafeCell::new([0; PRIVATE_STACK_SIZE]));

#[cfg(all(target_arch = "x86_64", not(test)))]
static IN_USE: AtomicBool = AtomicBool::new(false);

/// Claim the private stack; false if a service is already running on it.
#[cfg(all(target_arch = "x86_64", not(test)))]
fn claim() -> bool {
    !IN_USE.swap(true, Ordering::Acquire)
}

#[cfg(all(target_arch = "x86_64", not(test)))]
fn release() {
    IN_USE.store(false, Ordering::Release);
}

// Host tests call services from many threads at once; each thread models
// its own CPU.
#[cfg(all(target_arch = "x86_64", test))]
std::thread_local! {
    static IN_USE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[cfg(all(target_arch = "x86_64", test))]
fn claim() -> bool {
    !IN_USE.with(|in_use| in_use.replace(true))
}

#[cfg(all(target_arch = "x86_64", test))]
fn release() {
    IN_USE.with(|in_use| in_use.set(false));
}

/// Run `service` on the private stack on x86-64, or `busy` on the caller's
/// stack if a service is already running on it.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn run<R>(service: impl FnOnce() -> R, busy: impl FnOnce() -> R) -> R {
    if !claim() {
        return busy();
    }
    let result = on_stack(service);
    release();
    result
}

/// On AArch64 and RISC-V every service fits within the 8 KiB UEFI caller
/// stack, so run directly on the caller's stack without switching.
#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub fn run<R>(service: impl FnOnce() -> R, _busy: impl FnOnce() -> R) -> R {
    service()
}

#[cfg(target_arch = "x86_64")]
struct Call<F, R> {
    service: ManuallyDrop<F>,
    result: MaybeUninit<R>,
}

/// Called on the private stack. The audit recognizes this symbol as the
/// boundary between the two stacks.
#[cfg(target_arch = "x86_64")]
extern "C" fn trampoline<F: FnOnce() -> R, R>(call: *mut Call<F, R>) {
    // SAFETY: `on_stack` passes a valid, exclusive pointer and calls the
    // trampoline exactly once, so the service is taken exactly once.
    let call = unsafe { &mut *call };
    let service = unsafe { ManuallyDrop::take(&mut call.service) };
    call.result.write(service());
}

/// Run the trampoline (through `enter`) and return the service's result.
#[cfg(target_arch = "x86_64")]
fn with_call<F: FnOnce() -> R, R>(service: F, enter: impl FnOnce(*mut Call<F, R>)) -> R {
    let mut call = Call {
        service: ManuallyDrop::new(service),
        result: MaybeUninit::uninit(),
    };
    enter(&raw mut call);
    // SAFETY: `enter` returns only after the trampoline wrote the result.
    unsafe { call.result.assume_init() }
}

#[cfg(all(target_arch = "x86_64", not(any(test, kani, miri))))]
fn on_stack<F: FnOnce() -> R, R>(service: F) -> R {
    with_call(service, |call_pointer| switch::<F, R>(call_pointer))
}

#[cfg(all(target_arch = "x86_64", not(any(test, kani, miri))))]
#[inline(always)]
fn switch<F: FnOnce() -> R, R>(call_pointer: *mut Call<F, R>) {
    let top = STACK.0.get().cast::<u8>().wrapping_add(PRIVATE_STACK_SIZE);
    // SAFETY: `IN_USE` grants exclusive use of the 16-byte-aligned stack.
    // The assembly saves the caller's stack pointer in a callee-saved
    // register, calls the trampoline on the private stack under the C ABI,
    // and restores the stack pointer before the block ends.
    unsafe {
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
    }
}

/// Host tests, Kani and Miri run services on the test thread's stack.
#[cfg(all(target_arch = "x86_64", any(test, kani, miri)))]
fn on_stack<F: FnOnce() -> R, R>(service: F) -> R {
    let _ = &STACK;
    with_call(service, |call_pointer| trampoline(call_pointer))
}

#[cfg(all(target_arch = "x86_64", test))]
mod tests {
    use super::*;

    #[test]
    fn reentrant_calls_take_the_busy_path() {
        let inner = run(|| run(|| "service", || "busy"), || "outer busy");
        assert_eq!(inner, "busy");
        assert_eq!(run(|| 1, || 2), 1, "the stack is free again");
    }
}
