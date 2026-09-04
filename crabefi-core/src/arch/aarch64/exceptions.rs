//! AArch64 Exception Vector Table and Handlers
//!
//! Provides a minimal exception vector table for EL1 and EL2.  When an
//! exception fires, the assembly stub saves the original SP, reads
//! ESR/ELR/FAR from the correct exception level, and tail-calls
//! [`exception_rust_handler`].  That Rust function prints diagnostics
//! via the firmware's configured serial output and halts.
//!
//! The vector table is placed in a dedicated `.vectors` section that is
//! 2 KiB-aligned as required by the AArch64 architecture.

use core::arch::global_asm;

use crate::cell::StaticMut;

/// Exception stack (4 KiB, 16-byte aligned for AArch64 ABI).
///
/// Used by exception handlers to avoid corrupting the firmware stack
/// during exception processing.  `_exc_stack_top` is exported as a
/// symbol for the assembly stubs.
#[repr(C, align(16))]
struct ExcStack([u8; 4096]);

#[unsafe(no_mangle)]
#[used]
#[unsafe(link_section = ".bss.exc_stack")]
static EXC_STACK: StaticMut<ExcStack> = StaticMut::new(ExcStack([0u8; 4096]));

// Export _exc_stack_top = EXC_STACK + 4096.
global_asm!(
    r#"
.global _exc_stack_top
.set _exc_stack_top, EXC_STACK + 4096
"#
);

// ============================================================================
// Exception vector table + shared collection stub
// ============================================================================
//
// ARM requires the table to be 2 KiB aligned; each slot is 128 bytes
// (32 instructions max).  All 16 entries branch to one of four type labels
// (exc_handle_{sync,irq,fiq,serror}).  Those stubs set x4 to the exception
// type constant, then branch to exc_collect, which:
//
//   1. Saves the original SP in x3.
//   2. Switches SP to EXC_STACK top (a clean 4 KiB region).
//   3. Reads ESR / ELR / FAR from the current EL into x0 / x1 / x2.
//   4. Tail-calls exception_rust_handler(esr, elr, far, orig_sp, exc_type).
//
// exception_rust_handler is -> ! so exc_collect never returns.
//
// exc_type constants:  0 = Sync, 1 = IRQ, 2 = FIQ, 3 = SError
global_asm!(
    r#"
.section .vectors, "ax"
.balign 0x800

.global exception_vectors
exception_vectors:

// ---- Current EL with SP_EL0 ----
.balign 0x80
    b       exc_handle_sync
.balign 0x80
    b       exc_handle_irq
.balign 0x80
    b       exc_handle_fiq
.balign 0x80
    b       exc_handle_serror

// ---- Current EL with SP_ELx ----
.balign 0x80
    b       exc_handle_sync
.balign 0x80
    b       exc_handle_irq
.balign 0x80
    b       exc_handle_fiq
.balign 0x80
    b       exc_handle_serror

// ---- Lower EL using AArch64 ----
.balign 0x80
    b       exc_handle_sync
.balign 0x80
    b       exc_handle_irq
.balign 0x80
    b       exc_handle_fiq
.balign 0x80
    b       exc_handle_serror

// ---- Lower EL using AArch32 ----
.balign 0x80
    b       exc_handle_sync
.balign 0x80
    b       exc_handle_irq
.balign 0x80
    b       exc_handle_fiq
.balign 0x80
    b       exc_handle_serror

// ============================================================
// Type stubs — set exc_type (x4) then fall through to exc_collect.
// ============================================================
exc_handle_sync:
    mov     x4, #0
    b       exc_collect

exc_handle_irq:
    mov     x4, #1
    b       exc_collect

exc_handle_fiq:
    mov     x4, #2
    b       exc_collect

exc_handle_serror:
    mov     x4, #3
    b       exc_collect

// ============================================================
// exc_collect — common prologue, then tail-call into Rust.
//
// Entry:  x4 = exc_type
// Effect: switches to EXC_STACK, loads ESR/ELR/FAR,
//         tail-calls exception_rust_handler(x0, x1, x2, x3, x4)
// ============================================================
exc_collect:
    // Save original SP (x3 is our 4th argument slot).
    mov     x3, sp

    // Switch to the dedicated exception stack (16-byte aligned top).
    adrp    x9, _exc_stack_top
    add     x9, x9, :lo12:_exc_stack_top
    mov     sp, x9

    // Read ESR / ELR / FAR from the correct exception level.
    mrs     x9, CurrentEL
    ubfx    x9, x9, #2, #2          // EL field = bits [3:2]
    cmp     x9, #2
    b.ge    1f

    // EL1 path
    mrs     x0, ESR_EL1
    mrs     x1, ELR_EL1
    mrs     x2, FAR_EL1
    b       exception_rust_handler

1:  // EL2 path
    mrs     x0, ESR_EL2
    mrs     x1, ELR_EL2
    mrs     x2, FAR_EL2
    b       exception_rust_handler
"#
);

// ============================================================================
// Rust exception handler
// ============================================================================

/// Rust exception handler — tail-called from the assembly vector table.
///
/// Prints diagnostic registers (ESR, ELR, FAR, original SP, exception class)
/// via the firmware's configured serial output, then halts.
///
/// If called before the serial driver has been initialized (e.g. a very early
/// fault), it skips output and halts quietly — no panic, no hardcoded UART.
///
/// # Safety
///
/// Must only be called from the `exc_collect` assembly stub above. The caller
/// has already switched SP to `EXC_STACK`, so a valid Rust stack is available.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn exception_rust_handler(
    esr: u64,
    elr: u64,
    far: u64,
    sp: u64,
    exc_type: u64,
) -> ! {
    let name = match exc_type {
        0 => "Sync",
        1 => "IRQ",
        2 => "FIQ",
        3 => "SError",
        _ => "Unknown",
    };
    let ec = (esr >> 26) & 0x3f;

    // The serial driver silently drops output until a port is configured.
    crate::drivers::serial::write_fmt(format_args!(
        "\r\n*** EXCEPTION ({name}) \
         ESR={esr:#018x} ELR={elr:#018x} FAR={far:#018x} \
         SP={sp:#018x} EC={ec:#x}\r\n"
    ));

    loop {
        // SAFETY: wfe is side-effect-free with respect to memory.
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
    }
}

// ============================================================================
// Vector installation helpers
// ============================================================================

/// Install the exception vector table by writing `VBAR_EL2`.
///
/// # Safety
///
/// Must be called at EL2.
#[cfg(feature = "platform-entry")]
#[inline]
pub unsafe fn install_exception_vectors() {
    unsafe extern "C" {
        static exception_vectors: u8;
    }
    unsafe {
        let vbar = &exception_vectors as *const u8 as u64;
        core::arch::asm!(
            "msr VBAR_EL2, {}",
            "isb",
            in(reg) vbar,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Install the exception vector table at the current exception level.
///
/// Reads `CurrentEL` to decide between `VBAR_EL1` and `VBAR_EL2`.
///
/// # Safety
///
/// The exception vector table must be linked into the binary (the `.vectors`
/// section from the `global_asm!` above).  `_exc_stack_top` must be defined.
pub unsafe fn install_exception_vectors_auto() {
    unsafe extern "C" {
        static exception_vectors: u8;
    }
    unsafe {
        let vbar = &exception_vectors as *const u8 as u64;
        let current_el: u64;
        core::arch::asm!(
            "mrs {}, CurrentEL",
            out(reg) current_el,
            options(nomem, nostack, preserves_flags)
        );
        let el = (current_el >> 2) & 0x3;
        if el >= 2 {
            core::arch::asm!(
                "msr VBAR_EL2, {}",
                "isb",
                in(reg) vbar,
                options(nomem, nostack, preserves_flags)
            );
        } else {
            core::arch::asm!(
                "msr VBAR_EL1, {}",
                "isb",
                in(reg) vbar,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}
