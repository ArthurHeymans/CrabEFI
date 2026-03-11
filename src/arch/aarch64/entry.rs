//! AArch64 entry point for CrabEFI
//!
//! On QEMU SBSA with coreboot, the payload is called directly at EL2:
//!   - x0 = pointer to coreboot table
//!   - MMU state is whatever coreboot left (may be on or off)
//!   - Stack needs to be set up by us
//!
//! The entry point sets up the stack, zeroes BSS, and calls rust_main.

use core::arch::global_asm;

global_asm!(
    r#"
.section .text.entry, "ax"

.global _start
_start:
    // x0 = coreboot table pointer (passed by coreboot)
    // Save it in a callee-saved register
    mov x19, x0

    // Install our exception vector table FIRST, before anything else.
    // Coreboot's VBAR_EL2 points to ramstage memory that will be reused.
    adrp x1, exception_vectors
    add x1, x1, :lo12:exception_vectors
    msr VBAR_EL2, x1
    isb

    // Set up the stack pointer
    adrp x1, _stack_top
    add x1, x1, :lo12:_stack_top
    mov sp, x1

    // Zero BSS section
    adrp x1, _bss_start
    add x1, x1, :lo12:_bss_start
    adrp x2, _bss_end
    add x2, x2, :lo12:_bss_end
    cmp x1, x2
    b.ge 2f
1:
    stp xzr, xzr, [x1], #16
    cmp x1, x2
    b.lt 1b
2:

    // Restore coreboot table pointer as first argument
    mov x0, x19

    // Call Rust entry point
    bl rust_main

    // Should not return, but halt if it does
3:
    wfe
    b 3b
"#
);
