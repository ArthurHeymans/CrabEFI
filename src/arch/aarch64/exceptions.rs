//! AArch64 Exception Vector Table and Handlers
//!
//! This module provides a minimal exception vector table for EL2.
//! When an exception occurs, the handler prints diagnostic information
//! (ESR_EL2, ELR_EL2, FAR_EL2, SP) to the PL011 UART and halts.
//!
//! The vector table is placed in a dedicated `.vectors` section that is
//! 2KB-aligned as required by the ARM architecture.

use core::arch::global_asm;

/// PL011 UART base address on QEMU SBSA
const PL011_BASE: u64 = 0x6000_0000;

// The exception vector table and handlers in assembly.
//
// ARM requires the vector table to be 2KB aligned.
// Each vector entry is 128 bytes (0x80) = 32 instructions max.
// There are 16 entries in 4 groups of 4:
//   - Current EL with SP_EL0: Sync, IRQ, FIQ, SError
//   - Current EL with SP_ELx: Sync, IRQ, FIQ, SError
//   - Lower EL using AArch64: Sync, IRQ, FIQ, SError
//   - Lower EL using AArch32: Sync, IRQ, FIQ, SError
global_asm!(
    r#"
.section .vectors, "ax"
.balign 0x800

.global exception_vectors
exception_vectors:

// ============================================================
// Current EL with SP_EL0
// ============================================================

// 0x000: Synchronous
.balign 0x80
    b       exception_handler_sync

// 0x080: IRQ
.balign 0x80
    b       exception_handler_irq

// 0x100: FIQ
.balign 0x80
    b       exception_handler_fiq

// 0x180: SError
.balign 0x80
    b       exception_handler_serror

// ============================================================
// Current EL with SP_ELx  (this is what we normally use at EL2)
// ============================================================

// 0x200: Synchronous
.balign 0x80
    b       exception_handler_sync

// 0x280: IRQ
.balign 0x80
    b       exception_handler_irq

// 0x300: FIQ
.balign 0x80
    b       exception_handler_fiq

// 0x380: SError
.balign 0x80
    b       exception_handler_serror

// ============================================================
// Lower EL using AArch64
// ============================================================

// 0x400: Synchronous
.balign 0x80
    b       exception_handler_sync

// 0x480: IRQ
.balign 0x80
    b       exception_handler_irq

// 0x500: FIQ
.balign 0x80
    b       exception_handler_fiq

// 0x580: SError
.balign 0x80
    b       exception_handler_serror

// ============================================================
// Lower EL using AArch32
// ============================================================

// 0x600: Synchronous
.balign 0x80
    b       exception_handler_sync

// 0x680: IRQ
.balign 0x80
    b       exception_handler_irq

// 0x700: FIQ
.balign 0x80
    b       exception_handler_fiq

// 0x780: SError
.balign 0x80
    b       exception_handler_serror


// ============================================================
// Exception handlers
// ============================================================

// Print a hex character (nibble in w1)
// Clobbers: w2 only
uart_print_nibble:
    and     w1, w1, #0xf
    cmp     w1, #10
    b.lt    1f
    add     w1, w1, #('a' - 10)
    b       2f
1:
    add     w1, w1, #'0'
2:
    // Wait for UART TX ready (bit 5 of FR register = TXFF)
3:
    ldr     w2, [x0, #0x18]        // PL011 FR register
    tbnz    w2, #5, 3b             // Loop while TXFF set
    str     w1, [x0, #0x00]        // PL011 DR register
    ret

// Print 64-bit value in x3 as hex
// Uses: x0 (UART base), x3 (value), x4 (loop counter), x30/lr saved in x5
uart_print_hex64:
    mov     x5, x30                // Save LR
    mov     x4, #60                // Start from bit 60 (top nibble)
4:
    lsr     x1, x3, x4
    bl      uart_print_nibble
    subs    x4, x4, #4
    b.ge    4b
    mov     x30, x5                // Restore LR
    ret

// Print a string (pointer in x6, length in x7)
// Uses: x0 (UART base), w1, w2
uart_print_str:
    cbz     x7, 9f
8:
    ldrb    w1, [x6], #1
    // Wait for TX ready
80:
    ldr     w2, [x0, #0x18]        // PL011 FR register
    tbnz    w2, #5, 80b            // Loop while TXFF set
    str     w1, [x0, #0x00]        // PL011 DR register
    subs    x7, x7, #1
    b.ne    8b
9:
    ret

// ============================================================
// Main exception handler (common for all exception types)
// ============================================================
exception_handler_sync:
    // We're in a bad state - use a dedicated exception stack area
    // Save the original SP in x9 before switching
    mov     x9, sp
    adrp    x10, _exc_stack_top
    add     x10, x10, :lo12:_exc_stack_top
    mov     sp, x10

    // Save a few regs we'll use
    stp     x29, x30, [sp, #-16]!
    stp     x5, x6, [sp, #-16]!
    stp     x7, x8, [sp, #-16]!

    // x0 = UART base address
    mov     x0, #{uart_base}

    // Print banner: "\r\n*** EXCEPTION (Sync) "
    adr     x6, msg_exception
    mov     x7, #msg_exception_len
    bl      uart_print_str

    // Print "ESR="
    adr     x6, msg_esr
    mov     x7, #msg_esr_len
    bl      uart_print_str

    mrs     x3, ESR_EL2
    mov     x8, x3                 // Save ESR for later decoding
    bl      uart_print_hex64

    // Print " ELR="
    adr     x6, msg_elr
    mov     x7, #msg_elr_len
    bl      uart_print_str

    mrs     x3, ELR_EL2
    bl      uart_print_hex64

    // Print " FAR="
    adr     x6, msg_far
    mov     x7, #msg_far_len
    bl      uart_print_str

    mrs     x3, FAR_EL2
    bl      uart_print_hex64

    // Print " SP="
    adr     x6, msg_sp
    mov     x7, #msg_sp_len
    bl      uart_print_str

    mov     x3, x9                 // Original SP
    bl      uart_print_hex64

    // Print " LR="
    adr     x6, msg_lr
    mov     x7, #msg_lr_len
    bl      uart_print_str

    // Recover saved x30 from stack
    ldr     x3, [sp, #40]         // saved_x30 is at sp+32+8
    bl      uart_print_hex64

    // Decode ESR exception class
    lsr     x3, x8, #26           // EC field = bits [31:26]
    adr     x6, msg_ec
    mov     x7, #msg_ec_len
    bl      uart_print_str
    bl      uart_print_hex64

    // Print newline
    adr     x6, msg_nl
    mov     x7, #msg_nl_len
    bl      uart_print_str

    // Halt
7:
    wfe
    b       7b

// IRQ/FIQ/SError handlers - simpler banners then halt
exception_handler_irq:
    mov     x9, sp
    adrp    x10, _exc_stack_top
    add     x10, x10, :lo12:_exc_stack_top
    mov     sp, x10
    stp     x29, x30, [sp, #-16]!
    stp     x5, x6, [sp, #-16]!
    stp     x7, x8, [sp, #-16]!
    mov     x0, #{uart_base}
    adr     x6, msg_irq
    mov     x7, #msg_irq_len
    bl      uart_print_str
    mrs     x3, ELR_EL2
    bl      uart_print_hex64
    adr     x6, msg_nl
    mov     x7, #msg_nl_len
    bl      uart_print_str
    b       7b

exception_handler_fiq:
    mov     x9, sp
    adrp    x10, _exc_stack_top
    add     x10, x10, :lo12:_exc_stack_top
    mov     sp, x10
    stp     x29, x30, [sp, #-16]!
    stp     x5, x6, [sp, #-16]!
    stp     x7, x8, [sp, #-16]!
    mov     x0, #{uart_base}
    adr     x6, msg_fiq
    mov     x7, #msg_fiq_len
    bl      uart_print_str
    mrs     x3, ELR_EL2
    bl      uart_print_hex64
    adr     x6, msg_nl
    mov     x7, #msg_nl_len
    bl      uart_print_str
    b       7b

exception_handler_serror:
    mov     x9, sp
    adrp    x10, _exc_stack_top
    add     x10, x10, :lo12:_exc_stack_top
    mov     sp, x10
    stp     x29, x30, [sp, #-16]!
    stp     x5, x6, [sp, #-16]!
    stp     x7, x8, [sp, #-16]!
    mov     x0, #{uart_base}
    adr     x6, msg_serror
    mov     x7, #msg_serror_len
    bl      uart_print_str
    mrs     x3, ESR_EL2
    bl      uart_print_hex64
    adr     x6, msg_elr
    mov     x7, #msg_elr_len
    bl      uart_print_str
    mrs     x3, ELR_EL2
    bl      uart_print_hex64
    adr     x6, msg_nl
    mov     x7, #msg_nl_len
    bl      uart_print_str
    b       7b

// ============================================================
// String constants
// ============================================================
.section .rodata.exceptions, "a"

msg_exception:
    .ascii  "\r\n*** EXCEPTION (Sync) "
.set msg_exception_len, . - msg_exception

msg_esr:
    .ascii  "ESR="
.set msg_esr_len, . - msg_esr

msg_elr:
    .ascii  " ELR="
.set msg_elr_len, . - msg_elr

msg_far:
    .ascii  " FAR="
.set msg_far_len, . - msg_far

msg_sp:
    .ascii  " SP="
.set msg_sp_len, . - msg_sp

msg_lr:
    .ascii  " LR="
.set msg_lr_len, . - msg_lr

msg_nl:
    .ascii  "\r\n"
.set msg_nl_len, . - msg_nl

msg_irq:
    .ascii  "\r\n*** EXCEPTION (IRQ) ELR="
.set msg_irq_len, . - msg_irq

msg_fiq:
    .ascii  "\r\n*** EXCEPTION (FIQ) ELR="
.set msg_fiq_len, . - msg_fiq

msg_serror:
    .ascii  "\r\n*** EXCEPTION (SError) ESR="
.set msg_serror_len, . - msg_serror

msg_ec:
    .ascii  " EC="
.set msg_ec_len, . - msg_ec
"#,
    uart_base = const PL011_BASE,
);

/// Install the exception vector table by setting VBAR_EL2.
///
/// # Safety
///
/// Must be called at EL2. This changes the exception vector base.
#[inline]
pub unsafe fn install_exception_vectors() {
    unsafe extern "C" {
        static exception_vectors: u8;
    }
    let vbar = &exception_vectors as *const u8 as u64;
    core::arch::asm!(
        "msr VBAR_EL2, {}",
        "isb",
        in(reg) vbar,
        options(nomem, nostack, preserves_flags)
    );
}
