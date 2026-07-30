//! RISC-V 64-bit entry point for CrabEFI
//!
//! When coreboot + OpenSBI launches this payload:
//!   - a0 = hart ID
//!   - a1 = pointer to Flattened Device Tree (FDT)
//!   - Running in S-mode (Supervisor mode)
//!   - MMU is off (satp = 0), identity-mapped
//!   - Interrupts disabled
//!
//! The FDT contains a `/chosen/coreboot-table` property with the
//! physical address of the coreboot information tables.

use core::arch::global_asm;

global_asm!(
    r#"
.section .text.entry, "ax"

.global _start
_start:
    # a0 = hart_id (from OpenSBI / coreboot)
    # a1 = FDT pointer (from OpenSBI / coreboot)

    # Save arguments in callee-saved registers
    mv s0, a0               # s0 = hart_id
    mv s1, a1               # s1 = fdt_ptr

    # Set up the stack pointer
    la sp, _stack_top

    # Set up the trap vector to our handler
    la t0, _trap_entry
    csrw stvec, t0

    # Zero BSS section
    la t0, _bss_start
    la t1, _bss_end
    bgeu t0, t1, 2f
1:
    sd zero, 0(t0)
    addi t0, t0, 8
    bgeu t0, t1, 2f
    sd zero, 0(t0)
    addi t0, t0, 8
    bltu t0, t1, 1b
2:

    # .runtime_state is NOLOAD and therefore has no initialized image bytes.
    la t0, _runtime_state_start
    la t1, _runtime_state_end
    bgeu t0, t1, 4f
3:
    sd zero, 0(t0)
    addi t0, t0, 8
    bltu t0, t1, 3b
4:

    # Call Rust entry point: riscv_main(hart_id, fdt_ptr)
    mv a0, s0
    mv a1, s1
    call riscv_main

    # Should not return, but halt if it does
5:
    wfi
    j 5b

# -------------------------------------------------------------------
# S-mode trap entry — minimal handler that logs and halts.
# -------------------------------------------------------------------
.balign 4
.global _trap_entry
_trap_entry:
    # Save a few registers for diagnostics
    csrw sscratch, sp
    addi sp, sp, -128

    sd ra,   0(sp)
    sd t0,   8(sp)
    sd t1,  16(sp)
    sd t2,  24(sp)
    sd a0,  32(sp)
    sd a1,  40(sp)
    sd a2,  48(sp)
    sd a3,  56(sp)
    sd a4,  64(sp)
    sd a5,  72(sp)
    sd a6,  80(sp)
    sd a7,  88(sp)

    # Read trap cause and value
    csrr a0, scause
    csrr a1, stval
    csrr a2, sepc

    call riscv_trap_handler

    # Restore and return (if handler returns)
    ld ra,   0(sp)
    ld t0,   8(sp)
    ld t1,  16(sp)
    ld t2,  24(sp)
    ld a0,  32(sp)
    ld a1,  40(sp)
    ld a2,  48(sp)
    ld a3,  56(sp)
    ld a4,  64(sp)
    ld a5,  72(sp)
    ld a6,  80(sp)
    ld a7,  88(sp)

    addi sp, sp, 128
    csrr sp, sscratch

    sret
"#
);
