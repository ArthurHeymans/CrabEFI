//! RISC-V S-mode trap handler.
//!
//! This module provides [`install_trap_vectors()`], which installs a minimal
//! S-mode trap entry that saves/restores registers and calls
//! [`super::riscv_trap_handler`].

use core::arch::global_asm;

// Minimal S-mode trap entry. Uses the current `sp` (no stack switch via
// sscratch) — this is safe because S-mode traps during CrabEFI execution
// always have a valid stack.
global_asm!(
    r#"
    .section .text
    .balign 4
    .global _crabefi_lib_trap_entry
_crabefi_lib_trap_entry:
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

    csrr a0, scause
    csrr a1, stval
    csrr a2, sepc

    call riscv_trap_handler

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

/// Install the library-mode S-mode trap vectors.
///
/// Sets `stvec` to [`_crabefi_lib_trap_entry`] which dispatches to
/// [`super::riscv_trap_handler`]. Called from [`crate::init_platform_impl`].
pub fn install_trap_vectors() {
    unsafe {
        core::arch::asm!(
            "la {tmp}, _crabefi_lib_trap_entry",
            "csrw stvec, {tmp}",
            tmp = out(reg) _,
            options(nomem, nostack)
        );
    }
}
