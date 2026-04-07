//! RISC-V 64-bit architecture support
//!
//! This module contains code specific to the RISC-V 64-bit (RV64GC)
//! architecture, including SBI wrappers, the entry point, trap handling,
//! and hardware primitives.
//!
//! CrabEFI runs in S-mode (Supervisor mode) under OpenSBI. All
//! privileged operations (timer, IPI, reset, console) go through
//! the SBI ecall interface to OpenSBI in M-mode.

pub mod cache;
#[cfg(feature = "platform-entry")]
pub mod entry;
pub mod reset;
pub mod rng;
pub mod sbi;

/// Read the monotonic time counter (`rdtime` / `time` CSR).
///
/// In S-mode the `time` CSR is a read-only shadow of `mtime`.
/// The frequency is reported in the FDT at `/cpus/timebase-frequency`
/// (typically 10 MHz on QEMU virt).
#[inline]
pub fn read_counter() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "rdtime {}",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Read the current hart ID.
///
/// In S-mode the `mhartid` CSR is not directly accessible.  The hart ID is
/// captured from the `a0` register at firmware entry and stored in a library
/// atomic via `crabefi::efi::set_boot_hartid`.  Use that value instead of
/// this function for the boot hart ID.
///
/// This stub is retained for API compatibility but always returns 0; callers
/// that need the actual boot hart ID should read it through `efi::set_boot_hartid`.
#[inline]
pub fn read_hart_id() -> u64 {
    0
}

/// Direct 16550 UART write (bypasses all logging infrastructure).
///
/// Writes directly to the QEMU virt 16550 UART at 0x1000_0000.
/// Use for debugging when the normal logging path may be broken.
#[inline]
pub fn uart_direct_write(s: &[u8]) {
    const UART_BASE: *mut u8 = 0x1000_0000 as *mut u8;
    const UART_LSR: *const u8 = 0x1000_0005 as *const u8;
    const LSR_TX_EMPTY: u8 = 0x20;

    for &byte in s {
        unsafe {
            // Wait for TX holding register empty
            while core::ptr::read_volatile(UART_LSR) & LSR_TX_EMPTY == 0 {}
            core::ptr::write_volatile(UART_BASE, byte);
        }
    }
}

/// Halt the CPU until the next interrupt (low-power wait).
#[inline]
pub fn halt() {
    unsafe {
        core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
    }
}

/// Full memory fence (all prior loads/stores complete before subsequent ones).
#[inline]
pub fn fence() {
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags));
    }
}

/// S-mode trap handler called from assembly.
///
/// For exceptions: logs the cause and halts with `wfi` (nothing useful can
/// be done after a firmware exception).
///
/// For interrupts: CrabEFI does not use interrupt-driven I/O — all timing is
/// done by polling `rdtime`.  Receiving an interrupt means something (e.g.
/// OpenSBI) left an interrupt source enabled.  We mask the specific interrupt
/// in `SIE` before returning via `sret`; this prevents the immediately
/// re-firing loop that the previous "log and return" approach caused.
/// Unknown interrupt codes halt unconditionally.
#[unsafe(no_mangle)]
pub extern "C" fn riscv_trap_handler(scause: u64, stval: u64, sepc: u64) {
    let is_interrupt = (scause >> 63) != 0;
    let code = scause & 0x7FFF_FFFF_FFFF_FFFF;

    if is_interrupt {
        // SIE bit positions for S-mode interrupt sources
        // Bit 1 = SSIE (software), 5 = STIE (timer), 9 = SEIE (external)
        let sie_mask: u64 = match code {
            1 => 1 << 1,
            5 => 1 << 5,
            9 => 1 << 9,
            _ => 0,
        };

        if sie_mask != 0 {
            log::warn!(
                "RISC-V unexpected interrupt: code={} stval={:#x} sepc={:#x} — masking in SIE",
                code,
                stval,
                sepc
            );
            // Clear the corresponding enable bit so this source cannot fire again.
            unsafe {
                core::arch::asm!(
                    "csrc sie, {mask}",
                    mask = in(reg) sie_mask,
                    options(nomem, nostack, preserves_flags)
                );
            }
            // Return via sret (assembly restores registers).
        } else {
            // Unknown interrupt code — halt rather than spin.
            log::error!(
                "RISC-V unknown interrupt: code={} stval={:#x} sepc={:#x} — halting",
                code,
                stval,
                sepc
            );
            loop {
                unsafe {
                    core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
                }
            }
        }
    } else {
        let cause_name = match code {
            0 => "Instruction address misaligned",
            1 => "Instruction access fault",
            2 => "Illegal instruction",
            3 => "Breakpoint",
            4 => "Load address misaligned",
            5 => "Load access fault",
            6 => "Store/AMO address misaligned",
            7 => "Store/AMO access fault",
            8 => "Environment call from U-mode",
            9 => "Environment call from S-mode",
            12 => "Instruction page fault",
            13 => "Load page fault",
            15 => "Store/AMO page fault",
            _ => "Unknown",
        };

        log::error!(
            "RISC-V EXCEPTION: {} (cause={}, stval={:#x}, sepc={:#x})",
            cause_name,
            code,
            stval,
            sepc
        );

        // Halt on exceptions
        loop {
            unsafe {
                core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
            }
        }
    }
}
