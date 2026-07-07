//! AArch64 architecture support
//!
//! This module contains code specific to the AArch64 (ARM64) architecture,
//! including exception handling and hardware primitives.

pub mod cache;
// Exception vectors are always available — even when CrabEFI is a library,
// it needs to install exception handlers before running UEFI applications.
// Without VBAR_EL1 set, any exception during shim/GRUB execution would
// vector to address 0x0 (the firmware's _start), causing infinite loops.
pub mod exceptions;
pub mod ns_switch;
pub mod reset;
pub mod rng;

/// Read the current counter value from the ARM Generic Timer
///
/// Returns the value of `CNTPCT_EL0` (physical counter), which increments
/// at the frequency reported by `CNTFRQ_EL0`.
#[inline]
pub fn read_counter() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, CNTPCT_EL0",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Read the ARM Generic Timer frequency in Hz
///
/// Returns the value of `CNTFRQ_EL0`, which is set by firmware (TF-A)
/// at boot. Typically 62.5 MHz on QEMU SBSA.
#[inline]
pub fn read_counter_freq() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, CNTFRQ_EL0",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Read the current exception level (0-3)
#[inline]
pub fn current_el() -> u8 {
    let el: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, CurrentEL",
            out(reg) el,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((el >> 2) & 0x3) as u8
}

/// Direct PL011 UART write (bypasses all logging infrastructure)
///
/// This writes directly to the PL011 UART MMIO registers. Use this for
/// debugging situations where the normal logging path might be broken
/// (e.g., during/after ExitBootServices).
#[inline]
pub fn uart_direct_write(s: &[u8]) {
    const PL011_BASE: *mut u32 = 0x6000_0000 as *mut u32;
    const PL011_FR: *const u32 = 0x6000_0018 as *const u32;
    for &byte in s {
        unsafe {
            // Wait for TX FIFO not full (bit 5 of FR = TXFF)
            while core::ptr::read_volatile(PL011_FR) & (1 << 5) != 0 {}
            core::ptr::write_volatile(PL011_BASE, byte as u32);
        }
    }
}

/// Halt the CPU until the next event (low-power wait)
#[inline]
pub fn halt() {
    unsafe {
        core::arch::asm!("wfe", options(nomem, nostack, preserves_flags));
    }
}

/// Data synchronization barrier (full system)
#[inline]
pub fn dsb_sy() {
    unsafe {
        core::arch::asm!("dsb sy", options(nomem, nostack, preserves_flags));
    }
}

/// Instruction synchronization barrier
#[inline]
pub fn isb() {
    unsafe {
        core::arch::asm!("isb", options(nomem, nostack, preserves_flags));
    }
}
