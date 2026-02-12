//! x86_64 architecture support
//!
//! This module contains code specific to the x86_64 architecture,
//! including the 32-bit to 64-bit mode transition and page table setup.

pub mod cache;
pub mod entry;
pub mod idt;
pub mod io;
pub mod port_regs;

/// Read the CR3 register (page table base)
#[inline]
pub fn read_cr3() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) value);
    }
    value
}

/// Write to the CR3 register (page table base)
///
/// # Safety
///
/// The caller must ensure that `value` is a valid page table base address.
/// Invalid values can cause undefined behavior or system crashes.
#[inline]
pub unsafe fn write_cr3(value: u64) {
    core::arch::asm!("mov cr3, {}", in(reg) value);
}

/// Read the Time Stamp Counter (TSC)
///
/// Returns the current value of the processor's time-stamp counter,
/// which increments at a constant rate (typically the processor's base frequency).
#[inline]
pub fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}
