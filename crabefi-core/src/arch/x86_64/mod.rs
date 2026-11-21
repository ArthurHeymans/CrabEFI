//! x86_64 architecture support
//!
//! This module contains code specific to the x86_64 architecture.

pub mod cache;
pub mod idt;
pub mod io;
pub mod port_regs;
pub mod reset;
pub mod rng;

use x86_64::PhysAddr;
use x86_64::instructions::tlb::Pcid;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::PhysFrame;

const CR3_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const CR3_NO_FLUSH_BIT: u64 = 1 << 63;

#[inline]
fn split_cr3(value: u64) -> (u64, u16, bool) {
    (
        value & CR3_ADDRESS_MASK,
        (value & 0xfff) as u16,
        value & CR3_NO_FLUSH_BIT != 0,
    )
}

/// Read the CR3 register (page table base)
#[inline]
pub fn read_cr3() -> u64 {
    let value: u64;
    // `Cr3::read_raw` intentionally drops CR3 bit 63; this API historically
    // returns the complete register value, including the no-flush bit.
    unsafe {
        core::arch::asm!(
            "mov {}, cr3",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
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
    let (address, low_bits, no_flush) = split_cr3(value);
    let frame = PhysFrame::containing_address(PhysAddr::new(address));

    // SAFETY: Caller ensures the frame and CR3 flags/PCID are valid.
    unsafe {
        if no_flush {
            Cr3::write_pcid_no_flush(frame, Pcid::new(low_bits).unwrap());
        } else {
            Cr3::write_raw(frame, low_bits);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::split_cr3;

    #[test]
    fn split_cr3_preserves_address_low_bits_and_no_flush() {
        assert_eq!(
            split_cr3(0x800f_ffff_ffff_f123),
            (0x000f_ffff_ffff_f000, 0x123, true)
        );
        assert_eq!(
            split_cr3(0x0000_1234_5678_9000),
            (0x0000_1234_5678_9000, 0, false)
        );
    }
}

/// Overwrite the stack below the current frame, where callees that have
/// returned left secrets (key schedules, derived keys, passphrases).
///
/// One `rep stosb` fills from the stack bottom up to the stack pointer,
/// with no gap: it uses no stack itself, and the target has no red zone.
/// Refills with the 0xA5 pattern the entry code writes, so stack usage
/// reports stay meaningful.
#[cfg(all(feature = "platform-entry", feature = "luks"))]
pub(crate) fn scrub_unused_stack() {
    unsafe extern "C" {
        static _stack_bottom: u8;
        static _stack_top: u8;
    }
    let bottom = (&raw const _stack_bottom) as usize;
    let top = (&raw const _stack_top) as usize;
    // SAFETY: everything below the stack pointer and above the stack bottom
    // is unused, and nothing refers to it; x86_64-unknown-none has no red
    // zone. The bounds check keeps another stack (an EFI image calling back)
    // untouched.
    unsafe {
        core::arch::asm!(
            "mov rcx, rsp",
            "cmp rcx, {bottom}",
            "jbe 2f",
            "cmp rcx, {top}",
            "ja 2f",
            "sub rcx, {bottom}",
            "mov rdi, {bottom}",
            "mov al, 0xa5",
            "cld",
            "rep stosb",
            "2:",
            bottom = in(reg) bottom,
            top = in(reg) top,
            out("rcx") _,
            out("rdi") _,
            out("al") _,
            options(nostack),
        );
    }
}

/// Read the Time Stamp Counter (TSC)
///
/// Returns the current value of the processor's time-stamp counter,
/// which increments at a constant rate (typically the processor's base frequency).
#[cfg(not(miri))]
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

/// Miri cannot run inline assembly. Host tests under Miri get a counter that
/// advances on every read, like a running TSC.
#[cfg(miri)]
pub fn rdtsc() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static TSC: AtomicU64 = AtomicU64::new(0);
    TSC.fetch_add(1_000, Ordering::Relaxed)
}

/// Halt the CPU until the next interrupt
#[inline]
pub fn halt() {
    x86_64::instructions::hlt();
}
