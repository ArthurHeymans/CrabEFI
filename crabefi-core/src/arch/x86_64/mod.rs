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

/// Halt the CPU until the next interrupt
#[inline]
pub fn halt() {
    x86_64::instructions::hlt();
}
