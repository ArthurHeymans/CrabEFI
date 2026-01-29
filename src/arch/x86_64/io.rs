//! x86_64 I/O Port Access
//!
//! This module provides safe wrappers around x86 port I/O instructions.
//! All port I/O in the codebase should use these functions rather than
//! inline assembly directly.

/// Read a byte from an I/O port
///
/// # Safety
///
/// Port I/O can have side effects on hardware. The caller must ensure
/// the port address is valid and appropriate for the intended operation.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") value,
        in("dx") port,
        options(nostack, preserves_flags)
    );
    value
}

/// Write a byte to an I/O port
///
/// # Safety
///
/// Port I/O can have side effects on hardware. The caller must ensure
/// the port address is valid and appropriate for the intended operation.
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nostack, preserves_flags)
    );
}

/// Read a word (16-bit) from an I/O port
///
/// # Safety
///
/// Port I/O can have side effects on hardware. The caller must ensure
/// the port address is valid and appropriate for the intended operation.
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    core::arch::asm!(
        "in ax, dx",
        out("ax") value,
        in("dx") port,
        options(nostack, preserves_flags)
    );
    value
}

/// Write a word (16-bit) to an I/O port
///
/// # Safety
///
/// Port I/O can have side effects on hardware. The caller must ensure
/// the port address is valid and appropriate for the intended operation.
#[inline]
pub unsafe fn outw(port: u16, value: u16) {
    core::arch::asm!(
        "out dx, ax",
        in("dx") port,
        in("ax") value,
        options(nostack, preserves_flags)
    );
}

/// Read a dword (32-bit) from an I/O port
///
/// # Safety
///
/// Port I/O can have side effects on hardware. The caller must ensure
/// the port address is valid and appropriate for the intended operation.
#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    core::arch::asm!(
        "in eax, dx",
        out("eax") value,
        in("dx") port,
        options(nostack, preserves_flags)
    );
    value
}

/// Write a dword (32-bit) to an I/O port
///
/// # Safety
///
/// Port I/O can have side effects on hardware. The caller must ensure
/// the port address is valid and appropriate for the intended operation.
#[inline]
pub unsafe fn outl(port: u16, value: u32) {
    core::arch::asm!(
        "out dx, eax",
        in("dx") port,
        in("eax") value,
        options(nostack, preserves_flags)
    );
}
