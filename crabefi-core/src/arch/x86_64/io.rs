//! x86_64 I/O Port Access
//!
//! This module preserves CrabEFI's port-I/O interface while delegating the
//! instructions to the rust-osdev `x86_64` crate.

use x86_64::instructions::port::{PortReadOnly, PortWriteOnly};

/// Read a byte from an I/O port
///
/// # Safety
///
/// Port I/O can have side effects on hardware. The caller must ensure
/// the port address is valid and appropriate for the intended operation.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    // SAFETY: The caller guarantees that reading this port is valid.
    unsafe { PortReadOnly::<u8>::new(port).read() }
}

/// Write a byte to an I/O port
///
/// # Safety
///
/// Port I/O can have side effects on hardware. The caller must ensure
/// the port address is valid and appropriate for the intended operation.
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: The caller guarantees that writing this port is valid.
    unsafe { PortWriteOnly::<u8>::new(port).write(value) }
}

/// Read a word (16-bit) from an I/O port
///
/// # Safety
///
/// Port I/O can have side effects on hardware. The caller must ensure
/// the port address is valid and appropriate for the intended operation.
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    // SAFETY: The caller guarantees that reading this port is valid.
    unsafe { PortReadOnly::<u16>::new(port).read() }
}

/// Write a word (16-bit) to an I/O port
///
/// # Safety
///
/// Port I/O can have side effects on hardware. The caller must ensure
/// the port address is valid and appropriate for the intended operation.
#[inline]
pub unsafe fn outw(port: u16, value: u16) {
    // SAFETY: The caller guarantees that writing this port is valid.
    unsafe { PortWriteOnly::<u16>::new(port).write(value) }
}

/// Read a dword (32-bit) from an I/O port
///
/// # Safety
///
/// Port I/O can have side effects on hardware. The caller must ensure
/// the port address is valid and appropriate for the intended operation.
#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    // SAFETY: The caller guarantees that reading this port is valid.
    unsafe { PortReadOnly::<u32>::new(port).read() }
}

/// Write a dword (32-bit) to an I/O port
///
/// # Safety
///
/// Port I/O can have side effects on hardware. The caller must ensure
/// the port address is valid and appropriate for the intended operation.
#[inline]
pub unsafe fn outl(port: u16, value: u32) {
    // SAFETY: The caller guarantees that writing this port is valid.
    unsafe { PortWriteOnly::<u32>::new(port).write(value) }
}
