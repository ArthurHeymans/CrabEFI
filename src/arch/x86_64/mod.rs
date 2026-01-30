//! x86_64 architecture support
//!
//! This module contains code specific to the x86_64 architecture,
//! including the 32-bit to 64-bit mode transition and page table setup.

pub mod cache;
pub mod entry;
pub mod idt;
pub mod io;
pub mod paging;
pub mod port_regs;
pub mod sse;

/// CPU feature flags
pub struct CpuFeatures {
    /// SSE support
    pub sse: bool,
    /// SSE2 support
    pub sse2: bool,
    /// Long mode (64-bit) support
    pub long_mode: bool,
    /// NX (No-Execute) bit support
    pub nx: bool,
    /// 1GB pages support
    pub page_1gb: bool,
}

impl CpuFeatures {
    /// Detect CPU features using CPUID
    pub fn detect() -> Self {
        let mut features = CpuFeatures {
            sse: false,
            sse2: false,
            long_mode: false,
            nx: false,
            page_1gb: false,
        };

        unsafe {
            // Check for CPUID support (assume present on 64-bit)
            // CPUID function 1: processor info and feature bits
            let result: u32;
            core::arch::asm!(
                "push rbx",
                "mov eax, 1",
                "cpuid",
                "pop rbx",
                out("edx") result,
                out("eax") _,
                out("ecx") _,
                options(preserves_flags),
            );

            features.sse = (result & (1 << 25)) != 0;
            features.sse2 = (result & (1 << 26)) != 0;

            // CPUID function 0x80000001: extended processor info
            let extended: u32;
            core::arch::asm!(
                "push rbx",
                "mov eax, 0x80000001",
                "cpuid",
                "pop rbx",
                out("edx") extended,
                out("eax") _,
                out("ecx") _,
                options(preserves_flags),
            );

            features.long_mode = (extended & (1 << 29)) != 0;
            features.nx = (extended & (1 << 20)) != 0;
            features.page_1gb = (extended & (1 << 26)) != 0;
        }

        features
    }
}

/// Halt the CPU
#[inline]
pub fn halt() {
    unsafe {
        core::arch::asm!("hlt");
    }
}

/// Disable interrupts
#[inline]
pub fn cli() {
    unsafe {
        core::arch::asm!("cli");
    }
}

/// Enable interrupts
#[inline]
pub fn sti() {
    unsafe {
        core::arch::asm!("sti");
    }
}

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

/// Read the CR0 register
#[inline]
pub fn read_cr0() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) value);
    }
    value
}

/// Write to the CR0 register
///
/// # Safety
///
/// The caller must ensure that `value` represents valid CR0 control bits.
/// Invalid values can cause undefined behavior or system crashes.
#[inline]
pub unsafe fn write_cr0(value: u64) {
    core::arch::asm!("mov cr0, {}", in(reg) value);
}

/// Read the CR4 register
#[inline]
pub fn read_cr4() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) value);
    }
    value
}

/// Write to the CR4 register
///
/// # Safety
///
/// The caller must ensure that `value` represents valid CR4 control bits.
/// Invalid values can cause undefined behavior or system crashes.
#[inline]
pub unsafe fn write_cr4(value: u64) {
    core::arch::asm!("mov cr4, {}", in(reg) value);
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
