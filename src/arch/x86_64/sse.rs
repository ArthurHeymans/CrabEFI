//! SSE/SIMD support for x86_64
//!
//! Rust requires SSE2 support for the x86_64 target. This module
//! provides utilities for enabling and checking SSE support.

/// Enable SSE/SSE2 support
///
/// This is already done in the assembly entry code, but this function
/// can be used to verify the state.
pub fn enable() {
    unsafe {
        // Clear CR0.EM (bit 2) - disable x87 emulation
        // Set CR0.MP (bit 1) - enable monitor coprocessor
        let mut cr0: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0);
        cr0 &= !(1 << 2); // Clear EM
        cr0 |= 1 << 1; // Set MP
        core::arch::asm!("mov cr0, {}", in(reg) cr0);

        // Set CR4.OSFXSR (bit 9) - enable SSE
        // Set CR4.OSXMMEXCPT (bit 10) - enable SSE exceptions
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4);
        cr4 |= 1 << 9; // OSFXSR
        cr4 |= 1 << 10; // OSXMMEXCPT
        core::arch::asm!("mov cr4, {}", in(reg) cr4);
    }
}

/// Check if SSE is enabled
pub fn is_enabled() -> bool {
    let cr4: u64;
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4);
    }
    // Check OSFXSR bit
    (cr4 & (1 << 9)) != 0
}

/// Check if the CPU supports SSE
pub fn cpu_supports_sse() -> bool {
    let edx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("edx") edx,
            out("eax") _,
            out("ecx") _,
            options(preserves_flags),
        );
    }
    // SSE is bit 25 of EDX
    (edx & (1 << 25)) != 0
}

/// Check if the CPU supports SSE2
pub fn cpu_supports_sse2() -> bool {
    let edx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("edx") edx,
            out("eax") _,
            out("ecx") _,
            options(preserves_flags),
        );
    }
    // SSE2 is bit 26 of EDX
    (edx & (1 << 26)) != 0
}
