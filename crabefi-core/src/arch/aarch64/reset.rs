//! AArch64 System Reset
//!
//! On SBSA platforms, system reset is performed via PSCI (Power State
//! Coordination Interface). TF-A handles the PSCI call at EL3.
//!
//! PSCI function IDs (from PSCI specification):
//!   - SYSTEM_RESET: 0x8400_0009 (SMC32) / 0xC400_0009 (SMC64)
//!   - SYSTEM_OFF:   0x8400_0008 (SMC32) / 0xC400_0008 (SMC64)

/// PSCI SYSTEM_RESET function ID (SMC32 calling convention)
const PSCI_SYSTEM_RESET: u32 = 0x8400_0009;

/// PSCI SYSTEM_OFF function ID (SMC32 calling convention)
const PSCI_SYSTEM_OFF: u32 = 0x8400_0008;

/// Perform a system reset via PSCI
///
/// Issues an HVC (Hypervisor Call) to request a system reset.
/// On QEMU SBSA, coreboot runs at EL2, so we use HVC to reach
/// TF-A's PSCI handler at EL3. If HVC doesn't work (e.g., because
/// PSCI is exposed via SMC conduit), fall back to SMC.
///
/// This function should not return.
pub fn system_reset() -> ! {
    // Try HVC first (coreboot on SBSA runs at EL2)
    unsafe {
        core::arch::asm!(
            "mov w0, {func_id:w}",
            "hvc #0",
            func_id = in(reg) PSCI_SYSTEM_RESET,
            options(nomem, nostack)
        );
    }

    // If HVC didn't work, try SMC
    unsafe {
        core::arch::asm!(
            "mov w0, {func_id:w}",
            "smc #0",
            func_id = in(reg) PSCI_SYSTEM_RESET,
            options(nomem, nostack)
        );
    }

    // If neither worked, halt
    loop {
        unsafe {
            core::arch::asm!("wfe", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Attempt system reset via keyboard controller
///
/// On aarch64 this is a no-op; the equivalent is PSCI system_reset.
/// Provided for API compatibility with x86.
pub fn keyboard_controller_reset() {
    // PSCI system_reset is the aarch64 equivalent
    unsafe {
        core::arch::asm!(
            "mov w0, {func_id:w}",
            "hvc #0",
            func_id = in(reg) PSCI_SYSTEM_RESET,
            options(nomem, nostack)
        );
    }
}

/// Force a system reset (equivalent to x86 triple fault)
///
/// On aarch64, uses PSCI to reset. This should not return.
pub fn triple_fault() -> ! {
    system_reset()
}

/// Perform a system shutdown via PSCI
///
/// Issues an HVC/SMC to request system power off.
pub fn system_off() -> ! {
    unsafe {
        core::arch::asm!(
            "mov w0, {func_id:w}",
            "hvc #0",
            func_id = in(reg) PSCI_SYSTEM_OFF,
            options(nomem, nostack)
        );
    }

    unsafe {
        core::arch::asm!(
            "mov w0, {func_id:w}",
            "smc #0",
            func_id = in(reg) PSCI_SYSTEM_OFF,
            options(nomem, nostack)
        );
    }

    loop {
        unsafe {
            core::arch::asm!("wfe", options(nomem, nostack, preserves_flags));
        }
    }
}
