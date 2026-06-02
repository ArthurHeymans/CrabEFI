//! RISC-V System Reset
//!
//! Uses the SBI System Reset extension (SRST, EID 0x53525354) to
//! request shutdown or reboot from OpenSBI / M-mode firmware.

use super::sbi;

/// Perform a cold reboot via SBI SRST.
pub fn system_reset() -> ! {
    sbi::sbi_system_reset(sbi::SRST_COLD_REBOOT, sbi::SRST_REASON_NONE);

    // If SBI SRST didn't work, loop forever.
    loop {
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Perform a system shutdown via SBI SRST.
pub fn system_off() -> ! {
    sbi::sbi_system_reset(sbi::SRST_SHUTDOWN, sbi::SRST_REASON_NONE);

    loop {
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Attempt a reset (API compatibility with x86/aarch64).
pub fn keyboard_controller_reset() {
    sbi::sbi_system_reset(sbi::SRST_COLD_REBOOT, sbi::SRST_REASON_NONE);
}

/// Force a system reset (equivalent to x86 triple fault / aarch64 PSCI).
pub fn triple_fault() -> ! {
    system_reset()
}
