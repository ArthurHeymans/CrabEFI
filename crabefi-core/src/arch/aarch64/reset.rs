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

/// Request a PSCI operation through the monitor at EL3.
///
/// At EL2, HVC does not reach EL3 and can take an undefined-instruction
/// exception, so it cannot be used to probe for a conduit. Use SMC directly
/// there. Retain the existing HVC-first path for EL1 under a hypervisor.
fn psci_request(function: u32) {
    let current_el: u64;
    unsafe {
        core::arch::asm!("mrs {}, CurrentEL", out(reg) current_el,
            options(nomem, nostack, preserves_flags));
        if current_el == 4 {
            core::arch::asm!(
                "hvc #0",
                inout("x0") u64::from(function) => _,
                clobber_abi("C"),
                options(nostack)
            );
        }
        core::arch::asm!(
            "smc #0",
            inout("x0") u64::from(function) => _,
            clobber_abi("C"),
            options(nostack)
        );
    }
}

/// Perform a system reset via PSCI. This function should not return.
pub fn system_reset() -> ! {
    psci_request(PSCI_SYSTEM_RESET);

    // If neither worked, halt
    loop {
        unsafe {
            core::arch::asm!("wfe", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Attempt system reset via keyboard controller
///
/// On aarch64 this requests PSCI SYSTEM_RESET.
/// Provided for API compatibility with x86.
pub fn keyboard_controller_reset() {
    psci_request(PSCI_SYSTEM_RESET);
}

/// Force a system reset (equivalent to x86 triple fault)
///
/// On aarch64, uses PSCI to reset. This should not return.
pub fn triple_fault() -> ! {
    system_reset()
}

/// Perform a system shutdown via PSCI
///
/// Issues a PSCI request for system power off.
pub fn system_off() -> ! {
    psci_request(PSCI_SYSTEM_OFF);

    loop {
        unsafe {
            core::arch::asm!("wfe", options(nomem, nostack, preserves_flags));
        }
    }
}
