//! AArch64 PL031 time and PSCI reset mechanisms.

use crabefi_runtime_abi::{ResetMechanism, TimeMechanism};

use crate::{
    efi,
    state::{ResetConfig, TimeConfig},
};

pub fn read_time(config: TimeConfig, out: &mut efi::Time) -> Result<(), efi::Status> {
    if config.mechanism != TimeMechanism::Pl031 || config.base == 0 {
        return Err(efi::Status::UNSUPPORTED);
    }
    // SAFETY: initialization accepts PL031 only with a declared retained MMIO
    // range, and the data register is a readable 32-bit register at offset 0.
    let seconds = unsafe { (config.base as *const u32).read_volatile() };
    crate::services::time_from_unix(u64::from(seconds), out)
}

pub fn reset(config: Option<ResetConfig>, reset_type: efi::ResetType) -> ! {
    let function = if reset_type == efi::RESET_SHUTDOWN {
        0x8400_0008u64
    } else {
        0x8400_0009u64
    };
    match config.map(|config| config.mechanism) {
        Some(ResetMechanism::PsciSmc) => {
            // SAFETY: PSCI conduit and function IDs are value-only platform
            // configuration; this call has no memory operands.
            unsafe {
                core::arch::asm!(
                    "smc #0",
                    inlateout("x0") function => _,
                    clobber_abi("C"),
                    options(nostack)
                )
            };
        }
        Some(ResetMechanism::PsciHvc) => {
            // SAFETY: same contract as the SMC conduit above.
            unsafe {
                core::arch::asm!(
                    "hvc #0",
                    inlateout("x0") function => _,
                    clobber_abi("C"),
                    options(nostack)
                )
            };
        }
        _ => {}
    }
    loop {
        // SAFETY: terminal fallback after ResetSystem.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}
