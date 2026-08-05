//! AArch64 PL031 time and PSCI reset mechanisms.

use crabefi_runtime_abi::{RuntimeResetConfig, RuntimeTimeConfig, reset_mechanism, time_mechanism};

use crate::efi;

pub fn read_time(config: RuntimeTimeConfig, out: &mut efi::Time) -> Result<(), efi::Status> {
    if config.mechanism != time_mechanism::PL031 || config.io_or_mmio_base == 0 {
        return Err(efi::Status::UNSUPPORTED);
    }
    // SAFETY: initialization accepts PL031 only with a declared retained MMIO
    // range, and the data register is a readable 32-bit register at offset 0.
    let seconds = unsafe { (config.io_or_mmio_base as *const u32).read_volatile() };
    crate::services::time_from_unix(u64::from(seconds), out)
}

pub fn reset(config: RuntimeResetConfig, reset_type: efi::ResetType) -> ! {
    let function = if reset_type == efi::RESET_SHUTDOWN {
        0x8400_0008u64
    } else {
        0x8400_0009u64
    };
    match config.mechanism {
        reset_mechanism::PSCI_SMC => {
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
        reset_mechanism::PSCI_HVC => {
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
