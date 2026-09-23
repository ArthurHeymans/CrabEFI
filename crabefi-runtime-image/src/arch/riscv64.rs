//! RISC-V goldfish RTC and SBI SRST mechanisms.

use crabefi_runtime_abi::{ResetMechanism, TimeMechanism};

use crate::{
    efi,
    state::{ResetConfig, TimeConfig},
};

pub fn read_time(config: TimeConfig, out: &mut efi::Time) -> Result<(), efi::Status> {
    if config.mechanism != TimeMechanism::GoldfishRtc || config.base == 0 {
        return Err(efi::Status::UNSUPPORTED);
    }
    let base = config.base as *const u32;
    // SAFETY: initialization accepts this mechanism only with its MMIO page in
    // the retained external-range manifest. Reading low latches high.
    let (low, high) = unsafe { (base.read_volatile(), base.add(1).read_volatile()) };
    let nanoseconds = (u64::from(high) << 32) | u64::from(low);
    crate::services::time_from_unix(nanoseconds / 1_000_000_000, out)
}

pub fn reset(config: Option<ResetConfig>, reset_type: efi::ResetType) -> ! {
    if config.is_some_and(|config| config.mechanism == ResetMechanism::SbiSrst) {
        let sbi_type = match reset_type {
            efi::RESET_SHUTDOWN => 0usize,
            efi::RESET_WARM => 2usize,
            _ => 1usize,
        };
        // SAFETY: SBI SRST uses only register arguments and has no borrowed
        // memory. OpenSBI owns the implementation beyond this image boundary.
        unsafe {
            core::arch::asm!(
                "ecall",
                inlateout("a0") sbi_type => _,
                inlateout("a1") 0usize => _,
                in("a6") 0usize,
                in("a7") 0x5352_5354usize,
                options(nostack)
            )
        };
    }
    loop {
        // SAFETY: terminal fallback after ResetSystem.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}
