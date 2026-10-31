//! Explicit fstart Secure-EL1 to Non-Secure-EL1 transition.
//!
//! This is a platform-specific service, NOT part of PSCI. Generic
//! ExitBootServices must never invoke it based on PSCI_VERSION: ordinary
//! TF-A can report the same version and coreboot already enters NS-EL2.
//! A platform owning the matching EL3 handler may request the transition
//! explicitly from its own handoff hook.

/// RAM template for fstart's vendor-specific SMCCC function 0xC200_0000.
const TRAMPOLINE_CODE: [u32; 5] = [
    0xA9BF_7FFE, // stp x30, xzr, [sp, #-16]!
    0xD2B8_4000, // mov x0, #0xC200, lsl #16
    0xD400_0003, // smc #0
    0xA8C1_7FFE, // ldp x30, xzr, [sp], #16
    0xD65F_03C0, // ret
];

#[cfg(target_arch = "aarch64")]
static TRAMPOLINE_BUF: crate::cell::StaticMut<[u32; 5]> = crate::cell::StaticMut::new([0; 5]);

/// Request the fstart-specific transition, only with a known matching EL3 ABI.
///
/// Returns without issuing an SMC outside EL1. There is intentionally no
/// PSCI_VERSION probe: it cannot identify the vendor handler or security state.
///
/// # Safety
/// The caller must own/verify the fstart EL3 service for 0xC200_0000 and run
/// at Secure EL1. The buffer, stack, caller and continuation must remain
/// accessible/executable after the security-state change. The handler must
/// preserve AAPCS64 callee-saved registers and execution must be exclusive.
/// Ordinary coreboot/TF-A platforms must NOT call this helper.
#[cfg(target_arch = "aarch64")]
pub unsafe fn install_ns_trampoline() {
    let current_el: u64;
    // SAFETY: read-only architectural register at the current EL.
    unsafe {
        core::arch::asm!("mrs {}, CurrentEL", out(reg) current_el,
            options(nomem, nostack, preserves_flags));
    }
    if current_el != 4 {
        return;
    }

    // SAFETY: caller provides exclusive execution and guarantees this RAM and
    // continuation are accessible on both sides of the platform transition.
    unsafe {
        let buf = TRAMPOLINE_BUF.get().cast::<u32>();
        for (index, instruction) in TRAMPOLINE_CODE.iter().copied().enumerate() {
            core::ptr::write_volatile(buf.add(index), instruction);
        }
        super::cache::sync_instruction_cache(buf as u64, core::mem::size_of_val(&TRAMPOLINE_CODE));
        // A real ABI call accounts for LR/caller-saved registers, memory and
        // stack effects. The old inline BLR incorrectly claimed nomem/nostack
        // and did not declare LR as clobbered.
        let trampoline: unsafe extern "C" fn() = core::mem::transmute(buf);
        trampoline();
    }
}

#[cfg(test)]
mod tests {
    use super::TRAMPOLINE_CODE;

    #[test]
    fn stack_pairs_use_distinct_lr_and_zero_registers() {
        for index in [0, 3] {
            let instruction = TRAMPOLINE_CODE[index];
            assert_eq!(instruction & 31, 30); // Rt = LR
            assert_eq!((instruction >> 10) & 31, 31); // Rt2 = XZR, not LR
            assert_eq!((instruction >> 5) & 31, 31); // Rn = SP
        }
        assert_eq!((TRAMPOLINE_CODE[0] >> 15) & 127, 126); // -16, scaled by 8
        assert_eq!((TRAMPOLINE_CODE[3] >> 15) & 127, 2); // +16
    }

    #[test]
    fn smc_id_is_in_the_documented_vendor_range() {
        let movz = TRAMPOLINE_CODE[1];
        let immediate = u64::from((movz >> 5) & 0xffff);
        let shift = ((movz >> 21) & 3) * 16;
        assert_eq!(immediate << shift, 0xc200_0000);
    }

    #[test]
    fn template_uses_smc_and_returns_through_lr() {
        assert_eq!(TRAMPOLINE_CODE[2], 0xd400_0003);
        assert_eq!(TRAMPOLINE_CODE[4], 0xd65f_03c0);
    }
}
