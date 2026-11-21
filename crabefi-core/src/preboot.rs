//! The trusted pre-boot phase.
//!
//! Until CrabEFI first runs code it does not own (an EFI image of any type,
//! a Linux kernel, a chainloaded payload), only firmware code has seen user
//! input, volume keys and TPM secrets. [`end`] closes that phase before such
//! code runs:
//!
//! - with `luks` and a TPM, it measures `EV_SEPARATOR` into each of PCRs
//!   0-7 that has none yet, so a TPM secret sealed to pre-boot PCR values
//!   cannot be unsealed again, by anything. Builds without `luks` keep the
//!   TCG ordering: separators at the first application's ReadyToBoot;
//! - it wipes volume keys and the unused stack (`luks` builds also clear
//!   every heap block when it is freed);
//! - it latches: CrabEFI never again asks for a passphrase or uses a TPM
//!   secret in this boot, because code it does not own may have changed the
//!   firmware since (a keylogger, for one).
//!
//! Every path that transfers control calls [`end`] first and must not
//! continue if it returns false. So code that is not CrabEFI's never runs
//! with pre-boot PCR values, and ReadyToBoot callbacks signalled before
//! [`end`] can only be the firmware's own.

use core::sync::atomic::{AtomicBool, Ordering};

static ENDED: AtomicBool = AtomicBool::new(false);
/// [`end`] refused a transfer in this boot.
static REFUSED: AtomicBool = AtomicBool::new(false);
/// Native boot: no UEFI services.
static NATIVE: AtomicBool = AtomicBool::new(false);

/// Record that this boot runs without UEFI services.
pub(crate) fn set_native() {
    NATIVE.store(true, Ordering::SeqCst);
}

/// Whether this boot runs without UEFI services.
pub(crate) fn is_native() -> bool {
    NATIVE.load(Ordering::SeqCst)
}

/// Whether code CrabEFI does not own may have run in this boot.
#[cfg_attr(not(all(feature = "luks", target_arch = "x86_64")), allow(dead_code))]
pub(crate) fn has_ended() -> bool {
    ENDED.load(Ordering::SeqCst)
}

/// Whether [`end`] refused to let the next stage run in this boot. The
/// refusal is final for the boot: only a restart helps.
pub(crate) fn refused() -> bool {
    REFUSED.load(Ordering::SeqCst)
}

/// Close the trusted phase before running code CrabEFI does not own.
///
/// Returns false if that code must not run: a TPM 2.0 is present, or was
/// described but did not come up, and did not record every separator, so
/// it may still hold firmware-only PCR values for the next stage.
#[must_use]
pub(crate) fn end() -> bool {
    if !ENDED.swap(true, Ordering::SeqCst) {
        log::info!("Ending the trusted pre-boot phase");
        #[cfg(all(feature = "luks", feature = "tpm", target_arch = "x86_64"))]
        crate::efi::tcg::measured_boot::measure_pre_os_separators();
        dispose_secrets();
        #[cfg(all(feature = "luks-test-post-cap", target_arch = "x86_64"))]
        crate::luks::check_refused_after_cap();
    }
    // Builds that unseal firmware-only secrets must never pass a TPM on in
    // its pre-boot state, whether or not this boot used a secret: the sealed
    // objects are on the disk for anyone to load.
    #[cfg(all(feature = "luks", feature = "tpm", target_arch = "x86_64"))]
    {
        use crate::efi::tcg::measured_boot as mb;
        if !may_hand_off(
            crate::efi::protocols::tcg2::has_hardware_tpm(),
            mb::hardware_tpm_expected(),
            mb::separators_recorded(mb::ALL_SEPARATORS),
        ) {
            if !REFUSED.swap(true, Ordering::SeqCst) {
                log::error!(
                    "The TPM did not record the pre-OS separators; not starting the next stage"
                );
            }
            return false;
        }
    }
    true
}

/// Whether the next stage may run: without a TPM there is no PCR state to
/// protect. A TPM that is up, or was described but failed to come up, must
/// have recorded every separator.
#[cfg_attr(
    not(all(feature = "luks", feature = "tpm", target_arch = "x86_64")),
    allow(dead_code)
)]
fn may_hand_off(tpm_up: bool, tpm_described: bool, separators_recorded: bool) -> bool {
    !(tpm_up || tpm_described) || separators_recorded
}

#[cfg(test)]
mod tests {
    use super::may_hand_off;

    #[test]
    fn described_tpms_fail_closed_and_absent_ones_do_not() {
        assert!(may_hand_off(false, false, false));
        assert!(!may_hand_off(false, true, false));
        assert!(!may_hand_off(true, true, false));
        assert!(may_hand_off(true, true, true));
    }
}

/// Wipe what the firmware holds in secret: volume keys and the unused
/// stack. Also before a reset or a halt, where nothing else runs.
pub(crate) fn dispose_secrets() {
    #[cfg(all(feature = "luks", target_arch = "x86_64"))]
    {
        crate::luks::wipe_keys();
        #[cfg(feature = "platform-entry")]
        crate::arch::x86_64::scrub_unused_stack();
    }
}

/// Wipe volume keys on a fatal error (panic, CPU exception), without
/// allocating or waiting on locks. Best effort: data the fatal error
/// interrupted, such as a loaded initrd, stays in memory.
pub fn emergency_wipe() {
    #[cfg(all(feature = "luks", target_arch = "x86_64"))]
    {
        crate::luks::emergency_wipe();
        #[cfg(feature = "platform-entry")]
        crate::arch::x86_64::scrub_unused_stack();
    }
}
