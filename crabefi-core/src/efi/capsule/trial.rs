//! Trial boots of a freshly activated A/B firmware slot.
//!
//! After a capsule activated the inactive slot, boots of that slot are trials
//! until the OS confirms one by writing `CrabEFIFirmwareConfirm`; the volatile
//! `CrabEFIFirmwareTrialPending` tells the OS that a trial is running. Without
//! a confirmation after [`MAX_ATTEMPTS`] boots the previous slot is activated
//! again. The flash is writable only in a capsule-update boot, so the rollback
//! requests one and resets; that boot rolls back before any capsule is read.

use alloc::vec::Vec;
use r_efi::efi::Status;

use super::disk;
use super::result::{self, CapsuleResultStatus};
use crate::efi::runtime_image::client::variables;
use crate::logger::CRABEFI_SETTINGS_GUID;
use crate::platform::{CapsuleBackend, StorageError};

/// Unconfirmed boots of the new slot before the previous one boots again.
pub const MAX_ATTEMPTS: u8 = 3;

const TRIAL: &str = "CrabEFIFirmwareTrial";
const CONFIRM: &str = "CrabEFIFirmwareConfirm";
const PENDING: &str = "CrabEFIFirmwareTrialPending";
const NON_VOLATILE: u32 = 0x1;
const BOOT_SERVICE_ACCESS: u32 = 0x2;
const RUNTIME_ACCESS: u32 = 0x4;
/// No runtime access: the OS can neither read nor forge the trial state.
const TRIAL_ATTRIBUTES: u32 = NON_VOLATILE | BOOT_SERVICE_ACCESS;
const FORMAT: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Trial {
    attempts: u8,
    rollback: bool,
    version: u32,
    slot: heapless::String<32>,
}

fn name(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

fn encode(trial: &Trial) -> Vec<u8> {
    let mut data = alloc::vec![
        FORMAT,
        trial.attempts,
        u8::from(trial.rollback),
        trial.slot.len() as u8,
    ];
    data.extend_from_slice(&trial.version.to_le_bytes());
    data.extend_from_slice(trial.slot.as_bytes());
    data
}

fn decode(data: &[u8]) -> Option<Trial> {
    if data.len() < 8 || data[0] != FORMAT {
        return None;
    }
    let slot = core::str::from_utf8(data.get(8..8 + usize::from(data[3]))?).ok()?;
    let mut name = heapless::String::new();
    name.push_str(slot).ok()?;
    Some(Trial {
        attempts: data[1],
        rollback: data[2] != 0,
        version: u32::from_le_bytes(data[4..8].try_into().ok()?),
        slot: name,
    })
}

fn load() -> Option<Trial> {
    variables::get(&CRABEFI_SETTINGS_GUID, &name(TRIAL))
        .filter(|(attributes, _)| *attributes == TRIAL_ATTRIBUTES)
        .and_then(|(_, data)| decode(&data))
}

fn store(trial: &Trial) -> bool {
    variables::set(
        &CRABEFI_SETTINGS_GUID,
        &name(TRIAL),
        TRIAL_ATTRIBUTES,
        &encode(trial),
    ) == Status::SUCCESS
}

fn finish() {
    let _ = variables::delete(&CRABEFI_SETTINGS_GUID, &name(TRIAL));
    let _ = variables::delete(&CRABEFI_SETTINGS_GUID, &name(CONFIRM));
}

fn failed(trial: &Trial) {
    result::record_last_attempt(trial.version, CapsuleResultStatus::Error);
    finish();
}

/// An activated slot waits for its confirmation.
pub fn pending() -> bool {
    load().is_some()
}

/// Start the trial of `slot`, just activated with firmware `version`.
pub fn start(slot: &str, version: u32) -> bool {
    // A confirmation left from an earlier update must not count.
    let _ = variables::delete(&CRABEFI_SETTINGS_GUID, &name(CONFIRM));
    let mut name = heapless::String::new();
    name.push_str(slot).is_ok()
        && store(&Trial {
            attempts: 0,
            rollback: false,
            version,
            slot: name,
        })
}

/// Count this boot of a trial slot, finish a confirmed or failed trial, or
/// roll back. Returns `true` if the system must reset now.
pub fn check(backend: &mut dyn CapsuleBackend) -> bool {
    let Some(mut trial) = load() else {
        return false;
    };
    let Some(slots) = backend.firmware_slots() else {
        log::warn!("Dropping the firmware trial: no A/B slots");
        finish();
        return false;
    };
    if variables::get(&CRABEFI_SETTINGS_GUID, &name(CONFIRM)).is_some() {
        log::info!(
            "Firmware {} in slot '{}' confirmed",
            trial.version,
            trial.slot
        );
        finish();
        return false;
    }
    if slots.running != trial.slot {
        log::error!(
            "Firmware {} in slot '{}' did not boot; running '{}'",
            trial.version,
            trial.slot,
            slots.running
        );
        failed(&trial);
        return false;
    }
    if trial.rollback || trial.attempts >= MAX_ATTEMPTS {
        return match backend.activate_slot(slots.inactive.as_str()) {
            Ok(()) => {
                log::warn!(
                    "Firmware {} not confirmed after {} boots: slot '{}' boots again",
                    trial.version,
                    trial.attempts,
                    slots.inactive
                );
                failed(&trial);
                disk::clear_os_indications_capsule_bits();
                true
            }
            Err(StorageError::WriteProtected) if !trial.rollback => {
                // Only a capsule-update boot may write the slot headers.
                trial.rollback = true;
                if store(&trial) && disk::request_file_capsule_delivery() {
                    log::warn!(
                        "Firmware {} not confirmed after {} boots: rolling back",
                        trial.version,
                        trial.attempts
                    );
                    true
                } else {
                    log::error!("Cannot request the rollback boot");
                    false
                }
            }
            Err(error) => {
                log::error!(
                    "Rolling back to slot '{}' failed: {:?}",
                    slots.inactive,
                    error
                );
                failed(&trial);
                disk::clear_os_indications_capsule_bits();
                false
            }
        };
    }
    trial.attempts += 1;
    if store(&trial) {
        log::info!(
            "Trial boot {} of {} of firmware {} in slot '{}'",
            trial.attempts,
            MAX_ATTEMPTS,
            trial.version,
            trial.slot
        );
    }
    crate::efi::varstore::import_variable_into_runtime(
        &CRABEFI_SETTINGS_GUID,
        &name(PENDING),
        BOOT_SERVICE_ACCESS | RUNTIME_ACCESS,
        &[1],
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trial_record_round_trips() {
        let mut slot = heapless::String::new();
        slot.push_str("RECOVERY_B").unwrap();
        let trial = Trial {
            attempts: 2,
            rollback: true,
            version: 0x0102_0304,
            slot,
        };
        assert_eq!(decode(&encode(&trial)), Some(trial.clone()));
        let mut truncated = encode(&trial);
        truncated.pop();
        assert_eq!(decode(&truncated), None);
        let mut other_format = encode(&trial);
        other_format[0] = 2;
        assert_eq!(decode(&other_format), None);
    }
}
