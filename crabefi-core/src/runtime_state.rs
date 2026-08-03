//! Boot-to-runtime state handoff
//!
//! The pointer-free storage and relocation machinery live in the restricted
//! `crabefi-runtime` leaf crate. This wrapper only copies boot variable entries
//! into that state at ExitBootServices.

pub use crabefi_runtime::{
    BLOB_ARENA_SIZE, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN, MAX_VARIABLES, RuntimeState,
    RuntimeStateError, RuntimeVariable, SecureBootStatus, VamSafe, commit_virtual_mode,
    current_address, init, is_virtual_mode, physical_address, relocate, with, with_mut,
};

/// Validate that every runtime-visible boot variable fits the runtime snapshot.
///
/// This runs after the final ExitBootServices callbacks and before locking the
/// allocator. A failure leaves the map key valid, so the caller can retry the
/// transition instead of losing a variable silently.
pub fn validate_boot_state() -> Result<(), RuntimeStateError> {
    let efi = crate::state::efi();
    let mut count = 0usize;
    let mut bytes = 0usize;

    for variable in efi.variables.iter().filter(|variable| {
        variable.in_use && (variable.attributes & crate::efi::auth::attributes::RUNTIME_ACCESS) != 0
    }) {
        count += 1;
        if variable.name.iter().position(|&unit| unit == 0).is_none()
            || variable.data_size > MAX_VARIABLE_DATA_SIZE
        {
            return Err(RuntimeStateError::InvalidSize);
        }
        bytes = bytes
            .checked_add(variable.data_size)
            .ok_or(RuntimeStateError::OutOfResources)?;
    }

    if count > MAX_VARIABLES || bytes > BLOB_ARENA_SIZE {
        return Err(RuntimeStateError::OutOfResources);
    }
    Ok(())
}

/// Freeze boot variables into pointer-free runtime storage.
///
/// `validate_boot_state` must have succeeded after the final
/// ExitBootServices callbacks. The fixed-capacity invariant means this cannot
/// drop a valid variable; unexpected inconsistencies are returned to the
/// caller rather than logged and ignored.
pub fn freeze_from_boot_state(boot: &crate::phase::BootCtx<'_>) -> Result<(), RuntimeStateError> {
    let efi = crate::state::efi();
    let secure_boot = crate::state::boot_secure_boot_status(boot);
    crabefi_runtime::with_mut(|runtime| {
        runtime.reset(boot, secure_boot);
        for variable in efi.variables.iter().filter(|variable| {
            variable.in_use
                && (variable.attributes & crate::efi::auth::attributes::RUNTIME_ACCESS) != 0
        }) {
            let terminator = variable
                .name
                .iter()
                .position(|&unit| unit == 0)
                .ok_or(RuntimeStateError::InvalidSize)?;
            let name = &variable.name[..=terminator];
            let timestamp = if variable.auth_timestamp != [0; 16] {
                Some(variable.auth_timestamp)
            } else {
                crate::efi::auth::identify_key_database(name, &variable.vendor_guid)
                    .map(crate::efi::auth::database_timestamp)
                    .map(|timestamp| {
                        let mut bytes = [0; 16];
                        bytes.copy_from_slice(zerocopy::IntoBytes::as_bytes(&timestamp));
                        bytes
                    })
            };
            let dropped = runtime.set_variable(
                variable.vendor_guid,
                name,
                variable.attributes,
                &variable.data[..variable.data_size],
                timestamp,
            )?;
            if dropped != 0 {
                return Err(RuntimeStateError::OutOfResources);
            }
        }
        for replay in efi.auth_replay.iter().filter(|entry| entry.in_use) {
            let terminator = replay
                .name
                .iter()
                .position(|&unit| unit == 0)
                .ok_or(RuntimeStateError::InvalidSize)?;
            runtime.record_auth_timestamp(
                replay.vendor_guid,
                &replay.name[..=terminator],
                replay.timestamp,
            )?;
        }
        Ok(())
    })
}
