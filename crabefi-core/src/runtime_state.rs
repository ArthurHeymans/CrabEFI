//! Boot-to-runtime state handoff
//!
//! The pointer-free storage and relocation machinery live in the restricted
//! `crabefi-runtime` leaf crate. This wrapper only copies boot variable entries
//! into that state at ExitBootServices.

pub use crabefi_runtime::{
    BLOB_ARENA_SIZE, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN, MAX_VARIABLES, RuntimeState,
    RuntimeStateError, RuntimeVariable, VamSafe, current_address, init, physical_address, relocate,
    with, with_mut,
};

/// Freeze boot variables into pointer-free runtime storage.
///
/// Variables that cannot fit are logged and skipped. Aborting
/// `ExitBootServices` would not give the caller a useful recovery path and
/// would prevent the machine from booting because of one oversized cache entry.
pub fn freeze_from_boot_state() {
    let efi = crate::state::efi();
    crabefi_runtime::with_mut(|runtime| {
        runtime.reset(efi.setup_mode, efi.secure_boot_enabled);
        for variable in efi.variables.iter().filter(|variable| {
            variable.in_use
                && (variable.attributes & crate::efi::auth::attributes::RUNTIME_ACCESS) != 0
        }) {
            let Some(terminator) = variable.name.iter().position(|&unit| unit == 0) else {
                log::warn!(
                    "Skipping unterminated runtime variable during freeze: guid={:?}",
                    variable.vendor_guid
                );
                continue;
            };
            let name = &variable.name[..=terminator];
            match runtime.set_variable(
                variable.vendor_guid,
                name,
                variable.attributes,
                &variable.data[..variable.data_size],
            ) {
                Ok(dropped) if dropped != 0 => log::error!(
                    "Runtime variable compaction dropped {} corrupt entries during freeze",
                    dropped
                ),
                Ok(_) => {}
                Err(error) => log::warn!(
                    "Skipping runtime variable during freeze: guid={:?} name={:?} error={:?}",
                    variable.vendor_guid,
                    name,
                    error
                ),
            }
        }
    });
}
