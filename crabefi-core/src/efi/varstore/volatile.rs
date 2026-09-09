//! Persistence policy for firmware without a direct-flash variable store.
//!
//! The mandatory runtime image still owns ordinary variables. Durable operations
//! fail explicitly; this profile neither probes flash nor claims persistence.

use crabefi_runtime_abi::VariableTimestamp;
use r_efi::efi::Guid;

use super::VarStoreError;
use crate::platform::VariableStorage;

/// No persistent store is available in this build.
pub fn init(_source: VariableStorage<'_>) -> Result<(), VarStoreError> {
    Err(VarStoreError::NotInitialized)
}

/// Volatile-only firmware cannot make durable variable writes.
pub fn is_varstore_writable() -> bool {
    false
}

/// No persisted authentication timestamp is available.
pub fn get_variable_timestamp(_guid: &Guid, _name: &[u16]) -> Option<VariableTimestamp> {
    None
}

pub(crate) fn persist_firmware_variable(
    _guid: &Guid,
    _name: &[u16],
    _attributes: u32,
    _data: &[u8],
) -> Result<(), VarStoreError> {
    Err(VarStoreError::NotInitialized)
}
