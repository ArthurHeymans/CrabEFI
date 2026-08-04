//! Canonical UEFI definitions and image-private variable policy.

pub use r_efi::efi::*;

pub const VARIABLE_KNOWN_ATTRIBUTES: u32 = VARIABLE_NON_VOLATILE
    | VARIABLE_BOOTSERVICE_ACCESS
    | VARIABLE_RUNTIME_ACCESS
    | VARIABLE_HARDWARE_ERROR_RECORD
    | VARIABLE_AUTHENTICATED_WRITE_ACCESS
    | VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
    | VARIABLE_APPEND_WRITE;

// Kept for the bounded store, which deliberately does not otherwise depend on
// the Runtime Services status spelling.
pub const INVALID_PARAMETER: Status = Status::INVALID_PARAMETER;
pub const OUT_OF_RESOURCES: Status = Status::OUT_OF_RESOURCES;
pub const NOT_FOUND: Status = Status::NOT_FOUND;
pub const DEVICE_ERROR: Status = Status::DEVICE_ERROR;
