//! Canonical UEFI definitions and image-private variable attributes.

pub use r_efi::efi::*;

bitflags::bitflags! {
    /// EFI variable attributes known to the image.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct VariableAttributes: u32 {
        const NON_VOLATILE = VARIABLE_NON_VOLATILE;
        const BOOTSERVICE_ACCESS = VARIABLE_BOOTSERVICE_ACCESS;
        const RUNTIME_ACCESS = VARIABLE_RUNTIME_ACCESS;
        const HARDWARE_ERROR_RECORD = VARIABLE_HARDWARE_ERROR_RECORD;
        const AUTHENTICATED_WRITE_ACCESS = VARIABLE_AUTHENTICATED_WRITE_ACCESS;
        const TIME_BASED_AUTHENTICATED_WRITE_ACCESS =
            VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
        const APPEND_WRITE = VARIABLE_APPEND_WRITE;
    }
}

/// Collapse an internal result into the status returned at an ABI boundary.
pub fn status(result: Result<(), Status>) -> Status {
    match result {
        Ok(()) => Status::SUCCESS,
        Err(status) => status,
    }
}
