//! Image-local UEFI time-based authenticated-variable enforcement.

mod crypto;
mod signature;
pub mod structures;
pub mod variables;

pub use signature::verify_authenticated_variable;
pub use structures::validate_signature_database;
pub use variables::{
    EFI_GLOBAL_VARIABLE_GUID, SECURE_BOOT_ENABLE_NAME, SECURE_BOOT_NAME, SETUP_MODE_NAME,
    SecureBootVariable, identify_key_database, is_status_variable,
};

use crate::efi;

pub const MAX_AUTHENTICATED_ENVELOPE_SIZE: usize = 48 * 1024;
/// Complete RSA/CMS service-operation reservation, including signed-data assembly.
pub const AUTH_OPERATION_SCRATCH_BOUND: usize = 440 * 1024;
pub const WIN_CERT_REVISION: u16 = 0x0200;
pub const WIN_CERT_TYPE_EFI_GUID: u16 = 0x0ef1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    InvalidHeader,
    InvalidTimestamp,
    SignatureVerificationFailed,
    NoSuitableKey,
    CertificateParseError,
    InvalidVariableName,
    InvalidSignatureList,
    CryptoError,
    ChainTooDeep,
    OutOfResources,
}

impl From<AuthError> for efi::Status {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::InvalidHeader
            | AuthError::CertificateParseError
            | AuthError::InvalidVariableName
            | AuthError::InvalidSignatureList => efi::Status::INVALID_PARAMETER,
            AuthError::InvalidTimestamp
            | AuthError::SignatureVerificationFailed
            | AuthError::NoSuitableKey
            | AuthError::ChainTooDeep => efi::Status::SECURITY_VIOLATION,
            AuthError::CryptoError => efi::Status::DEVICE_ERROR,
            AuthError::OutOfResources => efi::Status::OUT_OF_RESOURCES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_exhaustion_maps_to_out_of_resources() {
        let _guard = crate::scratch::test_lock();
        crate::scratch::activate();
        crate::scratch::set_limit_for_test(0);
        let error = crypto::verify_pkcs7_signature(&[0x30, 0], &[], &[0x30, 0]).unwrap_err();
        assert_eq!(efi::Status::from(error), efi::Status::OUT_OF_RESOURCES);
        crate::scratch::reset();
        crate::scratch::set_limit_for_test(crate::scratch::SCRATCH_SIZE);
    }
}
