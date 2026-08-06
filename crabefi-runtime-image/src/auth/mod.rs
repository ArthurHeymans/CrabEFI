//! Image-local UEFI time-based authenticated-variable enforcement.

mod crypto;
mod limits;
mod signature;

pub use limits::{AUTH_OPERATION_SCRATCH_BOUND, MAX_AUTHENTICATED_ENVELOPE_SIZE};
pub use signature::verify_authenticated_variable;

use crabefi_efi_types::authentication::EfiTime;
use crabefi_runtime_abi::VariableTimestamp;

use crate::efi;

pub fn efi_time_from_timestamp(value: VariableTimestamp) -> EfiTime {
    EfiTime {
        year: value.year,
        month: value.month,
        day: value.day,
        hour: value.hour,
        minute: value.minute,
        second: value.second,
        pad1: value.pad1,
        nanosecond: value.nanosecond,
        timezone: value.timezone,
        daylight: value.daylight,
        pad2: value.pad2,
    }
}

pub fn timestamp_from_efi_time(value: EfiTime) -> VariableTimestamp {
    VariableTimestamp {
        year: value.year,
        month: value.month,
        day: value.day,
        hour: value.hour,
        minute: value.minute,
        second: value.second,
        pad1: value.pad1,
        nanosecond: value.nanosecond,
        timezone: value.timezone,
        daylight: value.daylight,
        pad2: value.pad2,
    }
}

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
        let error = crypto::verify_rsa_parts_for_test(&[3], &[3], &[1], &[0; 32]).unwrap_err();
        assert_eq!(efi::Status::from(error), efi::Status::OUT_OF_RESOURCES);
        crate::scratch::reset();
        crate::scratch::set_limit_for_test(crate::scratch::SCRATCH_SIZE);
    }

    #[test]
    fn maximum_width_rsa_stays_within_operation_scratch_bound() {
        let _guard = crate::scratch::test_lock();
        crate::scratch::activate();
        crate::scratch::set_limit_for_test(AUTH_OPERATION_SCRATCH_BOUND);

        const MAX_RSA_BYTES: usize = 4096 / 8;
        let modulus = [0xff; MAX_RSA_BYTES];
        let signature = [0xa5; MAX_RSA_BYTES];
        // Three operations would exceed the bound without per-operation
        // rewinding (a single 4096-bit op uses roughly half the bound), so a
        // missing rewind is caught by the high-water assertion below.
        for _ in 0..3 {
            let verified = crypto::verify_rsa_parts_for_test(
                &modulus,
                &[0x01, 0x00, 0x01],
                &signature,
                &[0u8; 32],
            )
            .unwrap();
            assert!(!verified);
        }
        let high_water = crate::scratch::high_water_for_test();
        crate::scratch::reset();
        crate::scratch::set_limit_for_test(crate::scratch::SCRATCH_SIZE);

        assert!(high_water <= AUTH_OPERATION_SCRATCH_BOUND);
    }
}
