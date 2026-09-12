//! Image-local UEFI time-based authenticated-variable enforcement.

mod bigint;
mod crypto;
mod limits;
mod signature;

pub use limits::MAX_AUTHENTICATED_ENVELOPE_SIZE;
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
    fn oversize_modulus_fails_soft() {
        // Inputs above the stack-backed maximum width fail soft (Ok(false)),
        // exactly like the previous arena-preflight path: unauthenticated
        // data must never become a hard error.
        let modulus = [0xffu8; 4096 / 8 + 1];
        let verified = crypto::verify_rsa_parts_for_test(&modulus, &[1], &[1], &[0; 32]).unwrap();
        assert!(!verified);
    }

    #[test]
    fn maximum_width_rsa_completes_without_arena() {
        // A 4096-bit verification runs entirely on fixed stack buffers.
        // The 16 KiB firmware stack fit is enforced separately by the
        // link-time stack-sizes audit, which fails the image build on
        // any function exceeding budget.
        const MAX_RSA_BYTES: usize = 4096 / 8;
        let modulus = [0xff; MAX_RSA_BYTES];
        let signature = [0xa5; MAX_RSA_BYTES];
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
    }
}
