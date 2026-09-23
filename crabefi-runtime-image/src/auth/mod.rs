//! Image-local UEFI time-based authenticated-variable enforcement.

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
