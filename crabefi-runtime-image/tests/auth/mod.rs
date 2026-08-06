#[path = "../../src/auth/limits.rs"]
mod limits;

pub use limits::{AUTH_OPERATION_SCRATCH_BOUND, MAX_AUTHENTICATED_ENVELOPE_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    InvalidHeader,
    SignatureVerificationFailed,
    NoSuitableKey,
    CertificateParseError,
    CryptoError,
    ChainTooDeep,
    OutOfResources,
}

#[path = "../../src/auth/crypto.rs"]
pub mod crypto;
