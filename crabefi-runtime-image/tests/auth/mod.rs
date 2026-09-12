#[path = "../../src/auth/limits.rs"]
mod limits;

#[path = "../../src/auth/bigint.rs"]
pub mod bigint;

pub use limits::MAX_AUTHENTICATED_ENVELOPE_SIZE;

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
