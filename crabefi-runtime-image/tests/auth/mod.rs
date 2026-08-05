pub const MAX_AUTHENTICATED_ENVELOPE_SIZE: usize = 48 * 1024;

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
