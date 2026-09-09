//! Algorithm-tagged digests shared by Authenticode hashing and measured boot.

/// TPM_ALG_SHA1
pub const TPM_ALG_SHA1: u16 = 0x0004;
/// TPM_ALG_SHA256
pub const TPM_ALG_SHA256: u16 = 0x000B;
/// TPM_ALG_SHA384
pub const TPM_ALG_SHA384: u16 = 0x000C;
/// TPM_ALG_SHA512
pub const TPM_ALG_SHA512: u16 = 0x000D;
/// TPM_ALG_SM3_256
pub const TPM_ALG_SM3_256: u16 = 0x0012;

/// Digest size for SHA-1.
pub const SHA1_DIGEST_SIZE: usize = 20;
/// Digest size for SHA-256.
pub const SHA256_DIGEST_SIZE: usize = 32;
/// Digest size for SHA-384.
pub const SHA384_DIGEST_SIZE: usize = 48;
/// Digest size for SHA-512.
pub const SHA512_DIGEST_SIZE: usize = 64;
/// Digest size for SM3-256.
pub const SM3_256_DIGEST_SIZE: usize = 32;

/// Return the digest size for a given TPM algorithm ID, or `None` if unknown.
pub fn digest_size_for_algorithm(alg: u16) -> Option<usize> {
    match alg {
        TPM_ALG_SHA1 => Some(SHA1_DIGEST_SIZE),
        TPM_ALG_SHA256 => Some(SHA256_DIGEST_SIZE),
        TPM_ALG_SHA384 => Some(SHA384_DIGEST_SIZE),
        TPM_ALG_SHA512 => Some(SHA512_DIGEST_SIZE),
        TPM_ALG_SM3_256 => Some(SM3_256_DIGEST_SIZE),
        _ => None,
    }
}

/// A single digest value tagged with its algorithm ID.
///
/// Part of `TPML_DIGEST_VALUES` in the TPM 2.0 crypto-agile event log.
#[derive(Clone, Copy)]
pub struct TaggedDigest {
    /// TPM algorithm ID (e.g., `TPM_ALG_SHA256`).
    pub algorithm: u16,
    /// Digest bytes. Length determined by `digest_size_for_algorithm()`.
    pub digest: [u8; SHA512_DIGEST_SIZE], // Max digest size
}

impl TaggedDigest {
    /// Create a new tagged digest with zeroed data.
    pub const fn zeroed(algorithm: u16) -> Self {
        Self {
            algorithm,
            digest: [0u8; SHA512_DIGEST_SIZE],
        }
    }

    /// Return the valid digest slice for this algorithm.
    pub fn as_slice(&self) -> &[u8] {
        let size = digest_size_for_algorithm(self.algorithm).unwrap_or(0);
        &self.digest[..size]
    }
}
