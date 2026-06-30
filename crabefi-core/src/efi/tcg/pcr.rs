//! Software PCR (Platform Configuration Register) bank.
//!
//! This module implements software mirrors for TPM PCR banks. A PCR value can
//! only be modified with the extend operation: `PCR[i] = Hash(PCR[i] || digest)`.
//!
//! The software PCR bank is a mirror used for log construction and internal
//! consistency checks after an attestable TPM backend has accepted an extend.
//! CrabEFI does not expose software-only PCR values as hardware-backed measured
//! boot evidence.

use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use super::types::{
    PCR_COUNT, SHA1_DIGEST_SIZE, SHA256_DIGEST_SIZE, SHA384_DIGEST_SIZE, SHA512_DIGEST_SIZE,
    TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, TaggedDigest, TcgError,
    digest_size_for_algorithm,
};

const MAX_SUPPORTED_BANKS: usize = 4;

fn supported_digest_size(algorithm: u16) -> Option<usize> {
    match algorithm {
        TPM_ALG_SHA1 | TPM_ALG_SHA256 | TPM_ALG_SHA384 | TPM_ALG_SHA512 => {
            digest_size_for_algorithm(algorithm)
        }
        _ => None,
    }
}

fn hash_data_for_algorithm(algorithm: u16, data: &[u8]) -> Option<TaggedDigest> {
    let mut digest = TaggedDigest::zeroed(algorithm);
    match algorithm {
        TPM_ALG_SHA1 => digest.digest[..SHA1_DIGEST_SIZE].copy_from_slice(&Sha1::digest(data)),
        TPM_ALG_SHA256 => {
            digest.digest[..SHA256_DIGEST_SIZE].copy_from_slice(&Sha256::digest(data))
        }
        TPM_ALG_SHA384 => {
            digest.digest[..SHA384_DIGEST_SIZE].copy_from_slice(&Sha384::digest(data))
        }
        TPM_ALG_SHA512 => {
            digest.digest[..SHA512_DIGEST_SIZE].copy_from_slice(&Sha512::digest(data))
        }
        _ => return None,
    }
    Some(digest)
}

// ============================================================================
// Single PCR Banks
// ============================================================================

/// Software PCR bank for one TPM hash algorithm.
pub struct PcrBank {
    algorithm: u16,
    digest_size: usize,
    pcrs: [[u8; SHA512_DIGEST_SIZE]; PCR_COUNT],
}

impl PcrBank {
    /// Create a new bank with all PCRs initialized to zeros.
    pub const fn new(algorithm: u16, digest_size: usize) -> Self {
        Self {
            algorithm,
            digest_size,
            pcrs: [[0u8; SHA512_DIGEST_SIZE]; PCR_COUNT],
        }
    }

    /// Return this bank's TPM algorithm ID.
    pub fn algorithm(&self) -> u16 {
        self.algorithm
    }

    /// Extend PCR `index` with the given digest.
    pub fn extend(&mut self, index: usize, digest: &[u8]) -> Result<(), TcgError> {
        if index >= PCR_COUNT {
            return Err(TcgError::InvalidPcrIndex);
        }
        if digest.len() < self.digest_size {
            return Err(TcgError::UnsupportedAlgorithm);
        }

        match self.algorithm {
            TPM_ALG_SHA1 => {
                let mut hasher = Sha1::new();
                hasher.update(&self.pcrs[index][..SHA1_DIGEST_SIZE]);
                hasher.update(&digest[..SHA1_DIGEST_SIZE]);
                self.pcrs[index][..SHA1_DIGEST_SIZE].copy_from_slice(&hasher.finalize());
            }
            TPM_ALG_SHA256 => {
                let mut hasher = Sha256::new();
                hasher.update(&self.pcrs[index][..SHA256_DIGEST_SIZE]);
                hasher.update(&digest[..SHA256_DIGEST_SIZE]);
                self.pcrs[index][..SHA256_DIGEST_SIZE].copy_from_slice(&hasher.finalize());
            }
            TPM_ALG_SHA384 => {
                let mut hasher = Sha384::new();
                hasher.update(&self.pcrs[index][..SHA384_DIGEST_SIZE]);
                hasher.update(&digest[..SHA384_DIGEST_SIZE]);
                self.pcrs[index][..SHA384_DIGEST_SIZE].copy_from_slice(&hasher.finalize());
            }
            TPM_ALG_SHA512 => {
                let mut hasher = Sha512::new();
                hasher.update(&self.pcrs[index][..SHA512_DIGEST_SIZE]);
                hasher.update(&digest[..SHA512_DIGEST_SIZE]);
                self.pcrs[index][..SHA512_DIGEST_SIZE].copy_from_slice(&hasher.finalize());
            }
            _ => return Err(TcgError::UnsupportedAlgorithm),
        }
        Ok(())
    }

    /// Read the current value of PCR `index`.
    pub fn read(&self, index: usize) -> Result<&[u8], TcgError> {
        self.pcrs
            .get(index)
            .map(|pcr| &pcr[..self.digest_size])
            .ok_or(TcgError::InvalidPcrIndex)
    }
}

/// Software PCR bank for SHA-1, used by the legacy EFI_TCG_PROTOCOL.
pub struct Sha1PcrBank {
    pcrs: [[u8; SHA1_DIGEST_SIZE]; PCR_COUNT],
}

impl Default for Sha1PcrBank {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1PcrBank {
    /// Create a new bank with all PCRs initialized to zeros.
    pub const fn new() -> Self {
        Self {
            pcrs: [[0u8; SHA1_DIGEST_SIZE]; PCR_COUNT],
        }
    }

    /// Extend PCR `index` with the given digest.
    pub fn extend(&mut self, index: usize, digest: &[u8]) -> Result<(), TcgError> {
        if index >= PCR_COUNT {
            return Err(TcgError::InvalidPcrIndex);
        }
        if digest.len() != SHA1_DIGEST_SIZE {
            return Err(TcgError::UnsupportedAlgorithm);
        }
        let mut hasher = Sha1::new();
        hasher.update(self.pcrs[index]);
        hasher.update(digest);
        self.pcrs[index].copy_from_slice(&hasher.finalize());
        Ok(())
    }

    /// Read the current value of PCR `index`.
    pub fn read(&self, index: usize) -> Result<&[u8; SHA1_DIGEST_SIZE], TcgError> {
        self.pcrs.get(index).ok_or(TcgError::InvalidPcrIndex)
    }
}

// ============================================================================
// Multi-algorithm PCR bank set
// ============================================================================

/// Collection of PCR banks for all active hash algorithms.
pub struct PcrBanks {
    banks: [PcrBank; MAX_SUPPORTED_BANKS],
    count: usize,
}

impl PcrBanks {
    /// Create PCR banks with SHA-256 only.
    pub fn sha256_only() -> Self {
        Self::from_algorithms(&[TPM_ALG_SHA256])
    }

    /// Create PCR banks with both SHA-1 and SHA-256.
    pub fn sha1_and_sha256() -> Self {
        Self::from_algorithms(&[TPM_ALG_SHA256, TPM_ALG_SHA1])
    }

    /// Create PCR banks for all supported algorithms in `algorithms`.
    pub fn from_algorithms(algorithms: &[u16]) -> Self {
        let mut banks = [
            PcrBank::new(0, 0),
            PcrBank::new(0, 0),
            PcrBank::new(0, 0),
            PcrBank::new(0, 0),
        ];
        let mut count = 0;

        for &algorithm in algorithms {
            if count >= MAX_SUPPORTED_BANKS
                || banks[..count].iter().any(|b| b.algorithm == algorithm)
            {
                continue;
            }
            let Some(digest_size) = supported_digest_size(algorithm) else {
                continue;
            };
            banks[count] = PcrBank::new(algorithm, digest_size);
            count += 1;
        }

        if count == 0 && algorithms.is_empty() {
            banks[0] = PcrBank::new(TPM_ALG_SHA256, SHA256_DIGEST_SIZE);
            count = 1;
        }

        Self { banks, count }
    }

    /// Return active software bank algorithms.
    pub fn algorithms(&self) -> impl Iterator<Item = u16> + '_ {
        self.banks[..self.count].iter().map(PcrBank::algorithm)
    }

    /// Return active software bank algorithms in a fixed array.
    pub fn algorithm_array(&self) -> (usize, [u16; 5]) {
        let mut out = [0u16; 5];
        for (dst, algorithm) in out.iter_mut().zip(self.algorithms()) {
            *dst = algorithm;
        }
        (self.count, out)
    }

    /// Return true if `algorithm` is active.
    pub fn contains(&self, algorithm: u16) -> bool {
        self.algorithms().any(|active| active == algorithm)
    }

    /// Extend PCR `index` across all active banks using the provided digests.
    pub fn extend(&mut self, index: usize, digests: &[TaggedDigest]) -> Result<(), TcgError> {
        if index >= PCR_COUNT {
            return Err(TcgError::InvalidPcrIndex);
        }

        for bank in self.banks[..self.count].iter_mut() {
            let digest = digests
                .iter()
                .find(|d| d.algorithm == bank.algorithm())
                .ok_or(TcgError::UnsupportedAlgorithm)?;
            bank.extend(index, digest.as_slice())?;
        }

        Ok(())
    }

    /// Hash data with all active algorithms and return tagged digests.
    pub fn hash_data(&self, data: &[u8]) -> (usize, [TaggedDigest; 5]) {
        let mut digests = [TaggedDigest::zeroed(0); 5];
        let mut count = 0;

        for algorithm in self.algorithms() {
            if let Some(digest) = hash_data_for_algorithm(algorithm, data) {
                digests[count] = digest;
                count += 1;
            }
        }

        (count, digests)
    }

    /// Whether the SHA-1 bank is active.
    pub fn has_sha1(&self) -> bool {
        self.contains(TPM_ALG_SHA1)
    }

    /// Access a bank by algorithm ID.
    pub fn bank(&self, algorithm: u16) -> Option<&PcrBank> {
        self.banks[..self.count]
            .iter()
            .find(|bank| bank.algorithm == algorithm)
    }

    /// Access the SHA-1 bank (if active).
    pub fn sha1(&self) -> Option<&PcrBank> {
        self.bank(TPM_ALG_SHA1)
    }

    /// Access the SHA-256 bank.
    pub fn sha256(&self) -> &PcrBank {
        self.bank(TPM_ALG_SHA256)
            .expect("PcrBanks always includes SHA-256 fallback")
    }
}
