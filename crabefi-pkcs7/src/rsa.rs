//! RSA PKCS#1 v1.5 signature verification with SHA-256.

use core::cmp::Ordering;

use crate::bigint;
use crate::der::{Result, Tlv, tag};

/// DER `DigestInfo` prefix for a SHA-256 digest (RFC 8017, section 9.2).
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// PKCS#1 `RSAPublicKey` with big-endian magnitudes.
#[derive(Clone, Copy, Debug)]
pub struct RsaPublicKey<'a> {
    pub modulus: &'a [u8],
    pub public_exponent: &'a [u8],
}

impl<'a> RsaPublicKey<'a> {
    /// Parse `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
    pub fn parse(der: &'a [u8]) -> Result<Self> {
        let mut integers = Tlv::parse(der)?.contents(tag::SEQUENCE)?;
        let modulus = integers.read()?.unsigned_integer()?;
        let public_exponent = integers.read()?.unsigned_integer()?;
        integers.finish()?;
        Ok(Self {
            modulus,
            public_exponent,
        })
    }

    /// Public exponent value, if it fits in 64 bits.
    pub fn exponent(&self) -> Option<u64> {
        (self.public_exponent.len() <= size_of::<u64>()).then(|| {
            self.public_exponent
                .iter()
                .fold(0, |value, byte| (value << 8) | u64::from(*byte))
        })
    }

    /// Modulus length in bits.
    pub fn modulus_bits(&self) -> usize {
        let significant = self.modulus.iter().skip_while(|byte| **byte == 0);
        let Some(&top) = significant.clone().next() else {
            return 0;
        };
        significant.count() * 8 - top.leading_zeros() as usize
    }

    /// Whether the key is arithmetically usable: odd modulus, odd exponent
    /// of at least 3 that fits in 64 bits, and exponent below the modulus.
    pub fn is_well_formed(&self) -> bool {
        bigint::is_odd_nonzero(self.modulus)
            && self
                .exponent()
                .is_some_and(|exponent| exponent >= 3 && exponent & 1 == 1)
            && bigint::cmp_be(self.public_exponent, self.modulus) == Ordering::Less
    }

    /// Verify an RSASSA-PKCS1-v1_5 signature over a SHA-256 `digest` for a
    /// modulus of at most `LIMBS * 64` bits.
    ///
    /// A signature one octet shorter than the modulus is accepted as a
    /// minimally encoded value with its leading zero octet stripped.
    /// Malformed keys, out-of-range signatures and oversized moduli verify as
    /// `false`.
    pub fn verify_pkcs1v15_sha256<const LIMBS: usize>(
        &self,
        signature: &[u8],
        digest: &[u8; 32],
    ) -> bool {
        let modulus_len = self.modulus.len();
        if !self.is_well_formed()
            || modulus_len > LIMBS * bigint::LIMB_BYTES
            || !(modulus_len.saturating_sub(1)..=modulus_len).contains(&signature.len())
            || bigint::cmp_be(signature, self.modulus) != Ordering::Less
        {
            return false;
        }
        let mut encoded = [[0u8; bigint::LIMB_BYTES]; LIMBS];
        let Some(encoded) = encoded.as_flattened_mut().get_mut(..modulus_len) else {
            return false;
        };
        bigint::mod_pow_vartime::<LIMBS>(signature, self.public_exponent, self.modulus, encoded)
            .is_ok()
            && is_pkcs1v15_sha256_encoding(encoded, digest)
    }
}

/// Check `EM = 0x00 || 0x01 || PS (>= 8 x 0xff) || 0x00 || DigestInfo(SHA-256, digest)`.
fn is_pkcs1v15_sha256_encoding(encoded: &[u8], digest: &[u8; 32]) -> bool {
    let Some(([0x00, 0x01], rest)) = encoded.split_first_chunk() else {
        return false;
    };
    let Some(padding_len) = rest
        .len()
        .checked_sub(1 + SHA256_DIGEST_INFO_PREFIX.len() + digest.len())
    else {
        return false;
    };
    let Some((padding, rest)) = rest.split_at_checked(padding_len) else {
        return false;
    };
    let Some((&0x00, digest_info)) = rest.split_first() else {
        return false;
    };
    padding_len >= 8
        && padding.iter().all(|byte| *byte == 0xff)
        && digest_info.strip_prefix(SHA256_DIGEST_INFO_PREFIX) == Some(&digest[..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modulus_bits_ignores_leading_zeros() {
        let key = |modulus| RsaPublicKey {
            modulus,
            public_exponent: &[3],
        };
        assert_eq!(key(&[0x00, 0x01, 0x00]).modulus_bits(), 9);
        assert_eq!(key(&[0xff; 512]).modulus_bits(), 4096);
        assert_eq!(key(&[0x00]).modulus_bits(), 0);
    }

    #[test]
    fn well_formedness_matches_rsa_key_rules() {
        let key = |modulus, public_exponent| RsaPublicKey {
            modulus,
            public_exponent,
        };
        assert!(key(&[0x0c, 0xa1], &[0x11]).is_well_formed());
        // Even modulus, even exponent, exponent 1, exponent >= modulus,
        // exponent wider than 64 bits.
        assert!(!key(&[0x0c, 0xa0], &[0x11]).is_well_formed());
        assert!(!key(&[0x0c, 0xa1], &[0x10]).is_well_formed());
        assert!(!key(&[0x0c, 0xa1], &[0x01]).is_well_formed());
        assert!(!key(&[0x0c, 0xa1], &[0x0c, 0xa3]).is_well_formed());
        assert!(!key(&[0xff; 16], &[0x01; 9]).is_well_formed());
    }

    #[test]
    fn oversize_modulus_fails_soft() {
        let key = RsaPublicKey {
            modulus: &[0xff; 4096 / 8 + 1],
            public_exponent: &[3],
        };
        assert!(!key.verify_pkcs1v15_sha256::<64>(&[1], &[0; 32]));
    }

    #[test]
    fn encoding_requires_full_padding_and_sha256_digest_info() {
        let digest = [0x5a; 32];
        let encode = |padding: usize| {
            let mut encoded = vec![0x00, 0x01];
            encoded.extend(core::iter::repeat_n(0xff, padding));
            encoded.push(0x00);
            encoded.extend_from_slice(SHA256_DIGEST_INFO_PREFIX);
            encoded.extend_from_slice(&digest);
            encoded
        };
        assert!(is_pkcs1v15_sha256_encoding(&encode(8), &digest));
        assert!(is_pkcs1v15_sha256_encoding(&encode(200), &digest));
        assert!(!is_pkcs1v15_sha256_encoding(&encode(7), &digest));
        assert!(!is_pkcs1v15_sha256_encoding(&encode(8), &[0x5b; 32]));
        let mut corrupted = encode(8);
        corrupted[5] = 0xfe;
        assert!(!is_pkcs1v15_sha256_encoding(&corrupted, &digest));
    }
}
