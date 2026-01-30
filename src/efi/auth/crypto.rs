//! Cryptographic Operations for Secure Boot
//!
//! This module implements cryptographic operations required for UEFI Secure Boot:
//! - SHA-256 hashing
//! - PKCS#7/CMS signature verification
//! - X.509 certificate parsing
//! - RSA signature verification

use super::AuthError;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

// ============================================================================
// SHA-256 Hashing
// ============================================================================

/// Compute SHA-256 hash of data
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-256 hash of multiple data chunks
pub fn sha256_chunks(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

// ============================================================================
// PKCS#7/CMS Signature Verification
// ============================================================================

/// Verify a PKCS#7 detached signature
///
/// # Arguments
///
/// * `pkcs7_data` - The PKCS#7 SignedData structure (DER encoded)
/// * `signed_data` - The data that was signed
/// * `trusted_cert` - A trusted X.509 certificate (DER encoded)
///
/// # Returns
///
/// * `Ok(true)` - Signature is valid and signed by the trusted certificate
/// * `Ok(false)` - Signature does not match this certificate
/// * `Err(...)` - Parse or verification error
pub fn verify_pkcs7_signature(
    pkcs7_data: &[u8],
    signed_data: &[u8],
    trusted_cert: &[u8],
) -> Result<bool, AuthError> {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::{Decode, Encode};

    // Parse the PKCS#7 ContentInfo structure
    let content_info = ContentInfo::from_der(pkcs7_data).map_err(|e| {
        log::debug!("Failed to parse PKCS#7 ContentInfo: {:?}", e);
        AuthError::InvalidHeader
    })?;

    // Get the raw content and parse as SignedData
    let signed_data_bytes = content_info
        .content
        .to_der()
        .map_err(|_| AuthError::InvalidHeader)?;
    let cms_signed_data = SignedData::from_der(&signed_data_bytes).map_err(|e| {
        log::debug!("Failed to parse PKCS#7 SignedData: {:?}", e);
        AuthError::InvalidHeader
    })?;

    // Compute the hash of the signed data
    let data_hash = sha256(signed_data);

    // Parse the trusted certificate
    let cert = parse_x509_certificate(trusted_cert)?;

    // Get signer info and verify
    for si in cms_signed_data.signer_infos.0.iter() {
        // Get the signature from signer info
        let signature = si.signature.as_bytes();

        // Try to verify using this signer's info
        match verify_rsa_signature_raw(&cert.public_key, signature, &data_hash) {
            Ok(true) => {
                log::info!("PKCS#7 signature verified successfully");
                return Ok(true);
            }
            Ok(false) => continue,
            Err(_) => continue,
        }
    }

    Ok(false)
}

// ============================================================================
// X.509 Certificate Parsing
// ============================================================================

/// Parsed X.509 certificate
pub struct X509Certificate {
    /// Subject name (DER encoded)
    #[allow(dead_code)]
    pub subject: Vec<u8>,
    /// Issuer name (DER encoded)
    pub issuer: Vec<u8>,
    /// Serial number
    pub serial_number: Vec<u8>,
    /// Public key (RSA modulus and exponent)
    pub public_key: RsaPublicKey,
}

/// RSA public key components
pub struct RsaPublicKey {
    /// Modulus (n)
    pub modulus: Vec<u8>,
    /// Public exponent (e)
    pub exponent: Vec<u8>,
}

/// Parse an X.509 certificate
pub fn parse_x509_certificate(cert_der: &[u8]) -> Result<X509Certificate, AuthError> {
    use der::{Decode, Encode};
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der).map_err(|e| {
        log::debug!("Failed to parse X.509 certificate: {:?}", e);
        AuthError::CertificateParseError
    })?;

    let tbs = &cert.tbs_certificate;

    // Extract subject and issuer names
    let subject = tbs
        .subject
        .to_der()
        .map_err(|_| AuthError::CertificateParseError)?;
    let issuer = tbs
        .issuer
        .to_der()
        .map_err(|_| AuthError::CertificateParseError)?;

    // Extract serial number
    let serial_number = tbs.serial_number.as_bytes().to_vec();

    // Extract public key
    let public_key = extract_rsa_public_key(&tbs.subject_public_key_info)?;

    Ok(X509Certificate {
        subject,
        issuer,
        serial_number,
        public_key,
    })
}

/// Extract RSA public key from SubjectPublicKeyInfo
fn extract_rsa_public_key(
    spki: &spki::SubjectPublicKeyInfoOwned,
) -> Result<RsaPublicKey, AuthError> {
    // The public key is in the subjectPublicKey field as a BIT STRING
    let pk_bytes = spki.subject_public_key.raw_bytes();

    // Parse as RSAPublicKey (SEQUENCE { modulus INTEGER, exponent INTEGER })
    // We need to parse this manually since pkcs1 crate may not be available
    parse_rsa_public_key_der(pk_bytes)
}

/// Parse RSA public key from DER-encoded RSAPublicKey structure
fn parse_rsa_public_key_der(data: &[u8]) -> Result<RsaPublicKey, AuthError> {
    // RSAPublicKey ::= SEQUENCE {
    //     modulus           INTEGER,  -- n
    //     publicExponent    INTEGER   -- e
    // }

    // Simple DER parser for RSA public key
    if data.len() < 4 {
        return Err(AuthError::CertificateParseError);
    }

    // Check for SEQUENCE tag (0x30)
    if data[0] != 0x30 {
        return Err(AuthError::CertificateParseError);
    }

    // Get sequence length
    let (seq_len, seq_offset) = parse_der_length(&data[1..])?;
    let seq_data = &data[1 + seq_offset..1 + seq_offset + seq_len];

    // Parse modulus (first INTEGER)
    if seq_data.is_empty() || seq_data[0] != 0x02 {
        return Err(AuthError::CertificateParseError);
    }

    let (mod_len, mod_offset) = parse_der_length(&seq_data[1..])?;
    let mod_data = &seq_data[1 + mod_offset..1 + mod_offset + mod_len];

    // Skip leading zero if present (used for positive numbers)
    let modulus = if !mod_data.is_empty() && mod_data[0] == 0x00 {
        mod_data[1..].to_vec()
    } else {
        mod_data.to_vec()
    };

    // Parse exponent (second INTEGER)
    let exp_start = 1 + mod_offset + mod_len;
    if exp_start >= seq_data.len() || seq_data[exp_start] != 0x02 {
        return Err(AuthError::CertificateParseError);
    }

    let (exp_len, exp_offset) = parse_der_length(&seq_data[exp_start + 1..])?;
    let exp_data = &seq_data[exp_start + 1 + exp_offset..exp_start + 1 + exp_offset + exp_len];

    // Skip leading zero if present
    let exponent = if !exp_data.is_empty() && exp_data[0] == 0x00 {
        exp_data[1..].to_vec()
    } else {
        exp_data.to_vec()
    };

    Ok(RsaPublicKey { modulus, exponent })
}

/// Parse DER length encoding
fn parse_der_length(data: &[u8]) -> Result<(usize, usize), AuthError> {
    if data.is_empty() {
        return Err(AuthError::CertificateParseError);
    }

    let first = data[0];
    if first < 0x80 {
        // Short form: length is in the first byte
        Ok((first as usize, 1))
    } else if first == 0x80 {
        // Indefinite length - not supported
        Err(AuthError::CertificateParseError)
    } else {
        // Long form: first byte indicates number of length bytes
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || num_bytes + 1 > data.len() {
            return Err(AuthError::CertificateParseError);
        }

        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | (data[1 + i] as usize);
        }

        Ok((length, 1 + num_bytes))
    }
}

// ============================================================================
// RSA Signature Verification
// ============================================================================

/// Verify an RSA signature using raw operations
fn verify_rsa_signature_raw(
    public_key: &RsaPublicKey,
    signature: &[u8],
    message_hash: &[u8; 32],
) -> Result<bool, AuthError> {
    use rsa::{BigUint, RsaPublicKey as RsaPubKey};

    // Construct the RSA public key
    let n = BigUint::from_bytes_be(&public_key.modulus);
    let e = BigUint::from_bytes_be(&public_key.exponent);

    let rsa_key = RsaPubKey::new(n, e).map_err(|e| {
        log::debug!("Failed to construct RSA key: {:?}", e);
        AuthError::CryptoError
    })?;

    // Create a verifying key for PKCS#1 v1.5 with SHA-256
    // Use new_unprefixed to avoid OID requirements
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new_unprefixed(rsa_key);

    // Parse the signature
    let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(|e| {
        log::debug!("Failed to parse signature: {:?}", e);
        AuthError::CryptoError
    })?;

    // Verify the signature
    use rsa::signature::Verifier;
    match verifying_key.verify(message_hash, &sig) {
        Ok(()) => Ok(true),
        Err(e) => {
            log::debug!("RSA signature verification failed: {:?}", e);
            Ok(false)
        }
    }
}

// ============================================================================
// Image Hash Verification
// ============================================================================

/// Compute the Authenticode PE hash of a binary image
///
/// This implements the PE/COFF hash algorithm used by UEFI Secure Boot.
/// The hash excludes:
/// - The checksum field in the optional header
/// - The Certificate Table entry in the optional header
/// - The attribute certificate table
pub fn compute_pe_hash(pe_data: &[u8]) -> Result<[u8; 32], AuthError> {
    // Use the proper Authenticode hash calculation
    super::authenticode::compute_authenticode_hash(pe_data)
}

/// Verify a PE image signature
///
/// This checks if the image's embedded signature is valid and signed by
/// a certificate in the allowed database (db) and not in the forbidden database (dbx).
pub fn verify_pe_image(pe_data: &[u8]) -> Result<bool, AuthError> {
    // Use the full Authenticode verification
    super::authenticode::verify_pe_image_secure_boot(pe_data)
}
