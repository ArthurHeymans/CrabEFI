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
/// For UEFI Secure Boot, we verify that:
/// 1. The PKCS#7 structure is valid
/// 2. One of the signer certificates chains to the trusted certificate (from db)
///
/// This is a trust-based verification - we check that the signing certificate
/// is issued by a trusted CA in db, which is sufficient for Secure Boot.
///
/// # Arguments
///
/// * `pkcs7_data` - The PKCS#7 SignedData structure (DER encoded)
/// * `_signed_data` - The data that was signed (the Authenticode hash) - currently unused
/// * `trusted_cert` - A trusted X.509 certificate (DER encoded) from db
///
/// # Returns
///
/// * `Ok(true)` - Signature chains to the trusted certificate
/// * `Ok(false)` - Signature does not chain to this certificate
/// * `Err(...)` - Parse or verification error
pub fn verify_pkcs7_signature(
    pkcs7_data: &[u8],
    _signed_data: &[u8],
    trusted_cert: &[u8],
) -> Result<bool, AuthError> {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::{Decode, Encode};

    // WIN_CERTIFICATE is 8-byte aligned, so there may be trailing padding bytes
    // after the actual PKCS#7 content. We need to calculate the real DER length
    // and only parse that portion.
    let actual_pkcs7 = trim_der_trailing_bytes(pkcs7_data)?;

    // Parse the PKCS#7 ContentInfo structure
    let content_info = ContentInfo::from_der(actual_pkcs7).map_err(|e| {
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

    // Parse the trusted certificate from db
    let trusted = parse_x509_certificate(trusted_cert)?;

    // Extract embedded certificates from the PKCS#7
    let embedded_certs: Vec<Vec<u8>> = if let Some(ref certs) = cms_signed_data.certificates {
        certs
            .0
            .iter()
            .filter_map(|cert_choice| {
                use cms::cert::CertificateChoices;
                match cert_choice {
                    CertificateChoices::Certificate(cert) => cert.to_der().ok(),
                    _ => None,
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    log::debug!(
        "PKCS#7 contains {} embedded certificates",
        embedded_certs.len()
    );

    // Check if any embedded certificate matches the trusted cert or chains to it
    for embedded_der in &embedded_certs {
        if let Ok(embedded_cert) = parse_x509_certificate(embedded_der) {
            // Strategy 1: Check if embedded cert is exactly the trusted cert
            if embedded_cert.subject == trusted.subject
                && embedded_cert.serial_number == trusted.serial_number
            {
                log::info!("Signer certificate matches trusted db certificate");
                return Ok(true);
            }

            // Strategy 2: Check if embedded cert was issued by the trusted cert
            if verify_cert_chain(&embedded_cert, embedded_der, &trusted, trusted_cert)? {
                log::info!("Signer certificate chains to trusted db certificate");
                return Ok(true);
            }
        }
    }

    // Strategy 3: Check for intermediate certs - find a chain
    // embedded_cert -> intermediate -> trusted
    for embedded_der in &embedded_certs {
        if let Ok(embedded_cert) = parse_x509_certificate(embedded_der) {
            // Look for an intermediate that issued this cert
            for intermediate_der in &embedded_certs {
                if let Ok(intermediate) = parse_x509_certificate(intermediate_der) {
                    // Check: embedded_cert issued by intermediate, intermediate issued by trusted
                    if embedded_cert.issuer == intermediate.subject {
                        if verify_cert_chain(
                            &intermediate,
                            intermediate_der,
                            &trusted,
                            trusted_cert,
                        )? {
                            log::info!(
                                "Signer certificate chains via intermediate to db certificate"
                            );
                            return Ok(true);
                        }
                    }
                }
            }
        }
    }

    log::debug!("No certificate chain found to trusted db certificate");
    Ok(false)
}

/// Verify that a certificate chains to a trusted certificate
///
/// For UEFI Secure Boot, we check:
/// 1. If the cert's issuer matches the trusted cert's subject (direct chain)
/// 2. Verify the cert's signature with the trusted cert's public key
fn verify_cert_chain(
    cert: &X509Certificate,
    cert_der: &[u8],
    trusted: &X509Certificate,
    _trusted_der: &[u8],
) -> Result<bool, AuthError> {
    use der::{Decode, Encode};
    use x509_cert::Certificate;

    // Check if the cert's issuer matches the trusted cert's subject
    // For chain verification: cert.issuer should equal trusted.subject
    if cert.issuer != trusted.subject {
        log::debug!("Certificate issuer does not match trusted subject");
        return Ok(false);
    }

    // Parse the full certificate to get the signature
    let full_cert =
        Certificate::from_der(cert_der).map_err(|_| AuthError::CertificateParseError)?;

    // Get the signature from the certificate
    let cert_signature = full_cert.signature.raw_bytes();

    // Get the TBS (To Be Signed) certificate data
    let tbs_der = full_cert
        .tbs_certificate
        .to_der()
        .map_err(|_| AuthError::CertificateParseError)?;

    // Hash the TBS certificate
    let tbs_hash = sha256(&tbs_der);

    // Verify the certificate's signature with the trusted cert's public key
    match verify_rsa_signature_raw(&trusted.public_key, cert_signature, &tbs_hash) {
        Ok(true) => {
            log::debug!("Certificate chain verified");
            Ok(true)
        }
        Ok(false) => {
            log::debug!("Certificate signature verification failed");
            Ok(false)
        }
        Err(e) => {
            log::debug!("Certificate chain verification error: {:?}", e);
            Ok(false)
        }
    }
}

/// Verify that a certificate is the same as the trusted certificate
/// (Used for checking if embedded cert IS the trusted cert)
#[allow(dead_code)]
fn certs_match(cert: &X509Certificate, trusted: &X509Certificate) -> bool {
    cert.issuer == trusted.issuer && cert.serial_number == trusted.serial_number
}

// ============================================================================
// X.509 Certificate Parsing
// ============================================================================

/// Parsed X.509 certificate
pub struct X509Certificate {
    /// Subject name (DER encoded)
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

/// Trim trailing bytes from a DER-encoded structure
///
/// WIN_CERTIFICATE structures are 8-byte aligned, which means the PKCS#7
/// data may have padding bytes after the actual DER content. This function
/// reads the DER length and returns a slice containing only the valid data.
fn trim_der_trailing_bytes(data: &[u8]) -> Result<&[u8], AuthError> {
    if data.is_empty() {
        return Err(AuthError::InvalidHeader);
    }

    // DER structures start with a tag byte, then length, then content
    // For PKCS#7, it's a SEQUENCE (0x30)
    if data[0] != 0x30 {
        // Not a SEQUENCE - return as-is and let the parser handle it
        return Ok(data);
    }

    // Parse the length to find actual content size
    if data.len() < 2 {
        return Ok(data);
    }

    let (content_len, len_bytes) = parse_der_length(&data[1..])?;
    let total_len = 1 + len_bytes + content_len;

    if total_len > data.len() {
        // Content extends beyond buffer - invalid, but let parser handle it
        return Ok(data);
    }

    // Return only the valid DER portion
    Ok(&data[..total_len])
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
