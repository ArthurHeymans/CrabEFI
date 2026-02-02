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
/// 2. The signature in SignerInfo is cryptographically valid
/// 3. The messageDigest attribute matches the hash of the signed data
/// 4. One of the signer certificates chains to the trusted certificate (from db)
///
/// # Arguments
///
/// * `pkcs7_data` - The PKCS#7 SignedData structure (DER encoded)
/// * `signed_data` - The data that was signed (the Authenticode hash or authenticated variable data)
/// * `trusted_cert` - A trusted X.509 certificate (DER encoded) from db
///
/// # Returns
///
/// * `Ok(true)` - Signature is valid and chains to the trusted certificate
/// * `Ok(false)` - Signature does not chain to this certificate
/// * `Err(...)` - Parse or verification error
pub fn verify_pkcs7_signature(
    pkcs7_data: &[u8],
    signed_data: &[u8],
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

    // Compute the hash of the actual signed data
    let computed_hash = sha256(signed_data);

    // Get SignerInfos and verify the signature
    if cms_signed_data.signer_infos.0.is_empty() {
        log::warn!("PKCS#7 contains no SignerInfo");
        return Err(AuthError::InvalidHeader);
    }

    // Verify each signer info
    for signer_info in cms_signed_data.signer_infos.0.iter() {
        // Extract the messageDigest from signed attributes (if present)
        // The messageDigest attribute contains the hash that was actually signed
        let message_digest = extract_message_digest(signer_info)?;

        // CRITICAL: Verify the messageDigest matches the hash of the actual data
        // This prevents signature replay attacks
        if let Some(ref md) = message_digest {
            if !constant_time_eq(md, &computed_hash) {
                log::warn!("messageDigest does not match computed hash - possible tampering");
                log::debug!(
                    "messageDigest: {:02x?}, computed: {:02x?}",
                    &md[..core::cmp::min(8, md.len())],
                    &computed_hash[..8]
                );
                continue; // Try next signer
            }
            log::debug!("messageDigest matches computed hash");
        }

        // Get the signature from SignerInfo
        let signature = signer_info.signature.as_bytes();

        // Find the signing certificate in the embedded certs
        let signer_cert_der =
            find_signer_certificate(&cms_signed_data, signer_info, &embedded_certs)?;

        if let Some(signer_der) = signer_cert_der {
            let signer_cert = parse_x509_certificate(&signer_der)?;

            // Build the data that was signed (signed attributes or content)
            let data_to_verify = build_signed_attrs_digest(signer_info, &computed_hash)?;

            // CRITICAL: Verify the RSA signature cryptographically
            match verify_rsa_signature_raw(&signer_cert.public_key, signature, &data_to_verify) {
                Ok(true) => {
                    log::debug!("RSA signature verification succeeded");

                    // Now verify the certificate chains to a trusted cert
                    // Check if signer is exactly the trusted cert (cryptographic comparison)
                    if verify_cert_chain(&signer_cert, &signer_der, &trusted, trusted_cert)? {
                        log::info!("Signer certificate chains to trusted db certificate");
                        return Ok(true);
                    }

                    // Check if signer cert is issued by trusted cert
                    if signer_cert.issuer == trusted.subject
                        && verify_cert_chain(&signer_cert, &signer_der, &trusted, trusted_cert)?
                    {
                        log::info!("Signer certificate issued by trusted db certificate");
                        return Ok(true);
                    }

                    // Check for intermediate chain
                    for intermediate_der in &embedded_certs {
                        if let Ok(intermediate) = parse_x509_certificate(intermediate_der)
                            && signer_cert.issuer == intermediate.subject
                            && verify_cert_chain(
                                &intermediate,
                                intermediate_der,
                                &trusted,
                                trusted_cert,
                            )?
                        {
                            log::info!(
                                "Signer certificate chains via intermediate to db certificate"
                            );
                            return Ok(true);
                        }
                    }
                }
                Ok(false) => {
                    log::debug!("RSA signature verification failed");
                    continue;
                }
                Err(e) => {
                    log::debug!("RSA signature verification error: {:?}", e);
                    continue;
                }
            }
        }
    }

    log::debug!("No valid signature chain found to trusted db certificate");
    Ok(false)
}

/// Extract the messageDigest attribute from SignerInfo
fn extract_message_digest(
    signer_info: &cms::signed_data::SignerInfo,
) -> Result<Option<Vec<u8>>, AuthError> {
    use der::Encode;

    // The messageDigest is in the signed attributes
    if let Some(ref attrs) = signer_info.signed_attrs {
        for attr in attrs.iter() {
            // messageDigest OID: 1.2.840.113549.1.9.4
            const MESSAGE_DIGEST_OID: &[u8] =
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
            let attr_oid = attr.oid.as_bytes();
            if attr_oid == MESSAGE_DIGEST_OID {
                // Extract the OCTET STRING value
                if let Some(value) = attr.values.get(0) {
                    let value_bytes = value.to_der().map_err(|_| AuthError::InvalidHeader)?;
                    // Parse the OCTET STRING to get the hash
                    if value_bytes.len() > 2 && value_bytes[0] == 0x04 {
                        let (len, offset) = parse_der_length(&value_bytes[1..])?;
                        if offset + len < value_bytes.len() {
                            return Ok(Some(value_bytes[1 + offset..1 + offset + len].to_vec()));
                        }
                    }
                }
            }
        }
    }
    Ok(None)
}

/// Find the certificate that corresponds to a SignerInfo
fn find_signer_certificate(
    _cms_signed_data: &cms::signed_data::SignedData,
    signer_info: &cms::signed_data::SignerInfo,
    embedded_certs: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, AuthError> {
    use cms::signed_data::SignerIdentifier;

    match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial) => {
            // Find cert matching issuer and serial number
            for cert_der in embedded_certs {
                if let Ok(cert) = parse_x509_certificate(cert_der) {
                    // Compare issuer (DER encoded) and serial number
                    use der::Encode;
                    if let Ok(issuer_bytes) = issuer_and_serial.issuer.to_der()
                        && cert.issuer == issuer_bytes
                        && cert.serial_number == issuer_and_serial.serial_number.as_bytes()
                    {
                        return Ok(Some(cert_der.clone()));
                    }
                }
            }
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            // Find cert matching subject key identifier
            // This requires parsing the cert's SKI extension
            let ski_bytes = ski.0.as_bytes();
            for cert_der in embedded_certs {
                if let Ok(ski_from_cert) = extract_subject_key_identifier(cert_der)
                    && ski_from_cert == ski_bytes
                {
                    return Ok(Some(cert_der.clone()));
                }
            }
        }
    }
    Ok(None)
}

/// Extract Subject Key Identifier from a certificate
fn extract_subject_key_identifier(cert_der: &[u8]) -> Result<Vec<u8>, AuthError> {
    use der::Decode;
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der).map_err(|_| AuthError::CertificateParseError)?;

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            // Subject Key Identifier OID: 2.5.29.14
            if ext.extn_id.as_bytes() == [0x55, 0x1d, 0x0e] {
                return Ok(ext.extn_value.as_bytes().to_vec());
            }
        }
    }
    Err(AuthError::CertificateParseError)
}

/// Build the digest of signed attributes for verification
fn build_signed_attrs_digest(
    signer_info: &cms::signed_data::SignerInfo,
    content_hash: &[u8; 32],
) -> Result<[u8; 32], AuthError> {
    use der::Encode;

    if let Some(ref attrs) = signer_info.signed_attrs {
        // Hash the DER-encoded signed attributes (with SET OF tag)
        let attrs_der = attrs.to_der().map_err(|_| AuthError::InvalidHeader)?;
        Ok(sha256(&attrs_der))
    } else {
        // No signed attributes - hash the content directly
        Ok(*content_hash)
    }
}

/// Constant-time byte array comparison to prevent timing attacks
///
/// This function compares two byte slices in constant time to prevent
/// timing side-channel attacks. The execution time is independent of
/// where (or whether) the bytes differ.
///
/// # Security
///
/// Use this function when comparing:
/// - Cryptographic hashes (SHA-256, etc.)
/// - Message authentication codes (HMACs)
/// - Any security-sensitive byte comparisons
///
/// Do NOT use regular `==` for these comparisons as it may short-circuit
/// on the first differing byte, leaking information through timing.
#[inline(never)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Verify that a certificate chains to a trusted certificate
///
/// For UEFI Secure Boot, we check:
/// 1. If the cert's issuer matches the trusted cert's subject (direct chain)
/// 2. Verify the cert's signature with the trusted cert's public key
/// 3. Validate the certificate's validity period (notBefore/notAfter)
fn verify_cert_chain(
    cert: &X509Certificate,
    cert_der: &[u8],
    trusted: &X509Certificate,
    _trusted_der: &[u8],
) -> Result<bool, AuthError> {
    use der::Decode;
    use x509_cert::Certificate;

    // Check if the cert's issuer matches the trusted cert's subject
    // For chain verification: cert.issuer should equal trusted.subject
    if cert.issuer != trusted.subject {
        log::debug!("Certificate issuer does not match trusted subject");
        return Ok(false);
    }

    // Validate certificate time validity
    if let Err(e) = validate_certificate_time(cert_der) {
        log::warn!("Certificate validity period check failed: {:?}", e);
        return Ok(false);
    }

    // Parse the full certificate to get the signature
    let full_cert =
        Certificate::from_der(cert_der).map_err(|_| AuthError::CertificateParseError)?;

    // Get the signature from the certificate
    let cert_signature = full_cert.signature.raw_bytes();

    // CRITICAL FIX: Extract the ORIGINAL TBS bytes from the raw DER
    // instead of re-encoding, which may produce different bytes due to
    // DER canonicalization differences.
    let tbs_bytes = extract_tbs_bytes(cert_der)?;

    // Hash the TBS certificate
    let tbs_hash = sha256(tbs_bytes);

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

/// Validate a certificate's validity period (notBefore/notAfter)
///
/// Checks that the current time is within the certificate's validity period.
/// This prevents use of expired or not-yet-valid certificates.
fn validate_certificate_time(cert_der: &[u8]) -> Result<(), AuthError> {
    use der::Decode;
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der).map_err(|_| AuthError::CertificateParseError)?;
    let validity = &cert.tbs_certificate.validity;

    // Get current time from the system
    // Note: In a real implementation, this should come from a trusted time source
    let current_time = get_current_time_for_cert_validation();

    // Parse notBefore
    let not_before = parse_x509_time(&validity.not_before)?;

    // Parse notAfter
    let not_after = parse_x509_time(&validity.not_after)?;

    // Check if current time is before notBefore
    if current_time < not_before {
        log::warn!(
            "Certificate not yet valid: notBefore={}, current={}",
            not_before,
            current_time
        );
        return Err(AuthError::CertificateNotYetValid);
    }

    // Check if current time is after notAfter
    if current_time > not_after {
        log::warn!(
            "Certificate expired: notAfter={}, current={}",
            not_after,
            current_time
        );
        return Err(AuthError::CertificateExpired);
    }

    log::debug!("Certificate validity period OK");
    Ok(())
}

/// Parse X.509 Time (UTCTime or GeneralizedTime) to Unix timestamp
fn parse_x509_time(time: &x509_cert::time::Time) -> Result<i64, AuthError> {
    use x509_cert::time::Time;

    let datetime = match time {
        Time::UtcTime(t) => t.to_date_time(),
        Time::GeneralTime(t) => t.to_date_time(),
    };

    // Convert to approximate Unix timestamp (seconds since 1970)
    // This is simplified - a full implementation would handle leap seconds, etc.
    let year = datetime.year() as i64;
    let month = datetime.month() as i64;
    let day = datetime.day() as i64;
    let hour = datetime.hour() as i64;
    let minute = datetime.minutes() as i64;
    let second = datetime.seconds() as i64;

    // Approximate days since epoch (1970-01-01)
    let years_since_1970 = year - 1970;
    let leap_years = (year - 1969) / 4 - (year - 1901) / 100 + (year - 1601) / 400;
    let days_in_year = match month {
        1 => 0,
        2 => 31,
        3 => 59,
        4 => 90,
        5 => 120,
        6 => 151,
        7 => 181,
        8 => 212,
        9 => 243,
        10 => 273,
        11 => 304,
        12 => 334,
        _ => 0,
    };
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let leap_day_adjustment = if is_leap && month > 2 { 1 } else { 0 };

    let total_days =
        years_since_1970 * 365 + leap_years + days_in_year + day - 1 + leap_day_adjustment;
    let total_seconds = total_days * 86400 + hour * 3600 + minute * 60 + second;

    Ok(total_seconds)
}

/// Get current time for certificate validation
///
/// Returns Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
fn get_current_time_for_cert_validation() -> i64 {
    // Read time from CMOS RTC
    // This is a simplified implementation - production code should use
    // a more reliable time source
    let (year, month, day, hour, minute, second) = read_rtc_time_for_crypto();

    let year = year as i64;
    let month = month as i64;
    let day = day as i64;
    let hour = hour as i64;
    let minute = minute as i64;
    let second = second as i64;

    // Same calculation as parse_x509_time
    let years_since_1970 = year - 1970;
    let leap_years = (year - 1969) / 4 - (year - 1901) / 100 + (year - 1601) / 400;
    let days_in_year = match month {
        1 => 0,
        2 => 31,
        3 => 59,
        4 => 90,
        5 => 120,
        6 => 151,
        7 => 181,
        8 => 212,
        9 => 243,
        10 => 273,
        11 => 304,
        12 => 334,
        _ => 0,
    };
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let leap_day_adjustment = if is_leap && month > 2 { 1 } else { 0 };

    let total_days =
        years_since_1970 * 365 + leap_years + days_in_year + day - 1 + leap_day_adjustment;
    total_days * 86400 + hour * 3600 + minute * 60 + second
}

/// Read time from CMOS RTC (simplified version for crypto module)
fn read_rtc_time_for_crypto() -> (u16, u8, u8, u8, u8, u8) {
    use crate::arch::x86_64::io;

    // Wait for RTC update to complete
    loop {
        unsafe {
            io::outb(0x70, 0x0A);
            if io::inb(0x71) & 0x80 == 0 {
                break;
            }
        }
    }

    let read_cmos = |reg: u8| -> u8 {
        unsafe {
            io::outb(0x70, reg);
            io::inb(0x71)
        }
    };

    let second = read_cmos(0x00);
    let minute = read_cmos(0x02);
    let hour = read_cmos(0x04);
    let day = read_cmos(0x07);
    let month = read_cmos(0x08);
    let year = read_cmos(0x09);
    let century = read_cmos(0x32);

    // Check if BCD mode
    let status_b = read_cmos(0x0B);
    let is_bcd = (status_b & 0x04) == 0;

    let convert = |val: u8| -> u8 {
        if is_bcd {
            (val & 0x0F) + ((val >> 4) * 10)
        } else {
            val
        }
    };

    let second = convert(second);
    let minute = convert(minute);
    let hour = convert(hour);
    let day = convert(day);
    let month = convert(month);
    let year = convert(year);
    let century = if century > 0 { convert(century) } else { 20 };

    let full_year = (century as u16) * 100 + (year as u16);

    (full_year, month, day, hour, minute, second)
}

/// Extract the original TBS (To Be Signed) certificate bytes from raw DER
///
/// Certificate ::= SEQUENCE {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
///
/// We need to extract the first element of the outer SEQUENCE, preserving
/// the original DER encoding exactly as it was signed.
fn extract_tbs_bytes(cert_der: &[u8]) -> Result<&[u8], AuthError> {
    // Certificate is a SEQUENCE
    if cert_der.is_empty() || cert_der[0] != 0x30 {
        return Err(AuthError::CertificateParseError);
    }

    // Parse the outer SEQUENCE length
    let (outer_len, outer_len_bytes) = parse_der_length(&cert_der[1..])?;
    let content_start = 1 + outer_len_bytes;

    if content_start + outer_len > cert_der.len() {
        return Err(AuthError::CertificateParseError);
    }

    let content = &cert_der[content_start..content_start + outer_len];

    // The first element is the TBSCertificate (also a SEQUENCE)
    if content.is_empty() || content[0] != 0x30 {
        return Err(AuthError::CertificateParseError);
    }

    // Parse the TBS SEQUENCE length
    let (tbs_len, tbs_len_bytes) = parse_der_length(&content[1..])?;
    let tbs_total_len = 1 + tbs_len_bytes + tbs_len;

    if tbs_total_len > content.len() {
        return Err(AuthError::CertificateParseError);
    }

    // Return the complete TBS including tag and length
    Ok(&content[..tbs_total_len])
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

/// Maximum DER length we'll accept (64 MB)
/// This prevents DoS attacks with maliciously crafted length fields
const MAX_DER_LENGTH: usize = 64 * 1024 * 1024;

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

        // Reject unreasonably large lengths to prevent DoS
        if length > MAX_DER_LENGTH {
            log::warn!("DER length {} exceeds maximum {}", length, MAX_DER_LENGTH);
            return Err(AuthError::CertificateParseError);
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
///
/// CRITICAL: Uses the standard PKCS#1 v1.5 verification with proper algorithm
/// identifier prefix to prevent algorithm substitution attacks. The signature
/// must contain the correct DigestInfo structure including the SHA-256 OID.
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

    // CRITICAL FIX: Use `new()` instead of `new_unprefixed()` to require proper
    // DigestInfo structure with SHA-256 OID. This prevents algorithm substitution
    // attacks where an attacker could use a different hash algorithm.
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa_key);

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
