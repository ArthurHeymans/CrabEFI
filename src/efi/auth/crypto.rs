//! Cryptographic Operations for Secure Boot
//!
//! This module implements cryptographic operations required for UEFI Secure Boot:
//! - SHA-256 hashing
//! - PKCS#7/CMS signature verification
//! - X.509 certificate parsing
//! - RSA signature verification
//! - Full certificate chain building and validation
//! - Certificate revocation checking (CRL/OCSP)

use super::AuthError;
use super::revocation::{RevocationCheckResult, RevocationConfig, check_certificate_revocation};
use super::time;
use alloc::vec;
use alloc::vec::Vec;
use der::{Decode, Encode, referenced::OwnedToRef};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::ext::pkix::KeyUsage as X509KeyUsage;
use x509_cert::ext::pkix::constraints::BasicConstraints as X509BasicConstraints;

// ============================================================================
// Certificate Chain Building Configuration
// ============================================================================

/// Maximum certificate chain depth allowed
/// This prevents infinite loops and excessive resource consumption
pub const MAX_CHAIN_DEPTH: usize = 10;

/// Default maximum chain depth for normal operations
const DEFAULT_MAX_CHAIN_DEPTH: usize = 5;

/// Configuration for certificate chain building and validation
#[derive(Debug, Clone)]
pub struct ChainBuildingConfig {
    /// Maximum chain depth allowed (default: 5)
    pub max_depth: usize,
    /// Whether to check certificate revocation status
    pub check_revocation: bool,
    /// Revocation checking configuration
    pub revocation_config: RevocationConfig,
    /// Current time as Unix timestamp (for validity period checking)
    pub current_time: i64,
    /// Whether to require CA certificates to have basicConstraints
    pub require_basic_constraints: bool,
    /// Whether to require CA certificates to have keyCertSign keyUsage
    pub require_key_usage: bool,
}

impl Default for ChainBuildingConfig {
    fn default() -> Self {
        ChainBuildingConfig {
            max_depth: DEFAULT_MAX_CHAIN_DEPTH,
            check_revocation: true,
            revocation_config: RevocationConfig::default(),
            current_time: get_current_time_for_cert_validation(),
            require_basic_constraints: true,
            require_key_usage: true,
        }
    }
}

/// A built certificate chain
#[derive(Debug, Clone)]
pub struct CertificateChain {
    /// Certificates in the chain, from end-entity to root
    /// Index 0 is the end-entity (signer) certificate
    /// Last index is the trust anchor (root CA)
    pub certificates: Vec<Vec<u8>>,
}

impl CertificateChain {
    /// Get the end-entity (signer) certificate
    pub fn end_entity(&self) -> Option<&[u8]> {
        self.certificates.first().map(|v| v.as_slice())
    }

    /// Get the trust anchor (root CA) certificate
    pub fn trust_anchor(&self) -> Option<&[u8]> {
        self.certificates.last().map(|v| v.as_slice())
    }

    /// Get the chain length
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }
}

// ============================================================================
// SHA-256 Hashing
// ============================================================================

/// Compute SHA-256 hash of data
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
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

    // Validate the trusted certificate from db can be parsed
    parse_cert(trusted_cert)?;

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
            let signer_cert = parse_cert(&signer_der)?;
            let signer_rsa_key = extract_rsa_key(&signer_cert)?;

            // Build the data that was signed (signed attributes or content)
            let data_to_verify = build_signed_attrs_digest(signer_info, &computed_hash)?;

            // CRITICAL: Verify the RSA signature cryptographically
            match verify_rsa_signature_raw(&signer_rsa_key, signature, &data_to_verify) {
                Ok(true) => {
                    log::debug!("RSA signature verification succeeded");

                    // Build and verify the certificate chain using the full chain building algorithm
                    let config = ChainBuildingConfig::default();

                    // Try to build a chain from the signer certificate to the trusted certificate
                    match build_and_verify_chain(
                        &signer_der,
                        trusted_cert,
                        &embedded_certs,
                        &config,
                    ) {
                        Ok(chain) => {
                            log::info!(
                                "Certificate chain verified successfully (depth: {})",
                                chain.len()
                            );
                            return Ok(true);
                        }
                        Err(e) => {
                            log::debug!("Chain building failed: {:?}", e);
                            // Continue trying other signers
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
    use der::asn1::OctetStringRef;

    // messageDigest OID: 1.2.840.113549.1.9.4
    let md_oid = const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

    if let Some(ref attrs) = signer_info.signed_attrs {
        for attr in attrs.iter() {
            if attr.oid == md_oid
                && let Some(value) = attr.values.get(0)
            {
                let value_bytes = value.to_der().map_err(|_| AuthError::InvalidHeader)?;
                let oct =
                    OctetStringRef::from_der(&value_bytes).map_err(|_| AuthError::InvalidHeader)?;
                return Ok(Some(oct.as_bytes().to_vec()));
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
                if let Ok(cert) = parse_cert(cert_der) {
                    let tbs = &cert.tbs_certificate;
                    // Compare issuer (DER-encoded) and serial number
                    if let Ok(cert_issuer_der) = tbs.issuer.to_der()
                        && let Ok(signer_issuer_der) = issuer_and_serial.issuer.to_der()
                        && cert_issuer_der == signer_issuer_der
                        && tbs.serial_number.as_bytes()
                            == issuer_and_serial.serial_number.as_bytes()
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
    let cert = Certificate::from_der(cert_der).map_err(|_| AuthError::CertificateParseError)?;

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER {
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

// ============================================================================
// Full Certificate Chain Building
// ============================================================================

/// Build and verify a complete certificate chain from end-entity to trust anchor
///
/// This function implements full certificate chain building that supports
/// arbitrary chain depths (up to the configured maximum), proper path validation,
/// and optional revocation checking.
///
/// # Arguments
///
/// * `end_entity_der` - The end-entity (signer) certificate in DER format
/// * `trust_anchor_der` - The trusted root certificate in DER format  
/// * `intermediates` - Pool of intermediate certificates to use for chain building
/// * `config` - Chain building configuration
///
/// # Returns
///
/// On success, returns the validated certificate chain.
/// On failure, returns an appropriate AuthError.
pub fn build_and_verify_chain(
    end_entity_der: &[u8],
    trust_anchor_der: &[u8],
    intermediates: &[Vec<u8>],
    config: &ChainBuildingConfig,
) -> Result<CertificateChain, AuthError> {
    log::debug!(
        "Building certificate chain (max depth: {}, intermediates available: {})",
        config.max_depth,
        intermediates.len()
    );

    // Parse the end-entity and trust anchor certificates
    let end_entity = parse_cert(end_entity_der)?;
    let trust_anchor = parse_cert(trust_anchor_der)?;

    // Quick check: is the end-entity directly the trust anchor?
    if end_entity.tbs_certificate.subject == trust_anchor.tbs_certificate.subject
        && end_entity.tbs_certificate.serial_number.as_bytes()
            == trust_anchor.tbs_certificate.serial_number.as_bytes()
    {
        // Self-signed or directly trusted - verify the chain
        if verify_single_cert(end_entity_der, trust_anchor_der, config)? {
            return Ok(CertificateChain {
                certificates: vec![end_entity_der.to_vec()],
            });
        }
    }

    // Quick check: is the end-entity directly issued by the trust anchor?
    if end_entity.tbs_certificate.issuer == trust_anchor.tbs_certificate.subject
        && verify_single_cert(end_entity_der, trust_anchor_der, config)?
    {
        return Ok(CertificateChain {
            certificates: vec![end_entity_der.to_vec(), trust_anchor_der.to_vec()],
        });
    }

    // Need to build a chain through intermediates
    let mut chain = vec![end_entity_der.to_vec()];

    // Use recursive chain building with cycle detection (DER-encoded subjects)
    let mut visited: Vec<Vec<u8>> = vec![
        end_entity
            .tbs_certificate
            .subject
            .to_der()
            .map_err(|_| AuthError::CertificateParseError)?,
    ];

    match build_chain_recursive(
        &end_entity,
        end_entity_der,
        &trust_anchor,
        trust_anchor_der,
        intermediates,
        &mut chain,
        &mut visited,
        1, // Current depth (end-entity is depth 0)
        config,
    ) {
        Ok(()) => {
            // Chain building succeeded
            log::info!(
                "Successfully built certificate chain with {} certificates",
                chain.len()
            );
            Ok(CertificateChain {
                certificates: chain,
            })
        }
        Err(e) => {
            log::debug!("Chain building failed: {:?}", e);
            Err(e)
        }
    }
}

/// Recursively build the certificate chain
fn build_chain_recursive(
    current_cert: &Certificate,
    current_cert_der: &[u8],
    trust_anchor: &Certificate,
    trust_anchor_der: &[u8],
    intermediates: &[Vec<u8>],
    chain: &mut Vec<Vec<u8>>,
    visited: &mut Vec<Vec<u8>>,
    depth: usize,
    config: &ChainBuildingConfig,
) -> Result<(), AuthError> {
    // Check maximum depth
    if depth >= config.max_depth {
        log::warn!(
            "Certificate chain depth {} exceeds maximum {}",
            depth,
            config.max_depth
        );
        return Err(AuthError::ChainTooDeep);
    }

    // Check if current cert is issued by trust anchor
    if current_cert.tbs_certificate.issuer == trust_anchor.tbs_certificate.subject {
        // Verify this link
        if verify_chain_link(current_cert_der, trust_anchor_der, config)? {
            chain.push(trust_anchor_der.to_vec());
            return Ok(());
        }
    }

    // Search for an intermediate that issued the current certificate
    for intermediate_der in intermediates {
        if let Ok(intermediate) = parse_cert(intermediate_der) {
            // Check if this intermediate issued the current certificate
            if current_cert.tbs_certificate.issuer != intermediate.tbs_certificate.subject {
                continue;
            }

            // Check for cycles (prevent infinite loops) using DER-encoded subjects
            let intermediate_subject_der = intermediate
                .tbs_certificate
                .subject
                .to_der()
                .map_err(|_| AuthError::CertificateParseError)?;
            if visited.contains(&intermediate_subject_der) {
                log::debug!("Cycle detected in certificate chain");
                continue;
            }

            // Verify the chain link
            if !verify_chain_link(current_cert_der, intermediate_der, config)? {
                continue;
            }

            // Check revocation status of intermediate if enabled
            if config.check_revocation {
                // Find the issuer of this intermediate for revocation checking
                let issuer_der = if intermediate.tbs_certificate.issuer
                    == trust_anchor.tbs_certificate.subject
                {
                    Some(trust_anchor_der)
                } else {
                    intermediates
                        .iter()
                        .find(|c| {
                            parse_cert(c)
                                .map(|p| {
                                    p.tbs_certificate.subject == intermediate.tbs_certificate.issuer
                                })
                                .unwrap_or(false)
                        })
                        .map(|v| v.as_slice())
                };

                if let Some(issuer) = issuer_der {
                    match check_certificate_revocation(
                        intermediate_der,
                        issuer,
                        &config.revocation_config,
                        config.current_time,
                    ) {
                        RevocationCheckResult::Revoked { reason, .. } => {
                            log::warn!("Intermediate certificate is revoked: {:?}", reason);
                            return Err(AuthError::CertificateRevoked);
                        }
                        RevocationCheckResult::Good => {
                            log::debug!("Intermediate certificate revocation check: good");
                        }
                        RevocationCheckResult::Unknown => {
                            if !config.revocation_config.allow_soft_fail {
                                log::warn!("Could not determine intermediate revocation status");
                                return Err(AuthError::CryptoError);
                            }
                        }
                        RevocationCheckResult::Skipped => {
                            // Soft-fail mode
                        }
                    }
                }
            }

            // Add intermediate to chain and continue building
            chain.push(intermediate_der.clone());
            visited.push(intermediate_subject_der);

            // Recursively continue building the chain
            match build_chain_recursive(
                &intermediate,
                intermediate_der,
                trust_anchor,
                trust_anchor_der,
                intermediates,
                chain,
                visited,
                depth + 1,
                config,
            ) {
                Ok(()) => return Ok(()),
                Err(_) => {
                    // This path didn't work, backtrack
                    chain.pop();
                    visited.pop();
                    continue;
                }
            }
        }
    }

    // No valid path found
    Err(AuthError::ChainBuildingFailed)
}

/// Verify a single link in the certificate chain
fn verify_chain_link(
    cert_der: &[u8],
    issuer_der: &[u8],
    config: &ChainBuildingConfig,
) -> Result<bool, AuthError> {
    let cert = parse_cert(cert_der)?;
    let issuer = parse_cert(issuer_der)?;

    // Check issuer/subject match
    if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Ok(false);
    }

    // Validate certificate time
    if let Err(e) = validate_certificate_time(cert_der) {
        log::debug!("Certificate validity check failed: {:?}", e);
        return Ok(false);
    }

    // Validate issuer can act as CA (if required)
    if config.require_basic_constraints
        && let Err(e) = validate_basic_constraints_for_ca(issuer_der)
    {
        log::debug!("Issuer basicConstraints check failed: {:?}", e);
        return Ok(false);
    }

    if config.require_key_usage
        && let Err(e) = validate_key_usage_for_ca(issuer_der)
    {
        log::debug!("Issuer keyUsage check failed: {:?}", e);
        return Ok(false);
    }

    // Verify the signature
    let cert_signature = cert.signature.raw_bytes();
    let tbs_bytes = extract_tbs_bytes(cert_der)?;
    let tbs_hash = sha256(tbs_bytes);
    let issuer_rsa_key = extract_rsa_key(&issuer)?;

    verify_rsa_signature_raw(&issuer_rsa_key, cert_signature, &tbs_hash)
}

/// Verify a single certificate against a trust anchor (for direct trust)
fn verify_single_cert(
    cert_der: &[u8],
    trust_anchor_der: &[u8],
    config: &ChainBuildingConfig,
) -> Result<bool, AuthError> {
    let cert = parse_cert(cert_der)?;
    let trust_anchor = parse_cert(trust_anchor_der)?;

    let tbs = &cert.tbs_certificate;
    // For self-signed certs, verify signature against self
    let issuer_der = if tbs.issuer == tbs.subject {
        cert_der
    } else if tbs.issuer == trust_anchor.tbs_certificate.subject {
        trust_anchor_der
    } else {
        return Ok(false);
    };

    verify_chain_link(cert_der, issuer_der, config)
}

/// Verify a certificate chain with full revocation checking
///
/// This function verifies an already-built certificate chain, checking:
/// - Each certificate's validity period
/// - Each certificate's signature
/// - CA constraints (basicConstraints, keyUsage)
/// - Path length constraints
/// - Revocation status (if enabled)
///
/// # Arguments
///
/// * `chain` - The certificate chain to verify
/// * `config` - Verification configuration
///
/// # Returns
///
/// `Ok(())` if the chain is valid, otherwise an appropriate error.
pub fn verify_certificate_chain(
    chain: &CertificateChain,
    config: &ChainBuildingConfig,
) -> Result<(), AuthError> {
    if chain.is_empty() {
        return Err(AuthError::ChainBuildingFailed);
    }

    // Verify each link in the chain
    for i in 0..chain.certificates.len() - 1 {
        let cert_der = &chain.certificates[i];
        let issuer_der = &chain.certificates[i + 1];

        // Verify the chain link
        if !verify_chain_link(cert_der, issuer_der, config)? {
            log::warn!("Chain link verification failed at index {}", i);
            return Err(AuthError::SignatureVerificationFailed);
        }

        // Check path length constraints
        if let Ok(Some(bc)) = extract_basic_constraints(issuer_der)
            && let Some(path_len) = bc.path_len_constraint
        {
            // Path length constraint limits how many certificates can follow
            // the CA in the path (not including the CA itself)
            let remaining = chain.certificates.len() - i - 2;
            if remaining > path_len as usize {
                log::warn!(
                    "Path length constraint violated: {} > {} at index {}",
                    remaining,
                    path_len,
                    i + 1
                );
                return Err(AuthError::ChainTooDeep);
            }
        }

        // Check revocation if enabled
        if config.check_revocation {
            match check_certificate_revocation(
                cert_der,
                issuer_der,
                &config.revocation_config,
                config.current_time,
            ) {
                RevocationCheckResult::Revoked { reason, .. } => {
                    log::warn!("Certificate at index {} is revoked: {:?}", i, reason);
                    return Err(AuthError::CertificateRevoked);
                }
                RevocationCheckResult::Good => {
                    log::debug!("Certificate at index {} revocation check: good", i);
                }
                RevocationCheckResult::Unknown => {
                    if !config.revocation_config.allow_soft_fail {
                        log::warn!("Could not determine revocation status for index {}", i);
                        return Err(AuthError::CryptoError);
                    }
                    log::debug!("Revocation status unknown for index {} (soft-fail)", i);
                }
                RevocationCheckResult::Skipped => {
                    log::debug!("Revocation check skipped for index {}", i);
                }
            }
        }
    }

    log::info!("Certificate chain verification successful");
    Ok(())
}

/// Validate a certificate's validity period (notBefore/notAfter)
///
/// Checks that the current time is within the certificate's validity period.
/// This prevents use of expired or not-yet-valid certificates.
fn validate_certificate_time(cert_der: &[u8]) -> Result<(), AuthError> {
    let cert = parse_cert(cert_der)?;
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

// ============================================================================
// Certificate Extension Validation (basicConstraints, keyUsage)
// ============================================================================

/// Validate that a certificate can be used as a CA (issuer)
///
/// Per RFC 5280 Section 4.2.1.9:
/// - If basicConstraints is present, cA must be TRUE
/// - For PKIX-compliant CAs, basicConstraints MUST be present with cA=TRUE
///
/// Returns Ok(()) if the certificate can be used as a CA.
pub fn validate_basic_constraints_for_ca(cert_der: &[u8]) -> Result<(), AuthError> {
    match extract_basic_constraints(cert_der) {
        Ok(Some(bc)) => {
            if bc.ca {
                log::debug!("Certificate has basicConstraints CA:TRUE");
                Ok(())
            } else {
                log::warn!("Certificate has basicConstraints but CA:FALSE");
                Err(AuthError::CertificateNotCA)
            }
        }
        Ok(None) => {
            // No basicConstraints extension - this is an end-entity certificate
            // It cannot be used as a CA to sign other certificates
            log::warn!("Certificate missing basicConstraints extension - cannot be used as CA");
            Err(AuthError::CertificateNotCA)
        }
        Err(e) => Err(e),
    }
}

/// Validate that a certificate has appropriate keyUsage for signing other certificates
///
/// Per RFC 5280 Section 4.2.1.3:
/// - The keyCertSign bit MUST be asserted when the certificate is used to verify
///   a signature on a certificate
///
/// Returns Ok(()) if the certificate can be used to sign other certificates.
pub fn validate_key_usage_for_ca(cert_der: &[u8]) -> Result<(), AuthError> {
    match extract_key_usage(cert_der) {
        Ok(Some(ku)) => {
            if ku.key_cert_sign() {
                log::debug!("Certificate has keyUsage with keyCertSign");
                Ok(())
            } else {
                log::warn!(
                    "Certificate has keyUsage but keyCertSign not set (bits: {:04x})",
                    ku.0.bits()
                );
                Err(AuthError::InvalidKeyUsage)
            }
        }
        Ok(None) => {
            // No keyUsage extension
            // Per RFC 5280, if the extension is absent, all key usages are allowed
            // However, for security, we should warn but allow for compatibility
            // with older certificates that may not have keyUsage
            log::debug!("Certificate has no keyUsage extension - allowing for compatibility");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Validate that a certificate has appropriate keyUsage for code signing
///
/// For Authenticode verification, the signing certificate should have
/// digitalSignature set (bit 0).
///
/// Returns Ok(()) if the certificate can be used for code signing.
pub fn validate_key_usage_for_code_signing(cert_der: &[u8]) -> Result<(), AuthError> {
    match extract_key_usage(cert_der) {
        Ok(Some(ku)) => {
            if ku.digital_signature() {
                log::debug!("Certificate has keyUsage with digitalSignature");
                Ok(())
            } else {
                log::warn!(
                    "Certificate has keyUsage but digitalSignature not set (bits: {:04x})",
                    ku.0.bits()
                );
                Err(AuthError::InvalidKeyUsage)
            }
        }
        Ok(None) => {
            // No keyUsage extension - allow for compatibility
            log::debug!("Certificate has no keyUsage extension - allowing for compatibility");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Extract the basicConstraints extension from a certificate
fn extract_basic_constraints(cert_der: &[u8]) -> Result<Option<X509BasicConstraints>, AuthError> {
    let cert = Certificate::from_der(cert_der).map_err(|_| AuthError::CertificateParseError)?;

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id == const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS {
                let bc = X509BasicConstraints::from_der(ext.extn_value.as_bytes())
                    .map_err(|_| AuthError::CertificateParseError)?;
                return Ok(Some(bc));
            }
        }
    }

    Ok(None)
}

/// Extract the keyUsage extension from a certificate
fn extract_key_usage(cert_der: &[u8]) -> Result<Option<X509KeyUsage>, AuthError> {
    let cert = Certificate::from_der(cert_der).map_err(|_| AuthError::CertificateParseError)?;

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id == const_oid::db::rfc5280::ID_CE_KEY_USAGE {
                let ku = X509KeyUsage::from_der(ext.extn_value.as_bytes())
                    .map_err(|_| AuthError::CertificateParseError)?;
                return Ok(Some(ku));
            }
        }
    }

    Ok(None)
}

/// Parse X.509 Time (UTCTime or GeneralizedTime) to Unix timestamp
fn parse_x509_time(t: &x509_cert::time::Time) -> Result<i64, AuthError> {
    time::x509_time_to_unix(t)
}

/// Get current time for certificate validation
///
/// Returns Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
fn get_current_time_for_cert_validation() -> i64 {
    time::current_unix_timestamp()
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
    use der::{Reader, SliceReader};

    let mut reader = SliceReader::new(cert_der).map_err(|_| AuthError::CertificateParseError)?;
    // Enter the outer SEQUENCE (Certificate), then read the first TLV (TBSCertificate)
    reader
        .sequence(|seq| seq.tlv_bytes())
        .map_err(|_| AuthError::CertificateParseError)
}

// ============================================================================
// Certificate Helpers
// ============================================================================

/// Parse a DER-encoded X.509 certificate
fn parse_cert(cert_der: &[u8]) -> Result<Certificate, AuthError> {
    Certificate::from_der(cert_der).map_err(|e| {
        log::debug!("Failed to parse X.509 certificate: {:?}", e);
        AuthError::CertificateParseError
    })
}

/// Extract the RSA public key from a parsed certificate's SPKI
fn extract_rsa_key(cert: &Certificate) -> Result<rsa::RsaPublicKey, AuthError> {
    let spki_ref = cert.tbs_certificate.subject_public_key_info.owned_to_ref();
    rsa::RsaPublicKey::try_from(spki_ref).map_err(|e| {
        log::debug!("Failed to extract RSA public key from SPKI: {:?}", e);
        AuthError::CertificateParseError
    })
}

/// Validate that DER data is a parseable X.509 certificate
///
/// Used by external modules (e.g. key_files) to validate certificate data.
pub fn validate_x509_certificate(cert_der: &[u8]) -> Result<(), AuthError> {
    parse_cert(cert_der)?;
    Ok(())
}

/// Trim trailing bytes from a DER-encoded structure
///
/// WIN_CERTIFICATE structures are 8-byte aligned, which means the PKCS#7
/// data may have padding bytes after the actual DER content. This function
/// reads the DER length and returns a slice containing only the valid data.
fn trim_der_trailing_bytes(data: &[u8]) -> Result<&[u8], AuthError> {
    use der::{Reader, SliceReader};

    let mut reader = SliceReader::new(data).map_err(|_| AuthError::InvalidHeader)?;
    // Read exactly one TLV, ignoring any trailing padding bytes
    reader.tlv_bytes().map_err(|_| AuthError::InvalidHeader)
}

// ============================================================================
// RSA Signature Verification
// ============================================================================

/// Verify an RSA PKCS#1 v1.5 signature against a pre-computed SHA-256 hash
///
/// Uses `PrehashVerifier::verify_prehash` because callers pass an already-computed
/// SHA-256 digest. The `VerifyingKey::new()` constructor ensures the DigestInfo
/// prefix includes the SHA-256 OID, preventing algorithm substitution attacks.
///
/// # Arguments
///
/// * `public_key` - The RSA public key to verify against
/// * `signature` - The raw signature bytes
/// * `message_hash` - Pre-computed SHA-256 hash of the signed data
fn verify_rsa_signature_raw(
    public_key: &rsa::RsaPublicKey,
    signature: &[u8],
    message_hash: &[u8; 32],
) -> Result<bool, AuthError> {
    use rsa::signature::hazmat::PrehashVerifier;

    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key.clone());

    let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(|e| {
        log::debug!("Failed to parse signature: {:?}", e);
        AuthError::CryptoError
    })?;

    // CRITICAL: Use verify_prehash since message_hash is already a SHA-256 digest.
    // The previous code used Verifier::verify which internally calls D::digest(msg),
    // resulting in SHA-256(SHA-256(TBS)) — a double-hash bug.
    match verifying_key.verify_prehash(message_hash, &sig) {
        Ok(()) => Ok(true),
        Err(e) => {
            log::debug!("RSA signature verification failed: {:?}", e);
            Ok(false)
        }
    }
}
