//! Cryptographic Operations for Secure Boot
//!
//! This module implements cryptographic operations required for UEFI Secure Boot:
//! - SHA-256 hashing
//! - PKCS#7/CMS signature verification (parsed via [`super::asn1_views`])
//! - X.509 certificate parsing
//! - RSA signature verification
//! - Full certificate chain building and validation
//! - Certificate revocation checking (CRL)

use super::AuthError;
use super::asn1_views;
use super::revocation::{RevocationCheckResult, RevocationConfig, check_certificate_revocation};
use super::time;
use alloc::vec;
use alloc::vec::Vec;

use crabefi_efi_types::constant_time_eq;
use rsa::pkcs1::DecodeRsaPublicKey;
use sha2::{Digest, Sha256};

// ============================================================================
// Certificate Chain Building Configuration
// ============================================================================

/// Maximum certificate chain depth for normal operations.
/// Prevents infinite loops and excessive resource consumption.
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
    /// Whether to check certificate validity periods (notBefore/notAfter)
    /// Set to false for Secure Boot image verification, matching edk2/u-boot behavior
    /// which do not enforce certificate expiry for firmware signing certificates.
    pub check_validity_period: bool,
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
            check_validity_period: true,
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
    // WIN_CERTIFICATE is 8-byte aligned, so there may be trailing padding bytes
    // after the actual PKCS#7 content. We need to calculate the real DER length
    // and only parse that portion.
    let actual_pkcs7 = trim_der_trailing_bytes(pkcs7_data)?;

    // Parse the PKCS#7 ContentInfo structure (requires signedData).
    let pkcs7 = asn1_views::parse_signed_data(actual_pkcs7).map_err(|e| {
        log::debug!("Failed to parse PKCS#7 SignedData: {:?}", e);
        AuthError::InvalidHeader
    })?;

    // Validate the trusted certificate from db can be parsed
    parse_cert_view(trusted_cert)?;

    // Embedded certificates are already borrowed slices; collect for logging.
    log::debug!(
        "PKCS#7 contains {} embedded certificates",
        pkcs7.certs.len()
    );

    // Compute the content digest for messageDigest verification.
    //
    // Per RFC 5652 Section 5.4, the messageDigest attribute value must match
    // the digest of the encapContentInfo eContent value.
    //
    // Both edk2 and u-boot hash the VALUE (V) portion of the ASN.1 element
    // inside the [0] EXPLICIT tag -- i.e., the bytes after stripping the outer
    // tag and length. For Authenticode (SEQUENCE), this is the inner content
    // of the SpcIndirectDataContent. For standard CMS (OCTET STRING), this is
    // the raw content bytes.
    //
    // - For attached content (e.g., Authenticode): hash the captured input
    // - For detached signatures (e.g., authenticated variables): hash the external data
    let computed_hash = if let Some(econtent) = pkcs7.econtent_hash_input {
        sha256(econtent)
    } else {
        // Detached signature: hash the externally-provided signed data
        sha256(signed_data)
    };

    // Get SignerInfos and verify the signature
    if pkcs7.signers.is_empty() {
        log::warn!("PKCS#7 contains no SignerInfo");
        return Err(AuthError::InvalidHeader);
    }

    // Verify each signer info
    for signer_info in pkcs7.signers.iter() {
        // The messageDigest from signed attributes (if present) contains the
        // hash that was actually signed.
        let message_digest = signer_info.message_digest.as_deref();

        // CRITICAL: Verify the messageDigest matches the hash of the actual data
        // This prevents signature replay attacks
        if let Some(md) = message_digest {
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
        let signature = signer_info.signature;

        // Find the signing certificate in the embedded certs
        let signer_cert_der = find_signer_certificate(signer_info, &pkcs7.certs)?;

        if let Some(signer_der) = signer_cert_der {
            let signer_cert = parse_cert_view(&signer_der)?;
            let signer_rsa_key = extract_rsa_key(&signer_cert)?;

            // Build the data that was signed (signed attributes or content)
            let data_to_verify =
                build_signed_attrs_digest(signer_info.signed_attrs_der.as_deref(), &computed_hash);

            // CRITICAL: Verify the RSA signature cryptographically
            match verify_rsa_signature_raw(&signer_rsa_key, signature, &data_to_verify) {
                Ok(true) => {
                    log::debug!("RSA signature verification succeeded");

                    // Build and verify the certificate chain using the full chain building algorithm
                    // Disable validity period checking: UEFI Secure Boot does not enforce
                    // certificate expiry for image verification, matching edk2 and u-boot behavior.
                    let config = ChainBuildingConfig {
                        check_validity_period: false,
                        ..ChainBuildingConfig::default()
                    };

                    // Try to build a chain from the signer certificate to the trusted certificate
                    match build_and_verify_chain(&signer_der, trusted_cert, &pkcs7.certs, &config) {
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

/// Find the certificate that corresponds to a SignerInfo
fn find_signer_certificate(
    signer_info: &asn1_views::SignerView<'_>,
    embedded_certs: &[&[u8]],
) -> Result<Option<Vec<u8>>, AuthError> {
    use asn1_views::SignerId;

    match &signer_info.sid {
        SignerId::IssuerAndSerial { issuer_der, serial } => {
            // Find cert matching issuer and serial number
            for cert_der in embedded_certs {
                if let Ok(cert) = parse_cert_view(cert_der) {
                    // Compare issuer (DER-encoded) and serial number
                    if cert.issuer_der == *issuer_der && cert.serial == *serial {
                        return Ok(Some(cert_der.to_vec()));
                    }
                }
            }
        }
        SignerId::SubjectKeyId(ski_bytes) => {
            // Find cert matching subject key identifier
            for cert_der in embedded_certs {
                if let Ok(ski_from_cert) = extract_subject_key_identifier(cert_der)
                    && ski_from_cert == *ski_bytes
                {
                    return Ok(Some(cert_der.to_vec()));
                }
            }
        }
    }
    Ok(None)
}

/// Extract Subject Key Identifier from a certificate
///
/// Returns the raw key-identifier bytes. Conformant extensions wrap the
/// identifier in an inner OCTET STRING (which is unwrapped); a bare byte
/// string is accepted as-is for compatibility. Note the previous
/// implementation compared the still-wrapped value, so SKI-identified
/// signers could never match (always fell through to `Ok(false)`).
fn extract_subject_key_identifier(cert_der: &[u8]) -> Result<Vec<u8>, AuthError> {
    let cert = parse_cert_view(cert_der)?;
    let Some(extensions_der) = cert.extensions_der else {
        return Err(AuthError::CertificateParseError);
    };
    let outer = asn1_views::find_extension(extensions_der, asn1_views::OID_SUBJECT_KEY_ID)?
        .ok_or(AuthError::CertificateParseError)?;
    // Selection is not trust (RSA + chain must still verify), so tolerate
    // both the conformant double-wrapped and bare encodings.
    Ok(asn1::parse_single::<&[u8]>(outer)
        .map(|bytes| bytes.to_vec())
        .unwrap_or_else(|_| outer.to_vec()))
}

/// Build the digest of signed attributes for verification
fn build_signed_attrs_digest(signed_attrs_der: Option<&[u8]>, content_hash: &[u8; 32]) -> [u8; 32] {
    if let Some(attrs_der) = signed_attrs_der {
        // Hash the DER-encoded signed attributes (with SET OF tag)
        sha256(attrs_der)
    } else {
        // No signed attributes - hash the content directly
        *content_hash
    }
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
    intermediates: &[&[u8]],
    config: &ChainBuildingConfig,
) -> Result<CertificateChain, AuthError> {
    log::debug!(
        "Building certificate chain (max depth: {}, intermediates available: {})",
        config.max_depth,
        intermediates.len()
    );

    // Parse the end-entity and trust anchor certificates
    let end_entity = parse_cert_view(end_entity_der)?;
    let trust_anchor = parse_cert_view(trust_anchor_der)?;

    // Quick check: is the end-entity directly the trust anchor?
    if end_entity.subject_der == trust_anchor.subject_der
        && end_entity.serial == trust_anchor.serial
    {
        // Self-signed or directly trusted - verify the chain
        if verify_single_cert(end_entity_der, trust_anchor_der, config)? {
            return Ok(CertificateChain {
                certificates: vec![end_entity_der.to_vec()],
            });
        }
    }

    // Quick check: is the end-entity directly issued by the trust anchor?
    if end_entity.issuer_der == trust_anchor.subject_der
        && verify_single_cert(end_entity_der, trust_anchor_der, config)?
    {
        return Ok(CertificateChain {
            certificates: vec![end_entity_der.to_vec(), trust_anchor_der.to_vec()],
        });
    }

    // Need to build a chain through intermediates
    let mut chain = vec![end_entity_der.to_vec()];

    // Use recursive chain building with cycle detection (DER-encoded subjects)
    let mut visited: Vec<Vec<u8>> = vec![end_entity.subject_der.to_vec()];

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
// Chain state threads through each recursion level; grouping it would hide
// which state each level reads versus mutates.
#[allow(clippy::too_many_arguments)]
fn build_chain_recursive(
    current_cert: &asn1_views::CertView<'_>,
    current_cert_der: &[u8],
    trust_anchor: &asn1_views::CertView<'_>,
    trust_anchor_der: &[u8],
    intermediates: &[&[u8]],
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
    if current_cert.issuer_der == trust_anchor.subject_der {
        // Verify this link
        if verify_chain_link(current_cert_der, trust_anchor_der, config)? {
            chain.push(trust_anchor_der.to_vec());
            return Ok(());
        }
    }

    // Search for an intermediate that issued the current certificate
    for intermediate_der in intermediates {
        if let Ok(intermediate) = parse_cert_view(intermediate_der) {
            // Check if this intermediate issued the current certificate
            if current_cert.issuer_der != intermediate.subject_der {
                continue;
            }

            // Check for cycles (prevent infinite loops) using DER-encoded subjects
            let intermediate_subject_der = intermediate.subject_der.to_vec();
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
                let issuer_der = if intermediate.issuer_der == trust_anchor.subject_der {
                    Some(trust_anchor_der)
                } else {
                    intermediates
                        .iter()
                        .find(|c| {
                            parse_cert_view(c)
                                .map(|p| p.subject_der == intermediate.issuer_der)
                                .unwrap_or(false)
                        })
                        .copied()
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
            chain.push(intermediate_der.to_vec());
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
    let cert = parse_cert_view(cert_der)?;
    let issuer = parse_cert_view(issuer_der)?;

    // Check issuer/subject match
    if cert.issuer_der != issuer.subject_der {
        return Ok(false);
    }

    // Validate certificate time (skipped for Secure Boot image verification)
    if config.check_validity_period
        && let Err(e) = validate_certificate_time(cert_der)
    {
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
    let tbs_hash = sha256(cert.tbs_der);
    let issuer_rsa_key = match extract_rsa_key(&issuer) {
        Ok(key) => key,
        Err(e) => {
            log::debug!("extract_rsa_key failed for issuer: {:?}", e);
            return Err(e);
        }
    };

    verify_rsa_signature_raw(&issuer_rsa_key, cert.signature, &tbs_hash)
}

/// Verify a single certificate against a trust anchor (for direct trust)
///
/// Per the UEFI specification, certificates in the db are explicit trust
/// anchors for image verification.  When the signer certificate IS the db
/// certificate (direct trust), we must NOT enforce CA-only extensions
/// (basicConstraints, keyUsage) because tools like `sbctl` generate plain
/// end-entity certificates without CA:TRUE.  edk2 and u-boot behave the
/// same way — the db is a flat allow-list, not a CA trust store.
fn verify_single_cert(
    cert_der: &[u8],
    trust_anchor_der: &[u8],
    config: &ChainBuildingConfig,
) -> Result<bool, AuthError> {
    let cert = parse_cert_view(cert_der)?;
    let trust_anchor = parse_cert_view(trust_anchor_der)?;

    // For self-signed certs, verify signature against self
    let issuer_der = if cert.issuer_der == cert.subject_der {
        cert_der
    } else if cert.issuer_der == trust_anchor.subject_der {
        trust_anchor_der
    } else {
        return Ok(false);
    };

    // For direct trust (cert is directly in db), relax CA-only checks.
    // The db entry is an explicit trust anchor — its extensions are irrelevant.
    let relaxed_config = ChainBuildingConfig {
        max_depth: config.max_depth,
        check_revocation: config.check_revocation,
        revocation_config: Default::default(),
        current_time: config.current_time,
        require_basic_constraints: false,
        require_key_usage: false,
        check_validity_period: config.check_validity_period,
    };

    verify_chain_link(cert_der, issuer_der, &relaxed_config)
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
    for (i, pair) in chain.certificates.windows(2).enumerate() {
        let cert_der = &pair[0];
        let issuer_der = &pair[1];

        // Verify the chain link
        if !verify_chain_link(cert_der, issuer_der, config)? {
            log::warn!("Chain link verification failed at index {}", i);
            return Err(AuthError::SignatureVerificationFailed);
        }

        // Check path length constraints
        if let Ok(Some(bc)) = extract_basic_constraints(issuer_der)
            && let Some(path_len) = bc.path_len
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
    let cert = parse_cert_view(cert_der)?;

    // Get current time from the system
    // Note: In a real implementation, this should come from a trusted time source
    let current_time = get_current_time_for_cert_validation();

    // Check if current time is before notBefore
    if current_time < cert.not_before {
        log::warn!(
            "Certificate not yet valid: notBefore={}, current={}",
            cert.not_before,
            current_time
        );
        return Err(AuthError::CertificateNotYetValid);
    }

    // Check if current time is after notAfter
    if current_time > cert.not_after {
        log::warn!(
            "Certificate expired: notAfter={}, current={}",
            cert.not_after,
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
            if ku.key_cert_sign {
                log::debug!("Certificate has keyUsage with keyCertSign");
                Ok(())
            } else {
                log::warn!(
                    "Certificate has keyUsage but keyCertSign not set (bits: {:04x})",
                    ku.bits
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
            if ku.digital_signature {
                log::debug!("Certificate has keyUsage with digitalSignature");
                Ok(())
            } else {
                log::warn!(
                    "Certificate has keyUsage but digitalSignature not set (bits: {:04x})",
                    ku.bits
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
fn extract_basic_constraints(
    cert_der: &[u8],
) -> Result<Option<asn1_views::BasicConstraints>, AuthError> {
    let cert = parse_cert_view(cert_der)?;
    let Some(extensions_der) = cert.extensions_der else {
        return Ok(None);
    };
    let Some(value) =
        asn1_views::find_extension(extensions_der, asn1_views::OID_BASIC_CONSTRAINTS)?
    else {
        return Ok(None);
    };
    asn1_views::parse_basic_constraints(value).map(Some)
}

/// Extract the keyUsage extension from a certificate
fn extract_key_usage(cert_der: &[u8]) -> Result<Option<asn1_views::KeyUsageBits>, AuthError> {
    let cert = parse_cert_view(cert_der)?;
    let Some(extensions_der) = cert.extensions_der else {
        return Ok(None);
    };
    let Some(value) = asn1_views::find_extension(extensions_der, asn1_views::OID_KEY_USAGE)? else {
        return Ok(None);
    };
    asn1_views::parse_key_usage(value).map(Some)
}

/// Get current time for certificate validation
///
/// Returns Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
fn get_current_time_for_cert_validation() -> i64 {
    time::current_unix_timestamp()
}

/// Parse a DER-encoded X.509 certificate
fn parse_cert_view(cert_der: &[u8]) -> Result<asn1_views::CertView<'_>, AuthError> {
    asn1_views::parse_cert_view(cert_der).map_err(|e| {
        log::debug!("Failed to parse X.509 certificate: {:?}", e);
        AuthError::CertificateParseError
    })
}

/// Extract the RSA public key from a parsed certificate's SPKI
fn extract_rsa_key(cert: &asn1_views::CertView<'_>) -> Result<rsa::RsaPublicKey, AuthError> {
    // The SPKI BIT STRING content is the DER RSAPublicKey (PKCS#1).
    rsa::RsaPublicKey::from_pkcs1_der(cert.spki_key_der).map_err(|e| {
        log::debug!("Failed to extract RSA public key from SPKI: {:?}", e);
        AuthError::CertificateParseError
    })
}

/// Validate that DER data is a parseable X.509 certificate
///
/// Used by external modules (e.g. key_files) to validate certificate data.
pub fn validate_x509_certificate(cert_der: &[u8]) -> Result<(), AuthError> {
    parse_cert_view(cert_der)?;
    Ok(())
}

/// Trim trailing bytes from a DER-encoded structure
///
/// WIN_CERTIFICATE structures are 8-byte aligned, which means the PKCS#7
/// data may have padding bytes after the actual DER content. This function
/// reads the DER length and returns a slice containing only the valid data.
pub(super) fn trim_der_trailing_bytes(data: &[u8]) -> Result<&[u8], AuthError> {
    asn1_views::trim_to_first_tlv(data)
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
    use signature::hazmat::PrehashVerifier;

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

#[cfg(test)]
mod fixture_tests {
    use super::*;
    use crate::efi::auth::revocation;

    const CA: &[u8] = include_bytes!("testdata/ca.der");
    const LEAF: &[u8] = include_bytes!("testdata/leaf.der");
    const DATA: &[u8] = include_bytes!("testdata/data.bin");
    const CMS_ATTRS: &[u8] = include_bytes!("testdata/cms_attrs.der");
    const CMS_NOATTR: &[u8] = include_bytes!("testdata/cms_noattr.der");
    const CMS_KEYID: &[u8] = include_bytes!("testdata/cms_keyid.der");
    const CRL_EMPTY: &[u8] = include_bytes!("testdata/crl_empty.der");
    const CRL_ONE: &[u8] = include_bytes!("testdata/crl_one.der");

    #[test]
    fn cert_views_are_sane() {
        let ca = parse_cert_view(CA).unwrap();
        let leaf = parse_cert_view(LEAF).unwrap();
        // Self-signed CA.
        assert_eq!(ca.issuer_der, ca.subject_der);
        assert!(!ca.serial.is_empty() && !leaf.serial.is_empty());
        assert_ne!(ca.serial, leaf.serial);
        assert!(!ca.spki_key_der.is_empty() && !leaf.spki_key_der.is_empty());
        assert!(!ca.signature.is_empty());
        assert!(!ca.tbs_der.is_empty());
        assert!(ca.extensions_der.is_some() && leaf.extensions_der.is_some());
        // Fixtures generated 2026-09-09; validity windows must be sane.
        assert!(ca.not_before > 1_750_000_000);
        assert!(ca.not_after > ca.not_before);
        assert!(leaf.not_before > 1_750_000_000);
        // Leaf issued by CA.
        assert_eq!(leaf.issuer_der, ca.subject_der);
    }

    #[test]
    fn pkcs7_variants_verify() {
        for cms in [CMS_ATTRS, CMS_NOATTR, CMS_KEYID] {
            assert_eq!(
                verify_pkcs7_signature(cms, DATA, CA),
                Ok(true),
                "variant of {} bytes failed",
                cms.len()
            );
        }
    }

    #[test]
    fn pkcs7_tampered_data_rejects() {
        let mut bad = DATA.to_vec();
        bad[0] ^= 0xff;
        assert_eq!(verify_pkcs7_signature(CMS_ATTRS, &bad, CA), Ok(false));
        assert_eq!(verify_pkcs7_signature(CMS_NOATTR, &bad, CA), Ok(false));
    }

    #[test]
    fn pkcs7_garbage_inputs_error() {
        assert!(verify_pkcs7_signature(b"junk", DATA, CA).is_err());
        assert!(verify_pkcs7_signature(CMS_ATTRS, DATA, b"junk").is_err());
        assert!(verify_pkcs7_signature(&[], DATA, CA).is_err());
    }

    #[test]
    fn chain_leaf_to_ca_with_validity() {
        let config = ChainBuildingConfig {
            check_validity_period: true,
            ..ChainBuildingConfig::default()
        };
        let chain = build_and_verify_chain(LEAF, CA, &[], &config).unwrap();
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn ca_constraints_enforced() {
        assert!(validate_basic_constraints_for_ca(CA).is_ok());
        assert_eq!(
            validate_basic_constraints_for_ca(LEAF),
            Err(AuthError::CertificateNotCA)
        );
        assert!(validate_key_usage_for_ca(CA).is_ok());
        assert!(validate_key_usage_for_code_signing(LEAF).is_ok());
    }

    #[test]
    fn crl_accept_and_reject_paths() {
        let empty = revocation::parse_crl(CRL_EMPTY).unwrap();
        let one = revocation::parse_crl(CRL_ONE).unwrap();
        assert!(empty.revoked_certificates.is_empty());
        assert_eq!(one.revoked_certificates.len(), 1);
        // openssl ca -revoke records no reason extension, so the entry
        // carries None (the reason lookup runs and finds nothing).
        assert_eq!(
            revocation::check_crl_revocation(LEAF, &one),
            revocation::RevocationCheckResult::Revoked {
                reason: None,
                revocation_time: one.revoked_certificates[0].revocation_date,
            }
        );
        // CA serial is not listed.
        assert_eq!(
            revocation::check_crl_revocation(CA, &one),
            revocation::RevocationCheckResult::Good
        );
        assert_eq!(
            revocation::check_crl_revocation(LEAF, &empty),
            revocation::RevocationCheckResult::Good
        );
    }

    #[test]
    fn crl_cache_roundtrip() {
        let crl = revocation::parse_crl(CRL_ONE).unwrap();
        let now = crl.this_update;
        revocation::cache_crl(crl, now);
        let config = revocation::RevocationConfig::default();
        // Issuer lookup uses the leaf's issuer (the CA name).
        let leaf = parse_cert_view(LEAF).unwrap();
        let cached = revocation::get_cached_crl(leaf.issuer_der, now, &config).expect("cached CRL");
        assert_eq!(cached.revoked_certificates.len(), 1);
    }
}
