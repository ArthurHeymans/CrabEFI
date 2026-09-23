//! Cryptographic Operations for Secure Boot
//!
//! This module implements cryptographic operations required for UEFI Secure Boot:
//! - SHA-256 hashing
//! - PKCS#7/CMS signature verification over the shared `crabefi-pkcs7` views
//! - Full certificate chain building and validation
//! - Certificate revocation checking (CRL)

use super::AuthError;
use super::revocation::{RevocationCheckResult, RevocationConfig, check_certificate_revocation};
use super::time;
use alloc::vec;
use alloc::vec::Vec;

use crabefi_efi_types::constant_time_eq;
use crabefi_pkcs7::cms::{SignedData, SignerIdentifier};
use crabefi_pkcs7::der::{DecodeError, tag};
use crabefi_pkcs7::oid;
use crabefi_pkcs7::rsa::RsaPublicKey;
use crabefi_pkcs7::x509::{BasicConstraints, Certificate, KeyUsage};
use sha2::{Digest, Sha256};

/// 8192-bit RSA arithmetic width.
const RSA_LIMBS: usize = 128;
/// Largest accepted RSA modulus.
const MAX_RSA_MODULUS_BITS: usize = RSA_LIMBS * 64;
/// Largest accepted RSA public exponent (2^33 - 1).
const MAX_RSA_EXPONENT: u64 = (1 << 33) - 1;

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
/// * `require_detached` - Reject attached eContent when the caller supplies the authenticated payload
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
    require_detached: bool,
) -> Result<bool, AuthError> {
    // WIN_CERTIFICATE is 8-byte aligned, so the parser ignores alignment
    // padding after the ContentInfo.
    let pkcs7 = SignedData::parse(pkcs7_data).map_err(|e| {
        log::debug!("Failed to parse PKCS#7 SignedData: {:?}", e);
        AuthError::InvalidHeader
    })?;
    let signers = pkcs7
        .signers()
        .map(|signer| {
            let signer = signer?;
            // RFC 5652 5.3: messageDigest is mandatory when signedAttrs is
            // present; without it the signature would not bind the content.
            let message_digest = signer
                .signed_attributes
                .map(|attributes| attributes.message_digest())
                .transpose()?;
            Ok((signer, message_digest))
        })
        .collect::<Result<Vec<_>, DecodeError>>()
        .map_err(|e| {
            log::debug!("Failed to parse PKCS#7 SignerInfo: {:?}", e);
            AuthError::InvalidHeader
        })?;

    // Validate the trusted certificate from db can be parsed
    parse_cert_view(trusted_cert)?;

    // Only plain X.509 certificates (SEQUENCE) take part in chain building.
    let embedded_certs: Vec<&[u8]> = pkcs7
        .certificates()
        .filter(|certificate| certificate.tag == tag::SEQUENCE)
        .map(|certificate| certificate.encoded)
        .collect();
    log::debug!(
        "PKCS#7 contains {} embedded certificates",
        embedded_certs.len()
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
    let computed_hash = match pkcs7.encapsulated_content.content {
        Some(_) if require_detached => return Err(AuthError::InvalidHeader),
        Some(econtent) => sha256(econtent.value),
        None => sha256(signed_data),
    };

    if signers.is_empty() {
        log::warn!("PKCS#7 contains no SignerInfo");
        return Err(AuthError::InvalidHeader);
    }

    for (signer_info, message_digest) in &signers {
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

        // Find the signing certificate in the embedded certs
        let Some(signer_der) = find_signer_certificate(signer_info.identifier, &embedded_certs)
        else {
            continue;
        };
        let signer_cert = parse_cert_view(signer_der)?;
        let signer_rsa_key = rsa_public_key(&signer_cert)?;

        // The signature covers the signed attributes when present, otherwise
        // the content digest directly.
        let data_to_verify = signer_info
            .signed_attributes
            .map_or(computed_hash, |attributes| attributes.digest());

        // CRITICAL: Verify the RSA signature cryptographically
        if !verify_rsa_signature(&signer_rsa_key, signer_info.signature, &data_to_verify) {
            log::debug!("RSA signature verification failed");
            continue;
        }
        log::debug!("RSA signature verification succeeded");

        // Build and verify the certificate chain using the full chain building algorithm
        // Disable validity period checking: UEFI Secure Boot does not enforce
        // certificate expiry for image verification, matching edk2 and u-boot behavior.
        let config = ChainBuildingConfig {
            check_validity_period: false,
            ..ChainBuildingConfig::default()
        };

        // Try to build a chain from the signer certificate to the trusted certificate
        match build_and_verify_chain(signer_der, trusted_cert, &embedded_certs, &config) {
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

    log::debug!("No valid signature chain found to trusted db certificate");
    Ok(false)
}

/// Find the certificate that corresponds to a SignerInfo
fn find_signer_certificate<'a>(
    identifier: SignerIdentifier<'_>,
    embedded_certs: &[&'a [u8]],
) -> Option<&'a [u8]> {
    embedded_certs.iter().copied().find(|cert_der| {
        let Ok(cert) = parse_cert_view(cert_der) else {
            return false;
        };
        match identifier {
            SignerIdentifier::IssuerAndSerialNumber { issuer, serial } => {
                cert.issuer == issuer && cert.serial == serial
            }
            SignerIdentifier::SubjectKeyIdentifier(identifier) => {
                subject_key_identifier(&cert) == Some(identifier)
            }
        }
    })
}

/// Subject Key Identifier of a certificate.
///
/// Conformant extensions wrap the identifier in an inner OCTET STRING (which
/// is unwrapped). Selection is not trust (RSA + chain must still verify), so
/// a bare byte string is accepted as-is.
fn subject_key_identifier<'a>(cert: &Certificate<'a>) -> Option<&'a [u8]> {
    cert.subject_key_identifier().unwrap_or_else(|_| {
        cert.extensions
            .find(oid::SUBJECT_KEY_IDENTIFIER)
            .map(|extension| extension.value)
    })
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

    // Quick check: is the end-entity byte-for-byte the trust anchor? The db
    // is a flat allow-list, so exact identity is trusted as-is. Only exact
    // identity counts: a forged self-signed certificate carrying the
    // anchor's subject and serial must never be verified against itself.
    if end_entity_der == trust_anchor_der {
        if config.check_validity_period
            && let Err(e) = validate_certificate_time(end_entity_der)
        {
            log::debug!("Trust anchor validity check failed: {:?}", e);
            return Err(AuthError::ChainBuildingFailed);
        }
        return Ok(CertificateChain {
            certificates: vec![end_entity_der.to_vec()],
        });
    }

    // Quick check: is the end-entity directly issued by the trust anchor?
    if end_entity.issuer == trust_anchor.subject
        && verify_single_cert(end_entity_der, trust_anchor_der, config)?
    {
        return Ok(CertificateChain {
            certificates: vec![end_entity_der.to_vec(), trust_anchor_der.to_vec()],
        });
    }

    // Need to build a chain through intermediates
    let mut chain = vec![end_entity_der.to_vec()];

    // Use recursive chain building with cycle detection (DER-encoded subjects)
    let mut visited: Vec<Vec<u8>> = vec![end_entity.subject.to_vec()];

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
    current_cert: &Certificate<'_>,
    current_cert_der: &[u8],
    trust_anchor: &Certificate<'_>,
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
    if current_cert.issuer == trust_anchor.subject {
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
            if current_cert.issuer != intermediate.subject {
                continue;
            }

            // Check for cycles (prevent infinite loops) using DER-encoded subjects
            let intermediate_subject_der = intermediate.subject.to_vec();
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
                let issuer_der = if intermediate.issuer == trust_anchor.subject {
                    Some(trust_anchor_der)
                } else {
                    intermediates
                        .iter()
                        .find(|c| {
                            parse_cert_view(c)
                                .map(|p| p.subject == intermediate.issuer)
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
    if cert.issuer != issuer.subject {
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
    let tbs_hash = sha256(cert.tbs);
    let issuer_rsa_key = rsa_public_key(&issuer)?;
    Ok(verify_rsa_signature(
        &issuer_rsa_key,
        cert.signature,
        &tbs_hash,
    ))
}

/// Verify a certificate issued directly by a trust anchor.
///
/// Per the UEFI specification, certificates in the db are explicit trust
/// anchors for image verification, so CA-only extensions (basicConstraints,
/// keyUsage) are NOT enforced on the anchor: tools like `sbctl` generate
/// plain end-entity certificates without CA:TRUE. edk2 and u-boot behave
/// the same way — the db is a flat allow-list, not a CA trust store.
fn verify_single_cert(
    cert_der: &[u8],
    trust_anchor_der: &[u8],
    config: &ChainBuildingConfig,
) -> Result<bool, AuthError> {
    let cert = parse_cert_view(cert_der)?;
    let trust_anchor = parse_cert_view(trust_anchor_der)?;
    if cert.issuer != trust_anchor.subject {
        return Ok(false);
    }

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

    verify_chain_link(cert_der, trust_anchor_der, &relaxed_config)
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
    let validity = parse_cert_view(cert_der)?
        .validity()
        .map_err(|_| AuthError::CertificateParseError)?;

    // Get current time from the system
    // Note: In a real implementation, this should come from a trusted time source
    let current_time = get_current_time_for_cert_validation();

    // Check if current time is before notBefore
    if current_time < validity.not_before {
        log::warn!(
            "Certificate not yet valid: notBefore={}, current={}",
            validity.not_before,
            current_time
        );
        return Err(AuthError::CertificateNotYetValid);
    }

    // Check if current time is after notAfter
    if current_time > validity.not_after {
        log::warn!(
            "Certificate expired: notAfter={}, current={}",
            validity.not_after,
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
                    ku.0
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
                    ku.0
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
fn extract_basic_constraints(cert_der: &[u8]) -> Result<Option<BasicConstraints>, AuthError> {
    Ok(parse_cert_view(cert_der)?.basic_constraints()?)
}

/// Extract the keyUsage extension from a certificate
fn extract_key_usage(cert_der: &[u8]) -> Result<Option<KeyUsage>, AuthError> {
    Ok(parse_cert_view(cert_der)?.key_usage()?)
}

/// Get current time for certificate validation
///
/// Returns Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
fn get_current_time_for_cert_validation() -> i64 {
    time::current_unix_timestamp()
}

/// Parse a DER-encoded X.509 certificate with a decodable validity window
pub(super) fn parse_cert_view(cert_der: &[u8]) -> Result<Certificate<'_>, AuthError> {
    Certificate::parse(cert_der)
        .and_then(|cert| cert.validity().map(|_| cert))
        .map_err(|e| {
            log::debug!("Failed to parse X.509 certificate: {:?}", e);
            AuthError::CertificateParseError
        })
}

/// Extract the RSA public key from a parsed certificate's SPKI
///
/// Keys must be well formed, at most 8192 bits, with a public exponent of at
/// most 2^33 - 1.
fn rsa_public_key<'a>(cert: &Certificate<'a>) -> Result<RsaPublicKey<'a>, AuthError> {
    let key = cert.rsa_public_key().map_err(|e| {
        log::debug!("Failed to extract RSA public key from SPKI: {:?}", e);
        AuthError::CertificateParseError
    })?;
    if !key.is_well_formed()
        || key.modulus_bits() > MAX_RSA_MODULUS_BITS
        || key
            .exponent()
            .is_none_or(|exponent| exponent > MAX_RSA_EXPONENT)
    {
        log::debug!("Unsupported RSA public key parameters");
        return Err(AuthError::CertificateParseError);
    }
    Ok(key)
}

/// Validate that DER data is a parseable X.509 certificate
///
/// Used by external modules (e.g. key_files) to validate certificate data.
pub fn validate_x509_certificate(cert_der: &[u8]) -> Result<(), AuthError> {
    parse_cert_view(cert_der)?;
    Ok(())
}

/// Verify an RSA PKCS#1 v1.5 signature against a pre-computed SHA-256 hash
fn verify_rsa_signature(
    public_key: &RsaPublicKey<'_>,
    signature: &[u8],
    message_hash: &[u8; 32],
) -> bool {
    public_key.verify_pkcs1v15_sha256::<RSA_LIMBS>(signature, message_hash)
}

#[cfg(test)]
mod fixture_tests {
    use super::*;
    use crate::efi::auth::revocation;
    use crabefi_pkcs7::der::{Reader, Tlv};

    const CA: &[u8] = include_bytes!("../../../../crabefi-pkcs7/testdata/ca.der");
    const LEAF: &[u8] = include_bytes!("../../../../crabefi-pkcs7/testdata/leaf.der");
    const DATA: &[u8] = include_bytes!("../../../../crabefi-pkcs7/testdata/data.bin");
    const CMS_ATTRS: &[u8] = include_bytes!("../../../../crabefi-pkcs7/testdata/cms_attrs.der");
    const CMS_NOATTR: &[u8] = include_bytes!("../../../../crabefi-pkcs7/testdata/cms_noattr.der");
    const CMS_KEYID: &[u8] = include_bytes!("../../../../crabefi-pkcs7/testdata/cms_keyid.der");
    const CRL_EMPTY: &[u8] = include_bytes!("testdata/crl_empty.der");
    const CRL_ONE: &[u8] = include_bytes!("testdata/crl_one.der");
    /// Self-signed under a different key, but with CA's exact subject and
    /// serial: must never be accepted when CA is the trust anchor.
    const FORGED_CA: &[u8] = include_bytes!("../../../../crabefi-pkcs7/testdata/forged_ca.der");

    #[test]
    fn pkcs7_variants_verify() {
        for cms in [CMS_ATTRS, CMS_NOATTR, CMS_KEYID] {
            assert_eq!(
                verify_pkcs7_signature(cms, DATA, CA, true),
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
        assert_eq!(verify_pkcs7_signature(CMS_ATTRS, &bad, CA, true), Ok(false));
        assert_eq!(
            verify_pkcs7_signature(CMS_NOATTR, &bad, CA, true),
            Ok(false)
        );
    }

    // Turn the detached fixture into a valid attached signature without
    // changing its signed attributes or signature over DATA.
    fn attach_fixture_content(cms: &[u8]) -> Vec<u8> {
        fn wrap(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut encoded = vec![tag];
            if value.len() < 128 {
                encoded.push(value.len() as u8);
            } else {
                let length = value.len().to_be_bytes();
                let length = &length[length.iter().take_while(|&&byte| byte == 0).count()..];
                encoded.push(0x80 | length.len() as u8);
                encoded.extend_from_slice(length);
            }
            encoded.extend_from_slice(value);
            encoded
        }

        let mut content_info = Tlv::parse(cms).unwrap().contents(tag::SEQUENCE).unwrap();
        let content_type = content_info.read().unwrap();
        let signed = content_info
            .read_tag(tag::context_constructed(0))
            .unwrap()
            .inner()
            .unwrap();
        content_info.finish().unwrap();
        let mut fields = Reader::new(signed.value);
        let version = fields.read().unwrap();
        let digest_algorithms = fields.read().unwrap();
        let old_encapsulated = fields.read().unwrap();
        let econtent_type = old_encapsulated
            .contents(tag::SEQUENCE)
            .unwrap()
            .read()
            .unwrap();
        let content = wrap(tag::context_constructed(0), &wrap(tag::OCTET_STRING, DATA));
        let encapsulated = wrap(
            tag::SEQUENCE,
            &[econtent_type.encoded, content.as_slice()].concat(),
        );
        let remaining = signed
            .value
            .get(
                version.encoded.len()
                    + digest_algorithms.encoded.len()
                    + old_encapsulated.encoded.len()..,
            )
            .unwrap();
        let signed = wrap(
            tag::SEQUENCE,
            &[
                version.encoded,
                digest_algorithms.encoded,
                encapsulated.as_slice(),
                remaining,
            ]
            .concat(),
        );
        let explicit = wrap(tag::context_constructed(0), &signed);
        wrap(
            tag::SEQUENCE,
            &[content_type.encoded, explicit.as_slice()].concat(),
        )
    }

    #[test]
    fn detached_callers_reject_attached_content_even_with_valid_signature() {
        let attached = attach_fixture_content(CMS_ATTRS);
        let mut other_payload = DATA.to_vec();
        other_payload[0] ^= 0xff;
        assert_eq!(
            verify_pkcs7_signature(&attached, &other_payload, CA, false),
            Ok(true)
        );
        assert_eq!(
            verify_pkcs7_signature(&attached, &other_payload, CA, true),
            Err(AuthError::InvalidHeader)
        );
    }

    #[test]
    fn pkcs7_garbage_inputs_error() {
        assert!(verify_pkcs7_signature(b"junk", DATA, CA, true).is_err());
        assert!(verify_pkcs7_signature(CMS_ATTRS, DATA, b"junk", true).is_err());
        assert!(verify_pkcs7_signature(&[], DATA, CA, true).is_err());
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
    fn forged_self_signed_anchor_lookalike_rejected() {
        let ca = parse_cert_view(CA).unwrap();
        let forged = parse_cert_view(FORGED_CA).unwrap();
        assert_eq!(forged.subject, ca.subject);
        assert_eq!(forged.serial, ca.serial);
        assert_ne!(
            forged.rsa_public_key().unwrap().modulus,
            ca.rsa_public_key().unwrap().modulus
        );
        // Secure Boot image verification skips validity periods, so trust
        // must come from the anchor identity alone.
        let config = ChainBuildingConfig {
            check_validity_period: false,
            ..ChainBuildingConfig::default()
        };
        assert!(build_and_verify_chain(FORGED_CA, CA, &[], &config).is_err());
        assert!(build_and_verify_chain(FORGED_CA, CA, &[FORGED_CA], &config).is_err());
        // The genuine anchor is trusted by identity alone.
        let chain = build_and_verify_chain(CA, CA, &[], &config).unwrap();
        assert_eq!(chain.len(), 1);
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
        let cached = revocation::get_cached_crl(leaf.issuer, now, &config).expect("cached CRL");
        assert_eq!(cached.revoked_certificates.len(), 1);
    }
}
