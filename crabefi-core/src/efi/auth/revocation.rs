//! Certificate Revocation Checking
//!
//! This module implements certificate revocation checking for UEFI Secure Boot:
//! - CRL (Certificate Revocation List) checking
//! - OCSP (Online Certificate Status Protocol) checking
//!
//! # Security Note
//!
//! Revocation checking is critical for ensuring that compromised certificates
//! cannot be used to sign malicious code. Without revocation checking, a
//! certificate that has been revoked by its issuer could still be accepted.
//!
//! # UEFI Environment Considerations
//!
//! In the UEFI environment:
//! - Network access may be limited or unavailable
//! - CRLs are typically cached in the dbx (forbidden signatures) database
//! - Real-time OCSP checking requires network stack initialization
//! - Soft-fail mode is used when revocation checking cannot be completed

use super::AuthError;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use der::{Decode, Encode};
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::name::GeneralName;

// Re-export x509_cert's CrlReason for use by callers.
// Variant naming differs slightly from the old hand-rolled enum:
//   CaCompromise (was CACompromise), AaCompromise (was AACompromise)
pub use x509_cert::ext::pkix::crl::CrlReason;

// ============================================================================
// CRL (Certificate Revocation List) Support
// ============================================================================

/// Maximum CRL size we'll accept (16 MB)
/// This prevents DoS attacks with maliciously large CRLs
const MAX_CRL_SIZE: usize = 16 * 1024 * 1024;

/// Maximum number of revoked certificates per CRL
/// This prevents DoS with CRLs containing excessive entries
const MAX_REVOKED_CERTS: usize = 100_000;

/// A parsed Certificate Revocation List
#[derive(Debug, Clone)]
pub struct CertificateRevocationList {
    /// DER-encoded issuer name
    pub issuer: Vec<u8>,
    /// This update time (Unix timestamp)
    pub this_update: i64,
    /// Next update time (Unix timestamp), if present
    pub next_update: Option<i64>,
    /// List of revoked certificate serial numbers with optional reason
    pub revoked_certificates: Vec<RevokedCertificate>,
}

/// A revoked certificate entry
#[derive(Debug, Clone)]
pub struct RevokedCertificate {
    /// Serial number of the revoked certificate
    pub serial_number: Vec<u8>,
    /// Revocation time (Unix timestamp)
    pub revocation_date: i64,
    /// Reason for revocation
    pub reason: Option<CrlReason>,
}

/// CRL distribution point extracted from a certificate
#[derive(Debug, Clone)]
pub struct CrlDistributionPoint {
    /// URL to fetch the CRL from
    pub uri: String,
}

/// Parse CRL Distribution Points extension from a certificate
///
/// Returns a list of URIs where CRLs can be fetched from.
pub fn extract_crl_distribution_points(
    cert_der: &[u8],
) -> Result<Vec<CrlDistributionPoint>, AuthError> {
    use x509_cert::ext::pkix::crl::CrlDistributionPoints;
    use x509_cert::ext::pkix::name::DistributionPointName;

    let cert = Certificate::from_der(cert_der).map_err(|_| AuthError::CertificateParseError)?;

    let mut points = Vec::new();

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id == <CrlDistributionPoints as const_oid::AssociatedOid>::OID {
                let cdps = CrlDistributionPoints::from_der(ext.extn_value.as_bytes())
                    .map_err(|_| AuthError::CertificateParseError)?;

                for dp in cdps.0.iter() {
                    if let Some(DistributionPointName::FullName(names)) = &dp.distribution_point {
                        for name in names {
                            if let GeneralName::UniformResourceIdentifier(uri) = name {
                                points.push(CrlDistributionPoint {
                                    uri: String::from(uri.as_str()),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(points)
}

/// Convert an x509_cert Time to a Unix timestamp (seconds since epoch)
fn time_to_unix(t: x509_cert::time::Time) -> i64 {
    t.to_unix_duration().as_secs() as i64
}

/// Parse a DER-encoded CRL
///
/// Uses `x509_cert::crl::CertificateList::from_der()` for structured parsing.
pub fn parse_crl(crl_der: &[u8]) -> Result<CertificateRevocationList, AuthError> {
    if crl_der.len() > MAX_CRL_SIZE {
        log::warn!(
            "CRL too large: {} bytes (max {})",
            crl_der.len(),
            MAX_CRL_SIZE
        );
        return Err(AuthError::InvalidHeader);
    }

    let crl = CertificateList::from_der(crl_der).map_err(|e| {
        log::debug!("Failed to parse CRL: {:?}", e);
        AuthError::CertificateParseError
    })?;

    let tbs = &crl.tbs_cert_list;

    let issuer = tbs
        .issuer
        .to_der()
        .map_err(|_| AuthError::CertificateParseError)?;

    let this_update = time_to_unix(tbs.this_update);
    let next_update = tbs.next_update.map(time_to_unix);

    // Parse revoked certificates
    let revoked_certificates: Vec<_> = tbs
        .revoked_certificates
        .as_ref()
        .map(|revoked| {
            revoked
                .iter()
                .take(MAX_REVOKED_CERTS)
                .map(|rc| {
                    let serial_number = rc.serial_number.as_bytes().to_vec();
                    let revocation_date = time_to_unix(rc.revocation_date);

                    // Extract CRL reason from entry extensions
                    let reason = rc.crl_entry_extensions.as_ref().and_then(|exts| {
                        exts.iter()
                            .find(|e| e.extn_id == <CrlReason as const_oid::AssociatedOid>::OID)
                            .and_then(|e| CrlReason::from_der(e.extn_value.as_bytes()).ok())
                    });

                    RevokedCertificate {
                        serial_number,
                        revocation_date,
                        reason,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    if revoked_certificates.len() >= MAX_REVOKED_CERTS {
        log::warn!("CRL contains too many revoked certificates, truncated");
    }

    Ok(CertificateRevocationList {
        issuer,
        this_update,
        next_update,
        revoked_certificates,
    })
}

// ============================================================================
// OCSP (Online Certificate Status Protocol) Support
// ============================================================================

/// OCSP response status codes (RFC 6960)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OcspResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    // 4 is unused
    SigRequired = 5,
    Unauthorized = 6,
}

impl OcspResponseStatus {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(OcspResponseStatus::Successful),
            1 => Some(OcspResponseStatus::MalformedRequest),
            2 => Some(OcspResponseStatus::InternalError),
            3 => Some(OcspResponseStatus::TryLater),
            5 => Some(OcspResponseStatus::SigRequired),
            6 => Some(OcspResponseStatus::Unauthorized),
            _ => None,
        }
    }
}

/// OCSP certificate status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspCertStatus {
    /// Certificate is not revoked
    Good,
    /// Certificate has been revoked
    Revoked {
        /// Revocation time (Unix timestamp)
        revocation_time: i64,
        /// Reason for revocation
        reason: Option<CrlReason>,
    },
    /// Revocation status is unknown
    Unknown,
}

/// Parsed OCSP response for a single certificate
#[derive(Debug, Clone)]
pub struct OcspSingleResponse {
    /// Certificate status
    pub cert_status: OcspCertStatus,
    /// When this response was produced
    pub this_update: i64,
    /// When the next update will be available
    pub next_update: Option<i64>,
}

/// OCSP responder URL extracted from a certificate
#[derive(Debug, Clone)]
pub struct OcspResponder {
    /// URL of the OCSP responder
    pub uri: String,
}

/// Extract OCSP responder URLs from a certificate's Authority Information Access extension
pub fn extract_ocsp_responders(cert_der: &[u8]) -> Result<Vec<OcspResponder>, AuthError> {
    use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;

    let cert = Certificate::from_der(cert_der).map_err(|_| AuthError::CertificateParseError)?;

    // OCSP access method OID: 1.3.6.1.5.5.7.48.1
    let ocsp_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");

    let mut responders = Vec::new();

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id == <AuthorityInfoAccessSyntax as const_oid::AssociatedOid>::OID {
                let aia = AuthorityInfoAccessSyntax::from_der(ext.extn_value.as_bytes())
                    .map_err(|_| AuthError::CertificateParseError)?;

                for ad in aia.0.iter() {
                    if ad.access_method == ocsp_oid
                        && let GeneralName::UniformResourceIdentifier(uri) = &ad.access_location
                    {
                        responders.push(OcspResponder {
                            uri: String::from(uri.as_str()),
                        });
                    }
                }
            }
        }
    }

    Ok(responders)
}

/// Compute SHA-1 hash (required by OCSP spec for CertID)
fn sha1_hash(data: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let result = Sha1::digest(data);
    result.into()
}

/// Build an OCSP request for a certificate
///
/// This creates a DER-encoded OCSP request that can be sent to an OCSP responder.
///
/// # Arguments
///
/// * `cert_der` - The certificate to check
/// * `issuer_der` - The issuer's certificate
///
/// # Returns
///
/// DER-encoded OCSP request
pub fn build_ocsp_request(cert_der: &[u8], issuer_der: &[u8]) -> Result<Vec<u8>, AuthError> {
    let cert = Certificate::from_der(cert_der).map_err(|_| AuthError::CertificateParseError)?;
    let issuer = Certificate::from_der(issuer_der).map_err(|_| AuthError::CertificateParseError)?;

    // Get issuer name hash (SHA-1)
    let issuer_name_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|_| AuthError::CertificateParseError)?;
    let issuer_name_hash = sha1_hash(&issuer_name_der);

    // Get issuer key hash (SHA-1 of the issuer's public key)
    let issuer_key_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let issuer_key_hash = sha1_hash(issuer_key_der);

    // Get serial number
    let serial_number = cert.tbs_certificate.serial_number.as_bytes();

    // Build the OCSP request manually (no x509-ocsp crate available)
    // OCSPRequest ::= SEQUENCE {
    //     tbsRequest   TBSRequest,
    //     optionalSignature [0] EXPLICIT Signature OPTIONAL
    // }
    // TBSRequest ::= SEQUENCE {
    //     version  [0] EXPLICIT Version DEFAULT v1,
    //     requestorName [1] EXPLICIT GeneralName OPTIONAL,
    //     requestList SEQUENCE OF Request,
    //     requestExtensions [2] EXPLICIT Extensions OPTIONAL
    // }
    // Request ::= SEQUENCE {
    //     reqCert     CertID,
    //     singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL
    // }
    // CertID ::= SEQUENCE {
    //     hashAlgorithm AlgorithmIdentifier,
    //     issuerNameHash OCTET STRING,
    //     issuerKeyHash OCTET STRING,
    //     serialNumber CertificateSerialNumber
    // }

    let mut request = Vec::new();

    // SHA-1 algorithm identifier: SEQUENCE { OID 1.3.14.3.2.26, NULL }
    let sha1_alg_id: &[u8] = &[
        0x30, 0x09, // SEQUENCE
        0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, // OID 1.3.14.3.2.26 (SHA-1)
        0x05, 0x00, // NULL
    ];

    // Build CertID
    let mut cert_id = Vec::new();
    cert_id.extend_from_slice(sha1_alg_id);

    // issuerNameHash OCTET STRING
    cert_id.push(0x04);
    cert_id.push(issuer_name_hash.len() as u8);
    cert_id.extend_from_slice(&issuer_name_hash);

    // issuerKeyHash OCTET STRING
    cert_id.push(0x04);
    cert_id.push(issuer_key_hash.len() as u8);
    cert_id.extend_from_slice(&issuer_key_hash);

    // serialNumber INTEGER
    cert_id.push(0x02);
    encode_der_length(&mut cert_id, serial_number.len());
    cert_id.extend_from_slice(serial_number);

    // Wrap CertID in SEQUENCE
    let mut cert_id_seq = vec![0x30];
    encode_der_length(&mut cert_id_seq, cert_id.len());
    cert_id_seq.extend_from_slice(&cert_id);

    // Build Request (just CertID for unsigned request)
    let mut single_request = vec![0x30];
    encode_der_length(&mut single_request, cert_id_seq.len());
    single_request.extend_from_slice(&cert_id_seq);

    // Build requestList SEQUENCE OF Request
    let mut request_list = vec![0x30];
    encode_der_length(&mut request_list, single_request.len());
    request_list.extend_from_slice(&single_request);

    // Build TBSRequest
    let mut tbs_request = vec![0x30];
    encode_der_length(&mut tbs_request, request_list.len());
    tbs_request.extend_from_slice(&request_list);

    // Build OCSPRequest
    request.push(0x30);
    encode_der_length(&mut request, tbs_request.len());
    request.extend_from_slice(&tbs_request);

    Ok(request)
}

/// Parse an OCSP response
///
/// # Note
///
/// This is a simplified implementation that validates the response status
/// but does not fully parse the BasicOCSPResponse body. Full OCSP parsing
/// would require the `x509-ocsp` crate or equivalent.
pub fn parse_ocsp_response(response_der: &[u8]) -> Result<OcspSingleResponse, AuthError> {
    use super::parse_der_length;

    // OCSPResponse ::= SEQUENCE {
    //     responseStatus OCSPResponseStatus,
    //     responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL
    // }

    if response_der.is_empty() || response_der[0] != 0x30 {
        return Err(AuthError::CertificateParseError);
    }

    let (resp_len, resp_offset) = parse_der_length(&response_der[1..])?;
    if 1 + resp_offset + resp_len > response_der.len() {
        return Err(AuthError::CertificateParseError);
    }

    let content = &response_der[1 + resp_offset..1 + resp_offset + resp_len];
    let mut pos = 0;

    // responseStatus ENUMERATED
    if pos >= content.len() || content[pos] != 0x0a {
        return Err(AuthError::CertificateParseError);
    }
    pos += 1;
    let (status_len, status_offset) = parse_der_length(&content[pos..])?;
    pos += status_offset;

    if status_len != 1 || pos >= content.len() {
        return Err(AuthError::CertificateParseError);
    }

    let status = content[pos];

    let response_status =
        OcspResponseStatus::from_u8(status).ok_or(AuthError::CertificateParseError)?;

    if response_status != OcspResponseStatus::Successful {
        log::warn!("OCSP response status: {:?}", response_status);
        return Err(AuthError::CryptoError);
    }

    // For now, return a basic response - full parsing would require
    // parsing BasicOCSPResponse and verifying the signature
    // This is a simplified implementation for the UEFI environment
    Ok(OcspSingleResponse {
        cert_status: OcspCertStatus::Unknown,
        this_update: 0,
        next_update: None,
    })
}

// ============================================================================
// Revocation Checking Integration
// ============================================================================

/// Revocation check result
#[derive(Debug, Clone)]
pub enum RevocationCheckResult {
    /// Certificate is not revoked
    Good,
    /// Certificate has been revoked
    Revoked {
        reason: Option<CrlReason>,
        revocation_time: i64,
    },
    /// Could not determine revocation status
    Unknown,
    /// Check was skipped (soft-fail mode)
    Skipped,
}

/// Configuration for revocation checking
#[derive(Debug, Clone)]
pub struct RevocationConfig {
    /// Enable CRL checking
    pub enable_crl: bool,
    /// Enable OCSP checking
    pub enable_ocsp: bool,
    /// Prefer OCSP over CRL when both are available
    pub prefer_ocsp: bool,
    /// Allow soft-fail when revocation status cannot be determined
    pub allow_soft_fail: bool,
    /// Maximum age of cached CRL in seconds (default: 7 days)
    pub max_crl_age: i64,
    /// Maximum age of OCSP response in seconds (default: 1 day)
    pub max_ocsp_age: i64,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        RevocationConfig {
            enable_crl: true,
            enable_ocsp: true,
            prefer_ocsp: true,
            allow_soft_fail: true,
            max_crl_age: 7 * 24 * 3600, // 7 days
            max_ocsp_age: 24 * 3600,    // 1 day
        }
    }
}

/// CRL cache entry
#[derive(Debug, Clone)]
pub struct CachedCrl {
    /// The parsed CRL
    pub crl: CertificateRevocationList,
    /// When this CRL was cached (Unix timestamp)
    pub cached_at: i64,
}

use spin::Mutex;

/// Global CRL cache
/// Key: DER-encoded issuer name
static CRL_CACHE: Mutex<Vec<(Vec<u8>, CachedCrl)>> = Mutex::new(Vec::new());

/// Maximum number of cached CRLs
const MAX_CACHED_CRLS: usize = 32;

/// Add a CRL to the cache
pub fn cache_crl(crl: CertificateRevocationList, current_time: i64) {
    let mut cache = CRL_CACHE.lock();

    // Remove existing entry for this issuer
    cache.retain(|(issuer, _)| issuer != &crl.issuer);

    // Enforce cache size limit
    while cache.len() >= MAX_CACHED_CRLS {
        // Remove oldest entry
        if let Some(oldest_idx) = cache
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, c))| c.cached_at)
            .map(|(i, _)| i)
        {
            cache.remove(oldest_idx);
        } else {
            break;
        }
    }

    let issuer = crl.issuer.clone();
    cache.push((
        issuer,
        CachedCrl {
            crl,
            cached_at: current_time,
        },
    ));
}

/// Look up a CRL from the cache
pub fn get_cached_crl(
    issuer: &[u8],
    current_time: i64,
    config: &RevocationConfig,
) -> Option<CertificateRevocationList> {
    let cache = CRL_CACHE.lock();

    for (cached_issuer, cached_crl) in cache.iter() {
        if cached_issuer == issuer {
            // Check if CRL is still fresh
            if current_time - cached_crl.cached_at <= config.max_crl_age {
                // Also check CRL's own nextUpdate if available
                if let Some(next_update) = cached_crl.crl.next_update {
                    if current_time <= next_update {
                        return Some(cached_crl.crl.clone());
                    }
                } else {
                    return Some(cached_crl.crl.clone());
                }
            }
        }
    }

    None
}

/// Check if a certificate is revoked using a CRL
///
/// # Arguments
///
/// * `cert_der` - The certificate to check
/// * `crl` - The CRL to check against
///
/// # Returns
///
/// Whether the certificate is revoked
pub fn check_crl_revocation(
    cert_der: &[u8],
    crl: &CertificateRevocationList,
) -> RevocationCheckResult {
    let cert = match Certificate::from_der(cert_der) {
        Ok(c) => c,
        Err(_) => return RevocationCheckResult::Unknown,
    };

    let serial_number = cert.tbs_certificate.serial_number.as_bytes();

    // Check if the serial number is in the revoked list
    for revoked in &crl.revoked_certificates {
        if revoked.serial_number == serial_number {
            return RevocationCheckResult::Revoked {
                reason: revoked.reason,
                revocation_time: revoked.revocation_date,
            };
        }
    }

    RevocationCheckResult::Good
}

/// Check certificate revocation status
///
/// This function checks the revocation status of a certificate using
/// available CRLs and/or OCSP responders according to the configuration.
///
/// # Arguments
///
/// * `cert_der` - The certificate to check
/// * `issuer_der` - The issuer's certificate
/// * `config` - Revocation checking configuration
/// * `current_time` - Current time as Unix timestamp
///
/// # Returns
///
/// The revocation status of the certificate
pub fn check_certificate_revocation(
    cert_der: &[u8],
    issuer_der: &[u8],
    config: &RevocationConfig,
    current_time: i64,
) -> RevocationCheckResult {
    // If both CRL and OCSP are disabled, skip checking
    if !config.enable_crl && !config.enable_ocsp {
        return RevocationCheckResult::Skipped;
    }

    // Get the issuer name for CRL lookup
    let issuer = match Certificate::from_der(issuer_der) {
        Ok(c) => c,
        Err(_) => return RevocationCheckResult::Unknown,
    };

    let issuer_name = match issuer.tbs_certificate.subject.to_der() {
        Ok(n) => n,
        Err(_) => return RevocationCheckResult::Unknown,
    };

    // Try OCSP first if preferred
    if config.enable_ocsp
        && config.prefer_ocsp
        && let Some(result) = try_ocsp_check(cert_der, issuer_der, config, current_time)
    {
        match result {
            RevocationCheckResult::Revoked { .. } | RevocationCheckResult::Good => {
                return result;
            }
            _ => {}
        }
    }

    // Try CRL
    if config.enable_crl
        && let Some(result) = try_crl_check(cert_der, &issuer_name, config, current_time)
    {
        match result {
            RevocationCheckResult::Revoked { .. } | RevocationCheckResult::Good => {
                return result;
            }
            _ => {}
        }
    }

    // Try OCSP if not already tried
    if config.enable_ocsp
        && !config.prefer_ocsp
        && let Some(result) = try_ocsp_check(cert_der, issuer_der, config, current_time)
    {
        match result {
            RevocationCheckResult::Revoked { .. } | RevocationCheckResult::Good => {
                return result;
            }
            _ => {}
        }
    }

    // Could not determine status
    if config.allow_soft_fail {
        log::debug!("Revocation check soft-fail: could not determine status");
        RevocationCheckResult::Skipped
    } else {
        RevocationCheckResult::Unknown
    }
}

/// Try to check revocation via CRL
fn try_crl_check(
    cert_der: &[u8],
    issuer_name: &[u8],
    config: &RevocationConfig,
    current_time: i64,
) -> Option<RevocationCheckResult> {
    // First check the cache
    if let Some(crl) = get_cached_crl(issuer_name, current_time, config) {
        let result = check_crl_revocation(cert_der, &crl);
        match result {
            RevocationCheckResult::Good | RevocationCheckResult::Revoked { .. } => {
                return Some(result);
            }
            _ => {}
        }
    }

    // In UEFI environment, we can't easily fetch CRLs from the network
    // The CRLs should be pre-loaded into the cache via dbx updates or
    // loaded from the ESP filesystem

    // Extract CRL distribution points from the certificate
    if let Ok(cdps) = extract_crl_distribution_points(cert_der) {
        for cdp in cdps {
            log::debug!("CRL distribution point: {}", cdp.uri);
            // In a full implementation, we would fetch the CRL here
            // For UEFI, CRLs should be pre-loaded
        }
    }

    None
}

/// Try to check revocation via OCSP
fn try_ocsp_check(
    cert_der: &[u8],
    issuer_der: &[u8],
    _config: &RevocationConfig,
    _current_time: i64,
) -> Option<RevocationCheckResult> {
    // Extract OCSP responders from the certificate
    if let Ok(responders) = extract_ocsp_responders(cert_der) {
        for responder in responders {
            log::debug!("OCSP responder: {}", responder.uri);

            // Build OCSP request
            if let Ok(_request) = build_ocsp_request(cert_der, issuer_der) {
                // In a full implementation, we would send the request and parse the response
                // For UEFI, this requires network stack support
            }
        }
    }

    None
}

/// Load CRLs from a data source (e.g., dbx variable or file)
///
/// This function parses CRL data and adds valid CRLs to the cache.
///
/// # Arguments
///
/// * `crl_data` - DER-encoded CRL data
/// * `current_time` - Current time as Unix timestamp
///
/// # Returns
///
/// Number of CRLs successfully loaded
pub fn load_crl(crl_data: &[u8], current_time: i64) -> Result<(), AuthError> {
    let crl = parse_crl(crl_data)?;

    // Validate the CRL is not expired
    if let Some(next_update) = crl.next_update
        && current_time > next_update
    {
        log::warn!("CRL has expired");
        return Err(AuthError::CertificateExpired);
    }

    log::info!(
        "Loaded CRL with {} revoked certificates",
        crl.revoked_certificates.len()
    );
    cache_crl(crl, current_time);

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Encode DER length (used for manual OCSP request building)
fn encode_der_length(output: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        output.push(length as u8);
    } else if length < 0x100 {
        output.push(0x81);
        output.push(length as u8);
    } else if length < 0x10000 {
        output.push(0x82);
        output.push((length >> 8) as u8);
        output.push(length as u8);
    } else if length < 0x1000000 {
        output.push(0x83);
        output.push((length >> 16) as u8);
        output.push((length >> 8) as u8);
        output.push(length as u8);
    } else {
        output.push(0x84);
        output.push((length >> 24) as u8);
        output.push((length >> 16) as u8);
        output.push((length >> 8) as u8);
        output.push(length as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crl_reason_values() {
        // Verify the x509_cert CrlReason enum has expected values
        assert_eq!(CrlReason::Unspecified as u32, 0);
        assert_eq!(CrlReason::KeyCompromise as u32, 1);
        assert_eq!(CrlReason::CessationOfOperation as u32, 5);
    }

    #[test]
    fn test_ocsp_response_status() {
        assert_eq!(
            OcspResponseStatus::from_u8(0),
            Some(OcspResponseStatus::Successful)
        );
        assert_eq!(
            OcspResponseStatus::from_u8(3),
            Some(OcspResponseStatus::TryLater)
        );
        assert_eq!(OcspResponseStatus::from_u8(4), None); // 4 is unused
    }

    #[test]
    fn test_sha1_hash() {
        // Test vector: SHA-1("abc") = a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
        let result = sha1_hash(b"abc");
        assert_eq!(
            result,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    #[test]
    fn test_revocation_config_default() {
        let config = RevocationConfig::default();
        assert!(config.enable_crl);
        assert!(config.enable_ocsp);
        assert!(config.prefer_ocsp);
        assert!(config.allow_soft_fail);
    }
}
