//! Certificate Revocation Checking
//!
//! This module implements CRL (Certificate Revocation List) checking for UEFI
//! Secure Boot. Revoked signatures reach the firmware through the dbx
//! (forbidden signatures) database and are pre-loaded into the cache below;
//! there is no network fetch path.
//!
//! # Deliberately unsupported: OCSP
//!
//! Online Certificate Status Protocol checking requires a network stack to
//! reach responders, which CrabEFI does not have. OCSP is therefore rejected
//! at the design level rather than stubbed out: there are no OCSP request
//! builders, response parsers, or configuration knobs. Revocation enforcement
//! is CRL/dbx only.

use super::AuthError;
use alloc::string::String;
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
    /// URL identifying where a CRL for this certificate is published
    ///
    /// Informational only: without a network stack the firmware cannot fetch
    /// it. CRLs must be pre-loaded via [`load_crl`] (e.g. from dbx updates).
    pub uri: String,
}

/// Parse CRL Distribution Points extension from a certificate
///
/// Returns the published locations of CRLs for this certificate. The firmware
/// cannot fetch them; this is diagnostic support for tooling that pre-loads
/// CRLs into the cache.
pub fn extract_crl_distribution_points(
    cert_der: &[u8],
) -> Result<Vec<CrlDistributionPoint>, AuthError> {
    use x509_cert::ext::pkix::crl::CrlDistributionPoints;
    use x509_cert::ext::pkix::name::DistributionPointName;

    let cert = Certificate::from_der(cert_der).map_err(|_| AuthError::CertificateParseError)?;

    let mut points = Vec::new();

    if let Some(extensions) = &cert.tbs_certificate().extensions() {
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

    let crl: CertificateList = CertificateList::from_der(crl_der).map_err(|e| {
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
    /// Enable CRL checking against the pre-loaded cache
    pub enable_crl: bool,
    /// Allow soft-fail when revocation status cannot be determined
    pub allow_soft_fail: bool,
    /// Maximum age of cached CRL in seconds (default: 7 days)
    pub max_crl_age: i64,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        RevocationConfig {
            enable_crl: true,
            allow_soft_fail: true,
            max_crl_age: 7 * 24 * 3600, // 7 days
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

    let serial_number = cert.tbs_certificate().serial_number().as_bytes();

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

/// Check certificate revocation status against the pre-loaded CRL cache
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
    // If CRL checking is disabled, skip checking
    if !config.enable_crl {
        return RevocationCheckResult::Skipped;
    }

    // Get the issuer name for CRL lookup
    let issuer = match Certificate::from_der(issuer_der) {
        Ok(c) => c,
        Err(_) => return RevocationCheckResult::Unknown,
    };

    let issuer_name = match issuer.tbs_certificate().subject().to_der() {
        Ok(n) => n,
        Err(_) => return RevocationCheckResult::Unknown,
    };

    if let Some(result) = try_crl_check(cert_der, &issuer_name, config, current_time) {
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

    // Without a network stack CRLs cannot be fetched; they must be pre-loaded
    // into the cache via dbx updates or files staged before boot. Log the
    // published distribution points for diagnostics.
    if let Ok(cdps) = extract_crl_distribution_points(cert_der) {
        for cdp in cdps {
            log::debug!("CRL distribution point (not fetchable): {}", cdp.uri);
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
    fn test_revocation_config_default() {
        let config = RevocationConfig::default();
        assert!(config.enable_crl);
        assert!(config.allow_soft_fail);
    }
}
