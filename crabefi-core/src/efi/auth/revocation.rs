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
use super::asn1_views;
use alloc::string::String;
use alloc::vec::Vec;

// Local CRL reason codes (previously re-exported from x509_cert).
pub use super::asn1_views::CrlReason;

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
    let cert = asn1_views::parse_cert_view(cert_der)?;
    let Some(extensions_der) = cert.extensions_der else {
        return Ok(Vec::new());
    };
    let Some(value) =
        asn1_views::find_extension(extensions_der, asn1_views::OID_CRL_DISTRIBUTION_POINTS)?
    else {
        return Ok(Vec::new());
    };
    asn1_views::extract_crl_uris(value)?
        .into_iter()
        .map(|uri| {
            core::str::from_utf8(&uri)
                .map(|s| CrlDistributionPoint {
                    uri: String::from(s),
                })
                .map_err(|_| AuthError::CertificateParseError)
        })
        .collect()
}

/// Parse a DER-encoded CRL into the cached representation.
pub fn parse_crl(crl_der: &[u8]) -> Result<CertificateRevocationList, AuthError> {
    if crl_der.len() > MAX_CRL_SIZE {
        log::warn!(
            "CRL too large: {} bytes (max {})",
            crl_der.len(),
            MAX_CRL_SIZE
        );
        return Err(AuthError::InvalidHeader);
    }

    let crl = asn1_views::parse_crl_view(crl_der, MAX_REVOKED_CERTS)?;

    let revoked_certificates = crl
        .revoked
        .iter()
        .map(|rc| RevokedCertificate {
            serial_number: rc.serial.to_vec(),
            revocation_date: rc.revocation_date,
            reason: rc.reason,
        })
        .collect::<Vec<_>>();

    if revoked_certificates.len() >= MAX_REVOKED_CERTS {
        log::warn!("CRL contains too many revoked certificates, truncated");
    }

    Ok(CertificateRevocationList {
        issuer: crl.issuer_der.to_vec(),
        this_update: crl.this_update,
        next_update: crl.next_update,
        revoked_certificates,
    })
}

// ============================================================================
// Revocation Checking Integration
// ============================================================================

/// Revocation check result
#[derive(Debug, Clone, PartialEq, Eq)]
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
    let cert = match asn1_views::parse_cert_view(cert_der) {
        Ok(c) => c,
        Err(_) => return RevocationCheckResult::Unknown,
    };

    // Check if the serial number is in the revoked list
    for revoked in &crl.revoked_certificates {
        if revoked.serial_number == cert.serial {
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
    let issuer_name = match asn1_views::parse_cert_view(issuer_der) {
        Ok(c) => c.subject_der.to_vec(),
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
