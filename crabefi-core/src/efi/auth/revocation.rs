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
use super::crypto::parse_cert_view;
use alloc::string::String;
use alloc::vec::Vec;
use crabefi_pkcs7::der::{DecodeError, Reader, Tlv, tag};
use crabefi_pkcs7::time::DateTime;
use crabefi_pkcs7::x509::Extensions;

/// CRL distribution points extension: 2.5.29.31
const OID_CRL_DISTRIBUTION_POINTS: &[u8] = &[0x55, 0x1d, 0x1f];
/// CRL reason code entry extension: 2.5.29.21
const OID_CRL_REASON: &[u8] = &[0x55, 0x1d, 0x15];

/// CRL reason codes (RFC 5280 5.3.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl CrlReason {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(CrlReason::Unspecified),
            1 => Some(CrlReason::KeyCompromise),
            2 => Some(CrlReason::CaCompromise),
            3 => Some(CrlReason::AffiliationChanged),
            4 => Some(CrlReason::Superseded),
            5 => Some(CrlReason::CessationOfOperation),
            6 => Some(CrlReason::CertificateHold),
            8 => Some(CrlReason::RemoveFromCrl),
            9 => Some(CrlReason::PrivilegeWithdrawn),
            10 => Some(CrlReason::AaCompromise),
            _ => None,
        }
    }
}

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
    let cert = parse_cert_view(cert_der)?;
    let Some(extension) = cert.extensions.find(OID_CRL_DISTRIBUTION_POINTS) else {
        return Ok(Vec::new());
    };
    extract_crl_uris(extension.value)?
        .into_iter()
        .map(|uri| {
            core::str::from_utf8(uri)
                .map(|s| CrlDistributionPoint {
                    uri: String::from(s),
                })
                .map_err(|_| AuthError::CertificateParseError)
        })
        .collect()
}

/// Extract CRL distribution-point URIs (context [6] IA5String) from a
/// CRLDP extension value. Diagnostic only; the firmware cannot fetch.
fn extract_crl_uris(ext_value: &[u8]) -> Result<Vec<&[u8]>, DecodeError> {
    let mut uris = Vec::new();
    for distribution_point in Tlv::parse(ext_value)?.contents(tag::SEQUENCE)? {
        collect_uris(distribution_point?.value, &mut uris, 0)?;
    }
    Ok(uris)
}

/// Maximum GeneralName nesting accepted below a DistributionPoint. Real
/// encodings need two levels ([0] distributionPoint -> [0] fullName ->
/// [6] URI); the bound keeps hostile input off the firmware call stack.
const MAX_URI_DEPTH: u8 = 4;

/// Collect every GeneralName UniformResourceIdentifier ([6] IMPLICIT
/// IA5String) found by walking constructed elements.
fn collect_uris<'a>(data: &'a [u8], out: &mut Vec<&'a [u8]>, depth: u8) -> Result<(), DecodeError> {
    if depth > MAX_URI_DEPTH {
        return Err(DecodeError);
    }
    for element in Reader::new(data) {
        let element = element?;
        if element.tag == tag::context(6) {
            out.push(element.value);
        } else if tag::is_constructed(element.tag) {
            collect_uris(element.value, out, depth + 1)?;
        }
    }
    Ok(())
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

    let mut crl = Tlv::parse(crl_der)?.contents(tag::SEQUENCE)?;
    let tbs = crl.read_tag(tag::SEQUENCE)?;
    // signatureAlgorithm + signatureValue (structure only; CRLs are trusted
    // via their dbx/file source).
    crl.read()?;
    crl.read()?;
    crl.finish()?;

    let mut fields = Reader::new(tbs.value);
    fields.read_optional(tag::INTEGER)?;
    fields.read()?;
    let issuer = fields.read()?.encoded.to_vec();
    let this_update = DateTime::parse(fields.read()?)?.unix_timestamp();
    let next_update = match fields.peek_tag() {
        Some(tag::UTC_TIME | tag::GENERALIZED_TIME) => {
            Some(DateTime::parse(fields.read()?)?.unix_timestamp())
        }
        _ => None,
    };
    let mut revoked_certificates = Vec::new();
    if !fields.is_empty() && fields.peek_tag() != Some(tag::context_constructed(0)) {
        for entry in fields.read()?.contents(tag::SEQUENCE)? {
            let entry = entry?;
            // Keep walking past the cap so the whole list stays validated.
            if revoked_certificates.len() < MAX_REVOKED_CERTS {
                revoked_certificates.push(parse_revoked_entry(entry)?);
            }
        }
    }
    // Optional [0] EXPLICIT CRL extensions (e.g. CRL number): skipped.
    fields.read_optional(tag::context_constructed(0))?;
    fields.finish()?;

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

fn parse_revoked_entry(entry: Tlv<'_>) -> Result<RevokedCertificate, DecodeError> {
    let mut fields = entry.contents(tag::SEQUENCE)?;
    let serial_number = fields.read()?.unsigned_integer()?.to_vec();
    let revocation_date = DateTime::parse(fields.read()?)?.unix_timestamp();
    let reason = fields
        .read_optional(tag::SEQUENCE)?
        .map(|extensions| crl_reason(Extensions::parse(extensions)?))
        .transpose()?
        .flatten();
    fields.finish()?;
    Ok(RevokedCertificate {
        serial_number,
        revocation_date,
        reason,
    })
}

/// First recognised cRLReason among the entry extensions.
fn crl_reason(extensions: Extensions<'_>) -> Result<Option<CrlReason>, DecodeError> {
    for extension in extensions.iter() {
        if extension.oid != OID_CRL_REASON {
            continue;
        }
        let enumerated = Tlv::parse(extension.value)?.expect(tag::ENUMERATED)?;
        // ENUMERATED shares the INTEGER encoding rules.
        let code = Tlv {
            tag: tag::INTEGER,
            ..enumerated
        }
        .unsigned_integer()?;
        if code.len() > size_of::<u32>() {
            return Err(DecodeError);
        }
        let code = code
            .iter()
            .fold(0u32, |code, byte| (code << 8) | u32::from(*byte));
        if let Some(reason) = CrlReason::from_u32(code) {
            return Ok(Some(reason));
        }
    }
    Ok(None)
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
    let cert = match parse_cert_view(cert_der) {
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
    let issuer_name = match parse_cert_view(issuer_der) {
        Ok(c) => c.subject.to_vec(),
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
    fn crl_reason_round_trips() {
        assert_eq!(CrlReason::from_u32(1), Some(CrlReason::KeyCompromise));
        assert_eq!(CrlReason::from_u32(7), None);
        assert_eq!(CrlReason::from_u32(10), Some(CrlReason::AaCompromise));
    }

    #[test]
    fn crl_reason_skips_other_entry_extensions() {
        // invalidityDate (2.5.29.24) with a GeneralizedTime, then
        // cRLReasons (2.5.29.21) = keyCompromise.
        let extensions = [
            0x30, 0x26, //
            0x30, 0x15, 0x06, 0x03, 0x55, 0x1d, 0x18, 0x04, 0x0e, 0x18, 0x0c, b'2', b'0', b'2',
            b'4', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', //
            0x30, 0x0d, 0x06, 0x03, 0x55, 0x1d, 0x15, 0x01, 0x01, 0xff, 0x04, 0x03, 0x0a, 0x01,
            0x01,
        ];
        let parse = |bytes| Extensions::parse(Tlv::parse(bytes).unwrap()).unwrap();
        assert_eq!(
            crl_reason(parse(&extensions)),
            Ok(Some(CrlReason::KeyCompromise))
        );
        let mut invalidity_only = extensions[..0x19].to_vec();
        invalidity_only[1] = 0x17;
        assert_eq!(crl_reason(parse(&invalidity_only)), Ok(None));
    }

    #[test]
    fn crl_uri_nesting_is_bounded() {
        // DistributionPoint { [0] { [0] { [6] "u" } } }: valid shape.
        let dp = [0x30, 0x07, 0xa0, 0x05, 0xa0, 0x03, 0x86, 0x01, b'u'];
        let mut ext = alloc::vec![0x30, dp.len() as u8];
        ext.extend_from_slice(&dp);
        assert_eq!(extract_crl_uris(&ext).unwrap(), alloc::vec![&b"u"[..]]);
        // Wrap the URI in more constructed layers than allowed.
        let mut nested = alloc::vec![0x86, 0x01, b'u'];
        for _ in 0..=MAX_URI_DEPTH {
            let mut wrapped = alloc::vec![0xa0, nested.len() as u8];
            wrapped.extend_from_slice(&nested);
            nested = wrapped;
        }
        let mut deep_dp = alloc::vec![0x30, nested.len() as u8];
        deep_dp.extend_from_slice(&nested);
        let mut deep = alloc::vec![0x30, deep_dp.len() as u8];
        deep.extend_from_slice(&deep_dp);
        assert!(extract_crl_uris(&deep).is_err());
    }

    #[test]
    fn test_crl_reason_values() {
        // Discriminants are the RFC 5280 reason codes.
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
