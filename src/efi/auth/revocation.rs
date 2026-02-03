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

// ============================================================================
// CRL (Certificate Revocation List) Support
// ============================================================================

/// Maximum CRL size we'll accept (16 MB)
/// This prevents DoS attacks with maliciously large CRLs
const MAX_CRL_SIZE: usize = 16 * 1024 * 1024;

/// Maximum number of revoked certificates per CRL
/// This prevents DoS with CRLs containing excessive entries
const MAX_REVOKED_CERTS: usize = 100_000;

/// X.509 extension OIDs for revocation
mod extension_oids {
    /// CRL Distribution Points: 2.5.29.31
    pub const CRL_DISTRIBUTION_POINTS: &[u8] = &[0x55, 0x1d, 0x1f];
    /// Authority Information Access: 1.3.6.1.5.5.7.1.1
    pub const AUTHORITY_INFO_ACCESS: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
    /// OCSP Access Method: 1.3.6.1.5.5.7.48.1
    pub const OCSP_ACCESS_METHOD: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
}

/// CRL reason codes (RFC 5280 Section 5.3.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CrlReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CACompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    // 7 is unused
    RemoveFromCRL = 8,
    PrivilegeWithdrawn = 9,
    AACompromise = 10,
}

impl CrlReason {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(CrlReason::Unspecified),
            1 => Some(CrlReason::KeyCompromise),
            2 => Some(CrlReason::CACompromise),
            3 => Some(CrlReason::AffiliationChanged),
            4 => Some(CrlReason::Superseded),
            5 => Some(CrlReason::CessationOfOperation),
            6 => Some(CrlReason::CertificateHold),
            8 => Some(CrlReason::RemoveFromCRL),
            9 => Some(CrlReason::PrivilegeWithdrawn),
            10 => Some(CrlReason::AACompromise),
            _ => None,
        }
    }
}

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
    use der::Decode;
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der).map_err(|_| AuthError::CertificateParseError)?;

    let mut points = Vec::new();

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id.as_bytes() == extension_oids::CRL_DISTRIBUTION_POINTS {
                // Parse the CRL Distribution Points extension
                let value = ext.extn_value.as_bytes();
                if let Ok(parsed_points) = parse_crl_distribution_points(value) {
                    points.extend(parsed_points);
                }
            }
        }
    }

    Ok(points)
}

/// Parse CRL Distribution Points extension value
///
/// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
/// DistributionPoint ::= SEQUENCE {
///     distributionPoint       [0]     DistributionPointName OPTIONAL,
///     reasons                 [1]     ReasonFlags OPTIONAL,
///     cRLIssuer               [2]     GeneralNames OPTIONAL
/// }
/// DistributionPointName ::= CHOICE {
///     fullName                [0]     GeneralNames,
///     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName
/// }
fn parse_crl_distribution_points(data: &[u8]) -> Result<Vec<CrlDistributionPoint>, AuthError> {
    let mut points = Vec::new();

    // Outer SEQUENCE
    if data.is_empty() || data[0] != 0x30 {
        return Err(AuthError::CertificateParseError);
    }

    let (seq_len, seq_offset) = parse_der_length(&data[1..])?;
    if 1 + seq_offset + seq_len > data.len() {
        return Err(AuthError::CertificateParseError);
    }

    let mut pos = 1 + seq_offset;
    let end = 1 + seq_offset + seq_len;

    while pos < end {
        // Each DistributionPoint is a SEQUENCE
        if data[pos] != 0x30 {
            break;
        }
        pos += 1;

        let (dp_len, dp_offset) = parse_der_length(&data[pos..])?;
        let dp_end = pos + dp_offset + dp_len;
        pos += dp_offset;

        // Look for distributionPoint [0]
        if pos < dp_end && data[pos] == 0xa0 {
            pos += 1;
            let (dpn_len, dpn_offset) = parse_der_length(&data[pos..])?;
            pos += dpn_offset;
            let dpn_end = pos + dpn_len;

            // Look for fullName [0]
            if pos < dpn_end && data[pos] == 0xa0 {
                pos += 1;
                let (fn_len, fn_offset) = parse_der_length(&data[pos..])?;
                pos += fn_offset;
                let fn_end = pos + fn_len;

                // GeneralNames contains GeneralName entries
                // Look for uniformResourceIdentifier [6] (context-specific, primitive)
                while pos < fn_end {
                    if data[pos] == 0x86 {
                        // URI
                        pos += 1;
                        let (uri_len, uri_offset) = parse_der_length(&data[pos..])?;
                        pos += uri_offset;

                        if pos + uri_len <= data.len()
                            && let Ok(uri) = core::str::from_utf8(&data[pos..pos + uri_len])
                        {
                            points.push(CrlDistributionPoint {
                                uri: String::from(uri),
                            });
                        }
                        pos += uri_len;
                    } else {
                        // Skip other GeneralName types
                        pos += 1;
                        if pos < fn_end {
                            let (skip_len, skip_offset) =
                                parse_der_length(&data[pos..]).unwrap_or((0, 1));
                            pos += skip_offset + skip_len;
                        }
                    }
                }
            }
        }

        pos = dp_end;
    }

    Ok(points)
}

/// Parse a DER-encoded CRL
///
/// CertificateList ::= SEQUENCE {
///     tbsCertList          TBSCertList,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
pub fn parse_crl(crl_der: &[u8]) -> Result<CertificateRevocationList, AuthError> {
    if crl_der.len() > MAX_CRL_SIZE {
        log::warn!(
            "CRL too large: {} bytes (max {})",
            crl_der.len(),
            MAX_CRL_SIZE
        );
        return Err(AuthError::InvalidHeader);
    }

    // Parse outer SEQUENCE
    if crl_der.is_empty() || crl_der[0] != 0x30 {
        return Err(AuthError::CertificateParseError);
    }

    let (outer_len, outer_offset) = parse_der_length(&crl_der[1..])?;
    if 1 + outer_offset + outer_len > crl_der.len() {
        return Err(AuthError::CertificateParseError);
    }

    let content_start = 1 + outer_offset;
    let content = &crl_der[content_start..content_start + outer_len];

    // Parse TBSCertList (first element of outer SEQUENCE)
    if content.is_empty() || content[0] != 0x30 {
        return Err(AuthError::CertificateParseError);
    }

    let (tbs_len, tbs_offset) = parse_der_length(&content[1..])?;
    let tbs_data = &content[1 + tbs_offset..1 + tbs_offset + tbs_len];

    parse_tbs_cert_list(tbs_data)
}

/// Parse TBSCertList structure
fn parse_tbs_cert_list(data: &[u8]) -> Result<CertificateRevocationList, AuthError> {
    let mut pos = 0;

    // Optional version (INTEGER with tag 0x02)
    if pos < data.len() && data[pos] == 0x02 {
        let (v_len, v_offset) = parse_der_length(&data[pos + 1..])?;
        pos += 1 + v_offset + v_len;
    }

    // Signature algorithm (SEQUENCE)
    if pos >= data.len() || data[pos] != 0x30 {
        return Err(AuthError::CertificateParseError);
    }
    let (alg_len, alg_offset) = parse_der_length(&data[pos + 1..])?;
    pos += 1 + alg_offset + alg_len;

    // Issuer (SEQUENCE - Name)
    if pos >= data.len() || data[pos] != 0x30 {
        return Err(AuthError::CertificateParseError);
    }
    let issuer_start = pos;
    let (issuer_len, issuer_offset) = parse_der_length(&data[pos + 1..])?;
    let issuer_total = 1 + issuer_offset + issuer_len;
    let issuer = data[issuer_start..issuer_start + issuer_total].to_vec();
    pos += issuer_total;

    // thisUpdate (Time - UTCTime or GeneralizedTime)
    let this_update = parse_crl_time(&data[pos..])?;
    pos += skip_time_field(&data[pos..])?;

    // nextUpdate (optional Time)
    let next_update = if pos < data.len() && (data[pos] == 0x17 || data[pos] == 0x18) {
        let nu = parse_crl_time(&data[pos..])?;
        pos += skip_time_field(&data[pos..])?;
        Some(nu)
    } else {
        None
    };

    // revokedCertificates (optional SEQUENCE)
    let mut revoked_certificates = Vec::new();
    if pos < data.len() && data[pos] == 0x30 {
        let (revoked_len, revoked_offset) = parse_der_length(&data[pos + 1..])?;
        let revoked_end = pos + 1 + revoked_offset + revoked_len;
        pos += 1 + revoked_offset;

        while pos < revoked_end {
            if revoked_certificates.len() >= MAX_REVOKED_CERTS {
                log::warn!("CRL contains too many revoked certificates");
                break;
            }

            if data[pos] != 0x30 {
                break;
            }

            let (entry_len, entry_offset) = parse_der_length(&data[pos + 1..])?;
            let entry_data = &data[pos + 1 + entry_offset..pos + 1 + entry_offset + entry_len];

            if let Ok(entry) = parse_revoked_certificate_entry(entry_data) {
                revoked_certificates.push(entry);
            }

            pos += 1 + entry_offset + entry_len;
        }
    }

    Ok(CertificateRevocationList {
        issuer,
        this_update,
        next_update,
        revoked_certificates,
    })
}

/// Parse a single revoked certificate entry
fn parse_revoked_certificate_entry(data: &[u8]) -> Result<RevokedCertificate, AuthError> {
    // Serial number (INTEGER)
    if data.is_empty() || data[0] != 0x02 {
        return Err(AuthError::CertificateParseError);
    }
    let (serial_len, serial_offset) = parse_der_length(&data[1..])?;
    let serial_number = data[1 + serial_offset..1 + serial_offset + serial_len].to_vec();
    let mut pos = 1 + serial_offset + serial_len;

    // Revocation date (Time)
    let revocation_date = if pos < data.len() && (data[pos] == 0x17 || data[pos] == 0x18) {
        let date = parse_crl_time(&data[pos..])?;
        pos += skip_time_field(&data[pos..])?;
        date
    } else {
        0
    };

    // Parse optional extensions to extract reason code
    // Extensions are a SEQUENCE of Extension
    let mut reason = None;

    // CRL entry extensions are in a SEQUENCE (tag 0x30)
    if pos < data.len() && data[pos] == 0x30 {
        let (ext_len, ext_offset) = parse_der_length(&data[pos + 1..])?;
        let ext_end = pos + 1 + ext_offset + ext_len;
        pos += 1 + ext_offset;

        // Parse each extension
        while pos < ext_end {
            if data[pos] != 0x30 {
                break;
            }

            let (single_ext_len, single_ext_offset) = parse_der_length(&data[pos + 1..])?;
            let single_ext_end = pos + 1 + single_ext_offset + single_ext_len;
            let mut ext_pos = pos + 1 + single_ext_offset;

            // Extension OID
            if ext_pos < single_ext_end && data[ext_pos] == 0x06 {
                let (oid_len, oid_offset) = parse_der_length(&data[ext_pos + 1..])?;
                let oid = &data[ext_pos + 1 + oid_offset..ext_pos + 1 + oid_offset + oid_len];
                ext_pos += 1 + oid_offset + oid_len;

                // CRL Reason OID: 2.5.29.21 = 0x55, 0x1d, 0x15
                if oid == [0x55, 0x1d, 0x15] {
                    // Skip optional critical flag (BOOLEAN)
                    if ext_pos < single_ext_end && data[ext_pos] == 0x01 {
                        ext_pos += 3; // BOOLEAN is always 3 bytes: tag + len(1) + value
                    }

                    // Extension value is an OCTET STRING containing ENUMERATED
                    if ext_pos < single_ext_end && data[ext_pos] == 0x04 {
                        let (octet_len, octet_offset) = parse_der_length(&data[ext_pos + 1..])?;
                        ext_pos += 1 + octet_offset;

                        // Inside the OCTET STRING is an ENUMERATED
                        if ext_pos + octet_len <= data.len()
                            && octet_len >= 3
                            && data[ext_pos] == 0x0a
                        {
                            let enum_len = data[ext_pos + 1] as usize;
                            if enum_len == 1 && ext_pos + 2 < data.len() {
                                reason = CrlReason::from_u8(data[ext_pos + 2]);
                            }
                        }
                    }
                }
            }

            pos = single_ext_end;
        }
    }

    Ok(RevokedCertificate {
        serial_number,
        revocation_date,
        reason,
    })
}

/// Parse a CRL time field (UTCTime or GeneralizedTime) to Unix timestamp
fn parse_crl_time(data: &[u8]) -> Result<i64, AuthError> {
    if data.is_empty() {
        return Err(AuthError::CertificateParseError);
    }

    let tag = data[0];
    let (len, offset) = parse_der_length(&data[1..])?;
    let time_str = &data[1 + offset..1 + offset + len];

    match tag {
        0x17 => parse_utc_time(time_str),         // UTCTime
        0x18 => parse_generalized_time(time_str), // GeneralizedTime
        _ => Err(AuthError::CertificateParseError),
    }
}

/// Skip a time field and return bytes consumed
fn skip_time_field(data: &[u8]) -> Result<usize, AuthError> {
    if data.is_empty() || (data[0] != 0x17 && data[0] != 0x18) {
        return Err(AuthError::CertificateParseError);
    }
    let (len, offset) = parse_der_length(&data[1..])?;
    Ok(1 + offset + len)
}

/// Parse UTCTime (YYMMDDHHMMSSZ)
fn parse_utc_time(data: &[u8]) -> Result<i64, AuthError> {
    if data.len() < 12 {
        return Err(AuthError::CertificateParseError);
    }

    let parse_two = |offset: usize| -> Result<i64, AuthError> {
        let d1 = (data[offset] as char)
            .to_digit(10)
            .ok_or(AuthError::CertificateParseError)?;
        let d2 = (data[offset + 1] as char)
            .to_digit(10)
            .ok_or(AuthError::CertificateParseError)?;
        Ok((d1 * 10 + d2) as i64)
    };

    let year = parse_two(0)?;
    let month = parse_two(2)?;
    let day = parse_two(4)?;
    let hour = parse_two(6)?;
    let minute = parse_two(8)?;
    let second = parse_two(10)?;

    // UTCTime uses 2-digit years: 00-49 = 2000-2049, 50-99 = 1950-1999
    let full_year = if year < 50 { 2000 + year } else { 1900 + year };

    Ok(datetime_to_unix_timestamp(
        full_year, month, day, hour, minute, second,
    ))
}

/// Parse GeneralizedTime (YYYYMMDDHHMMSSZ)
fn parse_generalized_time(data: &[u8]) -> Result<i64, AuthError> {
    if data.len() < 14 {
        return Err(AuthError::CertificateParseError);
    }

    let parse_two = |offset: usize| -> Result<i64, AuthError> {
        let d1 = (data[offset] as char)
            .to_digit(10)
            .ok_or(AuthError::CertificateParseError)?;
        let d2 = (data[offset + 1] as char)
            .to_digit(10)
            .ok_or(AuthError::CertificateParseError)?;
        Ok((d1 * 10 + d2) as i64)
    };

    let century = parse_two(0)?;
    let year = parse_two(2)?;
    let full_year = century * 100 + year;

    let month = parse_two(4)?;
    let day = parse_two(6)?;
    let hour = parse_two(8)?;
    let minute = parse_two(10)?;
    let second = parse_two(12)?;

    Ok(datetime_to_unix_timestamp(
        full_year, month, day, hour, minute, second,
    ))
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
    use der::Decode;
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der).map_err(|_| AuthError::CertificateParseError)?;

    let mut responders = Vec::new();

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id.as_bytes() == extension_oids::AUTHORITY_INFO_ACCESS {
                let value = ext.extn_value.as_bytes();
                if let Ok(parsed) = parse_authority_info_access(value) {
                    responders.extend(parsed);
                }
            }
        }
    }

    Ok(responders)
}

/// Parse Authority Information Access extension
///
/// AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
/// AccessDescription ::= SEQUENCE {
///     accessMethod    OBJECT IDENTIFIER,
///     accessLocation  GeneralName
/// }
fn parse_authority_info_access(data: &[u8]) -> Result<Vec<OcspResponder>, AuthError> {
    let mut responders = Vec::new();

    // Outer SEQUENCE
    if data.is_empty() || data[0] != 0x30 {
        return Err(AuthError::CertificateParseError);
    }

    let (seq_len, seq_offset) = parse_der_length(&data[1..])?;
    if 1 + seq_offset + seq_len > data.len() {
        return Err(AuthError::CertificateParseError);
    }

    let mut pos = 1 + seq_offset;
    let end = 1 + seq_offset + seq_len;

    while pos < end {
        // AccessDescription SEQUENCE
        if data[pos] != 0x30 {
            break;
        }
        pos += 1;

        let (ad_len, ad_offset) = parse_der_length(&data[pos..])?;
        let ad_end = pos + ad_offset + ad_len;
        pos += ad_offset;

        // accessMethod OID
        if pos >= ad_end || data[pos] != 0x06 {
            pos = ad_end;
            continue;
        }
        pos += 1;
        let (oid_len, oid_offset) = parse_der_length(&data[pos..])?;
        let oid_data = &data[pos + oid_offset..pos + oid_offset + oid_len];
        pos += oid_offset + oid_len;

        // Check if this is OCSP (1.3.6.1.5.5.7.48.1)
        if oid_data == extension_oids::OCSP_ACCESS_METHOD {
            // accessLocation - look for uniformResourceIdentifier [6]
            if pos < ad_end && data[pos] == 0x86 {
                pos += 1;
                let (uri_len, uri_offset) = parse_der_length(&data[pos..])?;
                pos += uri_offset;

                if pos + uri_len <= data.len()
                    && let Ok(uri) = core::str::from_utf8(&data[pos..pos + uri_len])
                {
                    responders.push(OcspResponder {
                        uri: String::from(uri),
                    });
                }
            }
        }

        pos = ad_end;
    }

    Ok(responders)
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
    use der::Decode;
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der).map_err(|_| AuthError::CertificateParseError)?;
    let issuer = Certificate::from_der(issuer_der).map_err(|_| AuthError::CertificateParseError)?;

    // Get issuer name hash (SHA-1)
    use der::Encode;
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

    // Build the OCSP request
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
/// # Arguments
///
/// * `response_der` - DER-encoded OCSP response
///
/// # Returns
///
/// The certificate status if the response is valid and successful
pub fn parse_ocsp_response(response_der: &[u8]) -> Result<OcspSingleResponse, AuthError> {
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
    pos += 1;

    let response_status =
        OcspResponseStatus::from_u8(status).ok_or(AuthError::CertificateParseError)?;

    if response_status != OcspResponseStatus::Successful {
        log::warn!("OCSP response status: {:?}", response_status);
        return Err(AuthError::CryptoError);
    }

    // responseBytes [0] EXPLICIT
    if pos >= content.len() || content[pos] != 0xa0 {
        return Err(AuthError::CertificateParseError);
    }
    pos += 1;
    let (_rb_len, rb_offset) = parse_der_length(&content[pos..])?;
    pos += rb_offset;

    // ResponseBytes SEQUENCE
    if pos >= content.len() || content[pos] != 0x30 {
        return Err(AuthError::CertificateParseError);
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
    use der::Decode;
    use x509_cert::Certificate;

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
    use der::Decode;
    use x509_cert::Certificate;

    let issuer = match Certificate::from_der(issuer_der) {
        Ok(c) => c,
        Err(_) => return RevocationCheckResult::Unknown,
    };

    use der::Encode;
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

/// Simple SHA-1 implementation for OCSP
/// Note: SHA-1 is required by OCSP spec for CertID
fn sha1_hash(data: &[u8]) -> [u8; 20] {
    // Simple SHA-1 implementation
    // In production, use a proper crypto library
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    // Pre-processing: adding padding bits
    let ml = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&ml.to_be_bytes());

    // Process each 512-bit chunk
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (i, w_i) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*w_i);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

/// Parse DER length encoding
fn parse_der_length(data: &[u8]) -> Result<(usize, usize), AuthError> {
    if data.is_empty() {
        return Err(AuthError::CertificateParseError);
    }

    let first = data[0];
    if first < 0x80 {
        // Short form
        Ok((first as usize, 1))
    } else if first == 0x80 {
        // Indefinite length - not supported
        Err(AuthError::CertificateParseError)
    } else {
        // Long form
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

/// Encode DER length
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

/// Convert date/time to Unix timestamp
fn datetime_to_unix_timestamp(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> i64 {
    let years_since_1970 = year - 1970;
    let leap_years = (year - 1969) / 4 - (year - 1901) / 100 + (year - 1601) / 400;

    let days_before_month = match month {
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
        years_since_1970 * 365 + leap_years + days_before_month + day - 1 + leap_day_adjustment;

    total_days * 86400 + hour * 3600 + minute * 60 + second
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crl_reason_from_u8() {
        assert_eq!(CrlReason::from_u8(0), Some(CrlReason::Unspecified));
        assert_eq!(CrlReason::from_u8(1), Some(CrlReason::KeyCompromise));
        assert_eq!(CrlReason::from_u8(5), Some(CrlReason::CessationOfOperation));
        assert_eq!(CrlReason::from_u8(7), None); // 7 is unused
        assert_eq!(CrlReason::from_u8(100), None);
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
    fn test_datetime_to_unix_timestamp() {
        // 2020-01-01 00:00:00 UTC = 1577836800
        assert_eq!(datetime_to_unix_timestamp(2020, 1, 1, 0, 0, 0), 1577836800);

        // 1970-01-01 00:00:00 UTC = 0
        assert_eq!(datetime_to_unix_timestamp(1970, 1, 1, 0, 0, 0), 0);
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
