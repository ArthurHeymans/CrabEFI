//! CMS/X.509 parsing on the `asn1` crate.
//!
//! Zero-copy borrowed views over the DER structures needed for Secure Boot
//! verification: PKCS#7 `SignedData`, X.509 certificates, CRL entries, and
//! Authenticode `SpcIndirectDataContent`. This module replaces the
//! `cms`/`x509-cert`/`der` framework with explicit parsing while preserving
//! byte-identical behavior:
//!
//! - Names (issuer/subject) and serials compare as raw DER bytes. Inputs
//!   here are already canonical DER (both encoders and the parser enforce
//!   it), so this matches the previous re-encode-and-compare convention.
//! - `signedAttrs` are re-encoded in DER SET OF order before hashing,
//!   exactly like the framework's `SetOf::to_der` did.
//! - The effective policy stays fail-closed SHA-256/RSA: RSA verification
//!   uses a SHA-256 DigestInfo prefix and all content hashes are SHA-256,
//!   so anything else was already rejected.
//!
//! Parsing strategy: `Tlv` captures exact byte ranges (comparisons, TBS
//! extraction, WIN_CERTIFICATE padding trim) while typed `asn1` values
//! validate OIDs, INTEGERs, times, and BIT/OCTET STRINGs.

use super::AuthError;
use alloc::vec::Vec;

// ============================================================================
// OID constants (DER content bytes, compared via ObjectIdentifier::as_der)
// ============================================================================

/// PKCS#7 signedData content type: 1.2.840.113549.1.7.2
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// messageDigest signed attribute: 1.2.840.113549.1.9.4
const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
/// Basic constraints extension: 2.5.29.19
pub const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
/// Key usage extension: 2.5.29.15
pub const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
/// Subject key identifier extension: 2.5.29.14
pub const OID_SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
/// CRL distribution points extension: 2.5.29.31
pub const OID_CRL_DISTRIBUTION_POINTS: &[u8] = &[0x55, 0x1d, 0x1f];

// DER tag bytes we match on.
const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_UTCTIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_CONTEXT_0: u8 = 0xa0;
const TAG_CONTEXT_3: u8 = 0xa3;

fn tag_of(tlv: &asn1::Tlv<'_>) -> Result<u8, AuthError> {
    tlv.tag().as_u8().ok_or(AuthError::CertificateParseError)
}

/// Trim trailing bytes (e.g. WIN_CERTIFICATE 8-byte alignment padding) by
/// returning exactly the first TLV.
pub fn trim_to_first_tlv(data: &[u8]) -> Result<&[u8], AuthError> {
    asn1::strip_tlv(data)
        .map(|(tlv, _)| tlv.full_data())
        .map_err(|_| AuthError::InvalidHeader)
}

/// Encode a DER length (used to rebuild SET OF wrappers for hashing).
fn encode_length(output: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        output.push(length as u8);
    } else {
        let mut bytes = [0u8; 8];
        let mut len = length;
        let mut count = 0;
        while len > 0 {
            bytes[7 - count] = (len & 0xff) as u8;
            len >>= 8;
            count += 1;
        }
        output.push(0x80 | (count as u8));
        output.extend_from_slice(&bytes[8 - count..]);
    }
}

/// Convert an asn1 DateTime to a Unix timestamp.
pub fn datetime_to_unix(dt: &asn1::DateTime) -> i64 {
    super::time::datetime_to_unix_timestamp(
        dt.year() as i64,
        dt.month() as i64,
        dt.day() as i64,
        dt.hour() as i64,
        dt.minute() as i64,
        dt.second() as i64,
    )
}

/// Parse a Time CHOICE (UTCTime or GeneralizedTime) TLV to Unix time.
pub fn parse_time_tlv(tlv: &asn1::Tlv<'_>) -> Result<i64, AuthError> {
    let full = tlv.full_data();
    match tag_of(tlv)? {
        TAG_UTCTIME => {
            let t = asn1::parse_single::<asn1::UtcTime>(full)
                .map_err(|_| AuthError::CertificateParseError)?;
            Ok(datetime_to_unix(t.as_datetime()))
        }
        TAG_GENERALIZED_TIME => {
            // Prefer the strict X.509 profile (no fractional seconds);
            // fall back to the general form.
            if let Ok(t) = asn1::parse_single::<asn1::X509GeneralizedTime>(full) {
                Ok(datetime_to_unix(t.as_datetime()))
            } else {
                let t = asn1::parse_single::<asn1::GeneralizedTime>(full)
                    .map_err(|_| AuthError::CertificateParseError)?;
                Ok(datetime_to_unix(t.as_datetime()))
            }
        }
        _ => Err(AuthError::CertificateParseError),
    }
}

// ============================================================================
// X.509 certificate views
// ============================================================================

/// Borrowed view of an X.509 certificate's security-relevant fields.
pub struct CertView<'a> {
    /// Full TBSCertificate TLV bytes (what signatures cover).
    pub tbs_der: &'a [u8],
    /// Serial number INTEGER content bytes.
    pub serial: &'a [u8],
    /// Full issuer Name TLV bytes.
    pub issuer_der: &'a [u8],
    /// Full subject Name TLV bytes.
    pub subject_der: &'a [u8],
    /// Validity window as Unix timestamps.
    pub not_before: i64,
    pub not_after: i64,
    /// BIT STRING content bytes of subjectPublicKey (DER RSAPublicKey).
    pub spki_key_der: &'a [u8],
    /// Full extensions [3] TLV bytes, if present.
    pub extensions_der: Option<&'a [u8]>,
    /// BIT STRING content bytes of signatureValue.
    pub signature: &'a [u8],
}

/// Parse a DER certificate into a borrowed view.
pub fn parse_cert_view(cert_der: &[u8]) -> Result<CertView<'_>, AuthError> {
    asn1::parse(
        cert_der,
        |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
            p.read_element::<asn1::Sequence>()?.parse(
                |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                    // TBSCertificate is the first element: capture exact bytes.
                    let tbs = p.read_element::<asn1::Tlv>()?;
                    if tag_of(&tbs)? != TAG_SEQUENCE {
                        return Err(AuthError::CertificateParseError);
                    }
                    let view = parse_tbs(tbs.data())?;
                    // signatureAlgorithm (structure-validated; RSA op gates values).
                    let _sig_alg = p.read_element::<asn1::Tlv>()?;
                    // signatureValue BIT STRING.
                    let signature = p.read_element::<asn1::BitString>()?.as_bytes();
                    Ok(CertView {
                        tbs_der: tbs.full_data(),
                        serial: view.serial,
                        issuer_der: view.issuer_der,
                        subject_der: view.subject_der,
                        not_before: view.not_before,
                        not_after: view.not_after,
                        spki_key_der: view.spki_key_der,
                        extensions_der: view.extensions_der,
                        signature,
                    })
                },
            )
        },
    )
    .map_err(|_| AuthError::CertificateParseError)
}

struct TbsView<'a> {
    serial: &'a [u8],
    issuer_der: &'a [u8],
    subject_der: &'a [u8],
    not_before: i64,
    not_after: i64,
    spki_key_der: &'a [u8],
    extensions_der: Option<&'a [u8]>,
}

/// Walk TBSCertificate content bytes for the security-relevant fields.
fn parse_tbs(tbs_content: &[u8]) -> Result<TbsView<'_>, AuthError> {
    asn1::parse(
        tbs_content,
        |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
            // Optional [0] EXPLICIT version.
            if p.peek_tag()
                .is_some_and(|t| t.as_u8() == Some(TAG_CONTEXT_0))
            {
                let _version = p.read_element::<asn1::Tlv>()?;
            }
            // Serial INTEGER content bytes.
            let serial_tlv = p.read_element::<asn1::Tlv>()?;
            if tag_of(&serial_tlv)? != TAG_INTEGER {
                return Err(AuthError::CertificateParseError);
            }
            let serial = asn1::parse_single::<asn1::BigUint>(serial_tlv.full_data())?.as_bytes();
            // Signature AlgorithmIdentifier (opaque here).
            let _sig_alg = p.read_element::<asn1::Tlv>()?;
            // Issuer Name: capture full TLV bytes.
            let issuer = p.read_element::<asn1::Tlv>()?;
            if tag_of(&issuer)? != TAG_SEQUENCE {
                return Err(AuthError::CertificateParseError);
            }
            // Validity SEQUENCE { notBefore Time, notAfter Time }.
            let (not_before, not_after) = p.read_element::<asn1::Sequence>()?.parse(
                |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                    let nb = p.read_element::<asn1::Tlv>()?;
                    let na = p.read_element::<asn1::Tlv>()?;
                    Ok((parse_time_tlv(&nb)?, parse_time_tlv(&na)?))
                },
            )?;
            // Subject Name: capture full TLV bytes.
            let subject = p.read_element::<asn1::Tlv>()?;
            if tag_of(&subject)? != TAG_SEQUENCE {
                return Err(AuthError::CertificateParseError);
            }
            // SubjectPublicKeyInfo: keep BIT STRING content (DER RSAPublicKey).
            let spki_key_der = p.read_element::<asn1::Sequence>()?.parse(
                |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                    let _alg = p.read_element::<asn1::Tlv>()?;
                    Ok(p.read_element::<asn1::BitString>()?.as_bytes())
                },
            )?;
            // Trailing optionals: [1]/[2] unique IDs, [3] extensions.
            let mut extensions_der = None;
            while !p.is_empty() {
                let t = p.read_element::<asn1::Tlv>()?;
                if tag_of(&t)? == TAG_CONTEXT_3 {
                    extensions_der = Some(t.full_data());
                }
            }
            Ok(TbsView {
                serial,
                issuer_der: issuer.full_data(),
                subject_der: subject.full_data(),
                not_before,
                not_after,
                spki_key_der,
                extensions_der,
            })
        },
    )
}

// ============================================================================
// Extension walking
// ============================================================================

/// Find an extension by OID; returns the extnValue OCTET STRING content bytes.
///
/// Matches the previous `ext.extn_value.as_bytes()` convention exactly.
pub fn find_extension<'a>(
    extensions_tlv: &'a [u8],
    oid: &[u8],
) -> Result<Option<&'a [u8]>, AuthError> {
    asn1::parse(
        extensions_tlv,
        |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
            // [3] EXPLICIT wrapper.
            if p.peek_tag()
                .is_some_and(|t| t.as_u8() == Some(TAG_CONTEXT_3))
            {
                let inner = p.read_element::<asn1::Tlv>()?;
                return find_extension_in_seq(inner.data(), oid);
            }
            // Or the bare Extensions SEQUENCE (callers may pass either).
            find_extension_in_seq(extensions_tlv, oid)
        },
    )
    .map_err(|_| AuthError::CertificateParseError)
}

fn find_extension_in_seq<'a>(seq_der: &'a [u8], oid: &[u8]) -> Result<Option<&'a [u8]>, AuthError> {
    asn1::parse(
        seq_der,
        |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
            p.read_element::<asn1::Sequence>()?.parse(
                |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                    // N.B.: no early return on match — Sequence::parse
                    // rejects trailing bytes, so every element must be
                    // consumed even after the wanted OID is found.
                    let mut found = None;
                    while !p.is_empty() {
                        let ext_oids = p.read_element::<asn1::Sequence>()?.parse(
                            |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                                let id = p.read_element::<asn1::ObjectIdentifier>()?;
                                let matches = id.as_der() == oid;
                                // Optional critical BOOLEAN.
                                if p.peek_tag().is_some_and(|t| {
                                    t.as_u8() == Some(0x01) // BOOLEAN
                                }) {
                                    let _critical: bool = p.read_element()?;
                                }
                                let value = p.read_element::<&[u8]>()?;
                                Ok((matches, value))
                            },
                        )?;
                        if found.is_none() && ext_oids.0 {
                            found = Some(ext_oids.1);
                        }
                    }
                    Ok(found)
                },
            )
        },
    )
}

/// Parsed basicConstraints.
pub struct BasicConstraints {
    pub ca: bool,
    pub path_len: Option<u32>,
}

/// Parse a basicConstraints extnValue.
pub fn parse_basic_constraints(value: &[u8]) -> Result<BasicConstraints, AuthError> {
    asn1::parse(value, |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
        // Empty SEQUENCE means cA=FALSE, no pathLen.
        let (ca, path_len) = p.read_element::<asn1::Sequence>()?.parse(
            |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                if p.is_empty() {
                    return Ok((false, None));
                }
                let ca: bool = p.read_element()?;
                let path_len = if p.is_empty() {
                    None
                } else {
                    let bytes = p.read_element::<asn1::BigUint>()?.as_bytes();
                    if bytes.len() > 4 {
                        return Err(AuthError::CertificateParseError);
                    }
                    let mut v = 0u32;
                    for b in bytes {
                        v = (v << 8) | u32::from(*b);
                    }
                    // Historical type was u8: larger values errored.
                    if v > u8::MAX as u32 {
                        return Err(AuthError::CertificateParseError);
                    }
                    Some(v)
                };
                Ok((ca, path_len))
            },
        )?;
        Ok(BasicConstraints { ca, path_len })
    })
    .map_err(|_| AuthError::CertificateParseError)
}

/// Key usage bits of interest, plus the raw u16 for logging.
pub struct KeyUsageBits {
    pub digital_signature: bool,
    pub key_cert_sign: bool,
    pub bits: u16,
}

/// Parse a keyUsage extnValue (BIT STRING content bytes).
pub fn parse_key_usage(value: &[u8]) -> Result<KeyUsageBits, AuthError> {
    // extnValue is the OCTET STRING content = DER BIT STRING.
    let bits = asn1::parse_single::<asn1::BitString>(value)
        .map_err(|_| AuthError::CertificateParseError)?
        .as_bytes();
    let mut raw = [0u8; 2];
    let take = core::cmp::min(bits.len(), 2);
    raw[..take].copy_from_slice(&bits[..take]);
    let word = u16::from_be_bytes(raw);
    Ok(KeyUsageBits {
        // Bit 0 (digitalSignature) = MSB of first byte; bit 5 (keyCertSign).
        digital_signature: word & 0x8000 != 0,
        key_cert_sign: word & 0x0400 != 0,
        bits: word,
    })
}

// ============================================================================
// PKCS#7 SignedData views
// ============================================================================

/// How a signer is identified.
pub enum SignerId<'a> {
    IssuerAndSerial {
        issuer_der: &'a [u8],
        serial: &'a [u8],
    },
    SubjectKeyId(&'a [u8]),
}

/// Borrowed view of one SignerInfo.
pub struct SignerView<'a> {
    pub sid: SignerId<'a>,
    /// Full signedAttrs SET OF TLV bytes (rebuilt in DER order for hashing),
    /// or None when the SET was absent.
    pub signed_attrs_der: Option<Vec<u8>>,
    /// Raw messageDigest bytes from the signed attributes, if present.
    pub message_digest: Option<Vec<u8>>,
    /// OCTET STRING content bytes of the signature.
    pub signature: &'a [u8],
}

/// Borrowed view of SignedData content (after the ContentInfo wrapper).
pub struct SignedDataView<'a> {
    /// Hash these (VALUE) bytes when eContent is present; matches the
    /// previous `Any::value()` convention in all encodings.
    pub econtent_hash_input: Option<&'a [u8]>,
    /// Each embedded certificate's full TLV bytes (SEQUENCE elements only,
    /// matching the previous CertificateChoices::Certificate filter).
    pub certs: Vec<&'a [u8]>,
    pub signers: Vec<SignerView<'a>>,
}

/// Parse ContentInfo, require signedData, and return the SignedData view.
pub fn parse_signed_data(content_info_der: &[u8]) -> Result<SignedDataView<'_>, AuthError> {
    asn1::parse(
        content_info_der,
        |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
            p.read_element::<asn1::Sequence>()?.parse(
                |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                    // contentType OID must be signedData.
                    let ctype = p.read_element::<asn1::ObjectIdentifier>()?;
                    if ctype.as_der() != OID_SIGNED_DATA {
                        return Err(AuthError::CertificateParseError);
                    }
                    // [0] EXPLICIT SignedData.
                    let signed = p.read_element::<asn1::Tlv>()?;
                    if tag_of(&signed)? != TAG_CONTEXT_0 {
                        return Err(AuthError::CertificateParseError);
                    }
                    parse_signed_data_content(signed.data())
                },
            )
        },
    )
    .map_err(|_| AuthError::InvalidHeader)
}

fn parse_signed_data_content(content: &[u8]) -> Result<SignedDataView<'_>, AuthError> {
    asn1::parse(
        content,
        |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
            p.read_element::<asn1::Sequence>()?.parse(
                |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                    // version INTEGER (accepted as-is; policy gates elsewhere).
                    let _version = p.read_element::<asn1::Tlv>()?;
                    // digestAlgorithms SET OF (structure-validated).
                    let _algs = p.read_element::<asn1::Tlv>()?;
                    // encapContentInfo.
                    let econtent_hash_input = p.read_element::<asn1::Sequence>()?.parse(
                        |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                            let _ctype = p.read_element::<asn1::ObjectIdentifier>()?;
                            // Optional [0] EXPLICIT eContent.
                            if p.is_empty()
                                || !p
                                    .peek_tag()
                                    .is_some_and(|t| t.as_u8() == Some(TAG_CONTEXT_0))
                            {
                                return Ok(None);
                            }
                            let econtent = p.read_element::<asn1::Tlv>()?;
                            // eContent hash input is always the VALUE bytes of
                            // the inner element (matching `Any::value()`),
                            // whether OCTET STRING-wrapped or directly encoded.
                            let inner = asn1::strip_tlv(econtent.data())?.0;
                            Ok(Some(inner.data()))
                        },
                    )?;
                    // Optional [0] IMPLICIT certificates.
                    let mut certs = Vec::new();
                    if p.peek_tag()
                        .is_some_and(|t| t.as_u8() == Some(TAG_CONTEXT_0))
                    {
                        let set = p.read_element::<asn1::Tlv>()?;
                        // Walk inner TLVs; keep SEQUENCE elements (plain certs).
                        let mut rest = set.data();
                        while !rest.is_empty() {
                            let (elem, tail) = asn1::strip_tlv(rest)?;
                            if tag_of(&elem)? == TAG_SEQUENCE {
                                certs.push(elem.full_data());
                            }
                            rest = tail;
                        }
                    }
                    // signerInfos SET OF SignerInfo (required, non-empty).
                    let signers_tlv = p.read_element::<asn1::Tlv>()?;
                    if tag_of(&signers_tlv)? != 0x31 {
                        return Err(AuthError::CertificateParseError);
                    }
                    let mut signers = Vec::new();
                    let mut rest = signers_tlv.data();
                    if rest.is_empty() {
                        return Err(AuthError::CertificateParseError);
                    }
                    while !rest.is_empty() {
                        let (si, tail) = asn1::strip_tlv(rest)?;
                        signers.push(parse_signer_info(si.full_data())?);
                        rest = tail;
                    }
                    Ok(SignedDataView {
                        econtent_hash_input,
                        certs,
                        signers,
                    })
                },
            )
        },
    )
}

fn parse_signer_info(si_der: &[u8]) -> Result<SignerView<'_>, AuthError> {
    asn1::parse(si_der, |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
        p.read_element::<asn1::Sequence>()?.parse(
            |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                // version INTEGER.
                let _version = p.read_element::<asn1::Tlv>()?;
                // sid CHOICE.
                let sid_tlv = p.read_element::<asn1::Tlv>()?;
                let sid = match tag_of(&sid_tlv)? {
                    TAG_SEQUENCE => {
                        // IssuerAndSerialNumber.
                        let (issuer_der, serial) = asn1::parse(
                            sid_tlv.full_data(),
                            |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                                p.read_element::<asn1::Sequence>()?.parse(
                                    |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                                        let issuer = p.read_element::<asn1::Tlv>()?;
                                        let serial_tlv = p.read_element::<asn1::Tlv>()?;
                                        let serial = asn1::parse_single::<asn1::BigUint>(
                                            serial_tlv.full_data(),
                                        )?
                                        .as_bytes();
                                        Ok((issuer.full_data(), serial))
                                    },
                                )
                            },
                        )?;
                        SignerId::IssuerAndSerial { issuer_der, serial }
                    }
                    // [0] IMPLICIT OCTET STRING is primitive (0x80): the
                    // content bytes are the key identifier directly.
                    0x80 => SignerId::SubjectKeyId(sid_tlv.data()),
                    _ => return Err(AuthError::CertificateParseError),
                };
                // digestAlgorithm (parsed for structure; SHA-256 enforced by use).
                let _digest_alg = p.read_element::<asn1::Tlv>()?;
                // Optional [0] IMPLICIT signedAttrs.
                let (signed_attrs_der, message_digest) = if p
                    .peek_tag()
                    .is_some_and(|t| t.as_u8() == Some(TAG_CONTEXT_0))
                {
                    let attrs = p.read_element::<asn1::Tlv>()?;
                    let set_der = rebuild_set_of(attrs.data())?;
                    let md = extract_message_digest_from_attrs(attrs.data())?;
                    (Some(set_der), md)
                } else {
                    (None, None)
                };
                // signatureAlgorithm (parsed for structure; RSA op gates values).
                let _sig_alg = p.read_element::<asn1::Tlv>()?;
                // signature OCTET STRING.
                let signature = p.read_element::<&[u8]>()?;
                // Optional unsignedAttrs [1] IMPLICIT (e.g. TSA countersignatures):
                // parsed-and-ignored, matching previous behavior.
                if !p.is_empty() {
                    let unsigned = p.read_element::<asn1::Tlv>()?;
                    if unsigned.tag().as_u8() != Some(0xa1) {
                        return Err(AuthError::CertificateParseError);
                    }
                }
                Ok(SignerView {
                    sid,
                    signed_attrs_der,
                    message_digest,
                    signature,
                })
            },
        )
    })
}

/// Rebuild a DER SET OF TLV from raw content bytes: sort elements by
/// encoded bytes, matching framework `SetOf::to_der` output.
fn rebuild_set_of(content: &[u8]) -> Result<Vec<u8>, AuthError> {
    let mut elements: Vec<&[u8]> = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let (elem, tail) = asn1::strip_tlv(rest)?;
        elements.push(elem.full_data());
        rest = tail;
    }
    elements.sort_unstable();
    let mut out = Vec::new();
    let total: usize = elements.iter().map(|e| e.len()).sum();
    out.push(0x31); // SET OF
    let mut len_buf = Vec::new();
    encode_length(&mut len_buf, total);
    out.extend_from_slice(&len_buf);
    for elem in elements {
        out.extend_from_slice(elem);
    }
    Ok(out)
}

/// Find the messageDigest attribute (OID 1.2.840.113549.1.9.4) in raw
/// signedAttrs content bytes; returns the OCTET STRING value bytes.
fn extract_message_digest_from_attrs(content: &[u8]) -> Result<Option<Vec<u8>>, AuthError> {
    let mut rest = content;
    while !rest.is_empty() {
        let (attr, tail) = asn1::strip_tlv(rest)?;
        rest = tail;
        // Attribute ::= SEQUENCE { OID, SET OF values }. Both fields are
        // consumed up front: Sequence::parse rejects trailing bytes, so an
        // early return must not leave the values SET unread.
        let (is_digest, values) = asn1::parse(
            attr.full_data(),
            |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                p.read_element::<asn1::Sequence>()?.parse(
                    |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                        let oid = p.read_element::<asn1::ObjectIdentifier>()?;
                        let set = p.read_element::<asn1::Tlv>()?;
                        Ok((oid.as_der() == OID_MESSAGE_DIGEST, set.full_data()))
                    },
                )
            },
        )?;
        if !is_digest {
            continue;
        }
        // SET OF AttributeValue: take the first value, an OCTET STRING.
        let set_content =
            asn1::parse(values, |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                Ok(p.read_element::<asn1::Tlv>()?.data())
            })?;
        let (first, _) = asn1::strip_tlv(set_content)?;
        if tag_of(&first)? != TAG_OCTET_STRING {
            return Err(AuthError::CertificateParseError);
        }
        return Ok(Some(first.data().to_vec()));
    }
    Ok(None)
}

// ============================================================================
// Authenticode SpcIndirectDataContent
// ============================================================================

/// Extract the digest OCTET STRING from SpcIndirectDataContent bytes.
///
/// Accepts both the OCTET STRING-wrapped and directly-encoded forms,
/// matching previous behavior.
pub fn extract_spc_digest(spc_der: &[u8]) -> Result<Vec<u8>, AuthError> {
    // If wrapped in OCTET STRING, unwrap to the inner DER first.
    let inner = asn1::parse(
        spc_der,
        |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
            if p.peek_tag()
                .is_some_and(|t| t.as_u8() == Some(TAG_OCTET_STRING))
            {
                Ok(p.read_element::<&[u8]>()?)
            } else {
                // Direct encoding: the whole input is the content.
                Ok(spc_der)
            }
        },
    )
    .map_err(|_| AuthError::InvalidHeader)?;
    asn1::parse(inner, |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
        p.read_element::<asn1::Sequence>()?.parse(
            |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                // Skip SpcAttributeTypeAndOptionalValue.
                let _data = p.read_element::<asn1::Tlv>()?;
                // DigestInfo SEQUENCE { alg (skip), digest OCTET STRING }.
                p.read_element::<asn1::Sequence>()?.parse(
                    |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                        let _alg = p.read_element::<asn1::Tlv>()?;
                        Ok(p.read_element::<&[u8]>()?.to_vec())
                    },
                )
            },
        )
    })
    .map_err(|_| AuthError::InvalidHeader)
}

// ============================================================================
// CRL views
// ============================================================================

/// CRL reason codes (RFC 5280 5.3.1), replacing the x509-cert re-export.
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

/// One revoked certificate entry.
pub struct RevokedEntry<'a> {
    pub serial: &'a [u8],
    pub revocation_date: i64,
    pub reason: Option<CrlReason>,
}

/// Borrowed view of a CRL's security-relevant fields.
pub struct CrlView<'a> {
    pub issuer_der: &'a [u8],
    pub this_update: i64,
    pub next_update: Option<i64>,
    pub revoked: Vec<RevokedEntry<'a>>,
}

/// Parse a DER CRL. Enforces the same size/entry bounds as before via the
/// caller's length checks; entry count is capped here.
pub fn parse_crl_view(crl_der: &[u8], max_entries: usize) -> Result<CrlView<'_>, AuthError> {
    asn1::parse(
        crl_der,
        |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
            p.read_element::<asn1::Sequence>()?.parse(
                |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                    // TBSCertList.
                    let tbs = p.read_element::<asn1::Tlv>()?;
                    if tag_of(&tbs)? != TAG_SEQUENCE {
                        return Err(AuthError::CertificateParseError);
                    }
                    let view = parse_tbs_cert_list(tbs.data(), max_entries)?;
                    // signatureAlgorithm + signatureValue (structure only; CRLs are
                    // trusted via their dbx/file source, as before).
                    let _sig_alg = p.read_element::<asn1::Tlv>()?;
                    let _sig = p.read_element::<asn1::Tlv>()?;
                    Ok(view)
                },
            )
        },
    )
    .map_err(|_| AuthError::CertificateParseError)
}

fn parse_tbs_cert_list(content: &[u8], max_entries: usize) -> Result<CrlView<'_>, AuthError> {
    asn1::parse(
        content,
        |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
            // Optional version INTEGER.
            if p.peek_tag().is_some_and(|t| t.as_u8() == Some(TAG_INTEGER)) {
                let _version = p.read_element::<asn1::Tlv>()?;
            }
            // Signature AlgorithmIdentifier.
            let _sig_alg = p.read_element::<asn1::Tlv>()?;
            // Issuer Name bytes.
            let issuer_der = p.read_element::<asn1::Tlv>()?.full_data();
            // thisUpdate / optional nextUpdate.
            let this_update = parse_time_tlv(&p.read_element::<asn1::Tlv>()?)?;
            let next_update = if p.peek_tag().is_some_and(|t| {
                matches!(t.as_u8(), Some(TAG_UTCTIME) | Some(TAG_GENERALIZED_TIME))
            }) {
                Some(parse_time_tlv(&p.read_element::<asn1::Tlv>()?)?)
            } else {
                None
            };
            // Optional revokedCertificates SEQUENCE OF. A trailing [0]
            // EXPLICIT CRL extensions element (e.g. CRL number) is skipped.
            let mut revoked = Vec::new();
            if !p.is_empty()
                && !p
                    .peek_tag()
                    .is_some_and(|t| t.as_u8() == Some(TAG_CONTEXT_0))
            {
                let list = p.read_element::<asn1::Tlv>()?;
                if tag_of(&list)? != TAG_SEQUENCE {
                    return Err(AuthError::CertificateParseError);
                }
                let mut rest = list.data();
                while !rest.is_empty() {
                    let (entry, tail) = asn1::strip_tlv(rest)?;
                    rest = tail;
                    // Parse up to the cap but keep consuming: Sequence::parse
                    // rejects trailing bytes, and the caller warns on truncation.
                    if revoked.len() < max_entries {
                        revoked.push(parse_revoked_entry(entry.full_data())?);
                    }
                }
            }
            // Optional trailing [0] EXPLICIT CRL extensions (e.g. CRL number,
            // authority key identifier): structure-skipped, as before.
            if !p.is_empty() {
                let exts = p.read_element::<asn1::Tlv>()?;
                if tag_of(&exts)? != TAG_CONTEXT_0 {
                    return Err(AuthError::CertificateParseError);
                }
            }
            Ok(CrlView {
                issuer_der,
                this_update,
                next_update,
                revoked,
            })
        },
    )
}

fn parse_revoked_entry(entry_der: &[u8]) -> Result<RevokedEntry<'_>, AuthError> {
    asn1::parse(
        entry_der,
        |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
            p.read_element::<asn1::Sequence>()?.parse(
                |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                    let serial_tlv = p.read_element::<asn1::Tlv>()?;
                    let serial =
                        asn1::parse_single::<asn1::BigUint>(serial_tlv.full_data())?.as_bytes();
                    let date = parse_time_tlv(&p.read_element::<asn1::Tlv>()?)?;
                    // Optional entry extensions: look for CRL reason (ENUMERATED).
                    let mut reason = None;
                    if !p.is_empty() {
                        let exts = p.read_element::<asn1::Tlv>()?;
                        reason = find_crl_reason(exts.data())?;
                    }
                    Ok(RevokedEntry {
                        serial,
                        revocation_date: date,
                        reason,
                    })
                },
            )
        },
    )
}

fn find_crl_reason(exts_content: &[u8]) -> Result<Option<CrlReason>, AuthError> {
    // SEQUENCE OF Extension; reason OID 2.5.29.21 (DER: 55 1D 15? no:
    // cRLReasons 2.5.29.21 = 55 1D 15... careful: 2.5.29.21 encodes as
    // 55 1D 15? 21 decimal = 0x15. Yes: [0x55, 0x1D, 0x15]).
    const OID_CRL_REASON: &[u8] = &[0x55, 0x1d, 0x15];
    let mut rest = exts_content;
    while !rest.is_empty() {
        let (ext, tail) = asn1::strip_tlv(rest)?;
        rest = tail;
        let found = asn1::parse(
            ext.full_data(),
            |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                p.read_element::<asn1::Sequence>()?.parse(
                    |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                        let oid = p.read_element::<asn1::ObjectIdentifier>()?;
                        if oid.as_der() != OID_CRL_REASON {
                            return Ok(None);
                        }
                        if p.peek_tag().is_some_and(|t| t.as_u8() == Some(0x01)) {
                            let _critical: bool = p.read_element()?;
                        }
                        let value = p.read_element::<&[u8]>()?;
                        // extnValue content = DER ENUMERATED.
                        let n = asn1::parse_single::<asn1::Enumerated>(value)?.value();
                        Ok(CrlReason::from_u32(n))
                    },
                )
            },
        )?;
        if found.is_some() {
            return Ok(found);
        }
    }
    Ok(None)
}

/// Extract CRL distribution-point URIs (context [6] IA5String) from a
/// CRLDP extension value. Diagnostic only; the firmware cannot fetch.
pub fn extract_crl_uris(ext_value: &[u8]) -> Result<Vec<Vec<u8>>, AuthError> {
    // ext_value = DER SEQUENCE OF DistributionPoint.
    let mut uris = Vec::new();
    let found = asn1::parse(
        ext_value,
        |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
            p.read_element::<asn1::Sequence>()?.parse(
                |p: &mut asn1::Parser<'_>| -> Result<_, AuthError> {
                    let mut inner_uris = Vec::new();
                    while !p.is_empty() {
                        let dp = p.read_element::<asn1::Tlv>()?;
                        collect_uris(dp.data(), &mut inner_uris)?;
                    }
                    Ok(inner_uris)
                },
            )
        },
    )
    .map_err(|_| AuthError::CertificateParseError)?;
    uris.extend(found);
    Ok(uris)
}

fn collect_uris(data: &[u8], out: &mut Vec<Vec<u8>>) -> Result<(), AuthError> {
    // Walk raw TLVs; any context-6 (URI) primitive captures its content.
    // GeneralName UniformResourceIdentifier = [6] IMPLICIT IA5String.
    let mut rest = data;
    while !rest.is_empty() {
        let (tlv, tail) = asn1::strip_tlv(rest)?;
        rest = tail;
        if tag_of(&tlv)? == 0x86 {
            out.push(tlv.data().to_vec());
        } else if tlv.tag().is_constructed() {
            collect_uris(tlv.data(), out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_trim_rejects_truncated_and_indefinite() {
        assert!(trim_to_first_tlv(&[0x30]).is_err());
        assert!(trim_to_first_tlv(&[0x30, 0x80]).is_err());
        assert!(trim_to_first_tlv(&[]).is_err());
        // One TLV plus padding returns just the first.
        let data = [0x30, 0x03, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(trim_to_first_tlv(&data), Ok(&data[..5]));
    }

    #[test]
    fn set_rebuild_sorts_der_order() {
        // Two attributes out of order must hash in DER order.
        let attr_b = [0x30, 0x03, 0x06, 0x01, 0x2b];
        let attr_a = [0x30, 0x03, 0x06, 0x01, 0x2a];
        let mut content = Vec::new();
        content.extend_from_slice(&attr_b);
        content.extend_from_slice(&attr_a);
        let rebuilt = rebuild_set_of(&content).unwrap();
        let mut expected = Vec::new();
        expected.push(0x31);
        expected.push(10);
        expected.extend_from_slice(&attr_a);
        expected.extend_from_slice(&attr_b);
        assert_eq!(rebuilt, expected);
    }

    #[test]
    fn crl_reason_round_trips() {
        assert_eq!(CrlReason::from_u32(1), Some(CrlReason::KeyCompromise));
        assert_eq!(CrlReason::from_u32(7), None);
        assert_eq!(CrlReason::from_u32(10), Some(CrlReason::AaCompromise));
    }

    #[test]
    fn encode_length_forms() {
        let mut out = Vec::new();
        encode_length(&mut out, 5);
        assert_eq!(out, [5]);
        out.clear();
        encode_length(&mut out, 200);
        assert_eq!(out, [0x81, 200]);
        out.clear();
        encode_length(&mut out, 0x1234);
        assert_eq!(out, [0x82, 0x12, 0x34]);
    }
}
