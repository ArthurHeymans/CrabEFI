//! Borrowed CMS/X.509 parsing and bounded RSA verification.

use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

use super::AuthError;
use crate::scratch;

const MAX_CERTIFICATES: usize = 16;
const MAX_SIGNERS: usize = 8;
const MAX_CERTIFICATE_SIZE: usize = 16 * 1024;
const MAX_CHAIN_DEPTH: usize = 5;
const MAX_RSA_BITS: usize = 4096;

const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x0e];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    full: &'a [u8],
    value: &'a [u8],
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn next(&mut self) -> Result<Tlv<'a>, AuthError> {
        let (value, remaining) = parse_tlv(self.remaining)?;
        self.remaining = remaining;
        Ok(value)
    }

    fn optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>, AuthError> {
        if self.remaining.first() == Some(&tag) {
            self.next().map(Some)
        } else {
            Ok(None)
        }
    }

    fn finish(self) -> Result<(), AuthError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(AuthError::InvalidHeader)
        }
    }
}

#[derive(Clone, Copy)]
struct CertificateView<'a> {
    raw: &'a [u8],
    tbs: &'a [u8],
    serial: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    subject_key_identifier: Option<&'a [u8]>,
    basic_constraints_ca: Option<bool>,
    key_usage: Option<u16>,
    modulus: &'a [u8],
    exponent: &'a [u8],
    signature: &'a [u8],
}

impl CertificateView<'_> {
    fn can_sign_certificates(self) -> bool {
        self.basic_constraints_ca == Some(true)
            && self.key_usage.is_none_or(|usage| usage & (1 << 5) != 0)
    }
}

#[derive(Clone, Copy, Default)]
struct CertificateExtensions<'a> {
    subject_key_identifier: Option<&'a [u8]>,
    basic_constraints_ca: Option<bool>,
    key_usage: Option<u16>,
}

#[derive(Clone, Copy)]
enum SignerId<'a> {
    IssuerSerial { issuer: &'a [u8], serial: &'a [u8] },
    SubjectKeyIdentifier(&'a [u8]),
}

#[derive(Clone, Copy)]
struct SignerView<'a> {
    identity: SignerId<'a>,
    signed_attributes: Option<Tlv<'a>>,
    signature: &'a [u8],
}

pub fn verify_pkcs7_signature(
    pkcs7_data: &[u8],
    signed_content: &[u8],
    trusted_cert: &[u8],
) -> Result<bool, AuthError> {
    let checkpoint = scratch::checkpoint();
    let result = verify_pkcs7_signature_inner(pkcs7_data, signed_content, trusted_cert);
    scratch::rewind(checkpoint);
    result
}

fn verify_pkcs7_signature_inner(
    pkcs7_data: &[u8],
    signed_content: &[u8],
    trusted_cert: &[u8],
) -> Result<bool, AuthError> {
    if pkcs7_data.len() > super::MAX_AUTHENTICATED_ENVELOPE_SIZE
        || trusted_cert.len() > MAX_CERTIFICATE_SIZE
        || !scratch::preflight(256 * 1024)
    {
        return Err(AuthError::OutOfResources);
    }
    let content_info = expect(parse_tlv(pkcs7_data)?.0, 0x30)?;
    let mut content = Reader::new(content_info.value);
    if expect(content.next()?, 0x06)?.value != OID_SIGNED_DATA {
        return Err(AuthError::InvalidHeader);
    }
    let explicit = expect(content.next()?, 0xa0)?;
    content.finish()?;
    let signed_data = expect(parse_tlv(explicit.value)?.0, 0x30)?;
    let mut signed = Reader::new(signed_data.value);
    let _version = expect(signed.next()?, 0x02)?;
    validate_digest_set(expect(signed.next()?, 0x31)?)?;
    let encapsulated = expect(signed.next()?, 0x30)?;
    let content_hash = encapsulated_content_hash(encapsulated, signed_content)?;

    let mut certificates = [None; MAX_CERTIFICATES];
    let mut certificate_count = 0usize;
    if let Some(set) = signed.optional(0xa0)? {
        let mut entries = Reader::new(set.value);
        while !entries.remaining.is_empty() {
            let certificate = entries.next()?;
            if certificate.tag != 0x30 || certificate.full.len() > MAX_CERTIFICATE_SIZE {
                return Err(AuthError::InvalidHeader);
            }
            let Some(slot) = certificates.get_mut(certificate_count) else {
                return Err(AuthError::OutOfResources);
            };
            *slot = Some(certificate.full);
            certificate_count += 1;
        }
    }
    let _crls = signed.optional(0xa1)?;
    let signer_set = expect(signed.next()?, 0x31)?;
    signed.finish()?;
    if certificate_count == 0 {
        return Err(AuthError::NoSuitableKey);
    }
    let trusted = parse_certificate(trusted_cert)?;

    let mut signer_reader = Reader::new(signer_set.value);
    let mut signer_count = 0usize;
    while !signer_reader.remaining.is_empty() {
        signer_count += 1;
        if signer_count > MAX_SIGNERS {
            return Err(AuthError::OutOfResources);
        }
        let signer = parse_signer(expect(signer_reader.next()?, 0x30)?)?;
        let Some(signer_certificate) =
            find_signer(signer.identity, &certificates[..certificate_count])?
        else {
            continue;
        };
        let content_digest = signed_attributes_digest(signer.signed_attributes, &content_hash)?;
        let key = rsa_key(&signer_certificate)?;
        if verify_rsa_signature(&key, signer.signature, &content_digest)?
            && certificate_authorized(
                signer_certificate,
                trusted,
                &certificates[..certificate_count],
                0,
            )?
        {
            return Ok(true);
        }
    }
    if signer_count == 0 {
        return Err(AuthError::InvalidHeader);
    }
    Ok(false)
}

fn parse_tlv(bytes: &[u8]) -> Result<(Tlv<'_>, &[u8]), AuthError> {
    if bytes.len() < 2 || bytes[0] & 0x1f == 0x1f {
        return Err(AuthError::InvalidHeader);
    }
    let first = bytes[1];
    let (length, header) = if first < 0x80 {
        (usize::from(first), 2usize)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || bytes.len() < 2 + count || bytes[2] == 0 {
            return Err(AuthError::InvalidHeader);
        }
        let mut length = 0usize;
        for byte in &bytes[2..2 + count] {
            length = length
                .checked_shl(8)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or(AuthError::InvalidHeader)?;
        }
        if length < 0x80 {
            return Err(AuthError::InvalidHeader);
        }
        (length, 2 + count)
    };
    let end = header.checked_add(length).ok_or(AuthError::InvalidHeader)?;
    let full = bytes.get(..end).ok_or(AuthError::InvalidHeader)?;
    Ok((
        Tlv {
            tag: bytes[0],
            full,
            value: &bytes[header..end],
        },
        &bytes[end..],
    ))
}

fn expect(value: Tlv<'_>, tag: u8) -> Result<Tlv<'_>, AuthError> {
    if value.tag == tag {
        Ok(value)
    } else {
        Err(AuthError::InvalidHeader)
    }
}

fn validate_digest_set(set: Tlv<'_>) -> Result<(), AuthError> {
    let mut algorithms = Reader::new(set.value);
    let algorithm = expect(algorithms.next()?, 0x30)?;
    validate_sha256_algorithm(algorithm)?;
    algorithms.finish()
}

fn validate_sha256_algorithm(algorithm: Tlv<'_>) -> Result<(), AuthError> {
    let mut fields = Reader::new(algorithm.value);
    if expect(fields.next()?, 0x06)?.value != OID_SHA256 {
        return Err(AuthError::CryptoError);
    }
    if !fields.remaining.is_empty() {
        let parameters = fields.next()?;
        if parameters.tag != 0x05 || !parameters.value.is_empty() {
            return Err(AuthError::InvalidHeader);
        }
    }
    fields.finish()
}

fn encapsulated_content_hash(
    encapsulated: Tlv<'_>,
    detached: &[u8],
) -> Result<[u8; 32], AuthError> {
    let mut fields = Reader::new(encapsulated.value);
    let _content_type = expect(fields.next()?, 0x06)?;
    let hash = if let Some(explicit) = fields.optional(0xa0)? {
        let content = parse_tlv(explicit.value)?.0;
        Sha256::digest(content.value).into()
    } else {
        Sha256::digest(detached).into()
    };
    fields.finish()?;
    Ok(hash)
}

fn parse_signer(sequence: Tlv<'_>) -> Result<SignerView<'_>, AuthError> {
    let mut fields = Reader::new(sequence.value);
    let _version = expect(fields.next()?, 0x02)?;
    let identity_tlv = fields.next()?;
    let identity = if identity_tlv.tag == 0x30 {
        let mut identity = Reader::new(identity_tlv.value);
        let issuer = expect(identity.next()?, 0x30)?.full;
        let serial = positive_integer(expect(identity.next()?, 0x02)?.value)?;
        identity.finish()?;
        SignerId::IssuerSerial { issuer, serial }
    } else if identity_tlv.tag == 0x80 {
        SignerId::SubjectKeyIdentifier(identity_tlv.value)
    } else {
        return Err(AuthError::InvalidHeader);
    };
    validate_sha256_algorithm(expect(fields.next()?, 0x30)?)?;
    let signed_attributes = fields.optional(0xa0)?;
    let _signature_algorithm = expect(fields.next()?, 0x30)?;
    let signature = expect(fields.next()?, 0x04)?.value;
    let _unsigned_attributes = fields.optional(0xa1)?;
    fields.finish()?;
    Ok(SignerView {
        identity,
        signed_attributes,
        signature,
    })
}

fn signed_attributes_digest(
    attributes: Option<Tlv<'_>>,
    content_hash: &[u8; 32],
) -> Result<[u8; 32], AuthError> {
    let Some(attributes) = attributes else {
        return Ok(*content_hash);
    };
    let mut found_digest = false;
    let mut entries = Reader::new(attributes.value);
    while !entries.remaining.is_empty() {
        let attribute = expect(entries.next()?, 0x30)?;
        let mut fields = Reader::new(attribute.value);
        let oid = expect(fields.next()?, 0x06)?;
        let values = expect(fields.next()?, 0x31)?;
        fields.finish()?;
        if oid.value == OID_MESSAGE_DIGEST {
            let mut values = Reader::new(values.value);
            let digest = expect(values.next()?, 0x04)?;
            values.finish()?;
            if digest.value.len() != 32 || !constant_time_eq(digest.value, content_hash) {
                return Err(AuthError::SignatureVerificationFailed);
            }
            found_digest = true;
        }
    }
    if !found_digest {
        return Err(AuthError::InvalidHeader);
    }
    let mut hash = Sha256::new();
    hash.update([0x31]);
    hash.update(&attributes.full[1..]);
    Ok(hash.finalize().into())
}

fn parse_certificate(certificate: &[u8]) -> Result<CertificateView<'_>, AuthError> {
    let outer = expect(parse_tlv(certificate)?.0, 0x30)?;
    if outer.full.len() != certificate.len() {
        return Err(AuthError::CertificateParseError);
    }
    let mut fields = Reader::new(outer.value);
    let tbs = expect(fields.next()?, 0x30)?;
    let signature_algorithm = expect(fields.next()?, 0x30)?;
    validate_certificate_signature_algorithm(signature_algorithm)?;
    let signature_bits = expect(fields.next()?, 0x03)?;
    fields.finish()?;
    let signature = bit_string(signature_bits.value)?;

    let mut tbs_fields = Reader::new(tbs.value);
    let _version = tbs_fields.optional(0xa0)?;
    let serial = positive_integer(expect(tbs_fields.next()?, 0x02)?.value)?;
    let _signature = expect(tbs_fields.next()?, 0x30)?;
    let issuer = expect(tbs_fields.next()?, 0x30)?.full;
    let _validity = expect(tbs_fields.next()?, 0x30)?;
    let subject = expect(tbs_fields.next()?, 0x30)?.full;
    let subject_key = expect(tbs_fields.next()?, 0x30)?;
    let (modulus, exponent) = parse_subject_public_key(subject_key)?;
    let mut extensions = CertificateExtensions::default();
    while !tbs_fields.remaining.is_empty() {
        let field = tbs_fields.next()?;
        match field.tag {
            0x81 | 0x82 => {}
            0xa3 => extensions = parse_certificate_extensions(field)?,
            _ => return Err(AuthError::CertificateParseError),
        }
    }
    Ok(CertificateView {
        raw: certificate,
        tbs: tbs.full,
        serial,
        issuer,
        subject,
        subject_key_identifier: extensions.subject_key_identifier,
        basic_constraints_ca: extensions.basic_constraints_ca,
        key_usage: extensions.key_usage,
        modulus,
        exponent,
        signature,
    })
}

fn parse_certificate_extensions(
    extensions: Tlv<'_>,
) -> Result<CertificateExtensions<'_>, AuthError> {
    let (sequence, trailing) = parse_tlv(extensions.value)?;
    let sequence = expect(sequence, 0x30)?;
    if !trailing.is_empty() {
        return Err(AuthError::CertificateParseError);
    }
    let mut result = CertificateExtensions::default();
    let mut extensions = Reader::new(sequence.value);
    while !extensions.remaining.is_empty() {
        let extension = expect(extensions.next()?, 0x30)?;
        let mut fields = Reader::new(extension.value);
        let oid = expect(fields.next()?, 0x06)?;
        if fields.remaining.first() == Some(&0x01) {
            let critical = fields.next()?;
            if critical.value.len() != 1 {
                return Err(AuthError::CertificateParseError);
            }
        }
        let value = expect(fields.next()?, 0x04)?;
        fields.finish()?;
        if oid.value == OID_SUBJECT_KEY_IDENTIFIER {
            let (identifier, trailing) = parse_tlv(value.value)?;
            if identifier.tag != 0x04 || !trailing.is_empty() {
                return Err(AuthError::CertificateParseError);
            }
            result.subject_key_identifier = Some(identifier.value);
        } else if oid.value == OID_BASIC_CONSTRAINTS {
            let (constraints, trailing) = parse_tlv(value.value)?;
            let constraints = expect(constraints, 0x30)?;
            if !trailing.is_empty() {
                return Err(AuthError::CertificateParseError);
            }
            let mut fields = Reader::new(constraints.value);
            result.basic_constraints_ca = if fields.remaining.first() == Some(&0x01) {
                let ca = fields.next()?;
                if ca.value.len() != 1 {
                    return Err(AuthError::CertificateParseError);
                }
                Some(ca.value[0] != 0)
            } else {
                Some(false)
            };
        } else if oid.value == OID_KEY_USAGE {
            let (usage, trailing) = parse_tlv(value.value)?;
            let usage = expect(usage, 0x03)?;
            if !trailing.is_empty() || usage.value.is_empty() || usage.value[0] > 7 {
                return Err(AuthError::CertificateParseError);
            }
            let mut bits = 0u16;
            for (index, byte) in usage.value[1..].iter().take(2).enumerate() {
                bits |= u16::from(byte.reverse_bits()) << (index * 8);
            }
            result.key_usage = Some(bits);
        }
    }
    Ok(result)
}

fn validate_certificate_signature_algorithm(algorithm: Tlv<'_>) -> Result<(), AuthError> {
    const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    let mut fields = Reader::new(algorithm.value);
    if expect(fields.next()?, 0x06)?.value != SHA256_WITH_RSA {
        return Err(AuthError::CryptoError);
    }
    if !fields.remaining.is_empty() {
        let null = fields.next()?;
        if null.tag != 0x05 || !null.value.is_empty() {
            return Err(AuthError::CertificateParseError);
        }
    }
    fields.finish()
}

fn parse_subject_public_key(subject_key: Tlv<'_>) -> Result<(&[u8], &[u8]), AuthError> {
    let mut fields = Reader::new(subject_key.value);
    let _algorithm = expect(fields.next()?, 0x30)?;
    let key_bits = bit_string(expect(fields.next()?, 0x03)?.value)?;
    fields.finish()?;
    let key = expect(parse_tlv(key_bits)?.0, 0x30)?;
    let mut integers = Reader::new(key.value);
    let modulus = positive_integer(expect(integers.next()?, 0x02)?.value)?;
    let exponent = positive_integer(expect(integers.next()?, 0x02)?.value)?;
    integers.finish()?;
    if modulus.is_empty() || modulus.len() > MAX_RSA_BITS / 8 || exponent.len() > 8 {
        return Err(AuthError::OutOfResources);
    }
    Ok((modulus, exponent))
}

fn positive_integer(value: &[u8]) -> Result<&[u8], AuthError> {
    if value.is_empty() || value[0] & 0x80 != 0 {
        return Err(AuthError::InvalidHeader);
    }
    Ok(if value.len() > 1 && value[0] == 0 {
        &value[1..]
    } else {
        value
    })
}

fn bit_string(value: &[u8]) -> Result<&[u8], AuthError> {
    if value.first() != Some(&0) {
        return Err(AuthError::CertificateParseError);
    }
    Ok(&value[1..])
}

fn find_signer<'a>(
    identity: SignerId<'_>,
    certificates: &[Option<&'a [u8]>],
) -> Result<Option<CertificateView<'a>>, AuthError> {
    for raw in certificates.iter().flatten() {
        let certificate = parse_certificate(raw)?;
        let matches = match identity {
            SignerId::IssuerSerial { issuer, serial } => {
                certificate.issuer == issuer && certificate.serial == serial
            }
            SignerId::SubjectKeyIdentifier(identifier) => certificate
                .subject_key_identifier
                .is_some_and(|candidate| constant_time_eq(candidate, identifier)),
        };
        if matches {
            return Ok(Some(certificate));
        }
    }
    Ok(None)
}

fn certificate_authorized(
    certificate: CertificateView<'_>,
    trusted: CertificateView<'_>,
    certificates: &[Option<&[u8]>],
    depth: usize,
) -> Result<bool, AuthError> {
    if certificate.raw == trusted.raw {
        return Ok(true);
    }
    if depth >= MAX_CHAIN_DEPTH {
        return Err(AuthError::ChainTooDeep);
    }
    if certificate.issuer == trusted.subject && verify_certificate(certificate, trusted)? {
        return Ok(true);
    }
    for raw in certificates.iter().flatten() {
        let issuer = parse_certificate(raw)?;
        if issuer.raw != certificate.raw
            && certificate.issuer == issuer.subject
            && issuer.can_sign_certificates()
            && verify_certificate(certificate, issuer)?
            && certificate_authorized(issuer, trusted, certificates, depth + 1)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn verify_certificate(
    certificate: CertificateView<'_>,
    issuer: CertificateView<'_>,
) -> Result<bool, AuthError> {
    let digest: [u8; 32] = Sha256::digest(certificate.tbs).into();
    verify_rsa_signature(&rsa_key(&issuer)?, certificate.signature, &digest)
}

fn rsa_key(certificate: &CertificateView<'_>) -> Result<rsa::RsaPublicKey, AuthError> {
    let modulus = rsa::BigUint::from_bytes_be(certificate.modulus);
    let exponent = rsa::BigUint::from_bytes_be(certificate.exponent);
    let key =
        rsa::RsaPublicKey::new(modulus, exponent).map_err(|_| AuthError::CertificateParseError)?;
    if key.n().bits() > MAX_RSA_BITS {
        return Err(AuthError::OutOfResources);
    }
    Ok(key)
}

fn verify_rsa_signature(
    key: &rsa::RsaPublicKey,
    signature: &[u8],
    digest: &[u8; 32],
) -> Result<bool, AuthError> {
    use rsa::signature::hazmat::PrehashVerifier;

    let signature =
        rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| AuthError::CryptoError)?;
    let verifier = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key.clone());
    Ok(verifier.verify_prehash(digest, &signature).is_ok())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let difference = left.len() ^ right.len();
    let mut result = difference as u8
        | (difference >> 8) as u8
        | (difference >> 16) as u8
        | (difference >> 24) as u8;
    for (left, right) in left.iter().zip(right) {
        result |= left ^ right;
    }
    result == 0
}
