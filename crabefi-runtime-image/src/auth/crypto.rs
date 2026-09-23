//! Authenticated-variable CMS policy over the shared `crabefi-pkcs7` views.
//!
//! # Accepted limitations
//!
//! This verifier is deliberately minimal and every gap below fails closed
//! (unparsable or unverifiable input is rejected):
//! - No certificate validity-period or revocation checking.
//! - Issuer/subject chaining compares the DER name bytes exactly instead of
//!   normalizing alternative encodings; a differently-encoded name simply
//!   fails to chain.
//! - The direct-issuance path does not require the trusted (db/PK)
//!   certificate to be a CA — only intermediates are checked for the CA bit.
//!   This grants no escalation: a trusted certificate's key can always sign
//!   the PKCS#7 directly anyway.
//! - The SignerInfo `signatureAlgorithm` OID is accepted but ignored;
//!   verification treats every signature as RSA-SHA256 regardless of the
//!   declared algorithm.

use crabefi_efi_types::constant_time_eq;
use crabefi_pkcs7::cms::{SignedAttributes, SignedData, SignerIdentifier};
use crabefi_pkcs7::der::{DecodeError, Tlv, tag};
use crabefi_pkcs7::oid;
use crabefi_pkcs7::rsa::RsaPublicKey;
use crabefi_pkcs7::x509::{AlgorithmIdentifier, Certificate};
use sha2::{Digest, Sha256};

use super::AuthError;

const MAX_CERTIFICATES: usize = 16;
const MAX_SIGNERS: usize = 8;
const MAX_CERTIFICATE_SIZE: usize = 16 * 1024;
const MAX_CHAIN_DEPTH: usize = 5;
/// 4096-bit RSA arithmetic width.
const RSA_LIMBS: usize = 64;
const MAX_RSA_BYTES: usize = RSA_LIMBS * 8;
// Match the 32-bit publicExponent accepted by Windows certificate tooling and
// cap attacker-controlled exponentiation work during runtime verification.
const MAX_RSA_EXPONENT: u64 = u32::MAX as u64;

impl From<DecodeError> for AuthError {
    fn from(_: DecodeError) -> Self {
        AuthError::InvalidHeader
    }
}

/// A certificate accepted by the runtime algorithm and size policy.
#[derive(Clone, Copy)]
struct PolicyCertificate<'a> {
    certificate: Certificate<'a>,
    key: RsaPublicKey<'a>,
    subject_key_identifier: Option<&'a [u8]>,
    can_sign_certificates: bool,
}

pub fn verify_pkcs7_signature_hash(
    pkcs7_data: &[u8],
    content_hash: &[u8; 32],
    trusted_cert: &[u8],
) -> Result<bool, AuthError> {
    if pkcs7_data.len() > super::MAX_AUTHENTICATED_ENVELOPE_SIZE
        || trusted_cert.len() > MAX_CERTIFICATE_SIZE
    {
        return Err(AuthError::OutOfResources);
    }
    let signed = SignedData::parse(pkcs7_data)?;
    validate_digest_algorithms(signed.digest_algorithms)?;
    // UEFI authenticated-variable updates use detached CMS. Accepting eContent
    // would authenticate attacker-selected attached bytes instead of the
    // variable name/GUID/attributes/timestamp/payload assembled by the caller.
    if signed.encapsulated_content.content_type != oid::DATA
        || signed.encapsulated_content.content.is_some()
    {
        return Err(AuthError::InvalidHeader);
    }

    let mut slots = [&[][..]; MAX_CERTIFICATES];
    let mut certificate_count = 0usize;
    for certificate in signed.certificates() {
        if certificate.tag != tag::SEQUENCE || certificate.encoded.len() > MAX_CERTIFICATE_SIZE {
            return Err(AuthError::InvalidHeader);
        }
        let slot = slots
            .get_mut(certificate_count)
            .ok_or(AuthError::OutOfResources)?;
        *slot = certificate.encoded;
        certificate_count += 1;
    }
    let certificates = slots
        .get(..certificate_count)
        .ok_or(AuthError::CertificateParseError)?;
    if certificates.is_empty() {
        return Err(AuthError::NoSuitableKey);
    }
    let trusted = parse_certificate(trusted_cert)?;

    let mut signer_count = 0usize;
    for signer in signed.signers() {
        signer_count += 1;
        if signer_count > MAX_SIGNERS {
            return Err(AuthError::OutOfResources);
        }
        let signer = signer?;
        validate_sha256_algorithm(signer.digest_algorithm)?;
        let Some(signer_certificate) = find_signer(signer.identifier, certificates)? else {
            continue;
        };
        let content_digest = signed_attributes_digest(signer.signed_attributes, content_hash)?;
        if verify_rsa_signature(signer_certificate, signer.signature, &content_digest)
            && certificate_authorized(signer_certificate, trusted, certificates, 0)?
        {
            return Ok(true);
        }
    }
    if signer_count == 0 {
        return Err(AuthError::InvalidHeader);
    }
    Ok(false)
}

/// `digestAlgorithms` must be exactly SHA-256.
fn validate_digest_algorithms(set: Tlv<'_>) -> Result<(), AuthError> {
    validate_sha256_algorithm(set.inner()?)
}

fn validate_sha256_algorithm(algorithm: Tlv<'_>) -> Result<(), AuthError> {
    let algorithm = AlgorithmIdentifier::parse(algorithm)?;
    if algorithm.oid != oid::SHA256 {
        return Err(AuthError::CryptoError);
    }
    if !algorithm.is(oid::SHA256) {
        return Err(AuthError::InvalidHeader);
    }
    Ok(())
}

fn signed_attributes_digest(
    attributes: Option<SignedAttributes<'_>>,
    content_hash: &[u8; 32],
) -> Result<[u8; 32], AuthError> {
    let Some(attributes) = attributes else {
        return Ok(*content_hash);
    };
    if attributes.content_type()? != oid::DATA {
        return Err(AuthError::InvalidHeader);
    }
    if !constant_time_eq(attributes.message_digest()?, content_hash) {
        return Err(AuthError::SignatureVerificationFailed);
    }
    Ok(attributes.digest())
}

fn parse_certificate(der: &[u8]) -> Result<PolicyCertificate<'_>, AuthError> {
    let certificate = Certificate::parse(der).map_err(|_| AuthError::CertificateParseError)?;
    let signature_algorithm = AlgorithmIdentifier::parse(certificate.signature_algorithm)
        .map_err(|_| AuthError::CertificateParseError)?;
    if signature_algorithm.oid != oid::SHA256_WITH_RSA_ENCRYPTION {
        return Err(AuthError::CryptoError);
    }
    if !signature_algorithm.is(oid::SHA256_WITH_RSA_ENCRYPTION) {
        return Err(AuthError::CertificateParseError);
    }
    let key = certificate.rsa_public_key()?;
    if key.modulus.len() > MAX_RSA_BYTES || key.exponent().is_none() {
        return Err(AuthError::OutOfResources);
    }
    let decode_error = |_: DecodeError| AuthError::CertificateParseError;
    let basic_constraints = certificate.basic_constraints().map_err(decode_error)?;
    let key_usage = certificate.key_usage().map_err(decode_error)?;
    Ok(PolicyCertificate {
        certificate,
        key,
        subject_key_identifier: certificate.subject_key_identifier().map_err(decode_error)?,
        can_sign_certificates: basic_constraints.is_some_and(|constraints| constraints.ca)
            && key_usage.is_none_or(|usage| usage.key_cert_sign()),
    })
}

fn find_signer<'a>(
    identifier: SignerIdentifier<'_>,
    certificates: &[&'a [u8]],
) -> Result<Option<PolicyCertificate<'a>>, AuthError> {
    for raw in certificates {
        let candidate = parse_certificate(raw)?;
        let matches = match identifier {
            SignerIdentifier::IssuerAndSerialNumber { issuer, serial } => {
                candidate.certificate.issuer == issuer && candidate.certificate.serial == serial
            }
            SignerIdentifier::SubjectKeyIdentifier(identifier) => candidate
                .subject_key_identifier
                .is_some_and(|candidate| constant_time_eq(candidate, identifier)),
        };
        if matches {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn certificate_authorized(
    certificate: PolicyCertificate<'_>,
    trusted: PolicyCertificate<'_>,
    certificates: &[&[u8]],
    depth: usize,
) -> Result<bool, AuthError> {
    if certificate.certificate.encoded == trusted.certificate.encoded {
        return Ok(true);
    }
    if depth >= MAX_CHAIN_DEPTH {
        return Err(AuthError::ChainTooDeep);
    }
    if certificate.certificate.issuer == trusted.certificate.subject
        && verify_certificate(certificate, trusted)
    {
        return Ok(true);
    }
    for raw in certificates {
        let issuer = parse_certificate(raw)?;
        if issuer.certificate.encoded != certificate.certificate.encoded
            && certificate.certificate.issuer == issuer.certificate.subject
            && issuer.can_sign_certificates
            && verify_certificate(certificate, issuer)
            && certificate_authorized(issuer, trusted, certificates, depth + 1)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn verify_certificate(certificate: PolicyCertificate<'_>, issuer: PolicyCertificate<'_>) -> bool {
    let digest: [u8; 32] = Sha256::digest(certificate.certificate.tbs).into();
    verify_rsa_signature(issuer, certificate.certificate.signature, &digest)
}

fn verify_rsa_signature(
    certificate: PolicyCertificate<'_>,
    signature: &[u8],
    digest: &[u8; 32],
) -> bool {
    certificate
        .key
        .exponent()
        .is_some_and(|exponent| exponent <= MAX_RSA_EXPONENT)
        && certificate
            .key
            .verify_pkcs1v15_sha256::<RSA_LIMBS>(signature, digest)
}
