//! Borrowed X.509 certificate views.

use crate::der::{DecodeError, Reader, Result, Tlv, tag};
use crate::oid;
use crate::rsa::RsaPublicKey;
use crate::time::DateTime;

/// Structurally validated X.509 certificate.
///
/// Names are the complete DER `Name` encodings and compare byte-for-byte.
/// Validity, key and extension contents are decoded on demand so each caller
/// chooses which of them its policy depends on.
#[derive(Clone, Copy, Debug)]
pub struct Certificate<'a> {
    /// Complete certificate encoding.
    pub encoded: &'a [u8],
    /// Complete `TBSCertificate` encoding covered by `signature`.
    pub tbs: &'a [u8],
    /// Serial number magnitude (see [`Tlv::unsigned_integer`]).
    pub serial: &'a [u8],
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    /// Outer `signatureAlgorithm` element.
    pub signature_algorithm: Tlv<'a>,
    pub signature: &'a [u8],
    pub extensions: Extensions<'a>,
    validity: &'a [u8],
    public_key: &'a [u8],
}

impl<'a> Certificate<'a> {
    /// Parse a certificate that spans all of `der`.
    pub fn parse(der: &'a [u8]) -> Result<Self> {
        let mut fields = Tlv::parse(der)?.contents(tag::SEQUENCE)?;
        let tbs = fields.read_tag(tag::SEQUENCE)?;
        let signature_algorithm = fields.read_tag(tag::SEQUENCE)?;
        let signature = fields.read()?.bit_string_octets()?;
        fields.finish()?;

        let mut tbs_fields = Reader::new(tbs.value);
        tbs_fields.read_optional(tag::context_constructed(0))?;
        let serial = tbs_fields.read()?.unsigned_integer()?;
        tbs_fields.read_tag(tag::SEQUENCE)?;
        let issuer = tbs_fields.read_tag(tag::SEQUENCE)?.encoded;
        let validity = tbs_fields.read_tag(tag::SEQUENCE)?.value;
        let subject = tbs_fields.read_tag(tag::SEQUENCE)?.encoded;
        let mut key_info = tbs_fields.read()?.contents(tag::SEQUENCE)?;
        key_info.read_tag(tag::SEQUENCE)?;
        let public_key = key_info.read()?.bit_string_octets()?;
        key_info.finish()?;
        tbs_fields.read_optional(tag::context(1))?;
        tbs_fields.read_optional(tag::context(2))?;
        let extensions = tbs_fields
            .read_optional(tag::context_constructed(3))?
            .map(|explicit| Extensions::parse(explicit.inner()?))
            .transpose()?
            .unwrap_or_default();
        tbs_fields.finish()?;

        Ok(Self {
            encoded: der,
            tbs: tbs.encoded,
            serial,
            issuer,
            subject,
            signature_algorithm,
            signature,
            extensions,
            validity,
            public_key,
        })
    }

    /// Decode the validity window.
    pub fn validity(&self) -> Result<Validity> {
        let mut times = Reader::new(self.validity);
        let not_before = DateTime::parse(times.read()?)?.unix_timestamp();
        let not_after = DateTime::parse(times.read()?)?.unix_timestamp();
        times.finish()?;
        Ok(Validity {
            not_before,
            not_after,
        })
    }

    /// Decode the subject public key as a PKCS#1 `RSAPublicKey`.
    pub fn rsa_public_key(&self) -> Result<RsaPublicKey<'a>> {
        RsaPublicKey::parse(self.public_key)
    }

    /// Decode the basicConstraints extension, if present.
    pub fn basic_constraints(&self) -> Result<Option<BasicConstraints>> {
        self.decode_extension(oid::BASIC_CONSTRAINTS, BasicConstraints::parse)
    }

    /// Decode the keyUsage extension, if present.
    pub fn key_usage(&self) -> Result<Option<KeyUsage>> {
        self.decode_extension(oid::KEY_USAGE, KeyUsage::parse)
    }

    /// Decode the subjectKeyIdentifier extension, if present.
    pub fn subject_key_identifier(&self) -> Result<Option<&'a [u8]>> {
        self.decode_extension(oid::SUBJECT_KEY_IDENTIFIER, |value| {
            Tlv::parse(value)?.octet_string()
        })
    }

    fn decode_extension<T>(
        &self,
        oid: &[u8],
        decode: impl FnOnce(&'a [u8]) -> Result<T>,
    ) -> Result<Option<T>> {
        self.extensions
            .find(oid)
            .map(|extension| decode(extension.value))
            .transpose()
    }
}

/// Validity window in Unix seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    pub not_before: i64,
    pub not_after: i64,
}

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`
#[derive(Clone, Copy, Debug)]
pub struct AlgorithmIdentifier<'a> {
    pub oid: &'a [u8],
    pub parameters: Option<Tlv<'a>>,
}

impl<'a> AlgorithmIdentifier<'a> {
    pub fn parse(sequence: Tlv<'a>) -> Result<Self> {
        let mut fields = sequence.contents(tag::SEQUENCE)?;
        let oid = fields.read()?.oid()?;
        let parameters = (!fields.is_empty()).then(|| fields.read()).transpose()?;
        fields.finish()?;
        Ok(Self { oid, parameters })
    }

    /// Whether this is `oid` with absent or NULL parameters.
    pub fn is(&self, oid: &[u8]) -> bool {
        self.oid == oid
            && self
                .parameters
                .is_none_or(|parameters| parameters.tag == tag::NULL && parameters.value.is_empty())
    }
}

/// Structurally validated `Extensions ::= SEQUENCE OF Extension`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Extensions<'a>(&'a [u8]);

impl<'a> Extensions<'a> {
    pub fn parse(sequence: Tlv<'a>) -> Result<Self> {
        sequence
            .contents(tag::SEQUENCE)?
            .try_for_each(|extension| Extension::parse(extension?).map(drop))?;
        Ok(Self(sequence.value))
    }

    pub fn iter(&self) -> impl Iterator<Item = Extension<'a>> {
        Reader::new(self.0).map_while(|extension| Extension::parse(extension.ok()?).ok())
    }

    /// First extension with `oid`.
    pub fn find(&self, oid: &[u8]) -> Option<Extension<'a>> {
        self.iter().find(|extension| extension.oid == oid)
    }
}

/// One certificate or CRL extension.
#[derive(Clone, Copy, Debug)]
pub struct Extension<'a> {
    pub oid: &'a [u8],
    pub critical: bool,
    /// Content of the `extnValue` OCTET STRING.
    pub value: &'a [u8],
}

impl<'a> Extension<'a> {
    fn parse(sequence: Tlv<'a>) -> Result<Self> {
        let mut fields = sequence.contents(tag::SEQUENCE)?;
        let oid = fields.read()?.oid()?;
        let critical = fields
            .read_optional(tag::BOOLEAN)?
            .map(Tlv::boolean)
            .transpose()?
            .unwrap_or(false);
        let value = fields.read()?.octet_string()?;
        fields.finish()?;
        Ok(Self {
            oid,
            critical,
            value,
        })
    }
}

/// basicConstraints extension value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_len: Option<u8>,
}

impl BasicConstraints {
    fn parse(value: &[u8]) -> Result<Self> {
        let mut fields = Tlv::parse(value)?.contents(tag::SEQUENCE)?;
        let ca = fields
            .read_optional(tag::BOOLEAN)?
            .map(Tlv::boolean)
            .transpose()?
            .unwrap_or(false);
        let path_len = fields
            .read_optional(tag::INTEGER)?
            .map(|integer| match integer.unsigned_integer()? {
                &[path_len] => Ok(path_len),
                _ => Err(DecodeError),
            })
            .transpose()?;
        fields.finish()?;
        Ok(Self { ca, path_len })
    }
}

/// keyUsage extension value: the first two BIT STRING octets, big-endian,
/// so RFC 5280 bit 0 (digitalSignature) is the most significant bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyUsage(pub u16);

impl KeyUsage {
    pub const fn digital_signature(self) -> bool {
        self.0 & 0x8000 != 0
    }

    pub const fn key_cert_sign(self) -> bool {
        self.0 & 0x0400 != 0
    }

    fn parse(value: &[u8]) -> Result<Self> {
        let bits = Tlv::parse(value)?.expect(tag::BIT_STRING)?.value;
        let (&unused, octets) = bits.split_first().ok_or(DecodeError)?;
        let padding_clear = match octets.last() {
            Some(last) => unused < 8 && last & ((1u8 << unused) - 1) == 0,
            None => unused == 0,
        };
        if !padding_clear {
            return Err(DecodeError);
        }
        let first = octets.first().copied().unwrap_or(0);
        let second = octets.get(1).copied().unwrap_or(0);
        Ok(Self(u16::from_be_bytes([first, second])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdata::{CA, FORGED_CA, LEAF};

    #[test]
    fn fixture_certificates_decode() {
        let ca = Certificate::parse(CA).unwrap();
        let leaf = Certificate::parse(LEAF).unwrap();
        assert_eq!(ca.issuer, ca.subject);
        assert_eq!(leaf.issuer, ca.subject);
        assert_ne!(ca.serial, leaf.serial);
        assert!(
            AlgorithmIdentifier::parse(ca.signature_algorithm)
                .unwrap()
                .is(oid::SHA256_WITH_RSA_ENCRYPTION)
        );

        // Fixtures were generated 2026-09-09 with an 825-day lifetime.
        let validity = leaf.validity().unwrap();
        assert!(validity.not_before > 1_750_000_000);
        assert!(validity.not_after > validity.not_before);

        let ca_constraints = ca.basic_constraints().unwrap().unwrap();
        assert!(ca_constraints.ca);
        assert!(ca.key_usage().unwrap().unwrap().key_cert_sign());
        assert!(!leaf.basic_constraints().unwrap().is_some_and(|bc| bc.ca));
        assert!(leaf.key_usage().unwrap().unwrap().digital_signature());
        assert!(ca.subject_key_identifier().unwrap().is_some());
    }

    #[test]
    fn issuer_key_verifies_tbs_signature() {
        use sha2::{Digest, Sha256};

        let ca = Certificate::parse(CA).unwrap();
        let key = ca.rsa_public_key().unwrap();
        for (certificate, expected) in [(LEAF, true), (FORGED_CA, false)] {
            let certificate = Certificate::parse(certificate).unwrap();
            let digest: [u8; 32] = Sha256::digest(certificate.tbs).into();
            assert_eq!(
                key.verify_pkcs1v15_sha256::<64>(certificate.signature, &digest),
                expected
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes_and_truncation() {
        let mut padded = CA.to_vec();
        padded.push(0);
        assert!(Certificate::parse(&padded).is_err());
        assert!(Certificate::parse(&CA[..CA.len() - 1]).is_err());
    }

    #[test]
    fn extension_values_are_strict() {
        let parse = |oid: &[u8], value: &[u8]| {
            let mut extension = vec![0x06, oid.len() as u8];
            extension.extend_from_slice(oid);
            extension.extend_from_slice(&[0x04, value.len() as u8]);
            extension.extend_from_slice(value);
            let mut sequence = vec![0x30, extension.len() as u8];
            sequence.extend_from_slice(&extension);
            let mut extensions = vec![0x30, sequence.len() as u8];
            extensions.extend_from_slice(&sequence);
            extensions
        };
        let decode = |extensions: &[u8]| {
            let extensions = Extensions::parse(Tlv::parse(extensions).unwrap()).unwrap();
            extensions
                .find(oid::BASIC_CONSTRAINTS)
                .map(|extension| BasicConstraints::parse(extension.value))
        };
        assert_eq!(
            decode(&parse(oid::BASIC_CONSTRAINTS, &[0x30, 0x00])),
            Some(Ok(BasicConstraints {
                ca: false,
                path_len: None
            }))
        );
        assert_eq!(
            decode(&parse(
                oid::BASIC_CONSTRAINTS,
                &[0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00]
            )),
            Some(Ok(BasicConstraints {
                ca: true,
                path_len: Some(0)
            }))
        );
        // Non-DER boolean and oversized pathLenConstraint.
        assert!(matches!(
            decode(&parse(
                oid::BASIC_CONSTRAINTS,
                &[0x30, 0x03, 0x01, 0x01, 0x01]
            )),
            Some(Err(_))
        ));
        assert!(matches!(
            decode(&parse(
                oid::BASIC_CONSTRAINTS,
                &[0x30, 0x04, 0x02, 0x02, 0x01, 0x00]
            )),
            Some(Err(_))
        ));
        assert!(decode(&parse(oid::KEY_USAGE, &[0x03, 0x02, 0x07, 0x80])).is_none());

        assert_eq!(
            KeyUsage::parse(&[0x03, 0x02, 0x05, 0xa0]),
            Ok(KeyUsage(0xa000))
        );
        assert!(KeyUsage::parse(&[0x03, 0x02, 0x05, 0xa1]).is_err());
        assert!(KeyUsage::parse(&[0x03, 0x02, 0x08, 0x00]).is_err());
    }
}
