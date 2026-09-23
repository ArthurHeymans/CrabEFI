//! Borrowed PKCS#7/CMS `SignedData` views (RFC 5652).

use sha2::{Digest, Sha256};

use crate::der::{DecodeError, Reader, Result, Tlv, tag};
use crate::oid;

/// Structurally validated `SignedData` from a `ContentInfo`.
///
/// Algorithm identifiers are exposed undecoded; each caller applies its own
/// algorithm policy.
#[derive(Clone, Copy, Debug)]
pub struct SignedData<'a> {
    /// `digestAlgorithms` SET.
    pub digest_algorithms: Tlv<'a>,
    pub encapsulated_content: EncapsulatedContent<'a>,
    certificates: &'a [u8],
    signer_infos: &'a [u8],
}

impl<'a> SignedData<'a> {
    /// Parse the `ContentInfo` at the start of `input`; bytes after it (such
    /// as WIN_CERTIFICATE alignment padding) are ignored.
    pub fn parse(input: &'a [u8]) -> Result<Self> {
        let (content_info, _padding) = Tlv::read(input)?;
        let mut content_info = content_info.contents(tag::SEQUENCE)?;
        if content_info.read()?.oid()? != oid::SIGNED_DATA {
            return Err(DecodeError);
        }
        let signed_data = content_info
            .read_tag(tag::context_constructed(0))?
            .inner()?;
        content_info.finish()?;

        let mut fields = signed_data.contents(tag::SEQUENCE)?;
        fields.read_tag(tag::INTEGER)?;
        let digest_algorithms = fields.read_tag(tag::SET)?;
        let encapsulated_content = EncapsulatedContent::parse(fields.read()?)?;
        let certificates = fields
            .read_optional(tag::context_constructed(0))?
            .map_or(&[][..], |set| set.value);
        Reader::new(certificates).try_for_each(|certificate| certificate.map(drop))?;
        fields.read_optional(tag::context_constructed(1))?;
        let signer_infos = fields.read_tag(tag::SET)?.value;
        Reader::new(signer_infos).try_for_each(|signer| {
            signer
                .and_then(|signer| signer.expect(tag::SEQUENCE))
                .map(drop)
        })?;
        fields.finish()?;

        Ok(Self {
            digest_algorithms,
            encapsulated_content,
            certificates,
            signer_infos,
        })
    }

    /// Elements of the `certificates` set, in encoding order. Elements are
    /// not decoded; non-SEQUENCE entries are other `CertificateChoices`.
    pub fn certificates(&self) -> impl Iterator<Item = Tlv<'a>> + use<'a> {
        Reader::new(self.certificates).map_while(|certificate| certificate.ok())
    }

    /// Each `SignerInfo`, decoded as it is reached.
    pub fn signers(&self) -> impl Iterator<Item = Result<SignerInfo<'a>>> + use<'a> {
        Reader::new(self.signer_infos).map(|signer| SignerInfo::parse(signer?))
    }
}

/// `EncapsulatedContentInfo`.
#[derive(Clone, Copy, Debug)]
pub struct EncapsulatedContent<'a> {
    pub content_type: &'a [u8],
    /// The element inside `[0] EXPLICIT eContent`, absent for detached
    /// signatures.
    pub content: Option<Tlv<'a>>,
}

impl<'a> EncapsulatedContent<'a> {
    fn parse(sequence: Tlv<'a>) -> Result<Self> {
        let mut fields = sequence.contents(tag::SEQUENCE)?;
        let content_type = fields.read()?.oid()?;
        let content = fields
            .read_optional(tag::context_constructed(0))?
            .map(Tlv::inner)
            .transpose()?;
        fields.finish()?;
        Ok(Self {
            content_type,
            content,
        })
    }
}

/// `SignerIdentifier`.
#[derive(Clone, Copy, Debug)]
pub enum SignerIdentifier<'a> {
    /// Complete issuer `Name` encoding and serial number magnitude.
    IssuerAndSerialNumber {
        issuer: &'a [u8],
        serial: &'a [u8],
    },
    SubjectKeyIdentifier(&'a [u8]),
}

/// One `SignerInfo`.
#[derive(Clone, Copy, Debug)]
pub struct SignerInfo<'a> {
    pub identifier: SignerIdentifier<'a>,
    /// `digestAlgorithm` SEQUENCE.
    pub digest_algorithm: Tlv<'a>,
    pub signed_attributes: Option<SignedAttributes<'a>>,
    pub signature: &'a [u8],
}

impl<'a> SignerInfo<'a> {
    fn parse(sequence: Tlv<'a>) -> Result<Self> {
        let mut fields = sequence.contents(tag::SEQUENCE)?;
        fields.read_tag(tag::INTEGER)?;
        let identifier = match fields.read()? {
            Tlv {
                tag: tag::SEQUENCE,
                value,
                ..
            } => {
                let mut issuer_and_serial = Reader::new(value);
                let issuer = issuer_and_serial.read_tag(tag::SEQUENCE)?.encoded;
                let serial = issuer_and_serial.read()?.unsigned_integer()?;
                issuer_and_serial.finish()?;
                SignerIdentifier::IssuerAndSerialNumber { issuer, serial }
            }
            Tlv { tag, value, .. } if tag == tag::context(0) => {
                SignerIdentifier::SubjectKeyIdentifier(value)
            }
            _ => return Err(DecodeError),
        };
        let digest_algorithm = fields.read_tag(tag::SEQUENCE)?;
        let signed_attributes = fields
            .read_optional(tag::context_constructed(0))?
            .map(SignedAttributes::parse)
            .transpose()?;
        fields.read_tag(tag::SEQUENCE)?;
        let signature = fields.read()?.octet_string()?;
        fields.read_optional(tag::context_constructed(1))?;
        fields.finish()?;
        Ok(Self {
            identifier,
            digest_algorithm,
            signed_attributes,
            signature,
        })
    }
}

/// Structurally validated `[0] IMPLICIT SignedAttributes`.
#[derive(Clone, Copy, Debug)]
pub struct SignedAttributes<'a> {
    encoded: &'a [u8],
    attributes: &'a [u8],
}

impl<'a> SignedAttributes<'a> {
    fn parse(implicit: Tlv<'a>) -> Result<Self> {
        Reader::new(implicit.value)
            .try_for_each(|attribute| Attribute::parse(attribute?).map(drop))?;
        Ok(Self {
            encoded: implicit.encoded,
            attributes: implicit.value,
        })
    }

    /// The `contentType` attribute value.
    pub fn content_type(&self) -> Result<&'a [u8]> {
        self.single_value(oid::CONTENT_TYPE)?.oid()
    }

    /// The `messageDigest` attribute value.
    pub fn message_digest(&self) -> Result<&'a [u8]> {
        self.single_value(oid::MESSAGE_DIGEST)?.octet_string()
    }

    /// SHA-256 over the attributes as signed: the encoding with the
    /// `[0] IMPLICIT` tag replaced by the SET OF tag (RFC 5652, section 5.4).
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update([tag::SET]);
        hash.update(self.encoded.get(1..).unwrap_or_default());
        hash.finalize().into()
    }

    /// The only value of the only attribute of type `oid`.
    fn single_value(&self, oid: &[u8]) -> Result<Tlv<'a>> {
        let mut matches = Reader::new(self.attributes)
            .map_while(|attribute| Attribute::parse(attribute.ok()?).ok())
            .filter(|attribute| attribute.oid == oid);
        match (matches.next(), matches.next()) {
            (Some(attribute), None) => Tlv::parse(attribute.values),
            _ => Err(DecodeError),
        }
    }
}

/// `Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }`
struct Attribute<'a> {
    oid: &'a [u8],
    values: &'a [u8],
}

impl<'a> Attribute<'a> {
    fn parse(sequence: Tlv<'a>) -> Result<Self> {
        let mut fields = sequence.contents(tag::SEQUENCE)?;
        let oid = fields.read()?.oid()?;
        let values = fields.read_tag(tag::SET)?.value;
        fields.finish()?;
        Ok(Self { oid, values })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdata::{CMS_ATTRS, CMS_KEYID, CMS_NOATTR, DATA, LEAF};
    use crate::x509::Certificate;

    fn signer(cms: &[u8]) -> SignerInfo<'_> {
        let signed = SignedData::parse(cms).unwrap();
        let mut signers = signed.signers();
        let signer = signers.next().unwrap().unwrap();
        assert!(signers.next().is_none());
        signer
    }

    #[test]
    fn fixture_signers_verify_with_embedded_leaf() {
        let leaf = Certificate::parse(LEAF).unwrap();
        let key = leaf.rsa_public_key().unwrap();
        let content_digest: [u8; 32] = Sha256::digest(DATA).into();
        for cms in [CMS_ATTRS, CMS_NOATTR, CMS_KEYID] {
            let signed = SignedData::parse(cms).unwrap();
            assert_eq!(signed.encapsulated_content.content_type, oid::DATA);
            assert!(signed.encapsulated_content.content.is_none());
            assert!(
                signed
                    .certificates()
                    .any(|certificate| certificate.encoded == LEAF)
            );

            let signer = signer(cms);
            match signer.identifier {
                SignerIdentifier::IssuerAndSerialNumber { issuer, serial } => {
                    assert_eq!((issuer, serial), (leaf.issuer, leaf.serial));
                }
                SignerIdentifier::SubjectKeyIdentifier(identifier) => {
                    assert_eq!(Some(identifier), leaf.subject_key_identifier().unwrap());
                }
            }
            let signed_digest = match signer.signed_attributes {
                Some(attributes) => {
                    assert_eq!(attributes.content_type(), Ok(oid::DATA));
                    assert_eq!(attributes.message_digest(), Ok(&content_digest[..]));
                    attributes.digest()
                }
                None => content_digest,
            };
            assert!(key.verify_pkcs1v15_sha256::<64>(signer.signature, &signed_digest));
        }
    }

    #[test]
    fn trailing_padding_is_ignored_but_truncation_is_not() {
        let mut padded = CMS_ATTRS.to_vec();
        padded.extend_from_slice(&[0; 7]);
        assert!(SignedData::parse(&padded).is_ok());
        assert!(SignedData::parse(&CMS_ATTRS[..CMS_ATTRS.len() - 1]).is_err());
        assert!(SignedData::parse(b"junk").is_err());
        assert!(SignedData::parse(&[]).is_err());
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        assert!(value.len() < 0x80);
        let mut encoded = vec![tag, value.len() as u8];
        encoded.extend_from_slice(value);
        encoded
    }

    fn attribute(oid: &[u8], values: &[&[u8]]) -> Vec<u8> {
        let values: Vec<u8> = values.concat();
        tlv(
            tag::SEQUENCE,
            &[tlv(tag::OID, oid), tlv(tag::SET, &values)].concat(),
        )
    }

    fn attributes(attributes: &[Vec<u8>]) -> Result<SignedAttributes<'static>> {
        let encoded = tlv(tag::context_constructed(0), &attributes.concat()).leak();
        SignedAttributes::parse(Tlv::parse(encoded).unwrap())
    }

    #[test]
    fn signed_attribute_values_must_be_unique() {
        let content_type = attribute(oid::CONTENT_TYPE, &[&tlv(tag::OID, oid::DATA)]);
        let digest = tlv(tag::OCTET_STRING, &[0xab; 32]);
        let message_digest = attribute(oid::MESSAGE_DIGEST, &[&digest]);

        let valid = attributes(&[content_type.clone(), message_digest.clone()]).unwrap();
        assert_eq!(valid.content_type(), Ok(oid::DATA));
        assert_eq!(valid.message_digest(), Ok(&[0xab; 32][..]));

        let missing = attributes(std::slice::from_ref(&content_type)).unwrap();
        assert!(missing.message_digest().is_err());
        let duplicated = attributes(&[message_digest.clone(), message_digest.clone()]).unwrap();
        assert!(duplicated.message_digest().is_err());
        let two_values =
            attributes(&[attribute(oid::MESSAGE_DIGEST, &[&digest, &digest])]).unwrap();
        assert!(two_values.message_digest().is_err());
        let wrong_type = attributes(&[attribute(oid::CONTENT_TYPE, &[&digest])]).unwrap();
        assert!(wrong_type.content_type().is_err());

        // Attribute structure is validated up front.
        assert!(attributes(&[tlv(tag::SEQUENCE, &tlv(tag::OID, oid::DATA))]).is_err());
    }

    #[test]
    fn signed_attribute_digest_uses_set_tag() {
        let message_digest = attribute(oid::MESSAGE_DIGEST, &[&tlv(tag::OCTET_STRING, &[1])]);
        let set = tlv(tag::SET, &message_digest);
        let expected: [u8; 32] = Sha256::digest(&set).into();
        assert_eq!(attributes(&[message_digest]).unwrap().digest(), expected);
    }
}
