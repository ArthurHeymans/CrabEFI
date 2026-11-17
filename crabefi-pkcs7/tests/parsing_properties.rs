//! Exercise parsing on the host; none of the test machinery is linked into firmware.

use crabefi_pkcs7::{
    cms::SignedData,
    der::{Reader, tag},
    x509::Certificate,
};
use proptest::prelude::*;

const CERTIFICATES: &[&[u8]] = &[
    include_bytes!("../testdata/ca.der"),
    include_bytes!("../testdata/leaf.der"),
];

const SIGNATURES: &[&[u8]] = &[
    include_bytes!("../testdata/cms_attrs.der"),
    include_bytes!("../testdata/cms_noattr.der"),
    include_bytes!("../testdata/cms_keyid.der"),
];

fn exercise_parsers(bytes: &[u8]) {
    let mut consumed = 0;
    // Every successful element must consume input; an error ends iteration.
    let mut reader = Reader::new(bytes);
    for _ in 0..bytes.len() + 1 {
        match reader.next() {
            Some(Ok(tlv)) => {
                assert!(!tlv.encoded.is_empty());
                assert!(bytes[consumed..].starts_with(tlv.encoded));
                consumed += tlv.encoded.len();
            }
            Some(Err(_)) => {
                assert!(consumed < bytes.len());
                assert!(reader.next().is_none());
                break;
            }
            None => {
                assert_eq!(consumed, bytes.len());
                break;
            }
        }
    }
    if let Ok(cert) = Certificate::parse(bytes) {
        let _ = cert.validity();
        let _ = cert.rsa_public_key();
        let _ = cert.basic_constraints();
        let _ = cert.key_usage();
        let _ = cert.subject_key_identifier();
    }
    if let Ok(signed) = SignedData::parse(bytes) {
        assert!(signed.certificates().take(bytes.len() + 1).count() <= bytes.len());
        for (index, signer) in signed.signers().take(bytes.len() + 1).enumerate() {
            assert!(index < bytes.len());
            // The outer parse validates the signer envelope, not its fields.
            if let Ok(signer) = signer
                && let Some(attributes) = signer.signed_attributes
            {
                let _ = attributes.content_type();
                let _ = attributes.message_digest();
                let _ = attributes.digest();
            }
        }
    }
}

#[test]
fn complete_fixtures_parse_and_all_proper_prefixes_are_rejected() {
    for &fixture in CERTIFICATES {
        assert_eq!(Certificate::parse(fixture).unwrap().encoded, fixture);
        for end in 0..fixture.len() {
            assert!(
                Certificate::parse(&fixture[..end]).is_err(),
                "certificate prefix of {end} bytes"
            );
        }
    }
    for &fixture in SIGNATURES {
        assert_detached_cms(fixture);
        for end in 0..fixture.len() {
            assert!(
                SignedData::parse(&fixture[..end]).is_err(),
                "CMS prefix of {end} bytes"
            );
        }
    }
}

fn assert_detached_cms(bytes: &[u8]) {
    let signed = SignedData::parse(bytes).unwrap();
    assert!(signed.encapsulated_content.content.is_none());
    let mut certificates = signed.certificates();
    assert_eq!(certificates.next().unwrap().encoded, CERTIFICATES[1]);
    assert!(certificates.next().is_none());
    let mut signers = signed.signers();
    assert!(signers.next().unwrap().is_ok());
    assert!(signers.next().is_none());
}

fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    match value.len() {
        n @ 0..=127 => result.push(n as u8),
        n @ 128..=255 => result.extend([0x81, n as u8]),
        n => {
            result.push(0x82);
            result.extend(u16::try_from(n).unwrap().to_be_bytes());
        }
    }
    result.extend_from_slice(value);
    result
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn arbitrary_bytes_have_bounded_parsing(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        exercise_parsers(&bytes);
    }

    #[test]
    fn mutated_fixtures_have_bounded_parsing(
        fixture in 0..CERTIFICATES.len() + SIGNATURES.len(),
        edits in prop::collection::vec((any::<u16>(), any::<u8>()), 1..9),
    ) {
        let mut bytes = CERTIFICATES.iter().chain(SIGNATURES).nth(fixture).unwrap().to_vec();
        let len = bytes.len();
        for (offset, xor) in edits {
            bytes[usize::from(offset) % len] ^= xor;
        }
        exercise_parsers(&bytes);
    }

    #[test]
    fn only_cms_allows_a_suffix(suffix in prop::collection::vec(any::<u8>(), 1..65)) {
        for &fixture in CERTIFICATES {
            let mut input = fixture.to_vec();
            input.extend_from_slice(&suffix);
            prop_assert!(Certificate::parse(&input).is_err());
        }
        for &fixture in SIGNATURES {
            let mut input = fixture.to_vec();
            input.extend_from_slice(&suffix);
            assert_detached_cms(&input);
        }
    }

    #[test]
    fn der_decodes_known_tags_lengths_and_values(
        byte in any::<u8>(),
        tail in prop::collection::vec(any::<u8>(), 0..300),
    ) {
        let fields = [
            (tag::OCTET_STRING, vec![byte; 127]),
            (tag::context(3), vec![byte; 128]),
            (tag::OCTET_STRING, vec![byte; 256]),
            (tag::context(1), tail),
        ];
        let encodings: Vec<_> = fields.iter().map(|(tag, bytes)| encode_tlv(*tag, bytes)).collect();
        let input = encodings.concat();
        let mut reader = Reader::new(&input);
        for ((tag, value), encoding) in fields.iter().zip(&encodings) {
            let tlv = reader.next().unwrap().unwrap();
            prop_assert_eq!(tlv.tag, *tag);
            prop_assert_eq!(tlv.value, value.as_slice());
            prop_assert_eq!(tlv.encoded, encoding.as_slice());
        }
        prop_assert!(reader.next().is_none());
        prop_assert!(reader.finish().is_ok());
    }
}
