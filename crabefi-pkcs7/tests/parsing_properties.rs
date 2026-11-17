//! Exercise parsing on the host; none of the test machinery is linked into firmware.

use crabefi_pkcs7::{cms::SignedData, der::Reader, x509::Certificate};
use proptest::prelude::*;

const FIXTURES: &[&[u8]] = &[
    include_bytes!("../testdata/ca.der"),
    include_bytes!("../testdata/leaf.der"),
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
fn all_prefixes_of_known_certificates_and_signed_data() {
    for fixture in FIXTURES {
        for end in 0..=fixture.len() {
            exercise_parsers(&fixture[..end]);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn arbitrary_bytes_have_bounded_parsing(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        exercise_parsers(&bytes);
    }

    #[test]
    fn mutated_fixtures_have_bounded_parsing(
        fixture in 0..FIXTURES.len(),
        edits in prop::collection::vec((any::<u16>(), any::<u8>()), 1..9),
    ) {
        let mut bytes = FIXTURES[fixture].to_vec();
        let len = bytes.len();
        for (offset, xor) in edits {
            bytes[usize::from(offset) % len] ^= xor;
        }
        exercise_parsers(&bytes);
    }
}
