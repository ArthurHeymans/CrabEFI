//! Adversarial host tests for the runtime image's authenticated-variable CMS
//! policy.

use core::convert::Infallible;

use rsa::rand_core::{TryCryptoRng, TryRng};
use rsa::signature::{SignatureEncoding, hazmat::PrehashSigner};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

mod auth;

const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];

fn verify_pkcs7_signature(
    pkcs7: &[u8],
    content: &[u8],
    trusted: &[u8],
) -> Result<bool, auth::AuthError> {
    let content_hash: [u8; 32] = Sha256::digest(content).into();
    auth::crypto::verify_pkcs7_signature_hash(pkcs7, &content_hash, trusted)
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    match value.len() {
        length @ 0..=0x7f => result.push(length as u8),
        length @ 0x80..=0xff => result.extend_from_slice(&[0x81, length as u8]),
        length @ 0x100..=0xffff => {
            result.push(0x82);
            result.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            result.push(0x84);
            result.extend_from_slice(&(length as u32).to_be_bytes());
        }
    }
    result.extend_from_slice(value);
    result
}

fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

fn integer(bytes: &[u8]) -> Vec<u8> {
    let mut value = bytes.to_vec();
    if value.first().is_some_and(|byte| byte & 0x80 != 0) {
        value.insert(0, 0);
    }
    tlv(0x02, &value)
}

fn algorithm(oid: &[u8]) -> Vec<u8> {
    tlv(0x30, &concat(&[tlv(0x06, oid), tlv(0x05, &[])]))
}

fn signed_data(digest_oid: &[u8], certificates: &[Vec<u8>], signers: &[Vec<u8>]) -> Vec<u8> {
    signed_data_with_encapsulated(digest_oid, certificates, signers, OID_DATA, None)
}

fn signed_data_with_encapsulated(
    digest_oid: &[u8],
    certificates: &[Vec<u8>],
    signers: &[Vec<u8>],
    content_type: &[u8],
    attached: Option<&[u8]>,
) -> Vec<u8> {
    let digest_set = tlv(0x31, &algorithm(digest_oid));
    let mut encapsulated_fields = tlv(0x06, content_type);
    if let Some(content) = attached {
        encapsulated_fields.extend_from_slice(&tlv(0xa0, &tlv(0x04, content)));
    }
    let encapsulated = tlv(0x30, &encapsulated_fields);
    let certificate_set = tlv(0xa0, &certificates.concat());
    let signer_set = tlv(0x31, &signers.concat());
    let body = tlv(
        0x30,
        &concat(&[
            integer(&[1]),
            digest_set,
            encapsulated,
            certificate_set,
            signer_set,
        ]),
    );
    tlv(
        0x30,
        &concat(&[tlv(0x06, OID_SIGNED_DATA), tlv(0xa0, &body)]),
    )
}

fn name(id: u8) -> Vec<u8> {
    tlv(0x30, &integer(&[id]))
}

fn subject_public_key(key: &rsa::RsaPublicKey) -> Vec<u8> {
    let key_sequence = tlv(
        0x30,
        &concat(&[
            integer(&key.n().to_be_bytes_trimmed_vartime()),
            integer(&key.e().to_be_bytes_trimmed_vartime()),
        ]),
    );
    let mut bits = vec![0];
    bits.extend_from_slice(&key_sequence);
    tlv(0x30, &concat(&[tlv(0x30, &[]), tlv(0x03, &bits)]))
}

fn certificate(key: &rsa::RsaPrivateKey, serial: u8, issuer: u8, subject: u8, ca: bool) -> Vec<u8> {
    named_certificate(key, serial, &name(issuer), &name(subject), ca)
}

fn named_certificate(
    key: &rsa::RsaPrivateKey,
    serial: u8,
    issuer: &[u8],
    subject: &[u8],
    ca: bool,
) -> Vec<u8> {
    let public = rsa::RsaPublicKey::from(key);
    let mut tbs_fields = concat(&[
        integer(&[serial]),
        algorithm(OID_SHA256_WITH_RSA),
        issuer.to_vec(),
        tlv(0x30, &[]),
        subject.to_vec(),
        subject_public_key(&public),
    ]);
    if ca {
        let constraints = tlv(0x30, &tlv(0x01, &[0xff]));
        let extension = tlv(
            0x30,
            &concat(&[tlv(0x06, OID_BASIC_CONSTRAINTS), tlv(0x04, &constraints)]),
        );
        tbs_fields.extend_from_slice(&tlv(0xa3, &tlv(0x30, &extension)));
    }
    let tbs = tlv(0x30, &tbs_fields);
    let digest: [u8; 32] = Sha256::digest(&tbs).into();
    let signature = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone())
        .sign_prehash(&digest)
        .expect("test key signs SHA-256 prehash")
        .to_vec();
    let mut signature_bits = vec![0];
    signature_bits.extend_from_slice(&signature);
    tlv(
        0x30,
        &concat(&[
            tbs,
            algorithm(OID_SHA256_WITH_RSA),
            tlv(0x03, &signature_bits),
        ]),
    )
}

fn signer(issuer: u8, serial: u8, signature: &[u8]) -> Vec<u8> {
    signer_with_attributes(issuer, serial, None, signature)
}

/// SignerInfo naming the certificate `serial` of the DER Name `issuer`.
fn named_signer(issuer: &[u8], serial: u8) -> Vec<u8> {
    let identity = tlv(0x30, &concat(&[issuer.to_vec(), integer(&[serial])]));
    tlv(
        0x30,
        &concat(&[
            integer(&[1]),
            identity,
            algorithm(OID_SHA256),
            tlv(0x30, &[]),
            tlv(0x04, &[0; 128]),
        ]),
    )
}

/// A Name of one RDN per (attribute OID, DER string) pair.
fn rdn_name(attributes: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    let rdns: Vec<Vec<u8>> = attributes
        .iter()
        .map(|(oid, value)| tlv(0x31, &tlv(0x30, &concat(&[tlv(0x06, oid), value.clone()]))))
        .collect();
    tlv(0x30, &rdns.concat())
}

fn common_name(text: &str) -> Vec<u8> {
    rdn_name(&[(OID_COMMON_NAME, tlv(0x0c, text.as_bytes()))])
}

/// The first element inside the DER SEQUENCE `der` (a certificate's TBS).
fn first_element(der: &[u8]) -> &[u8] {
    let header = |bytes: &[u8]| match bytes[1] {
        length @ 0..=0x7f => (2, length as usize),
        count => {
            let count = (count & 0x7f) as usize;
            let length = bytes[2..2 + count]
                .iter()
                .fold(0, |length, byte| length << 8 | *byte as usize);
            (2 + count, length)
        }
    };
    let (outer, _) = header(der);
    let inner = &der[outer..];
    let (size, length) = header(inner);
    &inner[..size + length]
}

fn signer_with_attributes(
    issuer: u8,
    serial: u8,
    attributes: Option<&[u8]>,
    signature: &[u8],
) -> Vec<u8> {
    let identity = tlv(0x30, &concat(&[name(issuer), integer(&[serial])]));
    let mut fields = concat(&[integer(&[1]), identity, algorithm(OID_SHA256)]);
    if let Some(attributes) = attributes {
        fields.extend_from_slice(&tlv(0xa0, attributes));
    }
    fields.extend_from_slice(&tlv(0x30, &[]));
    fields.extend_from_slice(&tlv(0x04, signature));
    tlv(0x30, &fields)
}

fn attribute(oid: &[u8], values: &[Vec<u8>]) -> Vec<u8> {
    tlv(
        0x30,
        &concat(&[tlv(0x06, oid), tlv(0x31, &values.concat())]),
    )
}

fn required_attributes(content: &[u8]) -> Vec<u8> {
    let digest: [u8; 32] = Sha256::digest(content).into();
    concat(&[
        attribute(OID_CONTENT_TYPE, &[tlv(0x06, OID_DATA)]),
        attribute(OID_MESSAGE_DIGEST, &[tlv(0x04, &digest)]),
    ])
}

fn sign(key: &rsa::RsaPrivateKey, content: &[u8]) -> Vec<u8> {
    rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone())
        .sign_prehash(&Sha256::digest(content))
        .unwrap()
        .to_vec()
}

fn verify_without_panic(
    pkcs7: &[u8],
    content: &[u8],
    trusted: &[u8],
) -> Result<bool, auth::AuthError> {
    std::panic::catch_unwind(|| verify_pkcs7_signature(pkcs7, content, trusted))
        .expect("adversarial DER input must not panic")
}

#[test]
fn more_than_sixteen_certificates_is_rejected_without_panic() {
    let key = test_key();
    let trusted = certificate(&key, 1, 1, 1, false);
    let signers = [signer(1, 1, &sign(&key, &[]))];
    let mut certificates = vec![trusted.clone(); 16];
    let accepted = signed_data(OID_SHA256, &certificates, &signers);
    assert_eq!(verify_without_panic(&accepted, &[], &trusted), Ok(true));
    certificates.push(trusted.clone());
    let input = signed_data(OID_SHA256, &certificates, &signers);
    assert_eq!(
        verify_without_panic(&input, &[], &trusted),
        Err(auth::AuthError::OutOfResources)
    );
}

#[test]
fn signer_budget_accepts_eighth_and_rejects_ninth_attempt() {
    let key = test_key();
    let trusted = certificate(&key, 1, 1, 1, false);
    let signature = sign(&key, &[]);
    let valid = signer(1, 1, &signature);
    let mut wrong_signature = signature;
    wrong_signature[0] ^= 0x80;
    let rejected = signer(1, 1, &wrong_signature);
    // The policy limits attempts, not total signers after an early success.
    // All entries have a real matching certificate; only their signatures
    // differ, with the successful attempt at the boundary being tested.
    let mut signers = vec![rejected.clone(); 7];
    signers.push(valid);
    let accepted = signed_data(OID_SHA256, std::slice::from_ref(&trusted), &signers);
    assert_eq!(verify_without_panic(&accepted, &[], &trusted), Ok(true));
    signers.insert(0, rejected);
    let input = signed_data(OID_SHA256, std::slice::from_ref(&trusted), &signers);
    assert_eq!(
        verify_without_panic(&input, &[], &trusted),
        Err(auth::AuthError::OutOfResources)
    );
}

#[test]
fn chain_deeper_than_five_is_rejected_without_panic() {
    let key = test_key();
    let leaf = certificate(&key, 1, 2, 1, false);
    let mut certificates = vec![leaf];
    for subject in 2..=6 {
        certificates.push(certificate(&key, subject, subject + 1, subject, true));
    }
    let trusted = certificate(&key, 42, 42, 42, true);
    let content_digest: [u8; 32] = Sha256::digest([]).into();
    let signature = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone())
        .sign_prehash(&content_digest)
        .expect("test key signs content prehash")
        .to_vec();
    let input = signed_data(OID_SHA256, &certificates, &[signer(2, 1, &signature)]);
    let outcome = std::panic::catch_unwind(|| verify_pkcs7_signature(&input, &[], &trusted));
    assert_eq!(
        outcome.expect("over-depth chain must not panic"),
        Err(auth::AuthError::ChainTooDeep)
    );
}

#[test]
fn non_sha256_digest_set_is_rejected_without_panic() {
    let key = test_key();
    let trusted = certificate(&key, 1, 1, 1, false);
    let content = b"digest policy";
    let signers = [signer(1, 1, &sign(&key, content))];
    let certificates = std::slice::from_ref(&trusted);
    let accepted = signed_data(OID_SHA256, certificates, &signers);
    assert_eq!(verify_without_panic(&accepted, content, &trusted), Ok(true));
    // Change only digestAlgorithms: signer, certificate and signature remain
    // the known-good baseline, so a missing policy check would accept it.
    let input = signed_data(OID_SHA1, certificates, &signers);
    assert_eq!(
        verify_without_panic(&input, content, &trusted),
        Err(auth::AuthError::CryptoError)
    );
}

#[test]
fn valid_detached_cms_is_accepted() {
    let key = test_key();
    let trusted = certificate(&key, 1, 1, 1, false);
    let content = b"authenticated variable bytes";
    let digest: [u8; 32] = Sha256::digest(content).into();
    let signature = rsa::pkcs1v15::SigningKey::<Sha256>::new(key)
        .sign_prehash(&digest)
        .unwrap()
        .to_vec();
    let cms = signed_data(
        OID_SHA256,
        std::slice::from_ref(&trusted),
        &[signer(1, 1, &signature)],
    );
    assert_eq!(verify_pkcs7_signature(&cms, content, &trusted), Ok(true));
}

#[test]
fn attached_content_and_wrong_encapsulated_type_are_rejected() {
    let attached = signed_data_with_encapsulated(OID_SHA256, &[], &[], OID_DATA, Some(b"attached"));
    assert_eq!(
        verify_pkcs7_signature(&attached, b"detached", &[]),
        Err(auth::AuthError::InvalidHeader)
    );
    let wrong_type = signed_data_with_encapsulated(OID_SHA256, &[], &[], OID_SIGNED_DATA, None);
    assert_eq!(
        verify_pkcs7_signature(&wrong_type, b"detached", &[]),
        Err(auth::AuthError::InvalidHeader)
    );
}

#[test]
fn signed_attributes_require_unique_matching_content_type_and_digest() {
    let key = test_key();
    let trusted = certificate(&key, 1, 1, 1, false);
    let content = b"signed attributes content";
    let valid = required_attributes(content);
    let valid_der = tlv(0x31, &valid);
    let valid_digest: [u8; 32] = Sha256::digest(&valid_der).into();
    let valid_signature = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone())
        .sign_prehash(&valid_digest)
        .unwrap()
        .to_vec();
    let valid_cms = signed_data(
        OID_SHA256,
        std::slice::from_ref(&trusted),
        &[signer_with_attributes(1, 1, Some(&valid), &valid_signature)],
    );
    assert_eq!(
        verify_pkcs7_signature(&valid_cms, content, &trusted),
        Ok(true)
    );

    let content_type = attribute(OID_CONTENT_TYPE, &[tlv(0x06, OID_DATA)]);
    let digest: [u8; 32] = Sha256::digest(content).into();
    let message_digest = attribute(OID_MESSAGE_DIGEST, &[tlv(0x04, &digest)]);
    use auth::AuthError::{InvalidHeader, SignatureVerificationFailed};
    let malformed = [
        (message_digest.clone(), InvalidHeader),
        (content_type.clone(), InvalidHeader),
        (
            concat(&[
                content_type.clone(),
                content_type.clone(),
                message_digest.clone(),
            ]),
            InvalidHeader,
        ),
        (
            concat(&[
                content_type.clone(),
                message_digest.clone(),
                message_digest.clone(),
            ]),
            InvalidHeader,
        ),
        (
            concat(&[
                attribute(OID_CONTENT_TYPE, &[tlv(0x06, OID_SIGNED_DATA)]),
                message_digest.clone(),
            ]),
            InvalidHeader,
        ),
        (
            concat(&[
                attribute(
                    OID_CONTENT_TYPE,
                    &[tlv(0x06, OID_DATA), tlv(0x06, OID_DATA)],
                ),
                message_digest.clone(),
            ]),
            InvalidHeader,
        ),
        (
            concat(&[
                content_type.clone(),
                attribute(OID_MESSAGE_DIGEST, &[tlv(0x04, &[0; 32])]),
            ]),
            SignatureVerificationFailed,
        ),
        (
            concat(&[
                content_type,
                attribute(
                    OID_MESSAGE_DIGEST,
                    &[tlv(0x04, &digest), tlv(0x04, &digest)],
                ),
            ]),
            InvalidHeader,
        ),
    ];
    for (attributes, expected) in malformed {
        // Even malformed attributes have a valid RSA signature over their
        // exact SET bytes. An unrelated signature error cannot satisfy this
        // test if an attribute-policy check is accidentally removed.
        let signature = sign(&key, &tlv(0x31, &attributes));
        let cms = signed_data(
            OID_SHA256,
            std::slice::from_ref(&trusted),
            &[signer_with_attributes(1, 1, Some(&attributes), &signature)],
        );
        assert_eq!(verify_without_panic(&cms, content, &trusted), Err(expected));
    }
}

fn private_signer_digest(cms: &[u8]) -> Result<([u8; 32], Vec<u8>), auth::AuthError> {
    std::panic::catch_unwind(|| {
        auth::crypto::private_signer(cms).map(|signer| (signer.digest, signer.top_level.to_vec()))
    })
    .expect("adversarial DER input must not panic")
}

fn binding(common_name: &[u8], top_level: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(common_name)
        .chain_update(first_element(top_level))
        .finalize()
        .into()
}

#[test]
fn private_signer_binds_the_common_name_and_the_top_level_issuer() {
    let key = test_key();
    let (root_name, mid_name) = (common_name("Root"), common_name("Mid"));
    let root = named_certificate(&key, 1, &root_name, &root_name, true);
    let mid = named_certificate(&key, 2, &root_name, &mid_name, true);
    let leaf = named_certificate(&key, 3, &mid_name, &common_name("Leaf"), false);
    let signers = [named_signer(&mid_name, 3)];
    // Any certificate order; the walk stops at the self-issued root.
    let cms = signed_data(
        OID_SHA256,
        &[root.clone(), leaf.clone(), mid.clone()],
        &signers,
    );
    assert_eq!(
        private_signer_digest(&cms),
        Ok((binding(b"Leaf", &root), root.clone()))
    );
    // Without the root, the intermediate is the top level.
    let cms = signed_data(OID_SHA256, &[leaf.clone(), mid.clone()], &signers);
    assert_eq!(
        private_signer_digest(&cms),
        Ok((binding(b"Leaf", &mid), mid))
    );

    // The CN in UTF-8 (BMPString here), the first one, cut to 127 bytes.
    for (subject, text) in [
        (
            rdn_name(&[(OID_COMMON_NAME, tlv(0x1e, &[0x00, 0x4c, 0x00, 0xe9]))]),
            "L\u{e9}".to_string(),
        ),
        (
            rdn_name(&[
                (OID_ORGANIZATION, tlv(0x0c, b"Org")),
                (OID_COMMON_NAME, tlv(0x13, b"First")),
                (OID_COMMON_NAME, tlv(0x13, b"Second")),
            ]),
            "First".to_string(),
        ),
        (common_name(&"a".repeat(200)), "a".repeat(127)),
        (common_name("Cut\0here"), "Cut".to_string()),
    ] {
        let leaf = named_certificate(&key, 3, &root_name, &subject, false);
        let cms = signed_data(
            OID_SHA256,
            &[leaf, root.clone()],
            &[named_signer(&root_name, 3)],
        );
        assert_eq!(
            private_signer_digest(&cms),
            Ok((binding(text.as_bytes(), &root), root.clone()))
        );
    }
}

#[test]
fn private_signer_rejects_ambiguous_or_nameless_signers_without_panic() {
    let key = test_key();
    let root_name = common_name("Root");
    let root = named_certificate(&key, 1, &root_name, &root_name, true);
    let signer = named_signer(&root_name, 1);
    let no_name = rdn_name(&[(OID_ORGANIZATION, tlv(0x0c, b"Org"))]);
    let nameless = named_certificate(&key, 1, &no_name, &no_name, true);
    for (certificates, signers, expected) in [
        (
            vec![root.clone()],
            vec![signer.clone(), signer.clone()],
            auth::AuthError::NoSuitableKey,
        ),
        (vec![root.clone()], vec![], auth::AuthError::InvalidHeader),
        (vec![], vec![signer.clone()], auth::AuthError::NoSuitableKey),
        (
            vec![nameless],
            vec![named_signer(&no_name, 1)],
            auth::AuthError::NoSuitableKey,
        ),
    ] {
        let cms = signed_data(OID_SHA256, &certificates, &signers);
        assert_eq!(private_signer_digest(&cms), Err(expected));
    }

    // Issuers that keep issuing each other stop at the depth limit.
    let (a, b) = (common_name("A"), common_name("B"));
    let certificates = [
        named_certificate(&key, 1, &b, &a, true),
        named_certificate(&key, 2, &a, &b, true),
    ];
    let cms = signed_data(OID_SHA256, &certificates, &[named_signer(&b, 1)]);
    assert_eq!(
        private_signer_digest(&cms),
        Err(auth::AuthError::ChainTooDeep)
    );
}

fn test_key() -> rsa::RsaPrivateKey {
    struct DeterministicRng(u64);

    impl TryRng for DeterministicRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.try_next_u64()? as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut value = self.0;
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            self.0 = value;
            Ok(value)
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in destination.chunks_mut(8) {
                let bytes = self.try_next_u64()?.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            Ok(())
        }
    }

    impl TryCryptoRng for DeterministicRng {}

    rsa::RsaPrivateKey::new(&mut DeterministicRng(0x5eed_cafe_f00d_beef), 1024)
        .expect("deterministic test key generation")
}
