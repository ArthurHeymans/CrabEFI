//! Adversarial host tests for the runtime image's bounded CMS/DER parser.

use core::convert::Infallible;

use rsa::rand_core::{TryCryptoRng, TryRng};
use rsa::signature::{SignatureEncoding, hazmat::PrehashSigner};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

mod scratch {
    use allocator_api2::alloc::{AllocError, Allocator};
    use core::{alloc::Layout, ptr::NonNull};
    use std::alloc::{GlobalAlloc, System};

    #[derive(Clone, Copy)]
    pub struct TestAlloc;

    // SAFETY: all operations delegate to the process system allocator.
    unsafe impl Allocator for TestAlloc {
        fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
            if layout.size() == 0 {
                let pointer = NonNull::new(layout.align() as *mut u8).ok_or(AllocError)?;
                return Ok(NonNull::slice_from_raw_parts(pointer, 0));
            }
            let pointer = unsafe { System.alloc(layout) };
            let pointer = NonNull::new(pointer).ok_or(AllocError)?;
            Ok(NonNull::slice_from_raw_parts(pointer, layout.size()))
        }

        unsafe fn deallocate(&self, pointer: NonNull<u8>, layout: Layout) {
            unsafe { System.dealloc(pointer.as_ptr(), layout) }
        }
    }

    pub fn with_scope<R>(body: impl FnOnce(TestAlloc) -> R) -> Option<R> {
        Some(body(TestAlloc))
    }

    pub fn preflight(_required: usize) -> bool {
        true
    }
}

mod auth;

const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];

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
    let public = rsa::RsaPublicKey::from(key);
    let mut tbs_fields = concat(&[
        integer(&[serial]),
        algorithm(OID_SHA256_WITH_RSA),
        name(issuer),
        tlv(0x30, &[]),
        name(subject),
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

fn assert_rejected_without_panic(pkcs7: &[u8], trusted: &[u8]) {
    let outcome =
        std::panic::catch_unwind(|| auth::crypto::verify_pkcs7_signature(pkcs7, &[], trusted));
    let verification = outcome.expect("adversarial DER input must not panic");
    assert!(
        verification.is_err() || verification == Ok(false),
        "malformed or over-limit input was accepted"
    );
}

#[test]
fn truncated_tlv_is_rejected_without_panic() {
    assert_rejected_without_panic(&[0x30, 0x82, 0x01], &[]);
}

#[test]
fn length_past_end_of_buffer_is_rejected_without_panic() {
    assert_rejected_without_panic(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff], &[]);
}

#[test]
fn more_than_sixteen_certificates_is_rejected_without_panic() {
    let certificates = vec![tlv(0x30, &[]); 17];
    let input = signed_data(OID_SHA256, &certificates, &[]);
    assert_rejected_without_panic(&input, &[]);
}

#[test]
fn more_than_eight_signers_is_rejected_without_panic() {
    let key = test_key();
    let trusted = certificate(&key, 1, 1, 1, false);
    let signers = (0..9).map(|_| signer(99, 1, &[])).collect::<Vec<_>>();
    let input = signed_data(OID_SHA256, std::slice::from_ref(&trusted), &signers);
    assert_rejected_without_panic(&input, &trusted);
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
    let outcome =
        std::panic::catch_unwind(|| auth::crypto::verify_pkcs7_signature(&input, &[], &trusted));
    assert_eq!(
        outcome.expect("over-depth chain must not panic"),
        Err(auth::AuthError::ChainTooDeep)
    );
}

#[test]
fn non_sha256_digest_set_is_rejected_without_panic() {
    let input = signed_data(OID_SHA1, &[], &[]);
    assert_rejected_without_panic(&input, &[]);
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
    assert_eq!(
        auth::crypto::verify_pkcs7_signature(&cms, content, &trusted),
        Ok(true)
    );
}

#[test]
fn attached_content_and_wrong_encapsulated_type_are_rejected() {
    let attached = signed_data_with_encapsulated(OID_SHA256, &[], &[], OID_DATA, Some(b"attached"));
    assert_eq!(
        auth::crypto::verify_pkcs7_signature(&attached, b"detached", &[]),
        Err(auth::AuthError::InvalidHeader)
    );
    let wrong_type = signed_data_with_encapsulated(OID_SHA256, &[], &[], OID_SIGNED_DATA, None);
    assert_eq!(
        auth::crypto::verify_pkcs7_signature(&wrong_type, b"detached", &[]),
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
        auth::crypto::verify_pkcs7_signature(&valid_cms, content, &trusted),
        Ok(true)
    );

    let content_type = attribute(OID_CONTENT_TYPE, &[tlv(0x06, OID_DATA)]);
    let digest: [u8; 32] = Sha256::digest(content).into();
    let message_digest = attribute(OID_MESSAGE_DIGEST, &[tlv(0x04, &digest)]);
    let malformed = [
        message_digest.clone(),
        content_type.clone(),
        concat(&[
            content_type.clone(),
            content_type.clone(),
            message_digest.clone(),
        ]),
        concat(&[
            content_type.clone(),
            message_digest.clone(),
            message_digest.clone(),
        ]),
        concat(&[
            attribute(OID_CONTENT_TYPE, &[tlv(0x06, OID_SIGNED_DATA)]),
            message_digest.clone(),
        ]),
        concat(&[
            attribute(
                OID_CONTENT_TYPE,
                &[tlv(0x06, OID_DATA), tlv(0x06, OID_DATA)],
            ),
            message_digest.clone(),
        ]),
        concat(&[
            content_type.clone(),
            attribute(OID_MESSAGE_DIGEST, &[tlv(0x04, &[0; 32])]),
        ]),
        concat(&[
            content_type,
            attribute(
                OID_MESSAGE_DIGEST,
                &[tlv(0x04, &digest), tlv(0x04, &digest)],
            ),
        ]),
    ];
    for attributes in malformed {
        let cms = signed_data(
            OID_SHA256,
            std::slice::from_ref(&trusted),
            &[signer_with_attributes(1, 1, Some(&attributes), &[])],
        );
        let result = auth::crypto::verify_pkcs7_signature(&cms, content, &trusted);
        assert!(result.is_err(), "malformed signed attributes were accepted");
    }
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
