#![no_main]

use crabefi_pkcs7::{cms::SignedData, x509::Certificate};

// Authenticated variables, capsules and signed images all reach this parser
// with attacker-chosen bytes before any signature is checked.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(signed) = SignedData::parse(data) {
        for certificate in signed.certificates() {
            if let Ok(certificate) = Certificate::parse(certificate.encoded) {
                let _ = certificate.validity();
                let _ = certificate.basic_constraints();
                let _ = certificate.key_usage();
                let _ = certificate.subject_key_identifier();
                if let Ok(key) = certificate.rsa_public_key() {
                    let _ = key.verify_pkcs1v15_sha256::<64>(certificate.signature, &[0; 32]);
                }
            }
        }
        for signer in signed.signers().flatten() {
            if let Some(attributes) = signer.signed_attributes {
                let _ = attributes.content_type();
                let _ = attributes.message_digest();
                core::hint::black_box(attributes.digest());
            }
        }
    }
    if let Ok(certificate) = Certificate::parse(data) {
        let _ = certificate.rsa_public_key();
        let _ = certificate.basic_constraints();
    }
});
