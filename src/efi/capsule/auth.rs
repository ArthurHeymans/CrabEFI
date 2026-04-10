//! Capsule Signature Verification
//!
//! Verifies PKCS#7 signatures on FMP capsule update images using the
//! existing RustCrypto infrastructure from `efi::auth`.
//!
//! # Trust Model
//!
//! Capsule signing certificates are separate from Secure Boot keys.
//! The platform provides trusted root certificates via
//! `CapsuleBackend::capsule_trust_store()`.
//!
//! # References
//!
//! - UEFI Specification 2.10, Section 23.1 — Firmware Image Authentication
//! - RFC 5652 — Cryptographic Message Syntax (PKCS#7/CMS)

use super::fmp::FirmwareImageAuth;
use super::header::CapsuleError;

/// Verify the PKCS#7 signature on a firmware update image.
///
/// # Arguments
///
/// - `auth`: The parsed authentication header containing the PKCS#7 data.
/// - `image_data`: The raw firmware image bytes that were signed.
/// - `trust_store`: DER-encoded X.509 certificates trusted for capsule signing.
///
/// # Returns
///
/// `Ok(())` if the signature is valid and chains to a trusted root,
/// `Err(CapsuleError::AuthenticationFailed)` otherwise.
pub fn verify_capsule_signature(
    auth: &FirmwareImageAuth,
    image_data: &[u8],
    trust_store: &[&[u8]],
) -> Result<(), CapsuleError> {
    if trust_store.is_empty() {
        log::error!("Capsule trust store is empty — cannot verify signature");
        return Err(CapsuleError::AuthenticationFailed);
    }

    if auth.pkcs7_data.is_empty() {
        log::error!("Capsule has no PKCS#7 signature data");
        return Err(CapsuleError::AuthenticationFailed);
    }

    log::info!(
        "Verifying capsule PKCS#7 signature ({} bytes) over {} bytes of image data",
        auth.pkcs7_data.len(),
        image_data.len()
    );

    // Try each trusted certificate in the trust store.
    // The signature is valid if it chains to any of them.
    for (i, cert_der) in trust_store.iter().enumerate() {
        match crate::efi::auth::verify_pkcs7_signature(
            auth.pkcs7_data.as_slice(),
            image_data,
            cert_der,
        ) {
            Ok(true) => {
                log::info!("Capsule signature verified against trust store cert #{}", i);
                return Ok(());
            }
            Ok(false) => {
                log::debug!("Trust store cert #{} did not match", i);
            }
            Err(e) => {
                log::debug!("Verification error with trust store cert #{}: {:?}", i, e);
            }
        }
    }

    log::error!(
        "Capsule signature did not chain to any of {} trusted certificate(s)",
        trust_store.len()
    );
    Err(CapsuleError::AuthenticationFailed)
}
