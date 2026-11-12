//! Secure Boot signature-database lookup helpers.
//!
//! Authenticated variable mutation is not exposed by the separate runtime
//! image: accepting a time-based authentication attribute without an
//! image-local verifier would weaken Secure Boot. The boot image retains these
//! allocation-backed lookups solely for Authenticode verification.

use sha2::{Digest, Sha256};

use super::variables::{db_database, dbx_database};

/// Return whether a binary image hash is revoked by dbx.
pub fn is_hash_forbidden(hash: &[u8; 32]) -> bool {
    dbx_database().contains_sha256_hash(hash)
}

/// Return whether a binary image hash is allowed by db.
pub fn is_hash_allowed(hash: &[u8; 32]) -> bool {
    db_database().contains_sha256_hash(hash)
}

/// Return whether a certificate is revoked by dbx, either as an X.509 entry
/// or as an EFI_CERT_X509_SHA256 hash of its TBSCertificate.
pub fn is_certificate_forbidden(cert_der: &[u8]) -> bool {
    let dbx = dbx_database();
    dbx.find_x509_certificate(cert_der).is_some()
        || crabefi_pkcs7::x509::Certificate::parse(cert_der)
            .is_ok_and(|cert| dbx.contains_x509_tbs_sha256(&Sha256::digest(cert.tbs).into()))
}
