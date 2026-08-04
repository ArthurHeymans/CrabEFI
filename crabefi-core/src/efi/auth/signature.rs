//! Secure Boot signature-database lookup helpers.
//!
//! Authenticated variable mutation is not exposed by the separate runtime
//! image: accepting a time-based authentication attribute without an
//! image-local verifier would weaken Secure Boot. The boot image retains these
//! allocation-backed lookups solely for Authenticode verification.

use super::variables::{db_database, dbx_database};

/// Return whether a binary image hash is revoked by dbx.
pub fn is_hash_forbidden(hash: &[u8; 32]) -> bool {
    dbx_database().contains_sha256_hash(hash)
}

/// Return whether a binary image hash is allowed by db.
pub fn is_hash_allowed(hash: &[u8; 32]) -> bool {
    db_database().contains_sha256_hash(hash)
}

/// Return whether a certificate is revoked by dbx.
pub fn is_certificate_forbidden(cert_der: &[u8]) -> bool {
    dbx_database().find_x509_certificate(cert_der).is_some()
}
