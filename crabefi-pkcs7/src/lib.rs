//! Allocation-free certificate and signature verification primitives.
//!
//! Borrowed views over DER-encoded X.509 certificates and PKCS#7/CMS
//! `SignedData`, plus RSA PKCS#1 v1.5 SHA-256 verification on fixed-width
//! stack arithmetic. The views validate structure only; trust decisions
//! (algorithm policy, chain building, key usage, validity, revocation) belong
//! to the caller.
//!
//! The crate runs inside the Runtime Services image, so no code path may
//! panic, allocate, or use more stack than a few RSA operand buffers.

#![cfg_attr(not(test), no_std)]

mod bigint;
pub mod cms;
pub mod der;
pub mod oid;
pub mod rsa;
pub mod time;
pub mod x509;

#[cfg(test)]
mod testdata {
    //! OpenSSL-generated fixtures: a self-signed CA, a leaf it issued, a
    //! self-signed look-alike with the CA's subject and serial but another
    //! key, and detached CMS signatures over `DATA` by the leaf (with signed
    //! attributes, without them, and identified by subject key identifier).
    pub const CA: &[u8] = include_bytes!("../testdata/ca.der");
    pub const LEAF: &[u8] = include_bytes!("../testdata/leaf.der");
    pub const FORGED_CA: &[u8] = include_bytes!("../testdata/forged_ca.der");
    pub const DATA: &[u8] = include_bytes!("../testdata/data.bin");
    pub const CMS_ATTRS: &[u8] = include_bytes!("../testdata/cms_attrs.der");
    pub const CMS_NOATTR: &[u8] = include_bytes!("../testdata/cms_noattr.der");
    pub const CMS_KEYID: &[u8] = include_bytes!("../testdata/cms_keyid.der");
}
