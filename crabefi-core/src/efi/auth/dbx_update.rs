//! Microsoft dbx (Forbidden Signature Database) Updates
//!
//! This module provides functionality to load and apply Microsoft's UEFI
//! Forbidden Signature Database (dbx) updates. These updates contain revoked
//! signatures that should be blocked from booting.
//!
//! # Security Model
//!
//! dbx updates MUST be signed by either:
//! - A certificate in the KEK (Key Exchange Key) database
//! - The Platform Key (PK)
//!
//! Updates are also subject to anti-downgrade protection:
//! - Each update must have a timestamp newer than the current dbx timestamp
//! - This prevents replay attacks using older dbx versions
//!
//! # Microsoft dbx Updates
//!
//! Microsoft publishes dbx updates that contain:
//! - SHA-256 hashes of revoked bootloaders
//! - X.509 certificates that have been compromised
//!
//! These are published at: https://www.microsoft.com/en-us/pkiops/revobjects
//!
//! # File Formats Supported
//!
//! - **Authenticated format** (.auth): EFI_VARIABLE_AUTHENTICATION_2 with PKCS#7 signature
//! - **Raw format** (.bin/.esl): Only allowed in Setup Mode or for initial provisioning
//!
//! # Usage
//!
//! ```rust,ignore
//! use crab_efi::efi::auth::dbx_update;
//!
//! // Search for and apply dbx updates from ESP
//! if let Ok(count) = dbx_update::enroll_dbx_from_file() {
//!     log::info!("Added {} entries to dbx", count);
//! }
//! ```

use crabefi_efi_types::{
    authentication::{
        EfiTime, EfiVariableAuthentication2, SignatureIterator, SignatureListIterator,
        validate_signature_database,
    },
    secure_boot::{
        DBX_NAME, EFI_CERT_SHA256_GUID, EFI_CERT_TYPE_PKCS7_GUID, EFI_CERT_X509_GUID,
        EFI_IMAGE_SECURITY_DATABASE_GUID,
    },
};

use super::crypto::{sha256, verify_pkcs7_signature_chain};
use super::variables::{kek_database, pk_database};
use super::{AuthError, is_setup_mode};
use crate::drivers::block::BlockDevice;
use crate::fs::fat::FatFilesystem;
use crate::fs::gpt;
use alloc::vec::Vec;

/// Maximum dbx update file size (1MB should be plenty)
const MAX_DBX_SIZE: usize = 1024 * 1024;

/// File paths to search for signed dbx updates (.auth format preferred)
const DBX_AUTH_PATHS: &[&str] = &[
    "EFI\\keys\\dbxupdate.auth",
    "EFI\\keys\\DBXUPDATE.auth",
    "EFI\\keys\\dbx.auth",
    "EFI\\keys\\DBX.auth",
    "EFI\\updatedbx\\dbxupdate.auth",
    "EFI\\updatedbx\\DBXUPDATE.auth",
    "EFI\\Microsoft\\Boot\\dbxupdate.auth",
    "EFI\\MICROSOFT\\BOOT\\DBXUPDATE.auth",
];

/// File paths to search for raw dbx files (only used in Setup Mode)
const DBX_RAW_PATHS: &[&str] = &[
    "EFI\\keys\\dbx.bin",
    "EFI\\keys\\DBX.bin",
    "EFI\\keys\\dbx.esl",
    "EFI\\keys\\DBX.esl",
    "EFI\\updatedbx\\dbx.bin",
    "EFI\\updatedbx\\DBX.bin",
    "EFI\\Microsoft\\Boot\\dbx.bin",
    "EFI\\MICROSOFT\\BOOT\\DBX.bin",
];

/// Source of dbx update
#[derive(Debug, Clone, Copy)]
pub enum DbxSource {
    /// Authenticated update file (signed)
    Authenticated(&'static str),
    /// Raw update file (only in Setup Mode)
    Raw(&'static str),
}

impl DbxSource {
    fn as_str(&self) -> &'static str {
        match self {
            DbxSource::Authenticated(s) => s,
            DbxSource::Raw(s) => s,
        }
    }
}

/// Result of dbx enrollment
#[derive(Debug, Clone)]
pub struct DbxEnrollmentResult {
    /// Number of SHA-256 hash entries added
    pub sha256_count: usize,
    /// Number of X.509 certificate entries added
    pub x509_count: usize,
    /// Source where dbx was found
    pub source: &'static str,
}

/// Verified preview of the exact owned update the user may choose to import.
/// Text-only builds consume `entries` but do not display the identity metadata.
#[cfg_attr(not(feature = "ui"), allow(dead_code))]
pub(crate) struct DbxPreview {
    pub entries: DbxEnrollmentResult,
    pub timestamp: Option<EfiTime>,
    /// SHA-256 of the cryptographically verified signer, not an arbitrary CMS cert.
    pub signer_sha256: Option<[u8; 32]>,
    /// The signature binds APPEND_WRITE: applying the update merges its
    /// entries into the existing dbx instead of replacing it. Microsoft's
    /// published updates are signed this way.
    pub append: bool,
}

#[cfg(feature = "ui")]
pub(crate) fn preview_dbx_update(data: &[u8], source: DbxSource) -> Result<DbxPreview, AuthError> {
    match source {
        DbxSource::Authenticated(src) => inspect_authenticated_dbx_update(data, src),
        DbxSource::Raw(src) if is_setup_mode() => Ok(DbxPreview {
            entries: apply_raw_dbx_update(data, src)?,
            timestamp: None,
            signer_sha256: None,
            append: false,
        }),
        DbxSource::Raw(_) => Err(AuthError::SignatureVerificationFailed),
    }
}

/// Search all available ESPs for dbx update files
///
/// Prefers authenticated (.auth) files over raw files.
/// Raw files are only accepted in Setup Mode.
pub fn find_dbx_file() -> Option<(Vec<u8>, DbxSource)> {
    // Try authenticated files first
    if let Some((data, source)) = search_all_disks_for_dbx(DBX_AUTH_PATHS) {
        return Some((data, DbxSource::Authenticated(source)));
    }

    // Try raw files only in Setup Mode
    if is_setup_mode() {
        if let Some((data, source)) = search_all_disks_for_dbx(DBX_RAW_PATHS) {
            log::warn!("Using raw dbx file in Setup Mode - this is less secure");
            return Some((data, DbxSource::Raw(source)));
        }
    } else {
        log::debug!("Not in Setup Mode - skipping raw dbx files (require signature)");
    }

    None
}

/// Search all disks for dbx files with the given paths
fn search_all_disks_for_dbx(paths: &[&str]) -> Option<(Vec<u8>, &'static str)> {
    super::search_all_disks(|disk, label| search_disk_for_dbx(disk, label, paths))
}

/// Search a disk for ESP partitions with dbx files
fn search_disk_for_dbx(
    disk: &mut dyn BlockDevice,
    source: &'static str,
    paths: &[&str],
) -> Option<(Vec<u8>, &'static str)> {
    // Read GPT
    let header = gpt::read_gpt_header(disk).ok()?;
    let partitions = gpt::read_partitions(disk, &header).ok()?;

    for partition in &partitions {
        if !partition.is_esp {
            continue;
        }

        // Try to mount as FAT
        let mut fat = match FatFilesystem::new(disk, partition.first_lba) {
            Ok(fs) => fs,
            Err(_) => continue,
        };

        // Search for dbx file
        if let Some(data) = try_load_dbx_file(&mut fat, paths) {
            return Some((data, source));
        }
    }

    None
}

/// Try to load a dbx file from any of the given paths
fn try_load_dbx_file(fat: &mut FatFilesystem<'_>, paths: &[&str]) -> Option<Vec<u8>> {
    for path in paths {
        if let Ok(size) = fat.file_size(path)
            && size > 0
            && size <= MAX_DBX_SIZE as u32
        {
            let mut buffer = alloc::vec![0u8; size as usize];
            if let Ok(bytes_read) = fat.read_file_all(path, &mut buffer)
                && bytes_read == size as usize
            {
                log::info!("Loaded dbx update file: {} ({} bytes)", path, bytes_read);
                return Some(buffer);
            }
        }
    }
    None
}

/// Load and enroll dbx entries from a file on the ESP
///
/// This searches all ESPs for a dbx update file and applies it to the
/// forbidden signature database.
///
/// # Security
///
/// - In User Mode: Only accepts authenticated (.auth) files signed by KEK or PK
/// - In Setup Mode: Accepts raw files without signature verification
/// - All updates are subject to anti-downgrade timestamp checking
///
/// # Returns
///
/// On success, returns the number of entries added to dbx.
pub fn enroll_dbx_from_file() -> Result<DbxEnrollmentResult, AuthError> {
    log::info!("Searching for dbx update file on ESP...");

    let (data, source) = find_dbx_file().ok_or_else(|| {
        log::warn!("No dbx update file found on any ESP");
        AuthError::NoSuitableKey
    })?;

    enroll_dbx_data(data, source)
}

/// Import exactly the bytes the graphical UI verified and previewed. Revalidate
/// at commit time too; never reopen a file after consent.
pub(crate) fn enroll_dbx_data(
    data: Vec<u8>,
    source: DbxSource,
) -> Result<DbxEnrollmentResult, AuthError> {
    let source_str = source.as_str();
    log::info!("Found dbx update ({} bytes) on {}", data.len(), source_str);

    let (result, append) = match source {
        DbxSource::Authenticated(src) => {
            let preview = inspect_authenticated_dbx_update(&data, src)?;
            (preview.entries, preview.append)
        }
        DbxSource::Raw(src) => {
            if !is_setup_mode() {
                log::error!("Raw dbx files require Setup Mode");
                return Err(AuthError::SignatureVerificationFailed);
            }
            let result = apply_raw_dbx_update(&data, src)?;
            // Setup Mode may omit a signature, but not authentication history.
            // Reuse firmware enrollment's strictly newer timestamped envelope,
            // including when dbx was previously deleted authentically.
            super::boot::persist_key_variable(
                crabefi_efi_types::secure_boot::SecureBootVariable::Dbx,
                &data,
            )?;
            super::boot::refresh_key_databases();
            return Ok(result);
        }
    };

    // Submit with exactly the attributes the signature binds: the runtime
    // hashes them into its own verification, and APPEND_WRITE selects
    // merge-instead-of-replace semantics for the signature lists.
    submit_dbx_update(&data, append, |attributes, bytes| {
        crate::efi::runtime_image::client::variables::set(
            &r_efi::efi::Guid::from_bytes(&EFI_IMAGE_SECURITY_DATABASE_GUID),
            DBX_NAME,
            attributes,
            bytes,
        )
    })?;
    super::boot::refresh_key_databases();

    log::info!(
        "dbx updated: {} SHA-256 hashes, {} certificates from {}",
        result.sha256_count,
        result.x509_count,
        result.source
    );

    Ok(result)
}

/// Single submission boundary, kept injectable so tests can assert the exact
/// attributes and owned bytes passed to Runtime Services, not just verification.
fn submit_dbx_update(
    data: &[u8],
    append: bool,
    set: impl FnOnce(u32, &[u8]) -> r_efi::efi::Status,
) -> Result<(), AuthError> {
    let status = set(dbx_attributes(append), data);
    if status == r_efi::efi::Status::SUCCESS {
        Ok(())
    } else {
        log::error!("Runtime Services rejected dbx update: {status:?}");
        Err(if status == r_efi::efi::Status::OUT_OF_RESOURCES {
            AuthError::BufferTooSmall
        } else {
            AuthError::AccessDenied
        })
    }
}

/// Attributes a dbx write is submitted (and was signed) with.
fn dbx_attributes(append: bool) -> u32 {
    super::attributes::SECURE_BOOT_ATTRS
        | if append {
            super::attributes::APPEND_WRITE
        } else {
            0
        }
}

fn inspect_authenticated_dbx_update(
    data: &[u8],
    source: &'static str,
) -> Result<DbxPreview, AuthError> {
    // Runtime authentication has a tighter envelope bound than ESP loading.
    if data.len() > 48 * 1024 {
        return Err(AuthError::InputTooLarge);
    }
    // Parse the EFI_VARIABLE_AUTHENTICATION_2 header
    let auth_header = EfiVariableAuthentication2::from_bytes(data).ok_or_else(|| {
        log::error!("Failed to parse EFI_VARIABLE_AUTHENTICATION_2 header");
        AuthError::InvalidHeader
    })?;

    // Verify the certificate type is PKCS#7
    if auth_header.auth_info.cert_type != EFI_CERT_TYPE_PKCS7_GUID
        || auth_header.auth_info.hdr.w_revision != super::WIN_CERT_REVISION
        || auth_header.auth_info.hdr.w_certificate_type != super::WIN_CERT_TYPE_EFI_GUID
    {
        log::error!("dbx update certificate type is not PKCS#7");
        return Err(AuthError::InvalidHeader);
    }

    // Input bounds are independent of free space: even an empty runtime
    // store cannot hold a larger variable. Reject before asking for consent.
    let sig_list_data = auth_header
        .variable_data(data)
        .ok_or(AuthError::InvalidHeader)?;
    validate_payload_size(sig_list_data)?;

    // Get the timestamp from the header
    let update_timestamp = auth_header.time_stamp;

    // Reject malformed timestamps before comparing: the nanosecond-precision
    // comparator would otherwise let out-of-range fields (seconds, nanoseconds,
    // timezone) sort after the current timestamp and defeat the anti-downgrade
    // check. Mirrors the runtime image's verify_authenticated_variable.
    if !update_timestamp.is_valid() {
        log::error!("dbx update timestamp is malformed");
        return Err(AuthError::InvalidTimestamp);
    }

    // Get the PKCS#7 signature data
    let pkcs7_data = auth_header.cert_data(data).ok_or_else(|| {
        log::error!("Failed to extract PKCS#7 data from dbx update");
        AuthError::InvalidHeader
    })?;

    // Verify signature against KEK or PK. The signed attributes are not
    // recorded in the envelope, so verification determines whether the
    // signer bound APPEND_WRITE (Microsoft's updates do) or a plain
    // replace; the write is then submitted with the matching attributes.
    let (signer_sha256, append) = verify_dbx_signer(pkcs7_data, &update_timestamp, sig_list_data)?
        .ok_or_else(|| {
            log::error!("dbx update signature verification failed");
            AuthError::SignatureVerificationFailed
        })?;

    log::info!("dbx update signature verified successfully");

    // Anti-downgrade check: a replacement must be newer than the current
    // dbx. An append is exempt, as in the runtime: it can only add
    // revocations, and Microsoft stamps every update it publishes 2010.
    // Unreadable history still refuses either kind.
    let replay_floor = super::boot::dbx_replay_floor()?;
    if !append && !update_timestamp.is_after(&replay_floor) {
        log::error!("dbx update timestamp is not newer than current (possible downgrade attack)");
        return Err(AuthError::InvalidTimestamp);
    }

    Ok(DbxPreview {
        entries: apply_signature_list_entries(sig_list_data, source)?,
        timestamp: Some(update_timestamp),
        signer_sha256: Some(signer_sha256),
        append,
    })
}

/// Apply a raw dbx update (Setup Mode only)
///
/// Raw updates don't have a signature, but we still check for a reasonable
/// format and update the timestamp.
fn apply_raw_dbx_update(
    data: &[u8],
    source: &'static str,
) -> Result<DbxEnrollmentResult, AuthError> {
    validate_payload_size(data)?;
    apply_signature_list_entries(data, source)
}

fn validate_payload_size(data: &[u8]) -> Result<(), AuthError> {
    if data.len() > crabefi_runtime_abi::MAX_VARIABLE_DATA_SIZE {
        Err(AuthError::InputTooLarge)
    } else {
        Ok(())
    }
}

/// Build the signed data blob for dbx variable authentication
///
/// Per UEFI spec, authenticated variables sign:
/// - VariableName (UCS-2, null-terminated)
/// - VendorGuid
/// - Attributes
/// - Timestamp
/// - Variable content
fn build_dbx_signed_data(timestamp: &EfiTime, content: &[u8], attributes: u32) -> Vec<u8> {
    let mut data = Vec::new();

    // Variable name "dbx" in UCS-2 (without null terminator for signing)
    data.extend_from_slice(&[0x64, 0x00, 0x62, 0x00, 0x78, 0x00]); // "dbx"

    // Vendor GUID
    data.extend_from_slice(&EFI_IMAGE_SECURITY_DATABASE_GUID);

    // Attributes (4 bytes, little-endian)
    data.extend_from_slice(&attributes.to_le_bytes());

    // Timestamp (16 bytes)
    // Copy the EfiTime fields directly
    data.extend_from_slice(&timestamp.year.to_le_bytes());
    data.push(timestamp.month);
    data.push(timestamp.day);
    data.push(timestamp.hour);
    data.push(timestamp.minute);
    data.push(timestamp.second);
    data.push(timestamp.pad1);
    data.extend_from_slice(&timestamp.nanosecond.to_le_bytes());
    data.extend_from_slice(&timestamp.timezone.to_le_bytes());
    data.push(timestamp.daylight);
    data.push(timestamp.pad2);

    // Variable content (signature lists)
    data.extend_from_slice(content);

    data
}

/// Verify the dbx update signature against KEK or PK, returning the signer
/// fingerprint and whether the signature binds APPEND_WRITE.
fn verify_dbx_signer(
    pkcs7_data: &[u8],
    timestamp: &EfiTime,
    content: &[u8],
) -> Result<Option<([u8; 32], bool)>, AuthError> {
    // Boot image verification supports larger RSA keys than authenticated
    // runtime variables. Do not ask for consent to a signer runtime cannot use.
    let signed =
        crabefi_pkcs7::cms::SignedData::parse(pkcs7_data).map_err(|_| AuthError::InvalidHeader)?;
    validate_cms_certificates(&signed)?;

    // Try to verify against KEK certificates, then PK.
    {
        let kek = kek_database();
        let trusted: Vec<&[u8]> = kek.x509_certificates().collect();
        if let Some(verified) = verify_signer_variants(pkcs7_data, timestamp, content, &trusted)? {
            log::info!("dbx update verified with KEK certificate");
            return Ok(Some(verified));
        }
    }
    {
        let pk = pk_database();
        let trusted: Vec<&[u8]> = pk.x509_certificates().collect();
        if let Some(verified) = verify_signer_variants(pkcs7_data, timestamp, content, &trusted)? {
            log::info!("dbx update verified with PK certificate");
            return Ok(Some(verified));
        }
    }

    log::warn!("dbx update signature did not verify against any KEK or PK certificate");
    Ok(None)
}

/// Try both attribute variants the signer could have bound (append first:
/// published revocation updates merge into dbx rather than replacing it).
/// The variant that verifies is the one the write must be submitted with,
/// because the runtime hashes the submitted attributes the same way.
fn verify_signer_variants(
    pkcs7_data: &[u8],
    timestamp: &EfiTime,
    content: &[u8],
    trusted: &[&[u8]],
) -> Result<Option<([u8; 32], bool)>, AuthError> {
    for append in [true, false] {
        let signed_data = build_dbx_signed_data(timestamp, content, dbx_attributes(append));
        if let Some(signer) =
            verify_with_trusted(pkcs7_data, &signed_data, trusted.iter().copied())?
        {
            return Ok(Some((signer, append)));
        }
    }
    Ok(None)
}

/// Every certificate embedded in the CMS blob must satisfy the runtime RSA
/// policy, matching the limits the runtime authenticated-variable verifier
/// enforces on the certificates it consumes (16 certificates, 16 KiB each,
/// SHA-256-with-RSA, at most 4096-bit keys; at most 8 signers).
fn validate_cms_certificates(signed: &crabefi_pkcs7::cms::SignedData) -> Result<(), AuthError> {
    // Match the runtime's detached CMS and digest policy before asking for
    // consent; the boot-image verifier deliberately has a different policy.
    validate_digest_algorithm(signed.digest_algorithms.inner()?)?;
    if signed.encapsulated_content.content_type != crabefi_pkcs7::oid::DATA
        || signed.encapsulated_content.content.is_some()
    {
        return Err(AuthError::InvalidHeader);
    }
    for signer in signed.signers() {
        let signer = signer?;
        validate_digest_algorithm(signer.digest_algorithm)?;
        if let Some(attributes) = signer.signed_attributes
            && attributes.content_type()? != crabefi_pkcs7::oid::DATA
        {
            return Err(AuthError::InvalidHeader);
        }
    }
    for (i, certificate) in signed.certificates().enumerate() {
        if i >= 16 || certificate.tag != crabefi_pkcs7::der::tag::SEQUENCE {
            return Err(AuthError::InvalidHeader);
        }
        validate_dbx_certificate(certificate.encoded)?;
    }
    if signed.signers().count() > 8 {
        return Err(AuthError::InvalidHeader);
    }
    Ok(())
}

fn validate_digest_algorithm(algorithm: crabefi_pkcs7::der::Tlv<'_>) -> Result<(), AuthError> {
    let algorithm = crabefi_pkcs7::x509::AlgorithmIdentifier::parse(algorithm)?;
    if !algorithm.is(crabefi_pkcs7::oid::SHA256) {
        return Err(AuthError::CryptoError);
    }
    Ok(())
}

/// Return the SHA-256 of the signing certificate if the CMS signature
/// verifies (through its embedded chain) against any trusted certificate.
fn verify_with_trusted<'a>(
    pkcs7_data: &[u8],
    signed_data: &[u8],
    trusted: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Option<[u8; 32]>, AuthError> {
    for cert_data in trusted {
        if validate_dbx_certificate(cert_data).is_err() {
            continue;
        }
        match verify_pkcs7_signature_chain(pkcs7_data, signed_data, cert_data, true) {
            Ok(Some(chain)) => return Ok(chain.end_entity().map(sha256)),
            Ok(None) => continue,
            Err(e) => {
                log::debug!("dbx verification error: {e:?}");
                continue;
            }
        }
    }
    Ok(None)
}

/// Match runtime authenticated-variable certificate limits, not the more
/// permissive boot-image RSA verifier (which also supports 8192-bit keys).
fn validate_dbx_certificate(der: &[u8]) -> Result<(), AuthError> {
    use crabefi_pkcs7::x509::{AlgorithmIdentifier, Certificate};
    if der.len() > 16 * 1024 {
        return Err(AuthError::InputTooLarge);
    }
    let cert = Certificate::parse(der).map_err(|_| AuthError::CertificateParseError)?;
    let algorithm = AlgorithmIdentifier::parse(cert.signature_algorithm)
        .map_err(|_| AuthError::CertificateParseError)?;
    if !algorithm.is(crabefi_pkcs7::oid::SHA256_WITH_RSA_ENCRYPTION) {
        return Err(AuthError::CryptoError);
    }
    let key = cert
        .rsa_public_key()
        .map_err(|_| AuthError::CertificateParseError)?;
    if !runtime_rsa_supported(key.modulus.len(), key.exponent()) {
        return Err(AuthError::CryptoError);
    }
    Ok(())
}

fn runtime_rsa_supported(bytes: usize, exponent: Option<u64>) -> bool {
    bytes <= 512 && exponent.is_some_and(|exponent| exponent <= u32::MAX as u64)
}

/// Apply signature list entries to the dbx database
fn apply_signature_list_entries(
    data: &[u8],
    source: &'static str,
) -> Result<DbxEnrollmentResult, AuthError> {
    if !validate_signature_database(data) {
        return Err(AuthError::InvalidHeader);
    }
    let mut sha256_count = 0usize;
    let mut x509_count = 0usize;

    // Convert GUIDs to bytes for comparison
    let sha256_guid = EFI_CERT_SHA256_GUID;
    let x509_guid = EFI_CERT_X509_GUID;

    // Parse signature lists without mutating the boot cache. The original
    // operation is committed through Runtime Services below; caches are then
    // refreshed from that authoritative result.
    for (list, list_data) in SignatureListIterator::new(data) {
        let signature_type = list.signature_type;
        for (_, signature_data) in SignatureIterator::new(list, list_data) {
            if signature_type == sha256_guid {
                if signature_data.len() != 32 {
                    return Err(AuthError::InvalidHeader);
                }
                sha256_count += 1;
            } else if signature_type == x509_guid {
                if signature_data.is_empty() {
                    return Err(AuthError::InvalidHeader);
                }
                x509_count += 1;
            }
        }
    }

    if sha256_count == 0 && x509_count == 0 {
        log::warn!("No valid entries found in dbx update");
        return Err(AuthError::InvalidHeader);
    }

    Ok(DbxEnrollmentResult {
        sha256_count,
        x509_count,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature_list() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&EFI_CERT_SHA256_GUID);
        data.extend_from_slice(&76u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&48u32.to_le_bytes());
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&[0xab; 32]);
        data
    }

    #[test]
    fn preview_rejects_a_valid_prefix_followed_by_malformed_data() {
        let mut data = signature_list();
        assert_eq!(apply_raw_dbx_update(&data, "test").unwrap().sha256_count, 1);
        data.push(0);
        assert!(matches!(
            apply_raw_dbx_update(&data, "test"),
            Err(AuthError::InvalidHeader)
        ));
        data.extend_from_slice(&signature_list());
        assert!(apply_raw_dbx_update(&data, "test").is_err());
    }

    /// Genuine Microsoft revocation update (amd64), from
    /// microsoft/secureboot_objects `PostSignedObjects/DBX/amd64/DBXUpdate.bin`
    /// (git blob f6ccec74a078267d56222b44d31ad30757ee8717;
    /// sha256 2089e3125e611376cb44326b5765674255443b2484f88de97251939d18055f68).
    /// If a future Microsoft signer fails the preflight policy while the
    /// runtime would accept it, this is the test that should turn red first.
    #[test]
    fn microsoft_dbxupdate_cms_policy_and_signature_verify() {
        let data = include_bytes!("testdata/microsoft_dbxupdate_x64.bin");
        assert!(data.len() <= 48 * 1024, "fits the runtime envelope bound");
        let header = EfiVariableAuthentication2::from_bytes(data).expect("auth header parses");
        assert!(header.time_stamp.is_valid());
        let pkcs7 = header.cert_data(data).expect("pkcs7 present");
        let sig_lists = header.variable_data(data).expect("signature lists present");
        assert_eq!(sig_lists.len(), 21_292);
        validate_payload_size(sig_lists).expect("fits the runtime variable limit");

        let entries =
            apply_signature_list_entries(sig_lists, "fixture").expect("signature lists parse");
        assert_eq!((entries.sha256_count, entries.x509_count), (443, 0));

        let signed = crabefi_pkcs7::cms::SignedData::parse(pkcs7).expect("CMS parses");
        validate_cms_certificates(&signed)
            .expect("embedded certificates pass the runtime RSA policy");
        let certs: Vec<&[u8]> = signed
            .certificates()
            .map(|certificate| certificate.encoded)
            .collect();
        // [0] Microsoft Windows UEFI Key Exchange Key (the signer),
        // [1] Microsoft Corporation KEK CA 2011 (its issuer, the enrolled KEK).
        assert_eq!(certs.len(), 2);

        // Microsoft binds APPEND_WRITE into the signature: the update merges
        // into dbx instead of replacing it, and only verifies as such.
        let (signer, append) =
            verify_signer_variants(pkcs7, &header.time_stamp, sig_lists, &[certs[1]])
                .expect("verification runs")
                .expect("verifies through the KEK CA chain");
        assert_eq!(signer, sha256(certs[0]));
        assert!(append, "Microsoft's update is signed for append writes");
        // Exercise the enrollment submission boundary with a recording setter.
        submit_dbx_update(data, append, |attributes, submitted| {
            assert_eq!(
                attributes,
                super::super::attributes::SECURE_BOOT_ATTRS
                    | super::super::attributes::APPEND_WRITE
            );
            assert_eq!(submitted, data);
            r_efi::efi::Status::SUCCESS
        })
        .unwrap();
        // The same signature must not verify as a plain replace write: the
        // variant is bound by the signature, not chosen by the importer.
        let replace_signed_data =
            build_dbx_signed_data(&header.time_stamp, sig_lists, dbx_attributes(false));
        assert_eq!(
            verify_with_trusted(pkcs7, &replace_signed_data, [certs[1]]).unwrap(),
            None
        );

        let unrelated = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../crabefi-pkcs7/testdata/ca.der"
        ));
        assert_eq!(
            verify_signer_variants(
                pkcs7,
                &header.time_stamp,
                sig_lists,
                &[unrelated.as_slice()]
            )
            .unwrap(),
            None,
            "must not verify against an unrelated trust anchor"
        );
    }

    #[test]
    fn replace_submission_and_storage_errors_are_not_confused_with_append_or_bad_signatures() {
        assert_eq!(
            submit_dbx_update(&[1, 2], false, |attributes, bytes| {
                assert_eq!(attributes, super::super::attributes::SECURE_BOOT_ATTRS);
                assert_eq!(bytes, [1, 2]);
                r_efi::efi::Status::OUT_OF_RESOURCES
            }),
            Err(AuthError::BufferTooSmall)
        );
        assert_eq!(
            submit_dbx_update(&[], true, |_, _| r_efi::efi::Status::ACCESS_DENIED),
            Err(AuthError::AccessDenied)
        );
    }

    #[test]
    fn preview_rejects_oversized_inputs_before_review() {
        let data = alloc::vec![0; crabefi_runtime_abi::MAX_VARIABLE_DATA_SIZE + 1];
        assert!(matches!(
            apply_raw_dbx_update(&data, "test"),
            Err(AuthError::InputTooLarge)
        ));
        assert!(matches!(
            inspect_authenticated_dbx_update(&alloc::vec![0; 48 * 1024 + 1], "test"),
            Err(AuthError::InputTooLarge)
        ));
        assert_eq!(
            validate_dbx_certificate(&alloc::vec![0; 16 * 1024 + 1]),
            Err(AuthError::InputTooLarge)
        );
    }

    #[test]
    fn cms_preflight_rejects_unsupported_digest_declarations() {
        let data = include_bytes!("testdata/microsoft_dbxupdate_x64.bin");
        let header = EfiVariableAuthentication2::from_bytes(data).unwrap();
        let cms = header.cert_data(data).unwrap();
        let signed = crabefi_pkcs7::cms::SignedData::parse(cms).unwrap();
        // Algorithm declarations are not themselves covered by the RSA
        // signature. Change each SHA-256 OID without changing the signature.
        for algorithm in [
            signed.digest_algorithms.inner().unwrap(),
            signed.signers().next().unwrap().unwrap().digest_algorithm,
        ] {
            let oid = algorithm
                .contents(crabefi_pkcs7::der::tag::SEQUENCE)
                .unwrap()
                .read()
                .unwrap();
            let last = oid.value.as_ptr() as usize - cms.as_ptr() as usize + oid.value.len() - 1;
            let mut changed = cms.to_vec();
            changed[last] ^= 1;
            let signed = crabefi_pkcs7::cms::SignedData::parse(&changed).unwrap();
            assert!(validate_cms_certificates(&signed).is_err());
        }
    }

    #[test]
    fn preview_matches_runtime_rsa_limits() {
        assert!(runtime_rsa_supported(256, Some(65537)));
        assert!(runtime_rsa_supported(512, Some(65537)));
        assert!(!runtime_rsa_supported(1024, Some(65537)));
        assert!(!runtime_rsa_supported(256, Some(1 << 32)));
        assert!(!runtime_rsa_supported(256, None));
        assert!(
            validate_dbx_certificate(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../crabefi-pkcs7/testdata/ca.der"
            )))
            .is_ok()
        );
    }
}
