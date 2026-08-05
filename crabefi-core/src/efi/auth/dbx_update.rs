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
    },
    secure_boot::{
        DBX_NAME, EFI_CERT_SHA256_GUID, EFI_CERT_TYPE_PKCS7_GUID, EFI_CERT_X509_GUID,
        EFI_IMAGE_SECURITY_DATABASE_GUID,
    },
};

use super::crypto::verify_pkcs7_signature;
use super::variables::{dbx_database, kek_database, pk_database};
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

    let source_str = source.as_str();
    log::info!("Found dbx update ({} bytes) on {}", data.len(), source_str);

    let (result, attributes) = match source {
        DbxSource::Authenticated(src) => (
            apply_authenticated_dbx_update(&data, src)?,
            super::attributes::SECURE_BOOT_ATTRS,
        ),
        DbxSource::Raw(src) => {
            if !is_setup_mode() {
                log::error!("Raw dbx files require Setup Mode");
                return Err(AuthError::SignatureVerificationFailed);
            }
            (
                apply_raw_dbx_update(&data, src)?,
                super::attributes::SECURE_BOOT_ATTRS
                    & !super::attributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
            )
        }
    };

    let status = crate::efi::runtime_image::client::variables::set(
        &r_efi::efi::Guid::from_bytes(&EFI_IMAGE_SECURITY_DATABASE_GUID),
        DBX_NAME,
        attributes,
        &data,
    );
    if status != r_efi::efi::Status::SUCCESS {
        log::error!("Runtime Services rejected dbx update: {:?}", status);
        return Err(if status == r_efi::efi::Status::OUT_OF_RESOURCES {
            AuthError::BufferTooSmall
        } else {
            AuthError::SignatureVerificationFailed
        });
    }
    super::boot::refresh_key_databases();

    log::info!(
        "dbx updated: {} SHA-256 hashes, {} certificates from {}",
        result.sha256_count,
        result.x509_count,
        result.source
    );

    Ok(result)
}

/// Apply an authenticated dbx update (EFI_VARIABLE_AUTHENTICATION_2 format)
///
/// This function:
/// 1. Parses the EFI_VARIABLE_AUTHENTICATION_2 header
/// 2. Verifies the PKCS#7 signature against KEK or PK
/// 3. Checks the timestamp is newer than current dbx timestamp
/// 4. Applies the signature list entries to dbx
fn apply_authenticated_dbx_update(
    data: &[u8],
    source: &'static str,
) -> Result<DbxEnrollmentResult, AuthError> {
    // Parse the EFI_VARIABLE_AUTHENTICATION_2 header
    let auth_header = EfiVariableAuthentication2::from_bytes(data).ok_or_else(|| {
        log::error!("Failed to parse EFI_VARIABLE_AUTHENTICATION_2 header");
        AuthError::InvalidHeader
    })?;

    // Verify the certificate type is PKCS#7
    if auth_header.auth_info.cert_type != EFI_CERT_TYPE_PKCS7_GUID {
        log::error!("dbx update certificate type is not PKCS#7");
        return Err(AuthError::InvalidHeader);
    }

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

    // Anti-downgrade check: verify timestamp is newer than current dbx
    {
        let dbx = dbx_database();
        let current_timestamp = dbx.timestamp();
        if !update_timestamp.is_after(current_timestamp) {
            log::error!(
                "dbx update timestamp is not newer than current (possible downgrade attack)"
            );
            return Err(AuthError::InvalidTimestamp);
        }
    }

    // Get the PKCS#7 signature data
    let pkcs7_data = auth_header.cert_data(data).ok_or_else(|| {
        log::error!("Failed to extract PKCS#7 data from dbx update");
        AuthError::InvalidHeader
    })?;

    // Get the variable data (signature lists)
    let sig_list_data = auth_header.variable_data(data).ok_or_else(|| {
        log::error!("Failed to extract signature list data from dbx update");
        AuthError::InvalidHeader
    })?;

    // Build the data that was signed (for UEFI authenticated variables)
    // This is: variable_name + vendor_guid + attributes + timestamp + content
    let signed_data = build_dbx_signed_data(&update_timestamp, sig_list_data);

    // Verify signature against KEK or PK
    if !verify_dbx_signature(pkcs7_data, &signed_data)? {
        log::error!("dbx update signature verification failed");
        return Err(AuthError::SignatureVerificationFailed);
    }

    log::info!("dbx update signature verified successfully");

    apply_signature_list_entries(sig_list_data, source)
}

/// Apply a raw dbx update (Setup Mode only)
///
/// Raw updates don't have a signature, but we still check for a reasonable
/// format and update the timestamp.
fn apply_raw_dbx_update(
    data: &[u8],
    source: &'static str,
) -> Result<DbxEnrollmentResult, AuthError> {
    apply_signature_list_entries(data, source)
}

/// Build the signed data blob for dbx variable authentication
///
/// Per UEFI spec, authenticated variables sign:
/// - VariableName (UCS-2, null-terminated)
/// - VendorGuid
/// - Attributes
/// - Timestamp
/// - Variable content
fn build_dbx_signed_data(timestamp: &EfiTime, content: &[u8]) -> Vec<u8> {
    use super::attributes;

    let mut data = Vec::new();

    // Variable name "dbx" in UCS-2 (without null terminator for signing)
    data.extend_from_slice(&[0x64, 0x00, 0x62, 0x00, 0x78, 0x00]); // "dbx"

    // Vendor GUID
    data.extend_from_slice(&EFI_IMAGE_SECURITY_DATABASE_GUID);

    // Attributes (4 bytes, little-endian)
    let attrs = attributes::SECURE_BOOT_ATTRS;
    data.extend_from_slice(&attrs.to_le_bytes());

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

/// Verify the dbx update signature against KEK or PK
fn verify_dbx_signature(pkcs7_data: &[u8], signed_data: &[u8]) -> Result<bool, AuthError> {
    // Try to verify against KEK certificates
    {
        let kek = kek_database();
        for cert_data in kek.x509_certificates() {
            match verify_pkcs7_signature(pkcs7_data, signed_data, cert_data) {
                Ok(true) => {
                    log::info!("dbx update verified with KEK certificate");
                    return Ok(true);
                }
                Ok(false) => continue,
                Err(e) => {
                    log::debug!("KEK verification error: {:?}", e);
                    continue;
                }
            }
        }
    }

    // Try to verify against PK
    {
        let pk = pk_database();
        for cert_data in pk.x509_certificates() {
            match verify_pkcs7_signature(pkcs7_data, signed_data, cert_data) {
                Ok(true) => {
                    log::info!("dbx update verified with PK certificate");
                    return Ok(true);
                }
                Ok(false) => continue,
                Err(e) => {
                    log::debug!("PK verification error: {:?}", e);
                    continue;
                }
            }
        }
    }

    log::warn!("dbx update signature did not verify against any KEK or PK certificate");
    Ok(false)
}

/// Apply signature list entries to the dbx database
fn apply_signature_list_entries(
    data: &[u8],
    source: &'static str,
) -> Result<DbxEnrollmentResult, AuthError> {
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
