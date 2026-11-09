//! Secure Boot Key File Loading
//!
//! This module provides functionality to load Secure Boot keys from files
//! on the EFI System Partition (ESP). This allows users to enroll their own
//! Platform Key, KEK, or db certificates.
//!
//! # Supported File Locations
//!
//! Keys are searched for in the following locations:
//! - `EFI\keys\PK.cer` or `EFI\keys\PK.der` - Platform Key
//! - `EFI\keys\KEK.cer` or `EFI\keys\KEK.der` - Key Exchange Key
//! - `EFI\keys\db.cer` or `EFI\keys\db.der` - Signature Database
//!
//! # File Formats
//!
//! - `.cer` or `.der` - DER-encoded X.509 certificate

use super::enrollment::{self, CRABEFI_OWNER_GUID};
use super::{AuthError, enter_user_mode};
use crate::drivers::block::BlockDevice;
use crate::fs::fat::FatFilesystem;
use crate::fs::gpt;
use alloc::vec::Vec;

/// Maximum certificate file size (64KB should be plenty)
const MAX_CERT_SIZE: usize = 64 * 1024;

/// Owner GUID for user-enrolled keys
const USER_OWNER_GUID: [u8; 16] = CRABEFI_OWNER_GUID;

/// Key file paths to search for PK
const PK_PATHS: &[&str] = &[
    "EFI\\keys\\PK.cer",
    "EFI\\keys\\PK.der",
    "EFI\\keys\\pk.cer",
    "EFI\\keys\\pk.der",
    "EFI\\KEYS\\PK.CER",
    "EFI\\KEYS\\PK.DER",
];

/// Key file paths to search for KEK
const KEK_PATHS: &[&str] = &[
    "EFI\\keys\\KEK.cer",
    "EFI\\keys\\KEK.der",
    "EFI\\keys\\kek.cer",
    "EFI\\keys\\kek.der",
];

/// Key file paths to search for db
const DB_PATHS: &[&str] = &[
    "EFI\\keys\\db.cer",
    "EFI\\keys\\db.der",
    "EFI\\keys\\DB.cer",
    "EFI\\keys\\DB.der",
];

/// Result of searching for key files
pub struct KeyFileSearchResult {
    /// PK certificate data if found
    pub pk: Option<Vec<u8>>,
    /// KEK certificate data if found  
    pub kek: Option<Vec<u8>>,
    /// db certificate data if found
    pub db: Option<Vec<u8>>,
    /// Description of where keys were found
    pub source: &'static str,
}

/// Search all available ESPs for key files
pub fn find_key_files() -> Option<KeyFileSearchResult> {
    super::search_all_disks(|disk, label| search_disk_for_keys(disk, label))
}

/// Search a disk for ESP partitions with key files
fn search_disk_for_keys(
    disk: &mut dyn BlockDevice,
    source: &'static str,
) -> Option<KeyFileSearchResult> {
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

        // Search for key files
        let pk = try_load_file(&mut fat, PK_PATHS);
        let kek = try_load_file(&mut fat, KEK_PATHS);
        let db = try_load_file(&mut fat, DB_PATHS);

        // Return if we found at least one key
        if pk.is_some() || kek.is_some() || db.is_some() {
            return Some(KeyFileSearchResult {
                pk,
                kek,
                db,
                source,
            });
        }
    }

    None
}

/// Try to load a file from any of the given paths
fn try_load_file(fat: &mut FatFilesystem<'_>, paths: &[&str]) -> Option<Vec<u8>> {
    for path in paths {
        if let Ok(size) = fat.file_size(path)
            && size > 0
            && size <= MAX_CERT_SIZE as u32
        {
            let mut buffer = alloc::vec![0u8; size as usize];
            if let Ok(bytes_read) = fat.read_file_all(path, &mut buffer)
                && bytes_read == size as usize
            {
                log::info!("Loaded key file: {} ({} bytes)", path, bytes_read);
                return Some(buffer);
            }
        }
    }
    None
}

/// Load and enroll a custom PK from file
///
/// This searches all ESPs for a PK certificate and enrolls it.
/// Also enrolls Microsoft db certificates for compatibility with shim/GRUB.
pub fn enroll_pk_from_file() -> Result<&'static str, AuthError> {
    log::info!("Searching for custom PK certificate on ESP...");

    let result = find_key_files().ok_or_else(|| {
        log::warn!("No key files found on any ESP");
        AuthError::NoSuitableKey
    })?;

    enroll_key_files(result)
}

/// Validate every supplied certificate before changing any enrolled key cache.
/// The graphical caller also uses this before showing trust identities.
pub(crate) fn validate_key_files(result: &KeyFileSearchResult) -> Result<(), AuthError> {
    validate_certificate(result.pk.as_deref().ok_or(AuthError::NoSuitableKey)?)?;
    if let Some(kek) = &result.kek {
        validate_certificate(kek)?;
    }
    if let Some(db) = &result.db {
        validate_certificate(db)?;
    }
    Ok(())
}

/// Enroll exactly the owned bytes previewed by the user, without reopening ESP files.
pub(crate) fn enroll_key_files(result: KeyFileSearchResult) -> Result<&'static str, AuthError> {
    if !super::is_setup_mode() {
        return Err(AuthError::AccessDenied);
    }
    validate_key_files(&result)?;
    let pk_data = result.pk.ok_or_else(|| {
        log::warn!("No PK certificate found (looked for EFI\\keys\\PK.cer)");
        AuthError::NoSuitableKey
    })?;

    log::info!(
        "Found PK certificate ({} bytes) on {}",
        pk_data.len(),
        result.source
    );

    // Snapshot the durable databases so a failure after some writes landed
    // can be reported as the partial enrollment it is, not as "nothing
    // happened". The caches currently mirror the store.
    let stored_before = key_database_bytes();

    // Always reconcile disposable drafts with the authoritative store, including
    // after a partial enrollment or an allocation/persistence failure.
    let enrollment = (|| {
        // All supplied certificates were validated before any cache mutation.
        // Clear existing keys first
        {
            let mut pk_db = super::variables::pk_database();
            pk_db.clear();
        }
        {
            let mut kek_db = super::variables::kek_database();
            kek_db.clear();
        }
        {
            let mut db_db = super::variables::db_database();
            db_db.clear();
        }

        // Enroll Microsoft db certificates for shim/GRUB compatibility
        enrollment::enroll_microsoft_uefi_ca_db()?;
        log::info!("Enrolled Microsoft UEFI CA for shim/GRUB compatibility");

        // Enroll custom KEK if found, otherwise use the custom PK as KEK too
        if let Some(kek_data) = result.kek {
            log::info!("Found custom KEK certificate ({} bytes)", kek_data.len());
            enrollment::enroll_kek(&kek_data, &USER_OWNER_GUID)?;
        } else {
            // Use the PK as KEK (common for self-managed systems)
            enrollment::enroll_kek(&pk_data, &USER_OWNER_GUID)?;
            log::info!("Using custom PK as KEK");
        }

        // Enroll custom db certificate if found
        if let Some(db_data) = result.db {
            log::info!("Found custom db certificate ({} bytes)", db_data.len());
            enrollment::enroll_db_certificate(&db_data, &USER_OWNER_GUID)?;
        }

        // Enroll the custom PK
        enrollment::enroll_pk(&pk_data, &USER_OWNER_GUID)?;

        // Enter User Mode
        enter_user_mode();

        // Persist all key databases
        super::boot::persist_key_databases()?;
        super::boot::update_status_variables()?;
        Ok::<(), AuthError>(())
    })();
    super::boot::force_refresh_key_databases();
    if let Err(error) = enrollment {
        let changed = changed_databases(&stored_before, &key_database_bytes());
        if changed.is_empty() {
            return Err(error);
        }
        log::error!(
            "Enrollment failed after durable changes to {}; stored keys match neither the previous nor the reviewed set",
            changed.join(", ")
        );
        return Err(AuthError::PartialEnrollment);
    }

    log::info!("Custom PK enrolled successfully from {}", result.source);
    Ok(result.source)
}

/// Serialized (PK, KEK, db) signature lists as currently cached from the store.
fn key_database_bytes() -> [alloc::vec::Vec<u8>; 3] {
    [
        super::variables::pk_database().to_signature_lists(),
        super::variables::kek_database().to_signature_lists(),
        super::variables::db_database().to_signature_lists(),
    ]
}

fn changed_databases(
    before: &[alloc::vec::Vec<u8>; 3],
    after: &[alloc::vec::Vec<u8>; 3],
) -> alloc::vec::Vec<&'static str> {
    ["PK", "KEK", "db"]
        .into_iter()
        .zip(before.iter().zip(after))
        .filter(|(_, (before, after))| before != after)
        .map(|(name, _)| name)
        .collect()
}

/// Validate that data is a valid X.509 certificate
fn validate_certificate(data: &[u8]) -> Result<(), AuthError> {
    // Basic check: X.509 certificates start with SEQUENCE tag (0x30)
    if data.is_empty() || data[0] != 0x30 {
        log::error!("Invalid certificate format: not a DER-encoded X.509");
        return Err(AuthError::CertificateParseError);
    }

    // Try to parse with the crypto module
    match super::crypto::validate_x509_certificate(data) {
        Ok(()) => {
            log::debug!("Certificate validated successfully");
            Ok(())
        }
        Err(e) => {
            log::error!("Certificate validation failed: {:?}", e);
            Err(AuthError::CertificateParseError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_all_previewed_certificates_before_enrollment() {
        let cert = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../crabefi-pkcs7/testdata/ca.der"
        ));
        let mut files = KeyFileSearchResult {
            pk: Some(cert.to_vec()),
            kek: None,
            db: None,
            source: "test",
        };
        assert!(validate_key_files(&files).is_ok());
        files.kek = Some(alloc::vec![0, 1, 2]);
        assert!(matches!(
            validate_key_files(&files),
            Err(AuthError::CertificateParseError)
        ));
        files.kek = Some(cert.to_vec());
        files.db = Some(alloc::vec![0]);
        assert!(matches!(
            validate_key_files(&files),
            Err(AuthError::CertificateParseError)
        ));
        files.db = Some(cert.to_vec());
        assert!(validate_key_files(&files).is_ok());
        files.pk = None;
        assert!(matches!(
            validate_key_files(&files),
            Err(AuthError::NoSuitableKey)
        ));
    }

    #[test]
    fn changed_databases_reports_only_databases_that_differ() {
        let before = [alloc::vec![1], alloc::vec![2], alloc::vec![3]];
        assert!(changed_databases(&before, &before.clone()).is_empty());
        let after = [alloc::vec![1], alloc::vec![9], alloc::vec![8]];
        assert_eq!(changed_databases(&before, &after), ["KEK", "db"]);
    }
}
