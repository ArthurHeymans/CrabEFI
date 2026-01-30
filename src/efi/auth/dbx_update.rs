//! Microsoft dbx (Forbidden Signature Database) Updates
//!
//! This module provides functionality to load and apply Microsoft's UEFI
//! Forbidden Signature Database (dbx) updates. These updates contain revoked
//! signatures that should be blocked from booting.
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
//! - Raw EFI_SIGNATURE_LIST format (.bin)
//! - Files are searched at `EFI\keys\dbx.bin` or `EFI\updatedbx\dbx.bin`
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

use super::variables::{dbx_database, KeyDatabaseEntry};
use super::{AuthError, EFI_CERT_SHA256_GUID, EFI_CERT_X509_GUID};
use crate::drivers::block::{AhciDisk, BlockDevice, NvmeDisk, SdhciDisk};
use crate::fs::fat::FatFilesystem;
use crate::fs::gpt;
use alloc::vec::Vec;

/// Maximum dbx update file size (1MB should be plenty)
const MAX_DBX_SIZE: usize = 1024 * 1024;

/// Microsoft's vendor GUID for dbx entries
const MICROSOFT_OWNER_GUID: [u8; 16] = [
    0xbd, 0x9a, 0xfa, 0x77, 0x59, 0x03, 0x32, 0x4d, 0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b,
];

/// File paths to search for dbx updates
const DBX_PATHS: &[&str] = &[
    "EFI\\keys\\dbx.bin",
    "EFI\\keys\\DBX.bin",
    "EFI\\keys\\dbx.esl",
    "EFI\\keys\\DBX.esl",
    "EFI\\updatedbx\\dbx.bin",
    "EFI\\updatedbx\\DBX.bin",
    "EFI\\Microsoft\\Boot\\dbx.bin",
    "EFI\\MICROSOFT\\BOOT\\DBX.bin",
];

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
pub fn find_dbx_file() -> Option<(Vec<u8>, &'static str)> {
    // Try NVMe devices
    if let Some(result) = search_nvme_for_dbx() {
        return Some(result);
    }

    // Try AHCI devices
    if let Some(result) = search_ahci_for_dbx() {
        return Some(result);
    }

    // Try SDHCI devices
    if let Some(result) = search_sdhci_for_dbx() {
        return Some(result);
    }

    None
}

/// Search NVMe devices for dbx files
fn search_nvme_for_dbx() -> Option<(Vec<u8>, &'static str)> {
    use crate::drivers::nvme;

    if let Some(controller) = nvme::get_controller(0)
        && let Some(ns) = controller.default_namespace()
    {
        let nsid = ns.nsid;

        if let Some(controller) = nvme::get_controller(0) {
            let mut disk = NvmeDisk::new(controller, nsid);

            if let Some(result) = search_disk_for_dbx(&mut disk, "NVMe") {
                return Some(result);
            }
        }
    }

    None
}

/// Search AHCI devices for dbx files
fn search_ahci_for_dbx() -> Option<(Vec<u8>, &'static str)> {
    use crate::drivers::ahci;

    if let Some(controller) = ahci::get_controller(0) {
        let num_ports = controller.num_active_ports();

        for port_index in 0..num_ports {
            if let Some(controller) = ahci::get_controller(0) {
                let mut disk = AhciDisk::new(controller, port_index);

                if let Some(result) = search_disk_for_dbx(&mut disk, "SATA") {
                    return Some(result);
                }
            }
        }
    }

    None
}

/// Search SDHCI devices for dbx files
fn search_sdhci_for_dbx() -> Option<(Vec<u8>, &'static str)> {
    use crate::drivers::sdhci;

    for controller_id in 0..sdhci::controller_count() {
        if let Some(controller) = sdhci::get_controller(controller_id) {
            if !controller.is_ready() {
                continue;
            }

            if let Some(controller) = sdhci::get_controller(controller_id) {
                let mut disk = SdhciDisk::new(controller);

                if let Some(result) = search_disk_for_dbx(&mut disk, "SD") {
                    return Some(result);
                }
            }
        }
    }

    None
}

/// Search a disk for ESP partitions with dbx files
fn search_disk_for_dbx(disk: &mut dyn BlockDevice, source: &'static str) -> Option<(Vec<u8>, &'static str)> {
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
        if let Some(data) = try_load_dbx_file(&mut fat) {
            return Some((data, source));
        }
    }

    None
}

/// Try to load a dbx file from any of the known paths
fn try_load_dbx_file(fat: &mut FatFilesystem<'_>) -> Option<Vec<u8>> {
    for path in DBX_PATHS {
        if let Ok(size) = fat.file_size(path) {
            if size > 0 && size <= MAX_DBX_SIZE as u32 {
                let mut buffer = alloc::vec![0u8; size as usize];
                if let Ok(bytes_read) = fat.read_file_all(path, &mut buffer) {
                    if bytes_read == size as usize {
                        log::info!("Loaded dbx update file: {} ({} bytes)", path, bytes_read);
                        return Some(buffer);
                    }
                }
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
/// # Returns
///
/// On success, returns the number of entries added to dbx.
pub fn enroll_dbx_from_file() -> Result<DbxEnrollmentResult, AuthError> {
    log::info!("Searching for dbx update file on ESP...");

    let (data, source) = find_dbx_file().ok_or_else(|| {
        log::warn!("No dbx update file found on any ESP");
        AuthError::NoSuitableKey
    })?;

    log::info!("Found dbx update ({} bytes) on {}", data.len(), source);

    // Parse and apply the dbx update
    let result = apply_dbx_update(&data, source)?;

    // Persist the updated dbx
    super::boot::persist_key_databases()?;

    log::info!(
        "dbx updated: {} SHA-256 hashes, {} certificates from {}",
        result.sha256_count,
        result.x509_count,
        source
    );

    Ok(result)
}

/// Apply a dbx update from raw signature list data
///
/// The data should be in EFI_SIGNATURE_LIST format (one or more lists).
pub fn apply_dbx_update(data: &[u8], source: &'static str) -> Result<DbxEnrollmentResult, AuthError> {
    use super::structures::{SignatureIterator, SignatureListIterator};

    let mut sha256_count = 0usize;
    let mut x509_count = 0usize;

    // Convert GUIDs to bytes for comparison
    let sha256_guid = guid_to_bytes(&EFI_CERT_SHA256_GUID);
    let x509_guid = guid_to_bytes(&EFI_CERT_X509_GUID);

    let mut dbx = dbx_database();

    // Parse signature lists
    for (list, list_data) in SignatureListIterator::new(data) {
        let sig_type = list.signature_type;

        for (owner, sig_data) in SignatureIterator::new(list, list_data) {
            // Determine the signature type
            let (entry_type, data_slice) = if sig_type == sha256_guid {
                // SHA-256 hash entry (32 bytes)
                if sig_data.len() >= 32 {
                    sha256_count += 1;
                    (sha256_guid, &sig_data[..32])
                } else {
                    log::warn!("Skipping short SHA-256 entry ({} bytes)", sig_data.len());
                    continue;
                }
            } else if sig_type == x509_guid {
                // X.509 certificate
                x509_count += 1;
                (x509_guid, sig_data)
            } else {
                // Unknown type - use as-is with the original type
                log::debug!("Unknown dbx signature type: {:02x?}", sig_type);
                (sig_type, sig_data)
            };

            // Check if this entry already exists
            if entry_exists_in_dbx(&dbx, &entry_type, data_slice) {
                log::debug!("Skipping duplicate dbx entry");
                continue;
            }

            // Add the entry
            let entry = KeyDatabaseEntry {
                cert_type: entry_type,
                data: data_slice.to_vec(),
                owner,
            };

            if let Err(e) = dbx.add_entry(entry) {
                log::warn!("Failed to add dbx entry: {:?}", e);
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

/// Check if an entry already exists in the dbx database
fn entry_exists_in_dbx(dbx: &spin::MutexGuard<'_, super::variables::KeyDatabase>, cert_type: &[u8; 16], data: &[u8]) -> bool {
    let sha256_guid = guid_to_bytes(&EFI_CERT_SHA256_GUID);
    let x509_guid = guid_to_bytes(&EFI_CERT_X509_GUID);

    if *cert_type == sha256_guid {
        // Check for SHA-256 hash
        if data.len() >= 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[..32]);
            return dbx.contains_sha256_hash(&hash);
        }
    } else if *cert_type == x509_guid {
        // Check for X.509 certificate
        return dbx.find_x509_certificate(data).is_some();
    }

    false
}

/// Convert a GUID to bytes
fn guid_to_bytes(guid: &r_efi::efi::Guid) -> [u8; 16] {
    let bytes = guid.as_bytes();
    let mut result = [0u8; 16];
    result.copy_from_slice(bytes);
    result
}

/// Check if a dbx update file is available on any ESP
pub fn dbx_update_available() -> bool {
    find_dbx_file().is_some()
}

/// Get information about available dbx updates without applying them
pub fn check_dbx_update() -> Option<DbxUpdateInfo> {
    let (data, source) = find_dbx_file()?;

    // Parse to count entries without applying
    use super::structures::{SignatureIterator, SignatureListIterator};

    let sha256_guid = guid_to_bytes(&EFI_CERT_SHA256_GUID);
    let x509_guid = guid_to_bytes(&EFI_CERT_X509_GUID);

    let mut sha256_count = 0usize;
    let mut x509_count = 0usize;

    for (list, list_data) in SignatureListIterator::new(&data) {
        let sig_type = list.signature_type;

        for (_owner, sig_data) in SignatureIterator::new(list, list_data) {
            if sig_type == sha256_guid && sig_data.len() >= 32 {
                sha256_count += 1;
            } else if sig_type == x509_guid {
                x509_count += 1;
            }
        }
    }

    Some(DbxUpdateInfo {
        file_size: data.len(),
        sha256_count,
        x509_count,
        source,
    })
}

/// Information about an available dbx update
#[derive(Debug, Clone)]
pub struct DbxUpdateInfo {
    /// Size of the dbx file in bytes
    pub file_size: usize,
    /// Number of SHA-256 hash entries
    pub sha256_count: usize,
    /// Number of X.509 certificate entries
    pub x509_count: usize,
    /// Source where the file was found
    pub source: &'static str,
}
