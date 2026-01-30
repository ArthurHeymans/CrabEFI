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
use super::{enter_user_mode, AuthError};
use crate::drivers::block::{AhciDisk, BlockDevice, NvmeDisk, SdhciDisk};
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
    // Try NVMe devices
    if let Some(result) = search_nvme_devices() {
        return Some(result);
    }

    // Try AHCI devices
    if let Some(result) = search_ahci_devices() {
        return Some(result);
    }

    // Try SDHCI devices
    if let Some(result) = search_sdhci_devices() {
        return Some(result);
    }

    None
}

/// Search NVMe devices for key files
fn search_nvme_devices() -> Option<KeyFileSearchResult> {
    use crate::drivers::nvme;

    if let Some(controller) = nvme::get_controller(0)
        && let Some(ns) = controller.default_namespace()
    {
        let nsid = ns.nsid;
        
        if let Some(controller) = nvme::get_controller(0) {
            let mut disk = NvmeDisk::new(controller, nsid);
            
            if let Some(result) = search_disk_for_keys(&mut disk, "NVMe") {
                return Some(result);
            }
        }
    }

    None
}

/// Search AHCI devices for key files
fn search_ahci_devices() -> Option<KeyFileSearchResult> {
    use crate::drivers::ahci;

    if let Some(controller) = ahci::get_controller(0) {
        let num_ports = controller.num_active_ports();

        for port_index in 0..num_ports {
            if let Some(controller) = ahci::get_controller(0) {
                let mut disk = AhciDisk::new(controller, port_index);
                
                if let Some(result) = search_disk_for_keys(&mut disk, "SATA") {
                    return Some(result);
                }
            }
        }
    }

    None
}

/// Search SDHCI devices for key files
fn search_sdhci_devices() -> Option<KeyFileSearchResult> {
    use crate::drivers::sdhci;

    for controller_id in 0..sdhci::controller_count() {
        if let Some(controller) = sdhci::get_controller(controller_id) {
            if !controller.is_ready() {
                continue;
            }

            if let Some(controller) = sdhci::get_controller(controller_id) {
                let mut disk = SdhciDisk::new(controller);
                
                if let Some(result) = search_disk_for_keys(&mut disk, "SD") {
                    return Some(result);
                }
            }
        }
    }

    None
}

/// Search a disk for ESP partitions with key files
fn search_disk_for_keys(disk: &mut dyn BlockDevice, source: &'static str) -> Option<KeyFileSearchResult> {
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
        if let Ok(size) = fat.file_size(path) {
            if size > 0 && size <= MAX_CERT_SIZE as u32 {
                let mut buffer = alloc::vec![0u8; size as usize];
                if let Ok(bytes_read) = fat.read_file_all(path, &mut buffer) {
                    if bytes_read == size as usize {
                        log::info!("Loaded key file: {} ({} bytes)", path, bytes_read);
                        return Some(buffer);
                    }
                }
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

    let pk_data = result.pk.ok_or_else(|| {
        log::warn!("No PK certificate found (looked for EFI\\keys\\PK.cer)");
        AuthError::NoSuitableKey
    })?;

    log::info!("Found PK certificate ({} bytes) on {}", pk_data.len(), result.source);

    // Validate it's a valid X.509 certificate
    validate_certificate(&pk_data)?;

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

    log::info!("Custom PK enrolled successfully from {}", result.source);
    Ok(result.source)
}

/// Validate that data is a valid X.509 certificate
fn validate_certificate(data: &[u8]) -> Result<(), AuthError> {
    // Basic check: X.509 certificates start with SEQUENCE tag (0x30)
    if data.is_empty() || data[0] != 0x30 {
        log::error!("Invalid certificate format: not a DER-encoded X.509");
        return Err(AuthError::CertificateParseError);
    }

    // Try to parse with the crypto module
    match super::crypto::parse_x509_certificate(data) {
        Ok(_cert) => {
            log::debug!("Certificate validated successfully");
            Ok(())
        }
        Err(e) => {
            log::error!("Certificate validation failed: {:?}", e);
            Err(AuthError::CertificateParseError)
        }
    }
}

/// Check if any key files exist on the ESP
pub fn key_files_available() -> bool {
    find_key_files().map(|r| r.pk.is_some()).unwrap_or(false)
}
