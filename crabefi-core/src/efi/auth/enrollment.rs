//! Secure Boot Key Enrollment
//!
//! This module provides functions for enrolling Secure Boot keys,
//! including default Microsoft certificates for Windows and third-party
//! UEFI drivers.
//!
//! # Default Keys
//!
//! The Microsoft default keys include:
//! - **Microsoft Corporation KEK CA 2011**: Used in the KEK database
//! - **Microsoft Windows Production PCA 2011**: Used in db for Windows boot
//! - **Microsoft Corporation UEFI CA 2011**: Used in db for third-party drivers
//!
//! # Usage
//!
//! ```rust,ignore
//! use crab_efi::efi::auth::enrollment;
//!
//! // Enroll all default Microsoft keys (enters User Mode)
//! enrollment::enroll_default_keys()?;
//!
//! // Or enroll individually in Setup Mode
//! enrollment::enroll_microsoft_kek()?;
//! enrollment::enroll_microsoft_windows_production_db()?;
//! enrollment::enroll_microsoft_uefi_ca_db()?;
//! enrollment::enroll_default_pk()?;
//! ```

use super::variables::{KeyDatabase, KeyDatabaseEntry, db_database, kek_database, pk_database};
use crabefi_efi_types::secure_boot::EFI_CERT_X509_GUID;

use super::{AuthError, enter_user_mode};

pub use crabefi_efi_types::secure_boot::defaults::CRABEFI_OWNER_GUID;
use crabefi_efi_types::secure_boot::defaults::{
    MICROSOFT_KEK_CA_2011, MICROSOFT_OWNER_GUID, MICROSOFT_UEFI_CA_2011,
    MICROSOFT_WINDOWS_PRODUCTION_PCA_2011,
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert EFI_CERT_X509_GUID to raw bytes
fn x509_cert_type() -> [u8; 16] {
    EFI_CERT_X509_GUID
}

/// Add a certificate entry to a key database
fn add_certificate_entry(
    db: &mut KeyDatabase,
    cert_data: &[u8],
    owner: &[u8; 16],
) -> Result<(), AuthError> {
    let entry = KeyDatabaseEntry {
        cert_type: x509_cert_type(),
        data: cert_data.to_vec(),
        owner: *owner,
    };
    db.add_entry(entry)
}

// ============================================================================
// Individual Key Enrollment Functions
// ============================================================================

/// Enroll Microsoft Corporation KEK CA 2011 into the KEK database
///
/// This certificate is required for Microsoft to authorize changes to db/dbx.
pub fn enroll_microsoft_kek() -> Result<(), AuthError> {
    log::info!("Enrolling Microsoft Corporation KEK CA 2011");
    let mut db = kek_database();
    add_certificate_entry(&mut db, MICROSOFT_KEK_CA_2011, &MICROSOFT_OWNER_GUID)?;
    log::info!(
        "Microsoft KEK CA 2011 enrolled ({} bytes)",
        MICROSOFT_KEK_CA_2011.len()
    );
    Ok(())
}

/// Enroll Microsoft Windows Production PCA 2011 into the db database
///
/// This certificate is required for booting Windows.
pub fn enroll_microsoft_windows_production_db() -> Result<(), AuthError> {
    log::info!("Enrolling Microsoft Windows Production PCA 2011");
    let mut db = db_database();
    add_certificate_entry(
        &mut db,
        MICROSOFT_WINDOWS_PRODUCTION_PCA_2011,
        &MICROSOFT_OWNER_GUID,
    )?;
    log::info!(
        "Microsoft Windows Production PCA 2011 enrolled ({} bytes)",
        MICROSOFT_WINDOWS_PRODUCTION_PCA_2011.len()
    );
    Ok(())
}

/// Enroll Microsoft Corporation UEFI CA 2011 into the db database
///
/// This certificate is required for third-party UEFI drivers and shim.
/// The bundled certificate custom-key enrollment adds to db, for review.
pub fn microsoft_uefi_ca_db_certificate() -> &'static [u8] {
    MICROSOFT_UEFI_CA_2011
}

pub fn enroll_microsoft_uefi_ca_db() -> Result<(), AuthError> {
    log::info!("Enrolling Microsoft Corporation UEFI CA 2011");
    let mut db = db_database();
    add_certificate_entry(&mut db, MICROSOFT_UEFI_CA_2011, &MICROSOFT_OWNER_GUID)?;
    log::info!(
        "Microsoft Corporation UEFI CA 2011 enrolled ({} bytes)",
        MICROSOFT_UEFI_CA_2011.len()
    );
    Ok(())
}

/// Enroll a default Platform Key (PK)
///
/// For a real implementation, the PK should be the platform owner's certificate.
/// This uses the Microsoft KEK CA as a placeholder PK for compatibility.
///
/// In a production environment, you should:
/// 1. Generate your own RSA-2048 key pair
/// 2. Create a self-signed certificate
/// 3. Use that as the PK
pub fn enroll_default_pk() -> Result<(), AuthError> {
    let mut db = pk_database();
    if let Some(cert) = SB_PK {
        log::info!("Enrolling the build's Platform Key ({} bytes)", cert.len());
        return add_certificate_entry(&mut db, cert, &CRABEFI_OWNER_GUID);
    }
    log::info!("Enrolling default Platform Key (using Microsoft KEK CA 2011)");

    // For now, use the Microsoft KEK CA as the PK
    // In a real implementation, this should be the platform owner's certificate
    add_certificate_entry(&mut db, MICROSOFT_KEK_CA_2011, &CRABEFI_OWNER_GUID)?;

    log::info!("Default PK enrolled");
    Ok(())
}

// Build-time key set (crabefi-core/build.rs).
include!(concat!(env!("OUT_DIR"), "/secure_boot_keys.rs"));

/// Add the build's Microsoft and platform-owner certificates to `db`.
fn enroll_build_certificates(
    db: &mut KeyDatabase,
    microsoft: &[&[u8]],
    owner: &[&[u8]],
) -> Result<(), AuthError> {
    for cert in microsoft {
        add_certificate_entry(db, cert, &MICROSOFT_OWNER_GUID)?;
    }
    for cert in owner {
        add_certificate_entry(db, cert, &CRABEFI_OWNER_GUID)?;
    }
    Ok(())
}

/// Enroll a custom certificate into the PK database
///
/// This allows platforms to use their own PK certificate.
pub fn enroll_pk(cert_der: &[u8], owner: &[u8; 16]) -> Result<(), AuthError> {
    log::info!("Enrolling custom Platform Key ({} bytes)", cert_der.len());
    let mut db = pk_database();
    add_certificate_entry(&mut db, cert_der, owner)?;
    log::info!("Custom PK enrolled");
    Ok(())
}

/// Enroll a custom certificate into the KEK database
pub fn enroll_kek(cert_der: &[u8], owner: &[u8; 16]) -> Result<(), AuthError> {
    log::info!(
        "Enrolling custom KEK certificate ({} bytes)",
        cert_der.len()
    );
    let mut db = kek_database();
    add_certificate_entry(&mut db, cert_der, owner)?;
    log::info!("Custom KEK enrolled");
    Ok(())
}

/// Enroll a custom certificate into the db database
pub fn enroll_db_certificate(cert_der: &[u8], owner: &[u8; 16]) -> Result<(), AuthError> {
    log::info!("Enrolling custom db certificate ({} bytes)", cert_der.len());
    let mut db = db_database();
    add_certificate_entry(&mut db, cert_der, owner)?;
    log::info!("Custom db certificate enrolled");
    Ok(())
}

// ============================================================================
// Composite Enrollment Functions
// ============================================================================

/// Enroll all Microsoft default keys for standard Secure Boot
///
/// This enrolls:
/// - Microsoft KEK CA 2011 -> KEK
/// - Microsoft Windows Production PCA 2011 -> db
/// - Microsoft Corporation UEFI CA 2011 -> db
/// - Default PK (Microsoft KEK CA 2011 as placeholder)
///
/// After calling this function, the system enters User Mode and Secure Boot
/// is ready to be enabled.
pub fn enroll_default_keys() -> Result<(), AuthError> {
    log::info!("Enrolling Microsoft default Secure Boot keys");

    // Enroll KEK first
    enroll_microsoft_kek()?;
    enroll_build_certificates(&mut kek_database(), SB_MS_KEK, SB_KEK)?;

    // Enroll db certificates
    enroll_microsoft_windows_production_db()?;
    enroll_microsoft_uefi_ca_db()?;
    enroll_build_certificates(&mut db_database(), SB_MS_DB, SB_DB)?;

    // Enroll PK last (this transitions from Setup Mode to User Mode)
    enroll_default_pk()?;

    // Enter User Mode now that PK is enrolled
    enter_user_mode();

    log::info!("Default keys enrolled - system in User Mode");
    log::info!(
        "  KEK: {} certificate(s)",
        1 + SB_MS_KEK.len() + SB_KEK.len()
    );
    log::info!("  db:  {} certificate(s)", 2 + SB_MS_DB.len() + SB_DB.len());
    log::info!(
        "  PK:  1 certificate{}",
        if SB_PK.is_some() { " (build)" } else { "" }
    );

    Ok(())
}

// ============================================================================
// Status Functions
// ============================================================================

/// Get enrollment status summary
pub fn get_enrollment_status() -> EnrollmentStatus {
    let pk_count = pk_database().len();
    let kek_count = kek_database().len();
    let db_count = db_database().len();
    let dbx_count = super::variables::dbx_database().len();

    EnrollmentStatus {
        pk_enrolled: pk_count > 0,
        pk_count,
        kek_count,
        db_count,
        dbx_count,
        setup_mode: super::is_setup_mode(),
        secure_boot_enabled: super::is_secure_boot_enabled(),
    }
}

/// Secure Boot enrollment status
#[derive(Debug, Clone)]
pub struct EnrollmentStatus {
    /// Whether a Platform Key is enrolled
    pub pk_enrolled: bool,
    /// Number of PK certificates
    pub pk_count: usize,
    /// Number of KEK certificates
    pub kek_count: usize,
    /// Number of db certificates
    pub db_count: usize,
    /// Number of dbx entries
    pub dbx_count: usize,
    /// Whether system is in Setup Mode
    pub setup_mode: bool,
    /// Whether Secure Boot is enabled
    pub secure_boot_enabled: bool,
}
