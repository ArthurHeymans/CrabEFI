//! PKCS#7 Signature Verification
//!
//! This module implements PKCS#7/CMS signature verification for UEFI
//! authenticated variables.

use super::structures::{EfiTime, EfiVariableAuthentication2};
use super::variables::{
    KeyDatabase, RuntimeAuthDatabases, SecureBootVariable, db_database, dbx_database, kek_database,
    pk_database,
};
use super::{AuthError, WIN_CERT_TYPE_EFI_GUID};
use alloc::vec::Vec;
use r_efi::efi::Guid;
use zerocopy::FromBytes;

// ============================================================================
// GUID Helper
// ============================================================================

/// EFI_CERT_TYPE_PKCS7_GUID as raw bytes for comparison
const EFI_CERT_TYPE_PKCS7_GUID_BYTES: [u8; 16] = [
    0x9D, 0xD2, 0xAF, 0x4A, 0xDF, 0x68, 0xEE, 0x49, 0x8A, 0xA9, 0x34, 0x7D, 0x37, 0x56, 0x65, 0xA7,
];

// ============================================================================
// Signature Verification
// ============================================================================

/// Verify an authenticated variable write
///
/// This function performs the complete authentication check for a SetVariable
/// call with `EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS` attribute.
///
/// # Arguments
///
/// * `variable_name` - The UCS-2 variable name
/// * `vendor_guid` - The variable's vendor GUID
/// * `attributes` - The variable attributes
/// * `data` - The complete data including EFI_VARIABLE_AUTHENTICATION_2 header
///
/// # Returns
///
/// On success, returns the actual variable data (without authentication header).
/// On failure, returns an AuthError.
pub fn verify_authenticated_variable(
    secure_boot: crate::runtime_state::SecureBootStatus,
    variable_name: &[u16],
    vendor_guid: &Guid,
    attributes: u32,
    data: &[u8],
) -> Result<Vec<u8>, AuthError> {
    verify_authenticated_variable_inner(
        secure_boot,
        variable_name,
        vendor_guid,
        attributes,
        data,
        None,
    )
}

/// Verify using databases reconstructed from pointer-free runtime state.
///
/// The supplied databases are operation-local and must not be retained by the
/// caller after the runtime allocation arena is reset.
pub fn verify_authenticated_variable_with_databases(
    secure_boot: crate::runtime_state::SecureBootStatus,
    variable_name: &[u16],
    vendor_guid: &Guid,
    attributes: u32,
    data: &[u8],
    databases: &RuntimeAuthDatabases,
) -> Result<Vec<u8>, AuthError> {
    verify_authenticated_variable_inner(
        secure_boot,
        variable_name,
        vendor_guid,
        attributes,
        data,
        Some(databases),
    )
}

fn verify_authenticated_variable_inner(
    secure_boot: crate::runtime_state::SecureBootStatus,
    variable_name: &[u16],
    vendor_guid: &Guid,
    attributes: u32,
    data: &[u8],
    databases: Option<&RuntimeAuthDatabases>,
) -> Result<Vec<u8>, AuthError> {
    // Parse the authentication header
    let auth = EfiVariableAuthentication2::from_bytes(data).ok_or(AuthError::InvalidHeader)?;
    if !auth.time_stamp.is_valid() {
        return Err(AuthError::InvalidTimestamp);
    }

    // Read certificate type from packed struct
    let cert_type_val = auth.auth_info.hdr.w_certificate_type;

    // Verify the certificate type is UEFI GUID
    if cert_type_val != WIN_CERT_TYPE_EFI_GUID {
        log::warn!("Authenticated variable: Invalid certificate type");
        return Err(AuthError::InvalidHeader);
    }

    // Check if the cert type GUID is PKCS#7
    if !auth
        .auth_info
        .cert_type_matches(&EFI_CERT_TYPE_PKCS7_GUID_BYTES)
    {
        log::warn!("Authenticated variable: Expected PKCS#7 certificate type");
        return Err(AuthError::InvalidHeader);
    }

    // Get the PKCS#7 signed data
    let pkcs7_data = auth.get_cert_data(data).ok_or(AuthError::InvalidHeader)?;

    // Get the actual variable data
    let variable_data = auth
        .get_variable_data(data)
        .ok_or(AuthError::InvalidHeader)?;

    // Build the data that was signed:
    // VariableName || VendorGuid || Attributes || TimeStamp || DataNew
    let signed_data = build_signed_data(
        variable_name,
        vendor_guid,
        attributes,
        &auth.time_stamp,
        variable_data,
    )?;

    // Determine which key database should authorize this variable
    if let Some(var_type) = super::variables::identify_key_database(variable_name, vendor_guid) {
        // This is a Secure Boot variable - requires special handling
        verify_secure_boot_variable(
            secure_boot,
            var_type,
            &auth.time_stamp,
            pkcs7_data,
            &signed_data,
            attributes & super::attributes::APPEND_WRITE != 0,
            databases,
        )?;
    } else {
        if let Some(previous) = previous_auth_timestamp(variable_name, vendor_guid, databases)
            && let Ok(previous) = EfiTime::read_from_bytes(&previous)
            && attributes & super::attributes::APPEND_WRITE == 0
            && !auth.time_stamp.is_after(&previous)
        {
            return Err(AuthError::InvalidTimestamp);
        }
        // For non-Secure Boot authenticated variables, verify against db.
        verify_signature_against_database(
            pkcs7_data,
            &signed_data,
            SecureBootVariable::Db,
            databases,
        )?;
    }

    let mut result = Vec::new();
    result
        .try_reserve(variable_data.len())
        .map_err(|_| AuthError::BufferTooSmall)?;
    result.extend_from_slice(variable_data);
    Ok(result)
}

fn previous_auth_timestamp(
    variable_name: &[u16],
    vendor_guid: &Guid,
    databases: Option<&RuntimeAuthDatabases>,
) -> Option<[u8; 16]> {
    match databases {
        Some(_) => {
            crate::runtime_state::with(|runtime| runtime.auth_timestamp(vendor_guid, variable_name))
        }
        None => crate::state::efi()
            .variables
            .iter()
            .find_map(|variable| {
                (variable.in_use
                    && variable.vendor_guid == *vendor_guid
                    && crate::efi::utils::ucs2_eq(&variable.name, variable_name)
                    && variable.auth_timestamp != [0; 16])
                    .then_some(variable.auth_timestamp)
            })
            .or_else(|| {
                crate::state::efi().auth_replay.iter().find_map(|entry| {
                    (entry.in_use
                        && entry.vendor_guid == *vendor_guid
                        && crate::efi::utils::ucs2_eq(&entry.name, variable_name))
                    .then_some(entry.timestamp)
                })
            }),
    }
}

/// Verify a Secure Boot variable update
fn verify_secure_boot_variable(
    secure_boot: crate::runtime_state::SecureBootStatus,
    var_type: SecureBootVariable,
    timestamp: &EfiTime,
    pkcs7_data: &[u8],
    signed_data: &[u8],
    is_append: bool,
    databases: Option<&RuntimeAuthDatabases>,
) -> Result<(), AuthError> {
    // Replay protection applies in Setup Mode too: deleting PK must not make an
    // older signed enrollment usable again. Setup Mode only relaxes signature
    // authorization for the initial enrollment.
    let current_timestamp = match databases {
        Some(databases) => match var_type {
            SecureBootVariable::PK => *databases.pk.timestamp(),
            SecureBootVariable::KEK => *databases.kek.timestamp(),
            SecureBootVariable::Db => *databases.db.timestamp(),
            SecureBootVariable::Dbx => *databases.dbx.timestamp(),
        },
        None => match var_type {
            SecureBootVariable::PK => *pk_database().timestamp(),
            SecureBootVariable::KEK => *kek_database().timestamp(),
            SecureBootVariable::Db => *db_database().timestamp(),
            SecureBootVariable::Dbx => *dbx_database().timestamp(),
        },
    };

    if !is_append
        && current_timestamp.compare(&EfiTime::zero()) != core::cmp::Ordering::Equal
        && !timestamp.is_after(&current_timestamp)
    {
        log::warn!("Authenticated variable: Timestamp not monotonically increasing");
        return Err(AuthError::InvalidTimestamp);
    }

    if secure_boot.setup_mode() {
        log::info!("Setup Mode: allowing initial write to {:?}", var_type);
        return Ok(());
    }

    // Verify the signature against the authorizing database.
    verify_signature_against_database(
        pkcs7_data,
        signed_data,
        var_type.authorizing_database(),
        databases,
    )?;

    Ok(())
}

/// Verify a PKCS#7 signature against a key database
fn verify_signature_against_database(
    pkcs7_data: &[u8],
    signed_data: &[u8],
    database: SecureBootVariable,
    databases: Option<&RuntimeAuthDatabases>,
) -> Result<(), AuthError> {
    let mut certificate_count = 0;
    let mut verify_database = |key_database: &KeyDatabase| {
        for cert_der in key_database.x509_certificates() {
            certificate_count += 1;
            if let Ok(true) =
                super::crypto::verify_pkcs7_signature(pkcs7_data, signed_data, cert_der)
            {
                return true;
            }
        }
        false
    };

    let verified = match databases {
        Some(databases) => match database {
            SecureBootVariable::PK => verify_database(&databases.pk),
            SecureBootVariable::KEK | SecureBootVariable::Db | SecureBootVariable::Dbx => {
                verify_database(&databases.kek) || verify_database(&databases.pk)
            }
        },
        None => match database {
            SecureBootVariable::PK => verify_database(&pk_database()),
            SecureBootVariable::KEK | SecureBootVariable::Db | SecureBootVariable::Dbx => {
                verify_database(&kek_database()) || verify_database(&pk_database())
            }
        },
    };

    if certificate_count == 0 {
        log::warn!(
            "Authenticated variable: No certificates in {:?} database",
            database
        );
        return Err(AuthError::NoSuitableKey);
    }
    if verified {
        log::info!("Authenticated variable: Signature verified successfully");
        Ok(())
    } else {
        log::warn!("Authenticated variable: No matching signature found");
        Err(AuthError::SignatureVerificationFailed)
    }
}

/// Build the data that is signed for authenticated variables
///
/// According to UEFI spec, the signed data is:
/// VariableName || VendorGuid || Attributes || TimeStamp || DataNew
fn build_signed_data(
    variable_name: &[u16],
    vendor_guid: &Guid,
    attributes: u32,
    timestamp: &EfiTime,
    data: &[u8],
) -> Result<Vec<u8>, AuthError> {
    let name_bytes = variable_name.iter().take_while(|&&ch| ch != 0).count() * 2;
    let required = name_bytes
        .checked_add(16)
        .and_then(|size| size.checked_add(4))
        .and_then(|size| size.checked_add(core::mem::size_of::<EfiTime>()))
        .and_then(|size| size.checked_add(data.len()))
        .ok_or(AuthError::BufferTooSmall)?;
    let mut result = Vec::new();
    result
        .try_reserve(required)
        .map_err(|_| AuthError::BufferTooSmall)?;

    // VariableName (UCS-2, NOT including null terminator per UEFI spec Section 8.2.2)
    for &ch in variable_name {
        if ch == 0 {
            break;
        }
        result.extend_from_slice(&ch.to_le_bytes());
    }

    // VendorGuid (16 bytes)
    result.extend_from_slice(&vendor_guid.as_bytes()[..]);

    // Attributes (4 bytes, little-endian)
    result.extend_from_slice(&attributes.to_le_bytes());

    // TimeStamp (EFI_TIME, 16 bytes)
    result.extend_from_slice(zerocopy::IntoBytes::as_bytes(timestamp));

    // DataNew (the actual variable data)
    result.extend_from_slice(data);

    Ok(result)
}

/// Check if a binary image hash is in the forbidden database (dbx)
pub fn is_hash_forbidden(hash: &[u8; 32]) -> bool {
    dbx_database().contains_sha256_hash(hash)
}

/// Check if a binary image hash is in the allowed database (db)
pub fn is_hash_allowed(hash: &[u8; 32]) -> bool {
    db_database().contains_sha256_hash(hash)
}

/// Check if a certificate is in the forbidden database (dbx)
pub fn is_certificate_forbidden(cert_der: &[u8]) -> bool {
    // Check if the certificate itself is in dbx
    dbx_database().find_x509_certificate(cert_der).is_some()
}
