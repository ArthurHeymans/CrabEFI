//! PKCS#7 Signature Verification
//!
//! This module implements PKCS#7/CMS signature verification for UEFI
//! authenticated variables.

use super::structures::{EfiTime, EfiVariableAuthentication2};
use super::variables::{db_database, dbx_database, kek_database, pk_database, SecureBootVariable};
use super::{is_setup_mode, AuthError, WIN_CERT_TYPE_EFI_GUID};
use alloc::vec::Vec;
use r_efi::efi::Guid;

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
    variable_name: &[u16],
    vendor_guid: &Guid,
    attributes: u32,
    data: &[u8],
) -> Result<Vec<u8>, AuthError> {
    // Parse the authentication header
    let auth = EfiVariableAuthentication2::from_bytes(data).ok_or(AuthError::InvalidHeader)?;

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
    );

    // Determine which key database should authorize this variable
    if let Some(var_type) = super::variables::identify_key_database(variable_name, vendor_guid) {
        // This is a Secure Boot variable - requires special handling
        verify_secure_boot_variable(var_type, &auth.time_stamp, pkcs7_data, &signed_data)?;
    } else {
        // For non-Secure Boot authenticated variables, verify against db
        verify_signature_against_database(pkcs7_data, &signed_data, SecureBootVariable::Db)?;
    }

    Ok(variable_data.to_vec())
}

/// Verify a Secure Boot variable update
fn verify_secure_boot_variable(
    var_type: SecureBootVariable,
    timestamp: &EfiTime,
    pkcs7_data: &[u8],
    signed_data: &[u8],
) -> Result<(), AuthError> {
    // In Setup Mode, we skip signature verification for initial enrollment
    if is_setup_mode() {
        log::info!(
            "Setup Mode: Allowing unauthenticated write to {:?}",
            var_type
        );
        return Ok(());
    }

    // Get the authorizing database for this variable
    let auth_db = var_type.authorizing_database();

    // Check timestamp monotonicity
    let current_timestamp = match var_type {
        SecureBootVariable::PK => pk_database().timestamp().clone(),
        SecureBootVariable::KEK => kek_database().timestamp().clone(),
        SecureBootVariable::Db => db_database().timestamp().clone(),
        SecureBootVariable::Dbx => dbx_database().timestamp().clone(),
    };

    if !timestamp.is_after(&current_timestamp) {
        log::warn!("Authenticated variable: Timestamp not monotonically increasing");
        return Err(AuthError::InvalidTimestamp);
    }

    // Verify the signature against the authorizing database
    verify_signature_against_database(pkcs7_data, signed_data, auth_db)?;

    Ok(())
}

/// Verify a PKCS#7 signature against a key database
fn verify_signature_against_database(
    pkcs7_data: &[u8],
    signed_data: &[u8],
    database: SecureBootVariable,
) -> Result<(), AuthError> {
    // Get certificates from the appropriate database
    let certificates: Vec<Vec<u8>> = match database {
        SecureBootVariable::PK => pk_database()
            .x509_certificates()
            .map(|c| c.to_vec())
            .collect(),
        SecureBootVariable::KEK => {
            // KEK or PK can authorize
            let mut certs: Vec<Vec<u8>> = kek_database()
                .x509_certificates()
                .map(|c| c.to_vec())
                .collect();
            certs.extend(pk_database().x509_certificates().map(|c| c.to_vec()));
            certs
        }
        SecureBootVariable::Db | SecureBootVariable::Dbx => {
            // For db/dbx verification, we check KEK (and PK as fallback)
            let mut certs: Vec<Vec<u8>> = kek_database()
                .x509_certificates()
                .map(|c| c.to_vec())
                .collect();
            certs.extend(pk_database().x509_certificates().map(|c| c.to_vec()));
            certs
        }
    };

    if certificates.is_empty() {
        log::warn!(
            "Authenticated variable: No certificates in {:?} database",
            database
        );
        return Err(AuthError::NoSuitableKey);
    }

    // Try to verify against each certificate
    for cert_der in &certificates {
        match super::crypto::verify_pkcs7_signature(pkcs7_data, signed_data, cert_der) {
            Ok(true) => {
                log::info!("Authenticated variable: Signature verified successfully");
                return Ok(());
            }
            Ok(false) => {
                // Signature didn't match this certificate, try next
                continue;
            }
            Err(e) => {
                log::debug!("Signature verification error: {:?}", e);
                continue;
            }
        }
    }

    log::warn!("Authenticated variable: No matching signature found");
    Err(AuthError::SignatureVerificationFailed)
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
) -> Vec<u8> {
    let mut result = Vec::new();

    // VariableName (UCS-2, including null terminator)
    for &ch in variable_name {
        result.extend_from_slice(&ch.to_le_bytes());
        if ch == 0 {
            break;
        }
    }

    // VendorGuid (16 bytes)
    result.extend_from_slice(&vendor_guid.as_bytes()[..]);

    // Attributes (4 bytes, little-endian)
    result.extend_from_slice(&attributes.to_le_bytes());

    // TimeStamp (EFI_TIME, 16 bytes)
    // We need to serialize the timestamp as raw bytes
    let timestamp_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            timestamp as *const EfiTime as *const u8,
            core::mem::size_of::<EfiTime>(),
        )
    };
    result.extend_from_slice(timestamp_bytes);

    // DataNew (the actual variable data)
    result.extend_from_slice(data);

    result
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
