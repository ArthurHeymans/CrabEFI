//! PE Authenticode Signature Verification
//!
//! This module implements Authenticode signature verification for PE executables,
//! as required by UEFI Secure Boot.
//!
//! # Authenticode Hash Calculation
//!
//! The Authenticode hash excludes:
//! - The Checksum field in the optional header
//! - The Certificate Table entry in the data directories
//! - The attribute certificate table (signature data at end of file)
//!
//! # References
//!
//! - Microsoft PE Authenticode specification
//! - UEFI Specification Section 32 (Secure Boot)

use super::crypto::verify_pkcs7_signature;
use super::signature::{is_certificate_forbidden, is_hash_allowed, is_hash_forbidden};
use super::variables::db_database;
use super::AuthError;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// DOS header magic "MZ"
const DOS_MAGIC: u16 = 0x5A4D;

/// PE signature "PE\0\0"
const PE_SIGNATURE: u32 = 0x00004550;

/// PE32+ magic
const PE32_PLUS_MAGIC: u16 = 0x020B;

/// PE32 magic
const PE32_MAGIC: u16 = 0x010B;

/// Data directory index for the Certificate Table (Security Directory)
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;

/// WIN_CERTIFICATE header type for PKCS#7
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

/// Offset of checksum field in PE32+ optional header (from start of optional header)
const PE32_PLUS_CHECKSUM_OFFSET: usize = 64;

/// Offset of checksum field in PE32 optional header
const PE32_CHECKSUM_OFFSET: usize = 64;

/// Size of a data directory entry
const DATA_DIRECTORY_SIZE: usize = 8;

/// PE file information extracted during parsing
struct PeInfo {
    /// Offset of checksum field from start of file
    checksum_offset: usize,
    /// Offset of certificate table data directory entry from start of file
    cert_table_entry_offset: usize,
    /// Size of headers
    size_of_headers: usize,
    /// Certificate table RVA (0 if none)
    cert_table_rva: u32,
    /// Certificate table size (0 if none)
    cert_table_size: u32,
    /// Sections sorted by PointerToRawData
    sections: Vec<SectionInfo>,
}

/// Section information for hashing
#[derive(Clone)]
struct SectionInfo {
    /// Offset in file (PointerToRawData)
    file_offset: u32,
    /// Size of raw data
    size_of_raw_data: u32,
}

/// Embedded Authenticode signature data
pub struct AuthenticodeSignature<'a> {
    /// The PKCS#7 SignedData blob
    pub pkcs7_data: &'a [u8],
}

/// Compute the Authenticode PE hash
///
/// This implements the PE/COFF hash algorithm as specified in the Microsoft
/// Authenticode specification and UEFI Secure Boot requirements.
///
/// # Arguments
///
/// * `pe_data` - The complete PE file data
///
/// # Returns
///
/// The SHA-256 hash of the image (excluding Authenticode-specific regions)
pub fn compute_authenticode_hash(pe_data: &[u8]) -> Result<[u8; 32], AuthError> {
    let info = parse_pe_for_hash(pe_data)?;

    let mut hasher = Sha256::new();

    // Region 1: From start to checksum field (exclusive)
    if info.checksum_offset > pe_data.len() {
        return Err(AuthError::InvalidHeader);
    }
    hasher.update(&pe_data[..info.checksum_offset]);

    // Skip checksum (4 bytes)
    let after_checksum = info.checksum_offset + 4;

    // Region 2: From after checksum to certificate table entry (exclusive)
    if info.cert_table_entry_offset < after_checksum {
        return Err(AuthError::InvalidHeader);
    }
    if info.cert_table_entry_offset > pe_data.len() {
        // No certificate table entry - hash to end of data directories
        hasher.update(&pe_data[after_checksum..]);
    } else {
        hasher.update(&pe_data[after_checksum..info.cert_table_entry_offset]);

        // Skip certificate table entry (8 bytes)
        let after_cert_entry = info.cert_table_entry_offset + DATA_DIRECTORY_SIZE;

        // Region 3: From after cert table entry to end of headers
        if after_cert_entry <= info.size_of_headers && info.size_of_headers <= pe_data.len() {
            hasher.update(&pe_data[after_cert_entry..info.size_of_headers]);
        }
    }

    // Region 4: Hash sections in order of file offset
    // Sections are already sorted by file_offset
    let mut current_pos = info.size_of_headers;

    for section in &info.sections {
        let section_start = section.file_offset as usize;
        let section_end = section_start + section.size_of_raw_data as usize;

        // Skip if section has no raw data
        if section.size_of_raw_data == 0 {
            continue;
        }

        // Handle gap between current position and section start
        if section_start > current_pos && section_start <= pe_data.len() {
            // There's a gap - hash it (could be alignment padding)
            hasher.update(&pe_data[current_pos..section_start]);
        }

        // Hash the section data
        if section_end <= pe_data.len() {
            hasher.update(&pe_data[section_start..section_end]);
            current_pos = section_end;
        }
    }

    // Hash any remaining data BEFORE the certificate table
    let file_end = if info.cert_table_rva > 0 && info.cert_table_size > 0 {
        // Certificate table is at the end - don't hash it
        info.cert_table_rva as usize
    } else {
        pe_data.len()
    };

    if current_pos < file_end && file_end <= pe_data.len() {
        hasher.update(&pe_data[current_pos..file_end]);
    }

    Ok(hasher.finalize().into())
}

/// Parse PE file to extract information needed for hash calculation
fn parse_pe_for_hash(pe_data: &[u8]) -> Result<PeInfo, AuthError> {
    // Check minimum size for DOS header
    if pe_data.len() < 64 {
        return Err(AuthError::InvalidHeader);
    }

    // Check DOS magic
    let dos_magic = u16::from_le_bytes([pe_data[0], pe_data[1]]);
    if dos_magic != DOS_MAGIC {
        return Err(AuthError::InvalidHeader);
    }

    // Get PE offset from DOS header
    let pe_offset =
        u32::from_le_bytes([pe_data[60], pe_data[61], pe_data[62], pe_data[63]]) as usize;

    // Validate PE offset
    if pe_offset + 4 > pe_data.len() {
        return Err(AuthError::InvalidHeader);
    }

    // Check PE signature
    let pe_sig = u32::from_le_bytes([
        pe_data[pe_offset],
        pe_data[pe_offset + 1],
        pe_data[pe_offset + 2],
        pe_data[pe_offset + 3],
    ]);
    if pe_sig != PE_SIGNATURE {
        return Err(AuthError::InvalidHeader);
    }

    // COFF header starts after PE signature
    let coff_offset = pe_offset + 4;
    if coff_offset + 20 > pe_data.len() {
        return Err(AuthError::InvalidHeader);
    }

    // Get number of sections and optional header size
    let num_sections =
        u16::from_le_bytes([pe_data[coff_offset + 2], pe_data[coff_offset + 3]]) as usize;
    let opt_header_size =
        u16::from_le_bytes([pe_data[coff_offset + 16], pe_data[coff_offset + 17]]) as usize;

    // Optional header offset
    let opt_header_offset = coff_offset + 20;
    if opt_header_offset + 2 > pe_data.len() {
        return Err(AuthError::InvalidHeader);
    }

    // Check PE32 vs PE32+ magic
    let magic = u16::from_le_bytes([pe_data[opt_header_offset], pe_data[opt_header_offset + 1]]);
    let is_pe32_plus = match magic {
        PE32_PLUS_MAGIC => true,
        PE32_MAGIC => false,
        _ => return Err(AuthError::InvalidHeader),
    };

    // Calculate checksum offset
    let checksum_offset = opt_header_offset
        + if is_pe32_plus {
            PE32_PLUS_CHECKSUM_OFFSET
        } else {
            PE32_CHECKSUM_OFFSET
        };

    // Get size of headers
    let headers_size_offset = opt_header_offset + 60; // Same for PE32 and PE32+
    if headers_size_offset + 4 > pe_data.len() {
        return Err(AuthError::InvalidHeader);
    }
    let size_of_headers = u32::from_le_bytes([
        pe_data[headers_size_offset],
        pe_data[headers_size_offset + 1],
        pe_data[headers_size_offset + 2],
        pe_data[headers_size_offset + 3],
    ]) as usize;

    // Get number of data directories
    let num_rva_offset = if is_pe32_plus {
        opt_header_offset + 108
    } else {
        opt_header_offset + 92
    };
    if num_rva_offset + 4 > pe_data.len() {
        return Err(AuthError::InvalidHeader);
    }
    let num_data_dirs = u32::from_le_bytes([
        pe_data[num_rva_offset],
        pe_data[num_rva_offset + 1],
        pe_data[num_rva_offset + 2],
        pe_data[num_rva_offset + 3],
    ]);

    // Data directories start after the fixed optional header fields
    let data_dirs_offset = if is_pe32_plus {
        opt_header_offset + 112
    } else {
        opt_header_offset + 96
    };

    // Calculate certificate table entry offset
    let cert_table_entry_offset = if num_data_dirs as usize > IMAGE_DIRECTORY_ENTRY_SECURITY {
        data_dirs_offset + IMAGE_DIRECTORY_ENTRY_SECURITY * DATA_DIRECTORY_SIZE
    } else {
        // No certificate table entry
        pe_data.len()
    };

    // Read certificate table info
    let (cert_table_rva, cert_table_size) =
        if cert_table_entry_offset + DATA_DIRECTORY_SIZE <= pe_data.len() {
            let rva = u32::from_le_bytes([
                pe_data[cert_table_entry_offset],
                pe_data[cert_table_entry_offset + 1],
                pe_data[cert_table_entry_offset + 2],
                pe_data[cert_table_entry_offset + 3],
            ]);
            let size = u32::from_le_bytes([
                pe_data[cert_table_entry_offset + 4],
                pe_data[cert_table_entry_offset + 5],
                pe_data[cert_table_entry_offset + 6],
                pe_data[cert_table_entry_offset + 7],
            ]);
            (rva, size)
        } else {
            (0, 0)
        };

    // Parse sections and sort by file offset
    let sections_offset = opt_header_offset + opt_header_size;
    let mut sections = Vec::with_capacity(num_sections);

    for i in 0..num_sections {
        let section_offset = sections_offset + i * 40;
        if section_offset + 40 > pe_data.len() {
            break;
        }

        let size_of_raw_data = u32::from_le_bytes([
            pe_data[section_offset + 16],
            pe_data[section_offset + 17],
            pe_data[section_offset + 18],
            pe_data[section_offset + 19],
        ]);
        let pointer_to_raw_data = u32::from_le_bytes([
            pe_data[section_offset + 20],
            pe_data[section_offset + 21],
            pe_data[section_offset + 22],
            pe_data[section_offset + 23],
        ]);

        if size_of_raw_data > 0 && pointer_to_raw_data > 0 {
            sections.push(SectionInfo {
                file_offset: pointer_to_raw_data,
                size_of_raw_data,
            });
        }
    }

    // Sort sections by file offset
    sections.sort_by_key(|s| s.file_offset);

    Ok(PeInfo {
        checksum_offset,
        cert_table_entry_offset,
        size_of_headers,
        cert_table_rva,
        cert_table_size,
        sections,
    })
}

/// Extract the embedded Authenticode signature from a PE file
///
/// # Arguments
///
/// * `pe_data` - The complete PE file data
///
/// # Returns
///
/// The Authenticode signature if present, or None if unsigned
pub fn extract_authenticode_signature(
    pe_data: &[u8],
) -> Result<Option<AuthenticodeSignature<'_>>, AuthError> {
    let info = parse_pe_for_hash(pe_data)?;

    // Check if there's a certificate table
    if info.cert_table_rva == 0 || info.cert_table_size == 0 {
        return Ok(None);
    }

    // Certificate table is at a file offset (not RVA)
    let cert_offset = info.cert_table_rva as usize;
    let cert_end = cert_offset + info.cert_table_size as usize;

    if cert_end > pe_data.len() {
        log::warn!("Certificate table extends beyond file");
        return Err(AuthError::InvalidHeader);
    }

    // Parse WIN_CERTIFICATE structure
    // dwLength: DWORD (4 bytes)
    // wRevision: WORD (2 bytes)
    // wCertificateType: WORD (2 bytes)
    // bCertificate: variable
    if info.cert_table_size < 8 {
        return Err(AuthError::InvalidHeader);
    }

    let dw_length = u32::from_le_bytes([
        pe_data[cert_offset],
        pe_data[cert_offset + 1],
        pe_data[cert_offset + 2],
        pe_data[cert_offset + 3],
    ]) as usize;

    let w_certificate_type =
        u16::from_le_bytes([pe_data[cert_offset + 6], pe_data[cert_offset + 7]]);

    // Check for PKCS#7 signed data
    if w_certificate_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
        log::debug!("Certificate type is not PKCS#7: {:#x}", w_certificate_type);
        return Ok(None);
    }

    // Extract PKCS#7 data (after 8-byte header)
    let pkcs7_start = cert_offset + 8;
    let pkcs7_len = dw_length.saturating_sub(8);

    if pkcs7_start + pkcs7_len > pe_data.len() {
        return Err(AuthError::InvalidHeader);
    }

    Ok(Some(AuthenticodeSignature {
        pkcs7_data: &pe_data[pkcs7_start..pkcs7_start + pkcs7_len],
    }))
}

/// Verify a PE image for Secure Boot
///
/// This performs the full Secure Boot verification:
/// 1. Compute the Authenticode hash
/// 2. Check if hash is in dbx (forbidden) - reject if found
/// 3. Check if hash is in db (allowed) - accept if found
/// 4. If signed, verify signature against db certificates
///
/// # Arguments
///
/// * `pe_data` - The complete PE file data
///
/// # Returns
///
/// * `Ok(true)` - Image is authorized for execution
/// * `Ok(false)` - Image is NOT authorized
/// * `Err(...)` - Verification error
pub fn verify_pe_image_secure_boot(pe_data: &[u8]) -> Result<bool, AuthError> {
    // Compute the Authenticode hash
    let image_hash = compute_authenticode_hash(pe_data)?;

    log::debug!("PE Authenticode hash: {:02x?}", &image_hash[..8]);

    // Check if hash is in dbx (forbidden database)
    if is_hash_forbidden(&image_hash) {
        log::warn!("Secure Boot: Image hash is in forbidden database (dbx)");
        return Ok(false);
    }

    // Check if hash is in db (allowed database)
    if is_hash_allowed(&image_hash) {
        log::info!("Secure Boot: Image hash found in allowed database (db)");
        return Ok(true);
    }

    // Try to extract and verify embedded signature
    match extract_authenticode_signature(pe_data)? {
        Some(sig) => {
            log::debug!("Secure Boot: Found embedded Authenticode signature");
            verify_authenticode_signature(pe_data, &sig)
        }
        None => {
            log::warn!("Secure Boot: Unsigned image not in db");
            Ok(false)
        }
    }
}

/// Verify an Authenticode signature against the db database
fn verify_authenticode_signature(
    pe_data: &[u8],
    sig: &AuthenticodeSignature,
) -> Result<bool, AuthError> {
    // Compute what was signed (the Authenticode hash)
    let image_hash = compute_authenticode_hash(pe_data)?;

    // Get all X.509 certificates from db
    let db = db_database();
    let certificates: Vec<&[u8]> = db.x509_certificates().collect();

    if certificates.is_empty() {
        log::warn!("Secure Boot: No certificates in db for signature verification");
        return Ok(false);
    }

    // Try to verify against each certificate in db
    for cert_der in certificates {
        // Check if this certificate is forbidden
        if is_certificate_forbidden(cert_der) {
            log::debug!("Secure Boot: Skipping forbidden certificate");
            continue;
        }

        match verify_pkcs7_signature(sig.pkcs7_data, &image_hash, cert_der) {
            Ok(true) => {
                log::info!("Secure Boot: Signature verified successfully");
                return Ok(true);
            }
            Ok(false) => continue,
            Err(e) => {
                log::debug!("Secure Boot: Signature verification error: {:?}", e);
                continue;
            }
        }
    }

    log::warn!("Secure Boot: No matching signature found in db");
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pe_magic() {
        // Minimal invalid PE
        let bad_pe = [0u8; 64];
        assert!(parse_pe_for_hash(&bad_pe).is_err());

        // MZ but invalid PE offset
        let mut mz_only = [0u8; 128];
        mz_only[0] = b'M';
        mz_only[1] = b'Z';
        mz_only[60] = 0xFF; // Invalid PE offset
        assert!(parse_pe_for_hash(&mz_only).is_err());
    }
}
