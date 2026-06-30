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

use super::AuthError;
use super::crypto::verify_pkcs7_signature;
use super::signature::{is_certificate_forbidden, is_hash_allowed, is_hash_forbidden};
use super::variables::db_database;
use crate::efi::tcg::types::{
    SHA1_DIGEST_SIZE, SHA256_DIGEST_SIZE, SHA384_DIGEST_SIZE, SHA512_DIGEST_SIZE, TPM_ALG_SHA1,
    TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, TaggedDigest, digest_size_for_algorithm,
};
use crate::pe::{DATA_DIRECTORY_ENTRY_SIZE, IMAGE_DIRECTORY_ENTRY_SECURITY, parse_headers};
use alloc::vec::Vec;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// WIN_CERTIFICATE header type for PKCS#7
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

fn is_supported_authenticode_algorithm(algorithm: u16) -> bool {
    matches!(
        algorithm,
        TPM_ALG_SHA1 | TPM_ALG_SHA256 | TPM_ALG_SHA384 | TPM_ALG_SHA512
    )
}

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

/// Compute Authenticode digests for all requested hash algorithms.
///
/// This implements the PE/COFF hash algorithm (excluding the Checksum field,
/// Certificate Table data directory entry, and the certificate data itself)
/// for multiple hash algorithms simultaneously, as required by TCG measured
/// boot. Each active PCR bank needs the authenticode hash in its algorithm.
///
/// # Arguments
///
/// * `pe_data` - The complete PE file data
/// * `algorithms` - Slice of TPM algorithm IDs (e.g., `&[TPM_ALG_SHA256, TPM_ALG_SHA1]`)
///
/// # Returns
///
/// `(count, digests)` where `count` is the number of valid digests and
/// `digests` is a fixed-size array of [`TaggedDigest`] values.
pub fn compute_authenticode_digests(
    pe_data: &[u8],
    algorithms: &[u16],
) -> Result<(usize, [TaggedDigest; 5]), AuthError> {
    let info = parse_pe_for_hash(pe_data)?;
    let mut digests = [TaggedDigest::zeroed(0); 5];
    let mut count = 0;

    for &alg in algorithms {
        if count >= digests.len() {
            break;
        }
        if !is_supported_authenticode_algorithm(alg) {
            continue;
        }
        let digest_size = match digest_size_for_algorithm(alg) {
            Some(s) => s,
            None => continue,
        };

        let hash_bytes = compute_authenticode_hash_inner(pe_data, &info, alg)?;
        digests[count].algorithm = alg;
        digests[count].digest[..digest_size].copy_from_slice(&hash_bytes[..digest_size]);
        count += 1;
    }

    if count == 0 {
        return Err(AuthError::InvalidHeader);
    }

    Ok((count, digests))
}

/// Compute authenticode hash for a single algorithm. Returns up to 64 bytes.
fn compute_authenticode_hash_inner(
    pe_data: &[u8],
    info: &PeInfo,
    algorithm: u16,
) -> Result<[u8; 64], AuthError> {
    // Build the list of byte ranges to hash (shared logic for all algorithms).
    let regions = authenticode_regions(pe_data, info)?;

    let mut result = [0u8; 64];
    match algorithm {
        TPM_ALG_SHA256 => {
            let mut hasher = Sha256::new();
            for (start, end) in &regions {
                hasher.update(&pe_data[*start..*end]);
            }
            let hash = hasher.finalize();
            result[..SHA256_DIGEST_SIZE].copy_from_slice(&hash);
        }
        TPM_ALG_SHA1 => {
            let mut hasher = Sha1::new();
            for (start, end) in &regions {
                hasher.update(&pe_data[*start..*end]);
            }
            let hash = hasher.finalize();
            result[..SHA1_DIGEST_SIZE].copy_from_slice(&hash);
        }
        TPM_ALG_SHA384 => {
            let mut hasher = Sha384::new();
            for (start, end) in &regions {
                hasher.update(&pe_data[*start..*end]);
            }
            let hash = hasher.finalize();
            result[..SHA384_DIGEST_SIZE].copy_from_slice(&hash);
        }
        TPM_ALG_SHA512 => {
            let mut hasher = Sha512::new();
            for (start, end) in &regions {
                hasher.update(&pe_data[*start..*end]);
            }
            let hash = hasher.finalize();
            result[..SHA512_DIGEST_SIZE].copy_from_slice(&hash);
        }
        _ => return Err(AuthError::InvalidHeader),
    }
    Ok(result)
}

/// Build the list of (start, end) byte ranges for authenticode hashing.
///
/// The authenticode hash covers the entire file except:
/// 1. The 4-byte CheckSum field
/// 2. The 8-byte Certificate Table data directory entry
/// 3. The certificate table data (signature blob at end of file)
fn authenticode_regions(pe_data: &[u8], info: &PeInfo) -> Result<Vec<(usize, usize)>, AuthError> {
    let mut regions = Vec::new();

    // Region 1: From start to checksum field
    if info.checksum_offset > pe_data.len() {
        return Err(AuthError::InvalidHeader);
    }
    regions.push((0, info.checksum_offset));

    // Skip checksum (4 bytes)
    let after_checksum = info
        .checksum_offset
        .checked_add(4)
        .ok_or(AuthError::InvalidHeader)?;

    // Region 2: From after checksum to certificate table entry
    if info.cert_table_entry_offset < after_checksum {
        return Err(AuthError::InvalidHeader);
    }
    if info.cert_table_entry_offset > pe_data.len() {
        // No certificate table entry - hash to end of headers
        regions.push((after_checksum, info.size_of_headers.min(pe_data.len())));
    } else {
        regions.push((after_checksum, info.cert_table_entry_offset));

        // Skip certificate table entry (8 bytes)
        let after_cert_entry = info
            .cert_table_entry_offset
            .checked_add(DATA_DIRECTORY_ENTRY_SIZE)
            .ok_or(AuthError::InvalidHeader)?;

        // Region 3: From after cert table entry to end of headers
        if after_cert_entry <= info.size_of_headers && info.size_of_headers <= pe_data.len() {
            regions.push((after_cert_entry, info.size_of_headers));
        }
    }

    // Region 4: Hash each section in order of PointerToRawData
    let mut sum_of_bytes_hashed = info.size_of_headers;
    for section in &info.sections {
        if section.size_of_raw_data == 0 {
            continue;
        }
        let section_start = section.file_offset as usize;
        let section_end = section_start
            .checked_add(section.size_of_raw_data as usize)
            .ok_or(AuthError::InvalidHeader)?;
        if section_end <= pe_data.len() {
            regions.push((section_start, section_end));
            sum_of_bytes_hashed = sum_of_bytes_hashed
                .checked_add(section.size_of_raw_data as usize)
                .ok_or(AuthError::InvalidHeader)?;
        }
    }

    // Region 5: Extra data between sections and certificate table
    let file_end = if info.cert_table_size > 0 {
        let cert_start = info.cert_table_rva as usize;
        let cert_end = cert_start
            .checked_add(info.cert_table_size as usize)
            .ok_or(AuthError::InvalidHeader)?;
        if cert_end > pe_data.len() {
            return Err(AuthError::InvalidHeader);
        }
        cert_start
    } else {
        pe_data.len()
    };
    if sum_of_bytes_hashed < file_end && file_end <= pe_data.len() {
        regions.push((sum_of_bytes_hashed, file_end));
    }

    Ok(regions)
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
    let after_checksum = info
        .checksum_offset
        .checked_add(4)
        .ok_or(AuthError::InvalidHeader)?;

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
        let after_cert_entry = info
            .cert_table_entry_offset
            .checked_add(DATA_DIRECTORY_ENTRY_SIZE)
            .ok_or(AuthError::InvalidHeader)?;

        // Region 3: From after cert table entry to end of headers
        if after_cert_entry <= info.size_of_headers && info.size_of_headers <= pe_data.len() {
            hasher.update(&pe_data[after_cert_entry..info.size_of_headers]);
        }
    }

    // Region 4: Hash each section in order of PointerToRawData.
    // Per the Authenticode spec, only each section's raw data is hashed here
    // (no inter-section gaps). SUM_OF_BYTES_HASHED tracks the total byte count
    // for the extra-data calculation in the next step.
    let mut sum_of_bytes_hashed = info.size_of_headers;

    for section in &info.sections {
        let section_start = section.file_offset as usize;
        let section_end = section_start
            .checked_add(section.size_of_raw_data as usize)
            .ok_or(AuthError::InvalidHeader)?;

        // Skip if section has no raw data
        if section.size_of_raw_data == 0 {
            continue;
        }

        // Hash the section data
        if section_end <= pe_data.len() {
            hasher.update(&pe_data[section_start..section_end]);
            sum_of_bytes_hashed += section.size_of_raw_data as usize;
        }
    }

    // Region 5: Hash any extra data between SUM_OF_BYTES_HASHED and the
    // certificate table (or end of file). Per Authenticode spec step 14:
    //   extra_start = SUM_OF_BYTES_HASHED (as file offset)
    //   extra_end   = FILE_SIZE - Size_of_CertificateTable
    let file_end = if info.cert_table_size > 0 {
        pe_data.len().saturating_sub(info.cert_table_size as usize)
    } else {
        pe_data.len()
    };

    if sum_of_bytes_hashed < file_end && file_end <= pe_data.len() {
        hasher.update(&pe_data[sum_of_bytes_hashed..file_end]);
    }

    Ok(hasher.finalize().into())
}

/// Parse PE file to extract information needed for hash calculation
fn parse_pe_for_hash(pe_data: &[u8]) -> Result<PeInfo, AuthError> {
    // Use the shared PE parser from pe/mod.rs
    let headers = parse_headers(pe_data).map_err(|_| AuthError::InvalidHeader)?;

    // Calculate checksum offset (same offset from optional header for PE32 and PE32+)
    let checksum_offset = headers.checksum_offset();

    // Calculate certificate table entry offset
    let cert_table_entry_offset = headers
        .data_directory_offset(IMAGE_DIRECTORY_ENTRY_SECURITY)
        .unwrap_or(pe_data.len());

    // Read certificate table info (RVA and size)
    let (cert_table_rva, cert_table_size) = headers
        .data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY)
        .unwrap_or((0, 0));

    // Collect sections and sort by file offset
    let mut sections: Vec<SectionInfo> = headers
        .sections()
        .filter(|s| s.size_of_raw_data > 0 && s.pointer_to_raw_data > 0)
        .map(|s| SectionInfo {
            file_offset: s.pointer_to_raw_data,
            size_of_raw_data: s.size_of_raw_data,
        })
        .collect();

    // Sort sections by file offset
    sections.sort_by_key(|s| s.file_offset);

    Ok(PeInfo {
        checksum_offset,
        cert_table_entry_offset,
        size_of_headers: headers.size_of_headers as usize,
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
    let cert_end = cert_offset
        .checked_add(info.cert_table_size as usize)
        .ok_or(AuthError::InvalidHeader)?;

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
    let pkcs7_start = cert_offset.checked_add(8).ok_or(AuthError::InvalidHeader)?;
    let pkcs7_len = dw_length.saturating_sub(8);
    let pkcs7_end = pkcs7_start
        .checked_add(pkcs7_len)
        .ok_or(AuthError::InvalidHeader)?;

    if pkcs7_end > pe_data.len() {
        return Err(AuthError::InvalidHeader);
    }

    Ok(Some(AuthenticodeSignature {
        pkcs7_data: &pe_data[pkcs7_start..pkcs7_end],
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
            verify_authenticode_signature(&image_hash, &sig)
        }
        None => {
            log::warn!("Secure Boot: Unsigned image not in db");
            Ok(false)
        }
    }
}

/// Extract the Authenticode hash from the SpcIndirectDataContent in a PKCS#7 signature.
///
/// The SpcIndirectDataContent structure (Microsoft Authenticode) contains:
/// ```text
/// SpcIndirectDataContent ::= SEQUENCE {
///     data            SpcAttributeTypeAndOptionalValue,
///     messageDigest   DigestInfo ::= SEQUENCE {
///         digestAlgorithm  AlgorithmIdentifier,
///         digest           OCTET STRING
///     }
/// }
/// ```
///
/// This function parses the eContent from the PKCS#7 SignedData and extracts
/// the hash from the DigestInfo, which should match our computed Authenticode hash.
fn extract_spc_authenticode_hash(pkcs7_data: &[u8]) -> Result<Option<Vec<u8>>, AuthError> {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::asn1::OctetStringRef;
    use der::{Decode, Encode, Reader, SliceReader, Tagged};

    let actual_pkcs7 = super::crypto::trim_der_trailing_bytes(pkcs7_data)?;
    let content_info = ContentInfo::from_der(actual_pkcs7).map_err(|_| AuthError::InvalidHeader)?;
    let signed_data_bytes = content_info
        .content
        .to_der()
        .map_err(|_| AuthError::InvalidHeader)?;
    let cms_signed_data =
        SignedData::from_der(&signed_data_bytes).map_err(|_| AuthError::InvalidHeader)?;

    let econtent = match cms_signed_data.encap_content_info.econtent {
        Some(ref ec) => ec,
        None => return Ok(None),
    };

    // Get SpcIndirectDataContent bytes for parsing.
    // If eContent is OCTET STRING, the value is the DER of SpcIndirectDataContent.
    // If eContent is a SEQUENCE (direct encoding), we need the full DER.
    let spc_owned: Vec<u8>;
    let spc_data: &[u8] = if econtent.tag() == der::Tag::OctetString {
        econtent.value()
    } else {
        spc_owned = econtent.to_der().map_err(|_| AuthError::InvalidHeader)?;
        &spc_owned
    };

    // Parse SpcIndirectDataContent SEQUENCE to extract the digest
    let mut reader = SliceReader::new(spc_data).map_err(|_| AuthError::InvalidHeader)?;
    let hash = reader
        .sequence(|seq| {
            // Skip SpcAttributeTypeAndOptionalValue (first element)
            let _ = seq.tlv_bytes()?;
            // Parse DigestInfo SEQUENCE (second element)
            seq.sequence(|digest_seq| {
                // Skip AlgorithmIdentifier
                let _ = digest_seq.tlv_bytes()?;
                // Read digest OCTET STRING
                let digest: OctetStringRef = digest_seq.decode()?;
                Ok(digest.as_bytes().to_vec())
            })
        })
        .map_err(|_: der::Error| AuthError::InvalidHeader)?;

    Ok(Some(hash))
}

/// Verify an Authenticode signature against the db database
fn verify_authenticode_signature(
    image_hash: &[u8],
    sig: &AuthenticodeSignature,
) -> Result<bool, AuthError> {
    // Verify the Authenticode hash matches what's embedded in the PKCS#7's
    // SpcIndirectDataContent. This prevents signature transplant attacks where
    // a valid signature from one PE image is attached to a different image.
    match extract_spc_authenticode_hash(sig.pkcs7_data) {
        Ok(Some(ref spc_hash)) => {
            if !super::crypto::constant_time_eq(spc_hash, image_hash) {
                log::warn!(
                    "Authenticode hash in SpcIndirectDataContent does not match computed image hash"
                );
                log::debug!(
                    "SPC hash: {:02x?}, image hash: {:02x?}",
                    &spc_hash[..core::cmp::min(8, spc_hash.len())],
                    &image_hash[..core::cmp::min(8, image_hash.len())]
                );
                return Ok(false);
            }
            log::debug!("Authenticode hash matches SpcIndirectDataContent");
        }
        Ok(None) => {
            log::warn!("No SpcIndirectDataContent found in PKCS#7 signature");
            return Ok(false);
        }
        Err(e) => {
            log::debug!("Failed to extract SPC authenticode hash: {:?}", e);
            return Ok(false);
        }
    }

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

        match verify_pkcs7_signature(sig.pkcs7_data, image_hash, cert_der) {
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
