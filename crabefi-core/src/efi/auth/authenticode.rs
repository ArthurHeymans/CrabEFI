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
#[cfg(feature = "secure-boot")]
use super::crypto::verify_pkcs7_signature_chain;
#[cfg(feature = "secure-boot")]
use super::signature::certificate_forbidden;
#[cfg(feature = "secure-boot")]
use super::variables::{KeyDatabase, db_database, dbx_database};
use crate::efi::digest::{
    SHA1_DIGEST_SIZE, SHA256_DIGEST_SIZE, SHA384_DIGEST_SIZE, SHA512_DIGEST_SIZE, TPM_ALG_SHA1,
    TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, TaggedDigest, digest_size_for_algorithm,
};
use crate::pe::{DATA_DIRECTORY_ENTRY_SIZE, IMAGE_DIRECTORY_ENTRY_SECURITY, parse_headers};
use alloc::vec::Vec;

#[cfg(feature = "secure-boot")]
use crabefi_efi_types::{constant_time_eq, secure_boot::EFI_CERT_TYPE_PKCS7_GUID};
#[cfg(feature = "secure-boot")]
use crabefi_pkcs7::cms::SignedData;
#[cfg(feature = "secure-boot")]
use crabefi_pkcs7::der::{DecodeError, Tlv, tag};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// WIN_CERTIFICATE header type for PKCS#7
#[cfg(feature = "secure-boot")]
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
    let digest = compute_authenticode_hash_inner(pe_data, &info, TPM_ALG_SHA256)?;
    let mut sha256 = [0u8; SHA256_DIGEST_SIZE];
    sha256.copy_from_slice(&digest[..SHA256_DIGEST_SIZE]);
    Ok(sha256)
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

/// WIN_CERTIFICATE type carrying a WIN_CERTIFICATE_UEFI_GUID
#[cfg(feature = "secure-boot")]
const WIN_CERT_TYPE_EFI_GUID: u16 = 0x0EF1;

/// Size of the WIN_CERTIFICATE header
#[cfg(feature = "secure-boot")]
const WIN_CERTIFICATE_HEADER_SIZE: usize = 8;

/// PKCS#7 SignedData of every Authenticode signature in the attribute
/// certificate table, in table order.
///
/// Entries are 8-byte aligned (PE/COFF 4.7) and must end exactly at the end
/// of the table, otherwise the table is corrupt (EDK2
/// DxeImageVerificationLib rejects such images too). Certificate types other
/// than PKCS#7 are skipped.
#[cfg(feature = "secure-boot")]
fn authenticode_signatures(pe_data: &[u8]) -> Result<Vec<&[u8]>, AuthError> {
    let info = parse_pe_for_hash(pe_data)?;
    if info.cert_table_rva == 0 || info.cert_table_size == 0 {
        return Ok(Vec::new());
    }
    // The certificate table is located by file offset, not RVA.
    let start = info.cert_table_rva as usize;
    let table = start
        .checked_add(info.cert_table_size as usize)
        .and_then(|end| pe_data.get(start..end))
        .ok_or_else(|| {
            log::warn!("Certificate table extends beyond file");
            AuthError::InvalidHeader
        })?;
    let mut signatures = Vec::new();
    let mut offset = 0usize;
    while let Some(entry) = table.get(offset..).filter(|entry| !entry.is_empty()) {
        let header = entry
            .get(..WIN_CERTIFICATE_HEADER_SIZE)
            .filter(|_| entry.len() > WIN_CERTIFICATE_HEADER_SIZE)
            .ok_or(AuthError::InvalidHeader)?;
        let length = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let certificate_type = u16::from_le_bytes([header[6], header[7]]);
        let body = entry
            .get(WIN_CERTIFICATE_HEADER_SIZE..length)
            .filter(|body| !body.is_empty())
            .ok_or(AuthError::InvalidHeader)?;
        match certificate_type {
            WIN_CERT_TYPE_PKCS_SIGNED_DATA => signatures.push(body),
            WIN_CERT_TYPE_EFI_GUID => {
                let (cert_type, data) = body
                    .split_at_checked(16)
                    .filter(|(_, data)| !data.is_empty())
                    .ok_or(AuthError::InvalidHeader)?;
                if cert_type == EFI_CERT_TYPE_PKCS7_GUID {
                    signatures.push(data);
                }
            }
            other => log::debug!("Skipping certificate type {:#x}", other),
        }
        offset = offset
            .checked_add(length.next_multiple_of(8))
            .ok_or(AuthError::InvalidHeader)?;
    }
    if offset != table.len() {
        log::warn!("Attribute certificate table is corrupt");
        return Err(AuthError::InvalidHeader);
    }
    Ok(signatures)
}

/// Verify a PE image for Secure Boot against the current db and dbx.
///
/// * `Ok(true)` - Image is authorized for execution
/// * `Ok(false)` - Image is NOT authorized
/// * `Err(...)` - Malformed image or certificate table
#[cfg(feature = "secure-boot")]
pub fn verify_pe_image_secure_boot(pe_data: &[u8]) -> Result<bool, AuthError> {
    let db = db_database();
    let dbx = dbx_database();
    verify_pe_image(pe_data, &db, &dbx)
}

/// UEFI 2.10 chapter 32 image verification, over every signature as in
/// EDK2's DxeImageVerificationHandler:
///
/// 1. Reject if the image hash is in dbx, or if any signature is revoked by
///    dbx (see [`signature_forbidden`]), whatever the other signatures say.
/// 2. Otherwise accept if any signature verifies against a certificate in db,
///    or if the image hash is in db.
#[cfg(feature = "secure-boot")]
fn verify_pe_image(pe_data: &[u8], db: &KeyDatabase, dbx: &KeyDatabase) -> Result<bool, AuthError> {
    let image_hash = compute_authenticode_hash(pe_data)?;
    log::debug!("PE Authenticode hash: {:02x?}", &image_hash[..8]);
    if dbx.contains_sha256_hash(&image_hash) {
        log::warn!("Secure Boot: Image hash is in forbidden database (dbx)");
        return Ok(false);
    }

    let signatures = authenticode_signatures(pe_data)?;
    let mut allowed = false;
    for (index, pkcs7) in signatures.iter().enumerate() {
        let covers_image = signature_covers_image(pkcs7, &image_hash);
        if signature_forbidden(pkcs7, &image_hash, covers_image, dbx) {
            log::warn!("Secure Boot: Signature {} is revoked by dbx", index);
            return Ok(false);
        }
        if !allowed && covers_image && signature_allowed(pkcs7, &image_hash, db, dbx) {
            log::info!("Secure Boot: Signature {} verified against db", index);
            allowed = true;
        }
    }
    if allowed {
        return Ok(true);
    }
    if db.contains_sha256_hash(&image_hash) {
        log::info!("Secure Boot: Image hash found in allowed database (db)");
        return Ok(true);
    }
    log::warn!(
        "Secure Boot: None of {} signatures verified and the image hash is not in db",
        signatures.len()
    );
    Ok(false)
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
#[cfg(feature = "secure-boot")]
fn extract_spc_authenticode_hash(pkcs7_data: &[u8]) -> Result<Option<&[u8]>, AuthError> {
    let signed = SignedData::parse(pkcs7_data).map_err(|_| AuthError::InvalidHeader)?;
    signed
        .encapsulated_content
        .content
        .map(spc_digest)
        .transpose()
        .map_err(|_| AuthError::InvalidHeader)
}

/// Digest from an eContent carrying SpcIndirectDataContent, either directly
/// (the SEQUENCE itself) or wrapped in an OCTET STRING.
#[cfg(feature = "secure-boot")]
fn spc_digest(econtent: Tlv<'_>) -> Result<&[u8], DecodeError> {
    let spc = match econtent.tag {
        tag::OCTET_STRING => econtent.inner()?,
        _ => econtent,
    };
    let mut fields = spc.contents(tag::SEQUENCE)?;
    // SpcAttributeTypeAndOptionalValue (skipped).
    fields.read()?;
    let mut digest_info = fields.read()?.contents(tag::SEQUENCE)?;
    fields.finish()?;
    digest_info.read()?;
    let digest = digest_info.read()?.octet_string()?;
    digest_info.finish()?;
    Ok(digest)
}

/// Whether the SpcIndirectDataContent digest of `pkcs7` is this image's
/// Authenticode hash. A signature over other content proves nothing about
/// the image; checking it prevents signature transplants.
#[cfg(feature = "secure-boot")]
fn signature_covers_image(pkcs7: &[u8], image_hash: &[u8; 32]) -> bool {
    match extract_spc_authenticode_hash(pkcs7) {
        Ok(Some(spc_hash)) if constant_time_eq(spc_hash, image_hash) => true,
        Ok(Some(_)) => {
            log::warn!("Authenticode digest in SpcIndirectDataContent does not match the image");
            false
        }
        Ok(None) => {
            log::warn!("No SpcIndirectDataContent found in PKCS#7 signature");
            false
        }
        Err(e) => {
            log::debug!("Failed to extract SPC authenticode hash: {:?}", e);
            false
        }
    }
}

/// EDK2 IsForbiddenByDbx: a signature is revoked when a certificate it
/// carries is in dbx (as X.509 or as TBSCertificate hash), or when it
/// verifies up to an X.509 certificate in dbx. An unparsable signature
/// counts as revoked.
#[cfg(feature = "secure-boot")]
fn signature_forbidden(
    pkcs7: &[u8],
    image_hash: &[u8; 32],
    covers_image: bool,
    dbx: &KeyDatabase,
) -> bool {
    let Ok(signed) = SignedData::parse(pkcs7) else {
        log::warn!("Secure Boot: Unparsable Authenticode signature");
        return true;
    };
    if signed
        .certificates()
        .any(|certificate| certificate_forbidden(dbx, certificate.encoded))
    {
        return true;
    }
    covers_image
        && dbx.x509_certificates().any(|revoked| {
            matches!(
                verify_pkcs7_signature_chain(pkcs7, image_hash, revoked, false),
                Ok(Some(_))
            )
        })
}

/// Whether `pkcs7` verifies up to a db certificate through a chain without
/// dbx-revoked certificates.
#[cfg(feature = "secure-boot")]
fn signature_allowed(
    pkcs7: &[u8],
    image_hash: &[u8; 32],
    db: &KeyDatabase,
    dbx: &KeyDatabase,
) -> bool {
    db.x509_certificates()
        .filter(|trusted| !certificate_forbidden(dbx, trusted))
        .any(
            |trusted| match verify_pkcs7_signature_chain(pkcs7, image_hash, trusted, false) {
                Ok(Some(chain)) => !chain
                    .certificates
                    .iter()
                    .any(|certificate| certificate_forbidden(dbx, certificate)),
                Ok(None) => false,
                Err(e) => {
                    log::debug!("Secure Boot: Signature verification error: {:?}", e);
                    false
                }
            },
        )
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

    /// SpcIndirectDataContent over 32 known digest bytes: a dummy
    /// SpcAttributeTypeAndOptionalValue followed by a SHA-256 DigestInfo.
    #[cfg(feature = "secure-boot")]
    fn spc_indirect_data() -> (Vec<u8>, [u8; 32]) {
        let digest = [0xabu8; 32];
        let mut spc = alloc::vec![
            0x30, 0x3c, // SpcIndirectDataContent SEQUENCE
            0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, // SEQUENCE { OID }
            0x30, 0x31, // DigestInfo SEQUENCE
            0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, // sha256 AlgorithmIdentifier
            0x04, 0x20, // digest OCTET STRING
        ];
        spc.extend_from_slice(&digest);
        (spc, digest)
    }

    #[cfg(feature = "secure-boot")]
    #[test]
    fn spc_digest_accepts_direct_and_wrapped_econtent() {
        let (spc, digest) = spc_indirect_data();
        let mut wrapped = alloc::vec![0x04, spc.len() as u8];
        wrapped.extend_from_slice(&spc);
        for econtent in [&spc, &wrapped] {
            assert_eq!(spc_digest(Tlv::parse(econtent).unwrap()), Ok(&digest[..]));
        }

        // Trailing bytes inside the wrapper or the SEQUENCE are rejected.
        let mut padded_wrapper = alloc::vec![0x04, spc.len() as u8 + 1];
        padded_wrapper.extend_from_slice(&spc);
        padded_wrapper.push(0);
        assert!(spc_digest(Tlv::parse(&padded_wrapper).unwrap()).is_err());
        let mut padded_spc = spc.clone();
        padded_spc[1] += 1;
        padded_spc.push(0);
        assert!(spc_digest(Tlv::parse(&padded_spc).unwrap()).is_err());
        // Not a SEQUENCE.
        assert!(spc_digest(Tlv::parse(&[0x31, 0x00]).unwrap()).is_err());
    }

    /// Images from testdata/gen_authenticode.py, both over the same image:
    /// DUAL carries a rogue then a db-signer signature, REVERSED the other way.
    #[cfg(feature = "secure-boot")]
    mod multiple_signatures {
        use super::super::super::variables::KeyDatabaseEntry;
        use super::*;
        use crabefi_efi_types::secure_boot::{
            EFI_CERT_SHA256_GUID, EFI_CERT_X509_GUID, EFI_CERT_X509_SHA256_GUID,
        };

        const DUAL: &[u8] = include_bytes!("testdata/authenticode-dual.efi");
        const REVERSED: &[u8] = include_bytes!("testdata/authenticode-dual-reversed.efi");
        const DB_CA: &[u8] = include_bytes!("testdata/authenticode-db-ca.der");
        const DB_SIGNER: &[u8] = include_bytes!("testdata/authenticode-db-signer.der");
        const ROGUE: &[u8] = include_bytes!("testdata/authenticode-rogue.der");

        fn database(entries: &[([u8; 16], &[u8])]) -> KeyDatabase {
            let mut database = KeyDatabase::new();
            for (cert_type, data) in entries {
                database
                    .add_entry(KeyDatabaseEntry {
                        cert_type: *cert_type,
                        data: data.to_vec(),
                        owner: [0; 16],
                    })
                    .unwrap();
            }
            database
        }

        fn empty() -> KeyDatabase {
            KeyDatabase::new()
        }

        /// EFI_CERT_X509_SHA256 entry: TBSCertificate hash, no revocation time.
        fn tbs_hash(certificate: &[u8]) -> Vec<u8> {
            let tbs = crabefi_pkcs7::x509::Certificate::parse(certificate)
                .unwrap()
                .tbs;
            let mut entry = Sha256::digest(tbs).to_vec();
            entry.extend_from_slice(&[0; 16]);
            entry
        }

        #[test]
        fn any_signature_verifying_against_db_authorizes_the_image() {
            for image in [DUAL, REVERSED] {
                assert_eq!(
                    authenticode_signatures(image).map(|signatures| signatures.len()),
                    Ok(2)
                );
                for trusted in [DB_CA, DB_SIGNER] {
                    let db = database(&[(EFI_CERT_X509_GUID, trusted)]);
                    assert_eq!(verify_pe_image(image, &db, &empty()), Ok(true));
                }
                assert_eq!(verify_pe_image(image, &empty(), &empty()), Ok(false));
            }
        }

        #[test]
        fn a_revoked_signature_rejects_the_image_whatever_the_others_say() {
            let db = database(&[(EFI_CERT_X509_GUID, DB_CA)]);
            let rogue_tbs = tbs_hash(ROGUE);
            let signer_tbs = tbs_hash(DB_SIGNER);
            for dbx in [
                database(&[(EFI_CERT_X509_GUID, ROGUE)]),
                database(&[(EFI_CERT_X509_SHA256_GUID, &rogue_tbs)]),
                database(&[(EFI_CERT_X509_SHA256_GUID, &signer_tbs)]),
                // The issuer of the db signer, which its signature does not carry.
                database(&[(EFI_CERT_X509_GUID, DB_CA)]),
            ] {
                for image in [DUAL, REVERSED] {
                    assert_eq!(verify_pe_image(image, &db, &dbx), Ok(false));
                }
            }

            // An image hash in db does not override a revoked signature, and
            // an image hash in dbx overrides a valid one.
            let image_hash = compute_authenticode_hash(DUAL).unwrap();
            let hash_db = database(&[(EFI_CERT_SHA256_GUID, &image_hash)]);
            assert_eq!(verify_pe_image(DUAL, &hash_db, &empty()), Ok(true));
            let dbx = database(&[(EFI_CERT_X509_GUID, ROGUE)]);
            assert_eq!(verify_pe_image(DUAL, &hash_db, &dbx), Ok(false));
            assert_eq!(verify_pe_image(DUAL, &db, &hash_db), Ok(false));
        }

        fn read_u32(image: &[u8], offset: usize) -> u32 {
            u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap())
        }

        /// File offset of the PE32+ security directory entry of `image`.
        fn security_directory(image: &[u8]) -> usize {
            read_u32(image, 0x3c) as usize + 24 + 112 + 4 * 8
        }

        /// `image` with its certificate table size changed by `size`.
        fn with_table_size(image: &[u8], size: impl Fn(u32) -> u32) -> Vec<u8> {
            let entry = security_directory(image) + 4;
            let mut image = image.to_vec();
            let resized = size(read_u32(&image, entry));
            image[entry..entry + 4].copy_from_slice(&resized.to_le_bytes());
            image
        }

        #[test]
        fn corrupt_certificate_tables_are_rejected() {
            let db = database(&[(EFI_CERT_X509_GUID, DB_CA)]);
            // The last entry no longer fits.
            let truncated = with_table_size(DUAL, |size| size - 8);
            // Eight zero bytes after the last entry.
            let mut padded = with_table_size(DUAL, |size| size + 8);
            padded.extend_from_slice(&[0; 8]);
            // A first entry whose length overruns the table.
            let table = read_u32(DUAL, security_directory(DUAL)) as usize;
            let mut overrun = DUAL.to_vec();
            overrun[table..table + 4].copy_from_slice(&4000u32.to_le_bytes());
            for image in [truncated, padded, overrun] {
                assert_eq!(
                    authenticode_signatures(&image),
                    Err(AuthError::InvalidHeader)
                );
                assert!(!matches!(verify_pe_image(&image, &db, &empty()), Ok(true)));
            }
        }
    }
}
