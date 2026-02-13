//! UEFI Secure Boot Authentication
//!
//! This module implements UEFI Authenticated Variable support as defined in the
//! UEFI Specification Chapter 8 (Secure Boot and Driver Signing).
//!
//! # Overview
//!
//! UEFI Secure Boot uses time-based authenticated writes to protect critical
//! security variables:
//!
//! - **PK** (Platform Key): Single certificate that controls who can modify KEK
//! - **KEK** (Key Exchange Key): Certificates that can modify db/dbx
//! - **db** (Signature Database): Allowed signatures for boot images
//! - **dbx** (Forbidden Signature Database): Revoked signatures
//!
//! # Authentication Flow
//!
//! 1. SetVariable is called with `EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS`
//! 2. The variable data is prefixed with `EFI_VARIABLE_AUTHENTICATION_2` header
//! 3. The header contains a PKCS#7 signature and timestamp
//! 4. The signature is verified against the appropriate key database
//! 5. The timestamp must be monotonically increasing
//!
//! # Setup Mode vs User Mode
//!
//! - **Setup Mode**: When PK is empty, authenticated writes skip signature verification
//! - **User Mode**: When PK is enrolled, all authenticated variable writes require valid signatures

pub mod authenticode;
pub mod boot;
mod crypto;
pub mod dbx_update;
pub mod enrollment;
pub mod key_files;
pub mod revocation;
mod signature;
mod structures;
pub(crate) mod time;
mod variables;

pub use authenticode::verify_pe_image_secure_boot;
pub use crypto::*;
pub use signature::*;
pub use structures::*;
pub use variables::*;

use r_efi::efi::Guid;

// ============================================================================
// GUID Helper Functions
// ============================================================================

/// Convert a Guid to raw bytes (shared utility for auth submodules)
pub(crate) fn guid_to_bytes(guid: &Guid) -> [u8; 16] {
    let bytes = guid.as_bytes();
    let mut result = [0u8; 16];
    result.copy_from_slice(bytes);
    result
}

// ============================================================================
// DER Encoding Helpers
// ============================================================================

/// Maximum DER length we'll accept (64 MB)
/// This prevents DoS attacks with maliciously crafted length fields
const MAX_DER_LENGTH: usize = 64 * 1024 * 1024;

/// Parse DER length encoding
///
/// Returns `(length, bytes_consumed)` on success.
pub(crate) fn parse_der_length(data: &[u8]) -> Result<(usize, usize), AuthError> {
    if data.is_empty() {
        return Err(AuthError::CertificateParseError);
    }

    let first = data[0];
    if first < 0x80 {
        // Short form: length is in the first byte
        Ok((first as usize, 1))
    } else if first == 0x80 {
        // Indefinite length - not supported
        Err(AuthError::CertificateParseError)
    } else {
        // Long form: first byte indicates number of length bytes
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || num_bytes + 1 > data.len() {
            return Err(AuthError::CertificateParseError);
        }

        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | (data[1 + i] as usize);
        }

        // Reject unreasonably large lengths to prevent DoS
        if length > MAX_DER_LENGTH {
            log::warn!("DER length {} exceeds maximum {}", length, MAX_DER_LENGTH);
            return Err(AuthError::CertificateParseError);
        }

        Ok((length, 1 + num_bytes))
    }
}

// ============================================================================
// Disk Search Helpers
// ============================================================================

/// Iterate over all available block devices (NVMe, AHCI, SDHCI) and call a
/// function on each. Returns `Some(T)` as soon as the callback returns `Some`.
///
/// This avoids duplicating the controller-enumeration boilerplate in
/// `key_files.rs` and `dbx_update.rs`.
pub(crate) fn search_all_disks<T>(
    mut f: impl FnMut(&mut dyn crate::drivers::block::BlockDevice, &'static str) -> Option<T>,
) -> Option<T> {
    // NVMe
    if let Some(result) = search_nvme_disks(&mut f) {
        return Some(result);
    }

    // AHCI
    if let Some(result) = search_ahci_disks(&mut f) {
        return Some(result);
    }

    // SDHCI
    search_sdhci_disks(&mut f)
}

fn search_nvme_disks<T>(
    f: &mut impl FnMut(&mut dyn crate::drivers::block::BlockDevice, &'static str) -> Option<T>,
) -> Option<T> {
    use crate::drivers::{block::NvmeDisk, nvme};

    // First borrow: get namespace info, then drop the reference
    let nsid = {
        let controller_ptr = nvme::get_controller(0)?;
        let controller = unsafe { &*controller_ptr };
        controller.default_namespace().map(|ns| ns.nsid)?
    };

    // Second borrow: create disk for I/O
    let controller_ptr = nvme::get_controller(0)?;
    let controller = unsafe { &mut *controller_ptr };
    let mut disk = NvmeDisk::new(controller, nsid);
    f(&mut disk, "NVMe")
}

fn search_ahci_disks<T>(
    f: &mut impl FnMut(&mut dyn crate::drivers::block::BlockDevice, &'static str) -> Option<T>,
) -> Option<T> {
    use crate::drivers::{ahci, block::AhciDisk};

    let controller_ptr = ahci::get_controller(0)?;
    let num_ports = unsafe { &*controller_ptr }.num_active_ports();

    for port_index in 0..num_ports {
        if let Some(controller_ptr) = ahci::get_controller(0) {
            let controller = unsafe { &mut *controller_ptr };
            let mut disk = AhciDisk::new(controller, port_index);
            if let Some(result) = f(&mut disk, "SATA") {
                return Some(result);
            }
        }
    }

    None
}

fn search_sdhci_disks<T>(
    f: &mut impl FnMut(&mut dyn crate::drivers::block::BlockDevice, &'static str) -> Option<T>,
) -> Option<T> {
    use crate::drivers::{block::SdhciDisk, sdhci};

    for controller_id in 0..sdhci::controller_count() {
        let controller_ptr = sdhci::get_controller(controller_id)?;
        let controller = unsafe { &mut *controller_ptr };
        if !controller.is_ready() {
            continue;
        }

        let controller_ptr = sdhci::get_controller(controller_id)?;
        let controller = unsafe { &mut *controller_ptr };
        let mut disk = SdhciDisk::new(controller);
        if let Some(result) = f(&mut disk, "SD") {
            return Some(result);
        }
    }

    None
}

// ============================================================================
// Variable Attributes
// ============================================================================

/// Variable attribute flags (UEFI Specification Table 8-1)
pub mod attributes {
    /// Variable is non-volatile (persists across resets)
    pub const NON_VOLATILE: u32 = 0x00000001;

    /// Variable is accessible during Boot Services
    pub const BOOTSERVICE_ACCESS: u32 = 0x00000002;

    /// Variable is accessible at Runtime (after ExitBootServices)
    pub const RUNTIME_ACCESS: u32 = 0x00000004;

    /// Variable contains hardware error record
    pub const HARDWARE_ERROR_RECORD: u32 = 0x00000008;

    /// Variable uses time-based authenticated write access
    /// When set, data must be prefixed with EFI_VARIABLE_AUTHENTICATION_2
    pub const TIME_BASED_AUTHENTICATED_WRITE_ACCESS: u32 = 0x00000020;

    /// Append data to existing variable (for signature databases)
    /// When set with authenticated write, appends signatures instead of replacing
    pub const APPEND_WRITE: u32 = 0x00000040;

    /// Variable is authenticated with a monotonic count (deprecated)
    /// This is the legacy authentication method, superseded by time-based auth
    #[allow(dead_code)]
    pub const AUTHENTICATED_WRITE_ACCESS: u32 = 0x00000010;

    /// Combined attributes for typical Secure Boot variables
    pub const SECURE_BOOT_ATTRS: u32 =
        NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS | TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
}

// ============================================================================
// Secure Boot GUIDs
// ============================================================================

/// EFI Global Variable GUID
/// Used for: PK, KEK, SetupMode, SecureBoot, SignatureSupport, etc.
pub const EFI_GLOBAL_VARIABLE_GUID: Guid = Guid::from_fields(
    0x8BE4DF61,
    0x93CA,
    0x11D2,
    0xAA,
    0x0D,
    &[0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
);

/// EFI Image Security Database GUID
/// Used for: db, dbx, dbt, dbr
pub const EFI_IMAGE_SECURITY_DATABASE_GUID: Guid = Guid::from_fields(
    0xD719B2CB,
    0x3D3A,
    0x4596,
    0xA3,
    0xBC,
    &[0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F],
);

/// Certificate Type GUID for X.509 certificates
pub const EFI_CERT_X509_GUID: Guid = Guid::from_fields(
    0xA5C059A1,
    0x94E4,
    0x4AA7,
    0x87,
    0xB5,
    &[0xAB, 0x15, 0x5C, 0x2B, 0xF0, 0x72],
);

/// Certificate Type GUID for RSA-2048 public keys
pub const EFI_CERT_RSA2048_GUID: Guid = Guid::from_fields(
    0x3C5766E8,
    0x269C,
    0x4E34,
    0xAA,
    0x14,
    &[0xED, 0x77, 0x6E, 0x85, 0xB3, 0xB6],
);

/// Certificate Type GUID for SHA-256 hashes
pub const EFI_CERT_SHA256_GUID: Guid = Guid::from_fields(
    0xC1C41626,
    0x504C,
    0x4092,
    0xAC,
    0xA9,
    &[0x41, 0xF9, 0x36, 0x93, 0x43, 0x28],
);

/// Certificate Type GUID for PKCS#7 signatures
pub const EFI_CERT_TYPE_PKCS7_GUID: Guid = Guid::from_fields(
    0x4AAFD29D,
    0x68DF,
    0x49EE,
    0x8A,
    0xA9,
    &[0x34, 0x7D, 0x37, 0x56, 0x65, 0xA7],
);

/// WIN_CERTIFICATE revision
pub const WIN_CERT_REVISION: u16 = 0x0200;

/// WIN_CERTIFICATE type for PKCS#7 signed data
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

/// WIN_CERTIFICATE type for EFI GUID
pub const WIN_CERT_TYPE_EFI_GUID: u16 = 0x0EF1;

// ============================================================================
// Secure Boot State
// ============================================================================

use core::sync::atomic::{AtomicBool, Ordering};

/// Whether Secure Boot is in Setup Mode (PK not enrolled)
static SETUP_MODE: AtomicBool = AtomicBool::new(true);

/// Whether Secure Boot is enabled
static SECURE_BOOT_ENABLED: AtomicBool = AtomicBool::new(false);

/// Variable attributes for the SecureBootEnable user preference variable
/// This is non-volatile so it persists across resets
const SECURE_BOOT_ENABLE_ATTRS: u32 =
    attributes::NON_VOLATILE | attributes::BOOTSERVICE_ACCESS | attributes::RUNTIME_ACCESS;

/// Check if we're in Setup Mode
pub fn is_setup_mode() -> bool {
    SETUP_MODE.load(Ordering::Acquire)
}

/// Check if Secure Boot is enabled
pub fn is_secure_boot_enabled() -> bool {
    SECURE_BOOT_ENABLED.load(Ordering::Acquire)
}

/// Enter User Mode (called when PK is enrolled)
pub fn enter_user_mode() {
    SETUP_MODE.store(false, Ordering::Release);
    log::info!("Secure Boot: Entering User Mode");
}

/// Enter Setup Mode (called when PK is deleted)
pub fn enter_setup_mode() {
    SETUP_MODE.store(true, Ordering::Release);
    SECURE_BOOT_ENABLED.store(false, Ordering::Release);
    log::info!("Secure Boot: Entering Setup Mode");
}

/// Enable Secure Boot (only valid in User Mode)
pub fn enable_secure_boot() {
    if !is_setup_mode() {
        SECURE_BOOT_ENABLED.store(true, Ordering::Release);
        log::info!("Secure Boot: Enabled");
        // Persist the user preference to SPI flash
        persist_secure_boot_enable_preference(true);
    }
}

/// Disable Secure Boot
pub fn disable_secure_boot() {
    SECURE_BOOT_ENABLED.store(false, Ordering::Release);
    log::info!("Secure Boot: Disabled");
    // Persist the user preference to SPI flash
    persist_secure_boot_enable_preference(false);
}

/// Persist the SecureBootEnable preference to non-volatile storage
fn persist_secure_boot_enable_preference(enabled: bool) {
    use crate::efi::varstore::{persist_variable, update_variable_in_memory};
    use variables::SECURE_BOOT_ENABLE_NAME;

    let value: u8 = if enabled { 1 } else { 0 };

    // Update the in-memory cache
    update_variable_in_memory(
        &EFI_GLOBAL_VARIABLE_GUID,
        SECURE_BOOT_ENABLE_NAME,
        SECURE_BOOT_ENABLE_ATTRS,
        &[value],
    );

    // Persist to SPI flash
    if let Err(e) = persist_variable(
        &EFI_GLOBAL_VARIABLE_GUID,
        SECURE_BOOT_ENABLE_NAME,
        SECURE_BOOT_ENABLE_ATTRS,
        &[value],
    ) {
        log::warn!("Failed to persist SecureBootEnable preference: {:?}", e);
    } else {
        log::debug!("SecureBootEnable preference persisted: {}", enabled);
    }
}

// ============================================================================
// Authentication Error Types
// ============================================================================

/// Errors that can occur during authentication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Invalid authentication header
    InvalidHeader,
    /// Invalid timestamp (not monotonically increasing)
    InvalidTimestamp,
    /// Signature verification failed
    SignatureVerificationFailed,
    /// No suitable key found in key database
    NoSuitableKey,
    /// Certificate parsing error
    CertificateParseError,
    /// Certificate is not yet valid (current time < notBefore)
    CertificateNotYetValid,
    /// Certificate has expired (current time > notAfter)
    CertificateExpired,
    /// Certificate is not a CA (missing basicConstraints CA:TRUE)
    CertificateNotCA,
    /// Certificate has invalid key usage for the operation
    InvalidKeyUsage,
    /// Invalid variable name for authenticated variable
    InvalidVariableName,
    /// Access denied (wrong key database used)
    AccessDenied,
    /// Secure Boot is disabled, cannot perform authenticated write
    SecureBootDisabled,
    /// Variable is write-protected
    WriteProtected,
    /// Invalid signature list format
    InvalidSignatureList,
    /// Cryptographic operation failed
    CryptoError,
    /// Buffer too small
    BufferTooSmall,
    /// Certificate has been revoked
    CertificateRevoked,
    /// Certificate chain too deep (exceeded maximum allowed depth)
    ChainTooDeep,
    /// Could not build a valid certificate chain to a trusted root
    ChainBuildingFailed,
}

impl From<AuthError> for r_efi::efi::Status {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::InvalidHeader => r_efi::efi::Status::INVALID_PARAMETER,
            AuthError::InvalidTimestamp => r_efi::efi::Status::SECURITY_VIOLATION,
            AuthError::SignatureVerificationFailed => r_efi::efi::Status::SECURITY_VIOLATION,
            AuthError::NoSuitableKey => r_efi::efi::Status::SECURITY_VIOLATION,
            AuthError::CertificateParseError => r_efi::efi::Status::INVALID_PARAMETER,
            AuthError::CertificateNotYetValid => r_efi::efi::Status::SECURITY_VIOLATION,
            AuthError::CertificateExpired => r_efi::efi::Status::SECURITY_VIOLATION,
            AuthError::CertificateNotCA => r_efi::efi::Status::SECURITY_VIOLATION,
            AuthError::InvalidKeyUsage => r_efi::efi::Status::SECURITY_VIOLATION,
            AuthError::InvalidVariableName => r_efi::efi::Status::INVALID_PARAMETER,
            AuthError::AccessDenied => r_efi::efi::Status::ACCESS_DENIED,
            AuthError::SecureBootDisabled => r_efi::efi::Status::SECURITY_VIOLATION,
            AuthError::WriteProtected => r_efi::efi::Status::WRITE_PROTECTED,
            AuthError::InvalidSignatureList => r_efi::efi::Status::INVALID_PARAMETER,
            AuthError::CryptoError => r_efi::efi::Status::DEVICE_ERROR,
            AuthError::BufferTooSmall => r_efi::efi::Status::BUFFER_TOO_SMALL,
            AuthError::CertificateRevoked => r_efi::efi::Status::SECURITY_VIOLATION,
            AuthError::ChainTooDeep => r_efi::efi::Status::SECURITY_VIOLATION,
            AuthError::ChainBuildingFailed => r_efi::efi::Status::SECURITY_VIOLATION,
        }
    }
}
