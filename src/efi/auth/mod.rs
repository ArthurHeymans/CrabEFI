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
pub mod enrollment;
mod signature;
mod structures;
mod variables;

pub use authenticode::verify_pe_image_secure_boot;
pub use crypto::*;
pub use signature::*;
pub use structures::*;
pub use variables::*;

use r_efi::efi::Guid;

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
    }
}

/// Disable Secure Boot
pub fn disable_secure_boot() {
    SECURE_BOOT_ENABLED.store(false, Ordering::Release);
    log::info!("Secure Boot: Disabled");
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
}

impl From<AuthError> for r_efi::efi::Status {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::InvalidHeader => r_efi::efi::Status::INVALID_PARAMETER,
            AuthError::InvalidTimestamp => r_efi::efi::Status::SECURITY_VIOLATION,
            AuthError::SignatureVerificationFailed => r_efi::efi::Status::SECURITY_VIOLATION,
            AuthError::NoSuitableKey => r_efi::efi::Status::SECURITY_VIOLATION,
            AuthError::CertificateParseError => r_efi::efi::Status::INVALID_PARAMETER,
            AuthError::InvalidVariableName => r_efi::efi::Status::INVALID_PARAMETER,
            AuthError::AccessDenied => r_efi::efi::Status::ACCESS_DENIED,
            AuthError::SecureBootDisabled => r_efi::efi::Status::SECURITY_VIOLATION,
            AuthError::WriteProtected => r_efi::efi::Status::WRITE_PROTECTED,
            AuthError::InvalidSignatureList => r_efi::efi::Status::INVALID_PARAMETER,
            AuthError::CryptoError => r_efi::efi::Status::DEVICE_ERROR,
            AuthError::BufferTooSmall => r_efi::efi::Status::BUFFER_TOO_SMALL,
        }
    }
}
