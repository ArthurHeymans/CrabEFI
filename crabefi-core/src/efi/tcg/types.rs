//! TCG type definitions for TPM 1.2 and TPM 2.0 event logging.
//!
//! These types are defined by the TCG PC Client Platform Firmware Profile
//! Specification and the TCG EFI Protocol Specification. Since `r-efi` does
//! not provide TCG types, we define them here.
//!
//! # References
//!
//! - TCG PC Client Specific Platform Firmware Profile Specification (PFP)
//! - TCG EFI Protocol Specification, Family "2.0"
//! - TCG PC Client Specific Implementation Specification for Conventional BIOS

use r_efi::efi::Guid;

// ============================================================================
// GUIDs
// ============================================================================

/// EFI_TCG_PROTOCOL GUID (TPM 1.2)
/// {f541796d-a62e-4954-a775-9584f61b9cdd}
pub const TCG_PROTOCOL_GUID: Guid = Guid::from_fields(
    0xf541796d,
    0xa62e,
    0x4954,
    0xa7,
    0x75,
    &[0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd],
);

/// EFI_TCG2_PROTOCOL GUID (TPM 2.0)
/// {607f766c-7455-42be-930b-e4d76db2720f}
pub const TCG2_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x607f766c,
    0x7455,
    0x42be,
    0x93,
    0x0b,
    &[0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f],
);

// ============================================================================
// Hash algorithm identifiers (TPM 2.0 Algorithm IDs)
// ============================================================================

/// TPM_ALG_SHA1
pub const TPM_ALG_SHA1: u16 = 0x0004;
/// TPM_ALG_SHA256
pub const TPM_ALG_SHA256: u16 = 0x000B;
/// TPM_ALG_SHA384
pub const TPM_ALG_SHA384: u16 = 0x000C;
/// TPM_ALG_SHA512
pub const TPM_ALG_SHA512: u16 = 0x000D;
/// TPM_ALG_SM3_256
pub const TPM_ALG_SM3_256: u16 = 0x0012;

/// Digest size for SHA-1.
pub const SHA1_DIGEST_SIZE: usize = 20;
/// Digest size for SHA-256.
pub const SHA256_DIGEST_SIZE: usize = 32;
/// Digest size for SHA-384.
pub const SHA384_DIGEST_SIZE: usize = 48;
/// Digest size for SHA-512.
pub const SHA512_DIGEST_SIZE: usize = 64;
/// Digest size for SM3-256.
pub const SM3_256_DIGEST_SIZE: usize = 32;

/// Return the digest size for a given TPM algorithm ID, or `None` if unknown.
pub fn digest_size_for_algorithm(alg: u16) -> Option<usize> {
    match alg {
        TPM_ALG_SHA1 => Some(SHA1_DIGEST_SIZE),
        TPM_ALG_SHA256 => Some(SHA256_DIGEST_SIZE),
        TPM_ALG_SHA384 => Some(SHA384_DIGEST_SIZE),
        TPM_ALG_SHA512 => Some(SHA512_DIGEST_SIZE),
        TPM_ALG_SM3_256 => Some(SM3_256_DIGEST_SIZE),
        _ => None,
    }
}

// ============================================================================
// TCG2 Boot Service Capability bitmasks
// ============================================================================

/// Hash algorithm bitmap values for `EFI_TCG2_BOOT_SERVICE_CAPABILITY`.
pub const EFI_TCG2_BOOT_HASH_ALG_SHA1: u32 = 0x0000_0001;
pub const EFI_TCG2_BOOT_HASH_ALG_SHA256: u32 = 0x0000_0002;
pub const EFI_TCG2_BOOT_HASH_ALG_SHA384: u32 = 0x0000_0004;
pub const EFI_TCG2_BOOT_HASH_ALG_SHA512: u32 = 0x0000_0008;
pub const EFI_TCG2_BOOT_HASH_ALG_SM3_256: u32 = 0x0000_0010;

/// Event log format: TCG 1.2 SHA1 event log (legacy).
pub const EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2: u32 = 0x0000_0001;
/// Event log format: TCG 2.0 crypto-agile event log.
pub const EFI_TCG2_EVENT_LOG_FORMAT_TCG_2: u32 = 0x0000_0002;

/// Number of PCR banks (0..23).
pub const PCR_COUNT: usize = 24;

// ============================================================================
// TCG PC Client event types
// ============================================================================

/// Pre-boot: CRTM contents measurement.
pub const EV_POST_CODE: u32 = 0x0000_0001;
/// Unused/separator event.
pub const EV_NO_ACTION: u32 = 0x0000_0003;
/// Separator event (marks transition between pre-OS and OS).
pub const EV_SEPARATOR: u32 = 0x0000_0004;
/// Platform-specific action string.
pub const EV_ACTION: u32 = 0x0000_0005;
/// Event tag (tagged event wrapper).
pub const EV_EVENT_TAG: u32 = 0x0000_0006;
/// Compact hash (hash only, no event data).
pub const EV_COMPACT_HASH: u32 = 0x0000_000C;
/// IPL (initial program load) measurement.
pub const EV_IPL: u32 = 0x0000_000D;

/// EFI variable measurement (db, dbx, etc.).
pub const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x8000_0001;
/// Boot variable measurement.
pub const EV_EFI_VARIABLE_BOOT: u32 = 0x8000_0002;
/// Boot services application measurement.
pub const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003;
/// Boot services driver measurement.
pub const EV_EFI_BOOT_SERVICES_DRIVER: u32 = 0x8000_0004;
/// Runtime services driver measurement.
pub const EV_EFI_RUNTIME_SERVICES_DRIVER: u32 = 0x8000_0005;
/// GPT measurement.
pub const EV_EFI_GPT_EVENT: u32 = 0x8000_0006;
/// EFI action event.
pub const EV_EFI_ACTION: u32 = 0x8000_0007;
/// Platform firmware blob measurement.
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB: u32 = 0x8000_0008;
/// Handoff tables measurement.
pub const EV_EFI_HANDOFF_TABLES: u32 = 0x8000_0009;
/// Platform firmware blob (version 2).
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB2: u32 = 0x8000_000A;
/// Handoff tables (version 2).
pub const EV_EFI_HANDOFF_TABLES2: u32 = 0x8000_000B;
/// EFI variable boot (version 2).
pub const EV_EFI_VARIABLE_BOOT2: u32 = 0x8000_0010;
/// EFI variable authority.
pub const EV_EFI_VARIABLE_AUTHORITY: u32 = 0x8000_00E0;
/// EFI SPDM firmware blob.
pub const EV_EFI_SPDM_FIRMWARE_BLOB: u32 = 0x8000_00E1;

// ============================================================================
// TPM 1.2 legacy event log structures
// ============================================================================

/// TCG PC Client legacy event header (TPM 1.2, SHA1-only).
///
/// This is the `TCG_PCClientPCREvent` structure from the TCG PC Client
/// Specification. Each event has a fixed-size header followed by variable
/// event data.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TcgPcrEventHdr {
    /// PCR index (0..23).
    pub pcr_index: u32,
    /// Event type (EV_* constants).
    pub event_type: u32,
    /// SHA-1 digest of the event data.
    pub digest: [u8; SHA1_DIGEST_SIZE],
    /// Size of the event data following this header.
    pub event_data_size: u32,
    // Followed by `event_data_size` bytes of event data.
}

// ============================================================================
// TPM 2.0 crypto-agile event log structures
// ============================================================================

/// A single digest value tagged with its algorithm ID.
///
/// Part of `TPML_DIGEST_VALUES` in the TPM 2.0 crypto-agile event log.
#[derive(Clone, Copy)]
pub struct TaggedDigest {
    /// TPM algorithm ID (e.g., `TPM_ALG_SHA256`).
    pub algorithm: u16,
    /// Digest bytes. Length determined by `digest_size_for_algorithm()`.
    pub digest: [u8; SHA512_DIGEST_SIZE], // Max digest size
}

impl TaggedDigest {
    /// Create a new tagged digest with zeroed data.
    pub const fn zeroed(algorithm: u16) -> Self {
        Self {
            algorithm,
            digest: [0u8; SHA512_DIGEST_SIZE],
        }
    }

    /// Return the valid digest slice for this algorithm.
    pub fn as_slice(&self) -> &[u8] {
        let size = digest_size_for_algorithm(self.algorithm).unwrap_or(0);
        &self.digest[..size]
    }
}

/// Crypto-agile event header for TPM 2.0 event logs.
///
/// This corresponds to `TCG_PCR_EVENT2` from the TCG PC Client PFP
/// specification. The on-disk format is:
///
/// ```text
/// u32  pcr_index
/// u32  event_type
/// u32  digest_count
///   for each digest:
///     u16  algorithm_id
///     u8[] digest (size depends on algorithm)
/// u32  event_data_size
/// u8[] event_data
/// ```
///
/// We use this in-memory representation for construction. The event log
/// serialization code writes the packed on-disk format.
pub struct CryptoAgileEvent<'a> {
    /// PCR index (0..23).
    pub pcr_index: u32,
    /// Event type (EV_* constants).
    pub event_type: u32,
    /// Digest values, one per active hash algorithm.
    pub digests: &'a [TaggedDigest],
    /// Event data payload.
    pub event_data: &'a [u8],
}

impl CryptoAgileEvent<'_> {
    /// Compute the serialized size of this event in the crypto-agile format.
    pub fn serialized_size(&self) -> usize {
        let mut size = 4 + 4 + 4; // pcr_index + event_type + digest_count
        for d in self.digests {
            let ds = digest_size_for_algorithm(d.algorithm).unwrap_or(0);
            size += 2 + ds; // algorithm_id + digest bytes
        }
        size += 4 + self.event_data.len(); // event_data_size + event_data
        size
    }

    /// Serialize this event into the given buffer.
    ///
    /// Returns the number of bytes written, or `None` if the buffer is too small.
    pub fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let needed = self.serialized_size();
        if buf.len() < needed {
            return None;
        }

        let mut off = 0;

        buf[off..off + 4].copy_from_slice(&self.pcr_index.to_le_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&self.event_type.to_le_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&(self.digests.len() as u32).to_le_bytes());
        off += 4;

        for d in self.digests {
            buf[off..off + 2].copy_from_slice(&d.algorithm.to_le_bytes());
            off += 2;
            let ds = digest_size_for_algorithm(d.algorithm).unwrap_or(0);
            buf[off..off + ds].copy_from_slice(&d.digest[..ds]);
            off += ds;
        }

        buf[off..off + 4].copy_from_slice(&(self.event_data.len() as u32).to_le_bytes());
        off += 4;
        buf[off..off + self.event_data.len()].copy_from_slice(self.event_data);
        off += self.event_data.len();

        Some(off)
    }
}

// ============================================================================
// Specification ID Event (first event in a crypto-agile log)
// ============================================================================

/// TCG EFI Specification ID Event structure.
///
/// This is the `TCG_EfiSpecIDEvent` that must be the first event in a
/// crypto-agile event log. It is wrapped in a legacy `TcgPcrEventHdr`
/// (PCR 0, EV_NO_ACTION, SHA1 digest = all zeros).
///
/// The on-disk format is variable-length due to the algorithm list.
pub struct SpecIdEvent {
    /// Number of hash algorithms in the log.
    pub num_algorithms: u32,
    /// Algorithm ID and digest size pairs.
    pub digest_sizes: [(u16, u16); 5], // Up to 5 algorithms
}

impl SpecIdEvent {
    /// Signature bytes: "Spec ID Event03" (null-terminated).
    pub const SIGNATURE: &[u8; 16] = b"Spec ID Event03\0";

    /// Create a spec ID event for SHA-256 only.
    pub fn sha256_only() -> Self {
        let mut digest_sizes = [(0u16, 0u16); 5];
        digest_sizes[0] = (TPM_ALG_SHA256, SHA256_DIGEST_SIZE as u16);
        Self {
            num_algorithms: 1,
            digest_sizes,
        }
    }

    /// Create a spec ID event for SHA-1 + SHA-256.
    pub fn sha1_and_sha256() -> Self {
        let mut digest_sizes = [(0u16, 0u16); 5];
        digest_sizes[0] = (TPM_ALG_SHA1, SHA1_DIGEST_SIZE as u16);
        digest_sizes[1] = (TPM_ALG_SHA256, SHA256_DIGEST_SIZE as u16);
        Self {
            num_algorithms: 2,
            digest_sizes,
        }
    }

    /// Serialize the Spec ID Event into a buffer.
    ///
    /// This writes the event data payload (not the legacy event header wrapper).
    /// The caller must wrap this in a `TcgPcrEventHdr` with PCR=0,
    /// event_type=EV_NO_ACTION, digest=all-zeros.
    ///
    /// Returns the number of bytes written, or `None` if the buffer is too small.
    pub fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        // Minimum: signature(16) + platformClass(4) + specVersionMinor(1)
        //        + specVersionMajor(1) + specErrata(1) + uintnSize(1)
        //        + numberOfAlgorithms(4) + algorithms(4*n) + vendorInfoSize(1)
        let needed = 16 + 4 + 1 + 1 + 1 + 1 + 4 + (self.num_algorithms as usize * 4) + 1;

        if buf.len() < needed {
            return None;
        }

        let mut off = 0;

        // Signature: "Spec ID Event03\0"
        buf[off..off + 16].copy_from_slice(Self::SIGNATURE);
        off += 16;

        // platformClass: 0 (client)
        buf[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
        off += 4;

        // specVersionMinor: 0
        buf[off] = 0;
        off += 1;
        // specVersionMajor: 2
        buf[off] = 2;
        off += 1;
        // specErrata: 0
        buf[off] = 0;
        off += 1;
        // uintnSize: 2 (uint32)
        buf[off] = 2;
        off += 1;

        // numberOfAlgorithms
        buf[off..off + 4].copy_from_slice(&self.num_algorithms.to_le_bytes());
        off += 4;

        // Algorithm entries: (algorithmId: u16, digestSize: u16)
        for i in 0..self.num_algorithms as usize {
            let (alg, size) = self.digest_sizes[i];
            buf[off..off + 2].copy_from_slice(&alg.to_le_bytes());
            off += 2;
            buf[off..off + 2].copy_from_slice(&size.to_le_bytes());
            off += 2;
        }

        // vendorInfoSize: 0
        buf[off] = 0;
        off += 1;

        Some(off)
    }
}

// ============================================================================
// TCG2 Protocol structures
// ============================================================================

/// `EFI_TCG2_BOOT_SERVICE_CAPABILITY` — returned by `GetCapability`.
#[repr(C)]
#[derive(Clone)]
pub struct Tcg2BootServiceCapability {
    /// Size of this structure (must be set by caller on input).
    pub size: u8,
    /// Structure version (1.1).
    pub structure_version: Tcg2Version,
    /// Protocol version (1.1).
    pub protocol_version: Tcg2Version,
    /// Bitmap of supported hash algorithms.
    pub hash_algorithm_bitmap: u32,
    /// Bitmap of supported event log formats.
    pub supported_event_logs: u32,
    /// Whether a TPM is present and operational.
    pub tpm_present_flag: u8, // BOOLEAN
    /// Maximum size of a single command to the TPM.
    pub max_command_size: u16,
    /// Maximum size of a single response from the TPM.
    pub max_response_size: u16,
    /// Manufacturer ID from TPM.
    pub manufacturer_id: u32,
    /// Number of active PCR banks.
    pub number_of_pcr_banks: u32,
    /// Bitmap of active PCR banks.
    pub active_pcr_banks: u32,
}

/// TCG2 version — major.minor.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Tcg2Version {
    pub major: u8,
    pub minor: u8,
}

/// `EFI_TCG2_EVENT_HEADER` — the header portion of an `EFI_TCG2_EVENT`.
///
/// This struct is `repr(C, packed)` to match the ABI-correct layout from
/// the TCG EFI Protocol Specification (fields are not naturally aligned).
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Tcg2EventHeader {
    /// Size of the entire event header (this struct).
    pub header_size: u32,
    /// Version of this header (1).
    pub header_version: u16,
    /// PCR index (0..23).
    pub pcr_index: u32,
    /// Event type (EV_* constants).
    pub event_type: u32,
}

/// `EFI_TCG2_EVENT` — event structure passed to `HashLogExtendEvent`.
///
/// This is the caller-facing structure. The protocol implementation
/// hashes the data, extends PCRs, and serializes a `CryptoAgileEvent`
/// into the internal event log.
#[repr(C, packed)]
pub struct Tcg2Event {
    /// Total size of this structure including event data.
    pub size: u32,
    /// Event header.
    pub header: Tcg2EventHeader,
    // Followed by event data bytes (size = self.size - offset_of(event_data))
}

// ============================================================================
// TCG (TPM 1.2) Protocol structures
// ============================================================================

/// TCG version for TPM 1.2 protocol (4-byte version).
///
/// Note: this differs from `Tcg2Version` which is only 2 bytes.
/// The TPM 1.2 protocol spec uses a 4-byte version structure.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcgVersion {
    pub major: u8,
    pub minor: u8,
    pub rev_major: u8,
    pub rev_minor: u8,
}

/// `TCG_EFI_BOOT_SERVICE_CAPABILITY` — returned by TCG `StatusCheck`.
#[repr(C)]
pub struct TcgBootServiceCapability {
    /// Size of this structure.
    pub size: u8,
    /// Structure version.
    pub struct_version: TcgVersion,
    /// Protocol spec version.
    pub protocol_spec_version: TcgVersion,
    /// Hash algorithm bitmap (for TPM 1.2, only SHA1).
    pub hash_algorithm_bitmap: u8,
    /// Whether TPM is present.
    pub tpm_present_flag: u8, // BOOLEAN
    /// Whether TPM is deactivated.
    pub tpm_deactivated_flag: u8, // BOOLEAN
}

// ============================================================================
// Error types
// ============================================================================

// ============================================================================
// HashLogExtendEvent flags
// ============================================================================

/// Extend the PCR but do not log the event.
pub const TCG2_EXTEND_ONLY: u64 = 0x0000_0000_0000_0001;
/// The data being measured is a PE/COFF image.
pub const TCG2_PE_COFF_IMAGE: u64 = 0x0000_0000_0000_0010;

// ============================================================================
// Error types
// ============================================================================

/// Errors from TCG operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TcgError {
    /// The event log buffer is full.
    LogFull,
    /// Invalid PCR index (>= 24).
    InvalidPcrIndex,
    /// Unsupported hash algorithm.
    UnsupportedAlgorithm,
    /// Internal computation error.
    InternalError,
    /// Event data too large.
    EventTooLarge,
}
