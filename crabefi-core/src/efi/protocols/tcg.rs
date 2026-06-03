//! EFI TCG Protocol (TPM 1.2) implementation.
//!
//! This module implements `EFI_TCG_PROTOCOL` as defined in the TCG EFI
//! Protocol Specification for TPM Family 1.1 or 1.2. It provides:
//!
//! - `StatusCheck`: Report whether a physical TPM 1.2 backend is available.
//! - `HashAll`: Hash data using SHA-1.
//! - `LogEvent`: Append an event to the SHA1 event log.
//! - `PassThroughToTpm`: Not supported (no TPM 1.2 passthrough — returns UNSUPPORTED).
//! - `HashLogExtendEvent`: Hash data, extend PCRs, and log only when a physical
//!   TPM 1.2 backend is configured.
//!
//! # Compatibility mode
//!
//! CrabEFI currently has no TPM 1.2 hardware transport. The legacy protocol can
//! be installed for event-log discovery and SHA-1 hashing compatibility, but it
//! does not advertise TPM presence and rejects PCR extends unless a real TPM 1.2
//! backend is added.
//!
//! # Reference
//!
//! - TCG EFI Protocol Specification, for TPM Family 1.1 or 1.2
//! - EDK2 `SecurityPkg/Tcg/TcgDxe/TcgDxe.c`

use core::ffi::c_void;

use r_efi::efi::Status;
use sha1::Digest as _;
use sha1::Sha1;
use spin::Mutex;

use crate::efi::auth::authenticode::compute_authenticode_digests;
use crate::efi::tcg::event_log::{EventLog, Sha1EventLog};
use crate::efi::tcg::pcr::Sha1PcrBank;
use crate::efi::tcg::types::*;
use crate::efi::utils::allocate_protocol_with_log;

// ============================================================================
// Global TCG state
// ============================================================================

/// Global TCG (TPM 1.2) state.
static TCG_STATE: Mutex<Option<TcgState>> = Mutex::new(None);

struct TcgState {
    /// SHA-1 PCR bank.
    pcr_bank: Sha1PcrBank,
    /// SHA-1-only event log.
    event_log: Sha1EventLog,
    /// Whether this protocol is backed by a physical TPM 1.2 device.
    tpm_present: bool,
}

/// Initialize the TCG (TPM 1.2) state.
///
/// # Arguments
/// * `buffer` - Pre-allocated buffer for the SHA-1 event log.
/// * `existing_log` - Optional pre-existing log data to prepend.
/// * `tpm_present` - Whether a physical TPM 1.2 device backs PCR extends.
pub fn init_state(
    buffer: &'static mut [u8],
    existing_log: Option<&[u8]>,
    tpm_present: bool,
) -> Result<(), TcgError> {
    let event_log = if let Some(existing) = existing_log {
        Sha1EventLog::from_existing(buffer, existing)?
    } else {
        Sha1EventLog::new(buffer)
    };

    *TCG_STATE.lock() = Some(TcgState {
        pcr_bank: Sha1PcrBank::new(),
        event_log,
        tpm_present,
    });

    Ok(())
}

fn make_sha1_digest(data: &[u8]) -> ([u8; SHA1_DIGEST_SIZE], TaggedDigest) {
    let sha1_hash = Sha1::digest(data);
    let mut sha1_array = [0u8; SHA1_DIGEST_SIZE];
    sha1_array.copy_from_slice(&sha1_hash);

    let mut digest = TaggedDigest::zeroed(TPM_ALG_SHA1);
    digest.digest[..SHA1_DIGEST_SIZE].copy_from_slice(&sha1_array);
    (sha1_array, digest)
}

fn extend_and_log(
    state: &mut TcgState,
    pcr_index: u32,
    event_type: u32,
    sha1_digest: &[u8; SHA1_DIGEST_SIZE],
    tagged_digest: TaggedDigest,
    event_data: &[u8],
) -> Result<(), TcgError> {
    if pcr_index as usize >= PCR_COUNT {
        return Err(TcgError::InvalidPcrIndex);
    }

    state.pcr_bank.extend(pcr_index as usize, sha1_digest)?;
    state
        .event_log
        .log_event(pcr_index, event_type, &[tagged_digest], event_data)?;
    Ok(())
}

/// Measure a non-PE event through TCG (TPM 1.2) state.
///
/// Returns `None` if the TCG protocol is not installed.
pub fn measure_event(
    pcr_index: u32,
    event_type: u32,
    data_to_hash: &[u8],
    event_data: &[u8],
) -> Option<Result<(), TcgError>> {
    let mut guard = TCG_STATE.lock();
    let state = guard.as_mut()?;
    if !state.tpm_present {
        return None;
    }
    let (sha1_digest, tagged_digest) = make_sha1_digest(data_to_hash);
    Some(extend_and_log(
        state,
        pcr_index,
        event_type,
        &sha1_digest,
        tagged_digest,
        event_data,
    ))
}

/// Measure a PE/COFF image through TCG (TPM 1.2) state using Authenticode hashing.
///
/// Returns `None` if the TCG protocol is not installed.
pub fn measure_pe_image_event(
    pcr_index: u32,
    event_type: u32,
    pe_data: &[u8],
    event_data: &[u8],
) -> Option<Result<(), TcgError>> {
    let mut guard = TCG_STATE.lock();
    let state = guard.as_mut()?;
    if !state.tpm_present {
        return None;
    }
    Some(
        compute_authenticode_digests(pe_data, &[TPM_ALG_SHA1])
            .map_err(|_| TcgError::InternalError)
            .and_then(|(digest_count, digests)| {
                let tagged_digest = digests
                    .iter()
                    .take(digest_count)
                    .find(|digest| digest.algorithm == TPM_ALG_SHA1)
                    .copied()
                    .ok_or(TcgError::UnsupportedAlgorithm)?;
                let mut sha1_digest = [0u8; SHA1_DIGEST_SIZE];
                sha1_digest.copy_from_slice(&tagged_digest.digest[..SHA1_DIGEST_SIZE]);
                extend_and_log(
                    state,
                    pcr_index,
                    event_type,
                    &sha1_digest,
                    tagged_digest,
                    event_data,
                )
            }),
    )
}

// ============================================================================
// Protocol function pointers (extern "efiapi")
// ============================================================================

/// `EFI_TCG_PROTOCOL.StatusCheck`
extern "efiapi" fn tcg_status_check(
    _this: *mut TcgProtocolFfi,
    protocol_capability: *mut TcgBootServiceCapability,
    _feature_flags: *mut u32,
    event_log_location: *mut u64,
    event_log_last_entry: *mut u64,
) -> Status {
    log::debug!("TCG.StatusCheck()");

    let state = TCG_STATE.lock();
    let state = match state.as_ref() {
        Some(s) => s,
        None => return Status::DEVICE_ERROR,
    };

    if !protocol_capability.is_null() {
        // SAFETY: caller guarantees valid pointer.
        unsafe {
            *protocol_capability = TcgBootServiceCapability {
                size: core::mem::size_of::<TcgBootServiceCapability>() as u8,
                struct_version: TcgVersion {
                    major: 1,
                    minor: 2,
                    rev_major: 0,
                    rev_minor: 0,
                },
                protocol_spec_version: TcgVersion {
                    major: 1,
                    minor: 2,
                    rev_major: 0,
                    rev_minor: 0,
                },
                hash_algorithm_bitmap: 0x01, // SHA-1
                tpm_present_flag: u8::from(state.tpm_present),
                tpm_deactivated_flag: 0,
            };
        }
    }

    let log_data = state.event_log.log_data();

    if !event_log_location.is_null() {
        unsafe {
            *event_log_location = log_data.as_ptr() as u64;
        }
    }

    if !event_log_last_entry.is_null() {
        unsafe {
            *event_log_last_entry = match state.event_log.last_entry_offset() {
                Some(off) => log_data.as_ptr() as u64 + off as u64,
                None => 0,
            };
        }
    }

    log::debug!("  -> SUCCESS (TPM present: {})", state.tpm_present);
    Status::SUCCESS
}

/// `EFI_TCG_PROTOCOL.HashAll`
///
/// Hash the provided data using SHA-1.
extern "efiapi" fn tcg_hash_all(
    _this: *mut TcgProtocolFfi,
    hash_data: *const u8,
    hash_data_len: u64,
    algorithm_id: u32,
    hashed_data_len: *mut u64,
    hashed_data_result: *mut *mut u8,
) -> Status {
    log::debug!("TCG.HashAll(len={})", hash_data_len);

    if (hash_data.is_null() && hash_data_len != 0)
        || hashed_data_len.is_null()
        || hashed_data_result.is_null()
    {
        return Status::INVALID_PARAMETER;
    }
    if algorithm_id != TPM_ALG_SHA1 as u32 {
        return Status::UNSUPPORTED;
    }

    let result_buf = unsafe {
        if (*hashed_data_result).is_null() {
            match crate::efi::allocator::allocate_pool(
                crate::efi::allocator::MemoryType::BootServicesData,
                SHA1_DIGEST_SIZE,
            ) {
                Ok(p) => {
                    *hashed_data_result = p;
                    *hashed_data_len = SHA1_DIGEST_SIZE as u64;
                    p
                }
                Err(_) => return Status::OUT_OF_RESOURCES,
            }
        } else {
            if *hashed_data_len < SHA1_DIGEST_SIZE as u64 {
                *hashed_data_len = SHA1_DIGEST_SIZE as u64;
                return Status::BUFFER_TOO_SMALL;
            }
            *hashed_data_result
        }
    };

    // We only support SHA-1 (algorithm ID 0x04 / TPM_ALG_SHA1).
    let data = if hash_data_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(hash_data, hash_data_len as usize) }
    };
    let hash = Sha1::digest(data);

    unsafe {
        core::ptr::copy_nonoverlapping(hash.as_ptr(), result_buf, SHA1_DIGEST_SIZE);
        *hashed_data_len = SHA1_DIGEST_SIZE as u64;
    }

    Status::SUCCESS
}

/// `EFI_TCG_PROTOCOL.LogEvent`
///
/// Append an event to the SHA-1 event log without extending PCRs.
extern "efiapi" fn tcg_log_event(
    _this: *mut TcgProtocolFfi,
    event: *const c_void,
    _event_number: *mut u32,
    _flags: u32,
) -> Status {
    if event.is_null() {
        return Status::INVALID_PARAMETER;
    }

    log::debug!("TCG.LogEvent()");

    // Parse the legacy event header.
    let hdr = unsafe { &*(event as *const TcgPcrEventHdr) };
    let pcr_index = hdr.pcr_index;
    let event_type = hdr.event_type;
    let event_data_size = hdr.event_data_size as usize;

    let event_data = if event_data_size > 0 {
        unsafe {
            let data_ptr = (event as *const u8).add(core::mem::size_of::<TcgPcrEventHdr>());
            core::slice::from_raw_parts(data_ptr, event_data_size)
        }
    } else {
        &[]
    };

    let digest = TaggedDigest {
        algorithm: TPM_ALG_SHA1,
        digest: {
            let mut d = [0u8; SHA512_DIGEST_SIZE];
            d[..SHA1_DIGEST_SIZE].copy_from_slice(&hdr.digest);
            d
        },
    };

    let mut state = TCG_STATE.lock();
    let state = match state.as_mut() {
        Some(s) => s,
        None => return Status::DEVICE_ERROR,
    };

    if let Err(e) = state
        .event_log
        .log_event(pcr_index, event_type, &[digest], event_data)
    {
        log::warn!("TCG.LogEvent failed: {:?}", e);
        return Status::OUT_OF_RESOURCES;
    }

    Status::SUCCESS
}

/// `EFI_TCG_PROTOCOL.PassThroughToTpm`
///
/// Not supported — no physical TPM.
extern "efiapi" fn tcg_pass_through_to_tpm(
    _this: *mut TcgProtocolFfi,
    _tpm_input_size: u32,
    _tpm_input: *const u8,
    _tpm_output_size: u32,
    _tpm_output: *mut u8,
) -> Status {
    log::debug!("TCG.PassThroughToTpm() -> UNSUPPORTED");
    Status::UNSUPPORTED
}

/// `EFI_TCG_PROTOCOL.HashLogExtendEvent`
///
/// Hash data with SHA-1, extend the specified PCR, and log the event.
extern "efiapi" fn tcg_hash_log_extend_event(
    _this: *mut TcgProtocolFfi,
    hash_data: u64,
    hash_data_len: u64,
    algorithm_id: u32,
    event: *mut c_void,
    _event_number: *mut u32,
    _event_log_last_entry: *mut u64,
) -> Status {
    if event.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if algorithm_id != TPM_ALG_SHA1 as u32 {
        return Status::UNSUPPORTED;
    }

    // Parse the legacy event header.
    let hdr = unsafe { &*(event as *const TcgPcrEventHdr) };
    let pcr_index = hdr.pcr_index;
    let event_type = hdr.event_type;
    let event_data_size = hdr.event_data_size as usize;

    log::debug!(
        "TCG.HashLogExtendEvent(pcr={}, type={:#x}, data_len={})",
        pcr_index,
        event_type,
        hash_data_len,
    );

    if pcr_index as usize >= PCR_COUNT {
        return Status::INVALID_PARAMETER;
    }

    let event_data = if event_data_size > 0 {
        unsafe {
            let data_ptr = (event as *const u8).add(core::mem::size_of::<TcgPcrEventHdr>());
            core::slice::from_raw_parts(data_ptr, event_data_size)
        }
    } else {
        &[]
    };

    // Hash the data with SHA-1.
    let data_slice = if hash_data_len > 0 && hash_data != 0 {
        unsafe { core::slice::from_raw_parts(hash_data as *const u8, hash_data_len as usize) }
    } else {
        &[]
    };

    let sha1_hash = Sha1::digest(data_slice);
    let mut digest = TaggedDigest::zeroed(TPM_ALG_SHA1);
    digest.digest[..SHA1_DIGEST_SIZE].copy_from_slice(&sha1_hash);

    let mut state = TCG_STATE.lock();
    let state = match state.as_mut() {
        Some(s) => s,
        None => return Status::DEVICE_ERROR,
    };

    if !state.tpm_present {
        log::debug!("TCG.HashLogExtendEvent() -> DEVICE_ERROR (no physical TPM 1.2)");
        return Status::DEVICE_ERROR;
    }

    // Extend PCR.
    if let Err(e) = state.pcr_bank.extend(pcr_index as usize, &sha1_hash) {
        log::error!("PCR extend failed: {:?}", e);
        return Status::DEVICE_ERROR;
    }

    // Log the event.
    if let Err(e) = state
        .event_log
        .log_event(pcr_index, event_type, &[digest], event_data)
    {
        log::warn!("Event log append failed: {:?}", e);
    }

    log::debug!("  -> SUCCESS");
    Status::SUCCESS
}

// ============================================================================
// Protocol struct (matches EFI_TCG_PROTOCOL ABI)
// ============================================================================

/// FFI-compatible `EFI_TCG_PROTOCOL` structure.
///
/// Layout matches the TCG EFI Protocol Specification for TPM 1.1/1.2 and
/// `uefi-raw`'s `TcgProtocol` struct.
#[repr(C)]
pub struct TcgProtocolFfi {
    pub status_check: extern "efiapi" fn(
        *mut Self,
        *mut TcgBootServiceCapability,
        *mut u32,
        *mut u64,
        *mut u64,
    ) -> Status,
    pub hash_all:
        extern "efiapi" fn(*mut Self, *const u8, u64, u32, *mut u64, *mut *mut u8) -> Status,
    pub log_event: extern "efiapi" fn(*mut Self, *const c_void, *mut u32, u32) -> Status,
    pub pass_through_to_tpm: extern "efiapi" fn(*mut Self, u32, *const u8, u32, *mut u8) -> Status,
    pub hash_log_extend_event:
        extern "efiapi" fn(*mut Self, u64, u64, u32, *mut c_void, *mut u32, *mut u64) -> Status,
}

// ============================================================================
// Public API
// ============================================================================

/// Create and initialize the TCG (TPM 1.2) Protocol.
///
/// Returns a pointer to the protocol instance, or null on allocation failure.
/// The protocol's internal state must be initialized via [`init_state`] before
/// calling this.
pub fn create_protocol() -> *mut c_void {
    let ptr = allocate_protocol_with_log::<TcgProtocolFfi>("TCGProtocol", |p| {
        p.status_check = tcg_status_check;
        p.hash_all = tcg_hash_all;
        p.log_event = tcg_log_event;
        p.pass_through_to_tpm = tcg_pass_through_to_tpm;
        p.hash_log_extend_event = tcg_hash_log_extend_event;
    });

    if ptr.is_null() {
        return core::ptr::null_mut();
    }

    log::info!("EFI_TCG_PROTOCOL created");
    ptr as *mut c_void
}
