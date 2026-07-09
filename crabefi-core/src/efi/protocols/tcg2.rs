//! EFI TCG2 Protocol (TPM 2.0) implementation.
//!
//! This module implements `EFI_TCG2_PROTOCOL` as defined in the TCG EFI
//! Protocol Specification, Family "2.0". It provides:
//!
//! - `GetCapability`: Report TPM presence, supported hash algorithms, etc.
//! - `GetEventLog`: Return pointers to the crypto-agile event log.
//! - `HashLogExtendEvent`: Hash data, extend hardware PCRs, and log an event.
//! - `SubmitCommand`: Forward raw TPM commands when hardware is present, otherwise return UNSUPPORTED.
//! - `GetActivePcrBanks`: Return active PCR bank bitmap.
//! - `SetActivePcrBanks` / `GetResultOfSetActivePcrBanks`: Report immutable boot-time bank state.
//!
//! # Log-only mode
//!
//! If no hardware/platform TPM backend is available, the protocol may still be
//! installed so callers can discover a firmware-provided event log, but it does
//! not advertise TPM presence and rejects PCR-extending operations. This avoids
//! presenting software-only PCR state as attestable hardware TPM state.
//!
//! # Reference
//!
//! - TCG EFI Protocol Specification, Family "2.0", Level 00, Revision 00.13
//! - EDK2 `SecurityPkg/Tcg/Tcg2Dxe/Tcg2Dxe.c`

use core::ffi::c_void;

use r_efi::efi::Status;
use spin::Mutex;

use crate::efi::auth::authenticode::compute_authenticode_digests;
use crate::efi::tcg::event_log::{CryptoAgileEventLog, EventLog};
use crate::efi::tcg::pcr::PcrBanks;
use crate::efi::tcg::tpm_tis::TpmTis;
use crate::efi::tcg::types::*;
use crate::efi::utils::allocate_protocol_with_log;
use crate::platform::{Tpm2Device, TpmDigest, TpmError};

// ============================================================================
// Global TCG2 state
// ============================================================================

/// Global TCG2 state shared between all protocol function calls.
///
/// Protected by a spin mutex since UEFI boot services are single-threaded
/// but we still want to be safe with the global.
static TCG2_STATE: Mutex<Option<Tcg2State>> = Mutex::new(None);

enum Tpm2Backend {
    Tis(TpmTis),
    Driver(&'static mut dyn Tpm2Device),
}

impl Tpm2Backend {
    fn manufacturer_id(&self) -> u32 {
        match self {
            Self::Tis(tpm) => tpm.manufacturer_id(),
            Self::Driver(tpm) => tpm.manufacturer_id(),
        }
    }

    fn max_command_size(&self) -> u16 {
        match self {
            Self::Tis(tpm) => tpm.max_command_size(),
            Self::Driver(tpm) => tpm.max_command_size(),
        }
    }

    fn max_response_size(&self) -> u16 {
        match self {
            Self::Tis(tpm) => tpm.max_response_size(),
            Self::Driver(tpm) => tpm.max_response_size(),
        }
    }

    fn pcr_extend(&mut self, pcr_index: u32, digests: &[TaggedDigest]) -> Result<(), TcgError> {
        match self {
            Self::Tis(tpm) => tpm.pcr_extend(pcr_index, digests),
            Self::Driver(tpm) => {
                let mut digest_views = [TpmDigest {
                    algorithm: 0,
                    digest: &[],
                }; 5];
                let count = digests.len().min(digest_views.len());
                for (out, digest) in digest_views.iter_mut().zip(digests.iter()).take(count) {
                    out.algorithm = digest.algorithm;
                    out.digest = digest.as_slice();
                }
                tpm.pcr_extend(pcr_index, &digest_views[..count])
                    .map_err(platform_tpm_error_to_tcg)
            }
        }
    }

    fn submit_command(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, TcgError> {
        match self {
            Self::Tis(tpm) => tpm.send_command(command, response),
            Self::Driver(tpm) => tpm
                .submit_command(command, response)
                .map_err(platform_tpm_error_to_tcg),
        }
    }
}

fn platform_tpm_error_to_tcg(error: TpmError) -> TcgError {
    match error {
        TpmError::InvalidParameter => TcgError::InvalidPcrIndex,
        TpmError::BufferTooSmall => TcgError::EventTooLarge,
        TpmError::Unsupported => TcgError::UnsupportedAlgorithm,
        TpmError::DeviceError => TcgError::InternalError,
    }
}

fn checked_slice_len(len: u64) -> Option<usize> {
    usize::try_from(len)
        .ok()
        .filter(|len| *len <= isize::MAX as usize)
}

/// Internal state for the TCG2 protocol.
struct Tcg2State {
    /// Software PCR banks (SHA-256 + optional SHA-1).
    /// Used for hashing data and as a mirror of successful hardware extends.
    pcr_banks: PcrBanks,
    /// Crypto-agile event log (TPM 2.0 format).
    event_log: CryptoAgileEventLog,
    /// Optional hardware TPM device.
    /// When present, PCR extends go to hardware and SubmitCommand is forwarded.
    hardware_tpm: Option<Tpm2Backend>,
    /// Whether GetEventLog has been called by an OS loader.
    /// Subsequent events must also be mirrored to the TCG2 Final Events Table.
    get_event_log_called: bool,
}

impl Tcg2State {
    fn active_hash_bitmap(&self) -> u32 {
        if self.hardware_tpm.is_none() {
            0
        } else {
            bitmap_from_algorithms(self.pcr_banks.algorithms())
        }
    }
}

/// Initialize the TCG2 state.
///
/// Must be called before the protocol is installed. The `existing_log`
/// parameter allows prepopulating the event log with data from a previous
/// firmware phase (e.g., coreboot's CBMEM TCPA log).
///
/// # Arguments
/// * `buffer` - Pre-allocated buffer for the event log.
/// * `existing_log` - Optional pre-existing log data to prepend.
/// * `enable_sha1` - Whether to activate the SHA-1 PCR bank.
pub fn init_state(
    buffer: &'static mut [u8],
    existing_log: Option<&[u8]>,
    enable_sha1: bool,
) -> Result<(), TcgError> {
    let (alg_count, algorithms, existing_log) = software_log_selection(existing_log, enable_sha1);
    let algorithms = &algorithms[..alg_count];

    let event_log = if let Some(existing) = existing_log {
        CryptoAgileEventLog::from_existing(buffer, existing, algorithms)?
    } else {
        CryptoAgileEventLog::new(buffer, algorithms)?
    };

    let pcr_banks = PcrBanks::from_algorithms(algorithms)?;

    let state = Tcg2State {
        pcr_banks,
        event_log,
        hardware_tpm: None,
        get_event_log_called: false,
    };

    *TCG2_STATE.lock() = Some(state);
    Ok(())
}

/// Initialize with a hardware TPM device.
///
/// Similar to [`init_state`] but probes for a TPM at the given MMIO base
/// address. If a hardware TPM is found, PCR extends are sent to hardware
/// and `SubmitCommand` forwards raw TPM commands.
///
/// # Safety
///
/// `tpm_base` must point to a valid TIS MMIO region (e.g., `0xFED40000`).
pub unsafe fn init_state_with_hardware(
    buffer: &'static mut [u8],
    existing_log: Option<&[u8]>,
    tpm_base: u64,
    _enable_sha1: bool,
) -> Result<(), TcgError> {
    // Probe for hardware TPM.
    let tpm = unsafe { TpmTis::probe(tpm_base)? };
    if supported_algorithm_count(tpm.active_algorithms()) == 0 {
        log::error!("Hardware TPM does not expose a supported active PCR bank");
        return Err(TcgError::UnsupportedAlgorithm);
    }

    if let Some(unsupported) = unsupported_active_algorithm(tpm.active_algorithms()) {
        log::error!(
            "Hardware TPM active PCR bank {:#06x} is not supported by CrabEFI measured boot",
            unsupported
        );
        return Err(TcgError::UnsupportedAlgorithm);
    }

    // Continue a previous firmware log only when its SpecID algorithm set
    // exactly matches the TPM's active banks. Otherwise no event log can replay
    // every active PCR consistently, so hardware-backed measured boot is rejected.
    let (alg_count, algorithms, existing_log) =
        hardware_log_selection(existing_log, tpm.active_algorithms())?;
    let algorithms = &algorithms[..alg_count];

    let event_log = if let Some(existing) = existing_log {
        CryptoAgileEventLog::from_existing(buffer, existing, algorithms)?
    } else {
        CryptoAgileEventLog::new(buffer, algorithms)?
    };

    let pcr_banks = PcrBanks::from_algorithms(algorithms)?;

    let state = Tcg2State {
        pcr_banks,
        event_log,
        hardware_tpm: Some(Tpm2Backend::Tis(tpm)),
        get_event_log_called: false,
    };

    *TCG2_STATE.lock() = Some(state);
    log::info!("TCG2 state initialized with TIS hardware TPM");
    Ok(())
}

/// Initialize with a platform-provided TPM 2.0 device.
pub fn init_state_with_platform_tpm(
    buffer: &'static mut [u8],
    existing_log: Option<&[u8]>,
    tpm: &'static mut dyn Tpm2Device,
    _enable_sha1: bool,
) -> Result<(), TcgError> {
    let active_banks = tpm.active_pcr_banks();
    if active_banks.is_truncated() {
        log::error!("Platform TPM active PCR bank list exceeds CrabEFI capacity");
        return Err(TcgError::UnsupportedAlgorithm);
    }
    if supported_algorithm_count(active_banks.algorithms()) == 0 {
        log::error!("Platform TPM does not expose a supported active PCR bank");
        return Err(TcgError::UnsupportedAlgorithm);
    }
    if let Some(unsupported) = unsupported_active_algorithm(active_banks.algorithms()) {
        log::error!(
            "Platform TPM active PCR bank {:#06x} is not supported by CrabEFI measured boot",
            unsupported
        );
        return Err(TcgError::UnsupportedAlgorithm);
    }

    let backend = Tpm2Backend::Driver(tpm);

    // Continue a previous firmware log only when its SpecID algorithm set
    // exactly matches the platform TPM's active banks.
    let (alg_count, algorithms, existing_log) =
        hardware_log_selection(existing_log, active_banks.algorithms())?;
    let algorithms = &algorithms[..alg_count];

    let event_log = if let Some(existing) = existing_log {
        CryptoAgileEventLog::from_existing(buffer, existing, algorithms)?
    } else {
        CryptoAgileEventLog::new(buffer, algorithms)?
    };

    let pcr_banks = PcrBanks::from_algorithms(algorithms)?;

    let state = Tcg2State {
        pcr_banks,
        event_log,
        hardware_tpm: Some(backend),
        get_event_log_called: false,
    };

    *TCG2_STATE.lock() = Some(state);
    log::info!("TCG2 state initialized with platform TPM");
    Ok(())
}

fn algorithm_to_bitmap(algorithm: u16) -> u32 {
    match algorithm {
        TPM_ALG_SHA1 => EFI_TCG2_BOOT_HASH_ALG_SHA1,
        TPM_ALG_SHA256 => EFI_TCG2_BOOT_HASH_ALG_SHA256,
        TPM_ALG_SHA384 => EFI_TCG2_BOOT_HASH_ALG_SHA384,
        TPM_ALG_SHA512 => EFI_TCG2_BOOT_HASH_ALG_SHA512,
        TPM_ALG_SM3_256 => EFI_TCG2_BOOT_HASH_ALG_SM3_256,
        _ => 0,
    }
}

fn bitmap_from_algorithms(algorithms: impl Iterator<Item = u16>) -> u32 {
    algorithms.fold(0, |bitmap, algorithm| {
        bitmap | algorithm_to_bitmap(algorithm)
    })
}

fn is_supported_hash_algorithm(algorithm: u16) -> bool {
    matches!(
        algorithm,
        TPM_ALG_SHA1 | TPM_ALG_SHA256 | TPM_ALG_SHA384 | TPM_ALG_SHA512
    )
}

fn supported_algorithm_count(algorithms: &[u16]) -> usize {
    algorithms
        .iter()
        .filter(|algorithm| is_supported_hash_algorithm(**algorithm))
        .count()
}

fn supported_algorithm_array(algorithms: &[u16]) -> (usize, [u16; 5]) {
    let mut out = [0u16; 5];
    let mut count = 0;
    for &algorithm in algorithms {
        if count >= out.len()
            || !is_supported_hash_algorithm(algorithm)
            || out[..count].contains(&algorithm)
        {
            continue;
        }
        out[count] = algorithm;
        count += 1;
    }
    (count, out)
}

type HardwareLogSelection<'a> = (usize, [u16; 5], Option<&'a [u8]>);

fn software_log_selection(
    existing_log: Option<&[u8]>,
    requested_enable_sha1: bool,
) -> (usize, [u16; 5], Option<&[u8]>) {
    let default = if requested_enable_sha1 {
        supported_algorithm_array(&[TPM_ALG_SHA256, TPM_ALG_SHA1])
    } else {
        supported_algorithm_array(&[TPM_ALG_SHA256])
    };

    let Some(existing) = existing_log else {
        return (default.0, default.1, None);
    };

    let Some((count, existing_algorithms)) = parse_spec_id_algorithms(existing) else {
        log::warn!("Ignoring existing TCG2 log without a valid SpecID event");
        return (default.0, default.1, None);
    };
    let existing_algorithms = &existing_algorithms[..count];

    if let Some(unsupported) = unsupported_active_algorithm(existing_algorithms) {
        log::warn!(
            "Ignoring existing TCG2 log with unsupported SpecID algorithm {:#06x}",
            unsupported
        );
        return (default.0, default.1, None);
    }

    let selected = supported_algorithm_array(existing_algorithms);
    if selected.0 == 0 {
        return (default.0, default.1, None);
    }

    (selected.0, selected.1, Some(existing))
}

fn hardware_log_selection<'a>(
    existing_log: Option<&'a [u8]>,
    tpm_algorithms: &[u16],
) -> Result<HardwareLogSelection<'a>, TcgError> {
    let tpm_supported = supported_algorithm_array(tpm_algorithms);
    let Some(existing) = existing_log else {
        return Ok((tpm_supported.0, tpm_supported.1, None));
    };

    let Some((count, existing_algorithms)) = parse_spec_id_algorithms(existing) else {
        log::error!("Existing TCG2 log does not contain a valid SpecID event");
        return Err(TcgError::InternalError);
    };
    let existing_algorithms = &existing_algorithms[..count];

    if let Some(unsupported) = unsupported_active_algorithm(existing_algorithms) {
        log::error!(
            "Existing TCG2 log contains unsupported SpecID algorithm {:#06x}",
            unsupported
        );
        return Err(TcgError::UnsupportedAlgorithm);
    }

    let selected = supported_algorithm_array(existing_algorithms);
    let active = &tpm_supported.1[..tpm_supported.0];
    let selected_slice = &selected.1[..selected.0];
    if selected.0 != tpm_supported.0
        || !selected_slice
            .iter()
            .all(|algorithm| active.contains(algorithm))
    {
        log::error!(
            "Existing TCG2 log algorithms {:?} do not match active TPM banks {:?}",
            existing_algorithms,
            tpm_algorithms
        );
        return Err(TcgError::UnsupportedAlgorithm);
    }

    Ok((selected.0, selected.1, Some(existing)))
}

fn unsupported_active_algorithm(algorithms: &[u16]) -> Option<u16> {
    algorithms
        .iter()
        .copied()
        .find(|alg| !is_supported_hash_algorithm(*alg))
}

fn parse_spec_id_algorithms(existing_log: &[u8]) -> Option<(usize, [u16; 5])> {
    let legacy_header_size = core::mem::size_of::<TcgPcrEventHdr>();
    if existing_log.len() < legacy_header_size {
        return None;
    }

    let event_data_size_offset = 4 + 4 + SHA1_DIGEST_SIZE;
    let event_data_size = u32::from_le_bytes(
        existing_log
            .get(event_data_size_offset..event_data_size_offset + 4)?
            .try_into()
            .ok()?,
    ) as usize;
    let event_data = existing_log.get(legacy_header_size..legacy_header_size + event_data_size)?;

    // TCG_EfiSpecIDEvent: signature(16), platformClass(4), version bytes(4),
    // numberOfAlgorithms(4), digestSizes[count], vendorInfoSize(1).
    let algorithm_count_offset = 16 + 4 + 1 + 1 + 1 + 1;
    if event_data.get(..16)? != SpecIdEvent::SIGNATURE {
        return None;
    }
    let count = u32::from_le_bytes(
        event_data
            .get(algorithm_count_offset..algorithm_count_offset + 4)?
            .try_into()
            .ok()?,
    ) as usize;
    if count > 5 {
        return None;
    }
    let algorithms_offset = algorithm_count_offset + 4;
    event_data.get(algorithms_offset..algorithms_offset + count * 4 + 1)?;

    let mut algorithms = [0u16; 5];
    for (i, out) in algorithms.iter_mut().take(count).enumerate() {
        let off = algorithms_offset + i * 4;
        *out = u16::from_le_bytes(event_data.get(off..off + 2)?.try_into().ok()?);
    }

    Some((count, algorithms))
}

fn extend_and_maybe_log(
    state: &mut Tcg2State,
    pcr_index: u32,
    event_type: u32,
    digests: &[TaggedDigest],
    event_data: &[u8],
    log_event: bool,
) -> Result<(), TcgError> {
    if pcr_index as usize >= PCR_COUNT {
        return Err(TcgError::InvalidPcrIndex);
    }

    let Some(ref mut tpm) = state.hardware_tpm else {
        return Err(TcgError::InternalError);
    };
    tpm.pcr_extend(pcr_index, digests)?;

    // Keep a software mirror for log verification, but only after hardware PCR
    // extension succeeds. Software-only state is not attestable.
    state.pcr_banks.extend(pcr_index as usize, digests)?;

    if log_event {
        state
            .event_log
            .log_event(pcr_index, event_type, digests, event_data)?;

        if state.get_event_log_called {
            crate::efi::system_table::append_tpm_final_event(
                pcr_index, event_type, digests, event_data,
            )?;
        }
    }

    Ok(())
}

/// Measure a non-PE event through TCG2 state.
///
/// Returns `None` if the TCG2 protocol is not installed.
pub fn measure_event(
    pcr_index: u32,
    event_type: u32,
    data_to_hash: &[u8],
    event_data: &[u8],
) -> Option<Result<(), TcgError>> {
    let mut guard = TCG2_STATE.lock();
    let state = guard.as_mut()?;
    state.hardware_tpm.as_ref()?;
    let (count, digests) = state.pcr_banks.hash_data(data_to_hash);
    Some(extend_and_maybe_log(
        state,
        pcr_index,
        event_type,
        &digests[..count],
        event_data,
        true,
    ))
}

/// Precompute PE/COFF Authenticode digests for active TCG2 banks.
///
/// Returns `None` if the TCG2 protocol is not installed.
pub fn precompute_pe_image_digests(
    pe_data: &[u8],
) -> Option<Result<(usize, [TaggedDigest; 5]), TcgError>> {
    let guard = TCG2_STATE.lock();
    let state = guard.as_ref()?;
    state.hardware_tpm.as_ref()?;
    let (alg_count, algorithms) = state.pcr_banks.algorithm_array();
    Some(
        compute_authenticode_digests(pe_data, &algorithms[..alg_count])
            .map_err(|_| TcgError::InternalError),
    )
}

/// Measure a PE/COFF image through TCG2 state with precomputed digests.
///
/// Returns `None` if the TCG2 protocol is not installed.
pub fn measure_pe_image_digests_event(
    pcr_index: u32,
    event_type: u32,
    digests: &[TaggedDigest],
    event_data: &[u8],
) -> Option<Result<(), TcgError>> {
    let mut guard = TCG2_STATE.lock();
    let state = guard.as_mut()?;
    state.hardware_tpm.as_ref()?;
    let (alg_count, algorithms) = state.pcr_banks.algorithm_array();
    Some((|| {
        let mut filtered = [TaggedDigest::zeroed(0); 5];
        for (i, algorithm) in algorithms[..alg_count].iter().enumerate() {
            filtered[i] = digests
                .iter()
                .find(|digest| digest.algorithm == *algorithm)
                .copied()
                .ok_or(TcgError::UnsupportedAlgorithm)?;
        }
        extend_and_maybe_log(
            state,
            pcr_index,
            event_type,
            &filtered[..alg_count],
            event_data,
            true,
        )
    })())
}

/// Measure a PE/COFF image through TCG2 state using Authenticode hashing.
///
/// Returns `None` if the TCG2 protocol is not installed.
pub fn measure_pe_image_event(
    pcr_index: u32,
    event_type: u32,
    pe_data: &[u8],
    event_data: &[u8],
) -> Option<Result<(), TcgError>> {
    match precompute_pe_image_digests(pe_data)? {
        Ok((count, digests)) => {
            measure_pe_image_digests_event(pcr_index, event_type, &digests[..count], event_data)
        }
        Err(e) => Some(Err(e)),
    }
}

// ============================================================================
// Protocol function pointers (extern "efiapi")
// ============================================================================

/// `EFI_TCG2_PROTOCOL.GetCapability`
extern "efiapi" fn tcg2_get_capability(
    this: *mut Tcg2ProtocolFfi,
    protocol_capability: *mut Tcg2BootServiceCapability,
) -> Status {
    if this.is_null() || protocol_capability.is_null() {
        return Status::INVALID_PARAMETER;
    }

    log::debug!("TCG2.GetCapability()");

    let state = TCG2_STATE.lock();
    let state = match state.as_ref() {
        Some(s) => s,
        None => return Status::DEVICE_ERROR,
    };

    let tpm_present = state.hardware_tpm.is_some();
    let (hash_bitmap, active_bitmap, num_banks) = if !tpm_present {
        (0, 0, 0)
    } else {
        let active = state.active_hash_bitmap();
        (active, active, state.pcr_banks.algorithm_array().0 as u32)
    };

    // SAFETY: we checked null above, and the caller owns the buffer.
    unsafe {
        let caller_size = (*protocol_capability).size;
        let full_size = core::mem::size_of::<Tcg2BootServiceCapability>() as u8;
        let version_1_0_size =
            core::mem::offset_of!(Tcg2BootServiceCapability, number_of_pcr_banks) as u8;

        // Use hardware TPM info when available.
        let (manufacturer_id, max_cmd, max_resp) = match &state.hardware_tpm {
            Some(tpm) => (
                tpm.manufacturer_id(),
                tpm.max_command_size(),
                tpm.max_response_size(),
            ),
            None => (0, 0, 0),
        };

        let capability = Tcg2BootServiceCapability {
            size: full_size,
            structure_version: Tcg2Version { major: 1, minor: 1 },
            protocol_version: Tcg2Version { major: 1, minor: 1 },
            hash_algorithm_bitmap: hash_bitmap,
            supported_event_logs: EFI_TCG2_EVENT_LOG_FORMAT_TCG_2,
            tpm_present_flag: u8::from(tpm_present),
            max_command_size: max_cmd,
            max_response_size: max_resp,
            manufacturer_id,
            number_of_pcr_banks: num_banks,
            active_pcr_banks: active_bitmap,
        };

        // The caller passes the size of their buffer in .size.
        // We must not write beyond that.
        if caller_size < full_size {
            if caller_size >= version_1_0_size {
                let mut compatible = capability.clone();
                compatible.size = version_1_0_size;
                compatible.structure_version = Tcg2Version { major: 1, minor: 0 };
                compatible.protocol_version = Tcg2Version { major: 1, minor: 0 };
                core::ptr::copy_nonoverlapping(
                    &compatible as *const Tcg2BootServiceCapability as *const u8,
                    protocol_capability as *mut u8,
                    version_1_0_size as usize,
                );
                return Status::SUCCESS;
            }
            (*protocol_capability).size = full_size;
            return Status::BUFFER_TOO_SMALL;
        }

        *protocol_capability = capability;
    }

    log::debug!("  -> SUCCESS ({} bank(s))", num_banks);
    Status::SUCCESS
}

/// `EFI_TCG2_PROTOCOL.GetEventLog`
extern "efiapi" fn tcg2_get_event_log(
    this: *mut Tcg2ProtocolFfi,
    event_log_format: u32,
    event_log_location: *mut u64,
    event_log_last_entry: *mut u64,
    event_log_truncated: *mut u8,
) -> Status {
    log::debug!("TCG2.GetEventLog(format={:#x})", event_log_format);

    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // We only support the crypto-agile (TCG2) event log format.
    if event_log_format != EFI_TCG2_EVENT_LOG_FORMAT_TCG_2 {
        log::debug!("  -> INVALID_PARAMETER (unsupported log format)");
        return Status::INVALID_PARAMETER;
    }

    let mut state = TCG2_STATE.lock();
    let state = match state.as_mut() {
        Some(s) => s,
        None => return Status::DEVICE_ERROR,
    };

    let log_data = state.event_log.log_data();

    if !event_log_location.is_null() {
        // SAFETY: caller guarantees valid pointer.
        unsafe {
            *event_log_location = log_data.as_ptr() as u64;
        }
    }

    if !event_log_last_entry.is_null() {
        // Return pointer to the start of the last event in the log.
        // Linux's tpm_read_log_efi() uses (last_entry - first_entry) +
        // last_entry_size to determine the log size. If no events have
        // been appended (only the SpecID header), return 0.
        unsafe {
            *event_log_last_entry = match state.event_log.last_entry_offset() {
                Some(off) => log_data.as_ptr() as u64 + off as u64,
                None => 0,
            };
        }
    }

    if !event_log_truncated.is_null() {
        unsafe {
            *event_log_truncated = if state.event_log.is_truncated() { 1 } else { 0 };
        }
    }

    state.get_event_log_called = true;

    log::debug!(
        "  -> SUCCESS (log at {:#x}, {} bytes)",
        log_data.as_ptr() as u64,
        log_data.len()
    );
    Status::SUCCESS
}

/// `EFI_TCG2_PROTOCOL.HashLogExtendEvent`
///
/// Hash the provided data, extend the specified PCR in all active banks,
/// and append an event to the crypto-agile event log.
extern "efiapi" fn tcg2_hash_log_extend_event(
    this: *mut Tcg2ProtocolFfi,
    flags: u64,
    data_to_hash: u64, // PhysicalAddress
    data_to_hash_len: u64,
    event: *const c_void,
) -> Status {
    if this.is_null() || event.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Read the event header to get PCR index, event type, and event data.
    // SAFETY: caller guarantees `event` points to a valid EFI_TCG2_EVENT.
    // The structure is packed by the TCG2 protocol definition, so fields must
    // be copied with unaligned reads.
    let tcg2_event = event as *const Tcg2Event;
    let event_size = unsafe { core::ptr::addr_of!((*tcg2_event).size).read_unaligned() };
    let header = unsafe { core::ptr::addr_of!((*tcg2_event).header).read_unaligned() };
    let pcr_index = header.pcr_index;
    let event_type = header.event_type;

    log::debug!(
        "TCG2.HashLogExtendEvent(pcr={}, type={:#x}, data_len={}, flags={:#x})",
        pcr_index,
        event_type,
        data_to_hash_len,
        flags,
    );

    // EDK2 treats EV_NO_ACTION indices above the PCR range as TPM NV indices.
    // CrabEFI does not implement that optional path, so reject them rather than
    // logging a zero-digest event that was never extended anywhere.
    if pcr_index as usize >= PCR_COUNT {
        return Status::INVALID_PARAMETER;
    }

    if header.header_size as usize != core::mem::size_of::<Tcg2EventHeader>()
        || header.header_version != 1
    {
        return Status::INVALID_PARAMETER;
    }

    let header_total_size = core::mem::size_of::<u32>() + header.header_size as usize;
    if event_size < header_total_size as u32 {
        return Status::INVALID_PARAMETER;
    }

    if event_type != EV_NO_ACTION && data_to_hash == 0 {
        return Status::INVALID_PARAMETER;
    }

    let mut state = TCG2_STATE.lock();
    let state = match state.as_mut() {
        Some(s) => s,
        None => return Status::DEVICE_ERROR,
    };

    // Calculate event data offset and size after validating the caller-provided
    // event header. EV_NO_ACTION is log-only and can be accepted without an
    // attestable TPM backend.
    let event_data_size = (event_size - header_total_size as u32) as usize;
    let event_data = if event_data_size > 0 {
        // SAFETY: the event data follows the fixed-size header in the caller's
        // EFI_TCG2_EVENT buffer. Header fields were validated above.
        unsafe {
            let data_ptr = (event as *const u8).add(header_total_size);
            core::slice::from_raw_parts(data_ptr, event_data_size)
        }
    } else {
        &[]
    };

    // EV_NO_ACTION is log-only by specification. EDK2 records zero digests and
    // deliberately skips TPM PCR extension for this event type.
    if event_type == EV_NO_ACTION {
        let (alg_count, algorithms) = state.pcr_banks.algorithm_array();
        let mut digests = [TaggedDigest::zeroed(0); 5];
        for (out, alg) in digests.iter_mut().zip(algorithms.iter()).take(alg_count) {
            *out = TaggedDigest::zeroed(*alg);
        }

        if flags & TCG2_EXTEND_ONLY == 0 {
            match state.event_log.log_event(
                pcr_index,
                event_type,
                &digests[..alg_count],
                event_data,
            ) {
                Ok(()) => {
                    if state.get_event_log_called
                        && let Err(e) = crate::efi::system_table::append_tpm_final_event(
                            pcr_index,
                            event_type,
                            &digests[..alg_count],
                            event_data,
                        )
                    {
                        log::error!("TCG2 final event append failed: {:?}", e);
                        return Status::DEVICE_ERROR;
                    }
                }
                Err(TcgError::LogFull) => return Status::VOLUME_FULL,
                Err(e) => {
                    log::error!("TCG2 EV_NO_ACTION log failed: {:?}", e);
                    return Status::DEVICE_ERROR;
                }
            }
        }
        return Status::SUCCESS;
    }

    if state.hardware_tpm.is_none() {
        log::debug!("TCG2.HashLogExtendEvent() -> DEVICE_ERROR (no physical TPM)");
        return Status::DEVICE_ERROR;
    }

    let Some(data_to_hash_len) = checked_slice_len(data_to_hash_len) else {
        return Status::INVALID_PARAMETER;
    };

    // Hash the data to be measured.
    let data_slice = if data_to_hash_len > 0 {
        // SAFETY: caller guarantees the physical address range is valid.
        unsafe { core::slice::from_raw_parts(data_to_hash as *const u8, data_to_hash_len) }
    } else {
        &[]
    };

    // Hash the data with all active algorithms.
    // When TCG2_PE_COFF_IMAGE is set, use Authenticode hash (excludes
    // checksum, cert table entry, and certificate data) per the TCG PFP spec.
    let (digest_count, digests) = if flags & TCG2_PE_COFF_IMAGE != 0 && !data_slice.is_empty() {
        let (alg_count, algorithms) = state.pcr_banks.algorithm_array();
        match compute_authenticode_digests(data_slice, &algorithms[..alg_count]) {
            Ok(result) => result,
            Err(e) => {
                log::error!("PE/COFF authenticode hash failed: {:?}", e);
                return Status::DEVICE_ERROR;
            }
        }
    } else {
        state.pcr_banks.hash_data(data_slice)
    };

    match extend_and_maybe_log(
        state,
        pcr_index,
        event_type,
        &digests[..digest_count],
        event_data,
        flags & TCG2_EXTEND_ONLY == 0,
    ) {
        Ok(()) => {
            log::debug!("  -> SUCCESS");
            Status::SUCCESS
        }
        Err(TcgError::InvalidPcrIndex) => Status::INVALID_PARAMETER,
        Err(TcgError::LogFull) => {
            log::warn!("Event log append failed: log full");
            Status::VOLUME_FULL
        }
        Err(e) => {
            log::error!("TCG2.HashLogExtendEvent failed: {:?}", e);
            Status::DEVICE_ERROR
        }
    }
}

/// `EFI_TCG2_PROTOCOL.SubmitCommand`
///
/// Forwards raw TPM commands to hardware TPM if available.
/// Returns DEVICE_ERROR when no physical TPM backend is available.
extern "efiapi" fn tcg2_submit_command(
    this: *mut Tcg2ProtocolFfi,
    input_parameter_block_size: u32,
    input_parameter_block: *const u8,
    output_parameter_block_size: u32,
    output_parameter_block: *mut u8,
) -> Status {
    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }

    if input_parameter_block.is_null()
        || output_parameter_block.is_null()
        || input_parameter_block_size < 10
        || output_parameter_block_size == 0
    {
        return Status::INVALID_PARAMETER;
    }

    let mut state = TCG2_STATE.lock();
    let state = match state.as_mut() {
        Some(s) => s,
        None => return Status::DEVICE_ERROR,
    };

    let tpm = match state.hardware_tpm.as_mut() {
        Some(t) => t,
        None => {
            log::debug!("TCG2.SubmitCommand() -> DEVICE_ERROR (no physical TPM)");
            return Status::DEVICE_ERROR;
        }
    };

    let max_command_size = tpm.max_command_size();
    if max_command_size != 0 && input_parameter_block_size > max_command_size as u32 {
        return Status::INVALID_PARAMETER;
    }
    let max_response_size = tpm.max_response_size();
    if max_response_size != 0 && output_parameter_block_size > max_response_size as u32 {
        return Status::INVALID_PARAMETER;
    }
    let input = unsafe {
        core::slice::from_raw_parts(input_parameter_block, input_parameter_block_size as usize)
    };
    let output = unsafe {
        core::slice::from_raw_parts_mut(
            output_parameter_block,
            output_parameter_block_size as usize,
        )
    };

    match tpm.submit_command(input, output) {
        Ok(_) => {
            log::debug!("TCG2.SubmitCommand() -> SUCCESS");
            Status::SUCCESS
        }
        Err(TcgError::EventTooLarge) => {
            log::debug!("TCG2.SubmitCommand() -> BUFFER_TOO_SMALL");
            Status::BUFFER_TOO_SMALL
        }
        Err(TcgError::InvalidPcrIndex) => {
            log::debug!("TCG2.SubmitCommand() -> INVALID_PARAMETER");
            Status::INVALID_PARAMETER
        }
        Err(TcgError::UnsupportedAlgorithm) => {
            log::debug!("TCG2.SubmitCommand() -> UNSUPPORTED");
            Status::UNSUPPORTED
        }
        Err(e) => {
            log::error!("TCG2.SubmitCommand() failed: {:?}", e);
            Status::DEVICE_ERROR
        }
    }
}

/// `EFI_TCG2_PROTOCOL.GetActivePcrBanks`
extern "efiapi" fn tcg2_get_active_pcr_banks(
    this: *mut Tcg2ProtocolFfi,
    active_pcr_banks: *mut u32,
) -> Status {
    if this.is_null() || active_pcr_banks.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let state = TCG2_STATE.lock();
    let state = match state.as_ref() {
        Some(s) => s,
        None => return Status::DEVICE_ERROR,
    };

    let bitmap = state.active_hash_bitmap();

    unsafe {
        *active_pcr_banks = bitmap;
    }

    log::debug!("TCG2.GetActivePcrBanks() -> {:#x}", bitmap);
    Status::SUCCESS
}

/// `EFI_TCG2_PROTOCOL.SetActivePcrBanks`
///
/// Active PCR banks are fixed at initialization.
///
/// CrabEFI does not currently implement a physical-presence/reboot-backed
/// TPM2_PCR_Allocate flow. The current active set is accepted as a no-op;
/// requests to switch to any other set are rejected without modifying TPM state.
extern "efiapi" fn tcg2_set_active_pcr_banks(
    this: *mut Tcg2ProtocolFfi,
    active_pcr_banks: u32,
) -> Status {
    if this.is_null() || active_pcr_banks == 0 {
        return Status::INVALID_PARAMETER;
    }

    let state = TCG2_STATE.lock();
    let state = match state.as_ref() {
        Some(s) => s,
        None => return Status::DEVICE_ERROR,
    };

    let current = state.active_hash_bitmap();

    if active_pcr_banks & !state.active_hash_bitmap() != 0 {
        return Status::INVALID_PARAMETER;
    }

    if active_pcr_banks == current {
        log::debug!("TCG2.SetActivePcrBanks() -> SUCCESS (already active)");
        Status::SUCCESS
    } else {
        log::debug!("TCG2.SetActivePcrBanks() -> UNSUPPORTED (bank switching unavailable)");
        Status::UNSUPPORTED
    }
}

/// `EFI_TCG2_PROTOCOL.GetResultOfSetActivePcrBanks`
extern "efiapi" fn tcg2_get_result_of_set_active_pcr_banks(
    this: *mut Tcg2ProtocolFfi,
    operation_present: *mut u32,
    response: *mut u32,
) -> Status {
    if this.is_null() || operation_present.is_null() || response.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // No pending SetActivePcrBanks operation.
    if !operation_present.is_null() {
        unsafe {
            *operation_present = 0;
        }
    }
    if !response.is_null() {
        unsafe {
            *response = 0;
        }
    }
    log::debug!("TCG2.GetResultOfSetActivePcrBanks() -> SUCCESS (no pending op)");
    Status::SUCCESS
}

// ============================================================================
// Protocol struct (matches EFI_TCG2_PROTOCOL ABI)
// ============================================================================

/// FFI-compatible `EFI_TCG2_PROTOCOL` structure.
///
/// Layout matches the TCG EFI Protocol Specification and `uefi-raw`'s
/// `Tcg2Protocol` struct.
#[repr(C)]
pub struct Tcg2ProtocolFfi {
    pub get_capability: extern "efiapi" fn(*mut Self, *mut Tcg2BootServiceCapability) -> Status,
    pub get_event_log: extern "efiapi" fn(*mut Self, u32, *mut u64, *mut u64, *mut u8) -> Status,
    pub hash_log_extend_event:
        extern "efiapi" fn(*mut Self, u64, u64, u64, *const c_void) -> Status,
    pub submit_command: extern "efiapi" fn(*mut Self, u32, *const u8, u32, *mut u8) -> Status,
    pub get_active_pcr_banks: extern "efiapi" fn(*mut Self, *mut u32) -> Status,
    pub set_active_pcr_banks: extern "efiapi" fn(*mut Self, u32) -> Status,
    pub get_result_of_set_active_pcr_banks:
        extern "efiapi" fn(*mut Self, *mut u32, *mut u32) -> Status,
}

// ============================================================================
// Public API
// ============================================================================

/// Create and initialize the TCG2 Protocol.
///
/// Returns a pointer to the protocol instance, or null on allocation failure.
/// The protocol's internal state must be initialized via [`init_state`] before
/// calling this.
pub fn create_protocol() -> *mut c_void {
    let ptr = allocate_protocol_with_log::<Tcg2ProtocolFfi>("TCG2Protocol", |p| {
        p.get_capability = tcg2_get_capability;
        p.get_event_log = tcg2_get_event_log;
        p.hash_log_extend_event = tcg2_hash_log_extend_event;
        p.submit_command = tcg2_submit_command;
        p.get_active_pcr_banks = tcg2_get_active_pcr_banks;
        p.set_active_pcr_banks = tcg2_set_active_pcr_banks;
        p.get_result_of_set_active_pcr_banks = tcg2_get_result_of_set_active_pcr_banks;
    });

    if ptr.is_null() {
        return core::ptr::null_mut();
    }

    log::info!("EFI_TCG2_PROTOCOL created");
    ptr as *mut c_void
}
