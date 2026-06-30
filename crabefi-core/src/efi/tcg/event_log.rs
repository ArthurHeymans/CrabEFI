//! TPM event log management.
//!
//! This module provides the [`EventLog`] trait that abstracts over different
//! TPM event log formats, and concrete implementations for:
//!
//! - **Crypto-agile log** (TPM 2.0): `TCG_PCR_EVENT2` entries with multiple
//!   hash algorithms per event. Used by `EFI_TCG2_PROTOCOL`.
//! - **SHA1-only log** (TPM 1.2): `TCG_PCClientPCREvent` entries with a
//!   single SHA-1 digest. Used by `EFI_TCG_PROTOCOL`.
//!
//! # Coreboot integration
//!
//! Coreboot maintains TPM event logs in CBMEM (for example
//! `CBMEM_ID_TCPA_TCG_LOG` 0x54445041 for TPM 1.2 and `CBMEM_ID_TPM2_TCG_LOG`
//! 0x54504d32 for TPM 2.0). When CrabEFI runs as a coreboot payload, the
//! platform can provide this pre-existing log data via
//! [`crate::platform::TpmEventLogConfig`].
//! The event log implementations support initializing from existing data,
//! allowing CrabEFI to append firmware-phase measurements to coreboot's log.
//!
//! # Design
//!
//! The trait is object-safe so it can be used behind `&dyn EventLog` in the
//! protocol implementations. This allows runtime selection of the log format
//! based on TPM capabilities without generic monomorphization.

use super::types::{
    CryptoAgileEvent, SHA1_DIGEST_SIZE, SpecIdEvent, TaggedDigest, TcgError, TcgPcrEventHdr,
    digest_size_for_algorithm,
};

fn read_le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = data.get(offset..end)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes = data.get(offset..end)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn legacy_event_total_size(data: &[u8], offset: usize) -> Option<usize> {
    let header_size = core::mem::size_of::<TcgPcrEventHdr>();
    let size_offset = offset.checked_add(4 + 4 + SHA1_DIGEST_SIZE)?;
    let event_data_size = read_le_u32(data, size_offset)? as usize;
    let total = header_size.checked_add(event_data_size)?;
    let end = offset.checked_add(total)?;
    data.get(offset..end)?;
    Some(total)
}

fn parse_sha1_last_entry_offset(data: &[u8]) -> Result<Option<usize>, ()> {
    if data.is_empty() {
        return Ok(None);
    }

    let mut offset = 0usize;
    let mut last_entry = None;
    while offset < data.len() {
        let total = legacy_event_total_size(data, offset).ok_or(())?;
        last_entry = Some(offset);
        offset = offset.checked_add(total).ok_or(())?;
    }

    Ok(last_entry)
}

fn parse_crypto_agile_last_entry_offset(data: &[u8]) -> Result<Option<usize>, ()> {
    if data.is_empty() {
        return Ok(None);
    }

    let first_total = legacy_event_total_size(data, 0).ok_or(())?;
    if first_total == data.len() {
        return Ok(None);
    }

    let mut offset = first_total;
    let mut last_entry = None;
    while offset < data.len() {
        let event_start = offset;
        let header_end = offset.checked_add(12).ok_or(())?;
        data.get(offset..header_end).ok_or(())?;
        let digest_count_offset = offset.checked_add(8).ok_or(())?;
        let digest_count = read_le_u32(data, digest_count_offset).ok_or(())? as usize;
        offset = header_end;

        for _ in 0..digest_count {
            let algorithm = read_le_u16(data, offset).ok_or(())?;
            offset = offset.checked_add(2).ok_or(())?;
            let digest_size = digest_size_for_algorithm(algorithm).ok_or(())?;
            let digest_end = offset.checked_add(digest_size).ok_or(())?;
            data.get(offset..digest_end).ok_or(())?;
            offset = digest_end;
        }

        let event_data_size = read_le_u32(data, offset).ok_or(())? as usize;
        offset = offset.checked_add(4).ok_or(())?;
        let event_end = offset.checked_add(event_data_size).ok_or(())?;
        data.get(offset..event_end).ok_or(())?;
        offset = event_end;
        last_entry = Some(event_start);
    }

    Ok(last_entry)
}

// ============================================================================
// Event Log Format
// ============================================================================

/// Event log format identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLogFormat {
    /// TCG PC Client SHA1-only log (TPM 1.2).
    Sha1,
    /// TCG2 crypto-agile log (TPM 2.0).
    CryptoAgile,
}

// ============================================================================
// Event Log Trait
// ============================================================================

/// Abstraction over TPM event log formats.
///
/// Multiple variants exist in practice:
/// - TPM 1.2 SHA1-only log (`TCG_PCClientPCREvent`)
/// - TPM 2.0 crypto-agile log (`TCG_PCR_EVENT2` with multiple digests)
/// - Coreboot TCPA log (in CBMEM, follows either format above)
///
/// Implementations manage an in-memory buffer that grows as events are
/// appended. The buffer is allocated once at initialization and has a
/// fixed maximum size.
pub trait EventLog {
    /// Return the log format.
    fn format(&self) -> EventLogFormat;

    /// Return the raw event log bytes written so far.
    fn log_data(&self) -> &[u8];

    /// Return the total capacity of the event log buffer.
    fn capacity(&self) -> usize;

    /// Whether the log has been truncated (an event was dropped due to
    /// insufficient space).
    fn is_truncated(&self) -> bool;

    /// Return the byte offset of the last event written to the log.
    ///
    /// Returns `None` if no events have been written yet. The offset is
    /// relative to the start of `log_data()`. Linux's `tpm_read_log_efi()`
    /// uses this (via `GetEventLog`'s `event_log_last_entry`) to determine
    /// the log size.
    fn last_entry_offset(&self) -> Option<usize>;

    /// Append a crypto-agile event to the log.
    ///
    /// For SHA1-only logs, only the SHA-1 digest from `digests` is used.
    fn log_event(
        &mut self,
        pcr_index: u32,
        event_type: u32,
        digests: &[TaggedDigest],
        event_data: &[u8],
    ) -> Result<(), TcgError>;
}

// ============================================================================
// Crypto-Agile Event Log (TPM 2.0)
// ============================================================================

/// Default event log buffer size: 64 KiB.
///
/// This matches EDK2's default `TCG2_DEFAULT_MAX_EVENT_LOG_SIZE`.
/// The buffer is allocated from `BootServicesData` memory.
pub const DEFAULT_EVENT_LOG_SIZE: usize = 64 * 1024;

/// Crypto-agile event log for TPM 2.0.
///
/// The log starts with a legacy `TcgPcrEventHdr` wrapper containing a
/// `SpecIdEvent` (as required by the TCG PFP specification), followed by
/// `TCG_PCR_EVENT2` entries in the crypto-agile format.
pub struct CryptoAgileEventLog {
    /// The backing buffer for the event log.
    buffer: &'static mut [u8],
    /// Current write offset into the buffer.
    used: usize,
    /// Byte offset of the last event written (for `GetEventLog` last entry).
    last_entry: Option<usize>,
    /// Whether the log was truncated (an event didn't fit).
    truncated: bool,
    /// Active hash algorithms in this log (algorithm IDs).
    algorithms: [u16; 5],
    /// Number of active algorithms.
    num_algorithms: usize,
}

impl CryptoAgileEventLog {
    /// Create a new crypto-agile event log backed by the given buffer.
    ///
    /// Writes the Specification ID Event as the first entry. The
    /// `algorithms` slice specifies which hash algorithms are active
    /// (e.g., `&[TPM_ALG_SHA256]` or `&[TPM_ALG_SHA1, TPM_ALG_SHA256]`).
    ///
    /// # Arguments
    /// * `buffer` - Pre-allocated buffer for the event log.
    /// * `algorithms` - Active hash algorithm IDs.
    pub fn new(buffer: &'static mut [u8], algorithms: &[u16]) -> Result<Self, TcgError> {
        let num_algorithms = algorithms.len().min(5);
        let mut algs = [0u16; 5];
        algs[..num_algorithms].copy_from_slice(&algorithms[..num_algorithms]);

        let mut log = Self {
            buffer,
            used: 0,
            last_entry: None,
            truncated: false,
            algorithms: algs,
            num_algorithms,
        };

        // Write the Specification ID Event wrapped in a legacy event header.
        log.write_spec_id_event()?;

        Ok(log)
    }

    /// Create a crypto-agile event log from an existing log buffer.
    ///
    /// This is used when appending to a coreboot-provided log. The
    /// `existing_data` is copied into the beginning of `buffer`, and
    /// new events are appended after it.
    ///
    /// # Arguments
    /// * `buffer` - Pre-allocated buffer for the event log.
    /// * `existing_data` - Pre-existing log data to prepend.
    /// * `algorithms` - Active hash algorithm IDs.
    pub fn from_existing(
        buffer: &'static mut [u8],
        existing_data: &[u8],
        algorithms: &[u16],
    ) -> Result<Self, TcgError> {
        if existing_data.len() > buffer.len() {
            return Err(TcgError::LogFull);
        }

        buffer[..existing_data.len()].copy_from_slice(existing_data);

        let num_algorithms = algorithms.len().min(5);
        let mut algs = [0u16; 5];
        algs[..num_algorithms].copy_from_slice(&algorithms[..num_algorithms]);

        let last_entry = match parse_crypto_agile_last_entry_offset(existing_data) {
            Ok(offset) => offset,
            Err(()) => {
                log::warn!("Existing TCG2 event log could not be parsed for last-entry offset");
                None
            }
        };

        Ok(Self {
            buffer,
            used: existing_data.len(),
            last_entry,
            truncated: false,
            algorithms: algs,
            num_algorithms,
        })
    }

    /// Write the TCG Specification ID Event as the first log entry.
    ///
    /// Per the TCG PFP specification, the first entry in a crypto-agile
    /// log must be a `TCG_EfiSpecIDEvent` wrapped in a legacy
    /// `TCG_PCClientPCREvent` header (PCR 0, EV_NO_ACTION, SHA1=zeros).
    fn write_spec_id_event(&mut self) -> Result<(), TcgError> {
        // Build the SpecIdEvent payload.
        let mut spec_id = SpecIdEvent {
            num_algorithms: self.num_algorithms as u32,
            digest_sizes: [(0, 0); 5],
        };
        for i in 0..self.num_algorithms {
            let alg = self.algorithms[i];
            let size = digest_size_for_algorithm(alg).ok_or(TcgError::UnsupportedAlgorithm)?;
            spec_id.digest_sizes[i] = (alg, size as u16);
        }

        // Serialize the spec ID event data into a temporary buffer.
        let mut spec_data = [0u8; 128];
        let spec_len = spec_id
            .serialize(&mut spec_data)
            .ok_or(TcgError::InternalError)?;

        // Write a legacy event header wrapping the spec ID event.
        let header = TcgPcrEventHdr {
            pcr_index: 0,
            event_type: super::types::EV_NO_ACTION,
            digest: [0u8; SHA1_DIGEST_SIZE],
            event_data_size: spec_len as u32,
        };

        let header_size = core::mem::size_of::<TcgPcrEventHdr>();
        let total = header_size + spec_len;

        if self.used + total > self.buffer.len() {
            return Err(TcgError::LogFull);
        }

        // Write header as raw bytes.
        // SAFETY: TcgPcrEventHdr is repr(C, packed) and Copy.
        let header_bytes = unsafe {
            core::slice::from_raw_parts(&header as *const TcgPcrEventHdr as *const u8, header_size)
        };
        self.buffer[self.used..self.used + header_size].copy_from_slice(header_bytes);
        self.used += header_size;

        // Write spec ID event data.
        self.buffer[self.used..self.used + spec_len].copy_from_slice(&spec_data[..spec_len]);
        self.used += spec_len;

        Ok(())
    }

    /// Return the active algorithm IDs.
    pub fn algorithms(&self) -> &[u16] {
        &self.algorithms[..self.num_algorithms]
    }
}

impl EventLog for CryptoAgileEventLog {
    fn format(&self) -> EventLogFormat {
        EventLogFormat::CryptoAgile
    }

    fn log_data(&self) -> &[u8] {
        &self.buffer[..self.used]
    }

    fn capacity(&self) -> usize {
        self.buffer.len()
    }

    fn is_truncated(&self) -> bool {
        self.truncated
    }

    fn last_entry_offset(&self) -> Option<usize> {
        self.last_entry
    }

    fn log_event(
        &mut self,
        pcr_index: u32,
        event_type: u32,
        digests: &[TaggedDigest],
        event_data: &[u8],
    ) -> Result<(), TcgError> {
        let event = CryptoAgileEvent {
            pcr_index,
            event_type,
            digests,
            event_data,
        };

        let needed = event.serialized_size();
        if self.used + needed > self.buffer.len() {
            self.truncated = true;
            return Err(TcgError::LogFull);
        }

        // Record the offset of this event before writing — this is the
        // "last entry" pointer that GetEventLog returns.
        self.last_entry = Some(self.used);

        let written = event
            .serialize(&mut self.buffer[self.used..])
            .ok_or(TcgError::InternalError)?;
        self.used += written;

        Ok(())
    }
}

// ============================================================================
// SHA1-only Event Log (TPM 1.2)
// ============================================================================

/// SHA1-only event log for TPM 1.2.
///
/// Contains `TCG_PCClientPCREvent` entries with fixed SHA-1 digests.
pub struct Sha1EventLog {
    /// The backing buffer for the event log.
    buffer: &'static mut [u8],
    /// Current write offset into the buffer.
    used: usize,
    /// Byte offset of the last event written.
    last_entry: Option<usize>,
    /// Whether the log was truncated.
    truncated: bool,
}

impl Sha1EventLog {
    /// Create a new SHA1-only event log backed by the given buffer.
    pub fn new(buffer: &'static mut [u8]) -> Self {
        Self {
            buffer,
            used: 0,
            last_entry: None,
            truncated: false,
        }
    }

    /// Create from an existing log buffer (e.g., coreboot TCPA log).
    pub fn from_existing(
        buffer: &'static mut [u8],
        existing_data: &[u8],
    ) -> Result<Self, TcgError> {
        if existing_data.len() > buffer.len() {
            return Err(TcgError::LogFull);
        }
        buffer[..existing_data.len()].copy_from_slice(existing_data);
        let last_entry = match parse_sha1_last_entry_offset(existing_data) {
            Ok(offset) => offset,
            Err(()) => {
                log::warn!("Existing TCG event log could not be parsed for last-entry offset");
                None
            }
        };
        Ok(Self {
            buffer,
            used: existing_data.len(),
            last_entry,
            truncated: false,
        })
    }
}

impl EventLog for Sha1EventLog {
    fn format(&self) -> EventLogFormat {
        EventLogFormat::Sha1
    }

    fn log_data(&self) -> &[u8] {
        &self.buffer[..self.used]
    }

    fn capacity(&self) -> usize {
        self.buffer.len()
    }

    fn is_truncated(&self) -> bool {
        self.truncated
    }

    fn last_entry_offset(&self) -> Option<usize> {
        self.last_entry
    }

    fn log_event(
        &mut self,
        pcr_index: u32,
        event_type: u32,
        digests: &[TaggedDigest],
        event_data: &[u8],
    ) -> Result<(), TcgError> {
        // Extract the SHA-1 digest from the provided digests.
        // Return an error if no SHA-1 digest is present — silently using
        // a zero digest would produce a valid-looking but incorrect log entry.
        let sha1_digest = digests
            .iter()
            .find(|d| d.algorithm == super::types::TPM_ALG_SHA1)
            .map(|d| {
                let mut out = [0u8; SHA1_DIGEST_SIZE];
                out.copy_from_slice(&d.digest[..SHA1_DIGEST_SIZE]);
                out
            })
            .ok_or(TcgError::UnsupportedAlgorithm)?;

        let header = TcgPcrEventHdr {
            pcr_index,
            event_type,
            digest: sha1_digest,
            event_data_size: event_data.len() as u32,
        };

        let header_size = core::mem::size_of::<TcgPcrEventHdr>();
        let total = header_size + event_data.len();

        if self.used + total > self.buffer.len() {
            self.truncated = true;
            return Err(TcgError::LogFull);
        }

        // Record the offset of this event before writing.
        self.last_entry = Some(self.used);

        // Write header.
        // SAFETY: TcgPcrEventHdr is repr(C, packed) and Copy.
        let header_bytes = unsafe {
            core::slice::from_raw_parts(&header as *const TcgPcrEventHdr as *const u8, header_size)
        };
        self.buffer[self.used..self.used + header_size].copy_from_slice(header_bytes);
        self.used += header_size;

        // Write event data.
        self.buffer[self.used..self.used + event_data.len()].copy_from_slice(event_data);
        self.used += event_data.len();

        Ok(())
    }
}
