//! TPM TIS (TPM Interface Specification) MMIO driver.
//!
//! This module implements the TCG PC Client Platform TPM Profile (TIS)
//! register interface for communicating with hardware TPM 1.2 and TPM 2.0
//! devices
//! via memory-mapped I/O. This is the standard interface used by:
//!
//! - Discrete TPM chips (dTPM) on x86 platforms
//! - QEMU's `tpm-tis` device (backed by `swtpm`)
//! - coreboot's TPM driver on x86
//!
//! The TIS interface uses locality 0 at the standard MMIO base address
//! `0xFED4_0000`, with each locality occupying a 4 KiB page.
//!
//! # References
//!
//! - TCG PC Client Platform TPM Profile (PTP) Specification
//! - TCG PC Client Specific TIS, Family 1.3

use super::types::{
    SHA1_DIGEST_SIZE, TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, TaggedDigest,
    TcgError, digest_size_for_algorithm,
};
use crate::platform::{Tpm2Device, TpmDigest, TpmError, TpmPcrBanks};

// ============================================================================
// TIS Register Offsets (within a locality page)
// ============================================================================

/// Standard TIS MMIO base address on x86.
pub const TIS_BASE_ADDRESS: u64 = 0xFED4_0000;

/// TIS register: Access control.
const TPM_ACCESS: usize = 0x000;
/// TIS register: Status / control.
const TPM_STS: usize = 0x018;
/// TIS register: Data FIFO (read/write command and response bytes).
const TPM_DATA_FIFO: usize = 0x024;
/// TIS register: Device ID / Vendor ID.
const TPM_DID_VID: usize = 0xF00;
/// TIS register: Interface ID (PTP).
#[allow(dead_code)]
const TPM_INTF_ID: usize = 0x030;

// TPM_ACCESS bits
const ACCESS_VALID: u8 = 1 << 7;
const ACCESS_ACTIVE_LOCALITY: u8 = 1 << 5;
const ACCESS_REQUEST_USE: u8 = 1 << 1;

// TPM_STS bits. The status byte is at TPM_STS; burst count is the following
// two bytes in little-endian order. Use byte accesses for command/status bits
// because TIS defines write-one side effects on the status byte.
const STS_VALID: u8 = 1 << 7;
const STS_COMMAND_READY: u8 = 1 << 6;
const STS_DATA_AVAIL: u8 = 1 << 4;
#[allow(dead_code)]
const STS_EXPECT: u8 = 1 << 3;
const STS_GO: u8 = 1 << 5;
const STS_CANCEL_OFFSET: usize = TPM_STS + 3;
const STS_CANCEL: u8 = 1;

// TPM response codes
const TPM_RC_SUCCESS: u32 = 0x000;

// TPM 1.2 command and response constants. TPM 1.2 and TPM 2.0 share the
// TIS FIFO transport, but use disjoint command/response tag spaces.
const TPM12_TAG_RQU_COMMAND: u16 = 0x00C1;
const TPM12_TAG_RSP_COMMAND: u16 = 0x00C4;
const TPM12_TAG_RSP_AUTH1_COMMAND: u16 = 0x00C5;
const TPM12_TAG_RSP_AUTH2_COMMAND: u16 = 0x00C6;
const TPM12_ORD_STARTUP: u32 = 0x0000_0099;
const TPM12_ORD_EXTEND: u32 = 0x0000_0014;
const TPM12_ST_CLEAR: u16 = 0x0001;
const TPM12_INVALID_POSTINIT: u32 = 0x0000_0026;

// TPM2 command tags and codes
const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM2_CC_STARTUP: u32 = 0x0000_0144;
const TPM2_CC_PCR_EXTEND: u32 = 0x0000_0182;
const TPM2_CC_GET_CAPABILITY: u32 = 0x0000_017A;
const TPM2_CC_SELF_TEST: u32 = 0x0000_0143;

// TPM2 capability constants
const TPM2_CAP_PCRS: u32 = 0x0000_0005;
const TPM2_CAP_TPM_PROPERTIES: u32 = 0x0000_0006;
const TPM2_PT_MANUFACTURER: u32 = 0x0000_0105;
const TPM2_PT_MAX_COMMAND_SIZE: u32 = 0x0000_011E;
const TPM2_PT_MAX_RESPONSE_SIZE: u32 = 0x0000_011F;

// TPM2_Startup types
const TPM2_SU_CLEAR: u16 = 0x0000;

// TIS timeout classes from the PC Client TPM Interface Specification.
const TPM_TIMEOUT_A_US: u64 = 750_000;
const TPM_TIMEOUT_B_US: u64 = 2_000_000;
const TPM_TIMEOUT_C_US: u64 = 750_000;
const TPM_TIMEOUT_D_US: u64 = 750_000;
// Some TPM2 commands are legitimately long-running. EDK2 uses 90 seconds for
// the command-execution/data-available wait.
const TPM_TIMEOUT_MAX_US: u64 = 90_000_000;

fn tpm_wait_expired(start_us: u64, timeout_us: u64) -> bool {
    crate::logger::get_us_since_boot().saturating_sub(start_us) >= timeout_us
}

// ============================================================================
// TIS MMIO Register Access
// ============================================================================

/// Read a byte from a TIS MMIO register.
///
/// # Safety
///
/// `base` must point to a valid TIS MMIO region.
#[inline]
unsafe fn tis_read8(base: u64, offset: usize) -> u8 {
    let addr = (base + offset as u64) as *const u8;
    unsafe { core::ptr::read_volatile(addr) }
}

/// Write a byte to a TIS MMIO register.
///
/// # Safety
///
/// `base` must point to a valid TIS MMIO region.
#[inline]
unsafe fn tis_write8(base: u64, offset: usize, val: u8) {
    let addr = (base + offset as u64) as *mut u8;
    unsafe { core::ptr::write_volatile(addr, val) }
}

/// Read a 32-bit value from a TIS MMIO register.
///
/// # Safety
///
/// `base` must point to a valid TIS MMIO region.
#[inline]
unsafe fn tis_read32(base: u64, offset: usize) -> u32 {
    let addr = (base + offset as u64) as *const u32;
    unsafe { core::ptr::read_volatile(addr) }
}

/// Read the TIS burst count from TPM_STS+1/TPM_STS+2.
///
/// # Safety
///
/// `base` must point to a valid TIS MMIO region.
#[inline]
unsafe fn tis_read_burst_count(base: u64) -> usize {
    let lo = unsafe { tis_read8(base, TPM_STS + 1) } as u16;
    let hi = unsafe { tis_read8(base, TPM_STS + 2) } as u16;
    ((hi << 8) | lo) as usize
}

// ============================================================================
// TPM TIS Driver
// ============================================================================

/// TPM TIS hardware driver.
///
/// Communicates with a TPM 2.0 device via the TIS MMIO register interface.
/// Uses locality 0, which is the default for firmware-level TPM access.
pub struct TpmTis {
    /// MMIO base address for locality 0.
    base: u64,
    /// Cached active hash algorithms (populated during init).
    active_algorithms: [u16; 5],
    /// Number of active algorithms.
    num_algorithms: usize,
    /// Cached manufacturer ID.
    manufacturer_id: u32,
    /// Cached max command size.
    max_command_size: u16,
    /// Cached max response size.
    max_response_size: u16,
}

/// TPM family detected behind a TIS FIFO transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmFamily {
    Tpm12,
    Tpm20,
}

/// TPM 1.2 device using the TIS FIFO transport.
pub struct Tpm12Tis {
    transport: TpmTis,
}

impl TpmTis {
    /// Open the common TIS transport without assuming a TPM command family.
    unsafe fn open(base: u64) -> Result<Self, TcgError> {
        let did_vid = unsafe { tis_read32(base, TPM_DID_VID) };
        if did_vid == 0xFFFF_FFFF || did_vid == 0 {
            log::info!(
                "No TPM device detected at {:#x} (DID_VID={:#x})",
                base,
                did_vid
            );
            return Err(TcgError::InternalError);
        }

        log::info!(
            "TPM TIS detected at {:#x}: VID={:#06x}, DID={:#06x}",
            base,
            did_vid & 0xFFFF,
            (did_vid >> 16) & 0xFFFF,
        );

        let mut tpm = Self {
            base,
            active_algorithms: [0; 5],
            num_algorithms: 0,
            manufacturer_id: 0,
            max_command_size: 0,
            max_response_size: 0,
        };
        unsafe { tpm.request_locality()? };
        Ok(tpm)
    }

    fn detect_family_inner(&mut self) -> Result<TpmFamily, TcgError> {
        // TPM2_GetCapability(TPM_PROPERTIES, MANUFACTURER, 1). A TPM 1.2
        // device rejects the ordinal using a legacy response tag, while a
        // TPM 2.0 device always replies with a TPM2 response tag.
        let mut cmd = [0u8; 22];
        cmd[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd[2..6].copy_from_slice(&22u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&TPM2_CC_GET_CAPABILITY.to_be_bytes());
        cmd[10..14].copy_from_slice(&TPM2_CAP_TPM_PROPERTIES.to_be_bytes());
        cmd[14..18].copy_from_slice(&TPM2_PT_MANUFACTURER.to_be_bytes());
        cmd[18..22].copy_from_slice(&1u32.to_be_bytes());

        let mut resp = [0u8; 64];
        let n = self.send_command(&cmd, &mut resp)?;
        if n < 10 {
            return Err(TcgError::InternalError);
        }
        classify_response_tag(u16::from_be_bytes([resp[0], resp[1]]))
    }

    /// Detect whether the TIS device implements TPM 1.2 or TPM 2.0.
    ///
    /// # Safety
    /// `base` must point to a valid TIS MMIO region.
    pub unsafe fn detect_family(base: u64) -> Result<TpmFamily, TcgError> {
        let mut tpm = unsafe { Self::open(base)? };
        let family = tpm.detect_family_inner()?;
        log::info!("TPM TIS command family: {:?}", family);
        Ok(family)
    }

    /// Probe for a TPM at the given MMIO base address and initialize it.
    ///
    /// This performs:
    /// 1. Check that a TPM device is present (DID/VID != 0xFFFFFFFF)
    /// 2. Request locality 0
    /// 3. Send TPM2_Startup(CLEAR)
    /// 4. Send TPM2_SelfTest(incremental) best-effort
    /// 5. Query capabilities (active PCR banks, manufacturer ID)
    ///
    /// # Safety
    ///
    /// `base` must point to a valid TIS MMIO region (e.g., `0xFED40000`).
    pub unsafe fn probe(base: u64) -> Result<Self, TcgError> {
        let mut tpm = unsafe { Self::open(base)? };
        if tpm.detect_family_inner()? != TpmFamily::Tpm20 {
            log::error!("TIS device at {:#x} is not a TPM 2.0 device", base);
            return Err(TcgError::InternalError);
        }

        // TPM2_Startup(CLEAR).
        tpm.startup()?;

        // TPM2_SelfTest(fullTest = NO). Some dTPMs can exceed the normal
        // command timeout for a full self-test, so continue if this best-effort
        // command times out or otherwise fails in transport.
        if let Err(e) = tpm.self_test() {
            log::warn!("TPM2_SelfTest transport error: {:?} (continuing)", e);
        }

        // Query PCR banks and properties.
        tpm.query_capabilities()?;

        Ok(tpm)
    }

    /// Request access to locality 0.
    ///
    /// # Safety
    ///
    /// `self.base` must be a valid TIS MMIO region.
    unsafe fn request_locality(&mut self) -> Result<(), TcgError> {
        let access = unsafe { tis_read8(self.base, TPM_ACCESS) };
        if access & (ACCESS_VALID | ACCESS_ACTIVE_LOCALITY) == ACCESS_VALID | ACCESS_ACTIVE_LOCALITY
        {
            return Ok(()); // Already have it
        }

        unsafe { tis_write8(self.base, TPM_ACCESS, ACCESS_REQUEST_USE) };

        let start_us = crate::logger::get_us_since_boot();
        while !tpm_wait_expired(start_us, TPM_TIMEOUT_A_US) {
            let access = unsafe { tis_read8(self.base, TPM_ACCESS) };
            if access & (ACCESS_VALID | ACCESS_ACTIVE_LOCALITY)
                == ACCESS_VALID | ACCESS_ACTIVE_LOCALITY
            {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        log::error!("TPM TIS: timeout requesting locality 0");
        Err(TcgError::InternalError)
    }

    /// Wait for TPM_STS to indicate command ready.
    fn wait_command_ready(&self) -> Result<(), TcgError> {
        // Write commandReady to abort any previous command.
        unsafe { tis_write8(self.base, TPM_STS, STS_COMMAND_READY) };

        let start_us = crate::logger::get_us_since_boot();
        while !tpm_wait_expired(start_us, TPM_TIMEOUT_B_US) {
            let sts = unsafe { tis_read8(self.base, TPM_STS) };
            if sts & STS_COMMAND_READY != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        log::error!("TPM TIS: timeout waiting for commandReady");
        Err(TcgError::InternalError)
    }

    fn wait_burst_count(&self) -> Result<usize, TcgError> {
        let start_us = crate::logger::get_us_since_boot();
        while !tpm_wait_expired(start_us, TPM_TIMEOUT_D_US) {
            let burst = unsafe { tis_read_burst_count(self.base) };
            if burst > 0 {
                return Ok(burst);
            }
            core::hint::spin_loop();
        }

        let sts = unsafe { tis_read8(self.base, TPM_STS) };
        let burst = unsafe { tis_read_burst_count(self.base) };
        let access = unsafe { tis_read8(self.base, TPM_ACCESS) };
        log::error!(
            "TPM TIS: timeout waiting for burst count (access={:#x}, sts={:#x}, burst={})",
            access,
            sts,
            burst
        );
        Err(TcgError::InternalError)
    }

    fn wait_command_accepted(&self) -> Result<(), TcgError> {
        let start_us = crate::logger::get_us_since_boot();
        while !tpm_wait_expired(start_us, TPM_TIMEOUT_C_US) {
            let sts = unsafe { tis_read8(self.base, TPM_STS) };
            if sts & STS_VALID != 0 && sts & STS_EXPECT == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        let sts = unsafe { tis_read8(self.base, TPM_STS) };
        log::error!(
            "TPM TIS: timeout waiting for command acceptance (sts={:#x})",
            sts
        );
        Err(TcgError::InternalError)
    }

    fn finish_command(&self) {
        unsafe { tis_write8(self.base, TPM_STS, STS_COMMAND_READY) };
    }

    /// Send a raw TPM command and receive the response.
    ///
    /// The command and response use the standard TPM wire format
    /// (big-endian, with tag/size/code header).
    pub fn send_command(&mut self, cmd: &[u8], response: &mut [u8]) -> Result<usize, TcgError> {
        if cmd.len() < 10 {
            return Err(TcgError::InternalError); // Minimum TPM command is 10 bytes
        }
        if response.len() < 10 {
            return Err(TcgError::EventTooLarge);
        }

        // 1. Set commandReady
        self.wait_command_ready()?;

        let write_command = || -> Result<(), TcgError> {
            // 2. Write command bytes to FIFO, respecting the TPM burst count.
            let mut written = 0;
            while written < cmd.len() {
                let burst = self.wait_burst_count()?.min(cmd.len() - written);
                for &byte in &cmd[written..written + burst] {
                    unsafe { tis_write8(self.base, TPM_DATA_FIFO, byte) };
                }
                written += burst;
            }

            // The TPM should deassert EXPECT once the full command buffer has
            // been received. Sending GO before this point can execute a partial
            // command and produce misleading TPM_RC_VALUE responses.
            self.wait_command_accepted()
        };

        if let Err(e) = write_command() {
            self.finish_command();
            return Err(e);
        }

        // 3. Assert tpmGo
        unsafe { tis_write8(self.base, TPM_STS, STS_GO) };

        // 4. Wait for dataAvail
        let mut data_available = false;
        let start_us = crate::logger::get_us_since_boot();
        while !tpm_wait_expired(start_us, TPM_TIMEOUT_MAX_US) {
            let sts = unsafe { tis_read8(self.base, TPM_STS) };
            if sts & (STS_VALID | STS_DATA_AVAIL) == (STS_VALID | STS_DATA_AVAIL) {
                data_available = true;
                break;
            }
            if sts & STS_COMMAND_READY != 0 {
                // Command completed with no data (error?)
                log::error!("TPM TIS: command completed with no data");
                self.finish_command();
                return Err(TcgError::InternalError);
            }
            core::hint::spin_loop();
        }
        if !data_available {
            log::warn!("TPM TIS: command timed out; requesting cancellation");
            unsafe { tis_write8(self.base, STS_CANCEL_OFFSET, STS_CANCEL) };

            let cancel_start_us = crate::logger::get_us_since_boot();
            while !tpm_wait_expired(cancel_start_us, TPM_TIMEOUT_B_US) {
                let sts = unsafe { tis_read8(self.base, TPM_STS) };
                if sts & (STS_VALID | STS_DATA_AVAIL) == (STS_VALID | STS_DATA_AVAIL) {
                    data_available = true;
                    break;
                }
                core::hint::spin_loop();
            }

            if !data_available {
                log::error!("TPM TIS: cancellation produced no response");
                self.finish_command();
                return Err(TcgError::InternalError);
            }
        }

        // 5. Read response from FIFO. First read 10 bytes to get the
        // response header (tag + size + rc), respecting burst count.
        let mut offset = 0;
        while offset < 10 {
            let burst = match self.wait_burst_count() {
                Ok(burst) => burst.min(10 - offset),
                Err(e) => {
                    self.finish_command();
                    return Err(e);
                }
            };
            for _ in 0..burst {
                response[offset] = unsafe {
                    core::ptr::read_volatile((self.base + TPM_DATA_FIFO as u64) as *const u8)
                };
                offset += 1;
            }
        }

        // Parse response size from header (bytes 2..6, big-endian u32)
        let resp_size =
            u32::from_be_bytes([response[2], response[3], response[4], response[5]]) as usize;
        if resp_size < 10 {
            self.finish_command();
            log::error!("TPM TIS: malformed response size {}", resp_size);
            return Err(TcgError::InternalError);
        }
        if resp_size > response.len() {
            self.finish_command();
            return Err(TcgError::EventTooLarge);
        }

        // Read remaining response bytes.
        while offset < resp_size {
            let burst = match self.wait_burst_count() {
                Ok(burst) => burst.min(resp_size - offset),
                Err(e) => {
                    self.finish_command();
                    return Err(e);
                }
            };
            for _ in 0..burst {
                response[offset] = unsafe {
                    core::ptr::read_volatile((self.base + TPM_DATA_FIFO as u64) as *const u8)
                };
                offset += 1;
            }
        }

        // 6. Set commandReady to finish
        self.finish_command();

        Ok(offset)
    }

    /// Send TPM2_Startup(CLEAR).
    fn startup(&mut self) -> Result<(), TcgError> {
        // TPM2_Startup command: tag(2) + size(4) + code(4) + startupType(2) = 12 bytes
        let mut cmd = [0u8; 12];
        cmd[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        // Size
        cmd[2..6].copy_from_slice(&12u32.to_be_bytes());
        // Command code
        cmd[6..10].copy_from_slice(&TPM2_CC_STARTUP.to_be_bytes());
        // Startup type: CLEAR
        cmd[10..12].copy_from_slice(&TPM2_SU_CLEAR.to_be_bytes());

        let mut resp = [0u8; 64];
        let n = self.send_command(&cmd, &mut resp)?;
        if n < 10 {
            return Err(TcgError::InternalError);
        }

        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        // TPM_RC_INITIALIZE (0x100) means already started — that's OK.
        // Some firmware/TPM combinations return a non-success code after a
        // previous firmware phase has already started the TPM. Treat Startup
        // as a best-effort command and let the following capability queries
        // decide whether the TPM is actually usable.
        if rc != TPM_RC_SUCCESS && rc != 0x100 {
            log::warn!(
                "TPM2_Startup(CLEAR) returned rc={:#x}, resp={:02x?} (continuing)",
                rc,
                &resp[..n.min(16)]
            );
        } else {
            log::debug!("TPM2_Startup(CLEAR) -> rc={:#x}", rc);
        }
        Ok(())
    }

    /// Send TPM2_SelfTest(fullTest = NO) to let self-test complete incrementally.
    fn self_test(&mut self) -> Result<(), TcgError> {
        let mut cmd = [0u8; 11];
        cmd[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd[2..6].copy_from_slice(&11u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&TPM2_CC_SELF_TEST.to_be_bytes());
        cmd[10] = 0; // fullTest = NO

        let mut resp = [0u8; 64];
        let n = self.send_command(&cmd, &mut resp)?;
        if n < 10 {
            return Err(TcgError::InternalError);
        }

        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        if rc != TPM_RC_SUCCESS {
            log::warn!(
                "TPM2_SelfTest: rc={:#x}, resp={:02x?} (continuing)",
                rc,
                &resp[..n.min(16)]
            );
        } else {
            log::debug!("TPM2_SelfTest(incremental) -> SUCCESS");
        }
        Ok(())
    }

    /// Query TPM capabilities: active PCR banks and manufacturer properties.
    fn query_capabilities(&mut self) -> Result<(), TcgError> {
        // Query active PCR banks via TPM2_GetCapability(TPM_CAP_PCRS)
        self.query_pcr_banks()?;

        // Query manufacturer properties
        self.query_tpm_properties()?;

        Ok(())
    }

    /// Query active PCR banks.
    fn query_pcr_banks(&mut self) -> Result<(), TcgError> {
        // TPM2_GetCapability: tag(2) + size(4) + code(4) + cap(4) + prop(4) + count(4) = 22
        let mut cmd = [0u8; 22];
        cmd[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd[2..6].copy_from_slice(&22u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&TPM2_CC_GET_CAPABILITY.to_be_bytes());
        cmd[10..14].copy_from_slice(&TPM2_CAP_PCRS.to_be_bytes());
        cmd[14..18].copy_from_slice(&0u32.to_be_bytes()); // property = 0
        cmd[18..22].copy_from_slice(&16u32.to_be_bytes()); // propertyCount

        let mut resp = [0u8; 256];
        let n = self.send_command(&cmd, &mut resp)?;

        if n < 10 {
            return Err(TcgError::InternalError);
        }

        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        if rc != TPM_RC_SUCCESS {
            log::error!(
                "TPM2_GetCapability(PCRS) failed: rc={:#x}, resp={:02x?}",
                rc,
                &resp[..n.min(16)]
            );
            return Err(TcgError::InternalError);
        }

        // Parse TPML_PCR_SELECTION from response
        // Response: header(10) + moreData(1) + capabilityData
        //   capabilityData = capability(4) + TPML_PCR_SELECTION
        //   TPML_PCR_SELECTION = count(4) + pcr_selections[]
        //   each selection = hash(2) + sizeOfSelect(1) + pcrSelect[]
        if n < 19 {
            return Err(TcgError::InternalError);
        }

        let count = u32::from_be_bytes([resp[15], resp[16], resp[17], resp[18]]) as usize;
        let mut offset = 19;
        let mut num_algs = 0usize;

        for _ in 0..count {
            if offset + 3 > n {
                return Err(TcgError::InternalError);
            }
            let alg_id = u16::from_be_bytes([resp[offset], resp[offset + 1]]);
            let select_size = resp[offset + 2] as usize;
            offset += 3;

            let selection_end = offset
                .checked_add(select_size)
                .filter(|end| *end <= n)
                .ok_or(TcgError::InternalError)?;

            // Check if any PCR is selected (at least one bit set)
            let any_selected = resp[offset..selection_end].iter().any(|byte| *byte != 0);
            offset = selection_end;

            if any_selected {
                if !matches!(
                    alg_id,
                    TPM_ALG_SHA1 | TPM_ALG_SHA256 | TPM_ALG_SHA384 | TPM_ALG_SHA512
                ) {
                    log::error!("TPM active PCR bank {:#06x} is unsupported", alg_id);
                    return Err(TcgError::UnsupportedAlgorithm);
                }
                if !self.active_algorithms[..num_algs].contains(&alg_id) {
                    if num_algs >= self.active_algorithms.len() {
                        return Err(TcgError::UnsupportedAlgorithm);
                    }
                    self.active_algorithms[num_algs] = alg_id;
                    num_algs += 1;
                }
            }
        }

        self.num_algorithms = num_algs;

        let alg_names: alloc::vec::Vec<&str> = self.active_algorithms[..num_algs]
            .iter()
            .map(|a| match *a {
                TPM_ALG_SHA1 => "SHA-1",
                TPM_ALG_SHA256 => "SHA-256",
                0x000C => "SHA-384",
                0x000D => "SHA-512",
                _ => "unknown",
            })
            .collect();
        log::info!("TPM active PCR banks: {:?}", alg_names);

        Ok(())
    }

    /// Query TPM properties (manufacturer ID, max command/response sizes).
    fn query_tpm_properties(&mut self) -> Result<(), TcgError> {
        // Query TPM2_PT_MANUFACTURER
        let mut cmd = [0u8; 22];
        cmd[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd[2..6].copy_from_slice(&22u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&TPM2_CC_GET_CAPABILITY.to_be_bytes());
        cmd[10..14].copy_from_slice(&TPM2_CAP_TPM_PROPERTIES.to_be_bytes());
        cmd[14..18].copy_from_slice(&TPM2_PT_MANUFACTURER.to_be_bytes());
        // Query enough contiguous properties to include TPM2_PT_MAX_COMMAND_SIZE
        // and TPM2_PT_MAX_RESPONSE_SIZE.
        cmd[18..22].copy_from_slice(&32u32.to_be_bytes()); // propertyCount

        let mut resp = [0u8; 512];
        let n = self.send_command(&cmd, &mut resp)?;

        if n < 10 {
            return Err(TcgError::InternalError);
        }

        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        if rc != TPM_RC_SUCCESS {
            log::warn!("TPM2_GetCapability(PROPERTIES) failed: rc={:#x}", rc);
            return Ok(()); // Non-fatal
        }

        // Parse TPML_TAGGED_TPM_PROPERTY
        // Response: header(10) + moreData(1) + capability(4) + count(4) + props[]
        //   each prop = property(4) + value(4)
        if n < 19 {
            return Ok(());
        }
        let count = u32::from_be_bytes([resp[15], resp[16], resp[17], resp[18]]) as usize;
        let mut offset = 19;

        for _ in 0..count {
            if offset + 8 > n {
                break;
            }
            let prop = u32::from_be_bytes([
                resp[offset],
                resp[offset + 1],
                resp[offset + 2],
                resp[offset + 3],
            ]);
            let val = u32::from_be_bytes([
                resp[offset + 4],
                resp[offset + 5],
                resp[offset + 6],
                resp[offset + 7],
            ]);
            offset += 8;

            match prop {
                TPM2_PT_MANUFACTURER => {
                    self.manufacturer_id = val;
                    log::info!(
                        "TPM manufacturer: {:#x} (\"{}\")",
                        val,
                        manufacturer_id_to_str(val)
                    );
                }
                TPM2_PT_MAX_COMMAND_SIZE => {
                    self.max_command_size = val as u16;
                }
                TPM2_PT_MAX_RESPONSE_SIZE => {
                    self.max_response_size = val as u16;
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Extend a PCR with the given digests.
    ///
    /// Sends a TPM2_PCR_Extend command with digests for all active algorithms.
    pub fn pcr_extend(&mut self, pcr_index: u32, digests: &[TaggedDigest]) -> Result<(), TcgError> {
        // Build TPM2_PCR_Extend command
        // Header: tag(2) + size(4) + code(4) = 10
        // pcrHandle: 4 bytes (PCR index)
        // authSize: 4 bytes
        // auth session: 9 bytes minimum (sessionHandle(4) + nonceSize(2) + attributes(1) + hmacSize(2))
        // TPML_DIGEST_VALUES: count(4) + digests...

        let mut cmd = [0u8; 512];

        // Tag: TPM_ST_SESSIONS = 0x8002 (session-based for PCR_Extend)
        cmd[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
        let mut offset = 6; // Skip size for now (will fill in at end)

        // Command code
        cmd[offset..offset + 4].copy_from_slice(&TPM2_CC_PCR_EXTEND.to_be_bytes());
        offset += 4;

        // PCR handle
        cmd[offset..offset + 4].copy_from_slice(&pcr_index.to_be_bytes());
        offset += 4;

        // Authorization area size (will fill in)
        let auth_size_offset = offset;
        offset += 4;

        // Password session (TPM_RS_PW = 0x40000009)
        let auth_start = offset;
        cmd[offset..offset + 4].copy_from_slice(&0x40000009u32.to_be_bytes()); // sessionHandle
        offset += 4;
        cmd[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes()); // nonceSize = 0
        offset += 2;
        cmd[offset] = 0; // sessionAttributes = 0 (continueSession = false)
        offset += 1;
        cmd[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes()); // hmacSize = 0
        offset += 2;

        // Fill in auth area size
        let auth_size = (offset - auth_start) as u32;
        cmd[auth_size_offset..auth_size_offset + 4].copy_from_slice(&auth_size.to_be_bytes());

        // TPML_DIGEST_VALUES. Count only digests we actually encode.
        let digest_count = digests
            .iter()
            .take(5)
            .filter(|digest| digest_size_for_algorithm(digest.algorithm).is_some())
            .count() as u32;
        cmd[offset..offset + 4].copy_from_slice(&digest_count.to_be_bytes());
        offset += 4;

        for digest in digests.iter().take(5) {
            let d_size = match digest_size_for_algorithm(digest.algorithm) {
                Some(s) => s,
                None => continue,
            };
            cmd[offset..offset + 2].copy_from_slice(&digest.algorithm.to_be_bytes());
            offset += 2;
            cmd[offset..offset + d_size].copy_from_slice(&digest.digest[..d_size]);
            offset += d_size;
        }

        // Fill in total command size
        cmd[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

        // Send command
        let mut resp = [0u8; 64];
        let n = self.send_command(&cmd[..offset], &mut resp)?;

        if n < 10 {
            return Err(TcgError::InternalError);
        }

        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        if rc != TPM_RC_SUCCESS {
            log::error!("TPM2_PCR_Extend(pcr={}) failed: rc={:#x}", pcr_index, rc);
            return Err(TcgError::InternalError);
        }

        Ok(())
    }

    /// Return the active hash algorithm IDs.
    pub fn active_algorithms(&self) -> &[u16] {
        &self.active_algorithms[..self.num_algorithms]
    }

    /// Return whether SHA-1 is among the active algorithms.
    pub fn has_sha1(&self) -> bool {
        self.active_algorithms[..self.num_algorithms].contains(&TPM_ALG_SHA1)
    }

    /// Return whether SHA-256 is among the active algorithms.
    pub fn has_sha256(&self) -> bool {
        self.active_algorithms[..self.num_algorithms].contains(&TPM_ALG_SHA256)
    }

    /// Return the cached manufacturer ID.
    pub fn manufacturer_id(&self) -> u32 {
        self.manufacturer_id
    }

    /// Return the cached max command size.
    pub fn max_command_size(&self) -> u16 {
        self.max_command_size
    }

    /// Return the cached max response size.
    pub fn max_response_size(&self) -> u16 {
        self.max_response_size
    }
}

impl Tpm12Tis {
    /// Probe and initialize a TPM 1.2 device on a TIS FIFO transport.
    ///
    /// # Safety
    /// `base` must point to a valid TIS MMIO region.
    pub unsafe fn probe(base: u64) -> Result<Self, TcgError> {
        let mut transport = unsafe { TpmTis::open(base)? };

        // Coreboot commonly starts the TPM before entering the payload, so a
        // second TPM_Startup legitimately returns TPM_INVALID_POSTINIT.
        let mut cmd = [0u8; 12];
        cmd[0..2].copy_from_slice(&TPM12_TAG_RQU_COMMAND.to_be_bytes());
        cmd[2..6].copy_from_slice(&12u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&TPM12_ORD_STARTUP.to_be_bytes());
        cmd[10..12].copy_from_slice(&TPM12_ST_CLEAR.to_be_bytes());
        let mut resp = [0u8; 64];
        let n = transport.send_command(&cmd, &mut resp)?;
        if n < 10
            || classify_response_tag(u16::from_be_bytes([resp[0], resp[1]]))? != TpmFamily::Tpm12
        {
            log::error!("TIS device at {:#x} is not a TPM 1.2 device", base);
            return Err(TcgError::InternalError);
        }
        let rc = response_code(&resp[..n])?;
        if rc != TPM_RC_SUCCESS && rc != TPM12_INVALID_POSTINIT {
            log::error!("TPM_Startup(ST_CLEAR) failed: rc={:#x}", rc);
            return Err(TcgError::InternalError);
        }

        log::info!("TPM 1.2 TIS backend initialized");
        Ok(Self { transport })
    }

    /// Extend a TPM 1.2 SHA-1 PCR.
    pub fn pcr_extend(
        &mut self,
        pcr_index: u32,
        digest: &[u8; SHA1_DIGEST_SIZE],
    ) -> Result<(), TcgError> {
        let mut cmd = [0u8; 34];
        cmd[0..2].copy_from_slice(&TPM12_TAG_RQU_COMMAND.to_be_bytes());
        cmd[2..6].copy_from_slice(&34u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&TPM12_ORD_EXTEND.to_be_bytes());
        cmd[10..14].copy_from_slice(&pcr_index.to_be_bytes());
        cmd[14..34].copy_from_slice(digest);

        let mut resp = [0u8; 64];
        let n = self.transport.send_command(&cmd, &mut resp)?;
        let rc = response_code(&resp[..n])?;
        if rc != TPM_RC_SUCCESS {
            log::error!("TPM_Extend(pcr={}) failed: rc={:#x}", pcr_index, rc);
            return Err(TcgError::InternalError);
        }
        Ok(())
    }

    /// Submit an arbitrary TPM 1.2 command through the TIS FIFO.
    pub fn submit_command(
        &mut self,
        command: &[u8],
        response: &mut [u8],
    ) -> Result<usize, TcgError> {
        self.transport.send_command(command, response)
    }
}

fn response_code(response: &[u8]) -> Result<u32, TcgError> {
    if response.len() < 10 {
        return Err(TcgError::InternalError);
    }
    Ok(u32::from_be_bytes([
        response[6],
        response[7],
        response[8],
        response[9],
    ]))
}

fn classify_response_tag(tag: u16) -> Result<TpmFamily, TcgError> {
    match tag {
        TPM12_TAG_RSP_COMMAND | TPM12_TAG_RSP_AUTH1_COMMAND | TPM12_TAG_RSP_AUTH2_COMMAND => {
            Ok(TpmFamily::Tpm12)
        }
        TPM_ST_NO_SESSIONS | 0x8002 => Ok(TpmFamily::Tpm20),
        _ => Err(TcgError::InternalError),
    }
}

impl Tpm2Device for TpmTis {
    fn active_pcr_banks(&self) -> TpmPcrBanks {
        TpmPcrBanks::new(self.active_algorithms())
    }

    fn manufacturer_id(&self) -> u32 {
        self.manufacturer_id()
    }

    fn max_command_size(&self) -> u16 {
        self.max_command_size()
    }

    fn max_response_size(&self) -> u16 {
        self.max_response_size()
    }

    fn pcr_extend(&mut self, pcr_index: u32, digests: &[TpmDigest<'_>]) -> Result<(), TpmError> {
        let mut tagged = [TaggedDigest::zeroed(0); 5];
        let count = digests.len().min(tagged.len());
        for (out, digest) in tagged.iter_mut().zip(digests.iter()).take(count) {
            let Some(size) = digest_size_for_algorithm(digest.algorithm) else {
                return Err(TpmError::Unsupported);
            };
            if digest.digest.len() < size {
                return Err(TpmError::InvalidParameter);
            }
            out.algorithm = digest.algorithm;
            out.digest[..size].copy_from_slice(&digest.digest[..size]);
        }
        TpmTis::pcr_extend(self, pcr_index, &tagged[..count]).map_err(tcg_to_platform_error)
    }

    fn submit_command(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, TpmError> {
        self.send_command(command, response)
            .map_err(tcg_to_platform_error)
    }
}

fn tcg_to_platform_error(err: TcgError) -> TpmError {
    match err {
        TcgError::EventTooLarge | TcgError::LogFull => TpmError::BufferTooSmall,
        TcgError::InvalidPcrIndex => TpmError::InvalidParameter,
        TcgError::UnsupportedAlgorithm => TpmError::Unsupported,
        _ => TpmError::DeviceError,
    }
}

/// Convert a TPM manufacturer ID to a human-readable 4-character string.
fn manufacturer_id_to_str(id: u32) -> alloc::string::String {
    let bytes = id.to_be_bytes();
    let mut s = alloc::string::String::with_capacity(4);
    for &b in &bytes {
        if b.is_ascii_graphic() || b == b' ' {
            s.push(b as char);
        } else {
            s.push('?');
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::{TpmFamily, classify_response_tag};

    #[test]
    fn response_tags_distinguish_tpm_families() {
        assert_eq!(classify_response_tag(0x00c4), Ok(TpmFamily::Tpm12));
        assert_eq!(classify_response_tag(0x00c5), Ok(TpmFamily::Tpm12));
        assert_eq!(classify_response_tag(0x8001), Ok(TpmFamily::Tpm20));
        assert_eq!(classify_response_tag(0x8002), Ok(TpmFamily::Tpm20));
        assert!(classify_response_tag(0xffff).is_err());
    }
}
