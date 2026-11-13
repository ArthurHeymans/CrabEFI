//! TPM 2.0 Command Response Buffer (CRB) interface driver.
//!
//! The CRB interface of the TCG PC Client Platform TPM Profile (PTP) keeps
//! the locality 0 registers in one MMIO page. Its control area, at offset
//! 0x40 and the address the ACPI `TPM2` table names, points at the command
//! and response buffers: QEMU's `tpm-crb` has them in the register page, a
//! firmware TPM such as AMD's in DRAM that platform firmware assigned.
//!
//! Firmware TPMs started through the ACPI start method implement only part
//! of the control area: the start doorbell, the error bit and the buffer
//! registers. Following Linux, such a TPM gets no locality or idle requests.

use super::tpm_tis::TpmTransport;
use super::types::TcgError;
use crate::platform::CrbStart;

// Locality registers.
const LOC_STATE: u64 = 0x00;
const LOC_CTRL: u64 = 0x08;
const LOC_STATE_ASSIGNED: u32 = 1 << 1;
const LOC_STATE_ACTIVE_MASK: u32 = 0x7 << 2;
const LOC_STATE_REG_VALID: u32 = 1 << 7;
const LOC_CTRL_REQUEST_ACCESS: u32 = 1;

// Control area registers.
const CONTROL_AREA: u64 = 0x40;
const CTRL_REQ: u64 = 0x40;
const CTRL_STS: u64 = 0x44;
const CTRL_CANCEL: u64 = 0x48;
const CTRL_START: u64 = 0x4c;
const CTRL_CMD_SIZE: u64 = 0x58;
const CTRL_CMD_LADDR: u64 = 0x5c;
const CTRL_CMD_HADDR: u64 = 0x60;
const CTRL_RSP_SIZE: u64 = 0x64;
const CTRL_RSP_ADDR: u64 = 0x68;
const CTRL_REQ_CMD_READY: u32 = 1 << 0;
const CTRL_REQ_GO_IDLE: u32 = 1 << 1;
const CTRL_STS_ERROR: u32 = 1 << 0;
const CTRL_START_INVOKE: u32 = 1;
const CTRL_CANCEL_INVOKE: u32 = 1;

const HEADER_SIZE: usize = 10;

// PTP timeouts; commands get the 90 s EDK2 and the TIS driver allow.
const TIMEOUT_A_US: u64 = 750_000;
const TIMEOUT_B_US: u64 = 2_000_000;
const TIMEOUT_C_US: u64 = 750_000;
const TIMEOUT_MAX_US: u64 = 90_000_000;

/// The CRB registers of locality 0 and the buffers they describe.
pub struct CrbMmio {
    base: u64,
    start: CrbStart,
    command: u64,
    command_size: u32,
    response: u64,
    response_size: u32,
}

impl CrbMmio {
    /// Open the CRB interface whose control area is at `control_area`.
    ///
    /// # Safety
    ///
    /// `control_area` must be the control area of a CRB TPM, its register
    /// page and the buffers it names must be mapped, and nothing else may
    /// use the TPM while this transport exists.
    pub unsafe fn open(control_area: u64, start: CrbStart) -> Result<Self, TcgError> {
        let base = control_area
            .checked_sub(CONTROL_AREA)
            .ok_or(TcgError::InternalError)?;
        let mut crb = Self {
            base,
            start,
            command: 0,
            command_size: 0,
            response: 0,
            response_size: 0,
        };
        if start == CrbStart::Crb {
            crb.request_locality()?;
        }

        crb.command =
            u64::from(crb.read(CTRL_CMD_LADDR)) | (u64::from(crb.read(CTRL_CMD_HADDR)) << 32);
        crb.command_size = crb.read(CTRL_CMD_SIZE);
        crb.response =
            u64::from(crb.read(CTRL_RSP_ADDR)) | (u64::from(crb.read(CTRL_RSP_ADDR + 4)) << 32);
        crb.response_size = crb.read(CTRL_RSP_SIZE);

        let valid = |address: u64, size: u32| {
            address != 0
                && address != u64::MAX
                && size as usize >= HEADER_SIZE
                && address.checked_add(u64::from(size)).is_some()
        };
        if !valid(crb.command, crb.command_size) || !valid(crb.response, crb.response_size) {
            log::info!(
                "No usable TPM CRB at {:#x}: command {:#x}+{:#x}, response {:#x}+{:#x}",
                control_area,
                crb.command,
                crb.command_size,
                crb.response,
                crb.response_size
            );
            return Err(TcgError::InternalError);
        }
        log::info!(
            "TPM CRB at {:#x} ({:?} start): command {:#x}+{:#x}, response {:#x}+{:#x}",
            control_area,
            start,
            crb.command,
            crb.command_size,
            crb.response,
            crb.response_size
        );
        Ok(crb)
    }

    fn read(&self, offset: u64) -> u32 {
        // SAFETY: `open`'s contract maps the register page.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    fn write(&self, offset: u64, value: u32) {
        // SAFETY: `open`'s contract maps the register page.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }

    /// Wait until `done` holds for the register at `offset`.
    fn wait(&self, offset: u64, timeout_us: u64, done: impl Fn(u32) -> bool) -> Result<(), u32> {
        let start_us = crate::logger::get_us_since_boot();
        loop {
            let value = self.read(offset);
            if done(value) {
                return Ok(());
            }
            if crate::logger::get_us_since_boot().saturating_sub(start_us) >= timeout_us {
                return Err(value);
            }
            core::hint::spin_loop();
        }
    }

    fn request_locality(&self) -> Result<(), TcgError> {
        const GRANTED: u32 = LOC_STATE_REG_VALID | LOC_STATE_ASSIGNED;
        let granted = |state: u32| state & (GRANTED | LOC_STATE_ACTIVE_MASK) == GRANTED;
        if granted(self.read(LOC_STATE)) {
            return Ok(());
        }
        self.write(LOC_CTRL, LOC_CTRL_REQUEST_ACCESS);
        self.wait(LOC_STATE, TIMEOUT_A_US, granted)
            .map_err(|state| {
                log::error!("TPM CRB: locality 0 not granted (LOC_STATE={:#x})", state);
                TcgError::InternalError
            })
    }

    fn command_ready(&self) -> Result<(), TcgError> {
        self.write(CTRL_REQ, CTRL_REQ_CMD_READY);
        self.wait(CTRL_REQ, TIMEOUT_C_US, |req| req & CTRL_REQ_CMD_READY == 0)
            .map_err(|req| {
                log::error!("TPM CRB: not ready for a command (CTRL_REQ={:#x})", req);
                TcgError::InternalError
            })
    }

    /// Run one command; its response is left in the response buffer.
    fn execute(&mut self, cmd: &[u8]) -> Result<(), TcgError> {
        if self.start == CrbStart::Crb {
            self.command_ready()?;
        }
        if self.read(CTRL_START) & CTRL_START_INVOKE != 0 {
            log::error!("TPM CRB: previous command still running");
            return Err(TcgError::InternalError);
        }
        for (index, byte) in cmd.iter().enumerate() {
            // SAFETY: `cmd` fits the command buffer `open` validated.
            unsafe { core::ptr::write_volatile((self.command + index as u64) as *mut u8, *byte) };
        }
        if self.start == CrbStart::Acpi {
            // AMD's fTPM overwrites the response buffer size with the
            // length of each response; restore it before every command.
            self.write(CTRL_RSP_SIZE, self.response_size);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.write(CTRL_START, CTRL_START_INVOKE);

        let done = |start: u32| start & CTRL_START_INVOKE == 0;
        if self.wait(CTRL_START, TIMEOUT_MAX_US, done).is_err() {
            log::error!("TPM CRB: command {:02x?} timed out", &cmd[6..10]);
            if self.start == CrbStart::Crb {
                self.write(CTRL_CANCEL, CTRL_CANCEL_INVOKE);
                let _ = self.wait(CTRL_START, TIMEOUT_B_US, done);
                self.write(CTRL_CANCEL, 0);
            }
            return Err(TcgError::InternalError);
        }
        let status = self.read(CTRL_STS);
        if status & CTRL_STS_ERROR != 0 {
            log::error!("TPM CRB: TPM in error state (CTRL_STS={:#x})", status);
            return Err(TcgError::InternalError);
        }
        Ok(())
    }

    fn read_response(&self, response: &mut [u8]) -> Result<usize, TcgError> {
        let read = |index: usize| {
            // SAFETY: `index` is below the response buffer size `open`
            // validated.
            unsafe { core::ptr::read_volatile((self.response + index as u64) as *const u8) }
        };
        let size = u32::from_be_bytes([read(2), read(3), read(4), read(5)]) as usize;
        if size < HEADER_SIZE || size > self.response_size as usize {
            log::error!("TPM CRB: malformed response size {}", size);
            return Err(TcgError::InternalError);
        }
        if size > response.len() {
            return Err(TcgError::EventTooLarge);
        }
        for (index, byte) in response[..size].iter_mut().enumerate() {
            *byte = read(index);
        }
        Ok(size)
    }
}

impl TpmTransport for CrbMmio {
    fn send_command(&mut self, cmd: &[u8], response: &mut [u8]) -> Result<usize, TcgError> {
        if cmd.len() < HEADER_SIZE || cmd.len() > self.command_size as usize {
            return Err(TcgError::InternalError);
        }
        if response.len() < HEADER_SIZE {
            return Err(TcgError::EventTooLarge);
        }
        let result = self
            .execute(cmd)
            .and_then(|()| self.read_response(response));
        match self.start {
            CrbStart::Crb => self.write(CTRL_REQ, CTRL_REQ_GO_IDLE),
            // The OS reads the response buffer size from here.
            CrbStart::Acpi => self.write(CTRL_RSP_SIZE, self.response_size),
        }
        result
    }
}

/// TPM 2.0 behind the CRB interface.
pub type TpmCrb = super::Tpm2<CrbMmio>;

impl TpmCrb {
    /// Open the CRB at `control_area`, start the TPM and read its
    /// capabilities.
    ///
    /// # Safety
    ///
    /// See [`CrbMmio::open`].
    pub unsafe fn probe(control_area: u64, start: CrbStart) -> Result<Self, TcgError> {
        Self::new(unsafe { CrbMmio::open(control_area, start)? })
    }
}

#[cfg(test)]
#[path = "tpm_crb_tests.rs"]
mod tests;
