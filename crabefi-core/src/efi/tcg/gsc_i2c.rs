//! Google security chip (Cr50, Ti50) TPM 2.0 on I2C, ACPI `GOOG0005`.
//!
//! The TIS FIFO protocol with the chip's I2C specifics, as in coreboot's and
//! Linux's drivers:
//! - a register read is an address write, a wait for ready, then a data read
//! - every transfer ends with the chip signalling ready on its interrupt line,
//!   or after a fixed delay without one
//! - the status register is accessed as four bytes, with the burst count in
//!   bytes 1 and 2, at most 63
//! - a FIFO read takes the whole burst

use super::tpm_tis::TpmTransport;
use super::types::TcgError;
use crate::peripheral::{I2cBus, I2cPeripheral, Interrupt};
use crate::time::{Timeout, delay_ms};
use embedded_hal::i2c::I2c;

const ACCESS: u8 = 0x00;
const STS: u8 = 0x01;
const DATA_FIFO: u8 = 0x05;
const DID_VID: u8 = 0x06;

const ACCESS_VALID: u8 = 1 << 7;
const ACCESS_ACTIVE_LOCALITY: u8 = 1 << 5;
const ACCESS_REQUEST_USE: u8 = 1 << 1;

const STS_VALID: u8 = 1 << 7;
const STS_COMMAND_READY: u8 = 1 << 6;
const STS_GO: u8 = 1 << 5;
const STS_DATA_AVAIL: u8 = 1 << 4;
const STS_EXPECT: u8 = 1 << 3;

const MAX_BURST: usize = 63;
const HEADER_SIZE: usize = 10;
/// Cr50, Ti50 (DT) and Ti50 (OT).
const DID_VIDS: [u32; 3] = [0x0028_1ae0, 0x504a_6666, 0x5066_6666];

/// Delay standing in for the ready signal without an interrupt line.
const NO_IRQ_DELAY_MS: u64 = 20;
const IRQ_TIMEOUT_MS: u64 = 750;
const LONG_TIMEOUT_MS: u64 = 2_000;
const COMMAND_TIMEOUT_MS: u64 = 120_000;

/// ACPI identifiers of Google security chips on I2C.
pub(crate) const IDS: &[&str] = &["GOOG0005"];

/// A Google security chip TPM on I2C.
pub struct GscI2c<I> {
    bus: I,
    address: u8,
    /// Ready signal; `None` after the line failed to signal.
    interrupt: Option<Interrupt>,
}

// SAFETY: CrabEFI runs on one hart and never polls the TPM from interrupt
// context, so the bus and interrupt handles never cross threads.
unsafe impl<I> Send for GscI2c<I> {}

/// Run `attempt` until it yields a value, at least once, then until
/// `timeout_ms` passed, pausing `pause_ms` between attempts.
fn poll<T>(timeout_ms: u64, pause_ms: u64, mut attempt: impl FnMut() -> Option<T>) -> Option<T> {
    let timeout = Timeout::from_ms(timeout_ms);
    loop {
        if let Some(value) = attempt() {
            return Some(value);
        }
        if timeout.is_expired() {
            return None;
        }
        delay_ms(pause_ms);
    }
}

impl<I: I2c> GscI2c<I> {
    /// Identify the chip and claim locality 0.
    pub fn open(bus: I, address: u8, interrupt: Option<Interrupt>) -> Result<Self, TcgError> {
        let mut tpm = Self {
            bus,
            address,
            interrupt,
        };
        // The chip may still be processing a reset; give it a second.
        let did_vid = poll(1_000, 10, || {
            let mut did_vid = [0; 4];
            tpm.read(DID_VID, &mut did_vid).ok()?;
            Some(u32::from_le_bytes(did_vid)).filter(|id| DID_VIDS.contains(id))
        })
        .ok_or_else(|| {
            log::error!("GSC TPM at {:#x}: not found", address);
            TcgError::InternalError
        })?;
        log::info!("GSC TPM at {:#x}: DID_VID {:#010x}", address, did_vid);
        tpm.claim_locality()?;
        Ok(tpm)
    }

    /// Drain a stale ready signal before a transfer.
    fn clear_ready(&mut self) {
        if let Some(Interrupt::Latched(latch)) = &mut self.interrupt {
            latch.take();
        }
    }

    fn wait_ready(&mut self) -> Result<(), TcgError> {
        let Some(interrupt) = &mut self.interrupt else {
            delay_ms(NO_IRQ_DELAY_MS);
            return Ok(());
        };
        if poll(IRQ_TIMEOUT_MS, 0, || interrupt.is_pending().then_some(())).is_some() {
            return Ok(());
        }
        // A line that never signals would cost a timeout per transfer.
        log::warn!("GSC TPM: no ready interrupt, using fixed delays");
        self.interrupt = None;
        Ok(())
    }

    fn read(&mut self, register: u8, buffer: &mut [u8]) -> Result<(), TcgError> {
        self.clear_ready();
        self.bus
            .write(self.address, &[register])
            .map_err(|_| TcgError::InternalError)?;
        self.wait_ready()?;
        self.bus
            .read(self.address, buffer)
            .map_err(|_| TcgError::InternalError)
    }

    fn write(&mut self, register: u8, data: &[u8]) -> Result<(), TcgError> {
        if data.len() > MAX_BURST {
            return Err(TcgError::InternalError);
        }
        let mut message = [0; MAX_BURST + 1];
        message[0] = register;
        message[1..=data.len()].copy_from_slice(data);
        self.clear_ready();
        self.bus
            .write(self.address, &message[..=data.len()])
            .map_err(|_| TcgError::InternalError)?;
        self.wait_ready()
    }

    fn claim_locality(&mut self) -> Result<(), TcgError> {
        const ACTIVE: u8 = ACCESS_VALID | ACCESS_ACTIVE_LOCALITY;
        let mut access = [0];
        self.read(ACCESS, &mut access)?;
        if access[0] & ACTIVE == ACTIVE {
            return Ok(());
        }
        self.write(ACCESS, &[ACCESS_REQUEST_USE])?;
        self.read(ACCESS, &mut access)?;
        if access[0] & ACTIVE != ACTIVE {
            log::error!("GSC TPM: failed to claim locality 0");
            return Err(TcgError::InternalError);
        }
        Ok(())
    }

    /// Low status byte, or 0 if unreadable.
    fn status(&mut self) -> u8 {
        let mut status = [0; 4];
        self.read(STS, &mut status).map_or(0, |()| status[0])
    }

    fn command_ready(&mut self) {
        let _ = self.write(STS, &[STS_COMMAND_READY, 0, 0, 0]);
    }

    /// Wait until the status matches `mask` with a usable burst count.
    fn wait_burst(&mut self, mask: u8) -> Result<(usize, u8), TcgError> {
        poll(LONG_TIMEOUT_MS, 2, || {
            let mut status = [0; 4];
            self.read(STS, &mut status).ok()?;
            let burst = usize::from(u16::from_le_bytes([status[1], status[2]]));
            (status[0] & mask == mask && (1..=MAX_BURST).contains(&burst))
                .then_some((burst, status[0]))
        })
        .ok_or_else(|| {
            log::error!("GSC TPM: timeout waiting for status {:#x}", mask);
            TcgError::InternalError
        })
    }

    fn send(&mut self, command: &[u8]) -> Result<(), TcgError> {
        poll(LONG_TIMEOUT_MS, 0, || {
            let ready = self.status() & STS_COMMAND_READY != 0;
            if !ready {
                self.command_ready();
            }
            ready.then_some(())
        })
        .ok_or(TcgError::InternalError)?;

        let mut sent = 0;
        while sent < command.len() {
            let mask = if sent == 0 {
                STS_VALID
            } else {
                STS_VALID | STS_EXPECT
            };
            let (burst, _) = self.wait_burst(mask)?;
            // The register address takes one byte of the burst.
            let chunk = (burst - 1).min(command.len() - sent);
            if chunk == 0 {
                // A one-byte burst leaves no room after the register address.
                // Reject it rather than looping forever without sending data.
                return Err(TcgError::InternalError);
            }
            self.write(DATA_FIFO, &command[sent..sent + chunk])?;
            sent += chunk;
        }

        let (_, status) = self.wait_burst(STS_VALID)?;
        if status & STS_EXPECT != 0 {
            log::error!("GSC TPM: command not accepted");
            return Err(TcgError::InternalError);
        }
        self.write(STS, &[STS_GO, 0, 0, 0])
    }

    fn receive(&mut self, response: &mut [u8]) -> Result<usize, TcgError> {
        const AVAILABLE: u8 = STS_VALID | STS_DATA_AVAIL;
        let (burst, _) = self.wait_burst(AVAILABLE)?;
        // The chip requires reading the whole burst.
        let first = burst.min(response.len());
        if first < HEADER_SIZE {
            return Err(TcgError::InternalError);
        }
        self.read(DATA_FIFO, &mut response[..first])?;
        let expected = u32::from_be_bytes([response[2], response[3], response[4], response[5]]);
        let expected = usize::try_from(expected).map_err(|_| TcgError::InternalError)?;
        if expected < HEADER_SIZE {
            return Err(TcgError::InternalError);
        }
        if expected > response.len() {
            return Err(TcgError::EventTooLarge);
        }

        let mut received = first;
        while received < expected {
            let (burst, _) = self.wait_burst(AVAILABLE)?;
            let chunk = burst.min(expected - received);
            self.read(DATA_FIFO, &mut response[received..received + chunk])?;
            received += chunk;
        }

        let (_, status) = self.wait_burst(STS_VALID)?;
        if status & STS_DATA_AVAIL != 0 {
            log::error!("GSC TPM: response longer than its header");
            return Err(TcgError::InternalError);
        }
        Ok(expected)
    }
}

impl<I: I2c> TpmTransport for GscI2c<I> {
    fn send_command(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, TcgError> {
        if command.len() < HEADER_SIZE || response.len() < HEADER_SIZE {
            return Err(TcgError::InternalError);
        }
        let result = self.send(command).and_then(|()| {
            const DONE: u8 = STS_VALID | STS_DATA_AVAIL;
            poll(COMMAND_TIMEOUT_MS, 1, || {
                (self.status() & DONE == DONE).then_some(())
            })
            .ok_or_else(|| {
                log::error!("GSC TPM: command timed out");
                TcgError::InternalError
            })?;
            self.receive(response)
        });
        // Return the chip to ready, also aborting a failed transaction.
        self.command_ready();
        result
    }
}

/// Bind a described Google security chip as the TPM for measured boot.
pub(crate) fn bind(device: I2cPeripheral) {
    match GscI2c::<I2cBus>::open(device.bus, device.address, device.interrupt)
        .and_then(super::Tpm2::new)
    {
        Ok(tpm) => crate::peripheral::provide_tpm(alloc::boxed::Box::new(tpm)),
        Err(error) => log::warn!("GSC TPM initialization failed: {:?}", error),
    }
}

#[cfg(test)]
#[path = "gsc_i2c_tests.rs"]
mod tests;
