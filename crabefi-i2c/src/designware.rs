// SPDX-License-Identifier: MIT OR Apache-2.0
//! Synopsys DesignWare APB I2C master, polled.
//! Extracted from fstart-driver-i2c so firmware and its payload share a transport.
//!
//! A read that the target doesn't acknowledge ends at the
//! TX abort instead of waiting out the receive timeout, so probing absent
//! devices is cheap.

use embedded_hal::{
    delay::DelayNs,
    i2c::{self, ErrorKind, ErrorType, I2c, NoAcknowledgeSource, Operation, SevenBitAddress},
};
use tock_registers::{
    LocalRegisterCopy,
    interfaces::{ReadWriteable, Readable, Writeable},
    register_bitfields, register_structs,
    registers::{ReadOnly, ReadWrite},
};

register_bitfields![u32,
    Control [
        MASTER_MODE OFFSET(0) NUMBITS(1) [],
        SPEED OFFSET(1) NUMBITS(2) [Standard = 1, Fast = 2],
        ADDRESS_10BIT OFFSET(4) NUMBITS(1) [],
        RESTART_ENABLE OFFSET(5) NUMBITS(1) [],
        SLAVE_DISABLE OFFSET(6) NUMBITS(1) []
    ],
    DataCmd [
        DATA OFFSET(0) NUMBITS(8) [],
        READ OFFSET(8) NUMBITS(1) [],
        STOP OFFSET(9) NUMBITS(1) []
    ],
    Interrupt [
        TX_ABORT OFFSET(6) NUMBITS(1) [],
        STOP_DETECTED OFFSET(9) NUMBITS(1) []
    ],
    Enable [ENABLE OFFSET(0) NUMBITS(1) []],
    Status [
        TX_FIFO_NOT_FULL OFFSET(1) NUMBITS(1) [],
        TX_FIFO_EMPTY OFFSET(2) NUMBITS(1) [],
        RX_FIFO_NOT_EMPTY OFFSET(3) NUMBITS(1) [],
        MASTER_ACTIVITY OFFSET(5) NUMBITS(1) []
    ],
    SdaHold [TX OFFSET(0) NUMBITS(16) []],
    AbortSource [
        ADDRESS_NACK OFFSET(0) NUMBITS(1) [],
        DATA_NACK OFFSET(3) NUMBITS(1) [],
        ARBITRATION_LOST OFFSET(12) NUMBITS(1) []
    ]
];

register_structs! {
    Regs {
        (0x00 => control: ReadWrite<u32, Control::Register>),
        (0x04 => target: ReadWrite<u32>),
        (0x08 => _reserved0),
        (0x10 => data_cmd: ReadWrite<u32, DataCmd::Register>),
        (0x14 => ss_scl_high: ReadWrite<u32>),
        (0x18 => ss_scl_low: ReadWrite<u32>),
        (0x1c => fs_scl_high: ReadWrite<u32>),
        (0x20 => fs_scl_low: ReadWrite<u32>),
        (0x24 => _reserved1),
        (0x30 => interrupt_mask: ReadWrite<u32, Interrupt::Register>),
        (0x34 => raw_interrupt: ReadOnly<u32, Interrupt::Register>),
        (0x38 => rx_threshold: ReadWrite<u32>),
        (0x3c => tx_threshold: ReadWrite<u32>),
        /// Reading clears the interrupt.
        (0x40 => clear_interrupts: ReadOnly<u32>),
        (0x44 => _reserved2),
        (0x54 => clear_tx_abort: ReadOnly<u32>),
        (0x58 => _reserved3),
        (0x60 => clear_stop_detected: ReadOnly<u32>),
        (0x64 => _reserved4),
        (0x6c => enable: ReadWrite<u32, Enable::Register>),
        (0x70 => status: ReadOnly<u32, Status::Register>),
        (0x74 => _reserved5),
        (0x7c => sda_hold: ReadWrite<u32, SdaHold::Register>),
        (0x80 => abort_source: ReadOnly<u32, AbortSource::Register>),
        (0x84 => _reserved6),
        (0x9c => enable_status: ReadOnly<u32, Enable::Register>),
        (0xa0 => fs_spike_length: ReadWrite<u32>),
        (0xa4 => _reserved7),
        (0xfc => component_type: ReadOnly<u32>),
        (0x100 => @END),
    }
}

/// IC_COMP_TYPE of every DesignWare I2C ("DW" 0x0140).
const COMPONENT_TYPE: u32 = 0x4457_0140;
/// Per byte.
const TRANSFER_TIMEOUT_US: u32 = 500_000;
/// Bus idle, disable and FIFO flush.
const IDLE_TIMEOUT_US: u32 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speed {
    /// 100 kHz
    Standard,
    /// 400 kHz
    Fast,
}

/// SCL counts are in controller clock cycles.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub speed: Speed,
    pub scl_high: u16,
    pub scl_low: u16,
    /// IC_FS_SPKLEN, if the reset value isn't right.
    pub spike_length: Option<u8>,
    /// Transmit SDA hold time in controller clock cycles.
    pub sda_hold: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The registers don't identify a DesignWare I2C.
    NotPresent,
    InvalidRegion,
    NotConfigured,
    UnsupportedSpeed,
    Timeout,
    NoAcknowledge(NoAcknowledgeSource),
    ArbitrationLoss,
    /// Any other IC_TX_ABRT_SOURCE.
    Abort(u32),
}

impl i2c::Error for Error {
    fn kind(&self) -> ErrorKind {
        match *self {
            Self::NoAcknowledge(source) => ErrorKind::NoAcknowledge(source),
            Self::ArbitrationLoss => ErrorKind::ArbitrationLoss,
            Self::NotPresent
            | Self::InvalidRegion
            | Self::NotConfigured
            | Self::UnsupportedSpeed
            | Self::Timeout
            | Self::Abort(_) => ErrorKind::Other,
        }
    }
}

pub struct DesignWare<D> {
    regs: &'static Regs,
    delay: D,
}

impl<D: DelayNs> DesignWare<D> {
    /// Program the controller as a master with `timing`; it stays disabled
    /// between transactions.
    ///
    /// # Safety
    /// `base` is the controller's register block, decoded, clocked and
    /// UC-mapped, and nothing else uses it while this driver exists.
    pub unsafe fn new(base: usize, timing: &Timing, delay: D) -> Result<Self, Error> {
        // SAFETY: caller supplies a full, decoded controller register block.
        let this = unsafe { Self::prepare(base, size_of::<Regs>(), delay) }?;
        let regs = this.regs;
        let speed = match timing.speed {
            Speed::Standard => Control::SPEED::Standard,
            Speed::Fast => Control::SPEED::Fast,
        };
        regs.control.write(
            Control::MASTER_MODE::SET
                + speed
                + Control::RESTART_ENABLE::SET
                + Control::SLAVE_DISABLE::SET,
        );
        let (high, low) = match timing.speed {
            Speed::Standard => (&regs.ss_scl_high, &regs.ss_scl_low),
            Speed::Fast => (&regs.fs_scl_high, &regs.fs_scl_low),
        };
        high.set(timing.scl_high.into());
        low.set(timing.scl_low.into());
        if let Some(length) = timing.spike_length {
            regs.fs_spike_length.set(length.into());
        }
        if let Some(hold) = timing.sda_hold {
            regs.sda_hold.modify(SdaHold::TX.val(hold.into()));
        }
        regs.rx_threshold.set(0);
        regs.tx_threshold.set(0);
        Ok(this)
    }

    /// Adopt firmware's existing master configuration without changing SCL,
    /// SDA hold or spike-filter timings. ACPI supplies the requested bus speed;
    /// this rejects a mismatching mode rather than guessing the input clock.
    ///
    /// # Safety
    /// The region is decoded, UC-mapped controller MMIO, exclusively owned by
    /// this driver. The platform has already initialized clocks, pads and power.
    pub unsafe fn attach(base: usize, size: usize, speed_hz: u32, delay: D) -> Result<Self, Error> {
        // SAFETY: the caller guarantees the MMIO mapping and exclusivity.
        let this = unsafe { Self::prepare(base, size, delay) }?;
        let regs = this.regs;
        let mode = regs.control.extract();
        let expected = match speed_hz {
            100_000 => Control::SPEED::Standard,
            400_000 => Control::SPEED::Fast,
            _ => return Err(Error::UnsupportedSpeed),
        };
        let (high, low) = if speed_hz == 100_000 {
            (regs.ss_scl_high.get(), regs.ss_scl_low.get())
        } else {
            (regs.fs_scl_high.get(), regs.fs_scl_low.get())
        };
        if !mode.is_set(Control::MASTER_MODE)
            || !mode.is_set(Control::RESTART_ENABLE)
            || !mode.is_set(Control::SLAVE_DISABLE)
            || mode.is_set(Control::ADDRESS_10BIT)
            || !mode.matches_all(expected)
            || high == 0
            || low == 0
        {
            return Err(Error::NotConfigured);
        }
        Ok(this)
    }

    unsafe fn prepare(base: usize, size: usize, delay: D) -> Result<Self, Error> {
        if base == 0
            || base & 3 != 0
            || size < size_of::<Regs>()
            || base.checked_add(size).is_none()
        {
            return Err(Error::InvalidRegion);
        }
        // SAFETY: validated register span, plus the caller's hardware contract.
        let regs = unsafe { &*(base as *const Regs) };
        if regs.component_type.get() != COMPONENT_TYPE {
            return Err(Error::NotPresent);
        }
        let mut this = Self { regs, delay };
        this.wait(IDLE_TIMEOUT_US, |regs| {
            Ok(!regs.status.is_set(Status::MASTER_ACTIVITY))
        })?;
        this.disable()?;
        // Poll raw status; do not enable a controller interrupt without a handler.
        regs.interrupt_mask.set(0);
        let _ = regs.clear_interrupts.get();
        Ok(this)
    }

    /// Poll `done` every microsecond for up to `timeout_us`.
    fn wait(
        &mut self,
        timeout_us: u32,
        mut done: impl FnMut(&Regs) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        let regs = self.regs;
        for _ in 0..timeout_us {
            if done(regs)? {
                return Ok(());
            }
            self.delay.delay_us(1);
        }
        Err(Error::Timeout)
    }

    fn disable(&mut self) -> Result<(), Error> {
        self.regs.enable.write(Enable::ENABLE::CLEAR);
        self.wait(IDLE_TIMEOUT_US, |regs| {
            Ok(!regs.enable_status.is_set(Enable::ENABLE))
        })
    }

    /// Byte by byte with STOP on the last one; the controller issues a
    /// repeated start where the direction changes.
    fn run(&mut self, operations: &mut [Operation<'_>]) -> Result<(), Error> {
        let regs = self.regs;
        let last = operations.iter().rposition(|operation| match operation {
            Operation::Read(buffer) => !buffer.is_empty(),
            Operation::Write(bytes) => !bytes.is_empty(),
        });
        let Some(last) = last else {
            // Address only.
            regs.data_cmd.write(DataCmd::STOP::SET);
            return self.finish();
        };
        for (index, operation) in operations.iter_mut().enumerate() {
            match operation {
                Operation::Write(bytes) => {
                    let count = bytes.len();
                    for (offset, &byte) in bytes.iter().enumerate() {
                        self.wait(TRANSFER_TIMEOUT_US, |regs| {
                            check_abort(regs)?;
                            Ok(regs.status.is_set(Status::TX_FIFO_NOT_FULL))
                        })?;
                        let stop = index == last && offset + 1 == count;
                        regs.data_cmd
                            .write(DataCmd::DATA.val(byte.into()) + DataCmd::STOP.val(stop.into()));
                    }
                }
                Operation::Read(buffer) => {
                    let count = buffer.len();
                    for (offset, byte) in buffer.iter_mut().enumerate() {
                        let stop = index == last && offset + 1 == count;
                        regs.data_cmd
                            .write(DataCmd::READ::SET + DataCmd::STOP.val(stop.into()));
                        self.wait(TRANSFER_TIMEOUT_US, |regs| {
                            check_abort(regs)?;
                            Ok(regs.status.is_set(Status::RX_FIFO_NOT_EMPTY))
                        })?;
                        *byte = regs.data_cmd.read(DataCmd::DATA) as u8;
                    }
                }
            }
        }
        self.finish()
    }

    /// Wait for the STOP, then for the bus to go idle, and drain the RX FIFO.
    fn finish(&mut self) -> Result<(), Error> {
        self.wait(TRANSFER_TIMEOUT_US, |regs| {
            Ok(regs.raw_interrupt.is_set(Interrupt::STOP_DETECTED))
        })?;
        let _ = self.regs.clear_stop_detected.get();
        check_abort(self.regs)?;
        self.wait(IDLE_TIMEOUT_US, |regs| {
            let status = regs.status.extract();
            Ok(!status.is_set(Status::MASTER_ACTIVITY) && status.is_set(Status::TX_FIFO_EMPTY))
        })?;
        self.wait(IDLE_TIMEOUT_US, |regs| {
            if !regs.status.is_set(Status::RX_FIFO_NOT_EMPTY) {
                return Ok(true);
            }
            let _ = regs.data_cmd.get();
            Ok(false)
        })
    }
}

/// A TX abort ends the transfer: the controller flushed its FIFO and sent
/// the STOP itself.
fn check_abort(regs: &Regs) -> Result<(), Error> {
    if !regs.raw_interrupt.is_set(Interrupt::TX_ABORT) {
        return Ok(());
    }
    let source = LocalRegisterCopy::<u32, AbortSource::Register>::new(regs.abort_source.get());
    let _ = regs.clear_tx_abort.get();
    Err(if source.is_set(AbortSource::ADDRESS_NACK) {
        Error::NoAcknowledge(NoAcknowledgeSource::Address)
    } else if source.is_set(AbortSource::DATA_NACK) {
        Error::NoAcknowledge(NoAcknowledgeSource::Data)
    } else if source.is_set(AbortSource::ARBITRATION_LOST) {
        Error::ArbitrationLoss
    } else {
        Error::Abort(source.get())
    })
}

impl<D> ErrorType for DesignWare<D> {
    type Error = Error;
}

impl<D: DelayNs> I2c<SevenBitAddress> for DesignWare<D> {
    fn transaction(
        &mut self,
        address: SevenBitAddress,
        operations: &mut [Operation<'_>],
    ) -> Result<(), Error> {
        self.regs.target.set(address.into());
        self.regs.enable.write(Enable::ENABLE::SET);
        let result = self.run(operations);
        let _ = self.regs.clear_interrupts.get();
        let disabled = self.disable();
        result.and(disabled)
    }
}
