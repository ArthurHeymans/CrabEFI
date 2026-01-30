//! AMD SPI100 Controller Driver
//!
//! This module implements the SPI controller driver for AMD chipsets with SPI100 controller.
//! The SPI100 controller is found in AMD Ryzen and newer platforms.
//!
//! # Supported Chipsets
//!
//! - AMD Renoir/Cezanne (FCH 790b rev 0x51)
//! - AMD Pinnacle Ridge (FCH 790b rev 0x59)
//! - AMD Raven Ridge/Matisse/Starship (FCH 790b rev 0x61)
//! - AMD Raphael/Mendocino/Phoenix/Rembrandt (FCH 790b rev 0x71)
//!
//! # Architecture
//!
//! The AMD SPI100 controller has:
//! - A 71-byte FIFO for SPI commands and data
//! - Support for various SPI modes (normal, dual I/O, quad I/O, fast read)
//! - Configurable clock speeds

use super::amd_chipsets::AmdChipset;
use super::regs::*;
use super::{delay_us, Result, SpiController, SpiError, SpiMode};
use crate::drivers::mmio::MmioRegion;
use crate::drivers::pci::{self, PciAddress, PciDevice};

/// SPI100 FIFO size (in bytes)
const SPI100_FIFO_SIZE: usize = 71;

/// Maximum data transfer for read/write operations (accounting for address bytes)
const SPI100_MAX_DATA: usize = SPI100_FIFO_SIZE - 4;

/// AMD SPI100 register offsets
mod regs {
    /// SPI Control Register 0
    pub const SPI_CNTRL0: u64 = 0x00;
    /// SPI Status Register
    pub const SPI_STATUS: u64 = 0x4c;
    /// Command Register
    pub const CMD_CODE: u64 = 0x45;
    /// Command Trigger
    pub const CMD_TRIGGER: u64 = 0x47;
    /// Transmit Byte Count
    pub const TX_BYTE_COUNT: u64 = 0x48;
    /// Receive Byte Count
    pub const RX_BYTE_COUNT: u64 = 0x4b;
    /// FIFO base address
    pub const FIFO_BASE: u64 = 0x80;
    /// Speed configuration
    pub const SPEED_CFG: u64 = 0x22;
}

/// SPI Control 0 register bits
mod spi_cntrl0_bits {
    /// Illegal Access (bit 21)
    pub const ILLEGAL_ACCESS: u32 = 1 << 21;
}

/// SPI Status register bits
mod spi_status_bits {
    /// Transfer busy (bit 31)
    pub const BUSY: u32 = 1 << 31;
}

/// Command trigger bits
mod cmd_trigger_bits {
    /// Execute SPI command (bit 7)
    pub const EXECUTE: u8 = 1 << 7;
}

/// PCI register offset for SPI BAR in AMD FCH LPC device
const AMD_SPI_BAR_OFFSET: u8 = 0xa0;

/// LPC function number in AMD FCH
const AMD_LPC_FUNCTION: u8 = 3;

/// AMD SPI100 Controller
pub struct AmdSpi100Controller {
    /// Memory-mapped SPI registers
    spibar: MmioRegion,
    /// Chipset type
    chipset: AmdChipset,
    /// PCI address of the SMBus device
    pci_addr: PciAddress,
    /// Original alternate speed (for restoration on shutdown)
    _altspeed: u8,
}

impl AmdSpi100Controller {
    /// Create a new AMD SPI100 controller instance
    pub fn new(pci_dev: &PciDevice, chipset: AmdChipset) -> Result<Self> {
        if !chipset.uses_spi100() {
            log::error!("Chipset {:?} does not use SPI100 controller", chipset);
            return Err(SpiError::UnsupportedChipset);
        }

        // Get SPI BAR from LPC device (function 3)
        let lpc_addr = PciAddress::new(
            pci_dev.address.bus,
            pci_dev.address.device,
            AMD_LPC_FUNCTION,
        );
        let spibar = pci::read_config_u32(lpc_addr, AMD_SPI_BAR_OFFSET);

        if spibar == 0xffffffff {
            log::error!("SPI100 BAR reads all 0xff, aborting");
            return Err(SpiError::InitFailed);
        }

        // Log SPI BAR configuration bits
        log::debug!(
            "SPI BAR config: AltSpiCSEnable={} SpiRomEnable={} AbortEnable={}",
            spibar & 1,
            (spibar >> 1) & 1,
            (spibar >> 2) & 1,
        );

        let spirom_enabled = (spibar & (1 << 1)) != 0;

        // Extract physical SPI BAR address (lower 8 bits are config/reserved)
        let phys_spibar = (spibar & !0xff) as u64;

        if phys_spibar == 0 {
            if spirom_enabled {
                log::error!("SPI ROM is enabled but SPI BAR is unconfigured");
                return Err(SpiError::InitFailed);
            } else {
                log::debug!("SPI100 not used");
                return Err(SpiError::NotSupported);
            }
        }

        log::info!("AMD SPI100 BAR at {:#010x}", phys_spibar);

        // Map the SPI registers (256 bytes)
        let spibar_region = MmioRegion::new(phys_spibar, 256);

        // Read current speed config for restoration later
        let speed_cfg = spibar_region.read16(regs::SPEED_CFG);
        let altspeed = ((speed_cfg >> 4) & 0xf) as u8;

        let mut controller = Self {
            spibar: spibar_region,
            chipset,
            pci_addr: pci_dev.address,
            _altspeed: altspeed,
        };

        // Initialize the controller
        controller.init()?;

        Ok(controller)
    }

    /// Initialize the SPI100 controller
    fn init(&mut self) -> Result<()> {
        // Print controller configuration
        let spi_cntrl0 = self.spibar.read32(regs::SPI_CNTRL0);
        log::debug!(
            "SPI_CNTRL0: {:#010x} SpiArbEnable={} IllegalAccess={}",
            spi_cntrl0,
            (spi_cntrl0 >> 19) & 1,
            (spi_cntrl0 >> 21) & 1,
        );

        // Set speed to 33MHz for better compatibility
        self.set_altspeed();

        Ok(())
    }

    /// Set alternate speed for programming
    fn set_altspeed(&mut self) {
        let speed_cfg = self.spibar.read16(regs::SPEED_CFG);
        let normspeed = ((speed_cfg >> 12) & 0xf) as usize;

        // Set SPI speed to 33MHz (index 1) but not higher than normal read speed
        let altspeed = if normspeed > 0 && normspeed < 4 {
            normspeed as u8 // Keep existing speed if it's reasonable
        } else {
            1 // 33.33 MHz
        };

        let current_altspeed = ((speed_cfg >> 4) & 0xf) as u8;
        if altspeed != current_altspeed {
            log::info!("Setting SPI speed index to {}", altspeed);
            let new_speed_cfg = (speed_cfg & !0xf0) | ((altspeed as u16) << 4);
            self.spibar.write16(regs::SPEED_CFG, new_speed_cfg);
        }
    }

    /// Check read/write byte counts
    fn check_readwritecnt(&self, writecnt: usize, readcnt: usize) -> Result<()> {
        if writecnt < 1 {
            return Err(SpiError::InvalidArgument);
        }

        if writecnt - 1 > SPI100_FIFO_SIZE {
            return Err(SpiError::InvalidArgument);
        }

        let maxreadcnt = SPI100_FIFO_SIZE - (writecnt - 1);
        if readcnt > maxreadcnt {
            return Err(SpiError::InvalidArgument);
        }

        Ok(())
    }

    /// Send a raw SPI command
    pub fn send_command(&mut self, writearr: &[u8], readarr: &mut [u8]) -> Result<()> {
        let writecnt = writearr.len();
        let readcnt = readarr.len();

        self.check_readwritecnt(writecnt, readcnt)?;

        // First "command" byte is sent separately
        self.spibar.write8(regs::CMD_CODE, writearr[0]);
        self.spibar
            .write8(regs::TX_BYTE_COUNT, (writecnt - 1) as u8);
        self.spibar.write8(regs::RX_BYTE_COUNT, readcnt as u8);

        // Write remaining bytes to FIFO
        if writecnt > 1 {
            for i in 1..writecnt {
                self.spibar
                    .write8(regs::FIFO_BASE + (i - 1) as u64, writearr[i]);
            }
        }

        // Check if the command/address is allowed
        let spi_cntrl0 = self.spibar.read32(regs::SPI_CNTRL0);
        if spi_cntrl0 & spi_cntrl0_bits::ILLEGAL_ACCESS != 0 {
            log::error!("Illegal access for opcode {:#04x}", writearr[0]);
            return Err(SpiError::AccessDenied);
        }

        // Trigger command
        self.spibar
            .write8(regs::CMD_TRIGGER, cmd_trigger_bits::EXECUTE);

        // Wait for completion (10 second timeout)
        let timeout_us = 10_000_000u32;
        let mut elapsed_us = 0u32;

        loop {
            let spistatus = self.spibar.read32(regs::SPI_STATUS);
            if spistatus & spi_status_bits::BUSY == 0 {
                break;
            }

            if elapsed_us >= timeout_us {
                log::error!("SPI transfer timed out (status: {:#010x})", spistatus);
                return Err(SpiError::Timeout);
            }

            delay_us(1);
            elapsed_us += 1;
        }

        // Read response data from FIFO
        if readcnt > 0 {
            let fifo_offset = writecnt - 1;
            for i in 0..readcnt {
                readarr[i] = self
                    .spibar
                    .read8(regs::FIFO_BASE + (fifo_offset + i) as u64);
            }
        }

        Ok(())
    }

    /// Read data from flash using SPI READ command
    fn spi_read(&mut self, addr: u32, buf: &mut [u8]) -> Result<()> {
        let len = buf.len();
        let mut offset = 0;

        while offset < len {
            let chunk_len = (len - offset).min(SPI100_MAX_DATA);
            let current_addr = addr + offset as u32;

            // Build READ command: opcode + 3-byte address
            let mut writearr = [0u8; 4];
            writearr[0] = JEDEC_READ;
            writearr[1] = (current_addr >> 16) as u8;
            writearr[2] = (current_addr >> 8) as u8;
            writearr[3] = current_addr as u8;

            self.send_command(&writearr, &mut buf[offset..offset + chunk_len])?;
            offset += chunk_len;
        }

        Ok(())
    }

    /// Write data to flash using SPI PAGE PROGRAM command
    fn spi_write(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        let len = data.len();
        let mut offset = 0;

        while offset < len {
            // Calculate chunk size (max 64 bytes, respect 256-byte page boundaries)
            let remaining = len - offset;
            let current_addr = addr + offset as u32;
            let page_remaining = 256 - (current_addr as usize & 0xFF);
            let chunk_len = remaining.min(SPI100_MAX_DATA - 3).min(page_remaining);

            // Send WREN (Write Enable) first
            self.send_command(&[JEDEC_WREN], &mut [])?;

            // Build PAGE PROGRAM command: opcode + 3-byte address + data
            let mut writearr = [0u8; SPI100_FIFO_SIZE + 1];
            writearr[0] = JEDEC_BYTE_PROGRAM;
            writearr[1] = (current_addr >> 16) as u8;
            writearr[2] = (current_addr >> 8) as u8;
            writearr[3] = current_addr as u8;
            writearr[4..4 + chunk_len].copy_from_slice(&data[offset..offset + chunk_len]);

            self.send_command(&writearr[..4 + chunk_len], &mut [])?;

            // Wait for write to complete by polling status register
            self.wait_for_write_complete()?;

            offset += chunk_len;
        }

        Ok(())
    }

    /// Erase flash using SPI SECTOR ERASE command
    fn spi_erase(&mut self, addr: u32, len: u32) -> Result<()> {
        const ERASE_SIZE: u32 = 4096;

        if addr & (ERASE_SIZE - 1) != 0 || len & (ERASE_SIZE - 1) != 0 {
            log::error!("Erase address/length must be 4KB aligned");
            return Err(SpiError::InvalidArgument);
        }

        let mut current_addr = addr;
        let end_addr = addr + len;

        while current_addr < end_addr {
            // Send WREN (Write Enable) first
            self.send_command(&[JEDEC_WREN], &mut [])?;

            // Build SECTOR ERASE command: opcode + 3-byte address
            let writearr = [
                JEDEC_SE,
                (current_addr >> 16) as u8,
                (current_addr >> 8) as u8,
                current_addr as u8,
            ];

            self.send_command(&writearr, &mut [])?;

            // Wait for erase to complete
            self.wait_for_write_complete()?;

            current_addr += ERASE_SIZE;
        }

        Ok(())
    }

    /// Wait for write/erase operation to complete by polling status register
    fn wait_for_write_complete(&mut self) -> Result<()> {
        let timeout_us = 60_000_000u32; // 60 second timeout for erase
        let mut elapsed_us = 0u32;

        loop {
            let mut status = [0u8; 1];
            self.send_command(&[JEDEC_RDSR], &mut status)?;

            // Check WIP (Write In Progress) bit
            if status[0] & 0x01 == 0 {
                return Ok(());
            }

            if elapsed_us >= timeout_us {
                log::error!("Timeout waiting for write/erase to complete");
                return Err(SpiError::Timeout);
            }

            delay_us(100);
            elapsed_us += 100;
        }
    }
}

impl SpiController for AmdSpi100Controller {
    fn name(&self) -> &'static str {
        "AMD SPI100"
    }

    fn is_locked(&self) -> bool {
        // AMD SPI100 doesn't have a global lock bit like Intel
        false
    }

    fn writes_enabled(&self) -> bool {
        // AMD SPI100 doesn't need BIOS_CNTL write enable - it's always writable
        // (assuming the region isn't protected)
        true
    }

    fn enable_writes(&mut self) -> Result<()> {
        // AMD doesn't need explicit write enable
        Ok(())
    }

    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<()> {
        self.spi_read(addr, buf)
    }

    fn write(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        self.spi_write(addr, data)
    }

    fn erase(&mut self, addr: u32, len: u32) -> Result<()> {
        self.spi_erase(addr, len)
    }

    fn mode(&self) -> SpiMode {
        // AMD SPI100 uses software-controlled SPI commands
        SpiMode::SoftwareSequencing
    }
}
