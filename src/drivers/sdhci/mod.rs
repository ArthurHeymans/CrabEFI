//! SDHCI (SD Host Controller Interface) Driver
//!
//! This module provides a driver for SD/MMC cards connected via standard SDHCI
//! controllers. It supports PCI-based SDHCI controllers and implements the
//! SD card protocol for reading sectors.

pub mod regs;

use crate::drivers::pci::{self, PciAddress, PciDevice};
use crate::efi;
use crate::time::Timeout;
use core::ptr;
use core::sync::atomic::{fence, Ordering};
use spin::Mutex;

use regs::*;

/// Maximum number of SDHCI controllers we can track
const MAX_SDHCI_CONTROLLERS: usize = 4;

/// Block size for SD cards (always 512 bytes)
const SD_BLOCK_SIZE: u32 = 512;

/// Default timeout for commands (milliseconds)
const CMD_TIMEOUT_MS: u64 = 1000;

/// Default timeout for data transfers (milliseconds)
const DATA_TIMEOUT_MS: u64 = 5000;

/// Initialization clock frequency (400 kHz for card identification)
const INIT_CLOCK_HZ: u32 = 400_000;

/// Default speed clock frequency (25 MHz)
const DEFAULT_CLOCK_HZ: u32 = 25_000_000;

/// High speed clock frequency (50 MHz)
const HIGH_SPEED_CLOCK_HZ: u32 = 50_000_000;

/// SDHCI error type
#[derive(Debug, Clone, Copy)]
pub enum SdhciError {
    /// Controller not found or not initialized
    NotInitialized,
    /// Reset failed
    ResetFailed,
    /// No card present
    NoCard,
    /// Card initialization failed
    CardInitFailed,
    /// Command timeout
    CommandTimeout,
    /// Command CRC error
    CommandCrcError,
    /// Command index error
    CommandIndexError,
    /// Command end bit error
    CommandEndBitError,
    /// Data timeout
    DataTimeout,
    /// Data CRC error
    DataCrcError,
    /// Data end bit error
    DataEndBitError,
    /// DMA error
    DmaError,
    /// Invalid parameter
    InvalidParameter,
    /// Memory allocation failed
    AllocationFailed,
    /// Clock configuration failed
    ClockFailed,
    /// Generic error
    GenericError,
}

/// SDHCI Controller
pub struct SdhciController {
    /// PCI address (bus:device.function)
    pci_address: PciAddress,
    /// MMIO base address
    mmio_base: u64,
    /// SDHCI specification version
    version: u8,
    /// Maximum base clock frequency (Hz)
    max_clock: u32,
    /// Capabilities register value
    capabilities: u32,
    /// Capabilities 1 register value
    capabilities_1: u32,
    /// Card is present
    card_present: bool,
    /// Card is initialized
    card_initialized: bool,
    /// Relative Card Address (after initialization)
    rca: u16,
    /// Card is high capacity (SDHC/SDXC)
    high_capacity: bool,
    /// Total number of blocks on card
    num_blocks: u64,
    /// Block size (always 512 for SD)
    block_size: u32,
    /// DMA buffer (page-aligned)
    dma_buffer: *mut u8,
}

// Safety: SdhciController contains raw pointers but we ensure single-threaded
// access via the Mutex in SDHCI_CONTROLLERS
unsafe impl Send for SdhciController {}

impl SdhciController {
    /// Create a new SDHCI controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, SdhciError> {
        let mmio_base = pci_dev.mmio_base().ok_or(SdhciError::NotInitialized)?;

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        // Allocate a page-aligned DMA buffer for data transfers
        let dma_buffer = efi::allocate_pages(1).ok_or(SdhciError::AllocationFailed)? as *mut u8;

        let mut controller = Self {
            pci_address: pci_dev.address,
            mmio_base,
            version: 0,
            max_clock: 0,
            capabilities: 0,
            capabilities_1: 0,
            card_present: false,
            card_initialized: false,
            rca: 0,
            high_capacity: false,
            num_blocks: 0,
            block_size: SD_BLOCK_SIZE,
            dma_buffer,
        };

        controller.init()?;
        Ok(controller)
    }

    /// Initialize the SDHCI controller
    fn init(&mut self) -> Result<(), SdhciError> {
        // Read version
        let version_reg = self.read_reg16(SDHCI_HOST_VERSION);
        self.version = (version_reg & SDHCI_SPEC_VER_MASK) as u8;

        log::info!(
            "SDHCI controller version: {}.0 (vendor: {:#x})",
            self.version + 1,
            (version_reg >> 8) & 0xFF
        );

        // Read capabilities
        self.capabilities = self.read_reg32(SDHCI_CAPABILITIES);
        self.capabilities_1 = self.read_reg32(SDHCI_CAPABILITIES_1);

        log::debug!("SDHCI capabilities: {:#010x}", self.capabilities);
        log::debug!("SDHCI capabilities_1: {:#010x}", self.capabilities_1);

        // Calculate max clock from capabilities
        if self.version >= SDHCI_SPEC_300 {
            self.max_clock = ((self.capabilities & SDHCI_CLOCK_V3_BASE_MASK)
                >> SDHCI_CLOCK_BASE_SHIFT) as u32
                * 1_000_000;
        } else {
            self.max_clock = ((self.capabilities & SDHCI_CLOCK_BASE_MASK) >> SDHCI_CLOCK_BASE_SHIFT)
                as u32
                * 1_000_000;
        }

        log::info!("SDHCI max clock: {} MHz", self.max_clock / 1_000_000);

        // Log capabilities
        if self.capabilities & SDHCI_CAN_DO_SDMA != 0 {
            log::info!("SDHCI: SDMA supported");
        }
        if self.capabilities & SDHCI_CAN_DO_ADMA2 != 0 {
            log::info!("SDHCI: ADMA2 supported");
        }
        if self.capabilities & SDHCI_CAN_DO_HISPD != 0 {
            log::info!("SDHCI: High-speed supported");
        }
        if self.capabilities & SDHCI_CAN_VDD_330 != 0 {
            log::info!("SDHCI: 3.3V supported");
        }

        // Reset the controller
        self.reset(SDHCI_RESET_ALL)?;

        // Set power
        self.set_power(SDHCI_POWER_330)?;

        // Enable interrupts
        let int_mask = SDHCI_INT_CMD_MASK | SDHCI_INT_DATA_MASK;
        self.write_reg32(SDHCI_INT_ENABLE, int_mask);
        self.write_reg32(SDHCI_SIGNAL_ENABLE, 0); // Polling mode, no signal interrupts

        // Check for card presence
        self.card_present = self.detect_card();

        if self.card_present {
            log::info!("SDHCI: Card detected");
            // Initialize the card
            if let Err(e) = self.init_card() {
                log::error!("SDHCI: Failed to initialize card: {:?}", e);
                return Err(e);
            }
        } else {
            log::info!("SDHCI: No card detected");
        }

        Ok(())
    }

    /// Reset the controller
    fn reset(&mut self, mask: u8) -> Result<(), SdhciError> {
        self.write_reg8(SDHCI_SOFTWARE_RESET, mask);

        // Wait for reset to complete (up to 100ms)
        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if self.read_reg8(SDHCI_SOFTWARE_RESET) & mask == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        log::error!("SDHCI: Reset timeout (mask={:#x})", mask);
        Err(SdhciError::ResetFailed)
    }

    /// Set bus power
    fn set_power(&mut self, voltage: u8) -> Result<(), SdhciError> {
        // Turn off power first
        self.write_reg8(SDHCI_POWER_CONTROL, 0);

        // Small delay
        for _ in 0..1000 {
            core::hint::spin_loop();
        }

        // Turn on power with specified voltage
        self.write_reg8(SDHCI_POWER_CONTROL, voltage | SDHCI_POWER_ON);

        // Wait for power to stabilize
        let timeout = Timeout::from_ms(50);
        while !timeout.is_expired() {
            core::hint::spin_loop();
        }

        Ok(())
    }

    /// Set the SD clock frequency
    fn set_clock(&mut self, clock: u32) -> Result<(), SdhciError> {
        // Disable clock
        self.write_reg16(SDHCI_CLOCK_CONTROL, 0);

        if clock == 0 {
            return Ok(());
        }

        // Calculate divider
        let divider = if self.version >= SDHCI_SPEC_300 {
            // Version 3.0+: 10-bit divider
            let mut div = 0u16;
            if clock < self.max_clock {
                for d in (2..=SDHCI_MAX_DIV_SPEC_300 as u16).step_by(2) {
                    if self.max_clock / d as u32 <= clock {
                        div = d;
                        break;
                    }
                }
            }
            div
        } else {
            // Version 2.0: 8-bit divider, powers of 2
            let mut div = 1u16;
            while div < SDHCI_MAX_DIV_SPEC_200 as u16 {
                if self.max_clock / div as u32 <= clock {
                    break;
                }
                div *= 2;
            }
            div / 2 // SDHCI 2.0 stores div/2
        };

        let actual_clock = if divider == 0 {
            self.max_clock
        } else {
            self.max_clock / divider as u32
        };

        log::debug!(
            "SDHCI: Setting clock to {} Hz (divider={}, actual={})",
            clock,
            divider,
            actual_clock
        );

        // Encode divider into clock control register
        let clk = if self.version >= SDHCI_SPEC_300 {
            let div_lo = (divider & 0xFF) >> 1;
            let div_hi = ((divider >> 8) & 0x03) << 6;
            (div_lo << SDHCI_DIVIDER_SHIFT) | div_hi | SDHCI_CLOCK_INT_EN
        } else {
            ((divider & 0xFF) << SDHCI_DIVIDER_SHIFT) | SDHCI_CLOCK_INT_EN
        };

        self.write_reg16(SDHCI_CLOCK_CONTROL, clk);

        // Wait for internal clock stable
        let timeout = Timeout::from_ms(20);
        while !timeout.is_expired() {
            if self.read_reg16(SDHCI_CLOCK_CONTROL) & SDHCI_CLOCK_INT_STABLE != 0 {
                break;
            }
            core::hint::spin_loop();
        }

        if self.read_reg16(SDHCI_CLOCK_CONTROL) & SDHCI_CLOCK_INT_STABLE == 0 {
            log::error!("SDHCI: Internal clock not stable");
            return Err(SdhciError::ClockFailed);
        }

        // Enable card clock
        let clk = self.read_reg16(SDHCI_CLOCK_CONTROL) | SDHCI_CLOCK_CARD_EN;
        self.write_reg16(SDHCI_CLOCK_CONTROL, clk);

        Ok(())
    }

    /// Set bus width
    fn set_bus_width(&mut self, width: u8) {
        let mut ctrl = self.read_reg8(SDHCI_HOST_CONTROL);

        // Clear bus width bits
        ctrl &= !(SDHCI_CTRL_4BITBUS | SDHCI_CTRL_8BITBUS);

        match width {
            4 => ctrl |= SDHCI_CTRL_4BITBUS,
            8 => ctrl |= SDHCI_CTRL_8BITBUS,
            _ => {} // 1-bit mode
        }

        self.write_reg8(SDHCI_HOST_CONTROL, ctrl);
    }

    /// Detect if a card is present
    fn detect_card(&self) -> bool {
        let state = self.read_reg32(SDHCI_PRESENT_STATE);
        (state & SDHCI_CARD_PRESENT) != 0 && (state & SDHCI_CARD_STATE_STABLE) != 0
    }

    /// Wait for command/data inhibit to clear
    fn wait_inhibit(&self, data: bool) -> Result<(), SdhciError> {
        let mask = if data {
            SDHCI_CMD_INHIBIT | SDHCI_DATA_INHIBIT
        } else {
            SDHCI_CMD_INHIBIT
        };

        let timeout = Timeout::from_ms(CMD_TIMEOUT_MS);
        while !timeout.is_expired() {
            if self.read_reg32(SDHCI_PRESENT_STATE) & mask == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err(SdhciError::CommandTimeout)
    }

    /// Send a command (without data)
    fn send_command(&mut self, cmd: u8, arg: u32, resp_type: u8) -> Result<[u32; 4], SdhciError> {
        self.send_command_internal(cmd, arg, resp_type, false)
    }

    /// Send a command (internal implementation)
    fn send_command_internal(
        &mut self,
        cmd: u8,
        arg: u32,
        resp_type: u8,
        has_data: bool,
    ) -> Result<[u32; 4], SdhciError> {
        // Wait for command inhibit to clear
        self.wait_inhibit(has_data)?;

        // Clear all pending interrupts
        self.write_reg32(SDHCI_INT_STATUS, SDHCI_INT_ALL_MASK);

        // Set argument
        self.write_reg32(SDHCI_ARGUMENT, arg);

        // Build command flags
        let mut flags: u16 = 0;

        match resp_type {
            MMC_RSP_NONE => flags |= SDHCI_CMD_RESP_NONE,
            MMC_RSP_R1 | MMC_RSP_R6 | MMC_RSP_R7 => {
                flags |= SDHCI_CMD_RESP_SHORT | SDHCI_CMD_CRC | SDHCI_CMD_INDEX
            }
            MMC_RSP_R1B => flags |= SDHCI_CMD_RESP_SHORT_BUSY | SDHCI_CMD_CRC | SDHCI_CMD_INDEX,
            MMC_RSP_R2 => flags |= SDHCI_CMD_RESP_LONG | SDHCI_CMD_CRC,
            MMC_RSP_R3 => flags |= SDHCI_CMD_RESP_SHORT,
            _ => flags |= SDHCI_CMD_RESP_SHORT,
        }

        if has_data {
            flags |= SDHCI_CMD_DATA;
        }

        // Send command
        let cmd_reg = make_cmd(cmd, flags);
        self.write_reg16(SDHCI_COMMAND, cmd_reg);

        // Wait for command complete
        let timeout = Timeout::from_ms(CMD_TIMEOUT_MS);
        let mut status: u32;

        loop {
            status = self.read_reg32(SDHCI_INT_STATUS);

            // Check for errors
            if status & SDHCI_INT_ERROR != 0 {
                // Clear status
                self.write_reg32(SDHCI_INT_STATUS, status);

                if status & SDHCI_INT_TIMEOUT != 0 {
                    log::debug!("SDHCI: CMD{} timeout", cmd);
                    self.reset(SDHCI_RESET_CMD)?;
                    return Err(SdhciError::CommandTimeout);
                }
                if status & SDHCI_INT_CRC != 0 {
                    log::debug!("SDHCI: CMD{} CRC error", cmd);
                    self.reset(SDHCI_RESET_CMD)?;
                    return Err(SdhciError::CommandCrcError);
                }
                if status & SDHCI_INT_INDEX != 0 {
                    log::debug!("SDHCI: CMD{} index error", cmd);
                    self.reset(SDHCI_RESET_CMD)?;
                    return Err(SdhciError::CommandIndexError);
                }
                if status & SDHCI_INT_END_BIT != 0 {
                    log::debug!("SDHCI: CMD{} end bit error", cmd);
                    self.reset(SDHCI_RESET_CMD)?;
                    return Err(SdhciError::CommandEndBitError);
                }

                log::debug!("SDHCI: CMD{} unknown error: {:#x}", cmd, status);
                self.reset(SDHCI_RESET_CMD)?;
                return Err(SdhciError::GenericError);
            }

            // Check for command complete
            if status & SDHCI_INT_RESPONSE != 0 {
                break;
            }

            if timeout.is_expired() {
                self.reset(SDHCI_RESET_CMD)?;
                return Err(SdhciError::CommandTimeout);
            }

            core::hint::spin_loop();
        }

        // Clear command complete status
        self.write_reg32(SDHCI_INT_STATUS, SDHCI_INT_RESPONSE);

        // Read response
        let response = [
            self.read_reg32(SDHCI_RESPONSE),
            self.read_reg32(SDHCI_RESPONSE + 4),
            self.read_reg32(SDHCI_RESPONSE + 8),
            self.read_reg32(SDHCI_RESPONSE + 12),
        ];

        Ok(response)
    }

    /// Initialize the SD card
    fn init_card(&mut self) -> Result<(), SdhciError> {
        // Set identification clock (400 kHz)
        self.set_clock(INIT_CLOCK_HZ)?;

        // Start in 1-bit mode
        self.set_bus_width(1);

        // Small delay for card power-up
        let timeout = Timeout::from_ms(10);
        while !timeout.is_expired() {
            core::hint::spin_loop();
        }

        // CMD0: GO_IDLE_STATE
        log::debug!("SDHCI: Sending CMD0 (GO_IDLE_STATE)");
        let _ = self.send_command(MMC_CMD_GO_IDLE_STATE, 0, MMC_RSP_NONE);

        // Small delay
        let timeout = Timeout::from_ms(5);
        while !timeout.is_expired() {
            core::hint::spin_loop();
        }

        // CMD8: SEND_IF_COND (check for SD 2.0+)
        // Argument: 0x1AA = VHS (2.7-3.6V) + check pattern
        log::debug!("SDHCI: Sending CMD8 (SEND_IF_COND)");
        let sd_v2 = match self.send_command(SD_CMD_SEND_IF_COND, 0x1AA, MMC_RSP_R7) {
            Ok(resp) => {
                // Check that card echoed back the pattern
                if (resp[0] & 0x1FF) == 0x1AA {
                    log::debug!("SDHCI: SD 2.0+ card detected");
                    true
                } else {
                    log::debug!("SDHCI: CMD8 response mismatch: {:#x}", resp[0]);
                    false
                }
            }
            Err(_) => {
                log::debug!("SDHCI: CMD8 failed, assuming SD 1.x");
                false
            }
        };

        // ACMD41: SD_SEND_OP_COND (wait for card ready)
        // Try up to 1 second for card to become ready
        log::debug!("SDHCI: Starting ACMD41 loop");
        let ocr_arg = if sd_v2 {
            OCR_HCS | OCR_VDD_RANGE
        } else {
            OCR_VDD_RANGE
        };

        let timeout = Timeout::from_ms(1000);
        let mut ocr: u32 = 0;

        while !timeout.is_expired() {
            // CMD55: APP_CMD (prefix for ACMD)
            if self.send_command(MMC_CMD_APP_CMD, 0, MMC_RSP_R1).is_err() {
                continue;
            }

            // ACMD41: SD_SEND_OP_COND
            match self.send_command(SD_CMD_APP_SEND_OP_COND, ocr_arg, MMC_RSP_R3) {
                Ok(resp) => {
                    ocr = resp[0];
                    if ocr & OCR_BUSY != 0 {
                        log::debug!("SDHCI: Card ready, OCR={:#010x}", ocr);
                        break;
                    }
                }
                Err(_) => continue,
            }

            // Small delay before retry
            for _ in 0..10000 {
                core::hint::spin_loop();
            }
        }

        if ocr & OCR_BUSY == 0 {
            log::error!("SDHCI: Card initialization timeout");
            return Err(SdhciError::CardInitFailed);
        }

        // Check if high capacity card
        self.high_capacity = (ocr & OCR_HCS) != 0;
        log::info!(
            "SDHCI: Card type: {}",
            if self.high_capacity {
                "SDHC/SDXC"
            } else {
                "SDSC"
            }
        );

        // CMD2: ALL_SEND_CID (get card identification)
        log::debug!("SDHCI: Sending CMD2 (ALL_SEND_CID)");
        let cid = self.send_command(MMC_CMD_ALL_SEND_CID, 0, MMC_RSP_R2)?;
        log::debug!(
            "SDHCI: CID: {:08x} {:08x} {:08x} {:08x}",
            cid[3],
            cid[2],
            cid[1],
            cid[0]
        );

        // CMD3: SEND_RELATIVE_ADDR (get RCA)
        log::debug!("SDHCI: Sending CMD3 (SEND_RELATIVE_ADDR)");
        let resp = self.send_command(SD_CMD_SEND_RELATIVE_ADDR, 0, MMC_RSP_R6)?;
        self.rca = (resp[0] >> 16) as u16;
        log::debug!("SDHCI: RCA={:#06x}", self.rca);

        // CMD9: SEND_CSD (get card specific data)
        log::debug!("SDHCI: Sending CMD9 (SEND_CSD)");
        let csd = self.send_command(MMC_CMD_SEND_CSD, (self.rca as u32) << 16, MMC_RSP_R2)?;
        self.parse_csd(&csd);

        // CMD7: SELECT_CARD (select the card)
        log::debug!("SDHCI: Sending CMD7 (SELECT_CARD)");
        self.send_command(MMC_CMD_SELECT_CARD, (self.rca as u32) << 16, MMC_RSP_R1B)?;

        // CMD16: SET_BLOCKLEN (set block length to 512 for non-HC cards)
        if !self.high_capacity {
            log::debug!("SDHCI: Sending CMD16 (SET_BLOCKLEN)");
            self.send_command(MMC_CMD_SET_BLOCKLEN, 512, MMC_RSP_R1)?;
        }

        // Switch to 4-bit mode
        log::debug!("SDHCI: Switching to 4-bit mode");
        self.send_command(MMC_CMD_APP_CMD, (self.rca as u32) << 16, MMC_RSP_R1)?;
        self.send_command(SD_CMD_APP_SET_BUS_WIDTH, 2, MMC_RSP_R1)?; // 2 = 4-bit mode
        self.set_bus_width(4);

        // Switch to default speed (25 MHz)
        self.set_clock(DEFAULT_CLOCK_HZ)?;

        // Try to enable high-speed mode if supported
        if self.capabilities & SDHCI_CAN_DO_HISPD != 0 {
            if self.try_high_speed().is_ok() {
                log::info!("SDHCI: High-speed mode enabled (50 MHz)");
            }
        }

        self.card_initialized = true;
        log::info!(
            "SDHCI: Card initialized: {} blocks x {} bytes = {} MB",
            self.num_blocks,
            self.block_size,
            (self.num_blocks * self.block_size as u64) / (1024 * 1024)
        );

        Ok(())
    }

    /// Parse CSD register to get card capacity
    fn parse_csd(&mut self, csd: &[u32; 4]) {
        // Debug: print raw CSD values
        log::debug!(
            "SDHCI: Raw CSD: [{:08x}, {:08x}, {:08x}, {:08x}]",
            csd[0],
            csd[1],
            csd[2],
            csd[3]
        );

        // SDHCI R2 response format:
        // The 136-bit response is stored in RESPONSE[127:8] (bits 0-7 are CRC, not stored)
        // RESPONSE register 0 contains bits [39:8]
        // RESPONSE register 1 contains bits [71:40]
        // RESPONSE register 2 contains bits [103:72]
        // RESPONSE register 3 contains bits [127:104] (only 24 bits valid)
        //
        // CSD Version 2.0 layout (SDHC/SDXC):
        // [127:126] CSD_STRUCTURE = 01b
        // [69:48] C_SIZE (22 bits) - device size
        //
        // In our response array:
        // csd[3] bits [23:22] = CSD_STRUCTURE (bits 127:126 - 8 = 119:118 shifted)
        // Actually need to recalculate based on SDHCI spec

        // CSD_STRUCTURE is at bits [127:126], stored in response[3] upper bits
        // After removing the 8-bit shift: bits [119:118] in our data
        // csd[3] holds bits [127:104]-8 = [119:96]
        // So CSD_STRUCTURE is at csd[3] bits [23:22]
        let csd_structure = (csd[3] >> 22) & 0x03;

        log::debug!("SDHCI: CSD_STRUCTURE = {}", csd_structure);

        if csd_structure == 0 {
            // CSD Version 1.0 (SDSC)
            let c_size = ((csd[2] & 0x3FF) << 2) | ((csd[1] >> 30) & 0x03);
            let c_size_mult = (csd[1] >> 15) & 0x07;
            let read_bl_len = (csd[2] >> 16) & 0x0F;

            let mult = 1u64 << (c_size_mult + 2);
            let blocknr = (c_size as u64 + 1) * mult;
            let block_len = 1u64 << read_bl_len;

            self.num_blocks = blocknr * block_len / SD_BLOCK_SIZE as u64;
            log::debug!(
                "SDHCI: CSD v1.0: c_size={}, c_size_mult={}, read_bl_len={}",
                c_size,
                c_size_mult,
                read_bl_len
            );
        } else {
            // CSD Version 2.0 (SDHC/SDXC)
            // C_SIZE is at bits [69:48] of CSD
            // After 8-bit shift: bits [61:40] in our response
            // csd[1] holds bits [71:40]-8 = [63:32], so bits [61:40] span csd[1] and csd[0]
            // Actually: response bits [63:32] are in csd[1], bits [31:0] are in csd[0]
            // C_SIZE bits [61:48] are in csd[1] bits [29:16]
            // C_SIZE bits [47:40] are in csd[1] bits [15:8]
            // So full C_SIZE = csd[1] bits [29:8] (22 bits)
            let c_size = (csd[1] >> 8) & 0x3FFFFF;

            log::debug!("SDHCI: CSD v2.0: c_size={} (raw bits)", c_size);

            self.num_blocks = (c_size as u64 + 1) * 1024;
        }

        log::debug!(
            "SDHCI: CSD structure={}, capacity={} blocks ({} MB)",
            csd_structure,
            self.num_blocks,
            (self.num_blocks * 512) / (1024 * 1024)
        );
    }

    /// Try to enable high-speed mode
    fn try_high_speed(&mut self) -> Result<(), SdhciError> {
        // CMD6: SWITCH_FUNC would be used to check/switch high-speed mode
        // Mode 0 = check, function group 1, function 1 = high-speed
        // let _arg = 0x00FFFFF1; // Check high-speed
        // Mode 1 = switch: let _arg = 0x80FFFFF1;
        // We'd need to read the data for proper implementation

        // For now, just set the clock and high-speed bit in the host controller
        // This enables high-speed mode on the controller side

        // Enable high-speed in host control
        let mut ctrl = self.read_reg8(SDHCI_HOST_CONTROL);
        ctrl |= SDHCI_CTRL_HISPD;
        self.write_reg8(SDHCI_HOST_CONTROL, ctrl);

        // Set 50 MHz clock
        self.set_clock(HIGH_SPEED_CLOCK_HZ)?;

        Ok(())
    }

    /// Read sectors from the card using SDMA
    pub fn read_sectors(
        &mut self,
        start_lba: u64,
        count: u32,
        buffer: *mut u8,
    ) -> Result<(), SdhciError> {
        if !self.card_initialized {
            return Err(SdhciError::NotInitialized);
        }

        if count == 0 {
            return Err(SdhciError::InvalidParameter);
        }

        let transfer_size = count as usize * SD_BLOCK_SIZE as usize;

        // For transfers larger than one page, do multiple transfers
        if transfer_size > 4096 {
            let sectors_per_page = 4096 / SD_BLOCK_SIZE as usize;
            let mut remaining = count;
            let mut current_lba = start_lba;
            let mut current_buffer = buffer;

            while remaining > 0 {
                let sectors_this_read = core::cmp::min(remaining, sectors_per_page as u32);
                self.read_sectors_internal(current_lba, sectors_this_read, current_buffer)?;
                remaining -= sectors_this_read;
                current_lba += sectors_this_read as u64;
                current_buffer = unsafe {
                    current_buffer.add(sectors_this_read as usize * SD_BLOCK_SIZE as usize)
                };
            }
            return Ok(());
        }

        self.read_sectors_internal(start_lba, count, buffer)
    }

    /// Internal read sectors using SDMA
    fn read_sectors_internal(
        &mut self,
        start_lba: u64,
        count: u32,
        buffer: *mut u8,
    ) -> Result<(), SdhciError> {
        let transfer_size = count as usize * SD_BLOCK_SIZE as usize;

        // Wait for data inhibit to clear
        self.wait_inhibit(true)?;

        // Clear all pending interrupts
        self.write_reg32(SDHCI_INT_STATUS, SDHCI_INT_ALL_MASK);

        // Set DMA address (use our page-aligned buffer)
        let dma_addr = self.dma_buffer as u64;
        self.write_reg32(SDHCI_DMA_ADDRESS, dma_addr as u32);

        // Set block size with SDMA boundary (512KB)
        self.write_reg16(
            SDHCI_BLOCK_SIZE,
            make_blksz(SDHCI_DEFAULT_BOUNDARY_ARG, SD_BLOCK_SIZE as u16),
        );

        // Set block count
        self.write_reg16(SDHCI_BLOCK_COUNT, count as u16);

        // Set transfer mode (SDMA, read, block count enable)
        let mut mode = SDHCI_TRNS_DMA | SDHCI_TRNS_READ | SDHCI_TRNS_BLK_CNT_EN;
        if count > 1 {
            mode |= SDHCI_TRNS_MULTI | SDHCI_TRNS_ACMD12;
        }
        self.write_reg16(SDHCI_TRANSFER_MODE, mode);

        // Calculate argument (LBA for SDHC, byte address for SDSC)
        let arg = if self.high_capacity {
            start_lba as u32
        } else {
            (start_lba * SD_BLOCK_SIZE as u64) as u32
        };

        // Set argument
        self.write_reg32(SDHCI_ARGUMENT, arg);

        // Send read command
        let cmd = if count > 1 {
            MMC_CMD_READ_MULTIPLE_BLOCK
        } else {
            MMC_CMD_READ_SINGLE_BLOCK
        };

        let flags = SDHCI_CMD_RESP_SHORT | SDHCI_CMD_CRC | SDHCI_CMD_INDEX | SDHCI_CMD_DATA;
        let cmd_reg = make_cmd(cmd, flags);
        self.write_reg16(SDHCI_COMMAND, cmd_reg);

        // Wait for command complete
        let timeout = Timeout::from_ms(CMD_TIMEOUT_MS);
        loop {
            let status = self.read_reg32(SDHCI_INT_STATUS);

            if status & SDHCI_INT_ERROR != 0 {
                log::error!("SDHCI: Read command error: {:#x}", status);
                self.write_reg32(SDHCI_INT_STATUS, status);
                self.reset(SDHCI_RESET_CMD | SDHCI_RESET_DATA)?;
                return Err(SdhciError::GenericError);
            }

            if status & SDHCI_INT_RESPONSE != 0 {
                self.write_reg32(SDHCI_INT_STATUS, SDHCI_INT_RESPONSE);
                break;
            }

            if timeout.is_expired() {
                self.reset(SDHCI_RESET_CMD | SDHCI_RESET_DATA)?;
                return Err(SdhciError::CommandTimeout);
            }

            core::hint::spin_loop();
        }

        // Wait for data transfer complete
        let timeout = Timeout::from_ms(DATA_TIMEOUT_MS);
        loop {
            let status = self.read_reg32(SDHCI_INT_STATUS);

            if status & SDHCI_INT_ERROR != 0 {
                log::error!("SDHCI: Data transfer error: {:#x}", status);
                self.write_reg32(SDHCI_INT_STATUS, status);
                self.reset(SDHCI_RESET_DATA)?;

                if status & SDHCI_INT_DATA_TIMEOUT != 0 {
                    return Err(SdhciError::DataTimeout);
                }
                if status & SDHCI_INT_DATA_CRC != 0 {
                    return Err(SdhciError::DataCrcError);
                }
                if status & SDHCI_INT_DATA_END_BIT != 0 {
                    return Err(SdhciError::DataEndBitError);
                }
                if status & SDHCI_INT_ADMA_ERROR != 0 {
                    return Err(SdhciError::DmaError);
                }
                return Err(SdhciError::GenericError);
            }

            // For SDMA, we need to handle DMA interrupts if transfer crosses boundary
            if status & SDHCI_INT_DMA_END != 0 {
                // Update DMA address for next boundary
                let current_addr = self.read_reg32(SDHCI_DMA_ADDRESS);
                self.write_reg32(SDHCI_DMA_ADDRESS, current_addr);
                self.write_reg32(SDHCI_INT_STATUS, SDHCI_INT_DMA_END);
            }

            if status & SDHCI_INT_DATA_END != 0 {
                self.write_reg32(SDHCI_INT_STATUS, SDHCI_INT_DATA_END);
                break;
            }

            if timeout.is_expired() {
                self.reset(SDHCI_RESET_DATA)?;
                return Err(SdhciError::DataTimeout);
            }

            core::hint::spin_loop();
        }

        // Memory fence to ensure DMA is complete
        fence(Ordering::SeqCst);

        // Copy data from DMA buffer to caller's buffer
        unsafe {
            ptr::copy_nonoverlapping(self.dma_buffer, buffer, transfer_size);
        }

        Ok(())
    }

    /// Read a single sector (convenience method)
    pub fn read_sector(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), SdhciError> {
        if buffer.len() < SD_BLOCK_SIZE as usize {
            return Err(SdhciError::InvalidParameter);
        }

        self.read_sectors(lba, 1, buffer.as_mut_ptr())
    }

    /// Get the number of blocks on the card
    pub fn num_blocks(&self) -> u64 {
        self.num_blocks
    }

    /// Get the block size
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Check if card is present and initialized
    pub fn is_ready(&self) -> bool {
        self.card_present && self.card_initialized
    }

    /// Get the PCI address of this controller
    pub fn pci_address(&self) -> PciAddress {
        self.pci_address
    }

    // ========================================================================
    // Register Access Methods
    // ========================================================================

    fn read_reg32(&self, offset: u16) -> u32 {
        unsafe { ptr::read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    fn write_reg32(&mut self, offset: u16, value: u32) {
        unsafe { ptr::write_volatile((self.mmio_base + offset as u64) as *mut u32, value) }
    }

    fn read_reg16(&self, offset: u16) -> u16 {
        unsafe { ptr::read_volatile((self.mmio_base + offset as u64) as *const u16) }
    }

    fn write_reg16(&mut self, offset: u16, value: u16) {
        unsafe { ptr::write_volatile((self.mmio_base + offset as u64) as *mut u16, value) }
    }

    fn read_reg8(&self, offset: u16) -> u8 {
        unsafe { ptr::read_volatile((self.mmio_base + offset as u64) as *const u8) }
    }

    fn write_reg8(&mut self, offset: u16, value: u8) {
        unsafe { ptr::write_volatile((self.mmio_base + offset as u64) as *mut u8, value) }
    }
}

// ============================================================================
// Global Controller Management
// ============================================================================

/// Wrapper for SDHCI controller pointer to implement Send
struct SdhciControllerPtr(*mut SdhciController);

// Safety: We ensure single-threaded access via the Mutex
unsafe impl Send for SdhciControllerPtr {}

/// Global list of SDHCI controllers
static SDHCI_CONTROLLERS: Mutex<heapless::Vec<SdhciControllerPtr, MAX_SDHCI_CONTROLLERS>> =
    Mutex::new(heapless::Vec::new());

/// Initialize SDHCI controllers
pub fn init() {
    log::info!("Initializing SDHCI controllers...");

    let sdhci_devices = pci::find_sdhci_controllers();

    if sdhci_devices.is_empty() {
        log::info!("No SDHCI controllers found");
        return;
    }

    let mut controllers = SDHCI_CONTROLLERS.lock();

    for dev in sdhci_devices.iter() {
        log::info!(
            "Probing SDHCI controller at {}: {:04x}:{:04x}",
            dev.address,
            dev.vendor_id,
            dev.device_id
        );

        match SdhciController::new(dev) {
            Ok(controller) => {
                // Allocate memory for controller
                let size = core::mem::size_of::<SdhciController>();
                let pages = (size + 4095) / 4096;

                if let Some(ptr) = efi::allocate_pages(pages as u64) {
                    let controller_ptr = ptr as *mut SdhciController;
                    unsafe {
                        ptr::write(controller_ptr, controller);
                    }
                    let _ = controllers.push(SdhciControllerPtr(controller_ptr));
                    log::info!("SDHCI controller at {} initialized", dev.address);
                } else {
                    log::error!("Failed to allocate memory for SDHCI controller");
                }
            }
            Err(e) => {
                log::error!(
                    "Failed to initialize SDHCI controller at {}: {:?}",
                    dev.address,
                    e
                );
            }
        }
    }

    log::info!(
        "SDHCI initialization complete: {} controllers",
        controllers.len()
    );
}

/// Get an SDHCI controller by index
pub fn get_controller(index: usize) -> Option<&'static mut SdhciController> {
    let controllers = SDHCI_CONTROLLERS.lock();
    controllers.get(index).map(|ptr| unsafe { &mut *ptr.0 })
}

/// Get the number of initialized SDHCI controllers
pub fn controller_count() -> usize {
    SDHCI_CONTROLLERS.lock().len()
}

// ============================================================================
// Global Device for SimpleFileSystem Protocol
// ============================================================================

/// Global SDHCI device info for filesystem reads
struct GlobalSdhciDevice {
    controller_index: usize,
}

/// Pointer wrapper for global storage
struct GlobalSdhciDevicePtr(*mut GlobalSdhciDevice);

// Safety: We use mutex protection for all access
unsafe impl Send for GlobalSdhciDevicePtr {}

/// Global SDHCI device for filesystem protocol
static GLOBAL_SDHCI_DEVICE: Mutex<Option<GlobalSdhciDevicePtr>> = Mutex::new(None);

/// Store SDHCI device info globally for SimpleFileSystem protocol
///
/// # Arguments
/// * `controller_index` - Index of the SDHCI controller
///
/// # Returns
/// `true` if the device was stored successfully
pub fn store_global_device(controller_index: usize) -> bool {
    // Allocate memory for the device info
    let size = core::mem::size_of::<GlobalSdhciDevice>();
    let pages = (size + 4095) / 4096;

    if let Some(ptr) = efi::allocate_pages(pages as u64) {
        let device_ptr = ptr as *mut GlobalSdhciDevice;
        unsafe {
            ptr::write(device_ptr, GlobalSdhciDevice { controller_index });
        }

        *GLOBAL_SDHCI_DEVICE.lock() = Some(GlobalSdhciDevicePtr(device_ptr));
        log::info!(
            "SDHCI device stored globally (controller={})",
            controller_index
        );
        true
    } else {
        log::error!("Failed to allocate memory for global SDHCI device");
        false
    }
}

/// Read a sector from the global SDHCI device
///
/// This function is used as the read callback for the SimpleFileSystem protocol.
pub fn global_read_sector(lba: u64, buffer: &mut [u8]) -> Result<(), ()> {
    log::trace!("SDHCI global_read_sector: LBA={}", lba);

    // Get the device info
    let controller_index = match GLOBAL_SDHCI_DEVICE.lock().as_ref() {
        Some(ptr) => unsafe { (*ptr.0).controller_index },
        None => {
            log::error!("global_read_sector: no SDHCI device stored");
            return Err(());
        }
    };

    // Get the controller
    let controller = match get_controller(controller_index) {
        Some(c) => c,
        None => {
            log::error!(
                "global_read_sector: no SDHCI controller at index {}",
                controller_index
            );
            return Err(());
        }
    };

    // Read the sector
    let result = controller.read_sector(lba, buffer);
    if let Err(ref e) = result {
        log::error!("global_read_sector: read failed at LBA {}: {:?}", lba, e);
    }
    result.map_err(|_| ())
}
