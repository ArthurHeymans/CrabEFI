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
use core::sync::atomic::{Ordering, fence};
use spin::Mutex;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

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
    /// Pointer to MMIO registers
    regs: *const SdhciRegisters,
    /// SDHCI specification version
    version: u8,
    /// Maximum base clock frequency (Hz)
    max_clock: u32,
    /// Capabilities register value (cached)
    capabilities: u32,
    /// Capabilities 1 register value (cached)
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

// SAFETY: SdhciController contains raw pointers to MMIO registers and DMA buffer.
// These are:
// 1. MMIO base from PCI BAR that remains valid for the device's lifetime
// 2. DMA buffer allocated via EFI page allocator (persists until shutdown)
// All access is protected by the SDHCI_CONTROLLERS mutex, and the firmware
// is single-threaded with no concurrent SD card operations.
unsafe impl Send for SdhciController {}

impl SdhciController {
    /// Get reference to registers
    #[inline]
    fn regs(&self) -> &SdhciRegisters {
        unsafe { &*self.regs }
    }

    /// Create a new SDHCI controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, SdhciError> {
        let mmio_base = pci_dev.mmio_base().ok_or(SdhciError::NotInitialized)?;
        let regs = mmio_base as *const SdhciRegisters;

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        // Allocate a page-aligned DMA buffer for data transfers
        let dma_buffer = efi::allocate_pages(1).ok_or(SdhciError::AllocationFailed)? as *mut u8;

        let mut controller = Self {
            pci_address: pci_dev.address,
            regs,
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
        // Read version and capabilities - extract values before assigning to self
        let (version, vendor_version, capabilities, capabilities_1, base_clk) = {
            let regs = self.regs();
            let version = regs.host_version.read(HOST_VERSION::SPEC_VERSION) as u8;
            let vendor_version = regs.host_version.read(HOST_VERSION::VENDOR_VERSION);
            let capabilities = regs.capabilities.get();
            let capabilities_1 = regs.capabilities_1.get();
            let base_clk = regs.capabilities.read(CAPABILITIES::BASE_CLK_FREQ);
            (
                version,
                vendor_version,
                capabilities,
                capabilities_1,
                base_clk,
            )
        };

        // Now assign to self
        self.version = version;
        self.capabilities = capabilities;
        self.capabilities_1 = capabilities_1;
        self.max_clock = base_clk * 1_000_000;

        log::info!(
            "SDHCI controller version: {}.0 (vendor: {:#x})",
            self.version + 1,
            vendor_version
        );

        log::debug!("SDHCI capabilities: {:#010x}", self.capabilities);
        log::debug!("SDHCI capabilities_1: {:#010x}", self.capabilities_1);

        log::info!("SDHCI max clock: {} MHz", self.max_clock / 1_000_000);

        // Log capabilities using typed reads
        {
            let regs = self.regs();
            if regs.capabilities.is_set(CAPABILITIES::SUPPORT_SDMA) {
                log::info!("SDHCI: SDMA supported");
            }
            if regs.capabilities.is_set(CAPABILITIES::SUPPORT_ADMA2) {
                log::info!("SDHCI: ADMA2 supported");
            }
            if regs.capabilities.is_set(CAPABILITIES::SUPPORT_HIGHSPEED) {
                log::info!("SDHCI: High-speed supported");
            }
            if regs.capabilities.is_set(CAPABILITIES::SUPPORT_3V3) {
                log::info!("SDHCI: 3.3V supported");
            }
        }

        // Reset the controller
        self.reset_all()?;

        // Set power to 3.3V
        self.set_power_3v3()?;

        // Enable interrupts
        {
            let regs = self.regs();
            let int_mask = INT_STATUS::CMD_COMPLETE::SET
                + INT_STATUS::TRANSFER_COMPLETE::SET
                + INT_STATUS::DMA_INT::SET
                + INT_STATUS::BUFFER_WRITE_READY::SET
                + INT_STATUS::BUFFER_READ_READY::SET
                + INT_STATUS::ERROR::SET
                + INT_STATUS::CMD_TIMEOUT::SET
                + INT_STATUS::CMD_CRC::SET
                + INT_STATUS::CMD_END_BIT::SET
                + INT_STATUS::CMD_INDEX::SET
                + INT_STATUS::DATA_TIMEOUT::SET
                + INT_STATUS::DATA_CRC::SET
                + INT_STATUS::DATA_END_BIT::SET
                + INT_STATUS::ADMA::SET;

            regs.int_enable.write(int_mask);
            regs.signal_enable.set(0); // Polling mode, no signal interrupts
        }

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

    /// Reset the controller (all)
    fn reset_all(&mut self) -> Result<(), SdhciError> {
        let regs = self.regs();
        regs.software_reset.write(SOFTWARE_RESET::RESET_ALL::SET);

        // Wait for reset to complete (up to 100ms)
        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if !regs.software_reset.is_set(SOFTWARE_RESET::RESET_ALL) {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        log::error!("SDHCI: Reset timeout");
        Err(SdhciError::ResetFailed)
    }

    /// Reset command line
    fn reset_cmd(&mut self) -> Result<(), SdhciError> {
        let regs = self.regs();
        regs.software_reset.write(SOFTWARE_RESET::RESET_CMD::SET);

        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if !regs.software_reset.is_set(SOFTWARE_RESET::RESET_CMD) {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(SdhciError::ResetFailed)
    }

    /// Reset data line
    fn reset_data(&mut self) -> Result<(), SdhciError> {
        let regs = self.regs();
        regs.software_reset.write(SOFTWARE_RESET::RESET_DATA::SET);

        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if !regs.software_reset.is_set(SOFTWARE_RESET::RESET_DATA) {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(SdhciError::ResetFailed)
    }

    /// Set bus power to 3.3V
    fn set_power_3v3(&mut self) -> Result<(), SdhciError> {
        let regs = self.regs();

        // Turn off power first
        regs.power_control.set(0);

        // Small delay
        for _ in 0..1000 {
            core::hint::spin_loop();
        }

        // Turn on power with 3.3V
        regs.power_control
            .write(POWER_CONTROL::BUS_POWER::SET + POWER_CONTROL::BUS_VOLTAGE::V3_3);

        // Wait for power to stabilize
        let timeout = Timeout::from_ms(50);
        while !timeout.is_expired() {
            core::hint::spin_loop();
        }

        Ok(())
    }

    /// Set the SD clock frequency
    fn set_clock(&mut self, clock: u32) -> Result<(), SdhciError> {
        let regs = self.regs();

        // Disable clock
        regs.clock_control.set(0);

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
        let div_lo = (divider & 0xFF) >> 1;
        let div_hi = ((divider >> 8) & 0x03) as u8;

        regs.clock_control.write(
            CLOCK_CONTROL::FREQ_SELECT.val(div_lo)
                + CLOCK_CONTROL::FREQ_SELECT_HI.val(div_hi as u16)
                + CLOCK_CONTROL::INTERNAL_CLK_EN::SET,
        );

        // Wait for internal clock stable
        let timeout = Timeout::from_ms(20);
        while !timeout.is_expired() {
            if regs
                .clock_control
                .is_set(CLOCK_CONTROL::INTERNAL_CLK_STABLE)
            {
                break;
            }
            core::hint::spin_loop();
        }

        if !regs
            .clock_control
            .is_set(CLOCK_CONTROL::INTERNAL_CLK_STABLE)
        {
            log::error!("SDHCI: Internal clock not stable");
            return Err(SdhciError::ClockFailed);
        }

        // Enable card clock
        regs.clock_control.modify(CLOCK_CONTROL::SD_CLK_EN::SET);

        Ok(())
    }

    /// Set bus width
    fn set_bus_width(&mut self, width: u8) {
        let regs = self.regs();

        match width {
            4 => {
                regs.host_control.modify(
                    HOST_CONTROL::DATA_WIDTH_4BIT::SET + HOST_CONTROL::DATA_WIDTH_8BIT::CLEAR,
                );
            }
            8 => {
                regs.host_control.modify(
                    HOST_CONTROL::DATA_WIDTH_4BIT::CLEAR + HOST_CONTROL::DATA_WIDTH_8BIT::SET,
                );
            }
            _ => {
                // 1-bit mode
                regs.host_control.modify(
                    HOST_CONTROL::DATA_WIDTH_4BIT::CLEAR + HOST_CONTROL::DATA_WIDTH_8BIT::CLEAR,
                );
            }
        }
    }

    /// Detect if a card is present
    fn detect_card(&self) -> bool {
        let regs = self.regs();
        regs.present_state.is_set(PRESENT_STATE::CARD_INSERTED)
            && regs.present_state.is_set(PRESENT_STATE::CARD_STABLE)
    }

    /// Wait for command/data inhibit to clear
    fn wait_inhibit(&self, data: bool) -> Result<(), SdhciError> {
        let regs = self.regs();

        let timeout = Timeout::from_ms(CMD_TIMEOUT_MS);
        while !timeout.is_expired() {
            let cmd_inhibit = regs.present_state.is_set(PRESENT_STATE::CMD_INHIBIT);
            let dat_inhibit = data && regs.present_state.is_set(PRESENT_STATE::DAT_INHIBIT);

            if !cmd_inhibit && !dat_inhibit {
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
        let regs = self.regs();

        // Wait for command inhibit to clear
        self.wait_inhibit(has_data)?;

        // Clear all pending interrupts
        regs.int_status.set(0xFFFFFFFF);

        // Set argument
        regs.argument.set(arg);

        // Build command register value
        let mut cmd_val = COMMAND::CMD_INDEX.val(cmd as u16);

        match resp_type {
            MMC_RSP_NONE => {
                cmd_val += COMMAND::RESPONSE_TYPE::None;
            }
            MMC_RSP_R1 | MMC_RSP_R6 | MMC_RSP_R7 => {
                cmd_val = cmd_val
                    + COMMAND::RESPONSE_TYPE::Short48
                    + COMMAND::CRC_CHECK::SET
                    + COMMAND::INDEX_CHECK::SET;
            }
            MMC_RSP_R1B => {
                cmd_val = cmd_val
                    + COMMAND::RESPONSE_TYPE::Short48Busy
                    + COMMAND::CRC_CHECK::SET
                    + COMMAND::INDEX_CHECK::SET;
            }
            MMC_RSP_R2 => {
                cmd_val = cmd_val + COMMAND::RESPONSE_TYPE::Long136 + COMMAND::CRC_CHECK::SET;
            }
            MMC_RSP_R3 => {
                cmd_val += COMMAND::RESPONSE_TYPE::Short48;
            }
            _ => {
                cmd_val += COMMAND::RESPONSE_TYPE::Short48;
            }
        }

        if has_data {
            cmd_val += COMMAND::DATA_PRESENT::SET;
        }

        // Send command
        regs.command.write(cmd_val);

        // Wait for command complete
        let timeout = Timeout::from_ms(CMD_TIMEOUT_MS);

        loop {
            let status = regs.int_status.get();

            // Check for errors
            if regs.int_status.is_set(INT_STATUS::ERROR) {
                // Clear status
                regs.int_status.set(status);

                if regs.int_status.is_set(INT_STATUS::CMD_TIMEOUT) {
                    log::debug!("SDHCI: CMD{} timeout", cmd);
                    let _ = self.reset_cmd();
                    return Err(SdhciError::CommandTimeout);
                }
                if regs.int_status.is_set(INT_STATUS::CMD_CRC) {
                    log::debug!("SDHCI: CMD{} CRC error", cmd);
                    let _ = self.reset_cmd();
                    return Err(SdhciError::CommandCrcError);
                }
                if regs.int_status.is_set(INT_STATUS::CMD_INDEX) {
                    log::debug!("SDHCI: CMD{} index error", cmd);
                    let _ = self.reset_cmd();
                    return Err(SdhciError::CommandIndexError);
                }
                if regs.int_status.is_set(INT_STATUS::CMD_END_BIT) {
                    log::debug!("SDHCI: CMD{} end bit error", cmd);
                    let _ = self.reset_cmd();
                    return Err(SdhciError::CommandEndBitError);
                }

                log::debug!("SDHCI: CMD{} unknown error: {:#x}", cmd, status);
                let _ = self.reset_cmd();
                return Err(SdhciError::GenericError);
            }

            // Check for command complete
            if regs.int_status.is_set(INT_STATUS::CMD_COMPLETE) {
                break;
            }

            if timeout.is_expired() {
                let _ = self.reset_cmd();
                return Err(SdhciError::CommandTimeout);
            }

            core::hint::spin_loop();
        }

        // Clear command complete status
        regs.int_status.write(INT_STATUS::CMD_COMPLETE::SET);

        // Read response
        let response = [
            regs.response0.get(),
            regs.response1.get(),
            regs.response2.get(),
            regs.response3.get(),
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
        if self
            .regs()
            .capabilities
            .is_set(CAPABILITIES::SUPPORT_HIGHSPEED)
            && self.try_high_speed().is_ok()
        {
            log::info!("SDHCI: High-speed mode enabled (50 MHz)");
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
        log::debug!(
            "SDHCI: Raw CSD: [{:08x}, {:08x}, {:08x}, {:08x}]",
            csd[0],
            csd[1],
            csd[2],
            csd[3]
        );

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
        let regs = self.regs();

        // Enable high-speed in host control
        regs.host_control.modify(HOST_CONTROL::HIGH_SPEED::SET);

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

        // Setup DMA and send command (in a separate scope to release borrow)
        {
            let regs = self.regs();

            // Clear all pending interrupts
            regs.int_status.set(0xFFFFFFFF);

            // Set DMA address (use our page-aligned buffer)
            let dma_addr = self.dma_buffer as u32;
            regs.sdma_addr.set(dma_addr);

            // Set block size with SDMA boundary (512KB)
            regs.block_size.write(
                BLOCK_SIZE::BLOCK_SIZE.val(SD_BLOCK_SIZE as u16)
                    + BLOCK_SIZE::SDMA_BOUNDARY.val(SDHCI_DEFAULT_BOUNDARY_ARG),
            );

            // Set block count
            regs.block_count.set(count as u16);

            // Set transfer mode (SDMA, read, block count enable)
            let mut mode = TRANSFER_MODE::DMA_ENABLE::SET
                + TRANSFER_MODE::DATA_DIRECTION::SET
                + TRANSFER_MODE::BLOCK_COUNT_ENABLE::SET;

            if count > 1 {
                mode = mode + TRANSFER_MODE::MULTI_BLOCK::SET + TRANSFER_MODE::AUTO_CMD12::SET;
            }
            regs.transfer_mode.write(mode);

            // Calculate argument (LBA for SDHC, byte address for SDSC)
            let arg = if self.high_capacity {
                start_lba as u32
            } else {
                (start_lba * SD_BLOCK_SIZE as u64) as u32
            };

            // Set argument
            regs.argument.set(arg);

            // Send read command
            let cmd = if count > 1 {
                MMC_CMD_READ_MULTIPLE_BLOCK
            } else {
                MMC_CMD_READ_SINGLE_BLOCK
            };

            let cmd_val = COMMAND::CMD_INDEX.val(cmd as u16)
                + COMMAND::RESPONSE_TYPE::Short48
                + COMMAND::CRC_CHECK::SET
                + COMMAND::INDEX_CHECK::SET
                + COMMAND::DATA_PRESENT::SET;

            regs.command.write(cmd_val);
        }

        // Wait for command complete
        let timeout = Timeout::from_ms(CMD_TIMEOUT_MS);
        loop {
            // Check for errors or completion in a scoped borrow
            let (has_error, error_status, is_complete, is_timeout) = {
                let regs = self.regs();
                let has_error = regs.int_status.is_set(INT_STATUS::ERROR);
                let error_status = if has_error { regs.int_status.get() } else { 0 };
                let is_complete = regs.int_status.is_set(INT_STATUS::CMD_COMPLETE);

                if has_error {
                    regs.int_status.set(error_status);
                }
                if is_complete {
                    regs.int_status.write(INT_STATUS::CMD_COMPLETE::SET);
                }

                (has_error, error_status, is_complete, timeout.is_expired())
            };

            if has_error {
                log::error!("SDHCI: Read command error: {:#x}", error_status);
                let _ = self.reset_cmd();
                let _ = self.reset_data();
                return Err(SdhciError::GenericError);
            }

            if is_complete {
                break;
            }

            if is_timeout {
                let _ = self.reset_cmd();
                let _ = self.reset_data();
                return Err(SdhciError::CommandTimeout);
            }

            core::hint::spin_loop();
        }

        // Wait for data transfer complete
        let timeout = Timeout::from_ms(DATA_TIMEOUT_MS);
        loop {
            // Check status in a scoped borrow
            enum DataResult {
                Continue,
                Complete,
                Error {
                    status: u32,
                    is_timeout: bool,
                    is_crc: bool,
                    is_end_bit: bool,
                    is_adma: bool,
                },
                Timeout,
            }

            let result = {
                let regs = self.regs();
                let status = regs.int_status.get();

                if regs.int_status.is_set(INT_STATUS::ERROR) {
                    regs.int_status.set(status);
                    DataResult::Error {
                        status,
                        is_timeout: regs.int_status.is_set(INT_STATUS::DATA_TIMEOUT),
                        is_crc: regs.int_status.is_set(INT_STATUS::DATA_CRC),
                        is_end_bit: regs.int_status.is_set(INT_STATUS::DATA_END_BIT),
                        is_adma: regs.int_status.is_set(INT_STATUS::ADMA),
                    }
                } else if regs.int_status.is_set(INT_STATUS::DMA_INT) {
                    // For SDMA, handle DMA interrupts if transfer crosses boundary
                    let current_addr = regs.sdma_addr.get();
                    regs.sdma_addr.set(current_addr);
                    regs.int_status.write(INT_STATUS::DMA_INT::SET);
                    DataResult::Continue
                } else if regs.int_status.is_set(INT_STATUS::TRANSFER_COMPLETE) {
                    regs.int_status.write(INT_STATUS::TRANSFER_COMPLETE::SET);
                    DataResult::Complete
                } else if timeout.is_expired() {
                    DataResult::Timeout
                } else {
                    DataResult::Continue
                }
            };

            match result {
                DataResult::Continue => {
                    core::hint::spin_loop();
                }
                DataResult::Complete => break,
                DataResult::Error {
                    status,
                    is_timeout,
                    is_crc,
                    is_end_bit,
                    is_adma,
                } => {
                    log::error!("SDHCI: Data transfer error: {:#x}", status);
                    let _ = self.reset_data();

                    if is_timeout {
                        return Err(SdhciError::DataTimeout);
                    }
                    if is_crc {
                        return Err(SdhciError::DataCrcError);
                    }
                    if is_end_bit {
                        return Err(SdhciError::DataEndBitError);
                    }
                    if is_adma {
                        return Err(SdhciError::DmaError);
                    }
                    return Err(SdhciError::GenericError);
                }
                DataResult::Timeout => {
                    let _ = self.reset_data();
                    return Err(SdhciError::DataTimeout);
                }
            }
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
}

// ============================================================================
// Global Controller Management
// ============================================================================

/// Wrapper for SDHCI controller pointer to implement Send
struct SdhciControllerPtr(*mut SdhciController);

// SAFETY: SdhciControllerPtr wraps a pointer to an SdhciController allocated via the EFI
// page allocator. The pointer remains valid for the firmware's lifetime and all access
// is protected by the SDHCI_CONTROLLERS mutex. The firmware runs single-threaded with
// no concurrent SD card operations.
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
                let pages = size.div_ceil(4096);

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

// SAFETY: GlobalSdhciDevicePtr wraps a pointer to GlobalSdhciDevice allocated via EFI.
// All access is protected by the GLOBAL_SDHCI_DEVICE mutex, ensuring no concurrent
// access. The pointed-to data contains only the controller index (not raw pointers
// to hardware), and the firmware runs single-threaded.
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
    let pages = size.div_ceil(4096);

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
