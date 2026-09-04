//! SDHCI (SD Host Controller Interface) Driver
//!
//! This module provides a driver for SD/MMC cards connected via standard SDHCI
//! controllers. It supports PCI-based SDHCI controllers and implements the
//! SD card protocol for reading sectors.

mod logic;
pub mod regs;

use crate::barrier;
use crate::drivers::pci::{self, PciAddress, PciDevice};
use crate::efi::dma::{DmaBuffer, DmaCoherency, DmaDirection, DmaMask};
use crate::time::{Timeout, wait_for};
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

/// SDHCI controller origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdhciIdentity {
    /// PCI SDHCI controller.
    Pci(PciAddress),
    /// ACPI-described MMIO SDHCI controller.
    Acpi {
        /// ACPI namespace name.
        name: [u8; 4],
        /// ACPI hardware ID.
        hid: [u8; 16],
        /// Hardware ID length.
        hid_len: u8,
        /// MMIO base from `_CRS`.
        mmio_base: u64,
    },
}

/// Card protocol attached to an SDHCI controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdhciMedia {
    /// Removable SD card.
    Sd,
    /// Non-removable eMMC device.
    Emmc,
}

/// SDHCI error type
#[derive(Debug, Clone, Copy)]
pub enum SdhciError {
    /// Controller not found or not initialized
    NotInitialized,
    /// Reset failed
    ResetFailed,
    /// Recovery failed after a timing-mode transition error.
    RecoveryFailed,
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
    /// Feature not supported by the card
    NotSupported,
    /// Generic error
    GenericError,
}

/// SDHCI Controller
pub struct SdhciController {
    /// Controller origin.
    identity: SdhciIdentity,
    /// Card protocol.
    media: SdhciMedia,
    /// Whether media should be reported as removable.
    removable: bool,
    /// Whether to trust SDHCI card-detect status.
    use_card_detect: bool,
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
    /// OCR voltage mask matching the selected bus voltage.
    ocr_voltage: u32,
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
    /// Exclusively owned SDMA bounce buffer.
    dma_buffer: DmaBuffer,
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

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        Self::new_mmio(
            mmio_base,
            SdhciIdentity::Pci(pci_dev.address),
            SdhciMedia::Sd,
            true,
            true,
        )
    }

    /// Create a new SDHCI controller from an MMIO base address.
    pub fn new_mmio(
        mmio_base: u64,
        identity: SdhciIdentity,
        media: SdhciMedia,
        removable: bool,
        use_card_detect: bool,
    ) -> Result<Self, SdhciError> {
        if mmio_base == 0 {
            return Err(SdhciError::NotInitialized);
        }

        let regs = mmio_base as *const SdhciRegisters;

        // SDMA is 32-bit, so the bounce buffer must be below 4 GiB.
        let dma_buffer = DmaBuffer::allocate(4096, DmaMask::bits32(), DmaCoherency::NonCoherent)
            .map_err(|_| SdhciError::AllocationFailed)?;

        let mut controller = Self {
            identity,
            media,
            removable,
            use_card_detect,
            regs,
            version: 0,
            max_clock: 0,
            capabilities: 0,
            capabilities_1: 0,
            ocr_voltage: 0,
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

        // Select a bus voltage supported by the controller.
        self.set_power()?;

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

        // Check for card presence. Non-removable eMMC often does not wire
        // SDHCI card-detect, so ACPI-described eMMC skips it.
        self.card_present = !self.use_card_detect || self.detect_card();

        if self.card_present {
            log::info!("SDHCI: Card detected ({:?})", self.media);
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
        if !wait_for(100, || {
            !regs.software_reset.is_set(SOFTWARE_RESET::RESET_ALL)
        }) {
            log::error!("SDHCI: Reset timeout");
            return Err(SdhciError::ResetFailed);
        }
        Ok(())
    }

    /// Reset command line
    fn reset_cmd(&mut self) -> Result<(), SdhciError> {
        let regs = self.regs();
        regs.software_reset.write(SOFTWARE_RESET::RESET_CMD::SET);

        if !wait_for(100, || {
            !regs.software_reset.is_set(SOFTWARE_RESET::RESET_CMD)
        }) {
            return Err(SdhciError::ResetFailed);
        }
        Ok(())
    }

    /// Reset data line
    fn reset_data(&mut self) -> Result<(), SdhciError> {
        let regs = self.regs();
        regs.software_reset.write(SOFTWARE_RESET::RESET_DATA::SET);

        if !wait_for(100, || {
            !regs.software_reset.is_set(SOFTWARE_RESET::RESET_DATA)
        }) {
            return Err(SdhciError::ResetFailed);
        }
        Ok(())
    }

    /// Set bus power to a voltage supported by the controller.
    fn set_power(&mut self) -> Result<(), SdhciError> {
        let (voltage, ocr_voltage) = {
            let regs = self.regs();
            if regs.capabilities.is_set(CAPABILITIES::SUPPORT_3V3) {
                (POWER_CONTROL::BUS_VOLTAGE::V3_3, OCR_VDD_3V3)
            } else if regs.capabilities.is_set(CAPABILITIES::SUPPORT_3V0) {
                (POWER_CONTROL::BUS_VOLTAGE::V3_0, OCR_VDD_3V0)
            } else if regs.capabilities.is_set(CAPABILITIES::SUPPORT_1V8) {
                (POWER_CONTROL::BUS_VOLTAGE::V1_8, OCR_VDD_1V8)
            } else {
                log::error!("SDHCI: controller advertises no supported bus voltage");
                return Err(SdhciError::NotSupported);
            }
        };
        self.ocr_voltage = ocr_voltage;

        let regs = self.regs();
        regs.power_control.set(0);
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
        regs.power_control
            .write(POWER_CONTROL::BUS_POWER::SET + voltage);

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
        if !wait_for(20, || {
            regs.clock_control
                .is_set(CLOCK_CONTROL::INTERNAL_CLK_STABLE)
        }) {
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

        if !wait_for(CMD_TIMEOUT_MS, || {
            let cmd_inhibit = regs.present_state.is_set(PRESENT_STATE::CMD_INHIBIT);
            let dat_inhibit = data && regs.present_state.is_set(PRESENT_STATE::DAT_INHIBIT);
            !cmd_inhibit && !dat_inhibit
        }) {
            return Err(SdhciError::CommandTimeout);
        }
        Ok(())
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

            // Check for errors -- must check saved status BEFORE clearing,
            // because the interrupt status register is write-1-to-clear
            if status & INT_STATUS::ERROR::SET.value != 0 {
                // Clear status after saving it
                regs.int_status.set(status);

                if status & INT_STATUS::CMD_TIMEOUT::SET.value != 0 {
                    log::debug!("SDHCI: CMD{} timeout", cmd);
                    let _ = self.reset_cmd();
                    return Err(SdhciError::CommandTimeout);
                }
                if status & INT_STATUS::CMD_CRC::SET.value != 0 {
                    log::debug!("SDHCI: CMD{} CRC error", cmd);
                    let _ = self.reset_cmd();
                    return Err(SdhciError::CommandCrcError);
                }
                if status & INT_STATUS::CMD_INDEX::SET.value != 0 {
                    log::debug!("SDHCI: CMD{} index error", cmd);
                    let _ = self.reset_cmd();
                    return Err(SdhciError::CommandIndexError);
                }
                if status & INT_STATUS::CMD_END_BIT::SET.value != 0 {
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

        // SDHCI strips the CRC/end bit from 136-bit responses and shifts the
        // payload across its response registers. Normalize R2 once so every
        // CSD/CID consumer uses canonical bits 127:0 in MSW-first order.
        let raw_response = [
            regs.response0.get(),
            regs.response1.get(),
            regs.response2.get(),
            regs.response3.get(),
        ];
        Ok(if resp_type == MMC_RSP_R2 {
            logic::normalize_r2(raw_response)
        } else {
            raw_response
        })
    }

    /// Initialize the SD card
    fn init_card(&mut self) -> Result<(), SdhciError> {
        match self.media {
            SdhciMedia::Sd => self.init_sd_card(),
            SdhciMedia::Emmc => self.init_emmc(),
        }
    }

    /// Initialize an SD card
    fn init_sd_card(&mut self) -> Result<(), SdhciError> {
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
            OCR_HCS | self.ocr_voltage
        } else {
            self.ocr_voltage
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
            cid[0],
            cid[1],
            cid[2],
            cid[3]
        );

        // CMD3: SEND_RELATIVE_ADDR (get RCA)
        log::debug!("SDHCI: Sending CMD3 (SEND_RELATIVE_ADDR)");
        let resp = self.send_command(SD_CMD_SEND_RELATIVE_ADDR, 0, MMC_RSP_R6)?;
        self.rca = (resp[0] >> 16) as u16;
        log::debug!("SDHCI: RCA={:#06x}", self.rca);

        // CMD9: SEND_CSD (get card specific data)
        log::debug!("SDHCI: Sending CMD9 (SEND_CSD)");
        let csd = self.send_command(MMC_CMD_SEND_CSD, (self.rca as u32) << 16, MMC_RSP_R2)?;
        self.parse_csd(&csd)?;

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

        // Try to enable high-speed mode if supported. Unsupported cards can
        // continue at default speed, but a failed timing rollback is fatal.
        if self
            .regs()
            .capabilities
            .is_set(CAPABILITIES::SUPPORT_HIGHSPEED)
        {
            match self.try_high_speed() {
                Ok(()) => log::info!("SDHCI: High-speed mode enabled (50 MHz)"),
                Err(SdhciError::NotSupported) => {}
                Err(error) => return Err(error),
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

    /// Initialize a non-removable eMMC device.
    fn init_emmc(&mut self) -> Result<(), SdhciError> {
        const EMMC_RCA: u16 = 1;
        const EXT_CSD_SEC_COUNT: usize = 212;

        self.set_clock(INIT_CLOCK_HZ)?;
        self.set_bus_width(1);

        let timeout = Timeout::from_ms(10);
        while !timeout.is_expired() {
            core::hint::spin_loop();
        }

        log::debug!("SDHCI: eMMC CMD0 (GO_IDLE_STATE)");
        let _ = self.send_command(MMC_CMD_GO_IDLE_STATE, 0, MMC_RSP_NONE);

        log::debug!("SDHCI: eMMC CMD1 (SEND_OP_COND)");
        let timeout = Timeout::from_ms(1000);
        let mut ocr = 0u32;
        let ocr_arg = OCR_HCS | self.ocr_voltage;
        while !timeout.is_expired() {
            if let Ok(resp) = self.send_command(MMC_CMD_SEND_OP_COND, ocr_arg, MMC_RSP_R3) {
                ocr = resp[0];
                if ocr & OCR_BUSY != 0 {
                    break;
                }
            }
            for _ in 0..10000 {
                core::hint::spin_loop();
            }
        }

        if ocr & OCR_BUSY == 0 {
            log::error!("SDHCI: eMMC initialization timeout");
            return Err(SdhciError::CardInitFailed);
        }

        self.high_capacity = (ocr & OCR_HCS) != 0;
        log::debug!("SDHCI: eMMC OCR={:#010x}", ocr);

        log::debug!("SDHCI: eMMC CMD2 (ALL_SEND_CID)");
        let cid = self.send_command(MMC_CMD_ALL_SEND_CID, 0, MMC_RSP_R2)?;
        log::debug!(
            "SDHCI: eMMC CID: {:08x} {:08x} {:08x} {:08x}",
            cid[0],
            cid[1],
            cid[2],
            cid[3]
        );

        self.rca = EMMC_RCA;
        log::debug!("SDHCI: eMMC CMD3 (SET_RELATIVE_ADDR)");
        self.send_command(
            MMC_CMD_SET_RELATIVE_ADDR,
            (self.rca as u32) << 16,
            MMC_RSP_R1,
        )?;

        log::debug!("SDHCI: eMMC CMD9 (SEND_CSD)");
        let csd = self.send_command(MMC_CMD_SEND_CSD, (self.rca as u32) << 16, MMC_RSP_R2)?;
        self.parse_csd(&csd)?;

        log::debug!("SDHCI: eMMC CMD7 (SELECT_CARD)");
        self.send_command(MMC_CMD_SELECT_CARD, (self.rca as u32) << 16, MMC_RSP_R1B)?;

        log::debug!("SDHCI: eMMC CMD16 (SET_BLOCKLEN)");
        self.send_command(MMC_CMD_SET_BLOCKLEN, SD_BLOCK_SIZE, MMC_RSP_R1)?;

        match self.read_data_command(MMC_CMD_SEND_EXT_CSD, 0, 512) {
            Ok(()) => {
                barrier::dma_read();
                let ext_csd = &self.dma_buffer.as_slice()[..512];
                let sec_count = u32::from_le_bytes([
                    ext_csd[EXT_CSD_SEC_COUNT],
                    ext_csd[EXT_CSD_SEC_COUNT + 1],
                    ext_csd[EXT_CSD_SEC_COUNT + 2],
                    ext_csd[EXT_CSD_SEC_COUNT + 3],
                ]);
                if sec_count != 0 {
                    self.num_blocks = sec_count as u64;
                    self.high_capacity = true;
                } else if self.high_capacity {
                    log::error!("SDHCI: high-capacity eMMC reported zero EXT_CSD sector count");
                    return Err(SdhciError::CardInitFailed);
                }
            }
            Err(e) if self.high_capacity => {
                log::error!("SDHCI: failed to read high-capacity eMMC EXT_CSD: {:?}", e);
                return Err(e);
            }
            Err(e) => log::warn!("SDHCI: failed to read legacy eMMC EXT_CSD: {:?}", e),
        }

        if self.num_blocks == 0 {
            log::error!("SDHCI: eMMC capacity is zero");
            return Err(SdhciError::CardInitFailed);
        }

        self.set_clock(DEFAULT_CLOCK_HZ)?;

        self.card_initialized = true;
        log::info!(
            "SDHCI: eMMC initialized: {} blocks x {} bytes = {} MB",
            self.num_blocks,
            self.block_size,
            (self.num_blocks * self.block_size as u64) / (1024 * 1024)
        );

        Ok(())
    }

    /// Parse CSD register to get card capacity
    fn parse_csd(&mut self, csd: &[u32; 4]) -> Result<(), SdhciError> {
        log::debug!(
            "SDHCI: Canonical CSD: [{:08x}, {:08x}, {:08x}, {:08x}]",
            csd[0],
            csd[1],
            csd[2],
            csd[3]
        );

        let blocks = match self.media {
            SdhciMedia::Sd => logic::parse_sd_csd(csd),
            SdhciMedia::Emmc => logic::parse_mmc_csd(csd),
        }
        .filter(|blocks| *blocks != 0)
        .ok_or(SdhciError::CardInitFailed)?;
        self.num_blocks = blocks;

        log::debug!(
            "SDHCI: CSD capacity={} blocks ({} MB)",
            self.num_blocks,
            self.num_blocks.saturating_mul(512) / (1024 * 1024)
        );
        Ok(())
    }

    /// Try to enable high-speed mode by negotiating with the card via CMD6
    ///
    /// Per SD specification, the host must:
    /// 1. Send CMD6 in check mode to verify the card supports high-speed
    /// 2. Send CMD6 in switch mode to actually switch
    /// 3. Only then enable high-speed on the host controller
    fn try_high_speed(&mut self) -> Result<(), SdhciError> {
        // CMD6 argument: [31] Mode (0=check, 1=switch), [3:0] Access Mode (1=high-speed)
        const CMD6_CHECK_HIGH_SPEED: u32 = 0x00FF_FFF1; // Check mode, function group 1 = HS
        const CMD6_SWITCH_DEFAULT_SPEED: u32 = 0x80FF_FFF0;
        const CMD6_SWITCH_HIGH_SPEED: u32 = 0x80FF_FFF1; // Switch mode, function group 1 = HS

        // CMD6 returns 64 bytes (512 bits) of status data. We use the DMA
        // buffer to receive it. Check mode first to see if the card supports
        // high-speed.
        let status = self.cmd6_transfer(CMD6_CHECK_HIGH_SPEED)?;

        // In check mode byte 13 is the function-group-1 support bitmap.
        if !logic::cmd6_supports_high_speed(&status) {
            log::debug!("SDHCI: Card does not advertise high-speed support");
            return Err(SdhciError::NotSupported);
        }

        // Now send CMD6 in switch mode to actually enable high-speed on the card
        let status = self.cmd6_transfer(CMD6_SWITCH_HIGH_SPEED)?;

        // In switch mode byte 16 reports the selected group-1 function.
        let selected_function = logic::cmd6_selected_function(&status);
        if selected_function != 1 {
            log::warn!(
                "SDHCI: High-speed switch failed (function={})",
                selected_function
            );
            return Err(SdhciError::GenericError);
        }

        // Card is now in high-speed mode — enable it on the host controller
        let regs = self.regs();
        regs.host_control.modify(HOST_CONTROL::HIGH_SPEED::SET);

        // Set 50 MHz clock. If the host cannot establish it, restore both the
        // card and host to default-speed timing before reporting the optional
        // high-speed negotiation as unsupported.
        if let Err(error) = self.set_clock(HIGH_SPEED_CLOCK_HZ) {
            let clock_restored = self.set_clock(DEFAULT_CLOCK_HZ).is_ok();
            let card_restored = clock_restored
                && self
                    .cmd6_transfer(CMD6_SWITCH_DEFAULT_SPEED)
                    .is_ok_and(|status| logic::cmd6_selected_function(&status) == 0);
            if clock_restored && card_restored {
                self.regs()
                    .host_control
                    .modify(HOST_CONTROL::HIGH_SPEED::CLEAR);
                log::warn!("SDHCI: High-speed clock failed; restored default-speed mode");
                return Err(SdhciError::NotSupported);
            }
            log::error!(
                "SDHCI: Failed to restore default-speed mode after: {:?}",
                error
            );
            // The card timing mode is now unknown. Stop its clock and reset the
            // host before propagating a fatal initialization failure.
            let clock_stopped = self.set_clock(0).is_ok();
            let host_reset = self.reset_all().is_ok();
            self.card_initialized = false;
            self.regs()
                .host_control
                .modify(HOST_CONTROL::HIGH_SPEED::CLEAR);
            return if clock_stopped && host_reset {
                Err(error)
            } else {
                Err(SdhciError::RecoveryFailed)
            };
        }

        Ok(())
    }

    /// Send CMD6 (SWITCH_FUNC) and receive 64 bytes of status data via SDMA
    fn cmd6_transfer(&mut self, arg: u32) -> Result<[u8; 64], SdhciError> {
        self.read_data_command(SD_CMD_SWITCH_FUNC, arg, 64)?;
        self.dma_buffer.as_slice()[..64]
            .try_into()
            .map_err(|_| SdhciError::DmaError)
    }

    /// Send a single-block read-data command into the DMA buffer.
    fn read_data_command(&mut self, cmd: u8, arg: u32, block_size: u16) -> Result<(), SdhciError> {
        self.wait_inhibit(true)?;

        {
            let regs = self.regs();

            regs.int_status.set(0xFFFFFFFF);

            // SDMA address — use existing page-aligned DMA buffer
            let dma_addr = self.dma_buffer.dma_address();
            self.dma_buffer
                .sync_for_device(0..self.dma_buffer.len(), DmaDirection::FromDevice)
                .map_err(|_| SdhciError::DmaError)?;
            regs.sdma_addr.set(dma_addr as u32);

            regs.block_size
                .write(BLOCK_SIZE::BLOCK_SIZE.val(block_size) + BLOCK_SIZE::SDMA_BOUNDARY.val(0));
            regs.block_count.set(1);

            // Transfer mode: DMA, read, single block
            regs.transfer_mode.write(
                TRANSFER_MODE::DMA_ENABLE::SET
                    + TRANSFER_MODE::DATA_DIRECTION::SET
                    + TRANSFER_MODE::BLOCK_COUNT_ENABLE::SET,
            );

            regs.argument.set(arg);

            let cmd_val = COMMAND::CMD_INDEX.val(cmd as u16)
                + COMMAND::RESPONSE_TYPE::Short48
                + COMMAND::CRC_CHECK::SET
                + COMMAND::INDEX_CHECK::SET
                + COMMAND::DATA_PRESENT::SET;

            regs.command.write(cmd_val);
        }

        // Wait for transfer complete
        let timeout = Timeout::from_ms(CMD_TIMEOUT_MS);
        loop {
            let regs = self.regs();
            let status = regs.int_status.get();

            if status & INT_STATUS::ERROR::SET.value != 0 {
                regs.int_status.set(status);
                let _ = self.reset_cmd();
                let _ = self.reset_data();
                return Err(SdhciError::GenericError);
            }

            if status & INT_STATUS::TRANSFER_COMPLETE::SET.value != 0 {
                regs.int_status
                    .write(INT_STATUS::TRANSFER_COMPLETE::SET + INT_STATUS::CMD_COMPLETE::SET);
                break;
            }

            if timeout.is_expired() {
                let _ = self.reset_cmd();
                let _ = self.reset_data();
                return Err(SdhciError::CommandTimeout);
            }

            core::hint::spin_loop();
        }

        self.dma_buffer
            .sync_for_cpu(0..self.dma_buffer.len(), DmaDirection::FromDevice)
            .map_err(|_| SdhciError::DmaError)?;
        barrier::dma_read();

        Ok(())
    }

    /// Read sectors from the card using SDMA
    pub fn read_sectors(
        &mut self,
        start_lba: u64,
        count: u32,
        buffer: &mut [u8],
    ) -> Result<(), SdhciError> {
        if !self.card_initialized {
            return Err(SdhciError::NotInitialized);
        }

        if count == 0 {
            return Err(SdhciError::InvalidParameter);
        }

        let transfer_size = (count as usize)
            .checked_mul(SD_BLOCK_SIZE as usize)
            .ok_or(SdhciError::InvalidParameter)?;
        if buffer.len() != transfer_size {
            return Err(SdhciError::InvalidParameter);
        }

        // For transfers larger than one page, do multiple transfers
        if transfer_size > 4096 {
            let sectors_per_page = 4096 / SD_BLOCK_SIZE as usize;
            let mut remaining = count;
            let mut current_lba = start_lba;
            let mut byte_offset = 0;

            while remaining > 0 {
                let sectors_this_read = core::cmp::min(remaining, sectors_per_page as u32);
                let byte_len = sectors_this_read as usize * SD_BLOCK_SIZE as usize;
                self.read_sectors_internal(
                    current_lba,
                    sectors_this_read,
                    &mut buffer[byte_offset..byte_offset + byte_len],
                )?;
                remaining -= sectors_this_read;
                current_lba += sectors_this_read as u64;
                byte_offset += byte_len;
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
        buffer: &mut [u8],
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
            // SDMA only supports 32-bit addresses; verify buffer is below 4 GiB
            let dma_addr = self.dma_buffer.dma_address();
            self.dma_buffer
                .sync_for_device(0..self.dma_buffer.len(), DmaDirection::FromDevice)
                .map_err(|_| SdhciError::DmaError)?;
            regs.sdma_addr.set(dma_addr as u32);

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
            // Read status once to avoid TOCTOU races with hardware
            let (has_error, error_status, is_complete, is_timeout) = {
                let regs = self.regs();
                let status = regs.int_status.get();
                let has_error = status & INT_STATUS::ERROR::SET.value != 0;
                let is_complete = status & INT_STATUS::CMD_COMPLETE::SET.value != 0;

                if has_error {
                    regs.int_status.set(status);
                }
                if is_complete {
                    regs.int_status.write(INT_STATUS::CMD_COMPLETE::SET);
                }

                (has_error, status, is_complete, timeout.is_expired())
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

                if status & INT_STATUS::ERROR::SET.value != 0 {
                    // Clear status after saving -- check saved value, not register
                    regs.int_status.set(status);
                    DataResult::Error {
                        status,
                        is_timeout: status & INT_STATUS::DATA_TIMEOUT::SET.value != 0,
                        is_crc: status & INT_STATUS::DATA_CRC::SET.value != 0,
                        is_end_bit: status & INT_STATUS::DATA_END_BIT::SET.value != 0,
                        is_adma: status & INT_STATUS::ADMA::SET.value != 0,
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

        self.dma_buffer
            .sync_for_cpu(0..self.dma_buffer.len(), DmaDirection::FromDevice)
            .map_err(|_| SdhciError::DmaError)?;
        barrier::dma_read();

        buffer.copy_from_slice(&self.dma_buffer.as_slice()[..transfer_size]);

        Ok(())
    }

    /// Read one or more sectors into a buffer
    ///
    /// The number of sectors to read is inferred from the buffer size.
    /// If the buffer is larger than one sector, multiple sectors are read
    /// in a single operation for performance.
    pub fn read_sector(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), SdhciError> {
        if buffer.is_empty() || !buffer.len().is_multiple_of(SD_BLOCK_SIZE as usize) {
            return Err(SdhciError::InvalidParameter);
        }

        let num_sectors = u32::try_from(buffer.len() / SD_BLOCK_SIZE as usize)
            .map_err(|_| SdhciError::InvalidParameter)?;
        self.read_sectors(lba, num_sectors, buffer)
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

    /// Get the PCI address of this controller, if it has one.
    pub fn pci_address(&self) -> Option<PciAddress> {
        match self.identity {
            SdhciIdentity::Pci(address) => Some(address),
            SdhciIdentity::Acpi { .. } => None,
        }
    }

    /// Get this controller's origin.
    pub fn identity(&self) -> SdhciIdentity {
        self.identity
    }

    /// Return whether this controller's media is removable.
    pub fn removable(&self) -> bool {
        self.removable
    }
}

// ============================================================================
// Global Controller Management
// ============================================================================

/// Registry of initialized SDHCI controllers
static SDHCI_CONTROLLERS: super::ControllerRegistry<SdhciController, MAX_SDHCI_CONTROLLERS> =
    super::ControllerRegistry::new("SDHCI");

/// Initialize a single SDHCI controller from a PCI device
///
/// Called by the PCI driver model when an SDHCI device is discovered.
///
/// # Arguments
/// * `dev` - The PCI device to initialize as an SDHCI controller
// Failures are logged at the error site; callers only branch on success.
#[allow(clippy::result_unit_err)]
pub fn init_device(dev: &pci::PciDevice) -> Result<(), ()> {
    log::info!(
        "Initializing SDHCI controller at {}: {:04x}:{:04x}",
        dev.address,
        dev.vendor_id,
        dev.device_id
    );

    let controller = SdhciController::new(dev).map_err(|e| {
        log::error!(
            "Failed to initialize SDHCI controller at {}: {:?}",
            dev.address,
            e
        );
    })?;

    SDHCI_CONTROLLERS.register(controller)?;
    log::info!("SDHCI controller at {} initialized", dev.address);
    Ok(())
}

/// Initialize an ACPI-described MMIO SDHCI controller.
// Failures are logged at the error site; callers only branch on success.
#[allow(clippy::result_unit_err)]
pub fn init_mmio_device(dev: &crate::fdt::DsdtDevice, media: SdhciMedia) -> Result<(), ()> {
    if dev.mmio_base == 0 || dev.mmio_size == 0 {
        return Err(());
    }

    log::info!(
        "Initializing MMIO SDHCI controller {} [{}] at {:#x}+{:#x}",
        dev.name_str(),
        dev.hid_str(),
        dev.mmio_base,
        dev.mmio_size,
    );

    let controller = SdhciController::new_mmio(
        dev.mmio_base,
        SdhciIdentity::Acpi {
            name: dev.name,
            hid: dev.hid,
            hid_len: dev.hid_len,
            mmio_base: dev.mmio_base,
        },
        media,
        false,
        false,
    )
    .map_err(|e| {
        log::error!("Failed to initialize MMIO SDHCI controller: {:?}", e);
    })?;

    SDHCI_CONTROLLERS.register(controller)?;
    log::info!("MMIO SDHCI controller initialized");
    Ok(())
}

/// Shutdown all SDHCI controllers
///
/// Called during ExitBootServices to prepare for OS handoff.
/// Currently a placeholder — the OS will reset controllers during its own init.
pub fn shutdown() {
    SDHCI_CONTROLLERS.shutdown_log();
}

/// Initialize SDHCI controllers (legacy entry point)
///
/// Scans PCI bus for SDHCI controllers and initializes each one.
/// Prefer using `init_device()` via the PCI driver model instead.
pub fn init() {
    log::info!("Initializing SDHCI controllers...");

    let sdhci_devices = pci::find_sdhci_controllers();

    if sdhci_devices.is_empty() {
        log::info!("No SDHCI controllers found");
        return;
    }

    for dev in sdhci_devices.iter() {
        let _ = init_device(dev);
    }

    log::info!(
        "SDHCI initialization complete: {} controllers",
        SDHCI_CONTROLLERS.count()
    );
}

/// Access one SDHCI controller while retaining exclusive registry ownership.
pub fn with_controller<R>(index: usize, f: impl FnOnce(&mut SdhciController) -> R) -> Option<R> {
    SDHCI_CONTROLLERS.with_mut(index, f)
}

/// Get the number of initialized SDHCI controllers
pub fn controller_count() -> usize {
    SDHCI_CONTROLLERS.count()
}

// ============================================================================
// Global Device for SimpleFileSystem Protocol
// ============================================================================

/// Global SDHCI device info for filesystem reads
#[derive(Clone, Copy)]
struct GlobalSdhciDevice {
    controller_index: usize,
}

/// Global SDHCI device for filesystem protocol
static GLOBAL_SDHCI_DEVICE: Mutex<Option<GlobalSdhciDevice>> = Mutex::new(None);

/// Store SDHCI device info globally for SimpleFileSystem protocol
///
/// # Arguments
/// * `controller_index` - Index of the SDHCI controller
///
/// # Returns
/// `true` if the device was stored successfully
pub fn store_global_device(controller_index: usize) -> bool {
    *GLOBAL_SDHCI_DEVICE.lock() = Some(GlobalSdhciDevice { controller_index });
    log::info!(
        "SDHCI device stored globally (controller={})",
        controller_index
    );
    true
}

/// Read sectors from the global SDHCI device
///
/// This function is used as the read callback for the SimpleFileSystem protocol.
/// Supports reading multiple sectors by inferring sector count from buffer size.
// Failures are logged at the error site; callers only branch on success.
#[allow(clippy::result_unit_err)]
pub fn global_read_sectors(lba: u64, buffer: &mut [u8]) -> Result<(), ()> {
    log::trace!("SDHCI global_read_sectors: LBA={}", lba);

    // Get the device info
    let controller_index = match *GLOBAL_SDHCI_DEVICE.lock() {
        Some(device) => device.controller_index,
        None => {
            log::error!("global_read_sectors: no SDHCI device stored");
            return Err(());
        }
    };

    with_controller(controller_index, |controller| {
        controller.read_sector(lba, buffer).map_err(|error| {
            log::error!(
                "global_read_sectors: read failed at LBA {}: {:?}",
                lba,
                error
            );
        })
    })
    .unwrap_or_else(|| {
        log::error!(
            "global_read_sectors: no SDHCI controller at index {}",
            controller_index
        );
        Err(())
    })
}
