//! Intel ICH/PCH SPI Controller Driver
//!
//! This module implements the SPI controller driver for Intel ICH/PCH chipsets.
//! It supports both hardware sequencing (hwseq) and software sequencing (swseq)
//! modes.
//!
//! # Supported Chipsets
//!
//! - ICH7: Original SPI controller (swseq only)
//! - ICH8-ICH10: Hardware sequencing introduced
//! - 5-9 Series (Ibex Peak through Wildcat Point)
//! - 100+ Series (Sunrise Point and later): New register layout
//!
//! # Operating Modes
//!
//! - **Hardware Sequencing**: The SPI controller handles read/write/erase
//!   operations internally. This is the default for PCH100+.
//! - **Software Sequencing**: We control the SPI protocol directly.
//!   More flexible but may not be available on locked-down systems.

use super::intel_chipsets::IchChipset;
use super::regs::*;
use super::{delay_us, Result, SpiController, SpiError, SpiMode};
use crate::drivers::mmio::MmioRegion;
use crate::drivers::pci::{self, PciAddress, PciDevice};

/// Intel ICH/PCH SPI Controller
pub struct IntelSpiController {
    /// Memory-mapped SPI registers
    spibar: MmioRegion,
    /// Chipset generation
    generation: IchChipset,
    /// PCI address of LPC/eSPI bridge
    lpc_addr: PciAddress,
    /// Whether configuration is locked (HSFS.FLOCKDN)
    locked: bool,
    /// Whether software sequencing is locked (DLOCK.SSEQ_LOCKDN on PCH100+)
    swseq_locked: bool,
    /// Flash descriptor valid
    desc_valid: bool,
    /// Actual operating mode (after validation)
    mode: SpiMode,
    /// BIOS Write Enable state
    writes_enabled: bool,
    /// Address mask for hardware sequencing
    hwseq_addr_mask: u32,
    /// HSFC FCYCLE field mask
    hsfc_fcycle_mask: u16,
}

impl IntelSpiController {
    /// Initialize a new SPI controller for the detected chipset
    pub fn new(
        pci_dev: &PciDevice,
        generation: IchChipset,
        requested_mode: SpiMode,
    ) -> Result<Self> {
        // Get SPI BAR address
        let spibar_addr = Self::get_spibar_address(pci_dev, generation)?;
        log::debug!("SPI BAR at physical address: {:#x}", spibar_addr);

        // Map the SPI registers (512 bytes should be enough for all generations)
        let spibar = MmioRegion::new(spibar_addr, 0x200);

        // Initialize controller with default values
        let mut controller = Self {
            spibar,
            generation,
            lpc_addr: pci_dev.address,
            locked: false,
            swseq_locked: false,
            desc_valid: false,
            mode: SpiMode::Auto,
            writes_enabled: false,
            hwseq_addr_mask: if generation.is_pch100_compatible() {
                PCH100_FADDR_FLA
            } else {
                ICH9_FADDR_FLA
            },
            hsfc_fcycle_mask: if generation.is_pch100_compatible() {
                PCH100_HSFC_FCYCLE
            } else {
                HSFC_FCYCLE
            },
        };

        // Initialize the controller
        controller.init(requested_mode)?;

        Ok(controller)
    }

    /// Get the SPI BAR physical address from PCI config space
    fn get_spibar_address(pci_dev: &PciDevice, generation: IchChipset) -> Result<u64> {
        if generation.is_pch100_compatible() {
            // PCH100+ (Sunrise Point and later): SPI controller is a separate PCI device
            // at function 5 (00:1f.5), not part of the LPC bridge at function 0.
            let spi_addr = PciAddress::new(pci_dev.address.bus, pci_dev.address.device, 5);

            // Read SPIBAR (BAR0) from PCI config space
            let spibar_raw = pci::read_config_u32(spi_addr, PCI_REG_SPIBAR);

            // SPIBAR is a 32-bit memory BAR. Mask off the lower 12 bits
            let addr = (spibar_raw & 0xFFFF_F000) as u64;

            log::debug!(
                "Raw SPIBAR register: {:#010x}, masked addr: {:#010x}",
                spibar_raw,
                addr
            );

            if addr == 0 {
                log::error!("SPIBAR is 0 - SPI controller may be hidden or disabled");
                return Err(SpiError::InitFailed);
            }

            Ok(addr)
        } else if generation.is_ich9_compatible() || generation == IchChipset::Ich7 {
            // ICH7-ICH10, 5-9 Series: SPI is at an offset within RCBA
            Self::get_spibar_via_rcba(pci_dev, generation)
        } else {
            Err(SpiError::UnsupportedChipset)
        }
    }

    /// Get SPI BAR via RCBA (Root Complex Base Address)
    fn get_spibar_via_rcba(pci_dev: &PciDevice, generation: IchChipset) -> Result<u64> {
        // Read RCBA from LPC bridge config space
        let rcba = pci::read_config_u32(pci_dev.address, PCI_REG_RCBA);

        // Check if RCBA is enabled (bit 0)
        if rcba & 1 == 0 {
            log::error!("RCBA not enabled");
            return Err(SpiError::InitFailed);
        }

        // RCBA is 32-bit aligned, mask off lower bits
        let rcba_base = (rcba & !0x3FFF) as u64;

        // SPI offset depends on chipset generation
        let spi_offset = if generation == IchChipset::Ich7 {
            RCBA_SPI_OFFSET_ICH7
        } else {
            RCBA_SPI_OFFSET_ICH9
        };

        Ok(rcba_base + spi_offset)
    }

    /// Initialize the SPI controller
    fn init(&mut self, requested_mode: SpiMode) -> Result<()> {
        if self.generation == IchChipset::Ich7 {
            self.init_ich7()
        } else if self.generation.is_ich9_compatible() {
            self.init_ich9(requested_mode)
        } else {
            Err(SpiError::UnsupportedChipset)
        }
    }

    /// Initialize ICH7 SPI controller
    fn init_ich7(&mut self) -> Result<()> {
        let spis = self.spibar.read16(ICH7_REG_SPIS);
        log::debug!("ICH7 SPIS: {:#06x}", spis);

        // Check for lockdown (bit 15 of SPIS)
        if spis & (1 << 15) != 0 {
            log::warn!("ICH7 SPI Configuration Lockdown activated");
            self.locked = true;
        }

        // ICH7 only supports swseq
        self.mode = SpiMode::SoftwareSequencing;
        self.desc_valid = false;

        log::info!("Using swseq mode on ICH7 (hwseq not supported)");
        Ok(())
    }

    /// Initialize ICH9+ SPI controller (including PCH100+)
    fn init_ich9(&mut self, requested_mode: SpiMode) -> Result<()> {
        // Read HSFS
        let hsfs = self.spibar.read16(ICH9_REG_HSFS);
        log::debug!("HSFS: {:#06x}", hsfs);
        self.print_hsfs(hsfs);

        // Check for lockdown
        if hsfs & HSFS_FLOCKDN != 0 {
            log::info!("SPI Configuration is locked down");
            self.locked = true;
        }

        // Check descriptor valid
        if hsfs & HSFS_FDV != 0 {
            self.desc_valid = true;
            log::debug!("Flash Descriptor is valid");
        }

        // PCH100+ specific: check DLOCK.SSEQ_LOCKDN
        if self.generation.is_pch100_compatible() {
            let dlock = self.spibar.read32(PCH100_REG_DLOCK);
            log::debug!("DLOCK: {:#010x}", dlock);

            if dlock & DLOCK_SSEQ_LOCKDN != 0 {
                log::info!("Software sequencing is locked (DLOCK.SSEQ_LOCKDN=1)");
                self.swseq_locked = true;
            }
        }

        // Determine operating mode
        self.determine_mode(requested_mode)?;

        // Clear any pending errors
        let hsfs = self.spibar.read16(ICH9_REG_HSFS);
        if hsfs & HSFS_FCERR != 0 {
            log::debug!("Clearing HSFS.FCERR");
            self.spibar.write16(ICH9_REG_HSFS, HSFS_FCERR);
        }

        Ok(())
    }

    /// Determine the operating mode based on hardware and user request
    fn determine_mode(&mut self, requested: SpiMode) -> Result<()> {
        // Validate user's explicit request
        if requested == SpiMode::HardwareSequencing {
            if !self.generation.supports_hwseq() {
                log::error!("Hardware sequencing requested but not supported on ICH7");
                return Err(SpiError::NotSupported);
            }
            if !self.desc_valid {
                log::error!("Hardware sequencing requested but flash descriptor is not valid");
                return Err(SpiError::InvalidDescriptor);
            }
        } else if requested == SpiMode::SoftwareSequencing {
            if self.swseq_locked {
                log::error!("Software sequencing requested but locked");
                return Err(SpiError::NotSupported);
            }
        }

        // Determine effective mode for Auto
        let effective_mode = if requested != SpiMode::Auto {
            requested
        } else if !self.generation.supports_hwseq() {
            log::debug!("Using swseq (ICH7 has no hwseq support)");
            SpiMode::SoftwareSequencing
        } else if self.swseq_locked {
            log::info!("Using hwseq because swseq is locked");
            if !self.desc_valid {
                return Err(SpiError::InvalidDescriptor);
            }
            SpiMode::HardwareSequencing
        } else if self.generation.defaults_to_hwseq() && self.desc_valid {
            log::debug!("Enabling hwseq by default for {}", self.generation);
            SpiMode::HardwareSequencing
        } else {
            SpiMode::SoftwareSequencing
        };

        self.mode = effective_mode;
        log::info!(
            "Using {:?} mode on {} (requested: {:?})",
            self.mode,
            self.generation,
            requested
        );

        Ok(())
    }

    /// Print HSFS register bits for debugging
    fn print_hsfs(&self, hsfs: u16) {
        log::debug!(
            "HSFS: FDONE={} FCERR={} AEL={} SCIP={} FDV={} FLOCKDN={}",
            (hsfs & HSFS_FDONE) != 0,
            (hsfs & HSFS_FCERR) != 0,
            (hsfs & HSFS_AEL) != 0,
            (hsfs & HSFS_SCIP) != 0,
            (hsfs & HSFS_FDV) != 0,
            (hsfs & HSFS_FLOCKDN) != 0
        );
    }

    /// Enable BIOS write access via BIOS_CNTL register
    fn enable_bios_write_internal(&mut self) -> Result<()> {
        let bios_cntl = pci::read_config_u8(self.lpc_addr, PCI_REG_BIOS_CNTL);
        log::debug!("BIOS_CNTL: {:#04x}", bios_cntl);

        // Check if BIOS Lock Enable is set
        if bios_cntl & BIOS_CNTL_BLE != 0 {
            log::warn!("BIOS Lock Enable (BLE) is set - writes may trigger SMI");
        }

        // Check if SMM BIOS Write Protect is set
        if bios_cntl & BIOS_CNTL_SMM_BWP != 0 {
            log::warn!("SMM BIOS Write Protect is set - cannot enable writes");
            return Err(SpiError::WriteProtected);
        }

        // Enable BIOS Write Enable
        if bios_cntl & BIOS_CNTL_BWE == 0 {
            let new_val = bios_cntl | BIOS_CNTL_BWE;
            pci::write_config_u8(self.lpc_addr, PCI_REG_BIOS_CNTL, new_val);

            // Verify
            let verify = pci::read_config_u8(self.lpc_addr, PCI_REG_BIOS_CNTL);
            if verify & BIOS_CNTL_BWE == 0 {
                log::error!("Failed to enable BIOS Write Enable");
                return Err(SpiError::WriteProtected);
            }

            log::info!("BIOS Write Enable activated");
            self.writes_enabled = true;
        } else {
            log::debug!("BIOS Write Enable already active");
            self.writes_enabled = true;
        }

        Ok(())
    }

    // ========================================================================
    // Hardware Sequencing Operations
    // ========================================================================

    /// Set the flash address for hardware sequencing
    #[inline(always)]
    fn hwseq_set_addr(&self, addr: u32) {
        self.spibar
            .write32(ICH9_REG_FADDR, addr & self.hwseq_addr_mask);
    }

    /// Wait for hardware sequencing cycle to complete
    fn hwseq_wait_for_cycle(&self, timeout_us: u32) -> Result<()> {
        let done_or_err = HSFS_FDONE | HSFS_FCERR;

        let mut elapsed = 0u32;
        loop {
            let hsfs = self.spibar.read16(ICH9_REG_HSFS);

            if hsfs & done_or_err != 0 {
                // Clear status bits by writing 1s to them (W1C)
                self.spibar.write16(ICH9_REG_HSFS, hsfs);

                if hsfs & HSFS_FCERR != 0 {
                    log::error!("Hardware sequencing cycle error");
                    return Err(SpiError::CycleError);
                }

                return Ok(());
            }

            if elapsed >= timeout_us {
                log::error!("Hardware sequencing timeout");
                return Err(SpiError::Timeout);
            }

            delay_us(1);
            elapsed += 1;
        }
    }

    /// Read data using hardware sequencing
    fn hwseq_read(&mut self, addr: u32, buf: &mut [u8]) -> Result<()> {
        let len = buf.len();
        if len == 0 {
            return Ok(());
        }

        let mut offset = 0;
        let mut current_addr = addr;

        // Clear any pending status
        let hsfs = self.spibar.read16(ICH9_REG_HSFS);
        self.spibar.write16(ICH9_REG_HSFS, hsfs);

        while offset < len {
            // Calculate block size (max 64 bytes, respect 256-byte page boundaries)
            let remaining = len - offset;
            let page_remaining = 256 - (current_addr as usize & 0xFF);
            let block_len = remaining.min(HWSEQ_MAX_DATA).min(page_remaining);

            self.hwseq_set_addr(current_addr);

            // Set up read cycle
            let mut hsfc = self.spibar.read16(ICH9_REG_HSFC);
            hsfc &= !self.hsfc_fcycle_mask; // Clear FCYCLE (0 = read)
            hsfc &= !HSFC_FDBC; // Clear byte count
            hsfc |= ((block_len - 1) as u16) << HSFC_FDBC_OFF; // Set byte count
            hsfc |= HSFC_FGO; // Start
            self.spibar.write16(ICH9_REG_HSFC, hsfc);

            // Wait for completion (30 second timeout)
            self.hwseq_wait_for_cycle(30_000_000)?;

            // Read data from FDATA registers
            self.read_fdata(&mut buf[offset..offset + block_len]);

            offset += block_len;
            current_addr += block_len as u32;
        }

        Ok(())
    }

    /// Write data using hardware sequencing
    fn hwseq_write(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        let len = data.len();
        if len == 0 {
            return Ok(());
        }

        if !self.writes_enabled {
            return Err(SpiError::WriteProtected);
        }

        let mut offset = 0;
        let mut current_addr = addr;

        // Clear any pending status
        let hsfs = self.spibar.read16(ICH9_REG_HSFS);
        self.spibar.write16(ICH9_REG_HSFS, hsfs);

        while offset < len {
            // Calculate block size (max 64 bytes, respect 256-byte page boundaries)
            let remaining = len - offset;
            let page_remaining = 256 - (current_addr as usize & 0xFF);
            let block_len = remaining.min(HWSEQ_MAX_DATA).min(page_remaining);

            self.hwseq_set_addr(current_addr);

            // Fill data registers first (before starting cycle)
            self.write_fdata(&data[offset..offset + block_len]);

            // Set up write cycle
            let mut hsfc = self.spibar.read16(ICH9_REG_HSFC);
            hsfc &= !self.hsfc_fcycle_mask; // Clear FCYCLE
            hsfc |= 0x2 << HSFC_FCYCLE_OFF; // Set write cycle
            hsfc &= !HSFC_FDBC; // Clear byte count
            hsfc |= ((block_len - 1) as u16) << HSFC_FDBC_OFF; // Set byte count
            hsfc |= HSFC_FGO; // Start
            self.spibar.write16(ICH9_REG_HSFC, hsfc);

            // Wait for completion (30 second timeout)
            self.hwseq_wait_for_cycle(30_000_000)?;

            offset += block_len;
            current_addr += block_len as u32;
        }

        Ok(())
    }

    /// Erase a block using hardware sequencing
    fn hwseq_erase(&mut self, addr: u32, len: u32) -> Result<()> {
        if !self.writes_enabled {
            return Err(SpiError::WriteProtected);
        }

        // Hardware sequencing uses 4KB erase blocks
        const ERASE_SIZE: u32 = 4096;

        if addr & (ERASE_SIZE - 1) != 0 || len & (ERASE_SIZE - 1) != 0 {
            log::error!("Erase address/length must be 4KB aligned");
            return Err(SpiError::InvalidArgument);
        }

        let mut current_addr = addr;
        let end_addr = addr + len;

        // Clear any pending status
        let hsfs = self.spibar.read16(ICH9_REG_HSFS);
        self.spibar.write16(ICH9_REG_HSFS, hsfs);

        while current_addr < end_addr {
            self.hwseq_set_addr(current_addr);

            // Set up erase cycle
            let mut hsfc = self.spibar.read16(ICH9_REG_HSFC);
            hsfc &= !self.hsfc_fcycle_mask; // Clear FCYCLE
            hsfc |= 0x3 << HSFC_FCYCLE_OFF; // Set erase cycle
            hsfc |= HSFC_FGO; // Start
            self.spibar.write16(ICH9_REG_HSFC, hsfc);

            // Wait for completion (60 second timeout for erase)
            self.hwseq_wait_for_cycle(60_000_000)?;

            current_addr += ERASE_SIZE;
        }

        Ok(())
    }

    /// Read data from FDATA registers
    #[inline(always)]
    fn read_fdata(&self, buf: &mut [u8]) {
        let len = buf.len();
        let mut offset = 0;

        // Process full 32-bit words
        while offset + 4 <= len {
            let temp = self.spibar.read32(ICH9_REG_FDATA0 + offset as u64);
            buf[offset] = temp as u8;
            buf[offset + 1] = (temp >> 8) as u8;
            buf[offset + 2] = (temp >> 16) as u8;
            buf[offset + 3] = (temp >> 24) as u8;
            offset += 4;
        }

        // Handle remaining bytes
        if offset < len {
            let temp = self.spibar.read32(ICH9_REG_FDATA0 + offset as u64);
            let remaining = len - offset;
            if remaining > 0 {
                buf[offset] = temp as u8;
            }
            if remaining > 1 {
                buf[offset + 1] = (temp >> 8) as u8;
            }
            if remaining > 2 {
                buf[offset + 2] = (temp >> 16) as u8;
            }
        }
    }

    /// Write data to FDATA registers
    #[inline(always)]
    fn write_fdata(&self, data: &[u8]) {
        let len = data.len();
        if len == 0 {
            return;
        }

        let mut offset = 0;

        // Process full 32-bit words
        while offset + 4 <= len {
            let temp = (data[offset] as u32)
                | ((data[offset + 1] as u32) << 8)
                | ((data[offset + 2] as u32) << 16)
                | ((data[offset + 3] as u32) << 24);
            self.spibar.write32(ICH9_REG_FDATA0 + offset as u64, temp);
            offset += 4;
        }

        // Handle remaining bytes
        if offset < len {
            let mut temp: u32 = 0;
            let remaining = len - offset;
            if remaining > 0 {
                temp |= data[offset] as u32;
            }
            if remaining > 1 {
                temp |= (data[offset + 1] as u32) << 8;
            }
            if remaining > 2 {
                temp |= (data[offset + 2] as u32) << 16;
            }
            self.spibar.write32(ICH9_REG_FDATA0 + offset as u64, temp);
        }
    }
}

impl SpiController for IntelSpiController {
    fn name(&self) -> &'static str {
        "Intel ICH/PCH SPI"
    }

    fn is_locked(&self) -> bool {
        self.locked
    }

    fn writes_enabled(&self) -> bool {
        self.writes_enabled
    }

    fn enable_writes(&mut self) -> Result<()> {
        self.enable_bios_write_internal()
    }

    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<()> {
        match self.mode {
            SpiMode::HardwareSequencing => self.hwseq_read(addr, buf),
            SpiMode::SoftwareSequencing => {
                // Software sequencing read would go here
                // For now, we'll return an error
                log::error!("Software sequencing read not implemented");
                Err(SpiError::NotSupported)
            }
            SpiMode::Auto => unreachable!("Mode should be resolved during init"),
        }
    }

    fn write(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        match self.mode {
            SpiMode::HardwareSequencing => self.hwseq_write(addr, data),
            SpiMode::SoftwareSequencing => {
                log::error!("Software sequencing write not implemented");
                Err(SpiError::NotSupported)
            }
            SpiMode::Auto => unreachable!("Mode should be resolved during init"),
        }
    }

    fn erase(&mut self, addr: u32, len: u32) -> Result<()> {
        match self.mode {
            SpiMode::HardwareSequencing => self.hwseq_erase(addr, len),
            SpiMode::SoftwareSequencing => {
                log::error!("Software sequencing erase not implemented");
                Err(SpiError::NotSupported)
            }
            SpiMode::Auto => unreachable!("Mode should be resolved during init"),
        }
    }

    fn mode(&self) -> SpiMode {
        self.mode
    }
}
