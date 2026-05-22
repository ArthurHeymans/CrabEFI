//! Intel ICH/PCH SPI Controller Driver
//!
//! This module implements the SPI controller driver for Intel ICH/PCH chipsets.
//! It supports both hardware sequencing (hwseq) and software sequencing (swseq)
//! modes.
//!
//! # Supported Chipsets
//!
//! - ICH7: Original SPI controller (swseq only)
//! - ICH8: ICH9-like registers at the ICH7 RCBA offset; uses swseq here
//!   because the hardware-sequencing FPB is undocumented
//! - ICH9-ICH10 and 5-9 Series (Ibex Peak through Wildcat Point): hwseq when
//!   descriptor-backed, swseq otherwise
//! - 100+ Series (Sunrise Point and later): New register layout, hwseq only
//!
//! # Operating Modes
//!
//! - **Hardware Sequencing**: The SPI controller handles read/write/erase
//!   operations internally. This is the default for PCH100+.
//! - **Software Sequencing**: We control the SPI protocol directly.
//!   More flexible but may not be available on locked-down systems.
//!
//! # TODO: Missing features from rflasher/flashprog
//!
//! The following features are implemented in rflasher but not yet here:
//!
//! ## Access Permission Handling (MEDIUM priority)
//! - `handle_access_permissions()` - Check FRAP/FREG for region access
//! - `handle_protected_ranges()` - Check/clear PRx registers when not locked
//! - BIOS_BM_WAP/RAP reading for C740+ chipsets

use super::intel_chipsets::IchChipset;
use super::regs::*;
use super::{Result, SpiController, SpiError, SpiMode, delay_us};
use crate::drivers::mmio::MmioRegion;
use crate::drivers::pci::{self, PciAddress, PciDevice};

const SWSEQ_MAX_DATA: usize = 64;
const SPI_WRITE_TIMEOUT_US: u32 = 60_000_000;
const SPI_CYCLE_TIMEOUT_US: u32 = 60_000;
const SWSEQ_3B_ADDR_MASK: u32 = 0x00ff_ffff;
const ICH7_REG_BBAR: u64 = 0x50;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpcodeType {
    Read,
    Write,
    AddressRead,
    AddressWrite,
}

#[derive(Clone, Copy, Debug)]
struct Opcode {
    code: u8,
    kind: OpcodeType,
    atomic: u8,
}

#[derive(Clone, Copy, Debug)]
struct Opcodes {
    preop: [u8; 2],
    table: [Opcode; 8],
}

impl Default for Opcodes {
    fn default() -> Self {
        Self {
            preop: [JEDEC_WREN, JEDEC_EWSR],
            table: [
                Opcode {
                    code: JEDEC_BYTE_PROGRAM,
                    kind: OpcodeType::AddressWrite,
                    atomic: 1,
                },
                Opcode {
                    code: JEDEC_READ,
                    kind: OpcodeType::AddressRead,
                    atomic: 0,
                },
                Opcode {
                    code: JEDEC_SE,
                    kind: OpcodeType::AddressWrite,
                    atomic: 1,
                },
                Opcode {
                    code: JEDEC_RDSR,
                    kind: OpcodeType::Read,
                    atomic: 0,
                },
                Opcode {
                    code: JEDEC_REMS,
                    kind: OpcodeType::AddressRead,
                    atomic: 0,
                },
                Opcode {
                    code: JEDEC_WRSR,
                    kind: OpcodeType::Write,
                    atomic: 2,
                },
                Opcode {
                    code: JEDEC_RDID,
                    kind: OpcodeType::Read,
                    atomic: 0,
                },
                Opcode {
                    code: JEDEC_CE_C7,
                    kind: OpcodeType::Write,
                    atomic: 1,
                },
            ],
        }
    }
}

impl Opcodes {
    fn find(&self, code: u8) -> Option<Opcode> {
        self.table.iter().copied().find(|op| op.code == code)
    }

    fn opmenu(&self) -> u64 {
        let mut value = 0u64;
        for (i, op) in self.table.iter().enumerate() {
            value |= (op.code as u64) << (i * 8);
        }
        value
    }

    fn optype(&self) -> u16 {
        let mut value = 0u16;
        for (i, op) in self.table.iter().enumerate() {
            let ty = match op.kind {
                OpcodeType::Read => 0,
                OpcodeType::Write => 1,
                OpcodeType::AddressRead => 2,
                OpcodeType::AddressWrite => 3,
            };
            value |= ty << (i * 2);
        }
        value
    }
}

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
    /// Total flash size in bytes (derived from flash descriptor or address mask)
    flash_size: u32,
    /// Current opcodes (for software sequencing)
    opcodes: Opcodes,
    /// Effective software-sequencing lower address bound from BBAR, when applicable.
    swseq_bbar_lower_bound: Option<u32>,
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
        // SAFETY: spibar_addr is decoded from the chipset's SPI BAR register,
        // a valid MMIO region for SPI controller registers.
        let spibar = unsafe { MmioRegion::new(spibar_addr, 0x200) };

        // Determine address mask based on generation
        let hwseq_addr_mask = if generation.is_pch100_compatible() {
            PCH100_FADDR_FLA
        } else {
            ICH9_FADDR_FLA
        };

        // Initialize controller with default values
        // flash_size starts as the maximum addressable size based on address mask,
        // and will be refined during init() if a valid flash descriptor is present
        let mut controller = Self {
            spibar,
            generation,
            lpc_addr: pci_dev.address,
            locked: false,
            swseq_locked: false,
            desc_valid: false,
            mode: SpiMode::Auto,
            writes_enabled: false,
            hwseq_addr_mask,
            hsfc_fcycle_mask: if generation.is_pch100_compatible() {
                PCH100_HSFC_FCYCLE
            } else {
                HSFC_FCYCLE
            },
            // Default to max addressable size; will be refined from flash descriptor
            flash_size: hwseq_addr_mask + 1,
            opcodes: Opcodes::default(),
            swseq_bbar_lower_bound: None,
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

        // SPI offset within RCBA depends on chipset generation.
        // ICH7 and ICH8 both use RCBA+0x3020; ICH9 moved the SPI BAR to RCBA+0x3800.
        // (TunnelCreek and Centerton also use 0x3020 when they are added.)
        let spi_offset = match generation {
            IchChipset::Ich7 | IchChipset::Ich8 => RCBA_SPI_OFFSET_ICH7,
            _ => RCBA_SPI_OFFSET_ICH9,
        };

        Ok(rcba_base + spi_offset)
    }

    /// Initialize the SPI controller
    fn init(&mut self, requested_mode: SpiMode) -> Result<()> {
        if self.generation == IchChipset::Ich7 {
            self.init_ich7(requested_mode)
        } else if self.generation.is_ich9_compatible() {
            self.init_ich9(requested_mode)
        } else {
            Err(SpiError::UnsupportedChipset)
        }
    }

    /// Initialize ICH7 SPI controller.
    ///
    /// ICH7 only supports software sequencing. Opcode tables are programmed
    /// when unlocked and read back when locked; BBAR is cleared when possible
    /// and then tracked as a lower bound for swseq accesses.
    fn init_ich7(&mut self, requested_mode: SpiMode) -> Result<()> {
        if requested_mode == SpiMode::HardwareSequencing {
            log::error!("Hardware sequencing requested but not supported on ICH7");
            return Err(SpiError::NotSupported);
        }
        let spis = self.spibar.read16(ICH7_REG_SPIS);
        log::debug!("ICH7 SPIS: {:#06x}", spis);

        // Check for lockdown (bit 15 of SPIS)
        if spis & (1 << 15) != 0 {
            log::warn!("ICH7 SPI Configuration Lockdown activated");
            self.locked = true;
        }

        self.init_ich7_opcodes();

        self.update_ich7_bbar_lower_bound();

        // ICH7 only supports swseq
        self.mode = SpiMode::SoftwareSequencing;
        self.desc_valid = false;

        log::info!("Using swseq mode on ICH7 (hwseq not supported)");
        Ok(())
    }

    /// Initialize ICH9+ SPI controller (including PCH100+)
    ///
    /// TODO: Additional init steps from rflasher:
    /// - handle_access_permissions() - Check FRAP/FREG region access
    /// - handle_protected_ranges() - Check/clear PRx registers
    /// - Log SSFS/SSFC registers for debugging
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

        // PCH100+ specific: check DLOCK.SSEQ_LOCKDN before any possible
        // software-sequencing setup. PCH100 uses different swseq offsets, so
        // never touch ICH9 PREOP/OPTYPE/OPMENU offsets on those chipsets.
        if self.generation.is_pch100_compatible() {
            let dlock = self.spibar.read32(PCH100_REG_DLOCK);
            log::debug!("DLOCK: {:#010x}", dlock);
            // TODO: Log all DLOCK bits like rflasher's print_dlock()

            if dlock & DLOCK_SSEQ_LOCKDN != 0 {
                log::info!("Software sequencing is locked (DLOCK.SSEQ_LOCKDN=1)");
                self.swseq_locked = true;
            }
        }

        // TODO: handle_access_permissions() - check FRAP/FREG
        // TODO: handle_protected_ranges() - check/clear PRx registers

        // Determine operating mode
        self.determine_mode(requested_mode)?;

        // Calculate flash size from descriptor regions
        self.calculate_flash_size();

        // Clear any pending errors
        let hsfs = self.spibar.read16(ICH9_REG_HSFS);
        if hsfs & HSFS_FCERR != 0 {
            log::debug!("Clearing HSFS.FCERR");
            self.spibar.write16(ICH9_REG_HSFS, HSFS_FCERR);
        }

        if self.mode == SpiMode::SoftwareSequencing && !self.generation.is_pch100_compatible() {
            self.init_ich9_opcodes();
        }

        // ICH8 and Bay Trail have ICH9-like SPI engines but no documented
        // ICH9-compatible BBAR. Do not touch ICH9_REG_BBAR on those chipsets.
        if !self.generation.is_pch100_compatible()
            && self.generation != IchChipset::Ich8
            && self.generation != IchChipset::BayTrail
        {
            self.update_ich9_bbar_lower_bound();
        }

        Ok(())
    }

    fn update_ich7_bbar_lower_bound(&mut self) {
        let original = self.spibar.read32(ICH7_REG_BBAR);
        log::debug!("ICH7 BBAR: {:#010x}", original);
        if !self.locked {
            self.spibar.write32(ICH7_REG_BBAR, original & !BBAR_MASK);
        }
        let effective = self.spibar.read32(ICH7_REG_BBAR) & BBAR_MASK;
        self.swseq_bbar_lower_bound = Some(effective);
        if effective != 0 {
            log::warn!("ICH7 BBAR restricts swseq access below {:#x}", effective);
        }
    }

    fn update_ich9_bbar_lower_bound(&mut self) {
        let original = self.spibar.read32(ICH9_REG_BBAR);
        log::debug!("BBAR: {:#010x}", original);
        if !self.locked {
            self.spibar.write32(ICH9_REG_BBAR, original & !BBAR_MASK);
        }
        let effective = self.spibar.read32(ICH9_REG_BBAR) & BBAR_MASK;
        self.swseq_bbar_lower_bound = Some(effective);
        if effective != 0 {
            log::warn!("BBAR restricts swseq access below {:#x}", effective);
        }
    }

    fn init_ich7_opcodes(&mut self) {
        if self.locked {
            self.read_ich7_opcodes();
        } else {
            self.program_ich7_opcodes();
        }
    }

    fn init_ich9_opcodes(&mut self) {
        if self.locked || self.swseq_locked {
            self.read_ich9_opcodes();
        } else {
            self.program_ich9_opcodes();
        }
    }

    fn read_ich7_opcodes(&mut self) {
        self.opcodes.preop = self.spibar.read16(ICH7_REG_PREOP).to_le_bytes();
        let opmenu = self.spibar.read32(ICH7_REG_OPMENU) as u64
            | ((self.spibar.read32(ICH7_REG_OPMENU + 4) as u64) << 32);
        let optype = self.spibar.read16(ICH7_REG_OPTYPE);
        self.update_opcode_menu(opmenu, optype);
    }

    fn read_ich9_opcodes(&mut self) {
        let preop = self.spibar.read16(ICH9_REG_PREOP);
        self.opcodes.preop = preop.to_le_bytes();
        let opmenu = self.spibar.read32(ICH9_REG_OPMENU) as u64
            | ((self.spibar.read32(ICH9_REG_OPMENU + 4) as u64) << 32);
        let optype = self.spibar.read16(ICH9_REG_OPTYPE);
        self.update_opcode_menu(opmenu, optype);
    }

    fn update_opcode_menu(&mut self, opmenu: u64, optype: u16) {
        for i in 0..8 {
            let code = ((opmenu >> (i * 8)) & 0xff) as u8;
            let kind = match (optype >> (i * 2)) & 0x3 {
                0 => OpcodeType::Read,
                1 => OpcodeType::Write,
                2 => OpcodeType::AddressRead,
                _ => OpcodeType::AddressWrite,
            };
            self.opcodes.table[i] = Opcode {
                code,
                kind,
                atomic: Self::atomic_for_opcode(code, self.opcodes.preop),
            };
        }
        log::debug!("SPI opcode menu: {:#018x}, type: {:#06x}", opmenu, optype);
    }

    fn atomic_for_opcode(code: u8, preop: [u8; 2]) -> u8 {
        let wanted_preop = match code {
            JEDEC_WRSR => JEDEC_EWSR,
            JEDEC_BYTE_PROGRAM | JEDEC_SE | JEDEC_BE_52 | JEDEC_BE_D8 | JEDEC_CE_60
            | JEDEC_CE_C7 => JEDEC_WREN,
            _ => return 0,
        };

        if preop[0] == wanted_preop {
            1
        } else if preop[1] == wanted_preop {
            2
        } else {
            0
        }
    }

    fn program_ich7_opcodes(&self) {
        self.spibar
            .write16(ICH7_REG_PREOP, u16::from_le_bytes(self.opcodes.preop));
        self.spibar.write16(ICH7_REG_OPTYPE, self.opcodes.optype());
        let opmenu = self.opcodes.opmenu();
        self.spibar.write32(ICH7_REG_OPMENU, opmenu as u32);
        self.spibar
            .write32(ICH7_REG_OPMENU + 4, (opmenu >> 32) as u32);
    }

    fn program_ich9_opcodes(&self) {
        self.spibar
            .write16(ICH9_REG_PREOP, u16::from_le_bytes(self.opcodes.preop));
        self.spibar.write16(ICH9_REG_OPTYPE, self.opcodes.optype());
        let opmenu = self.opcodes.opmenu();
        self.spibar.write32(ICH9_REG_OPMENU, opmenu as u32);
        self.spibar
            .write32(ICH9_REG_OPMENU + 4, (opmenu >> 32) as u32);
    }

    /// Determine the operating mode based on hardware and user request.
    ///
    /// ICH7 and ICH8 use software sequencing. Later descriptor-capable
    /// chipsets default to hardware sequencing when possible.
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
            if self.generation == IchChipset::Ich8 {
                log::error!("Hardware sequencing is not supported on ICH8: FPB is undocumented");
                return Err(SpiError::NotSupported);
            }
        } else if requested == SpiMode::SoftwareSequencing {
            if self.generation.is_pch100_compatible() {
                log::error!("Software sequencing is not implemented for PCH100+ register layout");
                return Err(SpiError::NotSupported);
            }
            if self.swseq_locked {
                log::error!("Software sequencing requested but locked");
                return Err(SpiError::NotSupported);
            }
        }

        // Determine effective mode for Auto
        let effective_mode = if requested != SpiMode::Auto {
            requested
        } else if !self.generation.supports_hwseq() {
            // ICH7: swseq only (hwseq not available)
            log::debug!("Using swseq (ICH7 has no hwseq support)");
            SpiMode::SoftwareSequencing
        } else if self.generation == IchChipset::Ich8 {
            // ICH8 has no documented FPB at the ICH9 offset; use swseq.
            log::debug!("Using swseq on ICH8 (hwseq FPB is undocumented)");
            SpiMode::SoftwareSequencing
        } else if self.desc_valid {
            if self.swseq_locked {
                log::info!("Using hwseq (swseq is locked via DLOCK.SSEQ_LOCKDN)");
            } else {
                log::debug!("Using hwseq (flash descriptor valid)");
            }
            SpiMode::HardwareSequencing
        } else {
            if self.generation.is_pch100_compatible() {
                log::error!(
                    "PCH100+ auto mode requires a valid flash descriptor; swseq offsets are not implemented"
                );
                return Err(SpiError::InvalidDescriptor);
            }
            // No valid flash descriptor - must use swseq.
            log::warn!("Flash descriptor not valid, falling back to swseq");
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

    /// Calculate flash size from flash descriptor regions
    ///
    /// When the flash descriptor is valid, we read all FREG registers to find
    /// the highest region limit, which gives us the total flash size.
    /// If no valid descriptor, we fall back to the maximum addressable size.
    fn calculate_flash_size(&mut self) {
        if !self.desc_valid {
            // No valid descriptor, use max addressable size from address mask
            self.flash_size = self.hwseq_addr_mask + 1;
            log::debug!(
                "No flash descriptor, using max addressable size: {} MB",
                self.flash_size / (1024 * 1024)
            );
            return;
        }

        // Read all 5 FREG registers (FREG0-FREG4) to find highest limit
        // FREG0 = Flash Descriptor, FREG1 = BIOS, FREG2 = ME, FREG3 = GbE, FREG4 = Platform Data
        let mut max_limit: u32 = 0;

        for i in 0..5 {
            let freg = self.spibar.read32(ICH9_REG_FREG0 + (i * 4) as u64);
            let base = freg_base(freg);
            let limit = freg_limit(freg);

            // A valid region has base <= limit
            if base <= limit {
                if limit > max_limit {
                    max_limit = limit;
                }
                log::debug!("FREG{}: base={:#x}, limit={:#x}", i, base, limit);
            }
        }

        // Flash size is the limit + 1 (since limit is the last valid address)
        // Use saturating_add to prevent overflow
        self.flash_size = max_limit.saturating_add(1);

        // Sanity check: flash_size should not exceed address mask capability
        let max_addressable = self.hwseq_addr_mask + 1;
        if self.flash_size > max_addressable {
            log::warn!(
                "Flash size {} MB exceeds addressable range {} MB, capping",
                self.flash_size / (1024 * 1024),
                max_addressable / (1024 * 1024)
            );
            self.flash_size = max_addressable;
        }

        log::info!(
            "Flash size: {} MB (from descriptor)",
            self.flash_size / (1024 * 1024)
        );
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
    ///
    /// Returns an error if the address exceeds the flash size or address mask.
    /// Unlike the previous implementation, this does NOT silently truncate
    /// out-of-range addresses, which could lead to data corruption.
    fn hwseq_set_addr(&self, addr: u32) -> Result<()> {
        // Check if address exceeds flash size
        if addr >= self.flash_size {
            log::error!(
                "Address {:#x} exceeds flash size {:#x}",
                addr,
                self.flash_size
            );
            return Err(SpiError::AddressOutOfRange);
        }

        // Check if address exceeds the hardware address mask
        // This catches addresses that would be silently truncated
        if addr != (addr & self.hwseq_addr_mask) {
            log::error!(
                "Address {:#x} exceeds hardware address space (mask {:#x})",
                addr,
                self.hwseq_addr_mask
            );
            return Err(SpiError::AddressOutOfRange);
        }

        self.spibar.write32(ICH9_REG_FADDR, addr);
        Ok(())
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

        // Validate that the entire read range fits within flash
        let end_addr = addr
            .checked_add(len as u32)
            .ok_or(SpiError::AddressOutOfRange)?;
        if end_addr > self.flash_size {
            log::error!(
                "Read range [{:#x}, {:#x}) exceeds flash size {:#x}",
                addr,
                end_addr,
                self.flash_size
            );
            return Err(SpiError::AddressOutOfRange);
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

            self.hwseq_set_addr(current_addr)?;

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

        // Validate that the entire write range fits within flash
        let end_addr = addr
            .checked_add(len as u32)
            .ok_or(SpiError::AddressOutOfRange)?;
        if end_addr > self.flash_size {
            log::error!(
                "Write range [{:#x}, {:#x}) exceeds flash size {:#x}",
                addr,
                end_addr,
                self.flash_size
            );
            return Err(SpiError::AddressOutOfRange);
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

            self.hwseq_set_addr(current_addr)?;

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
        let end_addr = addr.checked_add(len).ok_or(SpiError::AddressOutOfRange)?;

        // Validate that the entire erase range fits within flash
        if end_addr > self.flash_size {
            log::error!(
                "Erase range [{:#x}, {:#x}) exceeds flash size {:#x}",
                addr,
                end_addr,
                self.flash_size
            );
            return Err(SpiError::AddressOutOfRange);
        }

        // Clear any pending status
        let hsfs = self.spibar.read16(ICH9_REG_HSFS);
        self.spibar.write16(ICH9_REG_HSFS, hsfs);

        while current_addr < end_addr {
            self.hwseq_set_addr(current_addr)?;

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

    fn swseq_addr_mask(&self) -> Result<u32> {
        if self.generation.is_pch100_compatible() {
            Err(SpiError::NotSupported)
        } else {
            // Only 3-byte address opcodes are implemented for swseq today.
            Ok(SWSEQ_3B_ADDR_MASK)
        }
    }

    fn validate_swseq_range(&self, addr: u32, len: usize) -> Result<()> {
        if len > u32::MAX as usize {
            return Err(SpiError::AddressOutOfRange);
        }
        let len = len as u32;
        let end = addr.checked_add(len).ok_or(SpiError::AddressOutOfRange)?;
        if end > self.flash_size {
            return Err(SpiError::AddressOutOfRange);
        }

        let mask = self.swseq_addr_mask()?;
        if len != 0 {
            let last = end - 1;
            if addr != (addr & mask) || last != (last & mask) {
                return Err(SpiError::AddressOutOfRange);
            }
            if let Some(lower_bound) = self.swseq_bbar_lower_bound
                && addr < lower_bound
            {
                log::error!(
                    "Swseq range starts below effective BBAR lower bound: addr={:#x}, BBAR={:#x}",
                    addr,
                    lower_bound
                );
                return Err(SpiError::AddressOutOfRange);
            }
        }

        Ok(())
    }

    fn swseq_read(&mut self, addr: u32, buf: &mut [u8]) -> Result<()> {
        self.validate_swseq_range(addr, buf.len())?;
        let op = self
            .opcodes
            .find(JEDEC_READ)
            .ok_or(SpiError::NotSupported)?;
        let mut offset = 0;
        while offset < buf.len() {
            let chunk = (buf.len() - offset).min(SWSEQ_MAX_DATA);
            self.run_swseq_opcode(op, addr + offset as u32, &mut buf[offset..offset + chunk])?;
            offset += chunk;
        }
        Ok(())
    }

    fn swseq_write(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        if !self.writes_enabled {
            return Err(SpiError::WriteProtected);
        }
        self.validate_swseq_range(addr, data.len())?;
        let op = self
            .opcodes
            .find(JEDEC_BYTE_PROGRAM)
            .ok_or(SpiError::NotSupported)?;
        let mut offset = 0;
        while offset < data.len() {
            let page_remaining = 256 - ((addr as usize + offset) & 0xff);
            let chunk = (data.len() - offset)
                .min(SWSEQ_MAX_DATA)
                .min(page_remaining);
            let mut scratch = [0u8; SWSEQ_MAX_DATA];
            scratch[..chunk].copy_from_slice(&data[offset..offset + chunk]);
            self.run_swseq_opcode(op, addr + offset as u32, &mut scratch[..chunk])?;
            self.swseq_wait_wip(SPI_WRITE_TIMEOUT_US)?;
            offset += chunk;
        }
        Ok(())
    }

    fn swseq_erase(&mut self, addr: u32, len: u32) -> Result<()> {
        if !self.writes_enabled {
            return Err(SpiError::WriteProtected);
        }
        const ERASE_SIZE: u32 = 4096;
        if addr & (ERASE_SIZE - 1) != 0 || len & (ERASE_SIZE - 1) != 0 {
            return Err(SpiError::InvalidArgument);
        }
        self.validate_swseq_range(addr, len as usize)?;
        let op = self.opcodes.find(JEDEC_SE).ok_or(SpiError::NotSupported)?;
        let mut current = addr;
        let end = addr.checked_add(len).ok_or(SpiError::AddressOutOfRange)?;
        while current < end {
            self.run_swseq_opcode(op, current, &mut [])?;
            self.swseq_wait_wip(SPI_WRITE_TIMEOUT_US)?;
            current += ERASE_SIZE;
        }
        Ok(())
    }

    fn run_swseq_opcode(&mut self, op: Opcode, addr: u32, data: &mut [u8]) -> Result<()> {
        if self.generation == IchChipset::Ich7 {
            self.run_ich7_opcode(op, addr, data)
        } else {
            self.run_ich9_opcode(op, addr, data)
        }
    }

    fn opcode_index(&self, op: Opcode) -> Result<u8> {
        self.opcodes
            .table
            .iter()
            .position(|candidate| candidate.code == op.code)
            .map(|i| i as u8)
            .ok_or(SpiError::NotSupported)
    }

    fn swseq_wait_wip(&mut self, timeout_us: u32) -> Result<()> {
        let op = self
            .opcodes
            .find(JEDEC_RDSR)
            .ok_or(SpiError::NotSupported)?;
        let mut elapsed = 0;
        loop {
            let mut status = [0u8; 1];
            self.run_swseq_opcode(op, 0, &mut status)?;
            if status[0] & 1 == 0 {
                return Ok(());
            }
            if elapsed >= timeout_us {
                return Err(SpiError::Timeout);
            }
            delay_us(10);
            elapsed += 10;
        }
    }

    fn run_ich7_opcode(&mut self, op: Opcode, addr: u32, data: &mut [u8]) -> Result<()> {
        let is_write = matches!(op.kind, OpcodeType::Write | OpcodeType::AddressWrite);
        let index = self.opcode_index(op)?;
        let mut elapsed = 0;
        while self.spibar.read16(ICH7_REG_SPIS) & SPIS_SCIP != 0 {
            if elapsed >= SPI_CYCLE_TIMEOUT_US {
                return Err(SpiError::Timeout);
            }
            delay_us(10);
            elapsed += 10;
        }

        let old_addr = self.spibar.read32(ICH7_REG_SPIA) & !0x00ff_ffff;
        self.spibar
            .write32(ICH7_REG_SPIA, old_addr | (addr & 0x00ff_ffff));
        if is_write && !data.is_empty() {
            self.write_ich7_data(data);
        }

        let mut spis = self.spibar.read16(ICH7_REG_SPIS) & SPIS_RESERVED_MASK;
        spis |= SPIS_CDS | SPIS_FCERR;
        self.spibar.write16(ICH7_REG_SPIS, spis);

        let mut spic = ((index as u16) << 4) & 0x0070;
        if !data.is_empty() {
            spic |= SPIC_DS | (((data.len() as u16 - 1) & 0x3f) << 8);
        }
        if op.atomic == 2 {
            spic |= SPIC_SPOP;
        }
        if op.atomic != 0 {
            spic |= SPIC_ACS;
        }
        spic |= SPIC_SCGO;
        self.spibar.write16(ICH7_REG_SPIC, spic);

        self.wait_ich7_cycle(if op.atomic == 0 {
            SPI_CYCLE_TIMEOUT_US
        } else {
            SPI_WRITE_TIMEOUT_US
        })?;
        if !is_write && !data.is_empty() {
            self.read_ich7_data(data);
        }
        Ok(())
    }

    fn run_ich9_opcode(&mut self, op: Opcode, addr: u32, data: &mut [u8]) -> Result<()> {
        let is_write = matches!(op.kind, OpcodeType::Write | OpcodeType::AddressWrite);
        let index = self.opcode_index(op)?;
        let mut elapsed = 0;
        while self.spibar.read8(ICH9_REG_SSFS) as u32 & SSFS_SCIP != 0 {
            if elapsed >= SPI_CYCLE_TIMEOUT_US {
                return Err(SpiError::Timeout);
            }
            delay_us(10);
            elapsed += 10;
        }

        let old_addr = self.spibar.read32(ICH9_REG_FADDR) & !ICH9_FADDR_FLA;
        self.spibar
            .write32(ICH9_REG_FADDR, old_addr | (addr & SWSEQ_3B_ADDR_MASK));
        if is_write && !data.is_empty() {
            self.write_fdata(data);
        }

        let mut ssfsc =
            self.spibar.read32(ICH9_REG_SSFS) & (SSFS_RESERVED_MASK | SSFC_RESERVED_MASK);
        ssfsc |= SSFS_FDONE | SSFS_FCERR | SSFC_SCF_20MHZ;
        if !data.is_empty() {
            ssfsc |= SSFC_DS | (((data.len() as u32 - 1) << SSFC_DBC_OFF) & SSFC_DBC);
        }
        ssfsc |= (index as u32) << SSFC_COP_OFF;
        if op.atomic == 2 {
            ssfsc |= SSFC_SPOP;
        }
        if op.atomic != 0 {
            ssfsc |= SSFC_ACS;
        }
        ssfsc |= SSFC_SCGO;
        self.spibar.write32(ICH9_REG_SSFS, ssfsc);

        self.wait_ich9_cycle(if op.atomic == 0 {
            SPI_CYCLE_TIMEOUT_US
        } else {
            SPI_WRITE_TIMEOUT_US
        })?;
        if !is_write && !data.is_empty() {
            self.read_fdata(data);
        }
        Ok(())
    }

    fn wait_ich7_cycle(&self, timeout_us: u32) -> Result<()> {
        let mut elapsed = 0;
        loop {
            let spis = self.spibar.read16(ICH7_REG_SPIS);
            if spis & (SPIS_CDS | SPIS_FCERR) != 0 {
                if spis & SPIS_FCERR != 0 {
                    self.spibar
                        .write16(ICH7_REG_SPIS, (spis & SPIS_RESERVED_MASK) | SPIS_FCERR);
                    return Err(SpiError::CycleError);
                }
                self.spibar
                    .write16(ICH7_REG_SPIS, (spis & SPIS_RESERVED_MASK) | SPIS_CDS);
                return Ok(());
            }
            if elapsed >= timeout_us {
                return Err(SpiError::Timeout);
            }
            delay_us(10);
            elapsed += 10;
        }
    }

    fn wait_ich9_cycle(&self, timeout_us: u32) -> Result<()> {
        let mut elapsed = 0;
        loop {
            let ssfsc = self.spibar.read32(ICH9_REG_SSFS);
            if ssfsc & (SSFS_FDONE | SSFS_FCERR) != 0 {
                if ssfsc & SSFS_FCERR != 0 {
                    self.spibar.write32(
                        ICH9_REG_SSFS,
                        (ssfsc & (SSFS_RESERVED_MASK | SSFC_RESERVED_MASK)) | SSFS_FCERR,
                    );
                    return Err(SpiError::CycleError);
                }
                self.spibar.write32(
                    ICH9_REG_SSFS,
                    (ssfsc & (SSFS_RESERVED_MASK | SSFC_RESERVED_MASK)) | SSFS_FDONE,
                );
                return Ok(());
            }
            if elapsed >= timeout_us {
                return Err(SpiError::Timeout);
            }
            delay_us(10);
            elapsed += 10;
        }
    }

    fn read_ich7_data(&self, buf: &mut [u8]) {
        for (i, byte) in buf.iter_mut().enumerate() {
            let word = self.spibar.read32(ICH7_REG_SPID0 + (i & !3) as u64);
            *byte = (word >> ((i & 3) * 8)) as u8;
        }
    }

    fn write_ich7_data(&self, data: &[u8]) {
        for (i, chunk) in data.chunks(4).enumerate() {
            let mut word = 0u32;
            for (j, byte) in chunk.iter().enumerate() {
                word |= (*byte as u32) << (j * 8);
            }
            self.spibar.write32(ICH7_REG_SPID0 + (i * 4) as u64, word);
        }
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
            SpiMode::SoftwareSequencing => self.swseq_read(addr, buf),
            SpiMode::Auto => unreachable!("Mode should be resolved during init"),
        }
    }

    fn write(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        match self.mode {
            SpiMode::HardwareSequencing => self.hwseq_write(addr, data),
            SpiMode::SoftwareSequencing => self.swseq_write(addr, data),
            SpiMode::Auto => unreachable!("Mode should be resolved during init"),
        }
    }

    fn erase(&mut self, addr: u32, len: u32) -> Result<()> {
        match self.mode {
            SpiMode::HardwareSequencing => self.hwseq_erase(addr, len),
            SpiMode::SoftwareSequencing => self.swseq_erase(addr, len),
            SpiMode::Auto => unreachable!("Mode should be resolved during init"),
        }
    }

    fn mode(&self) -> SpiMode {
        self.mode
    }

    fn get_bios_region(&self) -> Option<(u32, u32)> {
        // Only return BIOS region if flash descriptor is valid
        if !self.desc_valid {
            return None;
        }

        // Read FREG1 (BIOS region) - offset 0x58 = FREG0 (0x54) + 4
        let freg1 = self.spibar.read32(ICH9_REG_FREG0 + 4);
        let base = freg_base(freg1);
        let limit = freg_limit(freg1);

        // Check if region is valid (base <= limit)
        if base > limit {
            log::debug!(
                "BIOS region disabled (base {:#x} > limit {:#x})",
                base,
                limit
            );
            return None;
        }

        log::debug!(
            "BIOS region (FREG1): base={:#x}, limit={:#x}, size={} KB",
            base,
            limit,
            (limit - base + 1) / 1024
        );

        Some((base, limit))
    }
}
