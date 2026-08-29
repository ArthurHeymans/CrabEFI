//! AHCI (Advanced Host Controller Interface) driver for CrabEFI
//!
//! This module provides a minimal AHCI driver for reading from SATA devices.
//! It implements the basic AHCI command set needed for booting.

pub mod logic;
pub mod regs;

use crate::barrier;
use crate::drivers::pci::{self, PciDevice};
use crate::efi;
use crate::efi::dma::{DmaBuffer, DmaCoherency, DmaDirection, DmaMask};
use crate::time::{Timeout, wait_for};
use core::ptr;
use spin::Mutex;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

use logic::{
    AtaAddressing, SignatureKind, classify_signature, encode_read_fis, identify_geometry,
    read_range_valid,
};
use regs::*;

/// Command Header (32 bytes)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CommandHeader {
    /// DW0: Command FIS Length (0-4), flags (5-15), PRDTL (16-31)
    pub dw0: u32,
    /// DW1: Physical Region Descriptor Byte Count (updated by HBA)
    pub prdbc: u32,
    /// DW2: Command Table Base Address (low)
    pub ctba: u32,
    /// DW3: Command Table Base Address (high)
    pub ctbau: u32,
    /// DW4-7: Reserved
    pub reserved: [u32; 4],
}

impl CommandHeader {
    /// Set command FIS length (in DWORDs)
    fn set_cfl(&mut self, len: u8) {
        self.dw0 = (self.dw0 & !0x1F) | ((len as u32) & 0x1F);
    }

    /// Set write bit
    fn set_write(&mut self, write: bool) {
        if write {
            self.dw0 |= 1 << 6;
        } else {
            self.dw0 &= !(1 << 6);
        }
    }

    /// Set PRDT length (stored in upper 16 bits of DW0)
    fn set_prdtl(&mut self, len: u16) {
        self.dw0 = (self.dw0 & 0xFFFF) | ((len as u32) << 16);
    }

    /// Set command table address
    fn set_ctba(&mut self, addr: u64) {
        self.ctba = addr as u32;
        self.ctbau = (addr >> 32) as u32;
    }

    /// Initialise a command header for an ATAPI command
    fn init_atapi(&mut self) {
        self.dw0 = 0;
        self.set_cfl(5);
        self.set_write(false);
        self.set_prdtl(1);
        self.dw0 |= 1 << 5; // ATAPI bit
        self.prdbc = 0;
    }
}

/// Extract the ATA model string from an IDENTIFY buffer (words 27-46).
///
/// ATA strings are stored with bytes swapped within each 16-bit word.
/// Returns a 40-byte buffer containing the model string.
fn extract_ata_model(identify: &[u16]) -> [u8; 40] {
    let mut model = [0u8; 40];
    for i in 0..20 {
        let word = identify[27 + i];
        model[i * 2] = (word >> 8) as u8;
        model[i * 2 + 1] = (word & 0xFF) as u8;
    }
    model
}

/// FIS Register - Host to Device (20 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct FisRegH2D {
    /// FIS Type (0x27)
    pub fis_type: u8,
    /// Port multiplier, Command bit
    pub pm_c: u8,
    /// Command register
    pub command: u8,
    /// Feature register (low)
    pub feature_l: u8,
    /// LBA low (bits 0-7)
    pub lba0: u8,
    /// LBA mid (bits 8-15)
    pub lba1: u8,
    /// LBA high (bits 16-23)
    pub lba2: u8,
    /// Device register
    pub device: u8,
    /// LBA (bits 24-31)
    pub lba3: u8,
    /// LBA (bits 32-39)
    pub lba4: u8,
    /// LBA (bits 40-47)
    pub lba5: u8,
    /// Feature register (high)
    pub feature_h: u8,
    /// Count (low)
    pub count_l: u8,
    /// Count (high)
    pub count_h: u8,
    /// Isochronous command completion
    pub icc: u8,
    /// Control register
    pub control: u8,
    /// Reserved
    pub reserved: [u8; 4],
}

impl FisRegH2D {
    fn new() -> Self {
        Self {
            fis_type: FIS_TYPE_REG_H2D,
            pm_c: 0x80, // Command bit set
            ..Default::default()
        }
    }

    fn set_command(&mut self, cmd: u8) {
        self.command = cmd;
    }
}

/// Physical Region Descriptor Table Entry (16 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct PrdtEntry {
    /// Data Base Address (low)
    pub dba: u32,
    /// Data Base Address (high)
    pub dbau: u32,
    /// Reserved
    pub reserved: u32,
    /// Byte Count (bit 0 = interrupt on completion, bits 1-21 = byte count - 1)
    pub dbc: u32,
}

impl PrdtEntry {
    fn set_address(&mut self, addr: u64) {
        self.dba = addr as u32;
        self.dbau = (addr >> 32) as u32;
    }

    fn set_byte_count(&mut self, count: u32, interrupt: bool) -> Result<(), AhciError> {
        if count == 0 || count > 4 * 1024 * 1024 {
            return Err(AhciError::InvalidParameter);
        }
        self.dbc = (count - 1) | if interrupt { 1u32 << 31 } else { 0 };
        Ok(())
    }
}

/// Command Table (varies by PRDT length, minimum 128 bytes)
#[repr(C, align(128))]
pub struct CommandTable {
    /// Command FIS (64 bytes)
    pub cfis: [u8; 64],
    /// ATAPI Command (16 bytes)
    pub acmd: [u8; 16],
    /// Reserved (48 bytes)
    pub reserved: [u8; 48],
    /// PRDT entries (up to 65535, but we only use a few)
    pub prdt: [PrdtEntry; 8],
}

impl Default for CommandTable {
    fn default() -> Self {
        Self {
            cfis: [0; 64],
            acmd: [0; 16],
            reserved: [0; 48],
            prdt: [PrdtEntry::default(); 8],
        }
    }
}

/// Received FIS structure (256 bytes)
#[repr(C, align(256))]
#[derive(Clone, Copy)]
pub struct ReceivedFis {
    /// DMA Setup FIS
    pub dsfis: [u8; 28],
    pub reserved0: [u8; 4],
    /// PIO Setup FIS
    pub psfis: [u8; 20],
    pub reserved1: [u8; 12],
    /// D2H Register FIS
    pub rfis: [u8; 20],
    pub reserved2: [u8; 4],
    /// Set Device Bits FIS
    pub sdbfis: [u8; 8],
    /// Unknown FIS
    pub ufis: [u8; 64],
    pub reserved3: [u8; 96],
}

impl Default for ReceivedFis {
    fn default() -> Self {
        Self {
            dsfis: [0; 28],
            reserved0: [0; 4],
            psfis: [0; 20],
            reserved1: [0; 12],
            rfis: [0; 20],
            reserved2: [0; 4],
            sdbfis: [0; 8],
            ufis: [0; 64],
            reserved3: [0; 96],
        }
    }
}

/// AHCI Port state
pub struct AhciPort {
    /// Port number
    pub port_num: u8,
    /// Command list (32 entries, 1KB)
    cmd_list: *mut CommandHeader,
    /// Received FIS (256 bytes)
    // This field appears unused but must be kept alive — the HBA hardware
    // writes DMA data to the memory this pointer refers to.
    #[allow(dead_code)]
    received_fis: *mut ReceivedFis,
    /// Command tables (one per command slot)
    cmd_tables: [*mut CommandTable; 32],
    /// Owns all memory programmed into CLB/FB/CTBA registers.
    _cmd_list_dma: DmaBuffer,
    _received_fis_dma: DmaBuffer,
    _cmd_tables_dma: DmaBuffer,
    /// Device type
    pub device_type: DeviceType,
    /// Sector count (for SATA drives)
    pub sector_count: u64,
    /// Sector size
    pub sector_size: u32,
    /// ATA address encoding selected from IDENTIFY DEVICE.
    addressing: Option<AtaAddressing>,
}

/// Device type detected on port
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    None,
    Sata,
    Satapi,
    Semb,
    PortMultiplier,
}

const PCI_VENDOR_ID_INTEL: u16 = 0x8086;
const INTEL_PCS_6: u16 = 0x92;

fn needs_intel_pcs_quirk(pci_dev: &PciDevice) -> bool {
    if pci_dev.vendor_id != PCI_VENDOR_ID_INTEL {
        return false;
    }

    // Linux marks Cougar Point/Patsburg/Panther Point AHCI and RAID IDs with
    // AHCI_HFLAG_INTEL_PCS_QUIRK.  X220 is CPT-M AHCI (8086:1c03).
    matches!(
        pci_dev.device_id,
        0x1c02
            | 0x1c03
            | 0x1c04
            | 0x1c05
            | 0x1c06
            | 0x1c07
            | 0x1d02
            | 0x1d04
            | 0x1d06
            | 0x1e02
            | 0x1e03
            | 0x1e04
            | 0x1e05
            | 0x1e06
            | 0x1e07
            | 0x1e0e
    )
}

/// AHCI Controller
pub struct AhciController {
    /// PCI address (bus:device.function)
    pci_address: pci::PciAddress,
    /// MMIO base address (for port register calculation)
    mmio_base: u64,
    /// Number of command slots
    num_cmd_slots: u8,
    /// Ports implemented bitmap
    ports_implemented: u32,
    /// Whether PxCMD.CLO is implemented.
    supports_clo: bool,
    /// Address mask applied to every HBA-visible allocation.
    dma_mask: DmaMask,
    /// Active ports
    ports: heapless::Vec<AhciPort, 32>,
}

/// AHCI error type
#[derive(Debug)]
pub enum AhciError {
    /// No device on port
    NoDevice,
    /// Port not ready
    PortNotReady,
    /// Command failed
    CommandFailed,
    /// Timeout
    Timeout,
    /// Allocation failed
    AllocationFailed,
    /// Invalid parameter
    InvalidParameter,
    /// AHCI mode could not be established.
    AhciModeUnavailable,
    /// Host reset did not complete.
    ResetFailed,
    /// Port recovery could not produce a usable link/engine.
    RecoveryFailed,
    /// Device does not advertise usable LBA addressing.
    UnsupportedAddressing,
    /// DMA allocation or synchronization failed.
    DmaError,
}

impl core::fmt::Display for AhciError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AhciError::NoDevice => write!(f, "no device on port"),
            AhciError::PortNotReady => write!(f, "port not ready"),
            AhciError::CommandFailed => write!(f, "command failed"),
            AhciError::Timeout => write!(f, "timeout"),
            AhciError::AllocationFailed => write!(f, "allocation failed"),
            AhciError::InvalidParameter => write!(f, "invalid parameter"),
            AhciError::AhciModeUnavailable => write!(f, "AHCI mode unavailable"),
            AhciError::ResetFailed => write!(f, "HBA reset failed"),
            AhciError::RecoveryFailed => write!(f, "port recovery failed"),
            AhciError::UnsupportedAddressing => write!(f, "unsupported ATA addressing"),
            AhciError::DmaError => write!(f, "DMA synchronization failed"),
        }
    }
}

impl AhciController {
    /// Get reference to port registers
    #[inline]
    fn port_regs(&self, port: u8) -> &AhciPortRegisters {
        let port_addr = self.mmio_base + PORT_BASE + (port as u64) * PORT_SIZE;
        unsafe { &*(port_addr as *const AhciPortRegisters) }
    }

    fn apply_intel_pcs_quirk(&self, pci_dev: &PciDevice) {
        if !needs_intel_pcs_quirk(pci_dev) {
            return;
        }

        // Intel PCH SATA exposes a PCI PCS register which gates physical ports.
        // Linux's ahci_intel_pcs_quirk() enables every implemented AHCI port
        // after controller reset; without this, the X220 dock/SATAPI port can
        // be visible in PI but fail commands.
        let port_map = (self.ports_implemented & 0x3f) as u16;
        let pcs = pci::read_config16(pci_dev.address, INTEL_PCS_6);
        if (pcs & port_map) != port_map {
            let new_pcs = pcs | port_map;
            pci::write_config16(pci_dev.address, INTEL_PCS_6, new_pcs);
            log::debug!(
                "AHCI: Intel PCS quirk enabled ports ({:#06x} -> {:#06x})",
                pcs,
                new_pcs
            );
        }
    }

    fn enable_ahci_mode(hba: &AhciHbaRegisters) -> Result<(), AhciError> {
        for _ in 0..5 {
            hba.ghc.modify(GHC::AE::SET);
            if hba.ghc.is_set(GHC::AE) {
                return Ok(());
            }
            crate::time::delay_us(10_000);
        }
        Err(AhciError::AhciModeUnavailable)
    }

    fn bios_handoff(hba: &AhciHbaRegisters) -> Result<(), AhciError> {
        if !hba.cap2.is_set(CAP2::BOH) || !hba.bohc.is_set(BOHC::BOS) {
            return Ok(());
        }
        hba.bohc.modify(BOHC::OOS::SET);
        if wait_for(1000, || {
            !hba.bohc.is_set(BOHC::BOS) && !hba.bohc.is_set(BOHC::BB)
        }) {
            Ok(())
        } else {
            log::error!("AHCI: BIOS/OS handoff failed, BOHC={:#x}", hba.bohc.get());
            Err(AhciError::ResetFailed)
        }
    }

    fn reset_hba(hba: &AhciHbaRegisters) -> Result<(), AhciError> {
        hba.ghc.modify(GHC::HR::SET);
        if !wait_for(1000, || !hba.ghc.is_set(GHC::HR)) {
            return Err(AhciError::ResetFailed);
        }
        Self::enable_ahci_mode(hba)
    }

    fn allocate_dma(&self, len: usize) -> Result<DmaBuffer, AhciError> {
        DmaBuffer::allocate(len, self.dma_mask, DmaCoherency::Coherent)
            .map_err(|_| AhciError::AllocationFailed)
    }

    /// Create a new AHCI controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, AhciError> {
        let mmio_base = pci_dev.mmio_base().ok_or(AhciError::NoDevice)?;
        let hba_regs = mmio_base as *const AhciHbaRegisters;

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        log::debug!("AHCI: MMIO base at {:#x}", mmio_base);

        let hba = unsafe { &*hba_regs };

        Self::enable_ahci_mode(hba)?;
        Self::bios_handoff(hba)?;
        log::debug!("AHCI: Resetting HBA...");
        Self::reset_hba(hba)?;
        log::debug!("AHCI: HBA reset complete, AHCI mode enabled");

        // Read capabilities using typed access
        let num_cmd_slots = (hba.cap.read(CAP::NCS) + 1) as u8;
        let num_ports = (hba.cap.read(CAP::NP) + 1) as u8;
        let ports_implemented = hba.pi.get();
        let supports_sss = hba.cap.is_set(CAP::SSS);
        let supports_clo = hba.cap.is_set(CAP::SCLO);
        let dma_mask = if hba.cap.is_set(CAP::S64A) {
            DmaMask::bits64()
        } else {
            DmaMask::bits32()
        };

        // Read version
        let major = hba.vs.read(VS::MJR);
        let minor = hba.vs.read(VS::MNR);
        log::info!("AHCI version: {}.{}", major, minor);
        log::debug!(
            "AHCI CAP: {:#x}, ports={}, cmd_slots={}, SSS={}",
            hba.cap.get(),
            num_ports,
            num_cmd_slots,
            supports_sss
        );

        let mut controller = Self {
            pci_address: pci_dev.address,
            mmio_base,
            num_cmd_slots,
            ports_implemented,
            supports_clo,
            dma_mask,
            ports: heapless::Vec::new(),
        };

        controller.apply_intel_pcs_quirk(pci_dev);

        // Initialize ports (pass SSS capability)
        controller.init_ports_with_sss(supports_sss)?;

        Ok(controller)
    }

    /// Initialize all implemented ports (with staggered spin-up support)
    fn init_ports_with_sss(&mut self, supports_sss: bool) -> Result<(), AhciError> {
        for port_num in 0..32u8 {
            if self.ports_implemented & (1 << port_num) == 0 {
                continue;
            }

            log::debug!("AHCI: Probing port {}...", port_num);

            let port_regs = self.port_regs(port_num);

            // If staggered spin-up is supported, spin up the device
            if supports_sss {
                port_regs.cmd.modify(PORT_CMD::SUD::SET);
            }

            // Wait for port to become active
            let is_first = self.ports.is_empty();
            let wait_time_ms = if supports_sss || is_first { 100 } else { 10 };

            let timeout = Timeout::from_ms(wait_time_ms);
            while !timeout.is_expired() {
                let det = port_regs.ssts.read(PORT_SSTS::DET);
                let ipm = port_regs.ssts.read(PORT_SSTS::IPM);
                if det == 3 && ipm == 1 {
                    break;
                }
                crate::time::delay_us(100);
            }

            // Require stable communication, but give DET=1/slow links one COMRESET.
            let mut det = port_regs.ssts.read(PORT_SSTS::DET);
            if det != 3 && self.comreset_port(port_num) {
                det = self.port_regs(port_num).ssts.read(PORT_SSTS::DET);
            }
            let ipm = self.port_regs(port_num).ssts.read(PORT_SSTS::IPM);
            if det != 3 {
                log::debug!(
                    "AHCI Port {}: No stable link (DET={}, IPM={})",
                    port_num,
                    det,
                    ipm
                );
                continue;
            }

            // Clear error and interrupt status before init
            port_regs.serr.set(0xFFFFFFFF);
            port_regs.is.set(0xFFFFFFFF);

            // Device is connected - initialize the port
            match self.init_port(port_num) {
                Ok(port) => {
                    if port.device_type == DeviceType::Sata {
                        log::info!(
                            "AHCI Port {}: SATA drive, {} sectors",
                            port_num,
                            port.sector_count
                        );
                        if let Err(port) = self.ports.push(port) {
                            log::warn!("AHCI: Failed to add port {} - port list full", port_num);
                            self.discard_port(port)?;
                        }
                    } else if port.device_type == DeviceType::Satapi {
                        if port.sector_count == 0 {
                            log::info!(
                                "AHCI Port {}: SATAPI device has no readable media; stopping unused port",
                                port_num
                            );
                            self.discard_port(port)?;
                        } else {
                            log::info!(
                                "AHCI Port {}: SATAPI device, {} sectors (sector_size={})",
                                port_num,
                                port.sector_count,
                                port.sector_size
                            );
                            if let Err(port) = self.ports.push(port) {
                                log::warn!(
                                    "AHCI: Failed to add port {} - port list full",
                                    port_num
                                );
                                self.discard_port(port)?;
                            }
                        }
                    } else {
                        log::info!(
                            "AHCI Port {}: {:?} device is unsupported; stopping port",
                            port_num,
                            port.device_type
                        );
                        self.discard_port(port)?;
                    }
                }
                Err(e) => {
                    log::error!("Failed to initialize port {}: {:?}", port_num, e);
                }
            }
        }

        log::info!("AHCI: {} ports initialized", self.ports.len());
        Ok(())
    }

    /// Initialize a single port
    fn init_port(&mut self, port_num: u8) -> Result<AhciPort, AhciError> {
        // Stop command processing
        self.stop_port(port_num)?;

        let cmd_list_dma = self.allocate_dma(1024)?;
        let received_fis_dma = self.allocate_dma(256)?;
        let cmd_tables_dma = self
            .allocate_dma(usize::from(self.num_cmd_slots) * core::mem::size_of::<CommandTable>())?;
        let cmd_list_addr = cmd_list_dma.dma_address();
        let received_fis_addr = received_fis_dma.dma_address();
        let cmd_tables_page = cmd_tables_dma.dma_address();
        let mut cmd_tables = [ptr::null_mut(); 32];

        for (i, cmd_table) in cmd_tables
            .iter_mut()
            .enumerate()
            .take(self.num_cmd_slots as usize)
        {
            let table_addr = cmd_tables_page + (i * 256) as u64;
            *cmd_table = table_addr as *mut CommandTable;

            // Set command table address in command header
            let header = unsafe { &mut *(cmd_list_addr as *mut CommandHeader).add(i) };
            header.set_ctba(table_addr);
        }

        // Set command list and FIS addresses (re-borrow port_regs for this block)
        {
            let port_regs = self.port_regs(port_num);
            port_regs.clb.set(cmd_list_addr as u32);
            port_regs.clbu.set((cmd_list_addr >> 32) as u32);
            port_regs.fb.set(received_fis_addr as u32);
            port_regs.fbu.set((received_fis_addr >> 32) as u32);

            // Clear error register
            port_regs.serr.set(0xFFFFFFFF);

            // Clear interrupt status
            port_regs.is.set(0xFFFFFFFF);
        }

        // Start command processing
        self.start_port(port_num)?;

        // Put port into active state and wait for ready.
        let mut ready = false;
        {
            let port_regs = self.port_regs(port_num);
            port_regs.cmd.modify(PORT_CMD::ICC::Active);
            let timeout = Timeout::from_ms(30000);
            while !timeout.is_expired() {
                if !port_regs.tfd.is_set(PORT_TFD::STS_BSY)
                    && !port_regs.tfd.is_set(PORT_TFD::STS_DRQ)
                {
                    ready = true;
                    break;
                }
                crate::time::delay_us(10000);
            }
        }

        if !ready {
            log::warn!(
                "AHCI Port {}: device busy after start; issuing COMRESET",
                port_num
            );
            if !self.comreset_port(port_num) {
                return Err(AhciError::PortNotReady);
            }
            self.start_port(port_num)?;
            if !wait_for(5000, || {
                let regs = self.port_regs(port_num);
                !regs.tfd.is_set(PORT_TFD::STS_BSY) && !regs.tfd.is_set(PORT_TFD::STS_DRQ)
            }) {
                return Err(AhciError::PortNotReady);
            }
        }

        // Read the signature
        let sig = self.port_regs(port_num).sig.get();

        let device_type = match classify_signature(sig) {
            Some(SignatureKind::Sata) => DeviceType::Sata,
            Some(SignatureKind::Satapi) => DeviceType::Satapi,
            Some(SignatureKind::Semb) => DeviceType::Semb,
            Some(SignatureKind::PortMultiplier) => DeviceType::PortMultiplier,
            None => {
                log::warn!("AHCI port {}: invalid signature {:#x}", port_num, sig);
                self.stop_port(port_num)?;
                return Err(AhciError::NoDevice);
            }
        };

        let mut port = AhciPort {
            port_num,
            cmd_list: cmd_list_addr as *mut CommandHeader,
            received_fis: received_fis_addr as *mut ReceivedFis,
            cmd_tables,
            _cmd_list_dma: cmd_list_dma,
            _received_fis_dma: received_fis_dma,
            _cmd_tables_dma: cmd_tables_dma,
            device_type,
            sector_count: 0,
            sector_size: 512,
            addressing: None,
        };

        // Identify the device
        if device_type == DeviceType::Sata {
            if let Err(error) = self.identify_device(&mut port) {
                let _ = self.stop_port(port_num);
                return Err(error);
            }
        } else if device_type == DeviceType::Satapi {
            if let Err(error) = self.identify_device_atapi(&mut port) {
                let _ = self.stop_port(port_num);
                return Err(error);
            }
        } else {
            self.stop_port(port_num)?;
            return Err(AhciError::NoDevice);
        }

        Ok(port)
    }

    /// Stop command processing on a port
    fn discard_port(&mut self, port: AhciPort) -> Result<(), AhciError> {
        match self.stop_port(port.port_num) {
            Ok(()) => Ok(()),
            Err(error) => {
                // The HBA may still own these pages. Leak rather than returning
                // them to the allocator while DMA can continue.
                core::mem::forget(port);
                Err(error)
            }
        }
    }

    fn stop_port(&mut self, port_num: u8) -> Result<(), AhciError> {
        let port_regs = self.port_regs(port_num);

        // Clear ST (Start) bit
        port_regs.cmd.modify(PORT_CMD::ST::CLEAR);

        // Wait for CR (Command List Running) to clear (AHCI spec: up to 500ms)
        if !wait_for(500, || !port_regs.cmd.is_set(PORT_CMD::CR)) {
            log::error!("AHCI Port {}: Timeout waiting for CR to clear", port_num);
            return Err(AhciError::RecoveryFailed);
        }

        // Clear FRE (FIS Receive Enable) bit
        port_regs.cmd.modify(PORT_CMD::FRE::CLEAR);

        // Wait for FR (FIS Receive Running) to clear
        if !wait_for(500, || !port_regs.cmd.is_set(PORT_CMD::FR)) {
            log::error!("AHCI Port {}: Timeout waiting for FR to clear", port_num);
            return Err(AhciError::RecoveryFailed);
        }
        Ok(())
    }

    /// Start command processing on a port
    fn start_port(&mut self, port_num: u8) -> Result<(), AhciError> {
        let port_regs = self.port_regs(port_num);

        // Wait for CR to clear before starting new commands
        if !wait_for(500, || !port_regs.cmd.is_set(PORT_CMD::CR)) {
            return Err(AhciError::RecoveryFailed);
        }

        // Enable FIS receive
        port_regs.cmd.modify(PORT_CMD::FRE::SET);

        // Enable command processing
        port_regs.cmd.modify(PORT_CMD::ST::SET);

        Ok(())
    }

    /// Find a free command slot
    fn find_free_slot(&self, port_num: u8) -> Option<u8> {
        let port_regs = self.port_regs(port_num);
        let sact = port_regs.sact.get();
        let ci = port_regs.ci.get();
        let slots = sact | ci;

        (0..self.num_cmd_slots).find(|&i| slots & (1 << i) == 0)
    }

    /// Issue a command and wait for completion
    ///
    /// On error or timeout, performs port recovery per AHCI spec section 6.2.2:
    /// stops the command engine, clears error bits, and restarts.
    fn issue_command(&mut self, port: &AhciPort, slot: u8) -> Result<(), AhciError> {
        self.issue_command_on_port(port.port_num, slot)
    }

    /// Identify a SATA device
    fn identify_device(&mut self, port: &mut AhciPort) -> Result<(), AhciError> {
        let slot = self
            .find_free_slot(port.port_num)
            .ok_or(AhciError::PortNotReady)?;

        // Allocate buffer for identify data (512 bytes)
        let mut buffer = self.allocate_dma(512)?;
        buffer.as_mut_slice().fill(0);
        let buffer_addr = buffer.dma_address();
        buffer
            .sync_for_device(0..buffer.len(), DmaDirection::FromDevice)
            .map_err(|_| AhciError::DmaError)?;

        // Setup command header
        let header = unsafe { &mut *port.cmd_list.add(slot as usize) };
        header.dw0 = 0;
        header.set_cfl(5); // 5 DWORDs for H2D FIS
        header.set_write(false);
        header.set_prdtl(1);
        header.prdbc = 0;

        // Setup command table
        let table = unsafe { &mut *port.cmd_tables[slot as usize] };
        *table = CommandTable::default();

        // Setup FIS
        let fis = unsafe { &mut *(table.cfis.as_mut_ptr() as *mut FisRegH2D) };
        *fis = FisRegH2D::new();
        fis.set_command(ATA_CMD_IDENTIFY);

        // Setup PRDT
        table.prdt[0].set_address(buffer_addr);
        table.prdt[0].set_byte_count(512, true)?;

        // Issue command
        self.issue_command(port, slot)?;

        buffer
            .sync_for_cpu(0..buffer.len(), DmaDirection::FromDevice)
            .map_err(|_| AhciError::DmaError)?;
        let identify =
            unsafe { core::slice::from_raw_parts(buffer.dma_address() as *const u16, 256) };

        let identify_array: &[u16; 256] = identify
            .try_into()
            .map_err(|_| AhciError::UnsupportedAddressing)?;
        let geometry = identify_geometry(identify_array).ok_or(AhciError::UnsupportedAddressing)?;
        port.addressing = Some(geometry.addressing);
        port.sector_count = geometry.sector_count;
        port.sector_size = geometry.sector_size;

        let model = extract_ata_model(identify);
        let model_str = core::str::from_utf8(&model).unwrap_or("Unknown").trim();

        log::info!(
            "AHCI Port {}: {} - {} sectors x {} bytes = {} MB",
            port.port_num,
            model_str,
            port.sector_count,
            port.sector_size,
            (port.sector_count * port.sector_size as u64) / (1024 * 1024)
        );

        Ok(())
    }

    /// Identify a SATAPI device (CD/DVD)
    fn identify_device_atapi(&mut self, port: &mut AhciPort) -> Result<(), AhciError> {
        let slot = self
            .find_free_slot(port.port_num)
            .ok_or(AhciError::PortNotReady)?;

        // Allocate buffer for identify data (512 bytes)
        let mut buffer = self.allocate_dma(512)?;
        buffer.as_mut_slice().fill(0);
        buffer
            .sync_for_device(0..buffer.len(), DmaDirection::FromDevice)
            .map_err(|_| AhciError::DmaError)?;

        // IDENTIFY PACKET DEVICE is an ATA command, not an ATA PACKET command.
        // Do not set the AHCI command-header ATAPI bit here; that bit is only
        // for command 0xA0 with a CDB in CommandTable::acmd.
        let header = unsafe { &mut *port.cmd_list.add(slot as usize) };
        header.dw0 = 0;
        header.set_cfl(5);
        header.set_write(false);
        header.set_prdtl(1);
        header.prdbc = 0;

        // Setup command table
        let table = unsafe { &mut *port.cmd_tables[slot as usize] };
        *table = CommandTable::default();

        // Setup FIS for IDENTIFY PACKET DEVICE
        let fis = unsafe { &mut *(table.cfis.as_mut_ptr() as *mut FisRegH2D) };
        *fis = FisRegH2D::new();
        fis.set_command(ATA_CMD_IDENTIFY_PACKET);

        // Setup PRDT
        let buffer_addr = buffer.dma_address();
        table.prdt[0].set_address(buffer_addr);
        table.prdt[0].set_byte_count(512, true)?;

        // Issue command. Match Linux's first IDENTIFY/IDENTIFY PACKET timeout
        // budget: long enough for real devices, but not a 30s boot stall when
        // the dock bay is empty or confused.
        self.issue_command_on_port_with_timeout(port.port_num, slot, 5000)?;
        buffer
            .sync_for_cpu(0..buffer.len(), DmaDirection::FromDevice)
            .map_err(|_| AhciError::DmaError)?;
        let identify =
            unsafe { core::slice::from_raw_parts(buffer.dma_address() as *const u16, 256) };

        let model = extract_ata_model(identify);
        let model_str = core::str::from_utf8(&model).unwrap_or("Unknown").trim();

        log::info!("AHCI Port {}: ATAPI device: {}", port.port_num, model_str);

        // Now get the capacity using READ CAPACITY
        self.read_capacity_atapi(port)?;

        Ok(())
    }

    /// Read capacity from ATAPI device using SCSI READ CAPACITY(10)
    fn read_capacity_atapi(&mut self, port: &mut AhciPort) -> Result<(), AhciError> {
        let slot = self
            .find_free_slot(port.port_num)
            .ok_or(AhciError::PortNotReady)?;

        // Allocate buffer for capacity data (8 bytes)
        let mut buffer = self.allocate_dma(8)?;
        buffer.as_mut_slice().fill(0);
        let buffer_addr = buffer.dma_address();
        buffer
            .sync_for_device(0..buffer.len(), DmaDirection::FromDevice)
            .map_err(|_| AhciError::DmaError)?;

        // Setup command header (set ATAPI bit)
        let header = unsafe { &mut *port.cmd_list.add(slot as usize) };
        header.init_atapi();

        // Setup command table
        let table = unsafe { &mut *port.cmd_tables[slot as usize] };
        *table = CommandTable::default();

        // Setup FIS for ATAPI PACKET command
        let fis = unsafe { &mut *(table.cfis.as_mut_ptr() as *mut FisRegH2D) };
        *fis = FisRegH2D::new();
        fis.set_command(ATA_CMD_PACKET);
        fis.feature_l = 1; // DMA mode (required for AHCI DMA transfers)
        fis.lba1 = 8; // Byte count limit (low)
        fis.lba2 = 0; // Byte count limit (high)

        // Setup ATAPI command (SCSI READ CAPACITY(10))
        table.acmd[0] = SCSI_CMD_READ_CAPACITY_10;

        // Setup PRDT
        table.prdt[0].set_address(buffer_addr);
        table.prdt[0].set_byte_count(8, true)?;

        // Issue command. Empty optical drives can fail this; keep discovery
        // responsive and mark the device as no-media below.
        if let Err(e) = self.issue_command_on_port_with_timeout(port.port_num, slot, 5000) {
            log::warn!("READ CAPACITY failed: {:?}, using defaults", e);
            port.sector_size = 2048;
            port.sector_count = 0;
            return Ok(());
        }

        buffer
            .sync_for_cpu(0..buffer.len(), DmaDirection::FromDevice)
            .map_err(|_| AhciError::DmaError)?;
        let data = &buffer.as_slice()[..8];
        let last_lba = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let block_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        port.sector_count = (last_lba as u64) + 1;
        port.sector_size = block_size;

        log::info!(
            "AHCI Port {}: ATAPI capacity: {} sectors x {} bytes = {} MB",
            port.port_num,
            port.sector_count,
            port.sector_size,
            (port.sector_count * port.sector_size as u64) / (1024 * 1024)
        );

        Ok(())
    }

    /// Maximum sectors per ATA READ DMA EXT command (64KB at 512-byte sectors)
    const MAX_SATA_SECTORS_PER_CMD: u32 = 128;
    /// Maximum sectors per ATAPI PACKET READ(10) command (32KB at 2048-byte sectors)
    /// Limited by the 16-bit byte count field in the PACKET FIS
    const MAX_ATAPI_SECTORS_PER_CMD: u32 = 16;
    /// Maximum number of retries for a failed read
    const MAX_RETRIES: u32 = 3;

    /// Read sectors from a port with automatic chunking and retry
    ///
    /// Large reads are split into chunks appropriate for the device type:
    /// - SATA: 128 sectors (64KB) per ATA READ DMA EXT
    /// - SATAPI: 16 sectors (32KB) per SCSI READ(10) via ATAPI PACKET
    ///
    /// Each chunk is retried up to 3 times on transient errors.
    ///
    /// # Safety
    ///
    /// `buffer` must point to a valid, writable region of at least
    /// `num_sectors * sector_size` bytes.
    pub unsafe fn read_sectors(
        &mut self,
        port_index: usize,
        start_lba: u64,
        num_sectors: u32,
        buffer: *mut u8,
    ) -> Result<(), AhciError> {
        if port_index >= self.ports.len() || num_sectors == 0 || buffer.is_null() {
            return Err(AhciError::InvalidParameter);
        }
        let port = &self.ports[port_index];
        if start_lba
            .checked_add(u64::from(num_sectors))
            .is_none_or(|end| end > port.sector_count)
        {
            return Err(AhciError::InvalidParameter);
        }

        let device_type = port.device_type;
        let sector_size = self.ports[port_index].sector_size;
        let max_chunk = if device_type == DeviceType::Satapi {
            Self::MAX_ATAPI_SECTORS_PER_CMD
        } else {
            Self::MAX_SATA_SECTORS_PER_CMD
        };

        let mut remaining = num_sectors;
        let mut lba = start_lba;
        let mut buf_offset: usize = 0;

        while remaining > 0 {
            let chunk = remaining.min(max_chunk);
            let buf_ptr = unsafe { buffer.add(buf_offset) };

            self.read_chunk_with_retry(port_index, device_type, lba, chunk, buf_ptr, sector_size)?;

            remaining -= chunk;
            lba += chunk as u64;
            buf_offset = buf_offset
                .checked_add(
                    (chunk as usize)
                        .checked_mul(sector_size as usize)
                        .ok_or(AhciError::InvalidParameter)?,
                )
                .ok_or(AhciError::InvalidParameter)?;
        }

        Ok(())
    }

    /// Read a single chunk with retry logic
    fn read_chunk_with_retry(
        &mut self,
        port_index: usize,
        device_type: DeviceType,
        lba: u64,
        num_sectors: u32,
        buffer: *mut u8,
        sector_size: u32,
    ) -> Result<(), AhciError> {
        for attempt in 0..Self::MAX_RETRIES {
            let result = if device_type == DeviceType::Satapi {
                self.read_sectors_atapi(port_index, lba, num_sectors, buffer, sector_size)
            } else {
                self.read_sectors_sata(port_index, lba, num_sectors, buffer)
            };

            match result {
                Ok(()) => return Ok(()),
                Err(AhciError::RecoveryFailed) => return Err(AhciError::RecoveryFailed),
                Err(e) if attempt + 1 < Self::MAX_RETRIES => {
                    log::warn!(
                        "AHCI port {}: read LBA {} failed ({:?}), retry {}/{}",
                        self.ports[port_index].port_num,
                        lba,
                        e,
                        attempt + 1,
                        Self::MAX_RETRIES
                    );
                    crate::time::delay_us(1000);
                }
                Err(e) => return Err(e),
            }
        }
        // All code paths return inside the loop: Ok on success, Err on final attempt
        // (the `Err(e) if attempt + 1 < MAX_RETRIES` guard ensures the last iteration
        // falls through to the unconditional `Err(e)` arm).
        unreachable!("MAX_RETRIES must be >= 1")
    }

    /// Read sectors from a SATA device using READ DMA EXT
    fn read_sectors_sata(
        &mut self,
        port_index: usize,
        start_lba: u64,
        num_sectors: u32,
        buffer: *mut u8,
    ) -> Result<(), AhciError> {
        let port = &self.ports[port_index];
        let port_num = port.port_num;
        let addressing = port.addressing.ok_or(AhciError::UnsupportedAddressing)?;
        if !read_range_valid(addressing, port.sector_count, start_lba, num_sectors) {
            return Err(AhciError::InvalidParameter);
        }
        let byte_count = num_sectors
            .checked_mul(port.sector_size)
            .ok_or(AhciError::InvalidParameter)?;
        let cmd_list = port.cmd_list;
        let cmd_tables = port.cmd_tables;
        let bounce = self.allocate_dma(byte_count as usize)?;
        bounce
            .sync_for_device(0..bounce.len(), DmaDirection::FromDevice)
            .map_err(|_| AhciError::DmaError)?;
        let slot = self
            .find_free_slot(port_num)
            .ok_or(AhciError::PortNotReady)?;
        let header = unsafe { &mut *cmd_list.add(slot as usize) };
        header.dw0 = 0;
        header.set_cfl(5);
        header.set_write(false);
        header.set_prdtl(1);
        header.prdbc = 0;
        let table = unsafe { &mut *cmd_tables[slot as usize] };
        *table = CommandTable::default();
        let encoded = encode_read_fis(addressing, start_lba, num_sectors)
            .ok_or(AhciError::InvalidParameter)?;
        let fis = unsafe { &mut *(table.cfis.as_mut_ptr() as *mut FisRegH2D) };
        *fis = FisRegH2D::new();
        fis.command = encoded.command;
        fis.lba0 = encoded.lba[0];
        fis.lba1 = encoded.lba[1];
        fis.lba2 = encoded.lba[2];
        fis.lba3 = encoded.lba[3];
        fis.lba4 = encoded.lba[4];
        fis.lba5 = encoded.lba[5];
        fis.device = encoded.device;
        fis.count_l = encoded.count_low;
        fis.count_h = encoded.count_high;
        table.prdt[0].set_address(bounce.dma_address());
        table.prdt[0].set_byte_count(byte_count, true)?;
        self.issue_command_on_port(port_num, slot)?;
        bounce
            .sync_for_cpu(0..bounce.len(), DmaDirection::FromDevice)
            .map_err(|_| AhciError::DmaError)?;
        unsafe {
            ptr::copy_nonoverlapping(
                bounce.dma_address() as *const u8,
                buffer,
                byte_count as usize,
            )
        };
        Ok(())
    }

    /// Read sectors from a SATAPI device using ATAPI PACKET
    fn read_sectors_atapi(
        &mut self,
        port_index: usize,
        start_lba: u64,
        num_sectors: u32,
        buffer: *mut u8,
        sector_size: u32,
    ) -> Result<(), AhciError> {
        let port = &self.ports[port_index];
        if start_lba > u32::MAX as u64
            || num_sectors == 0
            || num_sectors > u16::MAX as u32
            || start_lba
                .checked_add(num_sectors as u64)
                .is_none_or(|end| end > port.sector_count)
        {
            return Err(AhciError::InvalidParameter);
        }
        let port_num = port.port_num;
        let cmd_list = port.cmd_list;
        let cmd_tables = port.cmd_tables;
        let byte_count = num_sectors
            .checked_mul(sector_size)
            .ok_or(AhciError::InvalidParameter)?;
        let bounce = self.allocate_dma(byte_count as usize)?;
        bounce
            .sync_for_device(0..bounce.len(), DmaDirection::FromDevice)
            .map_err(|_| AhciError::DmaError)?;
        let slot = self
            .find_free_slot(port_num)
            .ok_or(AhciError::PortNotReady)?;
        let header = unsafe { &mut *cmd_list.add(slot as usize) };
        header.init_atapi();
        let table = unsafe { &mut *cmd_tables[slot as usize] };
        *table = CommandTable::default();
        let fis = unsafe { &mut *(table.cfis.as_mut_ptr() as *mut FisRegH2D) };
        *fis = FisRegH2D::new();
        fis.set_command(ATA_CMD_PACKET);
        fis.feature_l = 1;
        let byte_count_hint = byte_count.min(0xfffe);
        fis.lba1 = byte_count_hint as u8;
        fis.lba2 = (byte_count_hint >> 8) as u8;
        table.acmd[0] = SCSI_CMD_READ_10;
        table.acmd[2] = (start_lba >> 24) as u8;
        table.acmd[3] = (start_lba >> 16) as u8;
        table.acmd[4] = (start_lba >> 8) as u8;
        table.acmd[5] = start_lba as u8;
        table.acmd[7] = (num_sectors >> 8) as u8;
        table.acmd[8] = num_sectors as u8;
        table.prdt[0].set_address(bounce.dma_address());
        table.prdt[0].set_byte_count(byte_count, true)?;
        self.issue_command_on_port(port_num, slot)?;
        bounce
            .sync_for_cpu(0..bounce.len(), DmaDirection::FromDevice)
            .map_err(|_| AhciError::DmaError)?;
        unsafe {
            ptr::copy_nonoverlapping(
                bounce.dma_address() as *const u8,
                buffer,
                byte_count as usize,
            )
        };
        Ok(())
    }

    /// Issue a command on a port by number and wait for completion
    ///
    /// On error or timeout, performs AHCI error recovery per spec section 6.2.2:
    /// 1. Stop the command engine (clear PxCMD.ST)
    /// 2. Clear error bits (PxSERR, PxIS)
    /// 3. Restart the command engine (set PxCMD.ST)
    fn issue_command_on_port(&mut self, port_num: u8, slot: u8) -> Result<(), AhciError> {
        self.issue_command_on_port_with_timeout(port_num, slot, 30000)
    }

    fn issue_command_on_port_with_timeout(
        &mut self,
        port_num: u8,
        slot: u8,
        timeout_ms: u64,
    ) -> Result<(), AhciError> {
        barrier::mmio_write();
        let port_regs = self.port_regs(port_num);
        port_regs.is.set(u32::MAX);
        port_regs.serr.set(u32::MAX);
        port_regs.ci.set(1 << slot);
        const FATAL_IS: u32 = (1 << 30) | (1 << 29) | (1 << 28) | (1 << 27) | (1 << 24);
        let timeout = Timeout::from_ms(timeout_ms);
        let mut failure = None;
        while !timeout.is_expired() {
            let interrupt_status = port_regs.is.get();
            if interrupt_status & FATAL_IS != 0 {
                failure = Some(AhciError::CommandFailed);
                break;
            }
            if port_regs.ci.get() & (1 << slot) == 0 {
                if port_regs.tfd.is_set(PORT_TFD::STS_ERR)
                    || port_regs.tfd.is_set(PORT_TFD::STS_BSY)
                    || port_regs.tfd.is_set(PORT_TFD::STS_DRQ)
                    || port_regs.is.get() & FATAL_IS != 0
                {
                    failure = Some(AhciError::CommandFailed);
                    break;
                }
                return Ok(());
            }
            core::hint::spin_loop();
        }
        let failure = failure.unwrap_or(AhciError::Timeout);
        self.log_port_diagnostics(port_num, slot, timeout_ms);
        match self.recover_port(port_num) {
            Ok(()) => Err(failure),
            Err(_) => Err(AhciError::RecoveryFailed),
        }
    }

    fn log_port_diagnostics(&self, port_num: u8, slot: u8, timeout_ms: u64) {
        let regs = self.port_regs(port_num);
        barrier::dma_read();
        let clb = u64::from(regs.clb.get()) | (u64::from(regs.clbu.get()) << 32);
        let fb = u64::from(regs.fb.get()) | (u64::from(regs.fbu.get()) << 32);
        let prdbc = if clb == 0 {
            0
        } else {
            unsafe { ptr::read_volatile((clb as *const CommandHeader).add(slot as usize)) }.prdbc
        };
        let (d2h_status, d2h_error) = if fb == 0 {
            (0, 0)
        } else {
            let received = unsafe { &*(fb as *const ReceivedFis) };
            (received.rfis[2], received.rfis[3])
        };
        log::error!(
            "AHCI {} port {} slot {} failure (budget={}ms): CMD={:#x} CI={:#x} SACT={:#x} IS={:#x} SERR={:#x} TFD={:#x} SSTS={:#x} SIG={:#x} PRDBC={} D2H status/error={:#04x}/{:#04x}",
            self.pci_address,
            port_num,
            slot,
            timeout_ms,
            regs.cmd.get(),
            regs.ci.get(),
            regs.sact.get(),
            regs.is.get(),
            regs.serr.get(),
            regs.tfd.get(),
            regs.ssts.get(),
            regs.sig.get(),
            prdbc,
            d2h_status,
            d2h_error
        );
    }

    fn kick_engine_with_clo(&self, port_num: u8) -> bool {
        if !self.supports_clo {
            return false;
        }
        let regs = self.port_regs(port_num);
        regs.cmd.modify(PORT_CMD::CLO::SET);
        wait_for(500, || !regs.cmd.is_set(PORT_CMD::CLO))
    }

    fn debounce_link(&self, port_num: u8) -> bool {
        let regs = self.port_regs(port_num);
        let timeout = Timeout::from_ms(2000);
        while !timeout.is_expired() {
            crate::time::delay_us(5000);
            let det = regs.ssts.read(PORT_SSTS::DET);
            if det != 1 {
                crate::time::delay_us(100_000);
                if regs.ssts.read(PORT_SSTS::DET) == det {
                    return det == 3;
                }
            }
        }
        false
    }

    fn comreset_port(&self, port_num: u8) -> bool {
        let regs = self.port_regs(port_num);
        regs.cmd.modify(PORT_CMD::ST::CLEAR);
        if !wait_for(500, || !regs.cmd.is_set(PORT_CMD::CR)) {
            log::error!(
                "AHCI port {}: COMRESET aborted because CR stayed set",
                port_num
            );
            return false;
        }
        regs.cmd.modify(PORT_CMD::FRE::CLEAR);
        if !wait_for(500, || !regs.cmd.is_set(PORT_CMD::FR)) {
            log::error!(
                "AHCI port {}: COMRESET aborted because FR stayed set",
                port_num
            );
            return false;
        }
        let saved_sctl = regs.sctl.get() & !0xf;
        regs.sctl.set(saved_sctl | 1);
        let _ = regs.sctl.get();
        crate::time::delay_us(1000);
        regs.sctl.set(saved_sctl);
        let _ = regs.sctl.get();
        regs.cmd.modify(PORT_CMD::ICC::Active);
        self.debounce_link(port_num)
    }

    fn recover_port(&mut self, port_num: u8) -> Result<(), AhciError> {
        let regs = self.port_regs(port_num);
        regs.cmd.modify(PORT_CMD::ST::CLEAR);
        let stopped = wait_for(500, || !regs.cmd.is_set(PORT_CMD::CR));
        regs.cmd.modify(PORT_CMD::FRE::CLEAR);
        let fis_stopped = wait_for(500, || !regs.cmd.is_set(PORT_CMD::FR));
        let busy = regs.tfd.is_set(PORT_TFD::STS_BSY) || regs.tfd.is_set(PORT_TFD::STS_DRQ);
        let clo_ok = !busy || self.kick_engine_with_clo(port_num);
        if busy && !clo_ok {
            log::warn!(
                "AHCI {} port {}: CLO unavailable or timed out; falling back to COMRESET",
                self.pci_address,
                port_num
            );
        }
        let need_reset = !stopped
            || !fis_stopped
            || !clo_ok
            || regs.ci.get() != 0
            || regs.tfd.is_set(PORT_TFD::STS_BSY)
            || regs.tfd.is_set(PORT_TFD::STS_DRQ)
            || regs.ssts.read(PORT_SSTS::DET) != 3;
        if need_reset && !self.comreset_port(port_num) {
            log::error!(
                "AHCI {} port {}: COMRESET failed/offline",
                self.pci_address,
                port_num
            );
            return Err(AhciError::RecoveryFailed);
        }
        regs.serr.set(u32::MAX);
        regs.is.set(u32::MAX);
        let hba = unsafe { &*(self.mmio_base as *const AhciHbaRegisters) };
        hba.is.set(1 << port_num);
        if !wait_for(5000, || {
            regs.ssts.read(PORT_SSTS::DET) == 3
                && !regs.tfd.is_set(PORT_TFD::STS_BSY)
                && !regs.tfd.is_set(PORT_TFD::STS_DRQ)
                && regs.ci.get() == 0
                && regs.sact.get() == 0
                && !regs.cmd.is_set(PORT_CMD::CR)
                && !regs.cmd.is_set(PORT_CMD::FR)
        }) {
            log::error!(
                "AHCI {} port {}: recovery did not reach a ready link (CMD={:#x} CI={:#x} SACT={:#x} SSTS={:#x} TFD={:#x})",
                self.pci_address,
                port_num,
                regs.cmd.get(),
                regs.ci.get(),
                regs.sact.get(),
                regs.ssts.get(),
                regs.tfd.get()
            );
            return Err(AhciError::RecoveryFailed);
        }
        regs.cmd.modify(PORT_CMD::FRE::SET);
        regs.cmd.modify(PORT_CMD::ST::SET);
        log::warn!(
            "AHCI {} port {} recovered: CMD={:#x} SSTS={:#x} TFD={:#x}",
            self.pci_address,
            port_num,
            regs.cmd.get(),
            regs.ssts.get(),
            regs.tfd.get()
        );
        Ok(())
    }

    /// Get the number of active ports
    pub fn num_active_ports(&self) -> usize {
        self.ports.len()
    }

    /// Get port info
    pub fn get_port(&self, index: usize) -> Option<&AhciPort> {
        self.ports.get(index)
    }

    /// Get the PCI address of this controller
    pub fn pci_address(&self) -> pci::PciAddress {
        self.pci_address
    }

    // ========================================================================
    // Security Commands (TCG Opal, IEEE 1667)
    // ========================================================================

    /// ATA TRUSTED RECEIVE (command 0x5C)
    ///
    /// Receives data from the security subsystem (e.g., TCG Opal response).
    ///
    /// # Arguments
    /// * `port_index` - Port index
    /// * `protocol_id` - Security Protocol ID (0x00=enumerate, 0x01=TCG, 0xEE=IEEE 1667)
    /// * `sp_specific` - Protocol-specific value (e.g., ComID for TCG)
    /// * `buffer` - Buffer to receive data
    ///
    /// # Returns
    /// Number of bytes transferred on success
    pub fn trusted_receive(
        &mut self,
        port_index: usize,
        protocol_id: u8,
        sp_specific: u16,
        buffer: &mut [u8],
    ) -> Result<usize, AhciError> {
        if port_index >= self.ports.len() {
            return Err(AhciError::InvalidParameter);
        }

        if buffer.is_empty() || buffer.len() > 65536 {
            return Err(AhciError::InvalidParameter);
        }

        log::debug!(
            "AHCI Trusted Receive: port={}, protocol={:#x}, sp_specific={:#x}, len={}",
            port_index,
            protocol_id,
            sp_specific,
            buffer.len()
        );

        let port_num = self.ports[port_index].port_num;
        let cmd_list = self.ports[port_index].cmd_list;
        let cmd_tables = self.ports[port_index].cmd_tables;

        let slot = self
            .find_free_slot(port_num)
            .ok_or(AhciError::PortNotReady)?;

        // Allocate an aligned DMA buffer large enough for the protocol's
        // 512-byte-block rounded transfer length.
        let transfer_blocks = (buffer.len() as u32).div_ceil(512);
        let transfer_len = (transfer_blocks as usize) * 512;
        let dma_buffer = self.allocate_dma(transfer_len)?;
        let dma_addr = dma_buffer.dma_address();
        dma_buffer
            .sync_for_device(0..dma_buffer.len(), DmaDirection::FromDevice)
            .map_err(|_| AhciError::DmaError)?;

        // Setup command header
        let header = unsafe { &mut *cmd_list.add(slot as usize) };
        header.dw0 = 0;
        header.set_cfl(5); // 5 DWORDs for H2D FIS
        header.set_write(false); // Read from device
        header.set_prdtl(1);
        header.prdbc = 0;

        // Setup command table
        let table = unsafe { &mut *cmd_tables[slot as usize] };
        *table = CommandTable::default();

        // Setup FIS for TRUSTED RECEIVE DMA
        // The ATA TRUSTED RECEIVE DMA command layout:
        // - Command: 0x5C
        // - Features (7:0): Security Protocol
        // - LBA (15:0): Transfer Length in 512-byte blocks
        // - LBA (31:24): Security Protocol Specific (high byte)
        // - Device (7:0): Security Protocol Specific (low byte) | 0x40 (LBA mode)
        let fis = unsafe { &mut *(table.cfis.as_mut_ptr() as *mut FisRegH2D) };
        *fis = FisRegH2D::new();
        fis.set_command(ATA_CMD_TRUSTED_RECEIVE_DMA);
        fis.feature_l = protocol_id;

        // Transfer length in 512-byte blocks
        fis.lba0 = (transfer_blocks & 0xFF) as u8;
        fis.lba1 = ((transfer_blocks >> 8) & 0xFF) as u8;
        fis.lba2 = 0;
        fis.lba3 = (sp_specific >> 8) as u8;
        fis.device = ((sp_specific & 0xFF) as u8) | 0x40; // LBA mode

        // Setup PRDT
        table.prdt[0].set_address(dma_addr);
        table.prdt[0].set_byte_count(transfer_blocks * 512, true)?;

        // Issue command
        let result = self.issue_command_on_port(port_num, slot);

        // Copy data from DMA buffer to caller's buffer
        let bytes_transferred = if result.is_ok() {
            dma_buffer
                .sync_for_cpu(0..dma_buffer.len(), DmaDirection::FromDevice)
                .map_err(|_| AhciError::DmaError)?;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    dma_buffer.dma_address() as *const u8,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                );
            }
            buffer.len()
        } else {
            0
        };

        result.map(|_| {
            log::debug!(
                "AHCI Trusted Receive: {} bytes transferred",
                bytes_transferred
            );
            bytes_transferred
        })
    }

    /// ATA TRUSTED SEND (command 0x5E)
    ///
    /// Sends data to the security subsystem (e.g., TCG Opal command).
    ///
    /// # Arguments
    /// * `port_index` - Port index
    /// * `protocol_id` - Security Protocol ID (0x00=enumerate, 0x01=TCG, 0xEE=IEEE 1667)
    /// * `sp_specific` - Protocol-specific value (e.g., ComID for TCG)
    /// * `buffer` - Buffer containing data to send
    ///
    /// # Returns
    /// Ok(()) on success
    pub fn trusted_send(
        &mut self,
        port_index: usize,
        protocol_id: u8,
        sp_specific: u16,
        buffer: &[u8],
    ) -> Result<(), AhciError> {
        if port_index >= self.ports.len() {
            return Err(AhciError::InvalidParameter);
        }

        if buffer.is_empty() || buffer.len() > 65536 {
            return Err(AhciError::InvalidParameter);
        }

        log::debug!(
            "AHCI Trusted Send: port={}, protocol={:#x}, sp_specific={:#x}, len={}",
            port_index,
            protocol_id,
            sp_specific,
            buffer.len()
        );

        let port_num = self.ports[port_index].port_num;
        let cmd_list = self.ports[port_index].cmd_list;
        let cmd_tables = self.ports[port_index].cmd_tables;

        let slot = self
            .find_free_slot(port_num)
            .ok_or(AhciError::PortNotReady)?;

        // Allocate an aligned DMA buffer large enough for the protocol's
        // 512-byte-block rounded transfer length.
        let transfer_blocks = (buffer.len() as u32).div_ceil(512);
        let transfer_len = (transfer_blocks as usize) * 512;
        let mut dma_buffer = self.allocate_dma(transfer_len)?;
        let dma_addr = dma_buffer.dma_address();

        // Zero-fill rounded padding before device ownership.
        dma_buffer.as_mut_slice().fill(0);
        dma_buffer.as_mut_slice()[..buffer.len()].copy_from_slice(buffer);
        dma_buffer
            .sync_for_device(0..dma_buffer.len(), DmaDirection::ToDevice)
            .map_err(|_| AhciError::DmaError)?;

        // Setup command header
        let header = unsafe { &mut *cmd_list.add(slot as usize) };
        header.dw0 = 0;
        header.set_cfl(5); // 5 DWORDs for H2D FIS
        header.set_write(true); // Write to device
        header.set_prdtl(1);
        header.prdbc = 0;

        // Setup command table
        let table = unsafe { &mut *cmd_tables[slot as usize] };
        *table = CommandTable::default();

        // Setup FIS for TRUSTED SEND DMA
        // The ATA TRUSTED SEND DMA command layout:
        // - Command: 0x5E
        // - Features (7:0): Security Protocol
        // - LBA (15:0): Transfer Length in 512-byte blocks
        // - LBA (31:24): Security Protocol Specific (high byte)
        // - Device (7:0): Security Protocol Specific (low byte) | 0x40 (LBA mode)
        let fis = unsafe { &mut *(table.cfis.as_mut_ptr() as *mut FisRegH2D) };
        *fis = FisRegH2D::new();
        fis.set_command(ATA_CMD_TRUSTED_SEND_DMA);
        fis.feature_l = protocol_id;

        // Transfer length in 512-byte blocks
        fis.lba0 = (transfer_blocks & 0xFF) as u8;
        fis.lba1 = ((transfer_blocks >> 8) & 0xFF) as u8;
        fis.lba2 = 0;
        fis.lba3 = (sp_specific >> 8) as u8;
        fis.device = ((sp_specific & 0xFF) as u8) | 0x40; // LBA mode

        // Setup PRDT
        table.prdt[0].set_address(dma_addr);
        table.prdt[0].set_byte_count(transfer_blocks * 512, true)?;

        // Issue command
        let result = self.issue_command_on_port(port_num, slot);

        result.map(|_| {
            log::debug!("AHCI Trusted Send: success");
        })
    }

    fn shutdown_controller(&mut self) {
        let hba = unsafe { &*(self.mmio_base as *const AhciHbaRegisters) };
        hba.ghc.modify(GHC::IE::CLEAR);
        for port_num in 0..32u8 {
            if self.ports_implemented & (1 << port_num) == 0 {
                continue;
            }
            let regs = self.port_regs(port_num);
            regs.ie.set(0);
            regs.cmd.modify(PORT_CMD::ST::CLEAR);
            let cr_clear = wait_for(500, || !regs.cmd.is_set(PORT_CMD::CR));
            regs.cmd.modify(PORT_CMD::FRE::CLEAR);
            let fr_clear = wait_for(500, || !regs.cmd.is_set(PORT_CMD::FR));
            if !cr_clear || !fr_clear {
                log::error!(
                    "AHCI {} port {}: handoff quiesce failed CMD={:#x} CI={:#x} SACT={:#x}",
                    self.pci_address,
                    port_num,
                    regs.cmd.get(),
                    regs.ci.get(),
                    regs.sact.get()
                );
            } else {
                log::debug!(
                    "AHCI {} port {} quiesced: ST/CR/FRE/FR clear",
                    self.pci_address,
                    port_num
                );
            }
            regs.is.set(u32::MAX);
            regs.serr.set(u32::MAX);
            hba.is.set(1 << port_num);
        }
    }
}

/// Registry of initialized AHCI controllers
static AHCI_CONTROLLERS: super::ControllerRegistry<AhciController, 4> =
    super::ControllerRegistry::new("AHCI");

/// Initialize a single AHCI controller from a PCI device
///
/// Called by the PCI driver model when an AHCI device is discovered.
///
/// # Arguments
/// * `dev` - The PCI device to initialize as an AHCI controller
pub fn init_device(dev: &pci::PciDevice) -> Result<(), ()> {
    log::info!(
        "Initializing AHCI controller at {}: {:04x}:{:04x}",
        dev.address,
        dev.vendor_id,
        dev.device_id
    );

    let controller = AhciController::new(dev).map_err(|e| {
        log::error!(
            "Failed to initialize AHCI controller at {}: {:?}",
            dev.address,
            e
        );
    })?;

    AHCI_CONTROLLERS.register(controller)?;
    log::info!("AHCI controller at {} initialized", dev.address);
    Ok(())
}

/// Shutdown all AHCI controllers
///
/// Called during ExitBootServices to prepare for OS handoff.
pub fn shutdown() {
    let controllers = AHCI_CONTROLLERS.controllers.lock();
    for controller in controllers.iter() {
        // SAFETY: the registry lock excludes other controller users.
        unsafe { &mut *controller.0 }.shutdown_controller();
    }
    drop(controllers);
    AHCI_CONTROLLERS.shutdown_log();
}

/// Initialize AHCI controllers (legacy entry point)
///
/// Scans PCI bus for AHCI controllers and initializes each one.
/// Prefer using `init_device()` via the PCI driver model instead.
pub fn init() {
    log::info!("Initializing AHCI controllers...");

    let ahci_devices = pci::find_ahci_controllers();

    if ahci_devices.is_empty() {
        log::info!("No AHCI controllers found");
        return;
    }

    for dev in ahci_devices.iter() {
        let _ = init_device(dev);
    }

    log::info!(
        "AHCI initialization complete: {} controllers",
        AHCI_CONTROLLERS.count()
    );
}

/// Get a raw pointer to an AHCI controller
///
/// Returns a raw pointer rather than `&'static mut` to avoid aliasing UB.
/// Callers must ensure they do not create overlapping mutable references.
///
/// # Safety
///
/// The returned pointer is valid for the firmware lifetime. Callers must
/// convert to `&mut` only for the duration of their immediate operation
/// and must not hold the reference across calls that may also access
/// the same controller.
pub fn get_controller(index: usize) -> Option<*mut AhciController> {
    AHCI_CONTROLLERS.get(index)
}

// SAFETY: AhciController contains raw pointers to MMIO registers and DMA buffers.
// All access is serialized through the AHCI_CONTROLLERS mutex and firmware is single-threaded.
unsafe impl Send for AhciController {}

// SAFETY: AhciPort contains raw pointers to DMA buffers.
// All port access is serialized through the parent AhciController which is mutex-protected.
unsafe impl Send for AhciPort {}

// ============================================================================
// Global AHCI Device for SimpleFileSystem Protocol
// ============================================================================

/// Global AHCI device info for filesystem reads
struct GlobalAhciDevice {
    controller_index: usize,
    port_index: usize,
}

/// Pointer wrapper for global storage
struct GlobalAhciDevicePtr(*mut GlobalAhciDevice);

// SAFETY: GlobalAhciDevicePtr wraps a pointer to GlobalAhciDevice allocated via EFI.
// All access is protected by the GLOBAL_AHCI_DEVICE mutex.
unsafe impl Send for GlobalAhciDevicePtr {}

/// Global AHCI device for filesystem protocol
static GLOBAL_AHCI_DEVICE: Mutex<Option<GlobalAhciDevicePtr>> = Mutex::new(None);

/// Store AHCI device info globally for SimpleFileSystem protocol
pub fn store_global_device(controller_index: usize, port_index: usize) -> bool {
    let size = core::mem::size_of::<GlobalAhciDevice>();
    let pages = size.div_ceil(4096);

    if let Some(mem) = efi::allocate_pages(pages as u64) {
        let device_ptr = mem.as_mut_ptr() as *mut GlobalAhciDevice;
        unsafe {
            core::ptr::write(
                device_ptr,
                GlobalAhciDevice {
                    controller_index,
                    port_index,
                },
            );
        }

        *GLOBAL_AHCI_DEVICE.lock() = Some(GlobalAhciDevicePtr(device_ptr));
        log::info!(
            "AHCI device stored globally (controller={}, port={})",
            controller_index,
            port_index
        );
        true
    } else {
        log::error!("Failed to allocate memory for global AHCI device");
        false
    }
}

/// Read a sector from the global AHCI device
///
/// The LBA is interpreted as a device block LBA (in terms of the device's native
/// sector size - 512 bytes for SATA, 2048 bytes for SATAPI/CD-ROM).
pub fn global_read_sectors(lba: u64, buffer: &mut [u8]) -> Result<(), ()> {
    let (controller_index, port_index) = match GLOBAL_AHCI_DEVICE.lock().as_ref() {
        Some(ptr) => unsafe {
            let device = &*ptr.0;
            (device.controller_index, device.port_index)
        },
        None => {
            log::error!("global_read_sectors: no AHCI device stored");
            return Err(());
        }
    };

    // Safety: pointer valid for firmware lifetime; no overlapping &mut created
    let controller = match get_controller(controller_index) {
        Some(ptr) => unsafe { &mut *ptr },
        None => {
            log::error!(
                "global_read_sectors: no AHCI controller at index {}",
                controller_index
            );
            return Err(());
        }
    };

    // Compute sector count from buffer size for multi-sector reads.
    // The caller is responsible for providing the correct LBA in device block terms.
    let sector_size = controller
        .get_port(port_index)
        .map(|p| p.sector_size as usize)
        .unwrap_or(512);
    if sector_size == 0 || buffer.is_empty() || !buffer.len().is_multiple_of(sector_size) {
        log::error!(
            "global_read_sectors: buffer length {} is not a non-zero multiple of sector size {}",
            buffer.len(),
            sector_size
        );
        return Err(());
    }
    let num_sectors = u32::try_from(buffer.len() / sector_size).map_err(|_| ())?;

    // Safety: the exact-multiple check above proves the raw read writes exactly
    // `buffer.len()` bytes into this slice.
    unsafe { controller.read_sectors(port_index, lba, num_sectors, buffer.as_mut_ptr()) }.map_err(
        |e| {
            log::error!("global_read_sectors: read failed at LBA {}: {:?}", lba, e);
        },
    )
}

/// Get the sector size of the global AHCI device
pub fn global_sector_size() -> Option<u32> {
    let (controller_index, port_index) = {
        let guard = GLOBAL_AHCI_DEVICE.lock();
        let ptr = guard.as_ref()?;
        unsafe {
            let device = &*ptr.0;
            (device.controller_index, device.port_index)
        }
    };

    // Safety: pointer valid for firmware lifetime; no overlapping &mut created
    let controller = unsafe { &mut *get_controller(controller_index)? };
    let port = controller.get_port(port_index)?;
    Some(port.sector_size)
}
