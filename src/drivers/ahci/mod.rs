//! AHCI (Advanced Host Controller Interface) driver for CrabEFI
//!
//! This module provides a minimal AHCI driver for reading from SATA devices.
//! It implements the basic AHCI command set needed for booting.

pub mod regs;

use crate::drivers::pci::{self, PciDevice};
use crate::efi;
use crate::time::{Timeout, wait_for};
use core::ptr;
use core::sync::atomic::{Ordering, fence};
use spin::Mutex;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

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

    fn set_lba(&mut self, lba: u64) {
        self.lba0 = (lba & 0xFF) as u8;
        self.lba1 = ((lba >> 8) & 0xFF) as u8;
        self.lba2 = ((lba >> 16) & 0xFF) as u8;
        self.lba3 = ((lba >> 24) & 0xFF) as u8;
        self.lba4 = ((lba >> 32) & 0xFF) as u8;
        self.lba5 = ((lba >> 40) & 0xFF) as u8;
        self.device = 0x40; // LBA mode
    }

    fn set_count(&mut self, count: u16) {
        self.count_l = (count & 0xFF) as u8;
        self.count_h = ((count >> 8) & 0xFF) as u8;
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

    fn set_byte_count(&mut self, count: u32, interrupt: bool) {
        self.dbc = (count - 1) | if interrupt { 1u32 << 31 } else { 0 };
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
    /// Pointer to port registers
    port_regs: *const AhciPortRegisters,
    /// Command list (32 entries, 1KB)
    cmd_list: *mut CommandHeader,
    /// Received FIS (256 bytes)
    #[allow(dead_code)]
    received_fis: *mut ReceivedFis,
    /// Command tables (one per command slot)
    cmd_tables: [*mut CommandTable; 32],
    /// Device type
    pub device_type: DeviceType,
    /// Sector count (for SATA drives)
    pub sector_count: u64,
    /// Sector size
    pub sector_size: u32,
}

impl AhciPort {
    /// Get reference to port registers
    #[inline]
    fn regs(&self) -> &AhciPortRegisters {
        unsafe { &*self.port_regs }
    }
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

/// AHCI Controller
pub struct AhciController {
    /// PCI address (bus:device.function)
    pci_address: pci::PciAddress,
    /// Pointer to HBA registers (kept for potential future use/debugging)
    #[allow(dead_code)]
    hba_regs: *const AhciHbaRegisters,
    /// MMIO base address (for port register calculation)
    mmio_base: u64,
    /// Number of command slots
    num_cmd_slots: u8,
    /// Number of ports
    #[allow(dead_code)]
    num_ports: u8,
    /// Ports implemented bitmap
    ports_implemented: u32,
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
}

impl AhciController {
    /// Get reference to HBA registers (kept for potential future use)
    #[inline]
    #[allow(dead_code)]
    fn hba(&self) -> &AhciHbaRegisters {
        unsafe { &*self.hba_regs }
    }

    /// Get reference to port registers
    #[inline]
    fn port_regs(&self, port: u8) -> &AhciPortRegisters {
        let port_addr = self.mmio_base + PORT_BASE + (port as u64) * PORT_SIZE;
        unsafe { &*(port_addr as *const AhciPortRegisters) }
    }

    /// Create a new AHCI controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, AhciError> {
        let mmio_base = pci_dev.mmio_base().ok_or(AhciError::NoDevice)?;
        let hba_regs = mmio_base as *const AhciHbaRegisters;

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        log::debug!("AHCI: MMIO base at {:#x}", mmio_base);

        let hba = unsafe { &*hba_regs };

        // Reset the HBA first
        log::debug!("AHCI: Resetting HBA...");
        hba.ghc.modify(GHC::HR::SET);

        // Wait for reset to complete (up to 1 second)
        if !wait_for(1000, || !hba.ghc.is_set(GHC::HR)) {
            log::error!("AHCI: HBA reset didn't complete within 1s");
            return Err(AhciError::Timeout);
        }
        log::debug!("AHCI: HBA reset complete");

        // Enable AHCI mode
        hba.ghc.modify(GHC::AE::SET);

        // Read capabilities using typed access
        let num_cmd_slots = (hba.cap.read(CAP::NCS) + 1) as u8;
        let num_ports = (hba.cap.read(CAP::NP) + 1) as u8;
        let ports_implemented = hba.pi.get();
        let supports_sss = hba.cap.is_set(CAP::SSS);

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

        // Perform BIOS/OS handoff if needed
        if hba.cap2.is_set(CAP2::BOH) && hba.bohc.is_set(BOHC::BOS) {
            // BIOS owns the HBA
            log::debug!("Performing BIOS/OS handoff...");
            hba.bohc.modify(BOHC::OOS::SET);
            wait_for(100, || !hba.bohc.is_set(BOHC::BOS));
        }

        let mut controller = Self {
            pci_address: pci_dev.address,
            hba_regs,
            mmio_base,
            num_cmd_slots,
            num_ports,
            ports_implemented,
            ports: heapless::Vec::new(),
        };

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

            // Check if device is present and active
            let det = port_regs.ssts.read(PORT_SSTS::DET);
            let ipm = port_regs.ssts.read(PORT_SSTS::IPM);

            if det != 3 || ipm != 1 {
                log::debug!(
                    "AHCI Port {}: No device (DET={}, IPM={})",
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
                        if self.ports.push(port).is_err() {
                            log::warn!("AHCI: Failed to add port {} - port list full", port_num);
                        }
                    } else if port.device_type == DeviceType::Satapi {
                        log::info!(
                            "AHCI Port {}: SATAPI device, {} sectors (sector_size={})",
                            port_num,
                            port.sector_count,
                            port.sector_size
                        );
                        if self.ports.push(port).is_err() {
                            log::warn!("AHCI: Failed to add port {} - port list full", port_num);
                        }
                    } else {
                        log::info!("AHCI Port {}: {:?} device", port_num, port.device_type);
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
        // Get port register pointer for later use
        let port_regs_ptr = self.port_regs(port_num) as *const AhciPortRegisters;

        // Stop command processing
        self.stop_port(port_num)?;

        // Allocate command list (1KB, 1024-byte aligned)
        let cmd_list_mem = efi::allocate_pages(1).ok_or(AhciError::AllocationFailed)?;
        cmd_list_mem.fill(0);
        let cmd_list_addr = cmd_list_mem.as_ptr() as u64;

        // Allocate received FIS (256 bytes, 256-byte aligned)
        let received_fis_mem = efi::allocate_pages(1).ok_or(AhciError::AllocationFailed)?;
        received_fis_mem.fill(0);
        let received_fis_addr = received_fis_mem.as_ptr() as u64;

        // Allocate command tables (one per slot, 256-byte aligned each)
        let mut cmd_tables = [ptr::null_mut(); 32];
        let cmd_tables_mem = efi::allocate_pages(4).ok_or(AhciError::AllocationFailed)?;
        cmd_tables_mem.fill(0);
        let cmd_tables_page = cmd_tables_mem.as_ptr() as u64;

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

        // Put port into active state and wait for ready
        let port_regs = self.port_regs(port_num);
        port_regs.cmd.modify(PORT_CMD::ICC::Active);

        // Wait for device to become ready (BSY=0, DRQ=0) - up to 30 seconds
        let mut ready = false;
        let timeout = Timeout::from_ms(30000);
        while !timeout.is_expired() {
            if !port_regs.tfd.is_set(PORT_TFD::STS_BSY) && !port_regs.tfd.is_set(PORT_TFD::STS_DRQ)
            {
                ready = true;
                break;
            }
            crate::time::delay_us(10000);
        }

        if !ready {
            log::warn!(
                "AHCI Port {}: Device not ready (TFD={:#x}), trying anyway",
                port_num,
                port_regs.tfd.get()
            );
        }

        // Read the signature
        let sig = port_regs.sig.get();

        // Determine device type from signature
        let device_type = match sig {
            SATA_SIG_ATA => DeviceType::Sata,
            SATA_SIG_ATAPI => DeviceType::Satapi,
            SATA_SIG_SEMB => DeviceType::Semb,
            SATA_SIG_PM => DeviceType::PortMultiplier,
            0xFFFFFFFF | 0x00000000 => DeviceType::Sata,
            _ => DeviceType::None,
        };

        let mut port = AhciPort {
            port_num,
            port_regs: port_regs_ptr,
            cmd_list: cmd_list_addr as *mut CommandHeader,
            received_fis: received_fis_addr as *mut ReceivedFis,
            cmd_tables,
            device_type,
            sector_count: 0,
            sector_size: 512,
        };

        // Identify the device
        if device_type == DeviceType::Sata {
            if let Err(e) = self.identify_device(&mut port) {
                log::warn!("AHCI Port {}: IDENTIFY failed: {:?}", port_num, e);
            }
        } else if device_type == DeviceType::Satapi
            && let Err(e) = self.identify_device_atapi(&mut port)
        {
            log::warn!("AHCI Port {}: IDENTIFY PACKET failed: {:?}", port_num, e);
        }

        Ok(port)
    }

    /// Stop command processing on a port
    fn stop_port(&mut self, port_num: u8) -> Result<(), AhciError> {
        let port_regs = self.port_regs(port_num);

        // Clear ST (Start) bit
        port_regs.cmd.modify(PORT_CMD::ST::CLEAR);

        // Wait for CR (Command List Running) to clear
        wait_for(1, || !port_regs.cmd.is_set(PORT_CMD::CR));

        // Clear FRE (FIS Receive Enable) bit
        port_regs.cmd.modify(PORT_CMD::FRE::CLEAR);

        // Wait for FR (FIS Receive Running) to clear
        if !wait_for(1, || !port_regs.cmd.is_set(PORT_CMD::FR)) {
            log::warn!("AHCI Port {}: Timeout stopping command engine", port_num);
        }
        Ok(())
    }

    /// Start command processing on a port
    fn start_port(&mut self, port_num: u8) -> Result<(), AhciError> {
        let port_regs = self.port_regs(port_num);

        // Wait for CR to clear
        wait_for(1, || !port_regs.cmd.is_set(PORT_CMD::CR));

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
    fn issue_command(&mut self, port: &AhciPort, slot: u8) -> Result<(), AhciError> {
        fence(Ordering::SeqCst);

        let port_regs = port.regs();

        // Issue command
        port_regs.ci.set(1 << slot);

        // Wait for completion (up to 30 seconds)
        let timeout = Timeout::from_ms(30000);
        while !timeout.is_expired() {
            let ci = port_regs.ci.get();
            if ci & (1 << slot) == 0 {
                // Check for errors
                if port_regs.tfd.is_set(PORT_TFD::STS_ERR)
                    || port_regs.tfd.is_set(PORT_TFD::STS_DRQ)
                {
                    log::error!("AHCI command error: TFD={:#x}", port_regs.tfd.get());
                    return Err(AhciError::CommandFailed);
                }
                return Ok(());
            }

            // Check for fatal errors (Task File Error)
            if port_regs.is.is_set(PORT_IS::TFES) {
                log::error!(
                    "AHCI task file error: TFD={:#x}, IS={:#x}",
                    port_regs.tfd.get(),
                    port_regs.is.get()
                );
                return Err(AhciError::CommandFailed);
            }
            core::hint::spin_loop();
        }

        log::error!("AHCI: Command timeout");
        Err(AhciError::Timeout)
    }

    /// Identify a SATA device
    fn identify_device(&mut self, port: &mut AhciPort) -> Result<(), AhciError> {
        let slot = self
            .find_free_slot(port.port_num)
            .ok_or(AhciError::PortNotReady)?;

        // Allocate buffer for identify data (512 bytes)
        let buffer = efi::allocate_pages(1).ok_or(AhciError::AllocationFailed)?;
        buffer.fill(0);
        let buffer_addr = buffer.as_ptr() as u64;

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
        table.prdt[0].set_byte_count(512, true);

        // Issue command
        self.issue_command(port, slot)?;

        // Parse identify data
        let identify = unsafe { core::slice::from_raw_parts(buffer.as_ptr() as *const u16, 256) };

        // Word 60-61: Total number of user addressable sectors (28-bit LBA)
        let lba28_sectors = (identify[61] as u64) << 16 | identify[60] as u64;

        // Word 100-103: Total number of user addressable sectors (48-bit LBA)
        let lba48_sectors = (identify[103] as u64) << 48
            | (identify[102] as u64) << 32
            | (identify[101] as u64) << 16
            | identify[100] as u64;

        port.sector_count = if lba48_sectors > 0 {
            lba48_sectors
        } else {
            lba28_sectors
        };

        // Word 106: Physical/Logical sector size info
        let sector_info = identify[106];
        if sector_info & (1 << 12) != 0 {
            port.sector_size = ((identify[118] as u32) << 16 | identify[117] as u32) * 2;
        } else {
            port.sector_size = 512;
        }

        // Get model number (words 27-46)
        let mut model = [0u8; 40];
        for i in 0..20 {
            let word = identify[27 + i];
            model[i * 2] = (word >> 8) as u8;
            model[i * 2 + 1] = (word & 0xFF) as u8;
        }
        let model_str = core::str::from_utf8(&model).unwrap_or("Unknown").trim();

        log::info!(
            "AHCI Port {}: {} - {} sectors x {} bytes = {} MB",
            port.port_num,
            model_str,
            port.sector_count,
            port.sector_size,
            (port.sector_count * port.sector_size as u64) / (1024 * 1024)
        );

        efi::free_pages(buffer, 1);
        Ok(())
    }

    /// Identify a SATAPI device (CD/DVD)
    fn identify_device_atapi(&mut self, port: &mut AhciPort) -> Result<(), AhciError> {
        let slot = self
            .find_free_slot(port.port_num)
            .ok_or(AhciError::PortNotReady)?;

        // Allocate buffer for identify data (512 bytes)
        let buffer = efi::allocate_pages(1).ok_or(AhciError::AllocationFailed)?;
        buffer.fill(0);

        // Setup command header (set ATAPI bit)
        let header = unsafe { &mut *port.cmd_list.add(slot as usize) };
        header.dw0 = 0;
        header.set_cfl(5);
        header.set_write(false);
        header.set_prdtl(1);
        header.dw0 |= 1 << 5; // ATAPI bit
        header.prdbc = 0;

        // Setup command table
        let table = unsafe { &mut *port.cmd_tables[slot as usize] };
        *table = CommandTable::default();

        // Setup FIS for IDENTIFY PACKET DEVICE
        let fis = unsafe { &mut *(table.cfis.as_mut_ptr() as *mut FisRegH2D) };
        *fis = FisRegH2D::new();
        fis.set_command(ATA_CMD_IDENTIFY_PACKET);

        // Setup PRDT
        let buffer_addr = buffer.as_ptr() as u64;
        table.prdt[0].set_address(buffer_addr);
        table.prdt[0].set_byte_count(512, true);

        // Issue command
        self.issue_command(port, slot)?;

        // Parse identify packet data
        let identify = unsafe { core::slice::from_raw_parts(buffer.as_ptr() as *const u16, 256) };

        // Get model number (words 27-46)
        let mut model = [0u8; 40];
        for i in 0..20 {
            let word = identify[27 + i];
            model[i * 2] = (word >> 8) as u8;
            model[i * 2 + 1] = (word & 0xFF) as u8;
        }
        let model_str = core::str::from_utf8(&model).unwrap_or("Unknown").trim();

        log::info!("AHCI Port {}: ATAPI device: {}", port.port_num, model_str);

        efi::free_pages(buffer, 1);

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
        let buffer = efi::allocate_pages(1).ok_or(AhciError::AllocationFailed)?;
        buffer.fill(0);
        let buffer_addr = buffer.as_ptr() as u64;

        // Setup command header (set ATAPI bit)
        let header = unsafe { &mut *port.cmd_list.add(slot as usize) };
        header.dw0 = 0;
        header.set_cfl(5);
        header.set_write(false);
        header.set_prdtl(1);
        header.dw0 |= 1 << 5; // ATAPI bit
        header.prdbc = 0;

        // Setup command table
        let table = unsafe { &mut *port.cmd_tables[slot as usize] };
        *table = CommandTable::default();

        // Setup FIS for ATAPI PACKET command
        let fis = unsafe { &mut *(table.cfis.as_mut_ptr() as *mut FisRegH2D) };
        *fis = FisRegH2D::new();
        fis.set_command(ATA_CMD_PACKET);
        fis.feature_l = 0;
        fis.lba1 = 8;
        fis.lba2 = 0;

        // Setup ATAPI command (SCSI READ CAPACITY(10))
        table.acmd[0] = SCSI_CMD_READ_CAPACITY_10;

        // Setup PRDT
        table.prdt[0].set_address(buffer_addr);
        table.prdt[0].set_byte_count(8, true);

        // Issue command
        if let Err(e) = self.issue_command(port, slot) {
            log::warn!("READ CAPACITY failed: {:?}, using defaults", e);
            port.sector_size = 2048;
            port.sector_count = 0;
            efi::free_pages(buffer, 1);
            return Ok(());
        }

        // Parse capacity data (big-endian)
        let data = &buffer[..8];
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

        efi::free_pages(buffer, 1);
        Ok(())
    }

    /// Read sectors from a port
    pub fn read_sectors(
        &mut self,
        port_index: usize,
        start_lba: u64,
        num_sectors: u32,
        buffer: *mut u8,
    ) -> Result<(), AhciError> {
        if port_index >= self.ports.len() {
            return Err(AhciError::InvalidParameter);
        }

        let device_type = self.ports[port_index].device_type;
        let sector_size = self.ports[port_index].sector_size;

        if device_type == DeviceType::Satapi {
            self.read_sectors_atapi(port_index, start_lba, num_sectors, buffer, sector_size)
        } else {
            self.read_sectors_sata(port_index, start_lba, num_sectors, buffer)
        }
    }

    /// Read sectors from a SATA device using READ DMA EXT
    fn read_sectors_sata(
        &mut self,
        port_index: usize,
        start_lba: u64,
        num_sectors: u32,
        buffer: *mut u8,
    ) -> Result<(), AhciError> {
        let port_num = self.ports[port_index].port_num;
        let cmd_list = self.ports[port_index].cmd_list;
        let cmd_tables = self.ports[port_index].cmd_tables;

        let slot = self
            .find_free_slot(port_num)
            .ok_or(AhciError::PortNotReady)?;

        // Setup command header
        let header = unsafe { &mut *cmd_list.add(slot as usize) };
        header.dw0 = 0;
        header.set_cfl(5);
        header.set_write(false);
        header.set_prdtl(1);
        header.prdbc = 0;

        // Setup command table
        let table = unsafe { &mut *cmd_tables[slot as usize] };
        *table = CommandTable::default();

        // Setup FIS for READ DMA EXT
        let fis = unsafe { &mut *(table.cfis.as_mut_ptr() as *mut FisRegH2D) };
        *fis = FisRegH2D::new();
        fis.set_command(ATA_CMD_READ_DMA_EXT);
        fis.set_lba(start_lba);
        fis.set_count(num_sectors as u16);

        // Setup PRDT
        let byte_count = num_sectors * 512;
        table.prdt[0].set_address(buffer as u64);
        table.prdt[0].set_byte_count(byte_count, true);

        // Issue command
        self.issue_command_by_port(port_num, slot)?;

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
        let port_num = self.ports[port_index].port_num;
        let cmd_list = self.ports[port_index].cmd_list;
        let cmd_tables = self.ports[port_index].cmd_tables;

        let slot = self
            .find_free_slot(port_num)
            .ok_or(AhciError::PortNotReady)?;

        // Setup command header (set ATAPI bit)
        let header = unsafe { &mut *cmd_list.add(slot as usize) };
        header.dw0 = 0;
        header.set_cfl(5);
        header.set_write(false);
        header.set_prdtl(1);
        header.dw0 |= 1 << 5; // ATAPI bit
        header.prdbc = 0;

        // Setup command table
        let table = unsafe { &mut *cmd_tables[slot as usize] };
        *table = CommandTable::default();

        // Setup FIS for ATAPI PACKET command
        let fis = unsafe { &mut *(table.cfis.as_mut_ptr() as *mut FisRegH2D) };
        *fis = FisRegH2D::new();
        fis.set_command(ATA_CMD_PACKET);
        fis.feature_l = 0;

        let byte_count = num_sectors * sector_size;
        fis.lba1 = (byte_count & 0xFF) as u8;
        fis.lba2 = ((byte_count >> 8) & 0xFF) as u8;

        // Setup ATAPI command (SCSI READ(10))
        table.acmd[0] = SCSI_CMD_READ_10;
        table.acmd[1] = 0;
        table.acmd[2] = ((start_lba >> 24) & 0xFF) as u8;
        table.acmd[3] = ((start_lba >> 16) & 0xFF) as u8;
        table.acmd[4] = ((start_lba >> 8) & 0xFF) as u8;
        table.acmd[5] = (start_lba & 0xFF) as u8;
        table.acmd[6] = 0;
        table.acmd[7] = ((num_sectors >> 8) & 0xFF) as u8;
        table.acmd[8] = (num_sectors & 0xFF) as u8;
        table.acmd[9] = 0;

        // Setup PRDT
        table.prdt[0].set_address(buffer as u64);
        table.prdt[0].set_byte_count(byte_count, true);

        log::trace!(
            "read_sectors_atapi: LBA={}, count={}, byte_count={}, buffer={:p}",
            start_lba,
            num_sectors,
            byte_count,
            buffer
        );

        // Issue command
        self.issue_command_by_port(port_num, slot)?;

        log::trace!("read_sectors_atapi: command completed successfully");

        Ok(())
    }

    /// Issue a command by port number and wait for completion
    fn issue_command_by_port(&mut self, port_num: u8, slot: u8) -> Result<(), AhciError> {
        fence(Ordering::SeqCst);

        let port_regs = self.port_regs(port_num);

        // Issue command
        port_regs.ci.set(1 << slot);

        // Wait for completion (up to 30 seconds)
        let timeout = Timeout::from_ms(30000);
        while !timeout.is_expired() {
            let ci = port_regs.ci.get();
            if ci & (1 << slot) == 0 {
                // Check for errors
                if port_regs.tfd.is_set(PORT_TFD::STS_ERR)
                    || port_regs.tfd.is_set(PORT_TFD::STS_DRQ)
                {
                    log::error!("AHCI command error: TFD={:#x}", port_regs.tfd.get());
                    return Err(AhciError::CommandFailed);
                }
                return Ok(());
            }

            // Check for fatal errors
            if port_regs.is.is_set(PORT_IS::TFES) {
                log::error!(
                    "AHCI task file error: TFD={:#x}, IS={:#x}",
                    port_regs.tfd.get(),
                    port_regs.is.get()
                );
                return Err(AhciError::CommandFailed);
            }
            core::hint::spin_loop();
        }

        log::error!("AHCI command timeout on port {}", port_num);
        Err(AhciError::Timeout)
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
}

/// Wrapper for AHCI controller pointer to implement Send
struct AhciControllerPtr(*mut AhciController);

// SAFETY: AhciControllerPtr wraps a pointer to an AhciController allocated via the EFI
// page allocator. The pointer remains valid for the firmware's lifetime and all access
// is protected by the AHCI_CONTROLLERS mutex. The firmware runs single-threaded.
unsafe impl Send for AhciControllerPtr {}

/// Global list of AHCI controllers
static AHCI_CONTROLLERS: Mutex<heapless::Vec<AhciControllerPtr, 4>> =
    Mutex::new(heapless::Vec::new());

/// Initialize AHCI controllers
pub fn init() {
    log::info!("Initializing AHCI controllers...");

    let ahci_devices = pci::find_ahci_controllers();

    if ahci_devices.is_empty() {
        log::info!("No AHCI controllers found");
        return;
    }

    let mut controllers = AHCI_CONTROLLERS.lock();

    for dev in ahci_devices.iter() {
        match AhciController::new(dev) {
            Ok(controller) => {
                let size = core::mem::size_of::<AhciController>();
                let pages = size.div_ceil(4096);
                log::debug!(
                    "AHCI: Allocating {} pages ({} bytes) for AhciController",
                    pages,
                    size
                );
                let controller_mem = efi::allocate_pages(pages as u64);
                if let Some(mem) = controller_mem {
                    let controller_box = mem.as_mut_ptr() as *mut AhciController;
                    unsafe {
                        ptr::write(controller_box, controller);
                    }
                    if controllers.push(AhciControllerPtr(controller_box)).is_err() {
                        log::warn!(
                            "AHCI: Failed to register controller at {} - controller list full",
                            dev.address
                        );
                    } else {
                        log::info!("AHCI controller at {} initialized", dev.address);
                    }
                }
            }
            Err(e) => {
                log::error!(
                    "Failed to initialize AHCI controller at {}: {:?}",
                    dev.address,
                    e
                );
            }
        }
    }

    log::info!(
        "AHCI initialization complete: {} controllers",
        controllers.len()
    );
}

/// Get an AHCI controller
pub fn get_controller(index: usize) -> Option<&'static mut AhciController> {
    let controllers = AHCI_CONTROLLERS.lock();
    controllers.get(index).map(|ptr| unsafe { &mut *ptr.0 })
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
pub fn global_read_sector(lba: u64, buffer: &mut [u8]) -> Result<(), ()> {
    let (controller_index, port_index) = match GLOBAL_AHCI_DEVICE.lock().as_ref() {
        Some(ptr) => unsafe {
            let device = &*ptr.0;
            (device.controller_index, device.port_index)
        },
        None => {
            log::error!("global_read_sector: no AHCI device stored");
            return Err(());
        }
    };

    let controller = match get_controller(controller_index) {
        Some(c) => c,
        None => {
            log::error!(
                "global_read_sector: no AHCI controller at index {}",
                controller_index
            );
            return Err(());
        }
    };

    // Read directly using the device's native sector size
    // The caller is responsible for providing the correct LBA in device block terms
    controller
        .read_sectors(port_index, lba, 1, buffer.as_mut_ptr())
        .map_err(|e| {
            log::error!("global_read_sector: read failed at LBA {}: {:?}", lba, e);
        })
}

/// Get the sector size of the global AHCI device
pub fn global_sector_size() -> Option<u32> {
    let (controller_index, port_index) = match GLOBAL_AHCI_DEVICE.lock().as_ref() {
        Some(ptr) => unsafe {
            let device = &*ptr.0;
            (device.controller_index, device.port_index)
        },
        None => return None,
    };

    let controller = get_controller(controller_index)?;
    let port = controller.get_port(port_index)?;
    Some(port.sector_size)
}
