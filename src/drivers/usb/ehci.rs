//! EHCI (USB 2.0) Host Controller Interface driver
//!
//! This module provides support for USB 2.0 high-speed devices via the
//! Enhanced Host Controller Interface.
//!
//! # Architecture
//!
//! EHCI uses two main data structures for transfers:
//! - Queue Head (QH): Describes an endpoint and links to transfer descriptors
//! - Queue Element Transfer Descriptor (qTD): Describes a single transfer
//!
//! The controller maintains two schedules:
//! - Asynchronous schedule: For control and bulk transfers (linked list of QHs)
//! - Periodic schedule: For interrupt and isochronous transfers (frame list)
//!
//! # References
//! - EHCI Specification 1.0
//! - U-Boot drivers/usb/host/ehci-hcd.c
//! - libpayload ehci.c

use crate::arch::x86_64::cache::{flush_cache_range, invalidate_cache_range};
use crate::drivers::pci::{self, PciAddress, PciDevice};
use crate::efi;
use crate::time::{Timeout, wait_for};
use core::ptr;
use core::sync::atomic::{Ordering, fence};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

use super::controller::{
    DeviceInfo, EndpointInfo, HUB_DESCRIPTOR_TYPE, HubDescriptor, SetupPacket, UsbController,
    UsbDevice, UsbError, UsbSpeed, enumerate_device, hub_feature, hub_port_status, req_type,
    request,
};

// Import register definitions from ehci_regs module
use super::ehci_regs::{
    // Bitfield types for typed register access
    CAPLENGTH_HCIVERSION,
    CONFIGFLAG,
    // Register struct types
    EhciCapRegs,
    EhciOpRegs,
    EhciPortRegs,
    HCCPARAMS,
    HCSPARAMS,
    PORTSC,
    QTD_TERMINATE,
    USBCMD,
    USBLEGSUP_CAP_ID,
    USBSTS,
    // QH constants
    qh_ep_caps,
    qh_ep_chars,
    qh_link,
    // qTD constants
    qtd_token,
    // Legacy support
    usblegsup,
};

// ============================================================================
// EHCI Data Structures (Memory-mapped)
// ============================================================================

/// Transfer Overlay - same layout as qTD but without alignment requirements
/// Used inside QH where it must start at offset 16 (not 32)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QtdOverlay {
    /// Next qTD Pointer
    pub next_qtd: u32,
    /// Alternate Next qTD Pointer
    pub alt_next_qtd: u32,
    /// qTD Token
    pub token: u32,
    /// Buffer Pointer Page 0 + Current Offset
    pub buffer: [u32; 5],
    /// Extended Buffer Pointer (for 64-bit)
    pub buffer_hi: [u32; 5],
}

impl Default for QtdOverlay {
    fn default() -> Self {
        Self {
            next_qtd: Qtd::TERMINATE,
            alt_next_qtd: Qtd::TERMINATE,
            token: 0,
            buffer: [0; 5],
            buffer_hi: [0; 5],
        }
    }
}

/// Queue Element Transfer Descriptor (qTD) - 32 bytes minimum, 32-byte aligned
/// Standalone qTDs must be 32-byte aligned per EHCI spec section 3.5
#[repr(C, align(32))]
#[derive(Clone, Copy)]
pub struct Qtd {
    /// Next qTD Pointer
    pub next_qtd: u32,
    /// Alternate Next qTD Pointer
    pub alt_next_qtd: u32,
    /// qTD Token
    pub token: u32,
    /// Buffer Pointer Page 0 + Current Offset
    pub buffer: [u32; 5],
    /// Extended Buffer Pointer (for 64-bit)
    pub buffer_hi: [u32; 5],
}

impl Default for Qtd {
    fn default() -> Self {
        Self {
            next_qtd: Self::TERMINATE,
            alt_next_qtd: Self::TERMINATE,
            token: 0,
            buffer: [0; 5],
            buffer_hi: [0; 5],
        }
    }
}

impl Qtd {
    // Re-export constants from ehci_regs for compatibility
    pub const TERMINATE: u32 = QTD_TERMINATE;

    // Token status bits
    pub const TOKEN_STATUS_ACTIVE: u32 = qtd_token::STATUS_ACTIVE;
    pub const TOKEN_STATUS_HALTED: u32 = qtd_token::STATUS_HALTED;
    pub const TOKEN_STATUS_BUFFER_ERR: u32 = qtd_token::STATUS_BUFFER_ERR;
    pub const TOKEN_STATUS_BABBLE: u32 = qtd_token::STATUS_BABBLE;
    pub const TOKEN_STATUS_XACT_ERR: u32 = qtd_token::STATUS_XACT_ERR;

    // PID codes
    pub const TOKEN_PID_OUT: u32 = qtd_token::PID_OUT;
    pub const TOKEN_PID_IN: u32 = qtd_token::PID_IN;
    pub const TOKEN_PID_SETUP: u32 = qtd_token::PID_SETUP;

    // Token field positions
    pub const TOKEN_CERR_SHIFT: u32 = qtd_token::CERR_SHIFT;
    pub const TOKEN_IOC: u32 = qtd_token::IOC;
    pub const TOKEN_BYTES_SHIFT: u32 = qtd_token::BYTES_SHIFT;
    pub const TOKEN_BYTES_MASK: u32 = qtd_token::BYTES_MASK;
    pub const TOKEN_TOGGLE: u32 = qtd_token::TOGGLE;

    /// Create a new qTD
    pub fn new() -> Self {
        Self::default()
    }

    /// Set up buffers for a transfer
    pub fn set_buffers(&mut self, addr: u64, len: usize) {
        // First buffer pointer includes the offset within the page
        self.buffer[0] = addr as u32;
        self.buffer_hi[0] = (addr >> 32) as u32;

        // Subsequent buffer pointers are page-aligned
        let mut remaining = len;
        let mut current_addr = addr;

        for i in 1..5 {
            if remaining == 0 {
                break;
            }
            // Move to next 4KB page
            current_addr = (current_addr + 0x1000) & !0xFFF;
            self.buffer[i] = current_addr as u32;
            self.buffer_hi[i] = (current_addr >> 32) as u32;

            let page_offset = (addr & 0xFFF) as usize;
            let first_page_bytes = 0x1000 - page_offset;
            if i == 1 {
                if remaining > first_page_bytes {
                    remaining -= first_page_bytes;
                } else {
                    remaining = 0;
                }
            } else if remaining > 0x1000 {
                remaining -= 0x1000;
            } else {
                remaining = 0;
            }
        }
    }

    /// Check if qTD is active
    pub fn is_active(&self) -> bool {
        (self.token & Self::TOKEN_STATUS_ACTIVE) != 0
    }

    /// Check if qTD has error
    pub fn has_error(&self) -> bool {
        (self.token
            & (Self::TOKEN_STATUS_HALTED
                | Self::TOKEN_STATUS_BUFFER_ERR
                | Self::TOKEN_STATUS_BABBLE
                | Self::TOKEN_STATUS_XACT_ERR))
            != 0
    }

    /// Check if qTD is halted (stalled)
    pub fn is_halted(&self) -> bool {
        (self.token & Self::TOKEN_STATUS_HALTED) != 0
    }

    /// Get actual bytes transferred
    pub fn bytes_transferred(&self, total: usize) -> usize {
        let remaining = ((self.token & Self::TOKEN_BYTES_MASK) >> Self::TOKEN_BYTES_SHIFT) as usize;
        total.saturating_sub(remaining)
    }
}

/// Queue Head (QH) - 48 bytes minimum, 32-byte aligned
/// Per EHCI spec section 3.6, the layout is:
/// - DWord 0 (offset 0): Queue Head Horizontal Link Pointer
/// - DWord 1 (offset 4): Endpoint Characteristics
/// - DWord 2 (offset 8): Endpoint Capabilities
/// - DWord 3 (offset 12): Current qTD Pointer
/// - DWords 4-11 (offset 16): Transfer Overlay (embedded qTD)
#[repr(C, align(32))]
#[derive(Clone, Copy)]
pub struct Qh {
    /// Queue Head Horizontal Link Pointer
    pub qh_link: u32,
    /// Endpoint Characteristics
    pub ep_chars: u32,
    /// Endpoint Capabilities
    pub ep_caps: u32,
    /// Current qTD Pointer
    pub current_qtd: u32,
    /// Transfer overlay (qTD that HC uses for state) - must be at offset 16!
    pub overlay: QtdOverlay,
}

impl Default for Qh {
    fn default() -> Self {
        Self {
            qh_link: Self::TERMINATE,
            ep_chars: 0,
            ep_caps: 0,
            current_qtd: 0,
            overlay: QtdOverlay::default(),
        }
    }
}

impl Qh {
    // Re-export link pointer constants from ehci_regs
    pub const TERMINATE: u32 = qh_link::TERMINATE;
    pub const TYPE_QH: u32 = qh_link::TYPE_QH;

    // Endpoint Characteristics constants
    pub const EP_DEVADDR_MASK: u32 = qh_ep_chars::DEVADDR_MASK;
    pub const EP_ENDPT_SHIFT: u32 = qh_ep_chars::ENDPT_SHIFT;
    pub const EP_EPS_FULL: u32 = qh_ep_chars::EPS_FULL;
    pub const EP_EPS_LOW: u32 = qh_ep_chars::EPS_LOW;
    pub const EP_EPS_HIGH: u32 = qh_ep_chars::EPS_HIGH;
    pub const EP_DTC: u32 = qh_ep_chars::DTC;
    pub const EP_HEAD: u32 = qh_ep_chars::HEAD;
    pub const EP_MAXPKT_SHIFT: u32 = qh_ep_chars::MAXPKT_SHIFT;
    pub const EP_CTRL: u32 = qh_ep_chars::CTRL;
    pub const EP_RL_SHIFT: u32 = qh_ep_chars::RL_SHIFT;

    // Endpoint Capabilities constants
    pub const CAP_SMASK_SHIFT: u32 = qh_ep_caps::SMASK_SHIFT;
    pub const CAP_CMASK_SHIFT: u32 = qh_ep_caps::CMASK_SHIFT;
    pub const CAP_HUBADDR_SHIFT: u32 = qh_ep_caps::HUBADDR_SHIFT;
    pub const CAP_PORTNUM_SHIFT: u32 = qh_ep_caps::PORTNUM_SHIFT;
    pub const CAP_MULT_SHIFT: u32 = qh_ep_caps::MULT_SHIFT;

    /// Create a new QH
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure QH for a device endpoint
    pub fn configure(
        &mut self,
        device_addr: u8,
        endpoint: u8,
        max_packet: u16,
        speed: UsbSpeed,
        is_control: bool,
    ) {
        self.configure_with_hub(device_addr, endpoint, max_packet, speed, is_control, 0, 0);
    }

    /// Configure QH with hub support for split transactions
    pub fn configure_with_hub(
        &mut self,
        device_addr: u8,
        endpoint: u8,
        max_packet: u16,
        speed: UsbSpeed,
        is_control: bool,
        hub_addr: u8,
        hub_port: u8,
    ) {
        let eps = match speed {
            UsbSpeed::Low => Self::EP_EPS_LOW,
            UsbSpeed::Full => Self::EP_EPS_FULL,
            _ => Self::EP_EPS_HIGH,
        };

        self.ep_chars = (device_addr as u32 & Self::EP_DEVADDR_MASK)
            | ((endpoint as u32) << Self::EP_ENDPT_SHIFT)
            | eps
            | Self::EP_DTC // Data toggle from qTD
            | ((max_packet as u32) << Self::EP_MAXPKT_SHIFT)
            | (8 << Self::EP_RL_SHIFT); // NAK reload = 8

        if is_control && speed != UsbSpeed::High {
            self.ep_chars |= Self::EP_CTRL;
        }

        // High-bandwidth multiplier = 1
        self.ep_caps = 1 << Self::CAP_MULT_SHIFT;

        // For low/full-speed devices behind a high-speed hub, set up split transactions
        if hub_addr != 0 && speed != UsbSpeed::High {
            self.ep_caps |= (hub_addr as u32) << Self::CAP_HUBADDR_SHIFT;
            self.ep_caps |= (hub_port as u32) << Self::CAP_PORTNUM_SHIFT;
            // Set split transaction masks
            self.ep_caps |= 0x01 << Self::CAP_SMASK_SHIFT; // Start split in microframe 0
            self.ep_caps |= 0x1C << Self::CAP_CMASK_SHIFT; // Complete splits in microframes 2,3,4
        }
    }
}

// UsbDevice is now UsbDevice from controller.rs

// ============================================================================
// EHCI Controller
// ============================================================================

/// Maximum number of devices
const MAX_DEVICES: usize = 16;

/// Maximum number of ports
const MAX_PORTS: usize = 15;

/// EHCI Host Controller
pub struct EhciController {
    /// PCI address
    pci_address: PciAddress,
    /// Pointer to capability registers (kept for debugging/future use)
    #[allow(dead_code)]
    cap_regs: *const EhciCapRegs,
    /// Pointer to operational registers
    op_regs: *const EhciOpRegs,
    /// Base address for port registers (first port at offset 0x44 from op_regs)
    port_regs_base: u64,
    /// Number of ports
    num_ports: u8,
    /// 64-bit addressing supported
    has_64bit: bool,
    /// Devices
    devices: [Option<UsbDevice>; MAX_DEVICES],
    /// Next device address
    next_address: u8,
    /// Async schedule list head QH
    async_qh: u64,
    /// Periodic frame list
    periodic_list: u64,
    /// DMA buffer for transfers
    dma_buffer: u64,
    /// QH pool
    qh_pool: u64,
    /// qTD pool
    qtd_pool: u64,
    /// Bulk transfer QH (kept linked for performance)
    bulk_qh: u64,
    /// Bulk transfer qTD
    bulk_qtd: u64,
    /// Whether bulk QH is linked to async schedule
    bulk_qh_linked: bool,
    /// Async schedule is enabled
    async_schedule_enabled: bool,
}

impl EhciController {
    /// DMA buffer size (64KB)
    const DMA_BUFFER_SIZE: usize = 64 * 1024;
    /// Frame list size (1024 entries * 4 bytes)
    const FRAME_LIST_SIZE: usize = 1024;

    /// Create a new EHCI controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, UsbError> {
        // EHCI uses MMIO from BAR0
        let mmio_base = pci_dev.mmio_base().ok_or(UsbError::NotReady)?;

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        log::info!("EHCI controller at MMIO base {:#x}", mmio_base);

        // Read capability registers using typed register access
        let cap_regs = mmio_base as *const EhciCapRegs;
        let cap = unsafe { &*cap_regs };

        let cap_length = cap
            .caplength_hciversion
            .read(CAPLENGTH_HCIVERSION::CAPLENGTH) as u8;
        let hci_version = cap
            .caplength_hciversion
            .read(CAPLENGTH_HCIVERSION::HCIVERSION) as u16;
        let num_ports = (cap.hcsparams.read(HCSPARAMS::N_PORTS) as u8).min(MAX_PORTS as u8);
        let has_64bit = cap.hccparams.read(HCCPARAMS::AC64) != 0;
        let eecp = cap.hccparams.read(HCCPARAMS::EECP) as u8;

        log::debug!(
            "EHCI: version {:#x}, {} ports, 64-bit: {}, EECP: {:#x}",
            hci_version,
            num_ports,
            has_64bit,
            eecp
        );

        // Calculate operational and port register addresses
        let op_base = mmio_base + cap_length as u64;
        let op_regs = op_base as *const EhciOpRegs;
        let port_regs_base = op_base + 0x44; // PORTSC starts at offset 0x44 from op base

        // Allocate memory structures below 4GB for DMA (EHCI uses 32-bit addresses)
        // Async QH (32-byte aligned)
        let async_qh = efi::allocate_pages_below_4g(1).ok_or(UsbError::AllocationFailed)?;
        unsafe { core::slice::from_raw_parts_mut(async_qh as *mut u8, 4096).fill(0) };

        // Periodic frame list (4KB aligned, 4KB)
        let periodic_list = efi::allocate_pages_below_4g(1).ok_or(UsbError::AllocationFailed)?;

        // DMA buffer
        let dma_pages = Self::DMA_BUFFER_SIZE.div_ceil(4096);
        let dma_buffer =
            efi::allocate_pages_below_4g(dma_pages as u64).ok_or(UsbError::AllocationFailed)?;

        // QH pool (enough for multiple QHs)
        let qh_pool = efi::allocate_pages_below_4g(1).ok_or(UsbError::AllocationFailed)?;
        unsafe { core::slice::from_raw_parts_mut(qh_pool as *mut u8, 4096).fill(0) };

        // qTD pool (enough for multiple qTDs)
        let qtd_pool = efi::allocate_pages_below_4g(2).ok_or(UsbError::AllocationFailed)?;
        unsafe { core::slice::from_raw_parts_mut(qtd_pool as *mut u8, 8192).fill(0) };

        // Dedicated bulk transfer structures (kept linked for performance)
        // Use offsets within the pools: bulk_qh at qh_pool+256, bulk_qtd at qtd_pool+512
        let bulk_qh = qh_pool + 256;
        let bulk_qtd = qtd_pool + 512;

        let mut controller = Self {
            pci_address: pci_dev.address,
            cap_regs,
            op_regs,
            port_regs_base,
            num_ports,
            has_64bit,
            devices: core::array::from_fn(|_| None),
            next_address: 1,
            async_qh,
            periodic_list,
            dma_buffer,
            qh_pool,
            qtd_pool,
            bulk_qh,
            bulk_qtd,
            bulk_qh_linked: false,
            async_schedule_enabled: false,
        };

        // Take ownership from BIOS
        controller.take_ownership(pci_dev.address, eecp)?;

        // Initialize the controller
        controller.init()?;

        // Enumerate ports
        controller.enumerate_ports()?;

        Ok(controller)
    }

    /// Get operational registers reference
    #[inline]
    fn op(&self) -> &EhciOpRegs {
        unsafe { &*self.op_regs }
    }

    /// Get port registers reference
    #[inline]
    fn port(&self, port: u8) -> &EhciPortRegs {
        let addr = self.port_regs_base + (port as u64) * 4;
        unsafe { &*(addr as *const EhciPortRegs) }
    }

    /// Take ownership from BIOS via USBLEGSUP extended capability
    fn take_ownership(&mut self, pci_addr: PciAddress, eecp: u8) -> Result<(), UsbError> {
        if eecp == 0 {
            return Ok(());
        }

        let mut cap_offset = eecp;
        while cap_offset != 0 {
            let cap = pci::read_config_u32(pci_addr, cap_offset);
            let cap_id = (cap & 0xFF) as u8;

            if cap_id == USBLEGSUP_CAP_ID {
                log::trace!("EHCI: Found USBLEGSUP at offset {:#x}", cap_offset);

                // Check if BIOS owns the controller
                if (cap & usblegsup::HC_BIOS_OWNED) != 0 {
                    log::trace!("EHCI: Requesting ownership from BIOS");

                    // Set OS owned bit
                    pci::write_config_u32(pci_addr, cap_offset, cap | usblegsup::HC_OS_OWNED);

                    // Wait for BIOS to release (up to 1 second)
                    let timeout = Timeout::from_ms(1000);
                    while !timeout.is_expired() {
                        let cap = pci::read_config_u32(pci_addr, cap_offset);
                        if (cap & usblegsup::HC_BIOS_OWNED) == 0 {
                            log::trace!("EHCI: BIOS released ownership");
                            break;
                        }
                        crate::time::delay_ms(10);
                    }

                    let cap = pci::read_config_u32(pci_addr, cap_offset);
                    if (cap & usblegsup::HC_BIOS_OWNED) != 0 {
                        log::warn!("EHCI: BIOS did not release ownership, forcing");
                        pci::write_config_u32(pci_addr, cap_offset, usblegsup::HC_OS_OWNED);
                    }
                }

                // Disable SMI generation (USBLEGCTLSTS is at offset +4)
                pci::write_config_u32(pci_addr, cap_offset + 4, 0);

                break;
            }

            // Next capability
            cap_offset = ((cap >> 8) & 0xFF) as u8;
        }

        Ok(())
    }

    /// Initialize the controller
    fn init(&mut self) -> Result<(), UsbError> {
        // Stop the controller
        self.op().usbcmd.modify(USBCMD::RS::CLEAR);

        // Wait for halt
        if !wait_for(100, || self.op().usbsts.is_set(USBSTS::HCHALTED)) {
            log::warn!("EHCI: Controller did not halt");
        }

        // Reset the controller
        self.op().usbcmd.write(USBCMD::HCRESET::SET);

        if !wait_for(250, || !self.op().usbcmd.is_set(USBCMD::HCRESET)) {
            return Err(UsbError::Timeout);
        }

        crate::time::delay_ms(10);

        // Set 64-bit segment selector to 0 (if supported)
        if self.has_64bit {
            self.op().ctrldssegment.set(0);
        }

        // Initialize async schedule list head (reclaim list head)
        let qh = unsafe { &mut *(self.async_qh as *mut Qh) };
        // Point to self (circular list with just the head)
        qh.qh_link = (self.async_qh as u32) | Qh::TYPE_QH;
        // Head of reclaim list, high speed
        qh.ep_chars = Qh::EP_HEAD | Qh::EP_EPS_HIGH;
        qh.ep_caps = 1 << Qh::CAP_MULT_SHIFT;
        qh.current_qtd = Qtd::TERMINATE;
        qh.overlay.next_qtd = Qtd::TERMINATE;
        qh.overlay.alt_next_qtd = Qtd::TERMINATE;
        // Halted so HC won't try to process the head
        qh.overlay.token = Qtd::TOKEN_STATUS_HALTED;
        fence(Ordering::SeqCst);

        // Flush async head to main memory for DMA
        flush_cache_range(self.async_qh, 96);

        // Set async list address
        self.op().asynclistaddr.set(self.async_qh as u32);

        // Initialize periodic frame list (all terminate)
        let frame_list = unsafe {
            core::slice::from_raw_parts_mut(self.periodic_list as *mut u32, Self::FRAME_LIST_SIZE)
        };
        frame_list.fill(Qh::TERMINATE);
        fence(Ordering::SeqCst);

        // Flush periodic list to main memory
        flush_cache_range(self.periodic_list, Self::FRAME_LIST_SIZE * 4);

        // Set periodic frame list base
        self.op().periodiclistbase.set(self.periodic_list as u32);

        // Clear status bits (write 1 to clear)
        self.op().usbsts.set(0x3F);

        // Disable interrupts (we poll)
        self.op().usbintr.set(0);

        // Start the controller with interrupt threshold = 8 microframes
        self.op()
            .usbcmd
            .write(USBCMD::RS::SET + USBCMD::ITC::Micro8);

        // Wait for running
        if !wait_for(100, || !self.op().usbsts.is_set(USBSTS::HCHALTED)) {
            log::error!("EHCI: Controller did not start");
            return Err(UsbError::Timeout);
        }

        // Set Configure Flag - route all ports to EHCI
        self.op().configflag.write(CONFIGFLAG::CF::SET);

        crate::time::delay_ms(100);

        log::info!("EHCI controller initialized");
        Ok(())
    }

    /// Enumerate ports
    fn enumerate_ports(&mut self) -> Result<(), UsbError> {
        log::trace!("EHCI: Enumerating {} ports", self.num_ports);

        for port in 0..self.num_ports {
            let port_reg = self.port(port);

            // Clear status change bits (write 1 to clear CSC, PEC, OCC)
            port_reg
                .portsc
                .modify(PORTSC::CSC::SET + PORTSC::PEC::SET + PORTSC::OCC::SET);

            if !port_reg.portsc.is_set(PORTSC::CCS) {
                continue;
            }

            // Check line status - if it's K-state (Low Speed), release to companion
            if port_reg.portsc.read(PORTSC::LS) == PORTSC::LS::KState.into() {
                log::debug!(
                    "EHCI: Port {} has low-speed device, releasing to companion",
                    port
                );
                port_reg.portsc.modify(PORTSC::PO::SET);
                continue;
            }

            log::info!("EHCI: Device detected on port {}", port);

            // Reset the port (set PR, clear PE)
            port_reg.portsc.modify(PORTSC::PR::SET + PORTSC::PE::CLEAR);

            crate::time::delay_ms(50); // USB spec: 10-20ms reset, we use 50ms

            // Clear reset
            port_reg.portsc.modify(PORTSC::PR::CLEAR);

            crate::time::delay_ms(10);

            // Wait for enable
            let timeout = Timeout::from_ms(100);
            let mut enabled = false;
            while !timeout.is_expired() {
                if port_reg.portsc.is_set(PORTSC::PE) {
                    enabled = true;
                    break;
                }
                if !port_reg.portsc.is_set(PORTSC::CCS) {
                    // Device disconnected during reset
                    break;
                }
                crate::time::delay_ms(1);
            }

            if !enabled {
                // Check if it's a full-speed device (should go to companion)
                if port_reg.portsc.is_set(PORTSC::CCS) && !port_reg.portsc.is_set(PORTSC::PE) {
                    log::debug!(
                        "EHCI: Port {} has full-speed device, releasing to companion",
                        port
                    );
                    port_reg.portsc.modify(PORTSC::PO::SET);
                }
                continue;
            }

            // Clear status change bits
            port_reg
                .portsc
                .modify(PORTSC::CSC::SET + PORTSC::PEC::SET + PORTSC::OCC::SET);

            // Device is high-speed if enabled on EHCI
            if let Err(e) = self.attach_device(port, UsbSpeed::High) {
                log::error!("Failed to attach device on port {}: {:?}", port, e);
            }
        }

        Ok(())
    }

    /// Attach a device on a port
    fn attach_device(&mut self, port: u8, speed: UsbSpeed) -> Result<(), UsbError> {
        let address = self.next_address;
        if address >= 128 {
            return Err(UsbError::NoFreeSlots);
        }

        let slot = self
            .devices
            .iter()
            .position(|d| d.is_none())
            .ok_or(UsbError::NoFreeSlots)?;

        // Use the shared enumeration helper
        let initial_device = UsbDevice::new(0, port, speed);
        let device = enumerate_device(initial_device, address, |dev, rt, req, val, idx, data| {
            self.control_transfer_internal(dev, rt, req, val, idx, data)
        })?;

        self.next_address += 1;

        // Store the device
        let is_hub = device.is_hub;
        let hub_address = device.address;
        self.devices[slot] = Some(device);

        // If this is a hub, enumerate its downstream ports
        if is_hub && let Err(e) = self.enumerate_hub(slot, hub_address) {
            log::warn!("Failed to enumerate hub ports: {:?}", e);
            // Don't fail the device attachment, hub is still usable
        }

        Ok(())
    }

    /// Attach a device on a hub port (for devices behind hubs)
    fn attach_device_on_hub(
        &mut self,
        hub_port: u8,
        speed: UsbSpeed,
        hub_addr: u8,
        hub_port_num: u8,
    ) -> Result<(), UsbError> {
        let address = self.next_address;
        if address >= 128 {
            return Err(UsbError::NoFreeSlots);
        }

        let slot = self
            .devices
            .iter()
            .position(|d| d.is_none())
            .ok_or(UsbError::NoFreeSlots)?;

        // Use the shared enumeration helper
        let initial_device = UsbDevice::new_on_hub(0, hub_port, speed, hub_addr, hub_port_num);
        let device = enumerate_device(initial_device, address, |dev, rt, req, val, idx, data| {
            self.control_transfer_internal(dev, rt, req, val, idx, data)
        })?;

        self.next_address += 1;

        // Store the device
        let is_hub = device.is_hub;
        let new_hub_address = device.address;
        self.devices[slot] = Some(device);

        // If this is a hub, enumerate its downstream ports (recursive)
        if is_hub && let Err(e) = self.enumerate_hub(slot, new_hub_address) {
            log::warn!("Failed to enumerate nested hub ports: {:?}", e);
        }

        Ok(())
    }

    /// Enumerate devices connected to a USB hub
    ///
    /// This gets the hub descriptor, powers on all ports, and enumerates
    /// any connected devices.
    fn enumerate_hub(&mut self, hub_slot: usize, hub_addr: u8) -> Result<(), UsbError> {
        log::info!("Enumerating hub at address {}", hub_addr);

        // Get the hub device
        let hub_device = self.devices[hub_slot]
            .as_ref()
            .ok_or(UsbError::DeviceNotFound)?
            .clone();

        // Get hub descriptor (class-specific request)
        // Request type: Device-to-Host | Class | Device = 0xA0
        let mut hub_desc_buf = [0u8; 9];
        self.control_transfer_internal(
            &hub_device,
            req_type::DIR_IN | req_type::TYPE_CLASS | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (HUB_DESCRIPTOR_TYPE as u16) << 8,
            0,
            Some(&mut hub_desc_buf),
        )?;

        let hub_desc =
            unsafe { ptr::read_unaligned(hub_desc_buf.as_ptr() as *const HubDescriptor) };
        let num_ports = hub_desc.num_ports;
        let power_on_delay = (hub_desc.power_on_to_power_good as u32) * 2; // Convert to ms

        log::info!(
            "  Hub has {} ports, power-on delay: {}ms",
            num_ports,
            power_on_delay
        );

        // Update the device's hub port count
        if let Some(ref mut dev) = self.devices[hub_slot] {
            dev.num_hub_ports = num_ports;
        }

        // Power on all hub ports
        // Request type: Host-to-Device | Class | Other = 0x23
        for port in 1..=num_ports {
            log::debug!("  Powering on hub port {}", port);
            let result = self.control_transfer_internal(
                &hub_device,
                req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                request::SET_FEATURE,
                hub_feature::PORT_POWER,
                port as u16,
                None,
            );
            if let Err(e) = result {
                log::warn!("  Failed to power on hub port {}: {:?}", port, e);
            }
        }

        // Wait for power to stabilize
        let delay = power_on_delay.max(100) as u64; // At least 100ms
        crate::time::delay_ms(delay);

        // Check each port for connected devices
        for port in 1..=num_ports {
            // Get port status
            // Request type: Device-to-Host | Class | Other = 0xA3
            let mut status_buf = [0u8; 4];
            let result = self.control_transfer_internal(
                &hub_device,
                req_type::DIR_IN | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                request::GET_STATUS,
                0,
                port as u16,
                Some(&mut status_buf),
            );

            if let Err(e) = result {
                log::debug!("  Failed to get status for hub port {}: {:?}", port, e);
                continue;
            }

            let port_status = u16::from_le_bytes([status_buf[0], status_buf[1]]);
            let port_change = u16::from_le_bytes([status_buf[2], status_buf[3]]);

            log::debug!(
                "  Hub port {} status: {:#06x}, change: {:#06x}",
                port,
                port_status,
                port_change
            );

            // Check if device is connected
            if (port_status & hub_port_status::CONNECTION) == 0 {
                continue;
            }

            log::info!("  Device detected on hub port {}", port);

            // Clear connection change bit if set
            if port_change & 0x01 != 0 {
                let _ = self.control_transfer_internal(
                    &hub_device,
                    req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                    request::CLEAR_FEATURE,
                    hub_feature::C_PORT_CONNECTION,
                    port as u16,
                    None,
                );
            }

            // Reset the port
            log::debug!("  Resetting hub port {}", port);
            self.control_transfer_internal(
                &hub_device,
                req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                request::SET_FEATURE,
                hub_feature::PORT_RESET,
                port as u16,
                None,
            )?;

            // Wait for reset to complete (poll port status)
            crate::time::delay_ms(50);

            // Poll for reset completion
            let mut reset_complete = false;
            let timeout = Timeout::from_ms(500);
            while !timeout.is_expired() {
                let mut status_buf = [0u8; 4];
                if self
                    .control_transfer_internal(
                        &hub_device,
                        req_type::DIR_IN | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                        request::GET_STATUS,
                        0,
                        port as u16,
                        Some(&mut status_buf),
                    )
                    .is_err()
                {
                    break;
                }

                let port_status = u16::from_le_bytes([status_buf[0], status_buf[1]]);
                let port_change = u16::from_le_bytes([status_buf[2], status_buf[3]]);

                // Check if reset is complete (C_PORT_RESET bit in change)
                if port_change & 0x10 != 0 {
                    // Clear the reset change bit
                    let _ = self.control_transfer_internal(
                        &hub_device,
                        req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                        request::CLEAR_FEATURE,
                        hub_feature::C_PORT_RESET,
                        port as u16,
                        None,
                    );

                    // Check if port is enabled
                    if (port_status & hub_port_status::ENABLE) != 0 {
                        reset_complete = true;

                        // Determine device speed
                        let speed = if (port_status & hub_port_status::HIGH_SPEED) != 0 {
                            UsbSpeed::High
                        } else if (port_status & hub_port_status::LOW_SPEED) != 0 {
                            UsbSpeed::Low
                        } else {
                            UsbSpeed::Full
                        };

                        log::info!("  Hub port {} reset complete, speed: {:?}", port, speed);

                        // Recovery time after reset
                        crate::time::delay_ms(10);

                        // Enumerate the device
                        if let Err(e) = self.attach_device_on_hub(port, speed, hub_addr, port) {
                            log::warn!("  Failed to attach device on hub port {}: {:?}", port, e);
                        }
                    }
                    break;
                }

                crate::time::delay_ms(10);
            }

            if !reset_complete {
                log::warn!("  Hub port {} reset timed out", port);
            }
        }

        Ok(())
    }

    /// Perform a control transfer
    fn control_transfer_internal(
        &mut self,
        device: &UsbDevice,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: Option<&mut [u8]>,
    ) -> Result<usize, UsbError> {
        let is_in = (request_type & 0x80) != 0;
        let data_len = data.as_ref().map(|d| d.len()).unwrap_or(0);

        log::trace!(
            "EHCI: control_transfer dev={} req={:#x} val={:#x} len={}",
            device.address,
            request,
            value,
            data_len
        );

        // Set up buffers - all must be below 4GB
        let setup_addr = self.dma_buffer;
        let data_addr = setup_addr + 64;
        let qh_addr = self.qh_pool + 64; // Use offset to avoid the async head
        let qtd_setup_addr = self.qtd_pool;
        let qtd_data_addr = qtd_setup_addr + 64;
        let qtd_status_addr = qtd_data_addr + 64;

        // Validate addresses are below 4GB (EHCI uses 32-bit addresses)
        debug_assert!(setup_addr < 0x1_0000_0000, "setup_addr above 4GB");
        debug_assert!(qh_addr < 0x1_0000_0000, "qh_addr above 4GB");
        debug_assert!(qtd_setup_addr < 0x1_0000_0000, "qtd_setup_addr above 4GB");

        // Clear the memory regions first
        unsafe {
            core::slice::from_raw_parts_mut(qh_addr as *mut u8, 64).fill(0);
            core::slice::from_raw_parts_mut(qtd_setup_addr as *mut u8, 64).fill(0);
            core::slice::from_raw_parts_mut(qtd_data_addr as *mut u8, 64).fill(0);
            core::slice::from_raw_parts_mut(qtd_status_addr as *mut u8, 64).fill(0);
        }
        fence(Ordering::SeqCst);

        // Build setup packet (8 bytes)
        let setup_packet = SetupPacket::new(request_type, request, value, index, data_len as u16);
        unsafe {
            ptr::copy_nonoverlapping(setup_packet.as_bytes().as_ptr(), setup_addr as *mut u8, 8);
        }

        // Copy OUT data
        if let Some(ref d) = data
            && !is_in
        {
            unsafe {
                ptr::copy_nonoverlapping(d.as_ptr(), data_addr as *mut u8, d.len());
            }
        }

        // Build qTDs - work backwards from status to setup
        // Status qTD (last in chain)
        let qtd_status = unsafe { &mut *(qtd_status_addr as *mut Qtd) };
        qtd_status.next_qtd = Qtd::TERMINATE;
        qtd_status.alt_next_qtd = Qtd::TERMINATE;
        qtd_status.token = Qtd::TOKEN_STATUS_ACTIVE
            | (if is_in {
                Qtd::TOKEN_PID_OUT
            } else {
                Qtd::TOKEN_PID_IN
            })
            | Qtd::TOKEN_TOGGLE
            | Qtd::TOKEN_IOC
            | (3 << Qtd::TOKEN_CERR_SHIFT); // Zero length status

        // Data qTD (if needed)
        if data_len > 0 {
            let qtd_data = unsafe { &mut *(qtd_data_addr as *mut Qtd) };
            qtd_data.next_qtd = qtd_status_addr as u32;
            qtd_data.alt_next_qtd = Qtd::TERMINATE;
            qtd_data.token = Qtd::TOKEN_STATUS_ACTIVE
                | (if is_in {
                    Qtd::TOKEN_PID_IN
                } else {
                    Qtd::TOKEN_PID_OUT
                })
                | Qtd::TOKEN_TOGGLE
                | (3 << Qtd::TOKEN_CERR_SHIFT)
                | ((data_len as u32) << Qtd::TOKEN_BYTES_SHIFT);
            qtd_data.set_buffers(data_addr, data_len);
        }

        // Setup qTD (first in chain)
        let setup_next = if data_len > 0 {
            qtd_data_addr as u32
        } else {
            qtd_status_addr as u32
        };
        let qtd_setup = unsafe { &mut *(qtd_setup_addr as *mut Qtd) };
        qtd_setup.next_qtd = setup_next;
        qtd_setup.alt_next_qtd = Qtd::TERMINATE;
        qtd_setup.token = Qtd::TOKEN_STATUS_ACTIVE
            | Qtd::TOKEN_PID_SETUP
            | (3 << Qtd::TOKEN_CERR_SHIFT)
            | (8 << Qtd::TOKEN_BYTES_SHIFT); // Setup is always 8 bytes
        qtd_setup.set_buffers(setup_addr, 8);

        // Build QH for this transfer
        let mut ep_chars = (device.address as u32 & Qh::EP_DEVADDR_MASK)
            | Qh::EP_DTC // Data toggle from qTD
            | ((device.ep0_max_packet as u32) << Qh::EP_MAXPKT_SHIFT)
            | (8 << Qh::EP_RL_SHIFT); // NAK reload = 8

        // Set endpoint speed
        ep_chars |= match device.speed {
            UsbSpeed::Low => Qh::EP_EPS_LOW,
            UsbSpeed::Full => Qh::EP_EPS_FULL,
            _ => Qh::EP_EPS_HIGH,
        };

        // Control Endpoint Flag (C) - ONLY set for non-high-speed control endpoints
        // For high-speed devices, this must ALWAYS be zero per EHCI spec section 3.6.2
        if device.speed != UsbSpeed::High {
            ep_chars |= Qh::EP_CTRL;
        }

        // Build ep_caps with high bandwidth multiplier
        let mut ep_caps = 1u32 << Qh::CAP_MULT_SHIFT;

        // For low/full-speed devices behind a high-speed hub, set up split transactions
        if device.hub_addr != 0 && device.speed != UsbSpeed::High {
            ep_caps |= (device.hub_addr as u32) << Qh::CAP_HUBADDR_SHIFT;
            ep_caps |= (device.hub_port as u32) << Qh::CAP_PORTNUM_SHIFT;
            ep_caps |= 0x01 << Qh::CAP_SMASK_SHIFT; // Start split in microframe 0
            ep_caps |= 0x1C << Qh::CAP_CMASK_SHIFT; // Complete splits in microframes 2,3,4
            log::trace!(
                "EHCI: Split transaction for dev {} via hub {}:{}",
                device.address,
                device.hub_addr,
                device.hub_port
            );
        }

        let qh = unsafe { &mut *(qh_addr as *mut Qh) };
        qh.ep_chars = ep_chars;
        qh.ep_caps = ep_caps;
        qh.current_qtd = Qtd::TERMINATE; // T-bit=1 so HC uses overlay.next_qtd
        qh.overlay.next_qtd = qtd_setup_addr as u32;
        qh.overlay.alt_next_qtd = Qtd::TERMINATE;
        qh.overlay.token = 0; // ACTIVE=0, HALTED=0 -> fetch qTD
        qh.overlay.buffer.fill(0);
        qh.overlay.buffer_hi.fill(0);

        fence(Ordering::SeqCst);

        // Flush setup packet data to main memory
        flush_cache_range(setup_addr, 8);
        if data_len > 0 && !is_in {
            flush_cache_range(data_addr, data_len);
        }

        // Flush qTDs to main memory so EHCI can see them
        flush_cache_range(qtd_setup_addr, 64);
        if data_len > 0 {
            flush_cache_range(qtd_data_addr, 64);
        }
        flush_cache_range(qtd_status_addr, 64);

        // Flush QH to main memory
        flush_cache_range(qh_addr, 96);

        // Link QH into async schedule (insert after async head)
        let async_qh = unsafe { &mut *(self.async_qh as *mut Qh) };
        let old_link = async_qh.qh_link;
        qh.qh_link = old_link;
        fence(Ordering::SeqCst);
        flush_cache_range(qh_addr, 4);

        // Now link our QH into the schedule
        async_qh.qh_link = (qh_addr as u32) | Qh::TYPE_QH;
        fence(Ordering::SeqCst);
        flush_cache_range(self.async_qh, 4);

        // Read back for debug
        invalidate_cache_range(self.async_qh, 64);
        invalidate_cache_range(qh_addr, 64);
        invalidate_cache_range(qtd_setup_addr, 64);
        let async_link = async_qh.qh_link;
        let qh_ep_chars = qh.ep_chars;
        let qh_current = qh.current_qtd;
        let qh_overlay_next = qh.overlay.next_qtd;
        let qh_overlay_token = qh.overlay.token;
        let qtd_buffer0 = qtd_setup.buffer[0];

        log::trace!(
            "EHCI: QH@{:#x} async_head@{:#x} async_head.link={:#x}",
            qh_addr,
            self.async_qh,
            async_link
        );
        log::trace!(
            "EHCI: QH.ep_chars={:#x} current_qtd={:#x} overlay.next={:#x} overlay.token={:#x}",
            qh_ep_chars,
            qh_current,
            qh_overlay_next,
            qh_overlay_token
        );
        log::trace!(
            "EHCI: setup_qtd@{:#x} buffer[0]={:#x}",
            qtd_setup_addr,
            qtd_buffer0
        );
        log::trace!(
            "EHCI: ASYNCLISTADDR={:#x}, USBCMD={:#x}",
            self.op().asynclistaddr.get(),
            self.op().usbcmd.get()
        );
        log::trace!(
            "EHCI: QH.ep_chars={:#x}, QH.overlay.next_qtd={:#x}",
            qh_ep_chars,
            qh_overlay_next
        );
        log::trace!(
            "EHCI: ASYNCLISTADDR={:#x}, USBCMD={:#x}",
            self.op().asynclistaddr.get(),
            self.op().usbcmd.get()
        );

        // Enable async schedule if not already
        if !self.op().usbcmd.is_set(USBCMD::ASE) {
            self.op().usbcmd.modify(USBCMD::ASE::SET);

            // Wait for async schedule to become active
            if !wait_for(100, || self.op().usbsts.is_set(USBSTS::ASS)) {
                log::error!("EHCI: Async schedule failed to start");
                // Unlink and return error
                async_qh.qh_link = old_link;
                fence(Ordering::SeqCst);
                return Err(UsbError::Timeout);
            }
            log::debug!(
                "EHCI: Async schedule enabled, ASS={}",
                self.op().usbsts.is_set(USBSTS::ASS)
            );
        }

        // Wait for transfer completion
        let timeout = Timeout::from_ms(5000);
        let mut poll_count = 0u32;
        while !timeout.is_expired() {
            // Invalidate cache to see updates from EHCI DMA
            invalidate_cache_range(qtd_setup_addr, 64);
            invalidate_cache_range(qtd_status_addr, 64);
            if data_len > 0 {
                invalidate_cache_range(qtd_data_addr, 64);
            }
            fence(Ordering::SeqCst);

            // Read qTD tokens (cache invalidated, so direct access is safe)
            let setup_token = qtd_setup.token;
            let status_token = qtd_status.token;

            // Check if setup qTD completed (ACTIVE bit cleared)
            if (setup_token & Qtd::TOKEN_STATUS_ACTIVE) == 0 {
                // Setup done, check if we need to wait for data/status
                if data_len > 0 {
                    let qtd_data = unsafe { &*(qtd_data_addr as *const Qtd) };
                    if (qtd_data.token & Qtd::TOKEN_STATUS_ACTIVE) != 0 {
                        poll_count += 1;
                        if poll_count.is_multiple_of(100000) {
                            log::trace!("EHCI: waiting for data qTD, token={:#x}", qtd_data.token);
                        }
                        crate::time::delay_us(1);
                        continue;
                    }
                }
                if (status_token & Qtd::TOKEN_STATUS_ACTIVE) == 0 {
                    break; // All done
                }
            }

            poll_count += 1;
            if poll_count.is_multiple_of(100000) {
                log::trace!(
                    "EHCI: waiting, setup_token={:#x} status_token={:#x} usbsts={:#x}",
                    setup_token,
                    status_token,
                    self.op().usbsts.get()
                );
            }
            crate::time::delay_us(1);
        }

        // Unlink QH from schedule
        async_qh.qh_link = old_link;
        fence(Ordering::SeqCst);

        // Ring doorbell and wait for async advance
        self.op().usbsts.modify(USBSTS::IAA::SET); // Clear any pending IAA (write 1 to clear)
        self.op().usbcmd.modify(USBCMD::IAAD::SET);

        let timeout2 = Timeout::from_ms(100);
        while !timeout2.is_expired() {
            if self.op().usbsts.is_set(USBSTS::IAA) {
                self.op().usbsts.modify(USBSTS::IAA::SET); // Clear (write 1 to clear)
                break;
            }
            crate::time::delay_us(10);
        }

        // Invalidate caches one more time to get final state
        invalidate_cache_range(qtd_setup_addr, 64);
        invalidate_cache_range(qtd_status_addr, 64);
        if data_len > 0 {
            invalidate_cache_range(qtd_data_addr, 64);
            if is_in {
                invalidate_cache_range(data_addr, data_len);
            }
        }
        fence(Ordering::SeqCst);

        // Check results (caches already invalidated above)
        let final_setup_token = qtd_setup.token;
        let final_status_token = qtd_status.token;

        if (final_status_token & Qtd::TOKEN_STATUS_ACTIVE) != 0 {
            log::error!(
                "EHCI: transfer timeout, setup={:#x} status={:#x}",
                final_setup_token,
                final_status_token
            );
            return Err(UsbError::Timeout);
        }

        // Check for errors (HALTED, BABBLE, BUFFER_ERR, XACT_ERR)
        const ERROR_MASK: u32 = Qtd::TOKEN_STATUS_HALTED
            | Qtd::TOKEN_STATUS_BUFFER_ERR
            | Qtd::TOKEN_STATUS_BABBLE
            | Qtd::TOKEN_STATUS_XACT_ERR;

        if (final_setup_token & ERROR_MASK) != 0 || (final_status_token & ERROR_MASK) != 0 {
            if (final_setup_token & Qtd::TOKEN_STATUS_HALTED) != 0
                || (final_status_token & Qtd::TOKEN_STATUS_HALTED) != 0
            {
                return Err(UsbError::Stall);
            }
            return Err(UsbError::TransactionError);
        }

        if data_len > 0 {
            let qtd_data = unsafe { &*(qtd_data_addr as *const Qtd) };
            let final_data_token = qtd_data.token;

            if (final_data_token & ERROR_MASK) != 0 {
                if (final_data_token & Qtd::TOKEN_STATUS_HALTED) != 0 {
                    return Err(UsbError::Stall);
                }
                return Err(UsbError::TransactionError);
            }

            // Copy IN data
            if let Some(d) = data
                && is_in
            {
                // Calculate bytes transferred: original - remaining
                let remaining =
                    ((final_data_token & Qtd::TOKEN_BYTES_MASK) >> Qtd::TOKEN_BYTES_SHIFT) as usize;
                let transferred = data_len.saturating_sub(remaining);
                unsafe {
                    ptr::copy_nonoverlapping(
                        data_addr as *const u8,
                        d.as_mut_ptr(),
                        transferred.min(d.len()),
                    );
                }
                log::trace!("EHCI: control transfer complete, {} bytes", transferred);
                return Ok(transferred);
            }
        }

        log::trace!("EHCI: control transfer complete (no data phase)");
        Ok(data_len)
    }

    /// Perform a bulk transfer (optimized - keeps QH linked)
    fn bulk_transfer_internal(
        &mut self,
        device: &UsbDevice,
        endpoint: u8,
        is_in: bool,
        data: &mut [u8],
        toggle: bool,
    ) -> Result<(usize, bool), UsbError> {
        let max_packet = if is_in {
            device
                .bulk_in
                .as_ref()
                .map(|e| e.max_packet_size)
                .unwrap_or(512)
        } else {
            device
                .bulk_out
                .as_ref()
                .map(|e| e.max_packet_size)
                .unwrap_or(512)
        };

        // Use DMA buffer for data
        let data_addr = self.dma_buffer;
        let qh_addr = self.bulk_qh;
        let qtd_addr = self.bulk_qtd;

        // Copy OUT data to DMA buffer
        if !is_in {
            unsafe {
                ptr::copy_nonoverlapping(data.as_ptr(), data_addr as *mut u8, data.len());
            }
            flush_cache_range(data_addr, data.len());
        }

        // Build qTD
        let qtd = unsafe { &mut *(qtd_addr as *mut Qtd) };
        qtd.next_qtd = Qtd::TERMINATE;
        qtd.alt_next_qtd = Qtd::TERMINATE;
        qtd.token = Qtd::TOKEN_STATUS_ACTIVE
            | (if is_in {
                Qtd::TOKEN_PID_IN
            } else {
                Qtd::TOKEN_PID_OUT
            })
            | (if toggle { Qtd::TOKEN_TOGGLE } else { 0 })
            | Qtd::TOKEN_IOC
            | (3 << Qtd::TOKEN_CERR_SHIFT)
            | ((data.len() as u32) << Qtd::TOKEN_BYTES_SHIFT);
        qtd.set_buffers(data_addr, data.len());

        fence(Ordering::SeqCst);

        // Configure QH - always update for correct device/endpoint
        let qh = unsafe { &mut *(qh_addr as *mut Qh) };

        // Link QH into async schedule if not already linked
        if !self.bulk_qh_linked {
            *qh = Qh::new();

            // Link QH into async schedule (keep it linked)
            let async_qh = unsafe { &mut *(self.async_qh as *mut Qh) };
            qh.qh_link = async_qh.qh_link;
            async_qh.qh_link = (qh_addr as u32) | Qh::TYPE_QH;
            self.bulk_qh_linked = true;

            fence(Ordering::SeqCst);
        }

        // Always reconfigure QH for current device/endpoint (ep_chars changes per transfer)
        // Include hub address/port for split transactions if device is behind a hub
        qh.configure_with_hub(
            device.address,
            endpoint,
            max_packet,
            device.speed,
            false,
            device.hub_addr,
            device.hub_port,
        );

        // Update QH overlay to point to new qTD
        qh.overlay.next_qtd = qtd_addr as u32;
        qh.overlay.alt_next_qtd = Qtd::TERMINATE;
        qh.overlay.token = 0; // Clear ACTIVE to let HC fetch new qTD

        fence(Ordering::SeqCst);

        // Enable async schedule if not already enabled
        if !self.async_schedule_enabled {
            self.op().usbcmd.modify(USBCMD::ASE::SET);
            if wait_for(100, || self.op().usbsts.is_set(USBSTS::ASS)) {
                self.async_schedule_enabled = true;
            }
        }

        // Wait for completion
        let timeout = Timeout::from_ms(5000);
        let qtd = unsafe { &*(qtd_addr as *const Qtd) };
        while !timeout.is_expired() {
            invalidate_cache_range(qtd_addr, 64);
            fence(Ordering::SeqCst);
            if (qtd.token & Qtd::TOKEN_STATUS_ACTIVE) == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // Check results
        invalidate_cache_range(qtd_addr, 64);
        fence(Ordering::SeqCst);
        let token = qtd.token;

        if (token & Qtd::TOKEN_STATUS_ACTIVE) != 0 {
            return Err(UsbError::Timeout);
        }

        if (token
            & (Qtd::TOKEN_STATUS_HALTED
                | Qtd::TOKEN_STATUS_BUFFER_ERR
                | Qtd::TOKEN_STATUS_BABBLE
                | Qtd::TOKEN_STATUS_XACT_ERR))
            != 0
        {
            if (token & Qtd::TOKEN_STATUS_HALTED) != 0 {
                // Clear halt by unlinking and relinking QH
                self.bulk_qh_linked = false;
                return Err(UsbError::Stall);
            }
            return Err(UsbError::TransactionError);
        }

        // Calculate bytes transferred
        let remaining = ((token >> Qtd::TOKEN_BYTES_SHIFT) & 0x7FFF) as usize;
        let transferred = data.len().saturating_sub(remaining);

        // Toggle flips for each max-packet-sized transaction
        let packets = transferred.div_ceil(max_packet as usize);
        let new_toggle = if packets % 2 == 1 { !toggle } else { toggle };

        // Copy IN data from DMA buffer
        if is_in && transferred > 0 {
            invalidate_cache_range(data_addr, transferred);
            unsafe {
                ptr::copy_nonoverlapping(data_addr as *const u8, data.as_mut_ptr(), transferred);
            }
        }

        Ok((transferred, new_toggle))
    }

    fn get_device_mut(&mut self, address: u8) -> Option<&mut UsbDevice> {
        self.devices
            .iter_mut()
            .find_map(|d| d.as_mut().filter(|d| d.address == address))
    }

    fn get_device(&self, address: u8) -> Option<&UsbDevice> {
        self.devices
            .iter()
            .find_map(|d| d.as_ref().filter(|d| d.address == address))
    }

    /// Get PCI address
    pub fn pci_address(&self) -> PciAddress {
        self.pci_address
    }

    /// Clean up the controller before handing off to the OS
    pub fn cleanup(&mut self) {
        log::debug!("EHCI cleanup: stopping controller");

        // Disable schedules and stop controller
        self.op()
            .usbcmd
            .modify(USBCMD::ASE::CLEAR + USBCMD::PSE::CLEAR + USBCMD::RS::CLEAR);

        // Wait for halt
        wait_for(100, || self.op().usbsts.is_set(USBSTS::HCHALTED));

        // Reset
        self.op().usbcmd.write(USBCMD::HCRESET::SET);

        wait_for(250, || !self.op().usbcmd.is_set(USBCMD::HCRESET));

        // Clear configure flag
        self.op().configflag.set(0);

        log::debug!("EHCI cleanup complete");
    }
}

// ============================================================================
// UsbController Implementation
// ============================================================================

impl UsbController for EhciController {
    fn controller_type(&self) -> &'static str {
        "EHCI"
    }

    fn control_transfer(
        &mut self,
        device: u8,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: Option<&mut [u8]>,
    ) -> Result<usize, UsbError> {
        let dev = self.get_device(device).ok_or(UsbError::DeviceNotFound)?;
        // Clone the device to avoid borrow issues
        let dev_copy = dev.clone();
        self.control_transfer_internal(&dev_copy, request_type, request, value, index, data)
    }

    fn bulk_transfer(
        &mut self,
        device: u8,
        endpoint: u8,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<usize, UsbError> {
        log::trace!(
            "EHCI: bulk_transfer dev={} ep={} is_in={} len={}",
            device,
            endpoint,
            is_in,
            data.len()
        );
        let dev = self.get_device(device).ok_or(UsbError::DeviceNotFound)?;
        // Clone the device to avoid borrow issues
        let dev_copy = dev.clone();
        let toggle = if is_in {
            dev.bulk_in_toggle
        } else {
            dev.bulk_out_toggle
        };

        let (transferred, new_toggle) =
            self.bulk_transfer_internal(&dev_copy, endpoint, is_in, data, toggle)?;

        // Update toggle
        if let Some(dev) = self.get_device_mut(device) {
            if is_in {
                dev.bulk_in_toggle = new_toggle;
            } else {
                dev.bulk_out_toggle = new_toggle;
            }
        }

        Ok(transferred)
    }

    fn create_interrupt_queue(
        &mut self,
        _device: u8,
        _endpoint: u8,
        _is_in: bool,
        _max_packet: u16,
        _interval: u8,
    ) -> Result<u32, UsbError> {
        // TODO: Implement interrupt queue support
        Err(UsbError::NotReady)
    }

    fn poll_interrupt_queue(&mut self, _queue: u32, _data: &mut [u8]) -> Option<usize> {
        None
    }

    fn destroy_interrupt_queue(&mut self, _queue: u32) {}

    fn find_mass_storage(&self) -> Option<u8> {
        self.devices
            .iter()
            .find_map(|d| d.as_ref().filter(|d| d.is_mass_storage).map(|d| d.address))
    }

    fn find_hid_keyboard(&self) -> Option<u8> {
        self.devices
            .iter()
            .find_map(|d| d.as_ref().filter(|d| d.is_hid_keyboard).map(|d| d.address))
    }

    fn get_device_info(&self, device: u8) -> Option<DeviceInfo> {
        self.get_device(device).map(|d| DeviceInfo {
            address: d.address,
            speed: d.speed,
            vendor_id: d.device_desc.vendor_id,
            product_id: d.device_desc.product_id,
            device_class: d.device_desc.device_class,
            is_mass_storage: d.is_mass_storage,
            is_hid: d.is_hid_keyboard,
            is_keyboard: d.is_hid_keyboard,
            is_hub: d.is_hub,
        })
    }

    fn get_bulk_endpoints(&self, device: u8) -> Option<(EndpointInfo, EndpointInfo)> {
        self.get_device(device)
            .and_then(|d| match (&d.bulk_in, &d.bulk_out) {
                (Some(in_ep), Some(out_ep)) => Some((*in_ep, *out_ep)),
                _ => None,
            })
    }

    fn get_interrupt_endpoint(&self, device: u8) -> Option<EndpointInfo> {
        self.get_device(device).and_then(|d| d.interrupt_in)
    }
}
