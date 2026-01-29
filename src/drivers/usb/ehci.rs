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

use crate::drivers::pci::{self, PciAddress, PciDevice};
use crate::efi;
use crate::time::Timeout;
use core::ptr;
use core::sync::atomic::{fence, Ordering};

use super::controller::{
    class, desc_type, hub_feature, hub_port_status, parse_configuration, req_type, request,
    DeviceDescriptor, DeviceInfo, EndpointInfo, HubDescriptor, UsbController, UsbDevice, UsbError,
    UsbSpeed, HUB_DESCRIPTOR_TYPE,
};

// ============================================================================
// Cache Management for DMA
// ============================================================================

/// Cache line size (typically 64 bytes on modern x86)
const CACHE_LINE_SIZE: usize = 64;

/// Flush a memory range from CPU cache to main memory
///
/// This ensures the EHCI controller (doing DMA) sees the data written by the CPU.
#[inline]
fn flush_cache_range(addr: u64, size: usize) {
    let start = addr as usize & !(CACHE_LINE_SIZE - 1);
    let end = (addr as usize + size + CACHE_LINE_SIZE - 1) & !(CACHE_LINE_SIZE - 1);

    for line in (start..end).step_by(CACHE_LINE_SIZE) {
        unsafe {
            core::arch::asm!(
                "clflush [{}]",
                in(reg) line,
                options(nostack, preserves_flags)
            );
        }
    }
    // Memory fence to ensure flushes complete before continuing
    fence(Ordering::SeqCst);
}

/// Invalidate a memory range in CPU cache
///
/// This ensures the CPU sees data written by the EHCI controller (DMA).
/// On x86, clflush both writes back and invalidates, so we use the same instruction.
#[inline]
fn invalidate_cache_range(addr: u64, size: usize) {
    flush_cache_range(addr, size);
}

// ============================================================================
// EHCI Register Definitions
// ============================================================================

/// Host Controller Capability Registers (read-only)
#[repr(C)]
pub struct EhciCapRegs {
    /// Capability Register Length and Interface Version
    /// [7:0] = CAPLENGTH: Offset to Operational Registers
    /// [31:16] = HCIVERSION: Interface Version Number
    pub cap_length_hci_version: u32,
    /// Structural Parameters
    pub hcs_params: u32,
    /// Capability Parameters
    pub hcc_params: u32,
    /// Companion Port Route Description
    pub hcsp_portroute: [u8; 8],
}

impl EhciCapRegs {
    /// Get capability register length (offset to operational registers)
    pub fn cap_length(&self) -> u8 {
        (self.cap_length_hci_version & 0xFF) as u8
    }

    /// Get interface version
    pub fn hci_version(&self) -> u16 {
        ((self.cap_length_hci_version >> 16) & 0xFFFF) as u16
    }

    /// Get number of ports
    pub fn num_ports(&self) -> u8 {
        (self.hcs_params & 0x0F) as u8
    }

    /// Check if port power control is supported
    pub fn has_port_power_control(&self) -> bool {
        (self.hcs_params & (1 << 4)) != 0
    }

    /// Check if 64-bit addressing is supported
    pub fn has_64bit(&self) -> bool {
        (self.hcc_params & 1) != 0
    }

    /// Get EECP (EHCI Extended Capabilities Pointer)
    pub fn eecp(&self) -> u8 {
        ((self.hcc_params >> 8) & 0xFF) as u8
    }
}

/// Host Controller Operational Registers
#[repr(C)]
pub struct EhciOpRegs {
    /// USB Command Register
    pub usbcmd: u32,
    /// USB Status Register
    pub usbsts: u32,
    /// USB Interrupt Enable
    pub usbintr: u32,
    /// USB Frame Index
    pub frindex: u32,
    /// 4G Segment Selector
    pub ctrldssegment: u32,
    /// Periodic Frame List Base Address
    pub periodiclistbase: u32,
    /// Current Asynchronous List Address
    pub asynclistaddr: u32,
    /// Reserved
    _reserved: [u32; 9],
    /// Configure Flag Register
    pub configflag: u32,
    /// Port Status/Control Registers (up to 15 ports)
    pub portsc: [u32; 15],
}

/// USB Command Register bits
#[allow(dead_code)]
mod usbcmd {
    /// Run/Stop
    pub const RS: u32 = 1 << 0;
    /// Host Controller Reset
    pub const HCRESET: u32 = 1 << 1;
    /// Frame List Size (bits 3:2)
    pub const FLS_MASK: u32 = 3 << 2;
    /// Periodic Schedule Enable
    pub const PSE: u32 = 1 << 4;
    /// Async Schedule Enable
    pub const ASE: u32 = 1 << 5;
    /// Interrupt on Async Advance Doorbell
    pub const IAAD: u32 = 1 << 6;
    /// Light Host Controller Reset
    pub const LHCRESET: u32 = 1 << 7;
    /// Async Schedule Park Mode Count (bits 9:8)
    pub const ASPMC_MASK: u32 = 3 << 8;
    /// Async Schedule Park Mode Enable
    pub const ASPME: u32 = 1 << 11;
    /// Interrupt Threshold Control (bits 23:16)
    pub const ITC_MASK: u32 = 0xFF << 16;
    /// Interrupt every 8 micro-frames
    pub const ITC_8: u32 = 0x08 << 16;
}

/// USB Status Register bits
#[allow(dead_code)]
mod usbsts {
    /// USB Interrupt
    pub const USBINT: u32 = 1 << 0;
    /// USB Error Interrupt
    pub const USBERRINT: u32 = 1 << 1;
    /// Port Change Detect
    pub const PCD: u32 = 1 << 2;
    /// Frame List Rollover
    pub const FLR: u32 = 1 << 3;
    /// Host System Error
    pub const HSE: u32 = 1 << 4;
    /// Interrupt on Async Advance
    pub const IAA: u32 = 1 << 5;
    /// HC Halted
    pub const HCHALTED: u32 = 1 << 12;
    /// Reclamation
    pub const RECLAMATION: u32 = 1 << 13;
    /// Periodic Schedule Status
    pub const PSS: u32 = 1 << 14;
    /// Async Schedule Status
    pub const ASS: u32 = 1 << 15;
}

/// Port Status/Control Register bits
#[allow(dead_code)]
mod portsc {
    /// Current Connect Status
    pub const CCS: u32 = 1 << 0;
    /// Connect Status Change
    pub const CSC: u32 = 1 << 1;
    /// Port Enabled
    pub const PE: u32 = 1 << 2;
    /// Port Enable Change
    pub const PEC: u32 = 1 << 3;
    /// Over-current Active
    pub const OCA: u32 = 1 << 4;
    /// Over-current Change
    pub const OCC: u32 = 1 << 5;
    /// Force Port Resume
    pub const FPR: u32 = 1 << 6;
    /// Suspend
    pub const SUSPEND: u32 = 1 << 7;
    /// Port Reset
    pub const PR: u32 = 1 << 8;
    /// Line Status (bits 11:10)
    pub const LS_MASK: u32 = 3 << 10;
    /// Line Status: SE0
    pub const LS_SE0: u32 = 0 << 10;
    /// Line Status: J-state (FS)
    pub const LS_J: u32 = 2 << 10;
    /// Line Status: K-state (LS)
    pub const LS_K: u32 = 1 << 10;
    /// Port Power
    pub const PP: u32 = 1 << 12;
    /// Port Owner (1 = companion controller)
    pub const PO: u32 = 1 << 13;
    /// Port Indicator Control (bits 15:14)
    pub const PIC_MASK: u32 = 3 << 14;
    /// Port Test Control (bits 19:16)
    pub const PTC_MASK: u32 = 0xF << 16;
    /// Wake on Connect Enable
    pub const WKOC_E: u32 = 1 << 22;
    /// Wake on Disconnect Enable
    pub const WKDSCNNT_E: u32 = 1 << 21;
    /// Wake on Over-current Enable
    pub const WKCNNT_E: u32 = 1 << 20;

    /// Write-clear status bits
    pub const WC_BITS: u32 = CSC | PEC | OCC;
}

/// Configure Flag Register bits
mod configflag {
    /// Configure Flag
    pub const CF: u32 = 1 << 0;
}

// ============================================================================
// EHCI Extended Capabilities
// ============================================================================

/// USBLEGSUP (Legacy Support) Extended Capability
mod usblegsup {
    /// Capability ID (should be 0x01)
    pub const CAP_ID: u8 = 0x01;
    /// HC BIOS Owned Semaphore
    pub const HC_BIOS_OWNED: u32 = 1 << 16;
    /// HC OS Owned Semaphore
    pub const HC_OS_OWNED: u32 = 1 << 24;
}

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
    /// Terminate bit
    pub const TERMINATE: u32 = 1;

    /// Token bits
    pub const TOKEN_STATUS_MASK: u32 = 0xFF;
    pub const TOKEN_STATUS_ACTIVE: u32 = 1 << 7;
    pub const TOKEN_STATUS_HALTED: u32 = 1 << 6;
    pub const TOKEN_STATUS_BUFFER_ERR: u32 = 1 << 5;
    pub const TOKEN_STATUS_BABBLE: u32 = 1 << 4;
    pub const TOKEN_STATUS_XACT_ERR: u32 = 1 << 3;
    pub const TOKEN_STATUS_MISSED_UFRAME: u32 = 1 << 2;
    pub const TOKEN_STATUS_SPLIT: u32 = 1 << 1;
    pub const TOKEN_STATUS_PERR: u32 = 1 << 0;

    pub const TOKEN_PID_OUT: u32 = 0 << 8;
    pub const TOKEN_PID_IN: u32 = 1 << 8;
    pub const TOKEN_PID_SETUP: u32 = 2 << 8;

    pub const TOKEN_CERR_SHIFT: u32 = 10;
    pub const TOKEN_CPAGE_SHIFT: u32 = 12;
    pub const TOKEN_IOC: u32 = 1 << 15;
    pub const TOKEN_BYTES_SHIFT: u32 = 16;
    pub const TOKEN_BYTES_MASK: u32 = 0x7FFF << 16;
    pub const TOKEN_TOGGLE: u32 = 1 << 31;

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
    /// Link pointer type bits
    pub const TERMINATE: u32 = 1;
    pub const TYPE_ITD: u32 = 0 << 1;
    pub const TYPE_QH: u32 = 1 << 1;
    pub const TYPE_SITD: u32 = 2 << 1;
    pub const TYPE_FSTN: u32 = 3 << 1;
    pub const TYPE_MASK: u32 = 3 << 1;

    /// Endpoint Characteristics bits
    pub const EP_DEVADDR_MASK: u32 = 0x7F;
    pub const EP_INACTIVE: u32 = 1 << 7;
    pub const EP_ENDPT_SHIFT: u32 = 8;
    pub const EP_ENDPT_MASK: u32 = 0xF << 8;
    pub const EP_EPS_SHIFT: u32 = 12;
    pub const EP_EPS_FULL: u32 = 0 << 12;
    pub const EP_EPS_LOW: u32 = 1 << 12;
    pub const EP_EPS_HIGH: u32 = 2 << 12;
    pub const EP_DTC: u32 = 1 << 14;
    pub const EP_HEAD: u32 = 1 << 15;
    pub const EP_MAXPKT_SHIFT: u32 = 16;
    pub const EP_MAXPKT_MASK: u32 = 0x7FF << 16;
    pub const EP_CTRL: u32 = 1 << 27;
    pub const EP_RL_SHIFT: u32 = 28;
    pub const EP_RL_MASK: u32 = 0xF << 28;

    /// Endpoint Capabilities bits
    pub const CAP_SMASK_SHIFT: u32 = 0;
    pub const CAP_CMASK_SHIFT: u32 = 8;
    pub const CAP_HUBADDR_SHIFT: u32 = 16;
    pub const CAP_PORTNUM_SHIFT: u32 = 23;
    pub const CAP_MULT_SHIFT: u32 = 30;

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
    /// MMIO base address (kept for hardware completeness)
    #[allow(dead_code)]
    mmio_base: u64,
    /// Capability registers base (kept for hardware completeness)
    #[allow(dead_code)]
    cap_regs: u64,
    /// Operational registers base
    op_regs: u64,
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

        // Read capability registers
        let cap_regs = mmio_base;
        let cap = unsafe { &*(cap_regs as *const EhciCapRegs) };
        let cap_length = cap.cap_length();
        let hci_version = cap.hci_version();
        let num_ports = cap.num_ports().min(MAX_PORTS as u8);
        let has_64bit = cap.has_64bit();
        let eecp = cap.eecp();

        log::debug!(
            "EHCI: version {:#x}, {} ports, 64-bit: {}, EECP: {:#x}",
            hci_version,
            num_ports,
            has_64bit,
            eecp
        );

        let op_regs = mmio_base + cap_length as u64;

        // Allocate memory structures below 4GB for DMA (EHCI uses 32-bit addresses)
        // Async QH (32-byte aligned)
        let async_qh = efi::allocate_pages_below_4g(1).ok_or(UsbError::AllocationFailed)?;
        unsafe { ptr::write_bytes(async_qh as *mut u8, 0, 4096) };

        // Periodic frame list (4KB aligned, 4KB)
        let periodic_list = efi::allocate_pages_below_4g(1).ok_or(UsbError::AllocationFailed)?;

        // DMA buffer
        let dma_pages = (Self::DMA_BUFFER_SIZE + 4095) / 4096;
        let dma_buffer =
            efi::allocate_pages_below_4g(dma_pages as u64).ok_or(UsbError::AllocationFailed)?;

        // QH pool (enough for multiple QHs)
        let qh_pool = efi::allocate_pages_below_4g(1).ok_or(UsbError::AllocationFailed)?;
        unsafe { ptr::write_bytes(qh_pool as *mut u8, 0, 4096) };

        // qTD pool (enough for multiple qTDs)
        let qtd_pool = efi::allocate_pages_below_4g(2).ok_or(UsbError::AllocationFailed)?;
        unsafe { ptr::write_bytes(qtd_pool as *mut u8, 0, 8192) };

        // Dedicated bulk transfer structures (kept linked for performance)
        // Use offsets within the pools: bulk_qh at qh_pool+256, bulk_qtd at qtd_pool+512
        let bulk_qh = qh_pool + 256;
        let bulk_qtd = qtd_pool + 512;

        let mut controller = Self {
            pci_address: pci_dev.address,
            mmio_base,
            cap_regs,
            op_regs,
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

    /// Get operational register
    fn read_op(&self, offset: usize) -> u32 {
        unsafe { ptr::read_volatile((self.op_regs + offset as u64) as *const u32) }
    }

    /// Write operational register
    fn write_op(&mut self, offset: usize, value: u32) {
        unsafe { ptr::write_volatile((self.op_regs + offset as u64) as *mut u32, value) }
    }

    /// Read port status register
    fn read_portsc(&self, port: u8) -> u32 {
        let offset = 0x44 + (port as usize) * 4; // PORTSC starts at 0x44
        self.read_op(offset)
    }

    /// Write port status register
    fn write_portsc(&mut self, port: u8, value: u32) {
        let offset = 0x44 + (port as usize) * 4;
        self.write_op(offset, value);
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

            if cap_id == usblegsup::CAP_ID {
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
                        pci::write_config_u32(pci_addr, cap_offset, usblegsup::HC_OS_OWNED as u32);
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
        let cmd = self.read_op(0x00); // USBCMD
        self.write_op(0x00, cmd & !usbcmd::RS);

        // Wait for halt
        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if (self.read_op(0x04) & usbsts::HCHALTED) != 0 {
                // USBSTS
                break;
            }
            core::hint::spin_loop();
        }

        if (self.read_op(0x04) & usbsts::HCHALTED) == 0 {
            log::warn!("EHCI: Controller did not halt");
        }

        // Reset the controller
        self.write_op(0x00, usbcmd::HCRESET);

        let timeout = Timeout::from_ms(250);
        while !timeout.is_expired() {
            if (self.read_op(0x00) & usbcmd::HCRESET) == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        if (self.read_op(0x00) & usbcmd::HCRESET) != 0 {
            return Err(UsbError::Timeout);
        }

        crate::time::delay_ms(10);

        // Set 64-bit segment selector to 0 (if supported)
        if self.has_64bit {
            self.write_op(0x10, 0); // CTRLDSSEGMENT
        }

        // Initialize async schedule list head (reclaim list head) using volatile writes
        unsafe {
            let qh = self.async_qh as *mut Qh;
            // Point to self (circular list with just the head)
            ptr::write_volatile(&mut (*qh).qh_link, (self.async_qh as u32) | Qh::TYPE_QH);
            // Head of reclaim list, high speed
            ptr::write_volatile(&mut (*qh).ep_chars, Qh::EP_HEAD | Qh::EP_EPS_HIGH);
            ptr::write_volatile(&mut (*qh).ep_caps, 1 << Qh::CAP_MULT_SHIFT);
            ptr::write_volatile(&mut (*qh).current_qtd, Qtd::TERMINATE);
            ptr::write_volatile(&mut (*qh).overlay.next_qtd, Qtd::TERMINATE);
            ptr::write_volatile(&mut (*qh).overlay.alt_next_qtd, Qtd::TERMINATE);
            // Halted so HC won't try to process the head
            ptr::write_volatile(&mut (*qh).overlay.token, Qtd::TOKEN_STATUS_HALTED);
        }
        fence(Ordering::SeqCst);

        // Flush async head to main memory for DMA
        flush_cache_range(self.async_qh, 96);

        // Set async list address
        self.write_op(0x18, self.async_qh as u32); // ASYNCLISTADDR

        // Initialize periodic frame list (all terminate)
        let frame_list = self.periodic_list as *mut u32;
        for i in 0..Self::FRAME_LIST_SIZE {
            unsafe {
                ptr::write_volatile(frame_list.add(i), Qh::TERMINATE);
            }
        }

        // Flush periodic list to main memory
        flush_cache_range(self.periodic_list, Self::FRAME_LIST_SIZE * 4);

        // Set periodic frame list base
        self.write_op(0x14, self.periodic_list as u32); // PERIODICLISTBASE

        // Clear status bits
        self.write_op(0x04, 0x3F); // USBSTS - clear all

        // Disable interrupts (we poll)
        self.write_op(0x08, 0); // USBINTR

        // Start the controller
        let cmd = usbcmd::RS | usbcmd::ITC_8;
        self.write_op(0x00, cmd);

        // Wait for running
        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if (self.read_op(0x04) & usbsts::HCHALTED) == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        if (self.read_op(0x04) & usbsts::HCHALTED) != 0 {
            log::error!("EHCI: Controller did not start");
            return Err(UsbError::Timeout);
        }

        // Set Configure Flag - route all ports to EHCI
        self.write_op(0x40, configflag::CF); // CONFIGFLAG

        crate::time::delay_ms(100);

        log::info!("EHCI controller initialized");
        Ok(())
    }

    /// Enumerate ports
    fn enumerate_ports(&mut self) -> Result<(), UsbError> {
        log::trace!("EHCI: Enumerating {} ports", self.num_ports);

        for port in 0..self.num_ports {
            let portsc = self.read_portsc(port);

            // Clear status change bits
            self.write_portsc(port, portsc | portsc::WC_BITS);

            if (portsc & portsc::CCS) == 0 {
                continue;
            }

            // Check line status - if it's K-state (Low Speed), release to companion
            let line_status = portsc & portsc::LS_MASK;
            if line_status == portsc::LS_K {
                log::debug!(
                    "EHCI: Port {} has low-speed device, releasing to companion",
                    port
                );
                self.write_portsc(port, portsc | portsc::PO);
                continue;
            }

            log::info!("EHCI: Device detected on port {}", port);

            // Reset the port
            let portsc = self.read_portsc(port);
            self.write_portsc(port, (portsc | portsc::PR) & !portsc::PE);

            crate::time::delay_ms(50); // USB spec: 10-20ms reset, we use 50ms

            // Clear reset
            let portsc = self.read_portsc(port);
            self.write_portsc(port, portsc & !portsc::PR);

            crate::time::delay_ms(10);

            // Wait for enable
            let timeout = Timeout::from_ms(100);
            let mut enabled = false;
            while !timeout.is_expired() {
                let portsc = self.read_portsc(port);
                if (portsc & portsc::PE) != 0 {
                    enabled = true;
                    break;
                }
                if (portsc & portsc::CCS) == 0 {
                    // Device disconnected during reset
                    break;
                }
                crate::time::delay_ms(1);
            }

            if !enabled {
                let portsc = self.read_portsc(port);
                // Check if it's a full-speed device (should go to companion)
                if (portsc & portsc::CCS) != 0 && (portsc & portsc::PE) == 0 {
                    log::debug!(
                        "EHCI: Port {} has full-speed device, releasing to companion",
                        port
                    );
                    self.write_portsc(port, portsc | portsc::PO);
                }
                continue;
            }

            // Clear status change bits
            let portsc = self.read_portsc(port);
            self.write_portsc(port, portsc | portsc::WC_BITS);

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

        let mut device = UsbDevice::new(0, port, speed);

        // Get initial device descriptor (first 8 bytes)
        let mut desc_buf = [0u8; 8];
        self.control_transfer_internal(
            &device,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::DEVICE as u16) << 8,
            0,
            Some(&mut desc_buf),
        )?;

        device.ep0_max_packet = desc_buf[7].max(8) as u16;

        // Set address
        self.control_transfer_internal(
            &device,
            req_type::DIR_OUT | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::SET_ADDRESS,
            address as u16,
            0,
            None,
        )?;

        crate::time::delay_ms(2);
        device.address = address;
        self.next_address += 1;

        // Get full device descriptor
        let mut desc_buf = [0u8; 18];
        self.control_transfer_internal(
            &device,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::DEVICE as u16) << 8,
            0,
            Some(&mut desc_buf),
        )?;

        device.device_desc =
            unsafe { ptr::read_unaligned(desc_buf.as_ptr() as *const DeviceDescriptor) };

        let vid = { device.device_desc.vendor_id };
        let pid = { device.device_desc.product_id };
        log::info!("  Device {}: VID={:04x} PID={:04x}", address, vid, pid);

        // Get configuration descriptor
        let mut config_buf = [0u8; 256];
        let mut header = [0u8; 9];

        self.control_transfer_internal(
            &device,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::CONFIGURATION as u16) << 8,
            0,
            Some(&mut header),
        )?;

        let total_len = u16::from_le_bytes([header[2], header[3]]) as usize;
        let total_len = total_len.min(config_buf.len());

        self.control_transfer_internal(
            &device,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::CONFIGURATION as u16) << 8,
            0,
            Some(&mut config_buf[..total_len]),
        )?;

        device.config_info = parse_configuration(&config_buf[..total_len]);

        // Check if this is a hub
        let device_class = device.device_desc.device_class;
        if device_class == class::HUB {
            device.is_hub = true;
            log::info!("    USB Hub detected");
        }

        // Find interfaces
        for iface in &device.config_info.interfaces[..device.config_info.num_interfaces] {
            if iface.is_mass_storage() {
                device.is_mass_storage = true;
                device.bulk_in = iface.find_bulk_in().cloned();
                device.bulk_out = iface.find_bulk_out().cloned();
                log::info!("    Mass Storage interface");
            } else if iface.is_hid_keyboard() {
                device.is_hid_keyboard = true;
                device.interrupt_in = iface.find_interrupt_in().cloned();
                log::info!("    HID Keyboard interface");
            } else if iface.interface_class == class::HUB {
                // Hub class in interface descriptor
                device.is_hub = true;
                log::info!("    USB Hub interface");
            }
        }

        // Set configuration
        if device.config_info.configuration_value > 0 {
            self.control_transfer_internal(
                &device,
                req_type::DIR_OUT | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
                request::SET_CONFIGURATION,
                device.config_info.configuration_value as u16,
                0,
                None,
            )?;
        }

        // Store the device
        let is_hub = device.is_hub;
        let hub_address = device.address;
        self.devices[slot] = Some(device);

        // If this is a hub, enumerate its downstream ports
        if is_hub {
            if let Err(e) = self.enumerate_hub(slot, hub_address) {
                log::warn!("Failed to enumerate hub ports: {:?}", e);
                // Don't fail the device attachment, hub is still usable
            }
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

        let mut device = UsbDevice::new_on_hub(0, hub_port, speed, hub_addr, hub_port_num);

        // Get initial device descriptor (first 8 bytes)
        let mut desc_buf = [0u8; 8];
        self.control_transfer_internal(
            &device,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::DEVICE as u16) << 8,
            0,
            Some(&mut desc_buf),
        )?;

        device.ep0_max_packet = desc_buf[7].max(8) as u16;

        // Set address
        self.control_transfer_internal(
            &device,
            req_type::DIR_OUT | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::SET_ADDRESS,
            address as u16,
            0,
            None,
        )?;

        crate::time::delay_ms(2);
        device.address = address;
        self.next_address += 1;

        // Get full device descriptor
        let mut desc_buf = [0u8; 18];
        self.control_transfer_internal(
            &device,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::DEVICE as u16) << 8,
            0,
            Some(&mut desc_buf),
        )?;

        device.device_desc =
            unsafe { ptr::read_unaligned(desc_buf.as_ptr() as *const DeviceDescriptor) };

        let vid = { device.device_desc.vendor_id };
        let pid = { device.device_desc.product_id };
        log::info!(
            "  Device {} (via hub {}:{}): VID={:04x} PID={:04x}",
            address,
            hub_addr,
            hub_port_num,
            vid,
            pid
        );

        // Get configuration descriptor
        let mut config_buf = [0u8; 256];
        let mut header = [0u8; 9];

        self.control_transfer_internal(
            &device,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::CONFIGURATION as u16) << 8,
            0,
            Some(&mut header),
        )?;

        let total_len = u16::from_le_bytes([header[2], header[3]]) as usize;
        let total_len = total_len.min(config_buf.len());

        self.control_transfer_internal(
            &device,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::CONFIGURATION as u16) << 8,
            0,
            Some(&mut config_buf[..total_len]),
        )?;

        device.config_info = parse_configuration(&config_buf[..total_len]);

        // Check if this is a hub
        let device_class = device.device_desc.device_class;
        if device_class == class::HUB {
            device.is_hub = true;
            log::info!("    USB Hub detected (nested)");
        }

        // Find interfaces
        for iface in &device.config_info.interfaces[..device.config_info.num_interfaces] {
            if iface.is_mass_storage() {
                device.is_mass_storage = true;
                device.bulk_in = iface.find_bulk_in().cloned();
                device.bulk_out = iface.find_bulk_out().cloned();
                log::info!("    Mass Storage interface");
            } else if iface.is_hid_keyboard() {
                device.is_hid_keyboard = true;
                device.interrupt_in = iface.find_interrupt_in().cloned();
                log::info!("    HID Keyboard interface");
            } else if iface.interface_class == class::HUB {
                device.is_hub = true;
                log::info!("    USB Hub interface");
            }
        }

        // Set configuration
        if device.config_info.configuration_value > 0 {
            self.control_transfer_internal(
                &device,
                req_type::DIR_OUT | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
                request::SET_CONFIGURATION,
                device.config_info.configuration_value as u16,
                0,
                None,
            )?;
        }

        // Store the device
        let is_hub = device.is_hub;
        let new_hub_address = device.address;
        self.devices[slot] = Some(device);

        // If this is a hub, enumerate its downstream ports (recursive)
        if is_hub {
            if let Err(e) = self.enumerate_hub(slot, new_hub_address) {
                log::warn!("Failed to enumerate nested hub ports: {:?}", e);
            }
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

        // Clear the memory regions first using volatile writes
        unsafe {
            ptr::write_bytes(qh_addr as *mut u8, 0, 64);
            ptr::write_bytes(qtd_setup_addr as *mut u8, 0, 64);
            ptr::write_bytes(qtd_data_addr as *mut u8, 0, 64);
            ptr::write_bytes(qtd_status_addr as *mut u8, 0, 64);
        }
        fence(Ordering::SeqCst);

        // Build setup packet (8 bytes)
        unsafe {
            let setup = setup_addr as *mut u8;
            *setup.add(0) = request_type;
            *setup.add(1) = request;
            *setup.add(2) = value as u8;
            *setup.add(3) = (value >> 8) as u8;
            *setup.add(4) = index as u8;
            *setup.add(5) = (index >> 8) as u8;
            *setup.add(6) = data_len as u8;
            *setup.add(7) = (data_len >> 8) as u8;
        }

        // Copy OUT data
        if let Some(ref d) = data {
            if !is_in {
                unsafe {
                    ptr::copy_nonoverlapping(d.as_ptr(), data_addr as *mut u8, d.len());
                }
            }
        }

        // Build qTDs using volatile writes - work backwards from status to setup
        // Status qTD (last in chain)
        let status_token = Qtd::TOKEN_STATUS_ACTIVE
            | (if is_in {
                Qtd::TOKEN_PID_OUT
            } else {
                Qtd::TOKEN_PID_IN
            })
            | Qtd::TOKEN_TOGGLE
            | Qtd::TOKEN_IOC
            | (3 << Qtd::TOKEN_CERR_SHIFT)
            | (0 << Qtd::TOKEN_BYTES_SHIFT); // Zero length status

        unsafe {
            let qtd_status = qtd_status_addr as *mut Qtd;
            ptr::write_volatile(&mut (*qtd_status).next_qtd, Qtd::TERMINATE);
            ptr::write_volatile(&mut (*qtd_status).alt_next_qtd, Qtd::TERMINATE);
            ptr::write_volatile(&mut (*qtd_status).token, status_token);
        }

        // Data qTD (if needed)
        if data_len > 0 {
            let data_token = Qtd::TOKEN_STATUS_ACTIVE
                | (if is_in {
                    Qtd::TOKEN_PID_IN
                } else {
                    Qtd::TOKEN_PID_OUT
                })
                | Qtd::TOKEN_TOGGLE
                | (3 << Qtd::TOKEN_CERR_SHIFT)
                | ((data_len as u32) << Qtd::TOKEN_BYTES_SHIFT);

            unsafe {
                let qtd_data = qtd_data_addr as *mut Qtd;
                ptr::write_volatile(&mut (*qtd_data).next_qtd, qtd_status_addr as u32);
                ptr::write_volatile(&mut (*qtd_data).alt_next_qtd, Qtd::TERMINATE);
                ptr::write_volatile(&mut (*qtd_data).token, data_token);
                // Set buffer pointers
                (*qtd_data).set_buffers(data_addr, data_len);
            }
        }

        // Setup qTD (first in chain)
        let setup_next = if data_len > 0 {
            qtd_data_addr as u32
        } else {
            qtd_status_addr as u32
        };
        let setup_token = Qtd::TOKEN_STATUS_ACTIVE
            | Qtd::TOKEN_PID_SETUP
            | (3 << Qtd::TOKEN_CERR_SHIFT)
            | (8 << Qtd::TOKEN_BYTES_SHIFT); // Setup is always 8 bytes

        unsafe {
            let qtd_setup = qtd_setup_addr as *mut Qtd;
            ptr::write_volatile(&mut (*qtd_setup).next_qtd, setup_next);
            ptr::write_volatile(&mut (*qtd_setup).alt_next_qtd, Qtd::TERMINATE);
            ptr::write_volatile(&mut (*qtd_setup).token, setup_token);
            (*qtd_setup).set_buffers(setup_addr, 8);
        }

        // Build QH for this transfer using volatile writes
        let mut ep_chars = (device.address as u32 & Qh::EP_DEVADDR_MASK)
            | (0 << Qh::EP_ENDPT_SHIFT) // Endpoint 0
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
        let mut ep_caps = 1u32 << Qh::CAP_MULT_SHIFT; // High bandwidth pipe multiplier = 1

        // For low/full-speed devices behind a high-speed hub, set up split transactions
        // This is needed when hub_addr != 0 (device is behind a hub)
        if device.hub_addr != 0 && device.speed != UsbSpeed::High {
            // Set hub address and port number for split transactions
            ep_caps |= (device.hub_addr as u32) << Qh::CAP_HUBADDR_SHIFT;
            ep_caps |= (device.hub_port as u32) << Qh::CAP_PORTNUM_SHIFT;
            // Set split transaction masks (SMASK and CMASK)
            // SMASK: start-split schedule mask (microframe 0)
            // CMASK: complete-split schedule mask (microframes 2,3,4)
            ep_caps |= 0x01 << Qh::CAP_SMASK_SHIFT; // Start split in microframe 0
            ep_caps |= 0x1C << Qh::CAP_CMASK_SHIFT; // Complete splits in microframes 2,3,4
            log::trace!(
                "EHCI: Split transaction for dev {} via hub {}:{}",
                device.address,
                device.hub_addr,
                device.hub_port
            );
        }

        unsafe {
            let qh = qh_addr as *mut Qh;
            ptr::write_volatile(&mut (*qh).ep_chars, ep_chars);
            ptr::write_volatile(&mut (*qh).ep_caps, ep_caps);
            // Set current_qtd to TERMINATE (T-bit=1) so HC uses overlay.next_qtd
            ptr::write_volatile(&mut (*qh).current_qtd, Qtd::TERMINATE);
            ptr::write_volatile(&mut (*qh).overlay.next_qtd, qtd_setup_addr as u32);
            ptr::write_volatile(&mut (*qh).overlay.alt_next_qtd, Qtd::TERMINATE);
            ptr::write_volatile(&mut (*qh).overlay.token, 0); // ACTIVE=0, HALTED=0 -> fetch qTD
                                                              // Clear rest of overlay
            for i in 0..5 {
                ptr::write_volatile(&mut (*qh).overlay.buffer[i], 0);
                ptr::write_volatile(&mut (*qh).overlay.buffer_hi[i], 0);
            }
        }

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

        // Link QH into async schedule (insert after async head) using volatile
        let old_link = unsafe { ptr::read_volatile(&(*(self.async_qh as *const Qh)).qh_link) };

        unsafe {
            let qh = qh_addr as *mut Qh;
            ptr::write_volatile(&mut (*qh).qh_link, old_link);
        }

        // Flush the QH link field
        flush_cache_range(qh_addr, 4);

        // Now link our QH into the schedule
        unsafe {
            let async_qh = self.async_qh as *mut Qh;
            ptr::write_volatile(&mut (*async_qh).qh_link, (qh_addr as u32) | Qh::TYPE_QH);
        }

        // Flush the async head's link to make it visible to HC
        flush_cache_range(self.async_qh, 4);

        // Read back for debug
        let async_link = unsafe { ptr::read_volatile(&(*(self.async_qh as *const Qh)).qh_link) };
        let qh_ep_chars = unsafe { ptr::read_volatile(&(*(qh_addr as *const Qh)).ep_chars) };
        let qh_current = unsafe { ptr::read_volatile(&(*(qh_addr as *const Qh)).current_qtd) };
        let qh_overlay_next =
            unsafe { ptr::read_volatile(&(*(qh_addr as *const Qh)).overlay.next_qtd) };
        let qh_overlay_token =
            unsafe { ptr::read_volatile(&(*(qh_addr as *const Qh)).overlay.token) };
        let qtd_buffer0 =
            unsafe { ptr::read_volatile(&(*(qtd_setup_addr as *const Qtd)).buffer[0]) };

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
            self.read_op(0x18),
            self.read_op(0x00)
        );
        log::trace!(
            "EHCI: QH.ep_chars={:#x}, QH.overlay.next_qtd={:#x}",
            qh_ep_chars,
            qh_overlay_next
        );
        log::trace!(
            "EHCI: ASYNCLISTADDR={:#x}, USBCMD={:#x}",
            self.read_op(0x18),
            self.read_op(0x00)
        );

        // Enable async schedule if not already
        let cmd = self.read_op(0x00);
        if (cmd & usbcmd::ASE) == 0 {
            self.write_op(0x00, cmd | usbcmd::ASE);

            // Wait for async schedule to become active
            let timeout = Timeout::from_ms(100);
            while !timeout.is_expired() {
                if (self.read_op(0x04) & usbsts::ASS) != 0 {
                    break;
                }
                crate::time::delay_us(10);
            }

            if (self.read_op(0x04) & usbsts::ASS) == 0 {
                log::error!("EHCI: Async schedule failed to start");
                // Unlink and return error
                unsafe {
                    let async_qh = self.async_qh as *mut Qh;
                    ptr::write_volatile(&mut (*async_qh).qh_link, old_link);
                }
                return Err(UsbError::Timeout);
            }
            log::debug!(
                "EHCI: Async schedule enabled, ASS={}",
                (self.read_op(0x04) & usbsts::ASS) != 0
            );
        }

        // Wait for transfer completion using volatile reads
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

            // Read qTD tokens using volatile
            let setup_token =
                unsafe { ptr::read_volatile(&(*(qtd_setup_addr as *const Qtd)).token) };
            let status_token =
                unsafe { ptr::read_volatile(&(*(qtd_status_addr as *const Qtd)).token) };

            // Check if setup qTD completed (ACTIVE bit cleared)
            if (setup_token & Qtd::TOKEN_STATUS_ACTIVE) == 0 {
                // Setup done, check if we need to wait for data/status
                if data_len > 0 {
                    let data_token =
                        unsafe { ptr::read_volatile(&(*(qtd_data_addr as *const Qtd)).token) };
                    if (data_token & Qtd::TOKEN_STATUS_ACTIVE) != 0 {
                        poll_count += 1;
                        if poll_count % 100000 == 0 {
                            log::trace!("EHCI: waiting for data qTD, token={:#x}", data_token);
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
            if poll_count % 100000 == 0 {
                log::trace!(
                    "EHCI: waiting, setup_token={:#x} status_token={:#x} usbsts={:#x}",
                    setup_token,
                    status_token,
                    self.read_op(0x04)
                );
            }
            crate::time::delay_us(1);
        }

        // Unlink QH from schedule
        unsafe {
            let async_qh = self.async_qh as *mut Qh;
            ptr::write_volatile(&mut (*async_qh).qh_link, old_link);
        }
        fence(Ordering::SeqCst);

        // Ring doorbell and wait for async advance
        self.write_op(0x04, usbsts::IAA); // Clear any pending IAA
        let cmd = self.read_op(0x00);
        self.write_op(0x00, cmd | usbcmd::IAAD);

        let timeout2 = Timeout::from_ms(100);
        while !timeout2.is_expired() {
            if (self.read_op(0x04) & usbsts::IAA) != 0 {
                self.write_op(0x04, usbsts::IAA); // Clear
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

        // Check results using volatile reads
        let final_setup_token =
            unsafe { ptr::read_volatile(&(*(qtd_setup_addr as *const Qtd)).token) };
        let final_status_token =
            unsafe { ptr::read_volatile(&(*(qtd_status_addr as *const Qtd)).token) };

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
            let final_data_token =
                unsafe { ptr::read_volatile(&(*(qtd_data_addr as *const Qtd)).token) };

            if (final_data_token & ERROR_MASK) != 0 {
                if (final_data_token & Qtd::TOKEN_STATUS_HALTED) != 0 {
                    return Err(UsbError::Stall);
                }
                return Err(UsbError::TransactionError);
            }

            // Copy IN data
            if let Some(d) = data {
                if is_in {
                    // Calculate bytes transferred: original - remaining
                    let remaining = ((final_data_token & Qtd::TOKEN_BYTES_MASK)
                        >> Qtd::TOKEN_BYTES_SHIFT) as usize;
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
            let cmd = self.read_op(0x00);
            self.write_op(0x00, cmd | usbcmd::ASE);
            let timeout = Timeout::from_ms(100);
            while !timeout.is_expired() {
                if (self.read_op(0x04) & usbsts::ASS) != 0 {
                    self.async_schedule_enabled = true;
                    break;
                }
                core::hint::spin_loop();
            }
        }

        // Wait for completion
        let timeout = Timeout::from_ms(5000);
        while !timeout.is_expired() {
            fence(Ordering::SeqCst);
            let token = unsafe { ptr::read_volatile(&(*(qtd_addr as *const Qtd)).token) };
            if (token & Qtd::TOKEN_STATUS_ACTIVE) == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // Check results (read token again)
        let token = unsafe { ptr::read_volatile(&(*(qtd_addr as *const Qtd)).token) };

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
        let packets = (transferred + max_packet as usize - 1) / max_packet as usize;
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

        // Disable schedules
        let cmd = self.read_op(0x00);
        self.write_op(0x00, cmd & !(usbcmd::ASE | usbcmd::PSE | usbcmd::RS));

        // Wait for halt
        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if (self.read_op(0x04) & usbsts::HCHALTED) != 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // Reset
        self.write_op(0x00, usbcmd::HCRESET);

        let timeout = Timeout::from_ms(250);
        while !timeout.is_expired() {
            if (self.read_op(0x00) & usbcmd::HCRESET) == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // Clear configure flag
        self.write_op(0x40, 0);

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
                (Some(in_ep), Some(out_ep)) => Some((in_ep.clone(), out_ep.clone())),
                _ => None,
            })
    }

    fn get_interrupt_endpoint(&self, device: u8) -> Option<EndpointInfo> {
        self.get_device(device).and_then(|d| d.interrupt_in.clone())
    }
}
