//! EHCI (USB 2.0) Host Controller Interface driver
//!
//! This module provides support for USB 2.0 high-speed devices via the
//! Enhanced Host Controller Interface.
//!
//! # References
//! - EHCI Specification 1.0
//! - libpayload ehci.c

use crate::drivers::pci::{self, PciAddress, PciDevice};
use crate::efi;
use crate::time::Timeout;
use core::ptr;
use core::sync::atomic::{fence, Ordering};

use super::core::{
    class, desc_type, parse_configuration, req_type, request, ConfigurationInfo, DeviceDescriptor,
    DeviceInfo, Direction, EndpointInfo, EndpointType, InterfaceInfo, UsbController, UsbError,
    UsbSpeed,
};

// ============================================================================
// EHCI Register Definitions
// ============================================================================

/// EHCI Capability Registers
mod cap_regs {
    /// Capability Register Length + HCI Version
    pub const CAPLENGTH: u32 = 0x00;
    /// Structural Parameters
    pub const HCSPARAMS: u32 = 0x04;
    /// Capability Parameters
    pub const HCCPARAMS: u32 = 0x08;
    /// Companion Port Route Description
    pub const HCSP_PORTROUTE: u32 = 0x0C;
}

/// EHCI Operational Registers
mod op_regs {
    /// USB Command
    pub const USBCMD: u32 = 0x00;
    /// USB Status
    pub const USBSTS: u32 = 0x04;
    /// USB Interrupt Enable
    pub const USBINTR: u32 = 0x08;
    /// Frame Index
    pub const FRINDEX: u32 = 0x0C;
    /// 4G Segment Selector
    pub const CTRLDSSEGMENT: u32 = 0x10;
    /// Periodic Frame List Base Address
    pub const PERIODICLISTBASE: u32 = 0x14;
    /// Async List Address
    pub const ASYNCLISTADDR: u32 = 0x18;
    /// Configured Flag
    pub const CONFIGFLAG: u32 = 0x40;
    /// Port Status/Control (base, each port +4)
    pub const PORTSC_BASE: u32 = 0x44;
}

/// USB Command Register bits
mod usbcmd {
    /// Run/Stop
    pub const RS: u32 = 1 << 0;
    /// Host Controller Reset
    pub const HCRESET: u32 = 1 << 1;
    /// Frame List Size (bits 2-3)
    pub const FLS_MASK: u32 = 3 << 2;
    pub const FLS_1024: u32 = 0 << 2;
    /// Periodic Schedule Enable
    pub const PSE: u32 = 1 << 4;
    /// Async Schedule Enable
    pub const ASE: u32 = 1 << 5;
    /// Interrupt on Async Advance Doorbell
    pub const IAAD: u32 = 1 << 6;
    /// Interrupt Threshold Control (bits 16-23)
    pub const ITC_MASK: u32 = 0xFF << 16;
    pub const ITC_8: u32 = 8 << 16;
}

/// USB Status Register bits
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
    /// Host Controller Halted
    pub const HCHALTED: u32 = 1 << 12;
    /// Reclamation
    pub const RECLAMATION: u32 = 1 << 13;
    /// Periodic Schedule Status
    pub const PSS: u32 = 1 << 14;
    /// Async Schedule Status
    pub const ASS: u32 = 1 << 15;
}

/// Port Status/Control bits
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
    /// Line Status (bits 10-11)
    pub const LS_MASK: u32 = 3 << 10;
    pub const LS_SE0: u32 = 0 << 10;
    pub const LS_JSTATE: u32 = 1 << 10;
    pub const LS_KSTATE: u32 = 2 << 10;
    /// Port Power
    pub const PP: u32 = 1 << 12;
    /// Port Owner (1 = companion controller)
    pub const PO: u32 = 1 << 13;
    /// Port Indicator Control (bits 14-15)
    pub const PIC_MASK: u32 = 3 << 14;
    /// Port Test Control (bits 16-19)
    pub const PTC_MASK: u32 = 0xF << 16;
    /// Wake on Connect Enable
    pub const WKOC_E: u32 = 1 << 20;
    /// Wake on Disconnect Enable
    pub const WKDC_E: u32 = 1 << 21;
    /// Wake on Over-current Enable
    pub const WKOC: u32 = 1 << 22;
    /// Write-1-to-clear bits
    pub const W1C_MASK: u32 = CSC | PEC | OCC;
}

// ============================================================================
// EHCI Data Structures
// ============================================================================

/// Queue Head (48 bytes, 32-byte aligned)
#[repr(C, align(32))]
#[derive(Clone, Copy)]
pub struct QueueHead {
    /// Horizontal Link Pointer
    pub horiz_link_ptr: u32,
    /// Endpoint Characteristics
    pub ep_chars: u32,
    /// Endpoint Capabilities
    pub ep_caps: u32,
    /// Current qTD Pointer
    pub cur_qtd: u32,
    /// Transfer Overlay (qTD)
    pub overlay: QueueTransferDescriptor,
}

impl Default for QueueHead {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

impl QueueHead {
    /// Create a new Queue Head
    pub fn new(
        device_addr: u8,
        endpoint: u8,
        max_packet: u16,
        speed: UsbSpeed,
        is_control: bool,
    ) -> Self {
        let mut qh = Self::default();

        // Endpoint Characteristics
        let mut ep_chars = (device_addr as u32) & 0x7F; // Device address
        ep_chars |= ((endpoint as u32) & 0xF) << 8; // Endpoint number
        ep_chars |= match speed {
            UsbSpeed::Low => 1 << 12,
            UsbSpeed::Full => 0 << 12,
            UsbSpeed::High | _ => 2 << 12,
        };
        if is_control && speed != UsbSpeed::High {
            ep_chars |= 1 << 27; // Control Endpoint Flag for full/low speed
        }
        ep_chars |= ((max_packet as u32) & 0x7FF) << 16; // Max packet size
        if is_control {
            ep_chars |= 1 << 14; // DTC = 1 for control endpoints
        }
        qh.ep_chars = ep_chars;

        // Endpoint Capabilities
        let mut ep_caps = 1 << 30; // High-Bandwidth Pipe Multiplier = 1
        if speed != UsbSpeed::High {
            // For full/low speed devices behind a high-speed hub
            ep_caps |= 0x1C; // S-mask (microframe schedule mask)
        }
        qh.ep_caps = ep_caps;

        // Terminate horizontal link
        qh.horiz_link_ptr = 1; // T-bit set

        // Initialize overlay
        qh.overlay.next_qtd = 1; // Terminated
        qh.overlay.alt_qtd = 1; // Terminated
        qh.overlay.token = 0;

        qh
    }
}

/// Queue Transfer Descriptor (32 bytes, 32-byte aligned)
#[repr(C, align(32))]
#[derive(Clone, Copy, Default)]
pub struct QueueTransferDescriptor {
    /// Next qTD Pointer
    pub next_qtd: u32,
    /// Alternate Next qTD Pointer
    pub alt_qtd: u32,
    /// Token
    pub token: u32,
    /// Buffer Pointers (5 pages max = 20KB)
    pub buffer_ptrs: [u32; 5],
    /// Extended Buffer Pointers (for 64-bit)
    pub ext_buffer_ptrs: [u32; 5],
}

impl QueueTransferDescriptor {
    /// PID codes
    pub const PID_OUT: u32 = 0 << 8;
    pub const PID_IN: u32 = 1 << 8;
    pub const PID_SETUP: u32 = 2 << 8;

    /// Token bits
    pub const TOKEN_ACTIVE: u32 = 1 << 7;
    pub const TOKEN_HALTED: u32 = 1 << 6;
    pub const TOKEN_DATA_BUFFER_ERROR: u32 = 1 << 5;
    pub const TOKEN_BABBLE: u32 = 1 << 4;
    pub const TOKEN_XACT_ERROR: u32 = 1 << 3;
    pub const TOKEN_MISSED_UFRAME: u32 = 1 << 2;
    pub const TOKEN_SPLIT_STATE: u32 = 1 << 1;
    pub const TOKEN_PING_STATE: u32 = 1 << 0;
    pub const TOKEN_ERROR_MASK: u32 = Self::TOKEN_HALTED
        | Self::TOKEN_DATA_BUFFER_ERROR
        | Self::TOKEN_BABBLE
        | Self::TOKEN_XACT_ERROR;

    /// Create a SETUP stage qTD
    pub fn setup(setup_packet: &[u8; 8], data_toggle: bool) -> Self {
        let mut qtd = Self::default();
        qtd.next_qtd = 1; // Terminated (will be linked later)
        qtd.alt_qtd = 1;
        qtd.token = Self::PID_SETUP
            | Self::TOKEN_ACTIVE
            | (3 << 10) // CERR = 3
            | (8 << 16); // Total bytes = 8
        if data_toggle {
            qtd.token |= 1 << 31; // Data toggle
        }
        // Copy setup packet to first buffer
        qtd.buffer_ptrs[0] = setup_packet.as_ptr() as u32;
        qtd
    }

    /// Create a DATA stage qTD
    pub fn data(buffer: *mut u8, length: usize, is_in: bool, data_toggle: bool) -> Self {
        let mut qtd = Self::default();
        qtd.next_qtd = 1;
        qtd.alt_qtd = 1;
        qtd.token = if is_in { Self::PID_IN } else { Self::PID_OUT }
            | Self::TOKEN_ACTIVE
            | (3 << 10) // CERR = 3
            | ((length as u32 & 0x7FFF) << 16); // Total bytes
        if data_toggle {
            qtd.token |= 1 << 31;
        }

        // Set up buffer pointers (can span up to 5 pages)
        let mut addr = buffer as usize;
        let mut remaining = length;
        for i in 0..5 {
            if remaining == 0 {
                break;
            }
            qtd.buffer_ptrs[i] = addr as u32;
            let page_offset = addr & 0xFFF;
            let this_page = (0x1000 - page_offset).min(remaining);
            addr += this_page;
            remaining -= this_page;
        }

        qtd
    }

    /// Create a STATUS stage qTD
    pub fn status(is_in: bool) -> Self {
        let mut qtd = Self::default();
        qtd.next_qtd = 1;
        qtd.alt_qtd = 1;
        qtd.token = if is_in { Self::PID_IN } else { Self::PID_OUT }
            | Self::TOKEN_ACTIVE
            | (3 << 10) // CERR = 3
            | (1 << 15) // IOC (Interrupt on Complete)
            | (1 << 31); // Data toggle = 1 for status
        qtd
    }

    /// Check if transfer is complete
    pub fn is_complete(&self) -> bool {
        (self.token & Self::TOKEN_ACTIVE) == 0
    }

    /// Check if transfer had errors
    pub fn has_error(&self) -> bool {
        (self.token & Self::TOKEN_ERROR_MASK) != 0
    }

    /// Get the number of bytes transferred
    pub fn bytes_transferred(&self, original_length: usize) -> usize {
        let remaining = ((self.token >> 16) & 0x7FFF) as usize;
        original_length.saturating_sub(remaining)
    }
}

// ============================================================================
// USB Device State
// ============================================================================

/// EHCI USB device state
pub struct EhciDevice {
    /// Device address (1-127)
    pub address: u8,
    /// Port number (0-based)
    pub port: u8,
    /// Device speed
    pub speed: UsbSpeed,
    /// Device descriptor
    pub device_desc: DeviceDescriptor,
    /// Configuration info
    pub config_info: ConfigurationInfo,
    /// Is mass storage device
    pub is_mass_storage: bool,
    /// Is HID keyboard
    pub is_hid_keyboard: bool,
    /// Bulk IN endpoint
    pub bulk_in: Option<EndpointInfo>,
    /// Bulk OUT endpoint
    pub bulk_out: Option<EndpointInfo>,
    /// Interrupt IN endpoint
    pub interrupt_in: Option<EndpointInfo>,
    /// Control endpoint max packet size
    pub ep0_max_packet: u16,
    /// Data toggle for bulk IN
    pub bulk_in_toggle: bool,
    /// Data toggle for bulk OUT
    pub bulk_out_toggle: bool,
}

impl EhciDevice {
    fn new(address: u8, port: u8, speed: UsbSpeed) -> Self {
        Self {
            address,
            port,
            speed,
            device_desc: DeviceDescriptor::default(),
            config_info: ConfigurationInfo::default(),
            is_mass_storage: false,
            is_hid_keyboard: false,
            bulk_in: None,
            bulk_out: None,
            interrupt_in: None,
            ep0_max_packet: speed.default_max_packet_size(),
            bulk_in_toggle: false,
            bulk_out_toggle: false,
        }
    }
}

// ============================================================================
// EHCI Controller
// ============================================================================

/// Maximum number of devices
const MAX_DEVICES: usize = 8;

/// Maximum number of ports
const MAX_PORTS: usize = 8;

/// EHCI Host Controller
pub struct EhciController {
    /// PCI address
    pci_address: PciAddress,
    /// MMIO base address
    mmio_base: u64,
    /// Operational registers base
    op_base: u64,
    /// Number of ports
    num_ports: u8,
    /// Devices
    devices: [Option<EhciDevice>; MAX_DEVICES],
    /// Next device address
    next_address: u8,
    /// Async list head QH
    async_qh: u64,
    /// Periodic frame list
    periodic_list: u64,
    /// DMA buffer for control transfers
    dma_buffer: u64,
}

impl EhciController {
    /// DMA buffer size (64KB)
    const DMA_BUFFER_SIZE: usize = 64 * 1024;

    /// Create a new EHCI controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, UsbError> {
        let mmio_base = pci_dev.mmio_base().ok_or(UsbError::NotReady)?;

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        // Read capability registers
        let cap_dword0 = unsafe { ptr::read_volatile(mmio_base as *const u32) };
        let caplength = (cap_dword0 & 0xFF) as u8;
        let hciversion = (cap_dword0 >> 16) & 0xFFFF;

        let hcsparams =
            unsafe { ptr::read_volatile((mmio_base + cap_regs::HCSPARAMS as u64) as *const u32) };
        let _hccparams =
            unsafe { ptr::read_volatile((mmio_base + cap_regs::HCCPARAMS as u64) as *const u32) };

        let num_ports = (hcsparams & 0xF) as u8;
        let op_base = mmio_base + caplength as u64;

        log::info!(
            "EHCI version: {}.{:02}, ports: {}",
            (hciversion >> 8) & 0xFF,
            hciversion & 0xFF,
            num_ports
        );

        // Allocate async list head QH (32-byte aligned)
        let async_qh = efi::allocate_pages(1).ok_or(UsbError::AllocationFailed)?;
        unsafe { ptr::write_bytes(async_qh as *mut u8, 0, 4096) };

        // Allocate periodic frame list (4KB, 4KB-aligned)
        let periodic_list = efi::allocate_pages(1).ok_or(UsbError::AllocationFailed)?;
        // Initialize to all terminated entries
        unsafe {
            let list = periodic_list as *mut u32;
            for i in 0..1024 {
                ptr::write_volatile(list.add(i), 1); // T-bit set
            }
        }

        // Allocate DMA buffer
        let dma_pages = (Self::DMA_BUFFER_SIZE + 4095) / 4096;
        let dma_buffer = efi::allocate_pages(dma_pages as u64).ok_or(UsbError::AllocationFailed)?;

        let mut controller = Self {
            pci_address: pci_dev.address,
            mmio_base,
            op_base,
            num_ports: num_ports.min(MAX_PORTS as u8),
            devices: core::array::from_fn(|_| None),
            next_address: 1,
            async_qh,
            periodic_list,
            dma_buffer,
        };

        controller.init()?;
        controller.enumerate_ports()?;

        Ok(controller)
    }

    fn read_op_reg(&self, offset: u32) -> u32 {
        unsafe { ptr::read_volatile((self.op_base + offset as u64) as *const u32) }
    }

    fn write_op_reg(&mut self, offset: u32, value: u32) {
        unsafe { ptr::write_volatile((self.op_base + offset as u64) as *mut u32, value) }
    }

    fn read_port_reg(&self, port: u8) -> u32 {
        let addr = self.op_base + op_regs::PORTSC_BASE as u64 + (port as u64 * 4);
        unsafe { ptr::read_volatile(addr as *const u32) }
    }

    fn write_port_reg(&mut self, port: u8, value: u32) {
        let addr = self.op_base + op_regs::PORTSC_BASE as u64 + (port as u64 * 4);
        unsafe { ptr::write_volatile(addr as *mut u32, value) }
    }

    /// Initialize the controller
    fn init(&mut self) -> Result<(), UsbError> {
        // Stop the controller
        let cmd = self.read_op_reg(op_regs::USBCMD);
        self.write_op_reg(op_regs::USBCMD, cmd & !usbcmd::RS);

        // Wait for halt
        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if self.read_op_reg(op_regs::USBSTS) & usbsts::HCHALTED != 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // Reset the controller
        self.write_op_reg(op_regs::USBCMD, usbcmd::HCRESET);

        let timeout = Timeout::from_ms(500);
        while !timeout.is_expired() {
            if self.read_op_reg(op_regs::USBCMD) & usbcmd::HCRESET == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        if self.read_op_reg(op_regs::USBCMD) & usbcmd::HCRESET != 0 {
            return Err(UsbError::Timeout);
        }

        // Set up async list head (circular, pointing to itself)
        let qh = unsafe { &mut *(self.async_qh as *mut QueueHead) };
        qh.horiz_link_ptr = (self.async_qh as u32) | 2; // QH type
        qh.ep_chars = 1 << 15; // Head of Reclamation List Flag
        qh.overlay.next_qtd = 1; // Terminated
        qh.overlay.alt_qtd = 1;
        qh.overlay.token = 0;

        // Configure the controller
        self.write_op_reg(op_regs::USBINTR, 0); // Disable interrupts
        self.write_op_reg(op_regs::PERIODICLISTBASE, self.periodic_list as u32);
        self.write_op_reg(op_regs::ASYNCLISTADDR, self.async_qh as u32);
        self.write_op_reg(op_regs::CTRLDSSEGMENT, 0); // Use 32-bit addresses

        // Set configured flag (take ownership from companion controllers)
        self.write_op_reg(op_regs::CONFIGFLAG, 1);

        // Start the controller
        let cmd = usbcmd::RS | usbcmd::ASE | usbcmd::FLS_1024 | usbcmd::ITC_8;
        self.write_op_reg(op_regs::USBCMD, cmd);

        // Wait for running
        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if self.read_op_reg(op_regs::USBSTS) & usbsts::HCHALTED == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // Wait a bit for ports to stabilize
        crate::time::delay_ms(100);

        log::info!("EHCI controller initialized");
        Ok(())
    }

    /// Enumerate ports and attach devices
    fn enumerate_ports(&mut self) -> Result<(), UsbError> {
        for port in 0..self.num_ports {
            let portsc = self.read_port_reg(port);

            // Check if device connected
            if portsc & portsc::CCS == 0 {
                continue;
            }

            // Check line state - if K-state, it's a low-speed device
            // that should be handled by companion controller
            let line_status = portsc & portsc::LS_MASK;
            if line_status == portsc::LS_KSTATE {
                log::debug!("Port {}: Low-speed device, releasing to companion", port);
                // Release to companion controller
                self.write_port_reg(port, portsc | portsc::PO);
                continue;
            }

            log::info!("EHCI: Device detected on port {}", port);

            // Reset the port
            let portsc = self.read_port_reg(port);
            self.write_port_reg(port, (portsc & !portsc::PE) | portsc::PR);

            crate::time::delay_ms(50); // USB spec requires at least 50ms reset

            // Clear reset
            let portsc = self.read_port_reg(port);
            self.write_port_reg(port, portsc & !portsc::PR);

            crate::time::delay_ms(10);

            // Check if port is now enabled (high-speed device)
            let portsc = self.read_port_reg(port);
            if portsc & portsc::PE == 0 {
                // Not high-speed, release to companion
                log::debug!("Port {}: Full-speed device, releasing to companion", port);
                self.write_port_reg(port, portsc | portsc::PO);
                continue;
            }

            // Clear status change bits
            self.write_port_reg(port, portsc | portsc::W1C_MASK);

            // Enumerate the device
            if let Err(e) = self.attach_device(port) {
                log::error!("Failed to attach device on port {}: {:?}", port, e);
            }
        }

        Ok(())
    }

    /// Attach a device on a port
    fn attach_device(&mut self, port: u8) -> Result<(), UsbError> {
        // Allocate device address
        let address = self.next_address;
        if address >= 128 {
            return Err(UsbError::NoFreeSlots);
        }

        // Find a free slot
        let slot = self
            .devices
            .iter()
            .position(|d| d.is_none())
            .ok_or(UsbError::NoFreeSlots)?;

        // Create device with address 0 initially
        let mut device = EhciDevice::new(0, port, UsbSpeed::High);

        // Get device descriptor (first 8 bytes) to determine max packet size
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

        // Set device address
        self.control_transfer_internal(
            &device,
            req_type::DIR_OUT | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::SET_ADDRESS,
            address as u16,
            0,
            None,
        )?;

        crate::time::delay_ms(2); // USB spec SET_ADDRESS recovery time

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

        let vid = device.device_desc.vendor_id;
        let pid = device.device_desc.product_id;
        let dev_class = device.device_desc.device_class;

        log::info!(
            "  Device {}: VID={:04x} PID={:04x} Class={:02x}",
            address,
            vid,
            pid,
            dev_class
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

        // Parse configuration
        device.config_info = parse_configuration(&config_buf[..total_len]);

        // Find mass storage or HID interface
        for iface in &device.config_info.interfaces[..device.config_info.num_interfaces] {
            if iface.is_mass_storage() {
                device.is_mass_storage = true;
                device.bulk_in = iface.find_bulk_in().cloned();
                device.bulk_out = iface.find_bulk_out().cloned();
                log::info!("    Mass Storage interface found");
            } else if iface.is_hid_keyboard() {
                device.is_hid_keyboard = true;
                device.interrupt_in = iface.find_interrupt_in().cloned();
                log::info!("    HID Keyboard interface found");
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

        self.devices[slot] = Some(device);
        Ok(())
    }

    /// Internal control transfer (doesn't require mutable device)
    fn control_transfer_internal(
        &mut self,
        device: &EhciDevice,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: Option<&mut [u8]>,
    ) -> Result<usize, UsbError> {
        let is_in = (request_type & 0x80) != 0;
        let data_len = data.as_ref().map(|d| d.len()).unwrap_or(0);

        // Build setup packet in DMA buffer
        let setup_packet = self.dma_buffer as *mut [u8; 8];
        unsafe {
            (*setup_packet)[0] = request_type;
            (*setup_packet)[1] = request;
            (*setup_packet)[2] = value as u8;
            (*setup_packet)[3] = (value >> 8) as u8;
            (*setup_packet)[4] = index as u8;
            (*setup_packet)[5] = (index >> 8) as u8;
            (*setup_packet)[6] = data_len as u8;
            (*setup_packet)[7] = (data_len >> 8) as u8;
        }

        // Allocate QH and qTDs
        let qh_addr = self.dma_buffer + 64; // After setup packet
        let qtd_base = qh_addr + 64; // After QH
        let data_buffer = qtd_base + 256; // After qTDs

        // Copy data to DMA buffer for OUT transfers
        if let Some(ref d) = data {
            if !is_in {
                unsafe {
                    ptr::copy_nonoverlapping(d.as_ptr(), data_buffer as *mut u8, d.len());
                }
            }
        }

        // Create QH
        let qh = unsafe { &mut *(qh_addr as *mut QueueHead) };
        *qh = QueueHead::new(device.address, 0, device.ep0_max_packet, device.speed, true);

        // Create qTDs
        let setup_qtd = unsafe { &mut *(qtd_base as *mut QueueTransferDescriptor) };
        let setup_array = unsafe { &*(self.dma_buffer as *const [u8; 8]) };
        *setup_qtd = QueueTransferDescriptor::setup(setup_array, false);

        let mut qtd_count = 1;

        if data_len > 0 {
            let data_qtd = unsafe { &mut *((qtd_base + 32) as *mut QueueTransferDescriptor) };
            *data_qtd =
                QueueTransferDescriptor::data(data_buffer as *mut u8, data_len, is_in, true);
            setup_qtd.next_qtd = (qtd_base + 32) as u32;
            qtd_count = 2;
        }

        let status_qtd =
            unsafe { &mut *((qtd_base + qtd_count * 32) as *mut QueueTransferDescriptor) };
        *status_qtd = QueueTransferDescriptor::status(!is_in || data_len == 0);

        if data_len > 0 {
            let data_qtd = unsafe { &mut *((qtd_base + 32) as *mut QueueTransferDescriptor) };
            data_qtd.next_qtd = (qtd_base + qtd_count * 32) as u32;
        } else {
            setup_qtd.next_qtd = (qtd_base + qtd_count * 32) as u32;
        }

        // Link QH to async schedule
        qh.overlay.next_qtd = qtd_base as u32;
        qh.cur_qtd = 0;

        // Insert QH into async list
        let head_qh = unsafe { &mut *(self.async_qh as *mut QueueHead) };
        qh.horiz_link_ptr = head_qh.horiz_link_ptr;
        fence(Ordering::SeqCst);
        head_qh.horiz_link_ptr = (qh_addr as u32) | 2; // QH type
        fence(Ordering::SeqCst);

        // Wait for completion
        let timeout = Timeout::from_ms(5000);
        while !timeout.is_expired() {
            fence(Ordering::SeqCst);
            if status_qtd.is_complete() {
                break;
            }
            core::hint::spin_loop();
        }

        // Remove QH from async list
        head_qh.horiz_link_ptr = qh.horiz_link_ptr;
        fence(Ordering::SeqCst);

        // Ring doorbell to ensure removal
        let cmd = self.read_op_reg(op_regs::USBCMD);
        self.write_op_reg(op_regs::USBCMD, cmd | usbcmd::IAAD);

        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if self.read_op_reg(op_regs::USBSTS) & usbsts::IAA != 0 {
                self.write_op_reg(op_regs::USBSTS, usbsts::IAA);
                break;
            }
            core::hint::spin_loop();
        }

        // Check for errors
        if !status_qtd.is_complete() {
            return Err(UsbError::Timeout);
        }

        if status_qtd.has_error() || setup_qtd.has_error() {
            if status_qtd.token & QueueTransferDescriptor::TOKEN_HALTED != 0 {
                return Err(UsbError::Stall);
            }
            return Err(UsbError::TransactionError);
        }

        // Copy data back for IN transfers
        if let Some(d) = data {
            if is_in {
                let data_qtd = unsafe { &*((qtd_base + 32) as *const QueueTransferDescriptor) };
                let transferred = data_qtd.bytes_transferred(d.len());
                unsafe {
                    ptr::copy_nonoverlapping(data_buffer as *const u8, d.as_mut_ptr(), transferred);
                }
                return Ok(transferred);
            }
        }

        Ok(data_len)
    }

    /// Get mutable device reference
    fn get_device_mut(&mut self, address: u8) -> Option<&mut EhciDevice> {
        self.devices
            .iter_mut()
            .find_map(|d| d.as_mut().filter(|d| d.address == address))
    }

    /// Get device reference
    fn get_device(&self, address: u8) -> Option<&EhciDevice> {
        self.devices
            .iter()
            .find_map(|d| d.as_ref().filter(|d| d.address == address))
    }

    /// Get PCI address
    pub fn pci_address(&self) -> PciAddress {
        self.pci_address
    }
}

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
        let dev_copy = EhciDevice {
            address: dev.address,
            port: dev.port,
            speed: dev.speed,
            device_desc: dev.device_desc.clone(),
            config_info: dev.config_info.clone(),
            is_mass_storage: dev.is_mass_storage,
            is_hid_keyboard: dev.is_hid_keyboard,
            bulk_in: dev.bulk_in.clone(),
            bulk_out: dev.bulk_out.clone(),
            interrupt_in: dev.interrupt_in.clone(),
            ep0_max_packet: dev.ep0_max_packet,
            bulk_in_toggle: dev.bulk_in_toggle,
            bulk_out_toggle: dev.bulk_out_toggle,
        };
        self.control_transfer_internal(&dev_copy, request_type, request, value, index, data)
    }

    fn bulk_transfer(
        &mut self,
        device: u8,
        endpoint: u8,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<usize, UsbError> {
        let dev = self.get_device(device).ok_or(UsbError::DeviceNotFound)?;

        let ep_info = if is_in {
            dev.bulk_in.as_ref()
        } else {
            dev.bulk_out.as_ref()
        }
        .ok_or(UsbError::InvalidParameter)?;

        let max_packet = ep_info.max_packet_size;
        let toggle = if is_in {
            dev.bulk_in_toggle
        } else {
            dev.bulk_out_toggle
        };

        // Allocate QH and qTD
        let qh_addr = self.dma_buffer;
        let qtd_addr = qh_addr + 64;
        let data_buffer = qtd_addr + 64;

        // Copy data for OUT
        if !is_in {
            unsafe {
                ptr::copy_nonoverlapping(data.as_ptr(), data_buffer as *mut u8, data.len());
            }
        }

        // Create QH
        let qh = unsafe { &mut *(qh_addr as *mut QueueHead) };
        *qh = QueueHead::new(dev.address, endpoint, max_packet, dev.speed, false);

        // Create qTD
        let qtd = unsafe { &mut *(qtd_addr as *mut QueueTransferDescriptor) };
        *qtd = QueueTransferDescriptor::data(data_buffer as *mut u8, data.len(), is_in, toggle);
        qtd.token |= 1 << 15; // IOC

        qh.overlay.next_qtd = qtd_addr as u32;
        qh.cur_qtd = 0;

        // Insert into async list
        let head_qh = unsafe { &mut *(self.async_qh as *mut QueueHead) };
        qh.horiz_link_ptr = head_qh.horiz_link_ptr;
        fence(Ordering::SeqCst);
        head_qh.horiz_link_ptr = (qh_addr as u32) | 2;
        fence(Ordering::SeqCst);

        // Wait for completion
        let timeout = Timeout::from_ms(5000);
        while !timeout.is_expired() {
            fence(Ordering::SeqCst);
            if qtd.is_complete() {
                break;
            }
            core::hint::spin_loop();
        }

        // Remove from list
        head_qh.horiz_link_ptr = qh.horiz_link_ptr;
        fence(Ordering::SeqCst);

        // Check result
        if !qtd.is_complete() {
            return Err(UsbError::Timeout);
        }

        if qtd.has_error() {
            if qtd.token & QueueTransferDescriptor::TOKEN_HALTED != 0 {
                return Err(UsbError::Stall);
            }
            return Err(UsbError::TransactionError);
        }

        let transferred = qtd.bytes_transferred(data.len());

        // Update toggle
        if let Some(dev) = self.get_device_mut(device) {
            let new_toggle = (qtd.token >> 31) != 0;
            if is_in {
                dev.bulk_in_toggle = !new_toggle;
            } else {
                dev.bulk_out_toggle = !new_toggle;
            }
        }

        // Copy data for IN
        if is_in {
            unsafe {
                ptr::copy_nonoverlapping(data_buffer as *const u8, data.as_mut_ptr(), transferred);
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

impl EhciController {
    /// Clean up the controller before handing off to the OS
    ///
    /// This must be called before ExitBootServices to ensure Linux's EHCI
    /// driver can properly initialize the controller. Following libpayload's
    /// ehci_shutdown pattern.
    pub fn cleanup(&mut self) {
        log::debug!("EHCI cleanup: stopping controller");

        // 1. Disable async schedule
        let cmd = self.read_op_reg(op_regs::USBCMD);
        self.write_op_reg(op_regs::USBCMD, cmd & !usbcmd::ASE);

        // Wait for async schedule to stop
        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if self.read_op_reg(op_regs::USBSTS) & usbsts::ASS == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // 2. Disable periodic schedule
        let cmd = self.read_op_reg(op_regs::USBCMD);
        self.write_op_reg(op_regs::USBCMD, cmd & !usbcmd::PSE);

        // Wait for periodic schedule to stop
        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if self.read_op_reg(op_regs::USBSTS) & usbsts::PSS == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // 3. Stop the controller
        let cmd = self.read_op_reg(op_regs::USBCMD);
        self.write_op_reg(op_regs::USBCMD, cmd & !usbcmd::RS);

        // Wait for halt
        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if self.read_op_reg(op_regs::USBSTS) & usbsts::HCHALTED != 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // 4. Give all ports back to companion controllers (OHCI/UHCI)
        // This is critical - without this, Linux's EHCI driver may fail
        self.write_op_reg(op_regs::CONFIGFLAG, 0);

        log::debug!("EHCI cleanup complete");
    }
}
