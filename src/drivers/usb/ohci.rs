//! OHCI (USB 1.1) Host Controller Interface driver
//!
//! This module provides support for USB 1.1 full/low-speed devices via the
//! Open Host Controller Interface.
//!
//! # References
//! - OHCI Specification 1.0a
//! - libpayload ohci.c

use crate::drivers::pci::{self, PciAddress, PciDevice};
use crate::efi;
use crate::time::Timeout;
use core::ptr;
use core::sync::atomic::{fence, Ordering};

use super::controller::{
    desc_type, parse_configuration, req_type, request, DeviceDescriptor, DeviceInfo, Direction,
    EndpointInfo, UsbController, UsbDevice, UsbError, UsbSpeed,
};

// ============================================================================
// OHCI Register Definitions
// ============================================================================

/// OHCI Operational Registers
#[allow(dead_code)]
mod regs {
    /// Revision
    pub const HCREVISION: u32 = 0x00;
    /// Control
    pub const HCCONTROL: u32 = 0x04;
    /// Command Status
    pub const HCCOMMANDSTATUS: u32 = 0x08;
    /// Interrupt Status
    pub const HCINTERRUPTSTATUS: u32 = 0x0C;
    /// Interrupt Enable
    pub const HCINTERRUPTENABLE: u32 = 0x10;
    /// Interrupt Disable
    pub const HCINTERRUPTDISABLE: u32 = 0x14;
    /// HCCA
    pub const HCHCCA: u32 = 0x18;
    /// Period Current ED
    pub const HCPERIODCURRENTED: u32 = 0x1C;
    /// Control Head ED
    pub const HCCONTROLHEADED: u32 = 0x20;
    /// Control Current ED
    pub const HCCONTROLCURRENTED: u32 = 0x24;
    /// Bulk Head ED
    pub const HCBULKHEADED: u32 = 0x28;
    /// Bulk Current ED
    pub const HCBULKCURRENTED: u32 = 0x2C;
    /// Done Head
    pub const HCDONEHEAD: u32 = 0x30;
    /// Frame Interval
    pub const HCFMINTERVAL: u32 = 0x34;
    /// Frame Remaining
    pub const HCFMREMAINING: u32 = 0x38;
    /// Frame Number
    pub const HCFMNUMBER: u32 = 0x3C;
    /// Periodic Start
    pub const HCPERIODICSTART: u32 = 0x40;
    /// LS Threshold
    pub const HCLSTHRESHOLD: u32 = 0x44;
    /// Root Hub Descriptor A
    pub const HCRHDESCRIPTORA: u32 = 0x48;
    /// Root Hub Descriptor B
    pub const HCRHDESCRIPTORB: u32 = 0x4C;
    /// Root Hub Status
    pub const HCRHSTATUS: u32 = 0x50;
    /// Root Hub Port Status (base)
    pub const HCRHPORTSTATUS: u32 = 0x54;
}

/// HcControl register bits
#[allow(dead_code)]
mod hccontrol {
    /// Control/Bulk Service Ratio
    pub const CBSR_MASK: u32 = 3 << 0;
    /// Periodic List Enable
    pub const PLE: u32 = 1 << 2;
    /// Isochronous Enable
    pub const IE: u32 = 1 << 3;
    /// Control List Enable
    pub const CLE: u32 = 1 << 4;
    /// Bulk List Enable
    pub const BLE: u32 = 1 << 5;
    /// Host Controller Functional State
    pub const HCFS_MASK: u32 = 3 << 6;
    pub const HCFS_RESET: u32 = 0 << 6;
    pub const HCFS_RESUME: u32 = 1 << 6;
    pub const HCFS_OPERATIONAL: u32 = 2 << 6;
    pub const HCFS_SUSPEND: u32 = 3 << 6;
    /// Interrupt Routing
    pub const IR: u32 = 1 << 8;
    /// Remote Wakeup Connected
    pub const RWC: u32 = 1 << 9;
    /// Remote Wakeup Enable
    pub const RWE: u32 = 1 << 10;
}

/// HcCommandStatus register bits
mod hccommandstatus {
    /// Host Controller Reset
    pub const HCR: u32 = 1 << 0;
    /// Control List Filled
    pub const CLF: u32 = 1 << 1;
    /// Bulk List Filled
    pub const BLF: u32 = 1 << 2;
    /// Ownership Change Request
    pub const OCR: u32 = 1 << 3;
}

/// Root Hub Port Status bits
#[allow(dead_code)]
mod rhportstatus {
    /// Current Connect Status
    pub const CCS: u32 = 1 << 0;
    /// Port Enable Status
    pub const PES: u32 = 1 << 1;
    /// Port Suspend Status
    pub const PSS: u32 = 1 << 2;
    /// Port Over Current Indicator
    pub const POCI: u32 = 1 << 3;
    /// Port Reset Status
    pub const PRS: u32 = 1 << 4;
    /// Port Power Status
    pub const PPS: u32 = 1 << 8;
    /// Low Speed Device Attached
    pub const LSDA: u32 = 1 << 9;
    /// Connect Status Change
    pub const CSC: u32 = 1 << 16;
    /// Port Enable Status Change
    pub const PESC: u32 = 1 << 17;
    /// Port Suspend Status Change
    pub const PSSC: u32 = 1 << 18;
    /// Port Over Current Indicator Change
    pub const OCIC: u32 = 1 << 19;
    /// Port Reset Status Change
    pub const PRSC: u32 = 1 << 20;
    /// Clear bits mask
    pub const CLEAR_MASK: u32 = CSC | PESC | PSSC | OCIC | PRSC;
}

// ============================================================================
// OHCI Data Structures
// ============================================================================

/// Host Controller Communication Area (256 bytes, 256-byte aligned)
#[repr(C, align(256))]
#[derive(Clone, Copy)]
pub struct Hcca {
    /// Interrupt table (32 entries)
    pub interrupt_table: [u32; 32],
    /// Frame number
    pub frame_number: u16,
    /// Pad
    pub pad1: u16,
    /// Done head
    pub done_head: u32,
    /// Reserved
    pub reserved: [u8; 116],
}

impl Default for Hcca {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// Endpoint Descriptor (16 bytes, 16-byte aligned)
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct EndpointDescriptor {
    /// Control
    pub control: u32,
    /// Tail TD pointer
    pub tail_td: u32,
    /// Head TD pointer
    pub head_td: u32,
    /// Next ED pointer
    pub next_ed: u32,
}

impl EndpointDescriptor {
    /// Control field bits
    pub const CTRL_FA_MASK: u32 = 0x7F; // Function address
    pub const CTRL_EN_SHIFT: u32 = 7; // Endpoint number
    pub const CTRL_EN_MASK: u32 = 0xF << 7;
    pub const CTRL_D_SHIFT: u32 = 11; // Direction
    pub const CTRL_D_OUT: u32 = 1 << 11;
    pub const CTRL_D_IN: u32 = 2 << 11;
    pub const CTRL_S: u32 = 1 << 13; // Speed (1 = low speed)
    pub const CTRL_K: u32 = 1 << 14; // Skip
    pub const CTRL_F: u32 = 1 << 15; // Format (1 = isochronous)
    pub const CTRL_MPS_SHIFT: u32 = 16; // Max packet size
    pub const CTRL_MPS_MASK: u32 = 0x7FF << 16;

    /// Head TD bits
    pub const HEAD_HALTED: u32 = 1 << 0;
    pub const HEAD_TOGGLE: u32 = 1 << 1;

    /// Create a new ED
    pub fn new(
        device_addr: u8,
        endpoint: u8,
        max_packet: u16,
        is_low_speed: bool,
        direction: Option<Direction>,
    ) -> Self {
        let mut control = (device_addr as u32) & Self::CTRL_FA_MASK;
        control |= ((endpoint as u32) << Self::CTRL_EN_SHIFT) & Self::CTRL_EN_MASK;
        control |= ((max_packet as u32) << Self::CTRL_MPS_SHIFT) & Self::CTRL_MPS_MASK;

        if is_low_speed {
            control |= Self::CTRL_S;
        }

        if let Some(dir) = direction {
            match dir {
                Direction::Out => control |= Self::CTRL_D_OUT,
                Direction::In => control |= Self::CTRL_D_IN,
                Direction::Setup => {} // From TD
            }
        }

        Self {
            control,
            tail_td: 0,
            head_td: 0,
            next_ed: 0,
        }
    }

    /// Check if ED is halted
    pub fn is_halted(&self) -> bool {
        (self.head_td & Self::HEAD_HALTED) != 0
    }

    /// Check if head == tail (empty)
    pub fn is_empty(&self) -> bool {
        (self.head_td & !0xF) == (self.tail_td & !0xF)
    }
}

/// Transfer Descriptor (16 bytes, 16-byte aligned)
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct TransferDescriptor {
    /// Control
    pub control: u32,
    /// Current Buffer Pointer
    pub cbp: u32,
    /// Next TD
    pub next_td: u32,
    /// Buffer End
    pub be: u32,
}

impl TransferDescriptor {
    /// Control field bits
    pub const CTRL_R: u32 = 1 << 18; // Buffer Rounding
    pub const CTRL_DP_SHIFT: u32 = 19; // Direction/PID
    pub const CTRL_DP_SETUP: u32 = 0 << 19;
    pub const CTRL_DP_OUT: u32 = 1 << 19;
    pub const CTRL_DP_IN: u32 = 2 << 19;
    pub const CTRL_DI_SHIFT: u32 = 21; // Delay Interrupt
    pub const CTRL_DI_NONE: u32 = 7 << 21;
    pub const CTRL_T_SHIFT: u32 = 24; // Data Toggle
    pub const CTRL_T_DATA0: u32 = 2 << 24;
    pub const CTRL_T_DATA1: u32 = 3 << 24;
    pub const CTRL_EC_SHIFT: u32 = 26; // Error Count
    pub const CTRL_CC_SHIFT: u32 = 28; // Condition Code
    pub const CTRL_CC_MASK: u32 = 0xF << 28;
    pub const CTRL_CC_NOT_ACCESSED: u32 = 0xF << 28;

    /// Condition codes
    pub const CC_NO_ERROR: u32 = 0;
    pub const CC_CRC: u32 = 1;
    pub const CC_BIT_STUFFING: u32 = 2;
    pub const CC_DATA_TOGGLE: u32 = 3;
    pub const CC_STALL: u32 = 4;
    pub const CC_DEVICE_NOT_RESPONDING: u32 = 5;
    pub const CC_PID_CHECK_FAILURE: u32 = 6;
    pub const CC_UNEXPECTED_PID: u32 = 7;
    pub const CC_DATA_OVERRUN: u32 = 8;
    pub const CC_DATA_UNDERRUN: u32 = 9;
    pub const CC_BUFFER_OVERRUN: u32 = 12;
    pub const CC_BUFFER_UNDERRUN: u32 = 13;
    pub const CC_NOT_ACCESSED: u32 = 14;

    /// Create a SETUP TD
    pub fn setup(buffer: u32, next: u32) -> Self {
        Self {
            control: Self::CTRL_DP_SETUP | Self::CTRL_T_DATA0 | Self::CTRL_CC_NOT_ACCESSED,
            cbp: buffer,
            next_td: next,
            be: buffer + 7, // 8 bytes
        }
    }

    /// Create a DATA TD
    pub fn data(buffer: u32, length: usize, is_in: bool, toggle: bool, next: u32) -> Self {
        let mut control = if is_in {
            Self::CTRL_DP_IN
        } else {
            Self::CTRL_DP_OUT
        };
        control |= Self::CTRL_R; // Buffer rounding
        control |= if toggle {
            Self::CTRL_T_DATA1
        } else {
            Self::CTRL_T_DATA0
        };
        control |= Self::CTRL_CC_NOT_ACCESSED;

        Self {
            control,
            cbp: if length > 0 { buffer } else { 0 },
            next_td: next,
            be: if length > 0 {
                buffer + (length as u32) - 1
            } else {
                0
            },
        }
    }

    /// Create a STATUS TD
    pub fn status(is_in: bool, next: u32) -> Self {
        let mut control = if is_in {
            Self::CTRL_DP_IN
        } else {
            Self::CTRL_DP_OUT
        };
        control |= Self::CTRL_T_DATA1;
        control |= Self::CTRL_CC_NOT_ACCESSED;
        control |= 0 << Self::CTRL_DI_SHIFT; // Immediate interrupt

        Self {
            control,
            cbp: 0,
            next_td: next,
            be: 0,
        }
    }

    /// Get condition code
    pub fn condition_code(&self) -> u32 {
        (self.control >> Self::CTRL_CC_SHIFT) & 0xF
    }

    /// Check if TD is complete
    pub fn is_complete(&self) -> bool {
        self.condition_code() != Self::CC_NOT_ACCESSED
    }

    /// Check if TD has error
    pub fn has_error(&self) -> bool {
        let cc = self.condition_code();
        cc != Self::CC_NO_ERROR && cc != Self::CC_NOT_ACCESSED && cc != Self::CC_DATA_UNDERRUN
    }
}

// UsbDevice is now UsbDevice from controller.rs

// ============================================================================
// OHCI Controller
// ============================================================================

/// Maximum number of devices
const MAX_DEVICES: usize = 8;

/// Maximum number of ports
const MAX_PORTS: usize = 8;

/// OHCI Host Controller
pub struct OhciController {
    /// PCI address
    pci_address: PciAddress,
    /// MMIO base address
    mmio_base: u64,
    /// Number of ports
    num_ports: u8,
    /// Devices
    devices: [Option<UsbDevice>; MAX_DEVICES],
    /// Next device address
    next_address: u8,
    /// HCCA
    hcca: u64,
    /// Control ED list head
    control_ed: u64,
    /// Bulk ED list head
    bulk_ed: u64,
    /// DMA buffer
    dma_buffer: u64,
}

impl OhciController {
    /// DMA buffer size (64KB)
    const DMA_BUFFER_SIZE: usize = 64 * 1024;

    /// Create a new OHCI controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, UsbError> {
        let mmio_base = pci_dev.mmio_base().ok_or(UsbError::NotReady)?;

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        // Read revision
        let revision =
            unsafe { ptr::read_volatile((mmio_base + regs::HCREVISION as u64) as *const u32) };
        let version = revision & 0xFF;

        log::info!("OHCI version: {}.{}", (version >> 4) & 0xF, version & 0xF);

        // Get number of ports from RhDescriptorA
        let rh_desc_a =
            unsafe { ptr::read_volatile((mmio_base + regs::HCRHDESCRIPTORA as u64) as *const u32) };
        let num_ports = (rh_desc_a & 0xFF) as u8;

        log::info!("OHCI: {} ports", num_ports);

        // Allocate HCCA (256-byte aligned)
        let hcca = efi::allocate_pages(1).ok_or(UsbError::AllocationFailed)?;
        unsafe { ptr::write_bytes(hcca as *mut u8, 0, 4096) };

        // Allocate control ED
        let control_ed = efi::allocate_pages(1).ok_or(UsbError::AllocationFailed)?;
        unsafe { ptr::write_bytes(control_ed as *mut u8, 0, 4096) };

        // Allocate bulk ED
        let bulk_ed = efi::allocate_pages(1).ok_or(UsbError::AllocationFailed)?;
        unsafe { ptr::write_bytes(bulk_ed as *mut u8, 0, 4096) };

        // Allocate DMA buffer
        let dma_pages = (Self::DMA_BUFFER_SIZE + 4095) / 4096;
        let dma_buffer = efi::allocate_pages(dma_pages as u64).ok_or(UsbError::AllocationFailed)?;

        let mut controller = Self {
            pci_address: pci_dev.address,
            mmio_base,
            num_ports: num_ports.min(MAX_PORTS as u8),
            devices: core::array::from_fn(|_| None),
            next_address: 1,
            hcca,
            control_ed,
            bulk_ed,
            dma_buffer,
        };

        controller.init()?;
        controller.enumerate_ports()?;

        Ok(controller)
    }

    fn read_reg(&self, offset: u32) -> u32 {
        unsafe { ptr::read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    fn write_reg(&mut self, offset: u32, value: u32) {
        unsafe { ptr::write_volatile((self.mmio_base + offset as u64) as *mut u32, value) }
    }

    fn read_port_reg(&self, port: u8) -> u32 {
        let addr = self.mmio_base + regs::HCRHPORTSTATUS as u64 + (port as u64 * 4);
        unsafe { ptr::read_volatile(addr as *const u32) }
    }

    fn write_port_reg(&mut self, port: u8, value: u32) {
        let addr = self.mmio_base + regs::HCRHPORTSTATUS as u64 + (port as u64 * 4);
        unsafe { ptr::write_volatile(addr as *mut u32, value) }
    }

    /// Initialize the controller
    fn init(&mut self) -> Result<(), UsbError> {
        // Save frame interval
        let fminterval = self.read_reg(regs::HCFMINTERVAL);
        let fminterval_toggle = fminterval & (1 << 31);

        // Check if BIOS owns the controller (SMM)
        let control = self.read_reg(regs::HCCONTROL);
        if (control & hccontrol::IR) != 0 {
            // Request ownership
            self.write_reg(regs::HCCOMMANDSTATUS, hccommandstatus::OCR);

            let timeout = Timeout::from_ms(500);
            while !timeout.is_expired() {
                if (self.read_reg(regs::HCCONTROL) & hccontrol::IR) == 0 {
                    break;
                }
                core::hint::spin_loop();
            }
        }

        // Determine current state
        let current_state = control & hccontrol::HCFS_MASK;

        if current_state != hccontrol::HCFS_RESET {
            // If not in reset, put into reset
            self.write_reg(regs::HCCONTROL, hccontrol::HCFS_RESET);
            crate::time::delay_ms(50);
        }

        // Reset the controller
        self.write_reg(regs::HCCOMMANDSTATUS, hccommandstatus::HCR);

        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if (self.read_reg(regs::HCCOMMANDSTATUS) & hccommandstatus::HCR) == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        if (self.read_reg(regs::HCCOMMANDSTATUS) & hccommandstatus::HCR) != 0 {
            return Err(UsbError::Timeout);
        }

        // Now in USB Suspend state, we have 2ms to complete setup

        // Set HCCA
        self.write_reg(regs::HCHCCA, self.hcca as u32);

        // Set up dummy EDs for control and bulk lists
        let control_ed = unsafe { &mut *(self.control_ed as *mut EndpointDescriptor) };
        control_ed.control = EndpointDescriptor::CTRL_K; // Skip this ED
        control_ed.next_ed = 0;

        let bulk_ed = unsafe { &mut *(self.bulk_ed as *mut EndpointDescriptor) };
        bulk_ed.control = EndpointDescriptor::CTRL_K;
        bulk_ed.next_ed = 0;

        // Set ED list heads
        self.write_reg(regs::HCCONTROLHEADED, self.control_ed as u32);
        self.write_reg(regs::HCBULKHEADED, self.bulk_ed as u32);

        // Restore frame interval with toggle inverted
        let new_fminterval = (fminterval & 0x3FFF)
            | ((fminterval & 0x3FFF) << 16)
            | (!fminterval_toggle & (1 << 31));
        self.write_reg(regs::HCFMINTERVAL, new_fminterval);

        // Set periodic start (90% of frame interval)
        let periodic_start = ((fminterval & 0x3FFF) * 9) / 10;
        self.write_reg(regs::HCPERIODICSTART, periodic_start);

        // Clear interrupt status
        self.write_reg(regs::HCINTERRUPTSTATUS, 0xFFFFFFFF);

        // Enable control and bulk lists, go operational
        let control = hccontrol::CLE | hccontrol::BLE | hccontrol::HCFS_OPERATIONAL;
        self.write_reg(regs::HCCONTROL, control);

        // Power on all ports
        self.write_reg(regs::HCRHSTATUS, 1 << 16); // LPSC - Local Power Status Change

        crate::time::delay_ms(100); // Wait for power to stabilize

        log::info!("OHCI controller initialized");
        Ok(())
    }

    /// Enumerate ports and attach devices
    fn enumerate_ports(&mut self) -> Result<(), UsbError> {
        for port in 0..self.num_ports {
            let portsc = self.read_port_reg(port);

            // Clear status change bits
            self.write_port_reg(port, rhportstatus::CLEAR_MASK);

            // Check if device connected
            if (portsc & rhportstatus::CCS) == 0 {
                continue;
            }

            let is_low_speed = (portsc & rhportstatus::LSDA) != 0;
            log::info!(
                "OHCI: Device on port {} ({})",
                port,
                if is_low_speed {
                    "low-speed"
                } else {
                    "full-speed"
                }
            );

            // Reset the port
            self.write_port_reg(port, rhportstatus::PRS);

            // Wait for reset complete
            let timeout = Timeout::from_ms(100);
            while !timeout.is_expired() {
                let portsc = self.read_port_reg(port);
                if (portsc & rhportstatus::PRS) == 0 {
                    break;
                }
                core::hint::spin_loop();
            }

            crate::time::delay_ms(10); // Recovery time

            // Clear status change
            self.write_port_reg(port, rhportstatus::PRSC);

            // Check if enabled
            let portsc = self.read_port_reg(port);
            if (portsc & rhportstatus::PES) == 0 {
                log::warn!("OHCI: Port {} not enabled after reset", port);
                continue;
            }

            // Enumerate the device
            let speed = if is_low_speed {
                UsbSpeed::Low
            } else {
                UsbSpeed::Full
            };

            if let Err(e) = self.attach_device(port, speed) {
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

        // Get initial device descriptor (8 bytes)
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

        // Copy fields to avoid unaligned access on packed struct
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

    /// Internal control transfer
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

        // Build setup packet
        let setup_addr = self.dma_buffer;
        let setup_packet = setup_addr as *mut u8;
        unsafe {
            *setup_packet.add(0) = request_type;
            *setup_packet.add(1) = request;
            *setup_packet.add(2) = value as u8;
            *setup_packet.add(3) = (value >> 8) as u8;
            *setup_packet.add(4) = index as u8;
            *setup_packet.add(5) = (index >> 8) as u8;
            *setup_packet.add(6) = data_len as u8;
            *setup_packet.add(7) = (data_len >> 8) as u8;
        }

        // Allocate ED and TDs
        let ed_addr = self.dma_buffer + 64;
        let td_base = ed_addr + 32;
        let data_buffer = td_base + 128;

        // Copy data for OUT
        if let Some(ref d) = data {
            if !is_in {
                unsafe {
                    ptr::copy_nonoverlapping(d.as_ptr(), data_buffer as *mut u8, d.len());
                }
            }
        }

        // Create ED
        let ed = unsafe { &mut *(ed_addr as *mut EndpointDescriptor) };
        *ed = EndpointDescriptor::new(
            device.address,
            0,
            device.ep0_max_packet,
            device.speed == UsbSpeed::Low,
            None,
        );

        // Create TDs
        let setup_td = unsafe { &mut *(td_base as *mut TransferDescriptor) };
        let status_td_addr;

        if data_len > 0 {
            let data_td = unsafe { &mut *((td_base + 16) as *mut TransferDescriptor) };
            let status_td = unsafe { &mut *((td_base + 32) as *mut TransferDescriptor) };

            *setup_td = TransferDescriptor::setup(setup_addr as u32, (td_base + 16) as u32);
            *data_td = TransferDescriptor::data(
                data_buffer as u32,
                data_len,
                is_in,
                true,
                (td_base + 32) as u32,
            );
            *status_td = TransferDescriptor::status(!is_in, 0);
            status_td_addr = td_base + 32;

            ed.head_td = td_base as u32;
            ed.tail_td = (td_base + 48) as u32;
        } else {
            let status_td = unsafe { &mut *((td_base + 16) as *mut TransferDescriptor) };

            *setup_td = TransferDescriptor::setup(setup_addr as u32, (td_base + 16) as u32);
            *status_td = TransferDescriptor::status(true, 0);
            status_td_addr = td_base + 16;

            ed.head_td = td_base as u32;
            ed.tail_td = (td_base + 32) as u32;
        }

        fence(Ordering::SeqCst);

        // Insert ED into control list
        let head_ed = unsafe { &mut *(self.control_ed as *mut EndpointDescriptor) };
        ed.next_ed = head_ed.next_ed;
        fence(Ordering::SeqCst);
        head_ed.next_ed = ed_addr as u32;
        fence(Ordering::SeqCst);

        // Tell controller list is filled
        self.write_reg(regs::HCCOMMANDSTATUS, hccommandstatus::CLF);

        // Wait for completion
        let status_td = unsafe { &*(status_td_addr as *const TransferDescriptor) };
        let timeout = Timeout::from_ms(5000);

        while !timeout.is_expired() {
            fence(Ordering::SeqCst);
            if status_td.is_complete() {
                break;
            }
            core::hint::spin_loop();
        }

        // Remove ED from list
        head_ed.next_ed = ed.next_ed;
        fence(Ordering::SeqCst);

        // Check result
        if !status_td.is_complete() {
            return Err(UsbError::Timeout);
        }

        if setup_td.has_error() || status_td.has_error() {
            let cc = if setup_td.has_error() {
                setup_td.condition_code()
            } else {
                status_td.condition_code()
            };
            if cc == TransferDescriptor::CC_STALL {
                return Err(UsbError::Stall);
            }
            return Err(UsbError::TransactionError);
        }

        // Copy data for IN
        if let Some(d) = data {
            if is_in {
                let data_td = unsafe { &*((td_base + 16) as *const TransferDescriptor) };
                let transferred = if data_td.cbp == 0 {
                    data_len
                } else {
                    (data_td.cbp - data_buffer as u32) as usize
                };
                unsafe {
                    ptr::copy_nonoverlapping(
                        data_buffer as *const u8,
                        d.as_mut_ptr(),
                        transferred.min(d.len()),
                    );
                }
                return Ok(transferred);
            }
        }

        Ok(data_len)
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
}

impl UsbController for OhciController {
    fn controller_type(&self) -> &'static str {
        "OHCI"
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

        // Allocate ED and TD
        let ed_addr = self.dma_buffer;
        let td_addr = ed_addr + 32;
        let data_buffer = td_addr + 32;

        // Copy data for OUT
        if !is_in {
            unsafe {
                ptr::copy_nonoverlapping(data.as_ptr(), data_buffer as *mut u8, data.len());
            }
        }

        // Create ED
        let ed = unsafe { &mut *(ed_addr as *mut EndpointDescriptor) };
        *ed = EndpointDescriptor::new(
            dev.address,
            endpoint,
            max_packet,
            dev.speed == UsbSpeed::Low,
            Some(if is_in { Direction::In } else { Direction::Out }),
        );

        // Create TD
        let td = unsafe { &mut *(td_addr as *mut TransferDescriptor) };
        *td = TransferDescriptor::data(data_buffer as u32, data.len(), is_in, toggle, 0);
        td.control &= !TransferDescriptor::CTRL_DI_NONE;
        td.control |= 0 << TransferDescriptor::CTRL_DI_SHIFT;

        ed.head_td = td_addr as u32 | if toggle { 2 } else { 0 };
        ed.tail_td = (td_addr + 16) as u32;

        fence(Ordering::SeqCst);

        // Insert into bulk list
        let head_ed = unsafe { &mut *(self.bulk_ed as *mut EndpointDescriptor) };
        ed.next_ed = head_ed.next_ed;
        fence(Ordering::SeqCst);
        head_ed.next_ed = ed_addr as u32;
        fence(Ordering::SeqCst);

        // Trigger bulk list
        self.write_reg(regs::HCCOMMANDSTATUS, hccommandstatus::BLF);

        // Wait for completion
        let timeout = Timeout::from_ms(5000);
        while !timeout.is_expired() {
            fence(Ordering::SeqCst);
            if td.is_complete() {
                break;
            }
            core::hint::spin_loop();
        }

        // Remove from list
        head_ed.next_ed = ed.next_ed;
        fence(Ordering::SeqCst);

        // Check result
        if !td.is_complete() {
            return Err(UsbError::Timeout);
        }

        if td.has_error() {
            if td.condition_code() == TransferDescriptor::CC_STALL {
                return Err(UsbError::Stall);
            }
            return Err(UsbError::TransactionError);
        }

        // Calculate transferred
        let transferred = if td.cbp == 0 {
            data.len()
        } else if td.cbp > data_buffer as u32 {
            (td.cbp - data_buffer as u32) as usize
        } else {
            data.len()
        };

        // Update toggle
        if let Some(dev) = self.get_device_mut(device) {
            let new_toggle = (ed.head_td & EndpointDescriptor::HEAD_TOGGLE) != 0;
            if is_in {
                dev.bulk_in_toggle = new_toggle;
            } else {
                dev.bulk_out_toggle = new_toggle;
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

impl OhciController {
    /// Clean up the controller before handing off to the OS
    ///
    /// This must be called before ExitBootServices to ensure Linux's OHCI
    /// driver can properly initialize the controller. Following libpayload's
    /// ohci_shutdown pattern.
    pub fn cleanup(&mut self) {
        log::debug!("OHCI cleanup: stopping and resetting controller");

        // 1. Stop the controller (disable all list processing)
        let control = self.read_reg(regs::HCCONTROL);
        self.write_reg(
            regs::HCCONTROL,
            control & !(hccontrol::PLE | hccontrol::CLE | hccontrol::BLE | hccontrol::IE),
        );

        // 2. Reset the controller
        self.write_reg(regs::HCCOMMANDSTATUS, hccommandstatus::HCR);

        // Wait for reset to complete (should take at most 10us per spec)
        crate::time::delay_ms(2);

        // 3. Put controller in reset state
        self.write_reg(regs::HCCONTROL, 0);

        // Wait a bit more to ensure clean state
        crate::time::delay_ms(10);

        log::debug!("OHCI cleanup complete");
    }
}
