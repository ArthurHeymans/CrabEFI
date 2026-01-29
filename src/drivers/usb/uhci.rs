//! UHCI (USB 1.1) Host Controller Interface driver
//!
//! This module provides support for USB 1.1 full/low-speed devices via the
//! Universal Host Controller Interface (Intel's USB 1.x controller).
//!
//! # References
//! - UHCI Design Guide Revision 1.1
//! - libpayload uhci.c

use crate::drivers::pci::{self, PciAddress, PciDevice};
use crate::efi;
use crate::time::Timeout;
use core::ptr;
use core::sync::atomic::{Ordering, fence};

use super::controller::{
    DeviceDescriptor, DeviceInfo, EndpointInfo, UsbController, UsbDevice, UsbError, UsbSpeed,
    desc_type, parse_configuration, req_type, request,
};

// ============================================================================
// UHCI Register Definitions (I/O port based)
// ============================================================================

/// UHCI I/O Registers
#[allow(dead_code)]
mod regs {
    /// USB Command
    pub const USBCMD: u16 = 0x00;
    /// USB Status
    pub const USBSTS: u16 = 0x02;
    /// USB Interrupt Enable
    pub const USBINTR: u16 = 0x04;
    /// Frame Number
    pub const FRNUM: u16 = 0x06;
    /// Frame List Base Address
    pub const FLBASEADD: u16 = 0x08;
    /// Start of Frame Modify
    pub const SOFMOD: u16 = 0x0C;
    /// Port 1 Status/Control
    pub const PORTSC1: u16 = 0x10;
    /// Port 2 Status/Control
    pub const PORTSC2: u16 = 0x12;
}

/// USB Command Register bits
#[allow(dead_code)]
mod usbcmd {
    /// Run/Stop
    pub const RS: u16 = 1 << 0;
    /// Host Controller Reset
    pub const HCRESET: u16 = 1 << 1;
    /// Global Reset
    pub const GRESET: u16 = 1 << 2;
    /// Enter Global Suspend Mode
    pub const EGSM: u16 = 1 << 3;
    /// Force Global Resume
    pub const FGR: u16 = 1 << 4;
    /// Software Debug
    pub const SWDBG: u16 = 1 << 5;
    /// Configure Flag
    pub const CF: u16 = 1 << 6;
    /// Max Packet (1 = 64 bytes)
    pub const MAXP: u16 = 1 << 7;
}

/// USB Status Register bits
#[allow(dead_code)]
mod usbsts {
    /// USB Interrupt
    pub const USBINT: u16 = 1 << 0;
    /// USB Error Interrupt
    pub const USBERRINT: u16 = 1 << 1;
    /// Resume Detect
    pub const RESDET: u16 = 1 << 2;
    /// Host System Error
    pub const HSERR: u16 = 1 << 3;
    /// Host Controller Process Error
    pub const HCPE: u16 = 1 << 4;
    /// Host Controller Halted
    pub const HCHALTED: u16 = 1 << 5;
}

/// Port Status/Control bits
#[allow(dead_code)]
mod portsc {
    /// Current Connect Status
    pub const CCS: u16 = 1 << 0;
    /// Connect Status Change
    pub const CSC: u16 = 1 << 1;
    /// Port Enabled
    pub const PE: u16 = 1 << 2;
    /// Port Enable Change
    pub const PEC: u16 = 1 << 3;
    /// Line Status D+ (bit 4)
    pub const LS_DPLUS: u16 = 1 << 4;
    /// Line Status D- (bit 5)
    pub const LS_DMINUS: u16 = 1 << 5;
    /// Resume Detect
    pub const RD: u16 = 1 << 6;
    /// Reserved (always 1)
    pub const RESERVED: u16 = 1 << 7;
    /// Low Speed Device Attached
    pub const LSDA: u16 = 1 << 8;
    /// Port Reset
    pub const PR: u16 = 1 << 9;
    /// Suspend
    pub const SUSPEND: u16 = 1 << 12;
    /// Write-clear bits
    pub const WC_BITS: u16 = CSC | PEC;
}

// ============================================================================
// UHCI Data Structures
// ============================================================================

/// Frame List Pointer (entry in frame list)
#[repr(transparent)]
#[derive(Clone, Copy, Default)]
pub struct FrameListPointer(pub u32);

impl FrameListPointer {
    /// Terminate bit
    pub const TERMINATE: u32 = 1 << 0;
    /// QH/TD select (1 = QH)
    pub const QH: u32 = 1 << 1;

    /// Create a terminated pointer
    pub fn terminated() -> Self {
        Self(Self::TERMINATE)
    }

    /// Create a pointer to a QH
    pub fn to_qh(addr: u32) -> Self {
        Self((addr & !0xF) | Self::QH)
    }

    /// Create a pointer to a TD
    pub fn to_td(addr: u32) -> Self {
        Self(addr & !0xF)
    }
}

/// Queue Head (16 bytes, 16-byte aligned)
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct QueueHead {
    /// Head Link Pointer (horizontal)
    pub head_link: u32,
    /// Element Link Pointer (vertical - to TDs)
    pub element_link: u32,
    /// Reserved for software use
    pub reserved: [u32; 2],
}

impl QueueHead {
    /// Terminate bit
    pub const TERMINATE: u32 = 1 << 0;
    /// QH/TD select
    pub const QH: u32 = 1 << 1;

    /// Create a new QH
    pub fn new() -> Self {
        Self {
            head_link: Self::TERMINATE,
            element_link: Self::TERMINATE,
            reserved: [0; 2],
        }
    }
}

/// Transfer Descriptor (32 bytes, 16-byte aligned)
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct TransferDescriptor {
    /// Link Pointer
    pub link_ptr: u32,
    /// Control and Status
    pub ctrl_sts: u32,
    /// Token
    pub token: u32,
    /// Buffer Pointer
    pub buffer_ptr: u32,
    /// Reserved for software use
    pub reserved: [u32; 4],
}

impl TransferDescriptor {
    // Link Pointer bits
    pub const LP_TERMINATE: u32 = 1 << 0;
    pub const LP_QH: u32 = 1 << 1;
    pub const LP_DEPTH_FIRST: u32 = 1 << 2;

    // Control/Status bits
    pub const CS_ACTLEN_MASK: u32 = 0x7FF; // Actual length
    pub const CS_STATUS_SHIFT: u32 = 16;
    pub const CS_BITSTUFF: u32 = 1 << 17;
    pub const CS_CRC_TIMEOUT: u32 = 1 << 18;
    pub const CS_NAK: u32 = 1 << 19;
    pub const CS_BABBLE: u32 = 1 << 20;
    pub const CS_DATABUFFER: u32 = 1 << 21;
    pub const CS_STALLED: u32 = 1 << 22;
    pub const CS_ACTIVE: u32 = 1 << 23;
    pub const CS_IOC: u32 = 1 << 24;
    pub const CS_IOS: u32 = 1 << 25;
    pub const CS_LOWSPEED: u32 = 1 << 26;
    pub const CS_CERR_SHIFT: u32 = 27;
    pub const CS_CERR_MASK: u32 = 3 << 27;
    pub const CS_SPD: u32 = 1 << 29;
    pub const CS_ERROR_MASK: u32 = Self::CS_BITSTUFF
        | Self::CS_CRC_TIMEOUT
        | Self::CS_BABBLE
        | Self::CS_DATABUFFER
        | Self::CS_STALLED;

    // Token bits
    pub const TK_PID_MASK: u32 = 0xFF;
    pub const TK_PID_SETUP: u32 = 0x2D;
    pub const TK_PID_IN: u32 = 0x69;
    pub const TK_PID_OUT: u32 = 0xE1;
    pub const TK_DEVADDR_SHIFT: u32 = 8;
    pub const TK_DEVADDR_MASK: u32 = 0x7F << 8;
    pub const TK_ENDPOINT_SHIFT: u32 = 15;
    pub const TK_ENDPOINT_MASK: u32 = 0xF << 15;
    pub const TK_TOGGLE: u32 = 1 << 19;
    pub const TK_MAXLEN_SHIFT: u32 = 21;
    pub const TK_MAXLEN_MASK: u32 = 0x7FF << 21;

    /// Create a SETUP TD
    pub fn setup(device: u8, buffer: u32, next: u32, is_low_speed: bool) -> Self {
        let mut td = Self::default();
        td.link_ptr = if next != 0 {
            next | Self::LP_DEPTH_FIRST
        } else {
            Self::LP_TERMINATE
        };
        td.ctrl_sts = Self::CS_ACTIVE | (3 << Self::CS_CERR_SHIFT);
        if is_low_speed {
            td.ctrl_sts |= Self::CS_LOWSPEED;
        }
        td.token = Self::TK_PID_SETUP
            | ((device as u32) << Self::TK_DEVADDR_SHIFT)
            | (7 << Self::TK_MAXLEN_SHIFT); // 8 bytes - 1
        td.buffer_ptr = buffer;
        td
    }

    /// Create a DATA TD
    pub fn data(
        device: u8,
        endpoint: u8,
        buffer: u32,
        length: usize,
        is_in: bool,
        toggle: bool,
        next: u32,
        is_low_speed: bool,
    ) -> Self {
        let mut td = Self::default();
        td.link_ptr = if next != 0 {
            next | Self::LP_DEPTH_FIRST
        } else {
            Self::LP_TERMINATE
        };
        td.ctrl_sts = Self::CS_ACTIVE | (3 << Self::CS_CERR_SHIFT);
        if is_low_speed {
            td.ctrl_sts |= Self::CS_LOWSPEED;
        }
        td.token = if is_in {
            Self::TK_PID_IN
        } else {
            Self::TK_PID_OUT
        } | ((device as u32) << Self::TK_DEVADDR_SHIFT)
            | ((endpoint as u32) << Self::TK_ENDPOINT_SHIFT);
        if length > 0 {
            td.token |= (((length - 1) as u32) << Self::TK_MAXLEN_SHIFT) & Self::TK_MAXLEN_MASK;
        } else {
            td.token |= 0x7FF << Self::TK_MAXLEN_SHIFT; // Null packet
        }
        if toggle {
            td.token |= Self::TK_TOGGLE;
        }
        td.buffer_ptr = buffer;
        td
    }

    /// Create a STATUS TD
    pub fn status(device: u8, is_in: bool, next: u32, is_low_speed: bool) -> Self {
        let mut td = Self::default();
        td.link_ptr = if next != 0 {
            next | Self::LP_DEPTH_FIRST
        } else {
            Self::LP_TERMINATE
        };
        td.ctrl_sts = Self::CS_ACTIVE | Self::CS_IOC | (3 << Self::CS_CERR_SHIFT);
        if is_low_speed {
            td.ctrl_sts |= Self::CS_LOWSPEED;
        }
        td.token = if is_in {
            Self::TK_PID_IN
        } else {
            Self::TK_PID_OUT
        } | ((device as u32) << Self::TK_DEVADDR_SHIFT)
            | Self::TK_TOGGLE
            | (0x7FF << Self::TK_MAXLEN_SHIFT); // Null packet
        td.buffer_ptr = 0;
        td
    }

    /// Check if TD is active
    pub fn is_active(&self) -> bool {
        (self.ctrl_sts & Self::CS_ACTIVE) != 0
    }

    /// Check if TD has error
    pub fn has_error(&self) -> bool {
        (self.ctrl_sts & Self::CS_ERROR_MASK) != 0
    }

    /// Check if TD is stalled
    pub fn is_stalled(&self) -> bool {
        (self.ctrl_sts & Self::CS_STALLED) != 0
    }

    /// Get actual length
    pub fn actual_length(&self) -> usize {
        let actlen = self.ctrl_sts & Self::CS_ACTLEN_MASK;
        if actlen == Self::CS_ACTLEN_MASK {
            0
        } else {
            (actlen + 1) as usize
        }
    }
}

// UsbDevice is now UsbDevice from controller.rs

// ============================================================================
// UHCI Controller
// ============================================================================

/// Maximum number of devices
const MAX_DEVICES: usize = 8;

/// UHCI Host Controller
pub struct UhciController {
    /// PCI address
    pci_address: PciAddress,
    /// I/O base address
    io_base: u16,
    /// Number of ports (usually 2)
    num_ports: u8,
    /// Devices
    devices: [Option<UsbDevice>; MAX_DEVICES],
    /// Next device address
    next_address: u8,
    /// Frame list
    frame_list: u64,
    /// QH for bulk/control
    qh: u64,
    /// DMA buffer
    dma_buffer: u64,
}

impl UhciController {
    /// DMA buffer size (64KB)
    const DMA_BUFFER_SIZE: usize = 64 * 1024;
    /// Frame list entries
    const FRAME_LIST_SIZE: usize = 1024;

    /// Create a new UHCI controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, UsbError> {
        // UHCI uses I/O ports, not MMIO
        // BAR4 (or BAR0 on some) contains the I/O base
        let io_base = pci_dev.io_base().ok_or(UsbError::NotReady)? as u16;

        // Enable the device (bus master + I/O space)
        pci::enable_device(pci_dev);

        log::info!("UHCI controller at I/O base {:#x}", io_base);

        // Allocate frame list (4KB aligned)
        let frame_list = efi::allocate_pages(1).ok_or(UsbError::AllocationFailed)?;

        // Allocate QH
        let qh = efi::allocate_pages(1).ok_or(UsbError::AllocationFailed)?;
        unsafe { ptr::write_bytes(qh as *mut u8, 0, 4096) };

        // Allocate DMA buffer
        let dma_pages = Self::DMA_BUFFER_SIZE.div_ceil(4096);
        let dma_buffer = efi::allocate_pages(dma_pages as u64).ok_or(UsbError::AllocationFailed)?;

        let mut controller = Self {
            pci_address: pci_dev.address,
            io_base,
            num_ports: 2, // UHCI always has 2 root hub ports
            devices: core::array::from_fn(|_| None),
            next_address: 1,
            frame_list,
            qh,
            dma_buffer,
        };

        controller.init()?;
        controller.enumerate_ports()?;

        Ok(controller)
    }

    /// Read from I/O port
    fn inw(&self, offset: u16) -> u16 {
        unsafe {
            let mut value: u16;
            core::arch::asm!(
                "in ax, dx",
                out("ax") value,
                in("dx") self.io_base + offset,
                options(nostack, preserves_flags)
            );
            value
        }
    }

    /// Write to I/O port
    fn outw(&mut self, offset: u16, value: u16) {
        unsafe {
            core::arch::asm!(
                "out dx, ax",
                in("dx") self.io_base + offset,
                in("ax") value,
                options(nostack, preserves_flags)
            );
        }
    }

    /// Write dword to I/O port
    fn outl(&mut self, offset: u16, value: u32) {
        unsafe {
            core::arch::asm!(
                "out dx, eax",
                in("dx") self.io_base + offset,
                in("eax") value,
                options(nostack, preserves_flags)
            );
        }
    }

    /// Disable UHCI legacy support (BIOS keyboard/mouse emulation)
    ///
    /// UHCI has a legacy support register at PCI config offset 0xC0 (USBLEGSUP)
    /// that enables BIOS keyboard/mouse emulation via SMM. We need to disable
    /// this before taking control of the controller.
    fn disable_legacy_support(&mut self) {
        // UHCI legacy support register is at PCI config offset 0xC0
        const USBLEGSUP: u8 = 0xC0;

        let legsup = pci::read_config_u16(self.pci_address, USBLEGSUP);

        // Clear legacy support bits:
        // Bit 13: PIRQ enable (disable SMM interrupt routing)
        // Bit 4: Trap by 64h write
        // Bit 3: Trap by 64h read
        // Bit 2: Trap by 60h write
        // Bit 1: Trap by 60h read
        // Bit 0: SMI at end of pass-through
        // Mask 0xDF80 clears bits 0-6 and bit 13 (from libpayload)
        let new_legsup = legsup & 0xDF80;

        if legsup != new_legsup {
            log::debug!(
                "UHCI: Disabling legacy support: {:#06x} -> {:#06x}",
                legsup,
                new_legsup
            );
            pci::write_config_u16(self.pci_address, USBLEGSUP, new_legsup);
            crate::time::delay_ms(1);
        }
    }

    /// Initialize the controller
    fn init(&mut self) -> Result<(), UsbError> {
        // First disable legacy support (BIOS keyboard emulation via SMM)
        self.disable_legacy_support();

        // Stop the controller
        self.outw(regs::USBCMD, 0);

        // Wait for halt
        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if (self.inw(regs::USBSTS) & usbsts::HCHALTED) != 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // Global reset
        self.outw(regs::USBCMD, usbcmd::GRESET);
        crate::time::delay_ms(50);
        self.outw(regs::USBCMD, 0);
        crate::time::delay_ms(10);

        // Host controller reset
        self.outw(regs::USBCMD, usbcmd::HCRESET);

        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if (self.inw(regs::USBCMD) & usbcmd::HCRESET) == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        if (self.inw(regs::USBCMD) & usbcmd::HCRESET) != 0 {
            return Err(UsbError::Timeout);
        }

        // Initialize QH
        let qh = unsafe { &mut *(self.qh as *mut QueueHead) };
        qh.head_link = QueueHead::TERMINATE;
        qh.element_link = QueueHead::TERMINATE;

        // Initialize frame list - all point to our QH
        let frame_list = self.frame_list as *mut u32;
        for i in 0..Self::FRAME_LIST_SIZE {
            unsafe {
                ptr::write_volatile(frame_list.add(i), (self.qh as u32) | FrameListPointer::QH);
            }
        }

        // Set frame list base
        self.outl(regs::FLBASEADD, self.frame_list as u32);

        // Set frame number to 0
        self.outw(regs::FRNUM, 0);

        // Clear status
        self.outw(regs::USBSTS, 0xFFFF);

        // Disable interrupts
        self.outw(regs::USBINTR, 0);

        // Start the controller
        self.outw(regs::USBCMD, usbcmd::RS | usbcmd::CF | usbcmd::MAXP);

        // Wait for running
        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if (self.inw(regs::USBSTS) & usbsts::HCHALTED) == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        crate::time::delay_ms(100);

        log::info!("UHCI controller initialized");
        Ok(())
    }

    /// Enumerate ports
    fn enumerate_ports(&mut self) -> Result<(), UsbError> {
        for port in 0..self.num_ports {
            let reg = if port == 0 {
                regs::PORTSC1
            } else {
                regs::PORTSC2
            };

            let portsc = self.inw(reg);

            // Clear status change bits
            self.outw(reg, portsc | portsc::WC_BITS);

            if (portsc & portsc::CCS) == 0 {
                continue;
            }

            let is_low_speed = (portsc & portsc::LSDA) != 0;
            log::info!(
                "UHCI: Device on port {} ({})",
                port,
                if is_low_speed {
                    "low-speed"
                } else {
                    "full-speed"
                }
            );

            // Reset port
            self.outw(reg, portsc::PR);
            crate::time::delay_ms(50);
            self.outw(reg, 0);
            crate::time::delay_ms(10);

            // Enable port
            for _ in 0..10 {
                let portsc = self.inw(reg);
                if (portsc & portsc::CCS) == 0 {
                    break;
                }
                if (portsc & portsc::PE) != 0 {
                    break;
                }
                self.outw(reg, portsc | portsc::PE);
                crate::time::delay_ms(10);
            }

            let portsc = self.inw(reg);
            if (portsc & portsc::PE) == 0 {
                log::warn!("UHCI: Port {} not enabled", port);
                continue;
            }

            // Clear status changes again
            self.outw(reg, portsc | portsc::WC_BITS);

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

    /// Attach a device
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

        // Get initial device descriptor
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

        // Get configuration
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
        let is_low_speed = device.speed == UsbSpeed::Low;

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

        // Allocate TDs
        let td_base = self.dma_buffer + 64;
        let data_buffer = td_base + 256;

        // Copy data for OUT
        if let Some(ref d) = data
            && !is_in
        {
            unsafe {
                ptr::copy_nonoverlapping(d.as_ptr(), data_buffer as *mut u8, d.len());
            }
        }

        // Create TDs
        let setup_td_addr = td_base;
        let status_td_addr;

        if data_len > 0 {
            let data_td_addr = td_base + 32;
            status_td_addr = td_base + 64;

            let setup_td = unsafe { &mut *(setup_td_addr as *mut TransferDescriptor) };
            let data_td = unsafe { &mut *(data_td_addr as *mut TransferDescriptor) };
            let status_td = unsafe { &mut *(status_td_addr as *mut TransferDescriptor) };

            *setup_td = TransferDescriptor::setup(
                device.address,
                setup_addr as u32,
                data_td_addr as u32,
                is_low_speed,
            );
            *data_td = TransferDescriptor::data(
                device.address,
                0,
                data_buffer as u32,
                data_len,
                is_in,
                true,
                status_td_addr as u32,
                is_low_speed,
            );
            *status_td = TransferDescriptor::status(device.address, !is_in, 0, is_low_speed);
        } else {
            status_td_addr = td_base + 32;

            let setup_td = unsafe { &mut *(setup_td_addr as *mut TransferDescriptor) };
            let status_td = unsafe { &mut *(status_td_addr as *mut TransferDescriptor) };

            *setup_td = TransferDescriptor::setup(
                device.address,
                setup_addr as u32,
                status_td_addr as u32,
                is_low_speed,
            );
            *status_td = TransferDescriptor::status(device.address, true, 0, is_low_speed);
        }

        fence(Ordering::SeqCst);

        // Point QH element to first TD
        let qh = unsafe { &mut *(self.qh as *mut QueueHead) };
        qh.element_link = setup_td_addr as u32;
        fence(Ordering::SeqCst);

        // Wait for completion
        let status_td = unsafe { &*(status_td_addr as *const TransferDescriptor) };
        let timeout = Timeout::from_ms(5000);

        while !timeout.is_expired() {
            fence(Ordering::SeqCst);
            if !status_td.is_active() {
                break;
            }
            core::hint::spin_loop();
        }

        // Clear QH
        qh.element_link = QueueHead::TERMINATE;
        fence(Ordering::SeqCst);

        // Check result
        if status_td.is_active() {
            return Err(UsbError::Timeout);
        }

        let setup_td = unsafe { &*(setup_td_addr as *const TransferDescriptor) };
        if setup_td.has_error() || status_td.has_error() {
            if setup_td.is_stalled() || status_td.is_stalled() {
                return Err(UsbError::Stall);
            }
            return Err(UsbError::TransactionError);
        }

        // Copy data for IN
        if let Some(d) = data
            && is_in
        {
            let data_td = unsafe { &*((td_base + 32) as *const TransferDescriptor) };
            let transferred = data_td.actual_length();
            unsafe {
                ptr::copy_nonoverlapping(
                    data_buffer as *const u8,
                    d.as_mut_ptr(),
                    transferred.min(d.len()),
                );
            }
            return Ok(transferred);
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

impl UsbController for UhciController {
    fn controller_type(&self) -> &'static str {
        "UHCI"
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

        let _ep_info = if is_in {
            dev.bulk_in.as_ref()
        } else {
            dev.bulk_out.as_ref()
        }
        .ok_or(UsbError::InvalidParameter)?;

        let is_low_speed = dev.speed == UsbSpeed::Low;
        let toggle = if is_in {
            dev.bulk_in_toggle
        } else {
            dev.bulk_out_toggle
        };

        // Allocate TD
        let td_addr = self.dma_buffer;
        let data_buffer = td_addr + 64;

        // Copy data for OUT
        if !is_in {
            unsafe {
                ptr::copy_nonoverlapping(data.as_ptr(), data_buffer as *mut u8, data.len());
            }
        }

        // Create TD
        let td = unsafe { &mut *(td_addr as *mut TransferDescriptor) };
        *td = TransferDescriptor::data(
            dev.address,
            endpoint,
            data_buffer as u32,
            data.len(),
            is_in,
            toggle,
            0,
            is_low_speed,
        );
        td.ctrl_sts |= TransferDescriptor::CS_IOC;

        fence(Ordering::SeqCst);

        // Point QH to TD
        let qh = unsafe { &mut *(self.qh as *mut QueueHead) };
        qh.element_link = td_addr as u32;
        fence(Ordering::SeqCst);

        // Wait for completion
        let timeout = Timeout::from_ms(5000);
        while !timeout.is_expired() {
            fence(Ordering::SeqCst);
            if !td.is_active() {
                break;
            }
            core::hint::spin_loop();
        }

        // Clear QH
        qh.element_link = QueueHead::TERMINATE;
        fence(Ordering::SeqCst);

        // Check result
        if td.is_active() {
            return Err(UsbError::Timeout);
        }

        if td.has_error() {
            if td.is_stalled() {
                return Err(UsbError::Stall);
            }
            return Err(UsbError::TransactionError);
        }

        let transferred = td.actual_length();

        // Update toggle
        if let Some(dev) = self.get_device_mut(device) {
            if is_in {
                dev.bulk_in_toggle = !toggle;
            } else {
                dev.bulk_out_toggle = !toggle;
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
                (Some(in_ep), Some(out_ep)) => Some((*in_ep, *out_ep)),
                _ => None,
            })
    }

    fn get_interrupt_endpoint(&self, device: u8) -> Option<EndpointInfo> {
        self.get_device(device).and_then(|d| d.interrupt_in)
    }
}

impl UhciController {
    /// Clean up the controller before handing off to the OS
    ///
    /// This must be called before ExitBootServices to ensure Linux's UHCI
    /// driver can properly initialize the controller. Following libpayload's
    /// uhci_shutdown and uhci_reset patterns.
    pub fn cleanup(&mut self) {
        log::debug!("UHCI cleanup: stopping and resetting controller");

        // 1. Stop the controller
        self.outw(regs::USBCMD, 0);

        // 2. Global Reset (hold for at least 10ms per UHCI spec 2.1.1)
        self.outw(regs::USBCMD, usbcmd::GRESET);
        crate::time::delay_ms(50);
        self.outw(regs::USBCMD, 0);
        crate::time::delay_ms(10);

        // 3. Host Controller Reset
        self.outw(regs::USBCMD, usbcmd::HCRESET);

        // Wait for reset to complete (should be quick, timeout after 100ms)
        let timeout = Timeout::from_ms(100);
        while !timeout.is_expired() {
            if self.inw(regs::USBCMD) & usbcmd::HCRESET == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // 4. Clear status register
        self.outw(regs::USBSTS, 0x3F);

        log::debug!("UHCI cleanup complete");
    }
}
