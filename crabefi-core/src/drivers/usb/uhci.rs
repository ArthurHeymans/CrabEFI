//! UHCI (USB 1.1) Host Controller Interface driver
//!
//! This module provides support for USB 1.1 full/low-speed devices via the
//! Universal Host Controller Interface (Intel's USB 1.x controller).
//!
//! # References
//! - UHCI Design Guide Revision 1.1
//! - libpayload uhci.c

use super::controller::{
    SetupPacket, UsbController, UsbDevice, UsbError, UsbSpeed, enumerate_device,
    enumerate_hub_ports,
};
use super::uhci_regs::{PORTSC, USBCMD, USBSTS, UhciRegs};
use crate::arch::{flush_cache_range, invalidate_cache_range};
use crate::barrier;
use crate::drivers::pci::{self, PciAddress, PciDevice};
use crate::efi;
use crate::time::{Timeout, wait_for};
use core::ptr;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

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
        short_packet_detect: bool,
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
        if short_packet_detect {
            td.ctrl_sts |= Self::CS_SPD;
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
        let frame_list_mem = efi::allocate_pages_below_4g(1).ok_or(UsbError::AllocationFailed)?;
        let frame_list = frame_list_mem.as_ptr() as u64;

        // Allocate QH
        let qh_mem = efi::allocate_pages_below_4g(1).ok_or(UsbError::AllocationFailed)?;
        qh_mem.fill(0);
        let qh = qh_mem.as_ptr() as u64;

        // Allocate DMA buffer
        let dma_pages = Self::DMA_BUFFER_SIZE.div_ceil(4096);
        let dma_buffer_mem =
            efi::allocate_pages_below_4g(dma_pages as u64).ok_or(UsbError::AllocationFailed)?;
        let dma_buffer = dma_buffer_mem.as_ptr() as u64;

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

        // Port enumeration is deferred to rescan_ports(), called after all
        // USB controllers are initialized. On ICH8/9/10 chipsets, UHCI
        // companion controllers appear at lower PCI BDFs than their EHCI
        // companion, so they are initialized first.  EHCI must set
        // CONFIGFLAG and release companion ports before UHCI can see
        // the correct devices and speeds on its ports.

        Ok(controller)
    }

    /// Get typed register accessors for this controller's I/O port range
    #[inline]
    fn regs(&self) -> UhciRegs {
        UhciRegs::new(self.io_base)
    }

    fn stop_schedule(&self) -> bool {
        let regs = self.regs();
        regs.usbcmd().modify(USBCMD::RS::CLEAR);
        barrier::mmio_write();
        wait_for(100, || regs.usbsts().is_set(USBSTS::HCHALTED))
    }

    fn start_schedule(&self) -> bool {
        let regs = self.regs();
        regs.usbcmd().modify(USBCMD::RS::SET);
        barrier::mmio_write();
        wait_for(100, || !regs.usbsts().is_set(USBSTS::HCHALTED))
    }

    /// Disable UHCI legacy support (BIOS keyboard/mouse emulation)
    ///
    /// UHCI has a legacy support register at PCI config offset 0xC0 (USBLEGSUP)
    /// that enables BIOS keyboard/mouse emulation via SMM. We need to disable
    /// this before taking control of the controller.
    fn disable_legacy_support(&mut self) {
        // UHCI legacy support register is at PCI config offset 0xC0
        const USBLEGSUP: u16 = 0xC0;

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

        let regs = self.regs();

        // Stop the controller
        regs.usbcmd().set(0);

        // Wait for halt
        wait_for(100, || regs.usbsts().is_set(USBSTS::HCHALTED));

        // Global reset
        regs.usbcmd().write(USBCMD::GRESET::SET);
        crate::time::delay_ms(50);
        regs.usbcmd().set(0);
        crate::time::delay_ms(10);

        // Host controller reset
        regs.usbcmd().write(USBCMD::HCRESET::SET);

        if !wait_for(100, || !regs.usbcmd().is_set(USBCMD::HCRESET)) {
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

        flush_cache_range(self.qh, core::mem::size_of::<QueueHead>());
        flush_cache_range(self.frame_list, Self::FRAME_LIST_SIZE * 4);

        // Set frame list base
        regs.flbaseadd().set(self.frame_list as u32);

        // Set frame number to 0
        regs.frnum().set(0);

        // Clear status
        regs.usbsts().set(0xFFFF);

        // Disable interrupts
        regs.usbintr().set(0);

        // Start the controller
        regs.usbcmd()
            .write(USBCMD::RS::SET + USBCMD::CF::SET + USBCMD::MAXP::SET);

        // Wait for running
        wait_for(100, || !regs.usbsts().is_set(USBSTS::HCHALTED));

        crate::time::delay_ms(100);

        log::info!("UHCI controller initialized");
        Ok(())
    }

    /// Enumerate ports
    fn enumerate_ports(&mut self) -> Result<(), UsbError> {
        let regs = self.regs();

        for port in 0..self.num_ports {
            let portsc = regs.portsc(port);

            // Clear status change bits (write-1-to-clear CSC and PEC)
            portsc.modify(PORTSC::CSC::SET + PORTSC::PEC::SET);

            if !portsc.is_set(PORTSC::CCS) {
                continue;
            }

            let is_low_speed = portsc.is_set(PORTSC::LSDA);
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
            portsc.write(PORTSC::PR::SET);
            crate::time::delay_ms(50);
            portsc.set(0);
            crate::time::delay_ms(10);

            // Enable port
            for _ in 0..10 {
                if !portsc.is_set(PORTSC::CCS) {
                    break;
                }
                if portsc.is_set(PORTSC::PE) {
                    break;
                }
                portsc.modify(PORTSC::PE::SET);
                crate::time::delay_ms(10);
            }

            if !portsc.is_set(PORTSC::PE) {
                log::warn!("UHCI: Port {} not enabled", port);
                continue;
            }

            // Clear status changes again
            portsc.modify(PORTSC::CSC::SET + PORTSC::PEC::SET);

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

    /// Attach a device on a root hub port
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

        let initial_device = UsbDevice::new(0, port, speed);

        // Use the common enumeration helper with a closure for control transfers
        let device = enumerate_device(initial_device, address, |dev, rt, req, val, idx, data| {
            self.control_transfer_internal(dev, rt, req, val, idx, data)
        })?;

        self.next_address += 1;

        // Store the device and check if it's a hub
        let is_hub = device.is_hub;
        let hub_address = device.address;
        self.devices[slot] = Some(device);

        // If this is a hub, enumerate its downstream ports
        if is_hub && let Err(e) = self.enumerate_hub(slot, hub_address) {
            log::warn!("Failed to enumerate hub ports: {:?}", e);
            // Don't fail the device attachment, hub is still registered
        }

        Ok(())
    }

    /// Attach a device connected through an external hub
    ///
    /// # Arguments
    /// * `hub_port` - Hub port number (1-based)
    /// * `speed` - Detected device speed
    /// * `hub_addr` - USB address of the parent hub
    /// * `hub_port_num` - Hub port number for tracking
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

        let initial_device = UsbDevice::new_on_hub(0, hub_port, speed, hub_addr, hub_port_num);
        let device = enumerate_device(initial_device, address, |dev, rt, req, val, idx, data| {
            self.control_transfer_internal(dev, rt, req, val, idx, data)
        })?;

        self.next_address += 1;

        // Store the device and check for nested hubs
        let is_hub = device.is_hub;
        let new_hub_address = device.address;
        self.devices[slot] = Some(device);

        if is_hub && let Err(e) = self.enumerate_hub(slot, new_hub_address) {
            log::warn!("Failed to enumerate nested hub ports: {:?}", e);
        }

        Ok(())
    }

    /// Enumerate devices connected to an external USB hub.
    ///
    /// UHCI is USB 1.1 only so devices behind hubs are low-speed or
    /// full-speed. Delegates to the shared [`enumerate_hub_ports`] helper.
    fn enumerate_hub(&mut self, hub_slot: usize, hub_addr: u8) -> Result<(), UsbError> {
        log::info!("UHCI: Enumerating hub at address {}", hub_addr);

        let hub_device = self.devices[hub_slot]
            .as_ref()
            .ok_or(UsbError::DeviceNotFound)?
            .clone();

        let (num_ports, ready_ports) = enumerate_hub_ports(
            &hub_device,
            |dev, rt, req, val, idx, data| {
                self.control_transfer_internal(dev, rt, req, val, idx, data)
            },
            false, // UHCI is USB 1.1: low-speed or full-speed only
        )?;

        if let Some(ref mut dev) = self.devices[hub_slot] {
            dev.num_hub_ports = num_ports;
        }

        for (port, speed) in ready_ports {
            if let Err(e) = self.attach_device_on_hub(port, speed, hub_addr, port) {
                log::warn!("  Failed to attach device on hub port {}: {:?}", port, e);
            }
        }

        Ok(())
    }

    /// Maximum number of data TDs per control transfer
    ///
    /// Supports up to 256-byte transfers with 8-byte packets (low-speed worst case).
    const MAX_DATA_TDS: usize = 32;

    /// Internal control transfer
    ///
    /// In UHCI, each TD handles exactly one USB packet. Control transfers with
    /// data larger than max_packet_size require multiple data TDs, each carrying
    /// up to max_packet_size bytes with alternating DATA0/DATA1 toggles.
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
        let max_packet = device.ep0_max_packet.max(8) as usize;

        // Build setup packet at start of DMA buffer
        let setup_addr = self.dma_buffer;
        let setup_packet = SetupPacket::new(request_type, request, value, index, data_len as u16);
        unsafe {
            ptr::copy_nonoverlapping(setup_packet.as_bytes().as_ptr(), setup_addr as *mut u8, 8);
        }

        // DMA buffer layout:
        //   [0..8)       setup packet
        //   [64..)       TDs: setup(1) + data(N) + status(1), each 32 bytes
        //   [2048..)     data buffer  (DMA_BUFFER_SIZE - 2048 bytes available)
        const DATA_BUF_OFFSET: usize = 2048;
        let data_buf_capacity = Self::DMA_BUFFER_SIZE - DATA_BUF_OFFSET;
        if data_len > data_buf_capacity {
            log::warn!(
                "UHCI: control transfer data ({} bytes) exceeds DMA buffer ({})",
                data_len,
                data_buf_capacity,
            );
            return Err(UsbError::InvalidParameter);
        }
        let td_base = self.dma_buffer + 64;
        let data_buffer = self.dma_buffer + DATA_BUF_OFFSET as u64;

        // Copy data for OUT transfers
        if let Some(ref d) = data
            && !is_in
        {
            unsafe {
                ptr::copy_nonoverlapping(d.as_ptr(), data_buffer as *mut u8, d.len());
            }
        }

        // Calculate number of data TDs (one per packet).
        // Reject transfers that would require more TDs than we support rather
        // than silently truncating the data.
        let num_data_tds = if data_len > 0 {
            let n = data_len.div_ceil(max_packet);
            if n > Self::MAX_DATA_TDS {
                log::warn!(
                    "UHCI: control transfer needs {} TDs, max is {}",
                    n,
                    Self::MAX_DATA_TDS,
                );
                return Err(UsbError::InvalidParameter);
            }
            n
        } else {
            0
        };

        // TD addresses
        let setup_td_addr = td_base;
        let first_data_td_addr = td_base + 32;
        let status_td_addr = td_base + 32 * (1 + num_data_tds) as u64;

        // Build setup TD
        let next_after_setup = if num_data_tds > 0 {
            first_data_td_addr as u32
        } else {
            status_td_addr as u32
        };
        let setup_td = unsafe { &mut *(setup_td_addr as *mut TransferDescriptor) };
        *setup_td = TransferDescriptor::setup(
            device.address,
            setup_addr as u32,
            next_after_setup,
            is_low_speed,
        );

        // Build data TDs (one per packet, alternating DATA1/DATA0)
        let mut toggle = true; // First data packet after SETUP is DATA1
        let mut remaining = data_len;
        for i in 0..num_data_tds {
            let chunk = remaining.min(max_packet);
            let td_addr = first_data_td_addr + (i as u64) * 32;
            let next_td = if i + 1 < num_data_tds {
                (td_addr + 32) as u32
            } else {
                status_td_addr as u32
            };
            let buf_offset = i * max_packet;

            let td = unsafe { &mut *(td_addr as *mut TransferDescriptor) };
            *td = TransferDescriptor::data(
                device.address,
                0,
                (data_buffer + buf_offset as u64) as u32,
                chunk,
                is_in,
                toggle,
                is_in && i + 1 < num_data_tds,
                next_td,
                is_low_speed,
            );
            toggle = !toggle;
            remaining -= chunk;
        }

        // Build status TD (opposite direction from data, DATA1 toggle)
        let status_td = unsafe { &mut *(status_td_addr as *mut TransferDescriptor) };
        let status_dir_in = if data_len > 0 { !is_in } else { true };
        *status_td = TransferDescriptor::status(device.address, status_dir_in, 0, is_low_speed);

        flush_cache_range(setup_addr, 8);
        if data_len > 0 {
            if is_in {
                invalidate_cache_range(data_buffer, data_len);
            } else {
                flush_cache_range(data_buffer, data_len);
            }
        }
        flush_cache_range(td_base, 32 * (num_data_tds + 2));
        barrier::dma_write();

        // Point QH element to first TD
        let qh = unsafe { &mut *(self.qh as *mut QueueHead) };
        qh.element_link = setup_td_addr as u32;
        flush_cache_range(self.qh, core::mem::size_of::<QueueHead>());
        barrier::dma_write();

        // Wait for status TD completion. CS_SPD stops vertical traversal on a
        // short packet, so redirect the QH to the status stage when that occurs.
        let timeout = Timeout::from_ms(5000);
        let mut repaired_short_packet = false;
        loop {
            invalidate_cache_range(td_base, 32 * (num_data_tds + 2));
            barrier::dma_read();

            if is_in && !repaired_short_packet {
                for i in 0..num_data_tds.saturating_sub(1) {
                    let td_addr = first_data_td_addr + (i as u64) * 32;
                    let td = unsafe { &*(td_addr as *const TransferDescriptor) };
                    let expected = (data_len - i * max_packet).min(max_packet);
                    if !td.is_active() && !td.has_error() && td.actual_length() < expected {
                        qh.element_link = status_td_addr as u32;
                        flush_cache_range(self.qh, core::mem::size_of::<QueueHead>());
                        barrier::dma_write();
                        repaired_short_packet = true;
                        break;
                    }
                }
            }

            let sts = unsafe { ptr::read_volatile(&status_td.ctrl_sts) };
            if sts & TransferDescriptor::CS_ACTIVE == 0 {
                break;
            }
            if timeout.is_expired() {
                let halted = self.stop_schedule();
                if !halted {
                    log::error!("UHCI: schedule did not halt after control timeout; resetting");
                    self.cleanup();
                }
                qh.element_link = QueueHead::TERMINATE;
                flush_cache_range(self.qh, core::mem::size_of::<QueueHead>());
                barrier::dma_write();
                if halted && !self.start_schedule() {
                    log::error!("UHCI: schedule did not restart after control timeout");
                    self.cleanup();
                }
                return Err(UsbError::Timeout);
            }
            core::hint::spin_loop();
        }

        // Clear QH
        qh.element_link = QueueHead::TERMINATE;
        flush_cache_range(self.qh, core::mem::size_of::<QueueHead>());
        barrier::dma_write();

        invalidate_cache_range(td_base, 32 * (num_data_tds + 2));

        // Check setup TD and all data TDs for errors
        let setup_td = unsafe { &*(setup_td_addr as *const TransferDescriptor) };
        if setup_td.has_error() {
            return Err(if setup_td.is_stalled() {
                UsbError::Stall
            } else {
                UsbError::TransactionError
            });
        }
        for i in 0..num_data_tds {
            let td_addr = first_data_td_addr + (i as u64) * 32;
            let td = unsafe { &*(td_addr as *const TransferDescriptor) };
            if td.has_error() {
                return Err(if td.is_stalled() {
                    UsbError::Stall
                } else {
                    UsbError::TransactionError
                });
            }
        }
        let status_sts = unsafe { ptr::read_volatile(&status_td.ctrl_sts) };
        if status_sts & TransferDescriptor::CS_ERROR_MASK != 0 {
            return Err(if status_sts & TransferDescriptor::CS_STALLED != 0 {
                UsbError::Stall
            } else {
                UsbError::TransactionError
            });
        }

        // Copy received data for IN transfers
        if let Some(d) = data
            && is_in
        {
            let mut total = 0usize;
            for i in 0..num_data_tds {
                let td_addr = first_data_td_addr + (i as u64) * 32;
                let td = unsafe { &*(td_addr as *const TransferDescriptor) };
                let chunk_transferred = td.actual_length();
                let buf_offset = i * max_packet;
                let copy_len = chunk_transferred.min(d.len() - total);
                if copy_len > 0 {
                    invalidate_cache_range(data_buffer + buf_offset as u64, copy_len);
                    unsafe {
                        ptr::copy_nonoverlapping(
                            (data_buffer + buf_offset as u64) as *const u8,
                            d.as_mut_ptr().add(total),
                            copy_len,
                        );
                    }
                }
                total += chunk_transferred;
                // Short packet means device has no more data
                if chunk_transferred < max_packet {
                    break;
                }
            }
            return Ok(total);
        }

        Ok(data_len)
    }

    fn get_device_mut(&mut self, address: u8) -> Option<&mut UsbDevice> {
        self.devices
            .iter_mut()
            .find_map(|d| d.as_mut().filter(|d| d.address == address))
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

    fn clear_endpoint_halt(
        &mut self,
        device: u8,
        endpoint: u8,
        is_in: bool,
    ) -> Result<(), UsbError> {
        let mut dev_copy = self
            .get_device(device)
            .ok_or(UsbError::DeviceNotFound)?
            .clone();
        dev_copy.reset_bulk_toggle(endpoint, is_in)?;
        let endpoint_address = endpoint | if is_in { 0x80 } else { 0 };
        self.control_transfer_internal(
            &dev_copy,
            super::controller::req_type::DIR_OUT
                | super::controller::req_type::TYPE_STANDARD
                | super::controller::req_type::RCPT_ENDPOINT,
            super::controller::request::CLEAR_FEATURE,
            0,
            u16::from(endpoint_address),
            None,
        )?;
        self.get_device_mut(device)
            .ok_or(UsbError::DeviceNotFound)?
            .reset_bulk_toggle(endpoint, is_in)
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

        let is_low_speed = dev.speed == UsbSpeed::Low;
        let address = dev.address;
        // UHCI TDs can encode up to 2048 bytes (11-bit MaxLen field), but we
        // limit to max_packet_size to stay within spec and avoid crossing page
        // boundaries in a single TD.
        let max_packet = ep_info.max_packet_size as usize;
        let max_per_td = if max_packet > 0 { max_packet } else { 64 };

        let td_addr = self.dma_buffer;
        let data_buffer = td_addr + 64;

        let mut total_transferred = 0usize;
        let mut offset = 0usize;
        let mut toggle = if is_in {
            dev.bulk_in_toggle
        } else {
            dev.bulk_out_toggle
        };

        while offset < data.len() {
            let chunk = (data.len() - offset).min(max_per_td);

            // Copy data for OUT
            if !is_in {
                unsafe {
                    ptr::copy_nonoverlapping(
                        data.as_ptr().add(offset),
                        data_buffer as *mut u8,
                        chunk,
                    );
                }
            }

            // Create TD for this chunk
            let td = unsafe { &mut *(td_addr as *mut TransferDescriptor) };
            *td = TransferDescriptor::data(
                address,
                endpoint,
                data_buffer as u32,
                chunk,
                is_in,
                toggle,
                false,
                0,
                is_low_speed,
            );
            td.ctrl_sts |= TransferDescriptor::CS_IOC;

            flush_cache_range(td_addr, 32);
            if is_in {
                invalidate_cache_range(data_buffer, chunk);
            } else {
                flush_cache_range(data_buffer, chunk);
            }
            barrier::dma_write();

            // Point QH to TD
            let qh = unsafe { &mut *(self.qh as *mut QueueHead) };
            qh.element_link = td_addr as u32;
            flush_cache_range(self.qh, core::mem::size_of::<QueueHead>());
            barrier::dma_write();

            // Wait for completion
            let timeout = Timeout::from_ms(5000);
            while !timeout.is_expired() {
                invalidate_cache_range(td_addr, 32);
                barrier::dma_read();
                if !td.is_active() {
                    break;
                }
                core::hint::spin_loop();
            }

            let completed = !td.is_active();
            let halted = if completed {
                false
            } else {
                let halted = self.stop_schedule();
                if !halted {
                    log::error!("UHCI: schedule did not halt after bulk timeout; resetting");
                    self.cleanup();
                }
                halted
            };

            // Clear the QH only after a timed-out schedule has halted.
            qh.element_link = QueueHead::TERMINATE;
            flush_cache_range(self.qh, core::mem::size_of::<QueueHead>());
            barrier::dma_write();
            if halted && !self.start_schedule() {
                log::error!("UHCI: schedule did not restart after bulk timeout");
                self.cleanup();
            }

            invalidate_cache_range(td_addr, 32);

            // Check result
            if !completed {
                return Err(UsbError::Timeout);
            }

            if td.has_error() {
                if td.is_stalled() {
                    return Err(UsbError::Stall);
                }
                return Err(UsbError::TransactionError);
            }

            let transferred = td.actual_length();

            // Copy data for IN
            if is_in && transferred > 0 {
                invalidate_cache_range(data_buffer, transferred);
                unsafe {
                    ptr::copy_nonoverlapping(
                        data_buffer as *const u8,
                        data.as_mut_ptr().add(offset),
                        transferred,
                    );
                }
            }

            toggle = !toggle;
            total_transferred += transferred;
            offset += chunk;

            // Short packet means transfer is done (device had less data)
            if transferred < chunk {
                break;
            }
        }

        // Update toggle
        if let Some(dev) = self.get_device_mut(device) {
            if is_in {
                dev.bulk_in_toggle = toggle;
            } else {
                dev.bulk_out_toggle = toggle;
            }
        }

        Ok(total_transferred)
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

    fn devices(&self) -> &[Option<UsbDevice>] {
        &self.devices
    }
}

impl UhciController {
    /// Enumerate ports (deferred initialization)
    ///
    /// On ICH8/9/10 chipsets, UHCI companion controllers are initialized before
    /// their EHCI companion due to PCI BDF ordering (UHCI at functions 0-2,
    /// EHCI at function 7). EHCI must set CONFIGFLAG and release companion ports
    /// before UHCI can see correct devices and speeds on its ports.
    ///
    /// This is called from `rescan_companion_ports()` after all USB controllers
    /// have been initialized, ensuring EHCI has already released its companions.
    pub fn rescan_ports(&mut self) {
        if let Err(e) = self.enumerate_ports() {
            log::error!("UHCI: Port enumeration failed: {:?}", e);
        }
    }

    /// Clean up the controller before handing off to the OS
    ///
    /// This must be called before ExitBootServices to ensure Linux's UHCI
    /// driver can properly initialize the controller. Following libpayload's
    /// uhci_shutdown and uhci_reset patterns.
    pub fn cleanup(&mut self) {
        log::debug!("UHCI cleanup: stopping and resetting controller");

        let regs = self.regs();

        // 1. Stop the controller
        regs.usbcmd().set(0);

        // 2. Global Reset (hold for at least 10ms per UHCI spec 2.1.1)
        regs.usbcmd().write(USBCMD::GRESET::SET);
        crate::time::delay_ms(50);
        regs.usbcmd().set(0);
        crate::time::delay_ms(10);

        // 3. Host Controller Reset
        regs.usbcmd().write(USBCMD::HCRESET::SET);

        // Wait for reset to complete (should be quick, timeout after 100ms)
        wait_for(100, || !regs.usbcmd().is_set(USBCMD::HCRESET));

        // 4. Clear status register
        regs.usbsts().set(0x3F);

        log::debug!("UHCI cleanup complete");
    }
}
