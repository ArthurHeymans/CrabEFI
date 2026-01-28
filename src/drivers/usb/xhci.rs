//! xHCI (USB 3.0) Host Controller Interface driver
//!
//! This module provides a minimal xHCI driver for USB mass storage devices.

use crate::drivers::pci::{self, PciAddress, PciDevice};
use crate::efi;
use core::ptr;
use core::sync::atomic::{fence, Ordering};

use spin::Mutex;

/// xHCI Capability Registers
mod cap_regs {
    /// Capability Register Length
    pub const CAPLENGTH: u32 = 0x00;
    /// Host Controller Interface Version
    pub const HCIVERSION: u32 = 0x02;
    /// Structural Parameters 1
    pub const HCSPARAMS1: u32 = 0x04;
    /// Structural Parameters 2
    pub const HCSPARAMS2: u32 = 0x08;
    /// Structural Parameters 3
    pub const HCSPARAMS3: u32 = 0x0C;
    /// Capability Parameters 1
    pub const HCCPARAMS1: u32 = 0x10;
    /// Doorbell Offset
    pub const DBOFF: u32 = 0x14;
    /// Runtime Register Space Offset
    pub const RTSOFF: u32 = 0x18;
    /// Capability Parameters 2
    pub const HCCPARAMS2: u32 = 0x1C;
}

/// xHCI Operational Registers (relative to op_base)
mod op_regs {
    /// USB Command
    pub const USBCMD: u32 = 0x00;
    /// USB Status
    pub const USBSTS: u32 = 0x04;
    /// Page Size
    pub const PAGESIZE: u32 = 0x08;
    /// Device Notification Control
    pub const DNCTRL: u32 = 0x14;
    /// Command Ring Control
    pub const CRCR: u32 = 0x18;
    /// Device Context Base Address Array Pointer
    pub const DCBAAP: u32 = 0x30;
    /// Configure
    pub const CONFIG: u32 = 0x38;
}

/// USB Command bits
mod usbcmd {
    /// Run/Stop
    pub const RS: u32 = 1 << 0;
    /// Host Controller Reset
    pub const HCRST: u32 = 1 << 1;
    /// Interrupter Enable
    pub const INTE: u32 = 1 << 2;
    /// Host System Error Enable
    pub const HSEE: u32 = 1 << 3;
}

/// USB Status bits
mod usbsts {
    /// Host Controller Halted
    pub const HCH: u32 = 1 << 0;
    /// Host System Error
    pub const HSE: u32 = 1 << 2;
    /// Event Interrupt
    pub const EINT: u32 = 1 << 3;
    /// Port Change Detect
    pub const PCD: u32 = 1 << 4;
    /// Controller Not Ready
    pub const CNR: u32 = 1 << 11;
}

/// Port Register offsets (relative to port base)
mod port_regs {
    /// Port Status and Control
    pub const PORTSC: u32 = 0x00;
    /// Port Power Management Status and Control
    pub const PORTPMSC: u32 = 0x04;
    /// Port Link Info
    pub const PORTLI: u32 = 0x08;
    /// Port Hardware LPM Control
    pub const PORTHLPMC: u32 = 0x0C;
}

/// Port Status and Control bits
mod portsc {
    /// Current Connect Status
    pub const CCS: u32 = 1 << 0;
    /// Port Enabled/Disabled
    pub const PED: u32 = 1 << 1;
    /// Over-current Active
    pub const OCA: u32 = 1 << 3;
    /// Port Reset
    pub const PR: u32 = 1 << 4;
    /// Port Link State (bits 5-8)
    pub const PLS_MASK: u32 = 0xF << 5;
    pub const PLS_U0: u32 = 0 << 5;
    /// Port Power
    pub const PP: u32 = 1 << 9;
    /// Port Speed (bits 10-13)
    pub const SPEED_MASK: u32 = 0xF << 10;
    pub const SPEED_FULL: u32 = 1 << 10;
    pub const SPEED_LOW: u32 = 2 << 10;
    pub const SPEED_HIGH: u32 = 3 << 10;
    pub const SPEED_SUPER: u32 = 4 << 10;
    /// Port Indicator Control (bits 14-15)
    pub const PIC_MASK: u32 = 3 << 14;
    /// Port Link State Write Strobe
    pub const LWS: u32 = 1 << 16;
    /// Connect Status Change
    pub const CSC: u32 = 1 << 17;
    /// Port Enabled/Disabled Change
    pub const PEC: u32 = 1 << 18;
    /// Warm Port Reset Change
    pub const WRC: u32 = 1 << 19;
    /// Over-current Change
    pub const OCC: u32 = 1 << 20;
    /// Port Reset Change
    pub const PRC: u32 = 1 << 21;
    /// Port Link State Change
    pub const PLC: u32 = 1 << 22;
    /// Port Config Error Change
    pub const CEC: u32 = 1 << 23;
    /// Wake on Connect Enable
    pub const WCE: u32 = 1 << 25;
    /// Wake on Disconnect Enable
    pub const WDE: u32 = 1 << 26;
    /// Wake on Over-current Enable
    pub const WOE: u32 = 1 << 27;
    /// Write mask for clearing status changes
    pub const CHANGE_MASK: u32 = CSC | PEC | WRC | OCC | PRC | PLC | CEC;
}

/// TRB Types
mod trb_type {
    /// Normal TRB
    pub const NORMAL: u32 = 1;
    /// Setup Stage TRB
    pub const SETUP: u32 = 2;
    /// Data Stage TRB
    pub const DATA: u32 = 3;
    /// Status Stage TRB
    pub const STATUS: u32 = 4;
    /// Isoch TRB
    pub const ISOCH: u32 = 5;
    /// Link TRB
    pub const LINK: u32 = 6;
    /// Event Data TRB
    pub const EVENT_DATA: u32 = 7;
    /// No Op TRB
    pub const NOOP: u32 = 8;
    /// Enable Slot Command
    pub const ENABLE_SLOT: u32 = 9;
    /// Disable Slot Command
    pub const DISABLE_SLOT: u32 = 10;
    /// Address Device Command
    pub const ADDRESS_DEVICE: u32 = 11;
    /// Configure Endpoint Command
    pub const CONFIGURE_ENDPOINT: u32 = 12;
    /// Evaluate Context Command
    pub const EVALUATE_CONTEXT: u32 = 13;
    /// Reset Endpoint Command
    pub const RESET_ENDPOINT: u32 = 14;
    /// Stop Endpoint Command
    pub const STOP_ENDPOINT: u32 = 15;
    /// Set TR Dequeue Pointer Command
    pub const SET_TR_DEQUEUE: u32 = 16;
    /// Reset Device Command
    pub const RESET_DEVICE: u32 = 17;
    /// Transfer Event
    pub const TRANSFER_EVENT: u32 = 32;
    /// Command Completion Event
    pub const COMMAND_COMPLETION: u32 = 33;
    /// Port Status Change Event
    pub const PORT_STATUS_CHANGE: u32 = 34;
    /// Host Controller Event
    pub const HOST_CONTROLLER: u32 = 37;
}

/// TRB Completion Codes
mod trb_cc {
    pub const SUCCESS: u32 = 1;
    pub const DATA_BUFFER_ERROR: u32 = 2;
    pub const BABBLE_DETECTED_ERROR: u32 = 3;
    pub const USB_TRANSACTION_ERROR: u32 = 4;
    pub const TRB_ERROR: u32 = 5;
    pub const STALL_ERROR: u32 = 6;
    pub const SHORT_PACKET: u32 = 13;
}

/// USB Request Types
mod usb_req_type {
    pub const DIR_OUT: u8 = 0x00;
    pub const DIR_IN: u8 = 0x80;
    pub const TYPE_STANDARD: u8 = 0x00;
    pub const TYPE_CLASS: u8 = 0x20;
    pub const TYPE_VENDOR: u8 = 0x40;
    pub const RCPT_DEVICE: u8 = 0x00;
    pub const RCPT_INTERFACE: u8 = 0x01;
    pub const RCPT_ENDPOINT: u8 = 0x02;
}

/// USB Standard Requests
mod usb_req {
    pub const GET_STATUS: u8 = 0x00;
    pub const CLEAR_FEATURE: u8 = 0x01;
    pub const SET_FEATURE: u8 = 0x03;
    pub const SET_ADDRESS: u8 = 0x05;
    pub const GET_DESCRIPTOR: u8 = 0x06;
    pub const SET_DESCRIPTOR: u8 = 0x07;
    pub const GET_CONFIGURATION: u8 = 0x08;
    pub const SET_CONFIGURATION: u8 = 0x09;
    pub const GET_INTERFACE: u8 = 0x0A;
    pub const SET_INTERFACE: u8 = 0x0B;
}

/// USB Descriptor Types
mod usb_desc_type {
    pub const DEVICE: u8 = 1;
    pub const CONFIGURATION: u8 = 2;
    pub const STRING: u8 = 3;
    pub const INTERFACE: u8 = 4;
    pub const ENDPOINT: u8 = 5;
}

/// USB Device Descriptor
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct UsbDeviceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub bcd_usb: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub max_packet_size0: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub bcd_device: u16,
    pub manufacturer: u8,
    pub product: u8,
    pub serial_number: u8,
    pub num_configurations: u8,
}

/// USB Configuration Descriptor
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct UsbConfigDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub total_length: u16,
    pub num_interfaces: u8,
    pub configuration_value: u8,
    pub configuration: u8,
    pub attributes: u8,
    pub max_power: u8,
}

/// USB Interface Descriptor
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct UsbInterfaceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub interface: u8,
}

/// USB Endpoint Descriptor
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct UsbEndpointDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub endpoint_address: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

/// Transfer Request Block (16 bytes)
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct Trb {
    pub param: u64,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    fn set_type(&mut self, trb_type: u32) {
        self.control = (self.control & !0xFC00) | ((trb_type & 0x3F) << 10);
    }

    fn get_type(&self) -> u32 {
        (self.control >> 10) & 0x3F
    }

    fn set_cycle(&mut self, cycle: bool) {
        if cycle {
            self.control |= 1;
        } else {
            self.control &= !1;
        }
    }

    fn get_cycle(&self) -> bool {
        self.control & 1 != 0
    }

    fn completion_code(&self) -> u32 {
        (self.status >> 24) & 0xFF
    }

    fn slot_id(&self) -> u8 {
        ((self.control >> 24) & 0xFF) as u8
    }
}

/// Slot Context (32 bytes)
#[repr(C, align(32))]
#[derive(Clone, Copy, Default)]
pub struct SlotContext {
    pub dw0: u32, // Route String, Speed, MTT, Hub, Context Entries
    pub dw1: u32, // Max Exit Latency, Root Hub Port Number, Number of Ports
    pub dw2: u32, // Parent Hub Slot ID, Parent Port Number, TT Think Time, Interrupter Target
    pub dw3: u32, // USB Device Address, Slot State
    pub reserved: [u32; 4],
}

impl SlotContext {
    fn set_context_entries(&mut self, entries: u8) {
        self.dw0 = (self.dw0 & !0xF8000000) | ((entries as u32) << 27);
    }

    fn set_speed(&mut self, speed: u8) {
        self.dw0 = (self.dw0 & !0x00F00000) | ((speed as u32) << 20);
    }

    fn set_root_hub_port(&mut self, port: u8) {
        self.dw1 = (self.dw1 & !0x00FF0000) | ((port as u32) << 16);
    }
}

/// Endpoint Context (32 bytes)
#[repr(C, align(32))]
#[derive(Clone, Copy, Default)]
pub struct EndpointContext {
    pub dw0: u32,            // EP State, Mult, MaxPStreams, LSA, Interval, MaxESITPayloadHi
    pub dw1: u32,            // CErr, EP Type, HID, MaxBurstSize, MaxPacketSize
    pub tr_dequeue_ptr: u64, // TR Dequeue Pointer
    pub dw4: u32,            // Average TRB Length, MaxESITPayloadLo
    pub reserved: [u32; 3],
}

impl EndpointContext {
    fn set_ep_type(&mut self, ep_type: u8) {
        self.dw1 = (self.dw1 & !0x00000038) | ((ep_type as u32) << 3);
    }

    fn set_max_packet_size(&mut self, size: u16) {
        self.dw1 = (self.dw1 & !0xFFFF0000) | ((size as u32) << 16);
    }

    fn set_max_burst_size(&mut self, size: u8) {
        self.dw1 = (self.dw1 & !0x0000FF00) | ((size as u32) << 8);
    }

    fn set_cerr(&mut self, cerr: u8) {
        self.dw1 = (self.dw1 & !0x00000006) | ((cerr as u32) << 1);
    }

    fn set_tr_dequeue_ptr(&mut self, ptr: u64, dcs: bool) {
        self.tr_dequeue_ptr = (ptr & !0xF) | if dcs { 1 } else { 0 };
    }

    fn set_avg_trb_length(&mut self, len: u16) {
        self.dw4 = (self.dw4 & !0x0000FFFF) | (len as u32);
    }

    fn set_interval(&mut self, interval: u8) {
        self.dw0 = (self.dw0 & !0x00FF0000) | ((interval as u32) << 16);
    }
}

/// Input Control Context (32 bytes)
#[repr(C, align(32))]
#[derive(Clone, Copy, Default)]
pub struct InputControlContext {
    pub drop_flags: u32,
    pub add_flags: u32,
    pub reserved: [u32; 5],
    pub configuration_value: u8,
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub reserved2: u8,
}

/// Device Context (consists of Slot + 31 Endpoint Contexts)
#[repr(C, align(64))]
pub struct DeviceContext {
    pub slot: SlotContext,
    pub endpoints: [EndpointContext; 31],
}

impl Default for DeviceContext {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// Input Context (Input Control + Device Context)
#[repr(C, align(64))]
pub struct InputContext {
    pub control: InputControlContext,
    pub slot: SlotContext,
    pub endpoints: [EndpointContext; 31],
}

impl Default for InputContext {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// Ring buffer for TRBs
pub struct TrbRing {
    /// Base address of the ring
    base: u64,
    /// Current enqueue pointer index
    enqueue_idx: usize,
    /// Current dequeue pointer index
    dequeue_idx: usize,
    /// Number of TRBs in the ring
    size: usize,
    /// Current cycle bit
    cycle: bool,
}

impl TrbRing {
    /// Create an empty/uninitialized TrbRing (for placeholder use)
    const fn empty() -> Self {
        Self {
            base: 0,
            enqueue_idx: 0,
            dequeue_idx: 0,
            size: 0,
            cycle: true,
        }
    }

    /// Create a new command/transfer ring with a link TRB at the end
    fn new(base: u64, size: usize) -> Self {
        if size == 0 {
            return Self::empty();
        }

        // Initialize all TRBs to 0
        unsafe {
            ptr::write_bytes(base as *mut u8, 0, size * 16);
        }

        // Set up link TRB at the end to wrap around
        let link_trb = unsafe { &mut *((base + ((size - 1) * 16) as u64) as *mut Trb) };
        link_trb.param = base;
        link_trb.set_type(trb_type::LINK);
        link_trb.control |= 1 << 1; // Toggle Cycle bit

        Self {
            base,
            enqueue_idx: 0,
            dequeue_idx: 0,
            size,
            cycle: true,
        }
    }

    /// Create a new event ring (no link TRB, consumer-side cycle tracking)
    fn new_event_ring(base: u64, size: usize) -> Self {
        if size == 0 {
            return Self::empty();
        }

        // Initialize all TRBs to 0 (cycle bits = 0)
        // Hardware will write with cycle = 1 initially
        unsafe {
            ptr::write_bytes(base as *mut u8, 0, size * 16);
        }

        Self {
            base,
            enqueue_idx: 0,
            dequeue_idx: 0,
            size,
            cycle: true, // Expect cycle = 1 from hardware initially
        }
    }

    fn enqueue(&mut self, trb: &Trb) -> u64 {
        let addr = self.base + (self.enqueue_idx * 16) as u64;
        let entry = unsafe { &mut *(addr as *mut Trb) };

        entry.param = trb.param;
        entry.status = trb.status;
        entry.control = (trb.control & !1) | if self.cycle { 1 } else { 0 };

        fence(Ordering::SeqCst);

        self.enqueue_idx += 1;

        // Check if we need to wrap around via link TRB
        if self.enqueue_idx >= self.size - 1 {
            // Ring the link TRB's cycle bit
            let link = unsafe { &mut *((self.base + ((self.size - 1) * 16) as u64) as *mut Trb) };
            if self.cycle {
                link.control |= 1;
            } else {
                link.control &= !1;
            }
            fence(Ordering::SeqCst);

            self.enqueue_idx = 0;
            self.cycle = !self.cycle;
        }

        addr
    }

    fn dequeue(&mut self) -> Option<Trb> {
        let addr = self.base + (self.dequeue_idx * 16) as u64;
        let entry = unsafe { &*(addr as *const Trb) };

        // Check if this TRB is ready (cycle bit matches)
        if entry.get_cycle() != self.cycle {
            return None;
        }

        let trb = *entry;

        self.dequeue_idx += 1;
        if self.dequeue_idx >= self.size - 1 {
            self.dequeue_idx = 0;
            self.cycle = !self.cycle;
        }

        Some(trb)
    }

    fn physical_addr(&self) -> u64 {
        self.base | if self.cycle { 1 } else { 0 }
    }
}

/// USB device slot
pub struct UsbSlot {
    /// Slot ID
    pub slot_id: u8,
    /// Device context
    pub device_context: *mut DeviceContext,
    /// Input context
    pub input_context: *mut InputContext,
    /// Transfer rings for each endpoint (0 = control, 1-30 = other)
    pub transfer_rings: [Option<TrbRing>; 31],
    /// Device descriptor
    pub device_desc: UsbDeviceDescriptor,
    /// Port number
    pub port: u8,
    /// Speed
    pub speed: u8,
    /// Is this a mass storage device?
    pub is_mass_storage: bool,
    /// Bulk IN endpoint
    pub bulk_in_ep: u8,
    /// Bulk OUT endpoint
    pub bulk_out_ep: u8,
    /// Max packet size for bulk endpoints
    pub bulk_max_packet: u16,
}

/// xHCI Controller
pub struct XhciController {
    /// PCI address (bus:device.function)
    pci_address: PciAddress,
    /// MMIO base address
    mmio_base: u64,
    /// Operational registers base
    op_base: u64,
    /// Runtime registers base
    rt_base: u64,
    /// Doorbell registers base
    db_base: u64,
    /// Port registers base
    port_base: u64,
    /// Number of ports
    num_ports: u8,
    /// Number of slots
    max_slots: u8,
    /// Page size
    page_size: u32,
    /// Device Context Base Address Array
    dcbaa: u64,
    /// Command ring
    cmd_ring: TrbRing,
    /// Event ring segment table
    erst: u64,
    /// Event ring
    event_ring: TrbRing,
    /// Active slots (limited to 4 to avoid stack overflow - each UsbSlot is ~800 bytes)
    slots: [Option<UsbSlot>; 4],
}

/// xHCI error type
#[derive(Debug)]
pub enum XhciError {
    /// Controller not ready
    NotReady,
    /// Timeout
    Timeout,
    /// No free slots
    NoFreeSlots,
    /// Command failed
    CommandFailed(u32),
    /// Allocation failed
    AllocationFailed,
    /// Device not found
    DeviceNotFound,
    /// Transfer failed
    TransferFailed(u32),
    /// Invalid parameter
    InvalidParameter,
    /// USB transaction error
    UsbError,
    /// Stall error
    StallError,
}

impl XhciController {
    /// Create a new xHCI controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, XhciError> {
        let mmio_base = pci_dev.mmio_base().ok_or(XhciError::NotReady)?;

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        // Read capability registers
        // Read the first DWORD which contains CAPLENGTH and HCIVERSION
        let cap_dword0 = unsafe { ptr::read_volatile(mmio_base as *const u32) };
        let caplength = (cap_dword0 & 0xFF) as u8;
        let hciversion = ((cap_dword0 >> 16) & 0xFFFF) as u16;

        let hcsparams1 =
            unsafe { ptr::read_volatile((mmio_base + cap_regs::HCSPARAMS1 as u64) as *const u32) };
        let _hccparams1 =
            unsafe { ptr::read_volatile((mmio_base + cap_regs::HCCPARAMS1 as u64) as *const u32) };
        let dboff =
            unsafe { ptr::read_volatile((mmio_base + cap_regs::DBOFF as u64) as *const u32) };
        let rtsoff =
            unsafe { ptr::read_volatile((mmio_base + cap_regs::RTSOFF as u64) as *const u32) };

        let op_base = mmio_base + caplength as u64;
        let rt_base = mmio_base + (rtsoff & !0x1F) as u64;
        let db_base = mmio_base + (dboff & !0x3) as u64;

        let num_ports = ((hcsparams1 >> 24) & 0xFF) as u8;
        let hw_max_slots = (hcsparams1 & 0xFF) as u8;
        // Cap max_slots to our array size to avoid stack overflow
        let max_slots = hw_max_slots.min(4);

        log::info!(
            "xHCI version: {}.{}.{}, ports: {}, slots: {}",
            (hciversion >> 8) & 0xFF,
            (hciversion >> 4) & 0xF,
            hciversion & 0xF,
            num_ports,
            max_slots
        );

        // Calculate port base
        let port_base = op_base + 0x400;

        // Read page size
        let page_size_reg =
            unsafe { ptr::read_volatile((op_base + op_regs::PAGESIZE as u64) as *const u32) };
        let page_size = (page_size_reg & 0xFFFF) << 12;

        let mut controller = Self {
            pci_address: pci_dev.address,
            mmio_base,
            op_base,
            rt_base,
            db_base,
            port_base,
            num_ports,
            max_slots,
            page_size,
            dcbaa: 0,
            cmd_ring: TrbRing::empty(), // Will be initialized in init()
            erst: 0,
            event_ring: TrbRing::empty(), // Will be initialized in init()
            slots: core::array::from_fn(|_| None),
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

    fn read_op_reg64(&self, offset: u32) -> u64 {
        unsafe { ptr::read_volatile((self.op_base + offset as u64) as *const u64) }
    }

    fn write_op_reg64(&mut self, offset: u32, value: u64) {
        unsafe { ptr::write_volatile((self.op_base + offset as u64) as *mut u64, value) }
    }

    fn read_port_reg(&self, port: u8, offset: u32) -> u32 {
        let addr = self.port_base + (port as u64 * 0x10) + offset as u64;
        unsafe { ptr::read_volatile(addr as *const u32) }
    }

    fn write_port_reg(&mut self, port: u8, offset: u32, value: u32) {
        let addr = self.port_base + (port as u64 * 0x10) + offset as u64;
        unsafe { ptr::write_volatile(addr as *mut u32, value) }
    }

    fn ring_doorbell(&self, slot: u8, target: u8) {
        let addr = self.db_base + (slot as u64 * 4);
        unsafe { ptr::write_volatile(addr as *mut u32, target as u32) }
    }

    fn read_interrupter_reg(&self, offset: u32) -> u32 {
        let addr = self.rt_base + 0x20 + offset as u64; // Interrupter 0
        unsafe { ptr::read_volatile(addr as *const u32) }
    }

    fn write_interrupter_reg(&mut self, offset: u32, value: u32) {
        let addr = self.rt_base + 0x20 + offset as u64; // Interrupter 0
        unsafe { ptr::write_volatile(addr as *mut u32, value) }
    }

    fn write_interrupter_reg64(&mut self, offset: u32, value: u64) {
        let addr = self.rt_base + 0x20 + offset as u64; // Interrupter 0
        unsafe { ptr::write_volatile(addr as *mut u64, value) }
    }

    /// Initialize the controller
    fn init(&mut self) -> Result<(), XhciError> {
        // Wait for controller to be ready
        for _ in 0..100000 {
            let sts = self.read_op_reg(op_regs::USBSTS);
            if sts & usbsts::CNR == 0 {
                break;
            }
        }

        // Stop the controller
        let cmd = self.read_op_reg(op_regs::USBCMD);
        self.write_op_reg(op_regs::USBCMD, cmd & !usbcmd::RS);

        // Wait for halt
        for _ in 0..100000 {
            let sts = self.read_op_reg(op_regs::USBSTS);
            if sts & usbsts::HCH != 0 {
                break;
            }
        }

        // Reset the controller
        self.write_op_reg(op_regs::USBCMD, usbcmd::HCRST);

        // Wait for reset to complete
        for _ in 0..100000 {
            let cmd = self.read_op_reg(op_regs::USBCMD);
            let sts = self.read_op_reg(op_regs::USBSTS);
            if cmd & usbcmd::HCRST == 0 && sts & usbsts::CNR == 0 {
                break;
            }
        }

        // Set max device slots
        self.write_op_reg(op_regs::CONFIG, self.max_slots as u32);

        // Allocate and set up DCBAA (Device Context Base Address Array)
        let dcbaa_pages = (((self.max_slots as u64 + 1) * 8) + 4095) / 4096;
        self.dcbaa = efi::allocate_pages(dcbaa_pages).ok_or(XhciError::AllocationFailed)?;
        unsafe { ptr::write_bytes(self.dcbaa as *mut u8, 0, (dcbaa_pages * 4096) as usize) };
        self.write_op_reg64(op_regs::DCBAAP, self.dcbaa);

        // Allocate command ring (256 TRBs)
        let cmd_ring_base = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        self.cmd_ring = TrbRing::new(cmd_ring_base, 256);

        // Set command ring pointer
        self.write_op_reg64(op_regs::CRCR, self.cmd_ring.physical_addr());

        // Allocate event ring (256 TRBs) - no link TRB for event rings
        let event_ring_base = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        self.event_ring = TrbRing::new_event_ring(event_ring_base, 256);

        // Allocate Event Ring Segment Table (ERST)
        self.erst = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        unsafe { ptr::write_bytes(self.erst as *mut u8, 0, 4096) };

        // Set up ERST entry
        let erst_entry = self.erst as *mut u64;
        unsafe {
            ptr::write_volatile(erst_entry, event_ring_base); // Ring Segment Base Address
            ptr::write_volatile(erst_entry.add(1), 256); // Ring Segment Size
        }

        // Set ERSTSZ (Event Ring Segment Table Size)
        self.write_interrupter_reg(0x08, 1);

        // Set ERDP (Event Ring Dequeue Pointer)
        self.write_interrupter_reg64(0x18, event_ring_base);

        // Set ERSTBA (Event Ring Segment Table Base Address)
        self.write_interrupter_reg64(0x10, self.erst);

        // Start the controller
        let cmd = self.read_op_reg(op_regs::USBCMD);
        self.write_op_reg(op_regs::USBCMD, cmd | usbcmd::RS);

        // Wait for running
        for _ in 0..100000 {
            let sts = self.read_op_reg(op_regs::USBSTS);
            if sts & usbsts::HCH == 0 {
                break;
            }
        }

        log::info!("xHCI controller initialized");
        Ok(())
    }

    /// Wait for and process a command completion event
    fn wait_command_completion(&mut self) -> Result<Trb, XhciError> {
        for _ in 0..1000000 {
            // Read event ring dequeue pointer
            let erdp = self.event_ring.base + (self.event_ring.dequeue_idx * 16) as u64;
            let event = unsafe { &*(erdp as *const Trb) };

            // Check if event is ready
            if event.get_cycle() == self.event_ring.cycle {
                let trb = *event;

                // Advance dequeue pointer
                self.event_ring.dequeue_idx += 1;
                if self.event_ring.dequeue_idx >= self.event_ring.size {
                    self.event_ring.dequeue_idx = 0;
                    self.event_ring.cycle = !self.event_ring.cycle;
                }

                // Update ERDP (write low and high separately, no EHB bit)
                let new_erdp = self.event_ring.base + (self.event_ring.dequeue_idx * 16) as u64;
                self.write_interrupter_reg(0x18, new_erdp as u32);
                self.write_interrupter_reg(0x1C, (new_erdp >> 32) as u32);

                if trb.get_type() == trb_type::COMMAND_COMPLETION {
                    let cc = trb.completion_code();
                    if cc == trb_cc::SUCCESS {
                        return Ok(trb);
                    } else {
                        return Err(XhciError::CommandFailed(cc));
                    }
                } else if trb.get_type() == trb_type::PORT_STATUS_CHANGE {
                    // Ignore port status change events during command wait
                    continue;
                }
            }
        }
        Err(XhciError::Timeout)
    }

    /// Wait for transfer completion
    fn wait_transfer_completion(&mut self, _slot: u8, _ep: u8) -> Result<Trb, XhciError> {
        for i in 0..10000000 {
            let erdp = self.event_ring.base + (self.event_ring.dequeue_idx * 16) as u64;
            let event = unsafe { &*(erdp as *const Trb) };

            if event.get_cycle() == self.event_ring.cycle {
                let trb = *event;

                // Advance dequeue pointer
                self.event_ring.dequeue_idx += 1;
                if self.event_ring.dequeue_idx >= self.event_ring.size {
                    self.event_ring.dequeue_idx = 0;
                    self.event_ring.cycle = !self.event_ring.cycle;
                }

                // Update ERDP (write low and high separately, no EHB bit)
                let new_erdp = self.event_ring.base + (self.event_ring.dequeue_idx * 16) as u64;
                self.write_interrupter_reg(0x18, new_erdp as u32);
                self.write_interrupter_reg(0x1C, (new_erdp >> 32) as u32);

                if trb.get_type() == trb_type::TRANSFER_EVENT {
                    let cc = trb.completion_code();
                    if cc == trb_cc::SUCCESS || cc == trb_cc::SHORT_PACKET {
                        return Ok(trb);
                    } else if cc == trb_cc::STALL_ERROR {
                        return Err(XhciError::StallError);
                    } else {
                        return Err(XhciError::TransferFailed(cc));
                    }
                } else {
                    // Got a non-transfer event, log and continue waiting
                    log::trace!(
                        "xHCI: Got event type {} while waiting for transfer",
                        trb.get_type()
                    );
                }
            }

            // Small delay every 100000 iterations to avoid tight busy-loop
            if i % 100000 == 99999 {
                for _ in 0..1000 {
                    core::hint::spin_loop();
                }
            }
        }
        log::warn!(
            "xHCI: Transfer timeout, event ring dequeue_idx={}, cycle={}",
            self.event_ring.dequeue_idx,
            self.event_ring.cycle
        );
        Err(XhciError::Timeout)
    }

    /// Enable a slot
    fn enable_slot(&mut self) -> Result<u8, XhciError> {
        let mut trb = Trb::default();
        trb.set_type(trb_type::ENABLE_SLOT);

        self.cmd_ring.enqueue(&trb);
        self.ring_doorbell(0, 0); // Ring host controller doorbell

        let completion = self.wait_command_completion()?;
        Ok(completion.slot_id())
    }

    /// Address a device
    fn address_device(&mut self, slot_id: u8, port: u8, speed: u8) -> Result<(), XhciError> {
        // Allocate device context
        let device_context = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        unsafe { ptr::write_bytes(device_context as *mut u8, 0, 4096) };

        // Allocate input context
        let input_context = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        unsafe { ptr::write_bytes(input_context as *mut u8, 0, 4096) };

        // Allocate transfer ring for control endpoint
        let transfer_ring = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;

        let input = unsafe { &mut *(input_context as *mut InputContext) };

        // Set up input control context
        input.control.add_flags = 0x3; // Add slot and EP0

        // Set up slot context
        input.slot.set_context_entries(1);
        input.slot.set_speed(speed);
        input.slot.set_root_hub_port(port + 1);

        // Set up control endpoint context
        let max_packet = match speed {
            1 => 8,   // Full speed
            2 => 8,   // Low speed
            3 => 64,  // High speed
            4 => 512, // Super speed
            _ => 8,
        };

        input.endpoints[0].set_ep_type(4); // Control endpoint
        input.endpoints[0].set_max_packet_size(max_packet);
        input.endpoints[0].set_max_burst_size(0);
        input.endpoints[0].set_cerr(3);
        input.endpoints[0].set_tr_dequeue_ptr(transfer_ring, true);
        input.endpoints[0].set_avg_trb_length(8);

        // Set up transfer ring
        let ring = TrbRing::new(transfer_ring, 256);

        // Store in DCBAA
        let dcbaa_entry = unsafe { &mut *((self.dcbaa + (slot_id as u64 * 8)) as *mut u64) };
        *dcbaa_entry = device_context;

        // Build Address Device command
        let mut trb = Trb::default();
        trb.param = input_context;
        trb.set_type(trb_type::ADDRESS_DEVICE);
        trb.control |= (slot_id as u32) << 24;

        self.cmd_ring.enqueue(&trb);
        self.ring_doorbell(0, 0);

        self.wait_command_completion()?;

        // Store slot info
        let mut transfer_rings: [Option<TrbRing>; 31] = core::array::from_fn(|_| None);
        transfer_rings[0] = Some(ring);

        self.slots[slot_id as usize] = Some(UsbSlot {
            slot_id,
            device_context: device_context as *mut DeviceContext,
            input_context: input_context as *mut InputContext,
            transfer_rings,
            device_desc: UsbDeviceDescriptor::default(),
            port,
            speed,
            is_mass_storage: false,
            bulk_in_ep: 0,
            bulk_out_ep: 0,
            bulk_max_packet: 0,
        });

        Ok(())
    }

    /// Control transfer
    fn control_transfer(
        &mut self,
        slot_id: u8,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: Option<&mut [u8]>,
    ) -> Result<usize, XhciError> {
        let slot = self.slots[slot_id as usize]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        let ring = slot.transfer_rings[0]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        let is_in = (request_type & 0x80) != 0;
        let data_len = data.as_ref().map(|d| d.len()).unwrap_or(0);

        // Setup Stage TRB
        let mut setup = Trb::default();
        setup.param = (request_type as u64)
            | ((request as u64) << 8)
            | ((value as u64) << 16)
            | ((index as u64) << 32)
            | ((data_len as u64) << 48);
        setup.status = 8; // TRB transfer length = 8
        setup.set_type(trb_type::SETUP);
        setup.control |= 1 << 6; // IDT (Immediate Data)
        if data_len > 0 {
            setup.control |= if is_in { 3 << 16 } else { 2 << 16 }; // TRT
        }

        ring.enqueue(&setup);

        // Data Stage TRB (if needed)
        if let Some(data_buf) = data {
            let mut data_trb = Trb::default();
            data_trb.param = data_buf.as_ptr() as u64;
            data_trb.status = data_buf.len() as u32;
            data_trb.set_type(trb_type::DATA);
            if is_in {
                data_trb.control |= 1 << 16; // DIR = IN
            }

            ring.enqueue(&data_trb);
        }

        // Status Stage TRB
        let mut status = Trb::default();
        status.set_type(trb_type::STATUS);
        if data_len == 0 || !is_in {
            status.control |= 1 << 16; // DIR = IN for status
        }
        status.control |= 1 << 5; // IOC (Interrupt on Completion)

        ring.enqueue(&status);

        // Ring doorbell
        self.ring_doorbell(slot_id, 1); // EP0 = DCI 1

        // Wait for completion
        let completion = self.wait_transfer_completion(slot_id, 0)?;

        // Return transfer length
        let residual = completion.status & 0xFFFFFF;
        Ok(data_len.saturating_sub(residual as usize))
    }

    /// Get device descriptor
    fn get_device_descriptor(&mut self, slot_id: u8) -> Result<UsbDeviceDescriptor, XhciError> {
        let mut desc = [0u8; 18];

        // First, get just 8 bytes to determine max packet size
        let mut short_desc = [0u8; 8];
        self.control_transfer(
            slot_id,
            usb_req_type::DIR_IN | usb_req_type::TYPE_STANDARD | usb_req_type::RCPT_DEVICE,
            usb_req::GET_DESCRIPTOR,
            (usb_desc_type::DEVICE as u16) << 8,
            0,
            Some(&mut short_desc),
        )?;

        // Now get full descriptor
        self.control_transfer(
            slot_id,
            usb_req_type::DIR_IN | usb_req_type::TYPE_STANDARD | usb_req_type::RCPT_DEVICE,
            usb_req::GET_DESCRIPTOR,
            (usb_desc_type::DEVICE as u16) << 8,
            0,
            Some(&mut desc),
        )?;

        Ok(unsafe { ptr::read_unaligned(desc.as_ptr() as *const UsbDeviceDescriptor) })
    }

    /// Set configuration
    fn set_configuration(&mut self, slot_id: u8, config: u8) -> Result<(), XhciError> {
        self.control_transfer(
            slot_id,
            usb_req_type::DIR_OUT | usb_req_type::TYPE_STANDARD | usb_req_type::RCPT_DEVICE,
            usb_req::SET_CONFIGURATION,
            config as u16,
            0,
            None,
        )?;
        Ok(())
    }

    /// Enumerate ports and attach devices
    fn enumerate_ports(&mut self) -> Result<(), XhciError> {
        for port in 0..self.num_ports {
            let portsc = self.read_port_reg(port, port_regs::PORTSC);

            // Check if device is connected
            if portsc & portsc::CCS == 0 {
                continue;
            }

            // Get speed
            let speed = ((portsc & portsc::SPEED_MASK) >> 10) as u8;
            let speed_name = match speed {
                1 => "Full",
                2 => "Low",
                3 => "High",
                4 => "Super",
                _ => "Unknown",
            };

            log::info!("USB device on port {}: {} speed", port, speed_name);

            // Clear status change bits
            self.write_port_reg(port, port_regs::PORTSC, portsc | portsc::CHANGE_MASK);

            // Reset the port if needed
            if portsc & portsc::PED == 0 {
                let portsc = self.read_port_reg(port, port_regs::PORTSC);
                self.write_port_reg(port, port_regs::PORTSC, portsc | portsc::PR);

                // Wait for reset to complete
                for _ in 0..100000 {
                    let portsc = self.read_port_reg(port, port_regs::PORTSC);
                    if portsc & portsc::PRC != 0 {
                        self.write_port_reg(port, port_regs::PORTSC, portsc | portsc::PRC);
                        break;
                    }
                }
            }

            // Enable slot and address device
            match self.enable_slot() {
                Ok(slot_id) => {
                    log::debug!("Enabled slot {}", slot_id);

                    if let Err(e) = self.address_device(slot_id, port, speed) {
                        log::error!("Failed to address device on port {}: {:?}", port, e);
                        continue;
                    }

                    // Get device descriptor
                    match self.get_device_descriptor(slot_id) {
                        Ok(desc) => {
                            // Copy fields to avoid alignment issues
                            let vid = desc.vendor_id;
                            let pid = desc.product_id;
                            let class = desc.device_class;
                            let num_configs = desc.num_configurations;

                            log::info!("  VID={:04x} PID={:04x} Class={:02x}", vid, pid, class);

                            if let Some(slot) = &mut self.slots[slot_id as usize] {
                                slot.device_desc = desc;
                            }

                            // Check for mass storage (class 0x08)
                            if class == 0x08 || (class == 0x00 && num_configs > 0) {
                                // Try to configure as mass storage
                                if let Err(e) = self.configure_mass_storage(slot_id) {
                                    log::debug!("Not a mass storage device: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to get device descriptor: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    log::error!("Failed to enable slot for port {}: {:?}", port, e);
                }
            }
        }

        Ok(())
    }

    /// Configure a mass storage device
    fn configure_mass_storage(&mut self, slot_id: u8) -> Result<(), XhciError> {
        // Get configuration descriptor
        let mut config_buf = [0u8; 256];

        // First get just the header
        let mut header = [0u8; 9];
        self.control_transfer(
            slot_id,
            usb_req_type::DIR_IN | usb_req_type::TYPE_STANDARD | usb_req_type::RCPT_DEVICE,
            usb_req::GET_DESCRIPTOR,
            (usb_desc_type::CONFIGURATION as u16) << 8,
            0,
            Some(&mut header),
        )?;

        let total_len = u16::from_le_bytes([header[2], header[3]]) as usize;
        let total_len = total_len.min(config_buf.len());

        // Get full configuration
        self.control_transfer(
            slot_id,
            usb_req_type::DIR_IN | usb_req_type::TYPE_STANDARD | usb_req_type::RCPT_DEVICE,
            usb_req::GET_DESCRIPTOR,
            (usb_desc_type::CONFIGURATION as u16) << 8,
            0,
            Some(&mut config_buf[..total_len]),
        )?;

        // Parse configuration to find mass storage interface
        let mut offset = 9; // Skip config descriptor
        let mut bulk_in = 0u8;
        let mut bulk_out = 0u8;
        let mut bulk_max_packet = 0u16;
        let mut is_mass_storage = false;
        let mut _interface_num = 0u8;

        while offset < total_len {
            let len = config_buf[offset] as usize;
            if len == 0 {
                break;
            }

            let desc_type = config_buf[offset + 1];

            if desc_type == usb_desc_type::INTERFACE && offset + 9 <= total_len {
                let iface = unsafe {
                    ptr::read_unaligned(
                        config_buf[offset..].as_ptr() as *const UsbInterfaceDescriptor
                    )
                };

                // Mass storage class = 0x08, SCSI = 0x06, Bulk-Only = 0x50
                if iface.interface_class == 0x08 && iface.interface_protocol == 0x50 {
                    is_mass_storage = true;
                    _interface_num = iface.interface_number;
                    log::info!("  Found USB Mass Storage interface {}", _interface_num);
                }
            } else if desc_type == usb_desc_type::ENDPOINT
                && offset + 7 <= total_len
                && is_mass_storage
            {
                let ep = unsafe {
                    ptr::read_unaligned(
                        config_buf[offset..].as_ptr() as *const UsbEndpointDescriptor
                    )
                };

                // Bulk endpoint (type 2)
                if (ep.attributes & 0x03) == 0x02 {
                    let ep_addr = ep.endpoint_address;
                    let max_packet = ep.max_packet_size;

                    if ep_addr & 0x80 != 0 {
                        // IN endpoint
                        bulk_in = ep_addr & 0x0F;
                        bulk_max_packet = max_packet;
                        log::debug!("    Bulk IN EP: {} max_packet: {}", bulk_in, max_packet);
                    } else {
                        // OUT endpoint
                        bulk_out = ep_addr & 0x0F;
                        log::debug!("    Bulk OUT EP: {} max_packet: {}", bulk_out, max_packet);
                    }
                }
            }

            offset += len;
        }

        if !is_mass_storage || bulk_in == 0 || bulk_out == 0 {
            return Err(XhciError::DeviceNotFound);
        }

        // Set configuration
        let config_value = config_buf[5]; // bConfigurationValue
        self.set_configuration(slot_id, config_value)?;

        // Configure endpoints
        self.configure_bulk_endpoints(slot_id, bulk_in, bulk_out, bulk_max_packet)?;

        // Update slot info
        if let Some(slot) = &mut self.slots[slot_id as usize] {
            slot.is_mass_storage = true;
            slot.bulk_in_ep = bulk_in;
            slot.bulk_out_ep = bulk_out;
            slot.bulk_max_packet = bulk_max_packet;
        }

        log::info!("USB Mass Storage device configured on slot {}", slot_id);
        Ok(())
    }

    /// Configure bulk endpoints
    fn configure_bulk_endpoints(
        &mut self,
        slot_id: u8,
        bulk_in: u8,
        bulk_out: u8,
        max_packet: u16,
    ) -> Result<(), XhciError> {
        let slot = self.slots[slot_id as usize]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        // Allocate transfer rings for bulk endpoints
        let in_ring_addr = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        let out_ring_addr = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;

        let in_ring = TrbRing::new(in_ring_addr, 256);
        let out_ring = TrbRing::new(out_ring_addr, 256);

        // Calculate DCI (Device Context Index) for endpoints
        // DCI = (Endpoint Number * 2) + Direction (0=OUT, 1=IN)
        let in_dci = (bulk_in as usize * 2) + 1;
        let out_dci = bulk_out as usize * 2;

        // Set up input context
        let input = unsafe { &mut *slot.input_context };
        *input = InputContext::default();

        // Copy slot context from device context
        let device = unsafe { &*slot.device_context };
        input.slot = device.slot;
        input.slot.set_context_entries(in_dci.max(out_dci) as u8);

        // Set up endpoint contexts
        input.control.add_flags = 1 | (1 << in_dci) | (1 << out_dci);

        // Bulk IN endpoint
        input.endpoints[in_dci - 1].set_ep_type(6); // Bulk IN
        input.endpoints[in_dci - 1].set_max_packet_size(max_packet);
        input.endpoints[in_dci - 1].set_max_burst_size(0);
        input.endpoints[in_dci - 1].set_cerr(3);
        input.endpoints[in_dci - 1].set_tr_dequeue_ptr(in_ring_addr, true);
        input.endpoints[in_dci - 1].set_avg_trb_length(max_packet);

        // Bulk OUT endpoint
        input.endpoints[out_dci - 1].set_ep_type(2); // Bulk OUT
        input.endpoints[out_dci - 1].set_max_packet_size(max_packet);
        input.endpoints[out_dci - 1].set_max_burst_size(0);
        input.endpoints[out_dci - 1].set_cerr(3);
        input.endpoints[out_dci - 1].set_tr_dequeue_ptr(out_ring_addr, true);
        input.endpoints[out_dci - 1].set_avg_trb_length(max_packet);

        // Store rings
        slot.transfer_rings[in_dci - 1] = Some(in_ring);
        slot.transfer_rings[out_dci - 1] = Some(out_ring);

        // Send Configure Endpoint command
        let mut trb = Trb::default();
        trb.param = slot.input_context as u64;
        trb.set_type(trb_type::CONFIGURE_ENDPOINT);
        trb.control |= (slot_id as u32) << 24;

        self.cmd_ring.enqueue(&trb);
        self.ring_doorbell(0, 0);

        self.wait_command_completion()?;

        Ok(())
    }

    /// Bulk transfer
    pub fn bulk_transfer(
        &mut self,
        slot_id: u8,
        ep: u8,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<usize, XhciError> {
        let slot = self.slots[slot_id as usize]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        // Calculate DCI
        let dci = if is_in {
            (ep as usize * 2) + 1
        } else {
            ep as usize * 2
        };

        let ring = slot.transfer_rings[dci - 1]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        // Create Normal TRB
        let mut trb = Trb::default();
        trb.param = data.as_ptr() as u64;
        trb.status = data.len() as u32;
        trb.set_type(trb_type::NORMAL);
        trb.control |= 1 << 5; // IOC

        log::trace!(
            "xHCI: bulk_transfer slot={} ep={} dci={} dir={} len={} addr={:#x}",
            slot_id,
            ep,
            dci,
            if is_in { "IN" } else { "OUT" },
            data.len(),
            data.as_ptr() as u64
        );

        ring.enqueue(&trb);

        // Ring doorbell
        self.ring_doorbell(slot_id, dci as u8);

        // Wait for completion
        let completion = self.wait_transfer_completion(slot_id, ep)?;

        let residual = completion.status & 0xFFFFFF;
        Ok(data.len().saturating_sub(residual as usize))
    }

    /// Find a mass storage device
    pub fn find_mass_storage(&self) -> Option<u8> {
        for (slot_id, slot) in self.slots.iter().enumerate() {
            if let Some(s) = slot {
                if s.is_mass_storage {
                    return Some(slot_id as u8);
                }
            }
        }
        None
    }

    /// Get slot info
    pub fn get_slot(&self, slot_id: u8) -> Option<&UsbSlot> {
        self.slots[slot_id as usize].as_ref()
    }

    /// Get mutable slot info
    pub fn get_slot_mut(&mut self, slot_id: u8) -> Option<&mut UsbSlot> {
        self.slots[slot_id as usize].as_mut()
    }

    /// Get the PCI address of this controller
    pub fn pci_address(&self) -> PciAddress {
        self.pci_address
    }
}

/// Wrapper for xHCI controller pointer to implement Send
struct XhciControllerPtr(*mut XhciController);

// SAFETY: We ensure single-threaded access via the Mutex
unsafe impl Send for XhciControllerPtr {}

/// Global list of xHCI controllers
static XHCI_CONTROLLERS: Mutex<heapless::Vec<XhciControllerPtr, 4>> =
    Mutex::new(heapless::Vec::new());

/// Initialize xHCI controllers
pub fn init() {
    log::info!("Initializing xHCI controllers...");

    // Find xHCI controllers (class 0x0C, subclass 0x03, prog_if 0x30)
    let devices = pci::get_all_devices();
    let mut xhci_count = 0;

    let mut controllers = XHCI_CONTROLLERS.lock();

    for dev in devices.iter() {
        if dev.class_code == 0x0C && dev.subclass == 0x03 && dev.prog_if == 0x30 {
            log::info!(
                "Found xHCI controller at {}: {:04x}:{:04x}",
                dev.address,
                dev.vendor_id,
                dev.device_id
            );

            match XhciController::new(dev) {
                Ok(controller) => {
                    // Calculate required pages: XhciController contains
                    // slots: [Option<UsbSlot>; 4] where UsbSlot contains transfer_rings
                    let size = core::mem::size_of::<XhciController>();
                    let pages = (size + 4095) / 4096;
                    log::debug!(
                        "xHCI: Allocating {} pages ({} bytes) for XhciController",
                        pages,
                        size
                    );
                    let controller_ptr = efi::allocate_pages(pages as u64);
                    if let Some(ptr) = controller_ptr {
                        let controller_box = ptr as *mut XhciController;
                        unsafe {
                            ptr::write(controller_box, controller);
                        }
                        let _ = controllers.push(XhciControllerPtr(controller_box));
                        xhci_count += 1;
                        log::info!("xHCI controller at {} initialized", dev.address);
                    }
                }
                Err(e) => {
                    log::error!(
                        "Failed to initialize xHCI controller at {}: {:?}",
                        dev.address,
                        e
                    );
                }
            }
        }
    }

    log::info!("xHCI initialization complete: {} controllers", xhci_count);
}

/// Get an xHCI controller
pub fn get_controller(index: usize) -> Option<&'static mut XhciController> {
    let controllers = XHCI_CONTROLLERS.lock();
    controllers.get(index).map(|ptr| unsafe { &mut *ptr.0 })
}

// Ensure XhciController can be sent between threads
unsafe impl Send for XhciController {}
unsafe impl Send for UsbSlot {}
