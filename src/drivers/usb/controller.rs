//! USB Core Abstraction Layer
//!
//! This module provides common types, traits, and infrastructure for USB
//! host controller drivers and device class drivers.
//!
//! # Architecture
//!
//! The USB stack is organized in layers:
//! - Host Controller Drivers (xHCI, EHCI, OHCI, UHCI) implement the `UsbController` trait
//! - Device Class Drivers (MSC, HID) use the trait to communicate with devices
//! - The core layer handles enumeration and device management

use crate::efi;
use core::ptr;

// ============================================================================
// USB Speed
// ============================================================================

/// USB device speed
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbSpeed {
    /// Low speed (1.5 Mbps) - USB 1.0
    Low = 1,
    /// Full speed (12 Mbps) - USB 1.1
    Full = 2,
    /// High speed (480 Mbps) - USB 2.0
    High = 3,
    /// Super speed (5 Gbps) - USB 3.0
    Super = 4,
    /// Super speed+ (10+ Gbps) - USB 3.1+
    SuperPlus = 5,
}

impl UsbSpeed {
    /// Get the default max packet size for control endpoint 0
    pub fn default_max_packet_size(self) -> u16 {
        match self {
            UsbSpeed::Low => 8,
            UsbSpeed::Full => 8, // Can be 8, 16, 32, or 64
            UsbSpeed::High => 64,
            UsbSpeed::Super | UsbSpeed::SuperPlus => 512,
        }
    }

    /// Create from xHCI port speed value
    pub fn from_xhci(speed: u8) -> Option<Self> {
        match speed {
            1 => Some(UsbSpeed::Full),
            2 => Some(UsbSpeed::Low),
            3 => Some(UsbSpeed::High),
            4 => Some(UsbSpeed::Super),
            5 => Some(UsbSpeed::SuperPlus),
            _ => None,
        }
    }

    /// Create from EHCI/OHCI/UHCI port status
    pub fn from_ehci(is_low_speed: bool) -> Self {
        if is_low_speed {
            UsbSpeed::Low
        } else {
            UsbSpeed::High
        }
    }

    pub fn from_ohci(is_low_speed: bool) -> Self {
        if is_low_speed {
            UsbSpeed::Low
        } else {
            UsbSpeed::Full
        }
    }
}

// ============================================================================
// USB Endpoint Types
// ============================================================================

/// USB endpoint transfer type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EndpointType {
    /// Control endpoint
    Control = 0,
    /// Isochronous endpoint
    Isochronous = 1,
    /// Bulk endpoint
    Bulk = 2,
    /// Interrupt endpoint
    Interrupt = 3,
}

impl EndpointType {
    /// Create from endpoint descriptor attributes field
    pub fn from_attributes(attr: u8) -> Self {
        match attr & 0x03 {
            0 => EndpointType::Control,
            1 => EndpointType::Isochronous,
            2 => EndpointType::Bulk,
            3 => EndpointType::Interrupt,
            _ => unreachable!(),
        }
    }
}

/// USB transfer direction
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Host to device
    Out,
    /// Device to host
    In,
    /// Setup packet (control transfers)
    Setup,
}

// ============================================================================
// USB Setup Packet
// ============================================================================

/// USB Setup Packet (8 bytes)
///
/// Used for control transfers to send commands to USB devices.
/// All multi-byte fields are little-endian.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SetupPacket {
    /// Request type (direction, type, recipient)
    pub request_type: u8,
    /// Specific request
    pub request: u8,
    /// Value parameter (little-endian)
    pub value: u16,
    /// Index parameter (little-endian)
    pub index: u16,
    /// Number of bytes to transfer (little-endian)
    pub length: u16,
}

impl SetupPacket {
    /// Create a new setup packet
    pub const fn new(request_type: u8, request: u8, value: u16, index: u16, length: u16) -> Self {
        Self {
            request_type,
            request,
            value: value.to_le(),
            index: index.to_le(),
            length: length.to_le(),
        }
    }

    /// Get the packet as a byte slice for DMA transfers
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, 8) }
    }
}

// ============================================================================
// USB Descriptors
// ============================================================================

/// USB descriptor types
pub mod desc_type {
    pub const DEVICE: u8 = 1;
    pub const CONFIGURATION: u8 = 2;
    pub const STRING: u8 = 3;
    pub const INTERFACE: u8 = 4;
    pub const ENDPOINT: u8 = 5;
    pub const DEVICE_QUALIFIER: u8 = 6;
    pub const OTHER_SPEED_CONFIG: u8 = 7;
    pub const INTERFACE_POWER: u8 = 8;
    pub const OTG: u8 = 9;
    pub const DEBUG: u8 = 10;
    pub const INTERFACE_ASSOCIATION: u8 = 11;
    pub const HID: u8 = 0x21;
    pub const HID_REPORT: u8 = 0x22;
}

/// USB Device Descriptor (18 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct DeviceDescriptor {
    /// Size of this descriptor (18)
    pub length: u8,
    /// Descriptor type (1 = device)
    pub descriptor_type: u8,
    /// USB specification release number (BCD)
    pub bcd_usb: u16,
    /// Device class code
    pub device_class: u8,
    /// Device subclass code
    pub device_subclass: u8,
    /// Device protocol code
    pub device_protocol: u8,
    /// Maximum packet size for endpoint 0
    pub max_packet_size0: u8,
    /// Vendor ID
    pub vendor_id: u16,
    /// Product ID
    pub product_id: u16,
    /// Device release number (BCD)
    pub bcd_device: u16,
    /// Index of manufacturer string descriptor
    pub manufacturer: u8,
    /// Index of product string descriptor
    pub product: u8,
    /// Index of serial number string descriptor
    pub serial_number: u8,
    /// Number of configurations
    pub num_configurations: u8,
}

/// USB Configuration Descriptor (9 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct ConfigurationDescriptor {
    /// Size of this descriptor (9)
    pub length: u8,
    /// Descriptor type (2 = configuration)
    pub descriptor_type: u8,
    /// Total length of all descriptors for this configuration
    pub total_length: u16,
    /// Number of interfaces
    pub num_interfaces: u8,
    /// Configuration value for SET_CONFIGURATION
    pub configuration_value: u8,
    /// Index of string descriptor for this configuration
    pub configuration: u8,
    /// Attributes bitmap
    pub attributes: u8,
    /// Maximum power consumption (in 2mA units)
    pub max_power: u8,
}

/// USB Interface Descriptor (9 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct InterfaceDescriptor {
    /// Size of this descriptor (9)
    pub length: u8,
    /// Descriptor type (4 = interface)
    pub descriptor_type: u8,
    /// Interface number
    pub interface_number: u8,
    /// Alternate setting
    pub alternate_setting: u8,
    /// Number of endpoints
    pub num_endpoints: u8,
    /// Interface class code
    pub interface_class: u8,
    /// Interface subclass code
    pub interface_subclass: u8,
    /// Interface protocol code
    pub interface_protocol: u8,
    /// Index of string descriptor for this interface
    pub interface: u8,
}

/// USB Endpoint Descriptor (7 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct EndpointDescriptor {
    /// Size of this descriptor (7)
    pub length: u8,
    /// Descriptor type (5 = endpoint)
    pub descriptor_type: u8,
    /// Endpoint address (bit 7 = direction: 1=IN, 0=OUT)
    pub endpoint_address: u8,
    /// Attributes (bits 0-1 = transfer type)
    pub attributes: u8,
    /// Maximum packet size
    pub max_packet_size: u16,
    /// Polling interval (for interrupt/isochronous)
    pub interval: u8,
}

impl EndpointDescriptor {
    /// Get the endpoint number (0-15)
    pub fn endpoint_number(&self) -> u8 {
        self.endpoint_address & 0x0F
    }

    /// Check if this is an IN endpoint
    pub fn is_in(&self) -> bool {
        (self.endpoint_address & 0x80) != 0
    }

    /// Get the transfer type
    pub fn transfer_type(&self) -> EndpointType {
        EndpointType::from_attributes(self.attributes)
    }
}

/// HID Descriptor
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct HidDescriptor {
    /// Size of this descriptor
    pub length: u8,
    /// Descriptor type (0x21 = HID)
    pub descriptor_type: u8,
    /// HID specification release number (BCD)
    pub bcd_hid: u16,
    /// Country code
    pub country_code: u8,
    /// Number of class descriptors
    pub num_descriptors: u8,
    /// Class descriptor type (usually 0x22 = report)
    pub class_descriptor_type: u8,
    /// Class descriptor length
    pub class_descriptor_length: u16,
}

// ============================================================================
// USB Request Types and Standard Requests
// ============================================================================

/// USB request type fields
pub mod req_type {
    /// Direction: Host to Device
    pub const DIR_OUT: u8 = 0x00;
    /// Direction: Device to Host
    pub const DIR_IN: u8 = 0x80;

    /// Type: Standard
    pub const TYPE_STANDARD: u8 = 0x00;
    /// Type: Class
    pub const TYPE_CLASS: u8 = 0x20;
    /// Type: Vendor
    pub const TYPE_VENDOR: u8 = 0x40;

    /// Recipient: Device
    pub const RCPT_DEVICE: u8 = 0x00;
    /// Recipient: Interface
    pub const RCPT_INTERFACE: u8 = 0x01;
    /// Recipient: Endpoint
    pub const RCPT_ENDPOINT: u8 = 0x02;
    /// Recipient: Other
    pub const RCPT_OTHER: u8 = 0x03;
}

/// USB standard requests
pub mod request {
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
    pub const SYNCH_FRAME: u8 = 0x0C;
}

/// USB HID class requests
pub mod hid_request {
    pub const GET_REPORT: u8 = 0x01;
    pub const GET_IDLE: u8 = 0x02;
    pub const GET_PROTOCOL: u8 = 0x03;
    pub const SET_REPORT: u8 = 0x09;
    pub const SET_IDLE: u8 = 0x0A;
    pub const SET_PROTOCOL: u8 = 0x0B;
}

// ============================================================================
// USB Hub Class Support
// ============================================================================

/// USB Hub descriptor (USB 2.0 Section 11.23.2.1)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HubDescriptor {
    /// Descriptor length
    pub length: u8,
    /// Descriptor type (0x29 for hub)
    pub descriptor_type: u8,
    /// Number of downstream facing ports
    pub num_ports: u8,
    /// Hub characteristics (power switching, compound device, etc.)
    pub characteristics: u16,
    /// Time from power-on to power-good (in 2ms units)
    pub power_on_to_power_good: u8,
    /// Maximum current requirements of the hub controller
    pub hub_controller_current: u8,
    // DeviceRemovable and PortPwrCtrlMask bitmaps follow (variable length)
}

/// Hub descriptor type (class-specific)
pub const HUB_DESCRIPTOR_TYPE: u8 = 0x29;

/// Hub port features for SET_FEATURE/CLEAR_FEATURE
pub mod hub_feature {
    /// Port connection status (read-only)
    pub const PORT_CONNECTION: u16 = 0;
    /// Port enable/disable
    pub const PORT_ENABLE: u16 = 1;
    /// Port suspend
    pub const PORT_SUSPEND: u16 = 2;
    /// Port over-current indicator (read-only)
    pub const PORT_OVER_CURRENT: u16 = 3;
    /// Port reset
    pub const PORT_RESET: u16 = 4;
    /// Port power
    pub const PORT_POWER: u16 = 8;
    /// Port low-speed device attached (read-only)
    pub const PORT_LOW_SPEED: u16 = 9;
    /// Connection change (clear only)
    pub const C_PORT_CONNECTION: u16 = 16;
    /// Enable change (clear only)
    pub const C_PORT_ENABLE: u16 = 17;
    /// Suspend change (clear only)
    pub const C_PORT_SUSPEND: u16 = 18;
    /// Over-current change (clear only)
    pub const C_PORT_OVER_CURRENT: u16 = 19;
    /// Reset change (clear only)
    pub const C_PORT_RESET: u16 = 20;
}

/// Hub port status bits (from GET_STATUS)
pub mod hub_port_status {
    /// Device is connected
    pub const CONNECTION: u16 = 1 << 0;
    /// Port is enabled
    pub const ENABLE: u16 = 1 << 1;
    /// Port is suspended
    pub const SUSPEND: u16 = 1 << 2;
    /// Over-current condition
    pub const OVER_CURRENT: u16 = 1 << 3;
    /// Port reset active
    pub const RESET: u16 = 1 << 4;
    /// Port power is on
    pub const POWER: u16 = 1 << 8;
    /// Attached device is low-speed
    pub const LOW_SPEED: u16 = 1 << 9;
    /// Attached device is high-speed
    pub const HIGH_SPEED: u16 = 1 << 10;
}

/// Hub port status change bits (upper 16 bits of GET_STATUS)
pub mod hub_port_change {
    /// Connection status changed
    pub const C_CONNECTION: u16 = 1 << 0;
    /// Enable status changed
    pub const C_ENABLE: u16 = 1 << 1;
    /// Suspend status changed
    pub const C_SUSPEND: u16 = 1 << 2;
    /// Over-current status changed
    pub const C_OVER_CURRENT: u16 = 1 << 3;
    /// Reset complete
    pub const C_RESET: u16 = 1 << 4;
}

/// USB device class codes
pub mod class {
    /// Use class info in Interface Descriptor
    pub const INTERFACE: u8 = 0x00;
    /// Audio
    pub const AUDIO: u8 = 0x01;
    /// Communications and CDC Control
    pub const CDC: u8 = 0x02;
    /// Human Interface Device
    pub const HID: u8 = 0x03;
    /// Physical
    pub const PHYSICAL: u8 = 0x05;
    /// Image
    pub const IMAGE: u8 = 0x06;
    /// Printer
    pub const PRINTER: u8 = 0x07;
    /// Mass Storage
    pub const MASS_STORAGE: u8 = 0x08;
    /// Hub
    pub const HUB: u8 = 0x09;
    /// CDC-Data
    pub const CDC_DATA: u8 = 0x0A;
    /// Smart Card
    pub const SMART_CARD: u8 = 0x0B;
    /// Content Security
    pub const CONTENT_SECURITY: u8 = 0x0D;
    /// Video
    pub const VIDEO: u8 = 0x0E;
    /// Personal Healthcare
    pub const HEALTHCARE: u8 = 0x0F;
    /// Diagnostic Device
    pub const DIAGNOSTIC: u8 = 0xDC;
    /// Wireless Controller
    pub const WIRELESS: u8 = 0xE0;
    /// Miscellaneous
    pub const MISC: u8 = 0xEF;
    /// Application Specific
    pub const APPLICATION: u8 = 0xFE;
    /// Vendor Specific
    pub const VENDOR: u8 = 0xFF;
}

// ============================================================================
// USB Endpoint Info
// ============================================================================

/// Information about a USB endpoint
#[derive(Clone, Copy, Debug)]
pub struct EndpointInfo {
    /// Endpoint number (0-15)
    pub number: u8,
    /// Transfer direction
    pub direction: Direction,
    /// Transfer type
    pub transfer_type: EndpointType,
    /// Maximum packet size
    pub max_packet_size: u16,
    /// Polling interval (for interrupt endpoints)
    pub interval: u8,
    /// Current data toggle state
    pub toggle: bool,
}

impl EndpointInfo {
    /// Create from endpoint descriptor
    pub fn from_descriptor(desc: &EndpointDescriptor) -> Self {
        Self {
            number: desc.endpoint_number(),
            direction: if desc.is_in() {
                Direction::In
            } else {
                Direction::Out
            },
            transfer_type: desc.transfer_type(),
            max_packet_size: desc.max_packet_size,
            interval: desc.interval,
            toggle: false,
        }
    }

    /// Create a control endpoint 0
    pub fn control_ep0(max_packet_size: u16) -> Self {
        Self {
            number: 0,
            direction: Direction::Setup,
            transfer_type: EndpointType::Control,
            max_packet_size,
            interval: 0,
            toggle: false,
        }
    }
}

// ============================================================================
// USB Controller Trait
// ============================================================================

/// USB controller error types
#[derive(Debug, Clone, Copy)]
pub enum UsbError {
    /// Controller not ready
    NotReady,
    /// Operation timed out
    Timeout,
    /// No free device slots
    NoFreeSlots,
    /// Command failed with completion code
    CommandFailed(u32),
    /// Memory allocation failed
    AllocationFailed,
    /// Device not found
    DeviceNotFound,
    /// Transfer failed with completion code
    TransferFailed(u32),
    /// Invalid parameter
    InvalidParameter,
    /// USB transaction error
    TransactionError,
    /// Endpoint stalled
    Stall,
    /// Data toggle mismatch
    ToggleError,
    /// CRC error
    CrcError,
    /// Babble detected
    Babble,
    /// NAK (device busy)
    Nak,
    /// Device disconnected
    Disconnected,
}

/// USB device handle - identifies a device on a controller
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbDeviceHandle {
    /// Controller index
    pub controller: u8,
    /// Device address or slot ID
    pub address: u8,
}

/// Trait for USB host controller drivers
///
/// This trait abstracts the differences between xHCI, EHCI, OHCI, and UHCI
/// controllers, allowing device class drivers to work with any controller type.
pub trait UsbController {
    /// Get the controller type name (for debugging)
    fn controller_type(&self) -> &'static str;

    /// Perform a control transfer
    ///
    /// # Arguments
    /// * `device` - Device address/slot ID
    /// * `request_type` - Request type byte (direction, type, recipient)
    /// * `request` - Request code
    /// * `value` - wValue field
    /// * `index` - wIndex field
    /// * `data` - Optional data buffer (IN or OUT depending on request_type)
    ///
    /// # Returns
    /// Number of bytes transferred on success
    fn control_transfer(
        &mut self,
        device: u8,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: Option<&mut [u8]>,
    ) -> Result<usize, UsbError>;

    /// Perform a bulk transfer
    ///
    /// # Arguments
    /// * `device` - Device address/slot ID
    /// * `endpoint` - Endpoint number (without direction bit)
    /// * `is_in` - True for IN transfer, false for OUT
    /// * `data` - Data buffer
    ///
    /// # Returns
    /// Number of bytes transferred on success
    fn bulk_transfer(
        &mut self,
        device: u8,
        endpoint: u8,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<usize, UsbError>;

    /// Create an interrupt transfer queue
    ///
    /// # Arguments
    /// * `device` - Device address/slot ID
    /// * `endpoint` - Endpoint number
    /// * `is_in` - True for IN endpoint
    /// * `max_packet` - Maximum packet size
    /// * `interval` - Polling interval
    ///
    /// # Returns
    /// Queue handle on success
    fn create_interrupt_queue(
        &mut self,
        device: u8,
        endpoint: u8,
        is_in: bool,
        max_packet: u16,
        interval: u8,
    ) -> Result<u32, UsbError>;

    /// Poll an interrupt queue for data
    ///
    /// # Arguments
    /// * `queue` - Queue handle from create_interrupt_queue
    /// * `data` - Buffer to receive data
    ///
    /// # Returns
    /// Number of bytes received, or None if no data available
    fn poll_interrupt_queue(&mut self, queue: u32, data: &mut [u8]) -> Option<usize>;

    /// Destroy an interrupt queue
    fn destroy_interrupt_queue(&mut self, queue: u32);

    /// Find a mass storage device
    ///
    /// # Returns
    /// Device address/slot ID if found
    fn find_mass_storage(&self) -> Option<u8>;

    /// Find a HID keyboard device
    ///
    /// # Returns
    /// Device address/slot ID if found
    fn find_hid_keyboard(&self) -> Option<u8>;

    /// Get device info
    fn get_device_info(&self, device: u8) -> Option<DeviceInfo>;

    /// Get bulk endpoint info for a device
    fn get_bulk_endpoints(&self, device: u8) -> Option<(EndpointInfo, EndpointInfo)>;

    /// Get interrupt endpoint info for a device
    fn get_interrupt_endpoint(&self, device: u8) -> Option<EndpointInfo>;
}

/// Device information
#[derive(Clone, Debug)]
pub struct DeviceInfo {
    /// USB device address
    pub address: u8,
    /// Device speed
    pub speed: UsbSpeed,
    /// Vendor ID
    pub vendor_id: u16,
    /// Product ID
    pub product_id: u16,
    /// Device class
    pub device_class: u8,
    /// Is this a mass storage device?
    pub is_mass_storage: bool,
    /// Is this a HID device?
    pub is_hid: bool,
    /// Is this a keyboard?
    pub is_keyboard: bool,
    /// Is this a hub?
    pub is_hub: bool,
}

// ============================================================================
// Common USB Device State
// ============================================================================

/// Common USB device state shared across EHCI/OHCI/UHCI controllers
///
/// This struct contains all the device information that is common to USB 1.1/2.0
/// host controllers. xHCI uses a different model (slots) but can embed this
/// for the device-level information.
#[derive(Clone)]
pub struct UsbDevice {
    /// Device address (1-127, 0 = default address before SET_ADDRESS)
    pub address: u8,
    /// Port number (0-based)
    pub port: u8,
    /// Device speed
    pub speed: UsbSpeed,
    /// Device descriptor
    pub device_desc: DeviceDescriptor,
    /// Configuration info (parsed from configuration descriptor)
    pub config_info: ConfigurationInfo,
    /// Is mass storage device
    pub is_mass_storage: bool,
    /// Is HID keyboard
    pub is_hid_keyboard: bool,
    /// Is USB hub
    pub is_hub: bool,
    /// Number of hub ports (if is_hub)
    pub num_hub_ports: u8,
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
    /// Hub address for split transactions (0 = directly connected to root hub)
    pub hub_addr: u8,
    /// Hub port for split transactions (1-based, 0 = root hub)
    pub hub_port: u8,
}

impl UsbDevice {
    /// Create a new device with default state
    pub fn new(address: u8, port: u8, speed: UsbSpeed) -> Self {
        Self {
            address,
            port,
            speed,
            device_desc: DeviceDescriptor::default(),
            config_info: ConfigurationInfo::default(),
            is_mass_storage: false,
            is_hid_keyboard: false,
            is_hub: false,
            num_hub_ports: 0,
            bulk_in: None,
            bulk_out: None,
            interrupt_in: None,
            ep0_max_packet: speed.default_max_packet_size(),
            bulk_in_toggle: false,
            bulk_out_toggle: false,
            hub_addr: 0,
            hub_port: 0,
        }
    }

    /// Create a device connected through a hub
    pub fn new_on_hub(address: u8, port: u8, speed: UsbSpeed, hub_addr: u8, hub_port: u8) -> Self {
        let mut device = Self::new(address, port, speed);
        device.hub_addr = hub_addr;
        device.hub_port = hub_port;
        device
    }

    /// Get DeviceInfo for this device
    pub fn device_info(&self) -> DeviceInfo {
        DeviceInfo {
            address: self.address,
            speed: self.speed,
            vendor_id: self.device_desc.vendor_id,
            product_id: self.device_desc.product_id,
            device_class: self.device_desc.device_class,
            is_mass_storage: self.is_mass_storage,
            is_hid: self.is_hid_keyboard,
            is_keyboard: self.is_hid_keyboard,
            is_hub: self.is_hub,
        }
    }
}

// ============================================================================
// Interrupt Queue Management
// ============================================================================

/// Interrupt transfer queue entry
pub struct InterruptQueue {
    /// Device address
    pub device: u8,
    /// Endpoint number
    pub endpoint: u8,
    /// Is IN endpoint
    pub is_in: bool,
    /// Max packet size
    pub max_packet: u16,
    /// Buffer for received data
    pub buffer: *mut u8,
    /// Buffer size
    pub buffer_size: usize,
    /// Number of buffers
    pub num_buffers: usize,
    /// Current read index
    pub read_index: usize,
    /// Current write index
    pub write_index: usize,
    /// Controller-specific data
    pub controller_data: u64,
}

// SAFETY: InterruptQueue contains a raw pointer to a DMA-accessible buffer allocated
// via the EFI page allocator. This buffer:
// 1. Remains valid until the queue is explicitly destroyed
// 2. Is only accessed through the owning USB controller which serializes access
// 3. Contains data that may be written by hardware DMA, but firmware only reads
//    after checking completion status
// The firmware is single-threaded and interrupt queues are accessed serially.
unsafe impl Send for InterruptQueue {}

impl InterruptQueue {
    /// Allocate a new interrupt queue
    pub fn new(
        device: u8,
        endpoint: u8,
        is_in: bool,
        max_packet: u16,
        num_buffers: usize,
    ) -> Option<Self> {
        let buffer_size = max_packet as usize * num_buffers;
        let pages = buffer_size.div_ceil(4096);
        let buffer_mem = efi::allocate_pages(pages as u64)?;
        buffer_mem.fill(0);
        let buffer = buffer_mem.as_mut_ptr();

        Some(Self {
            device,
            endpoint,
            is_in,
            max_packet,
            buffer,
            buffer_size: max_packet as usize,
            num_buffers,
            read_index: 0,
            write_index: 0,
            controller_data: 0,
        })
    }

    /// Get current buffer for writing
    pub fn write_buffer(&mut self) -> &mut [u8] {
        let offset = self.write_index * self.buffer_size;
        unsafe { core::slice::from_raw_parts_mut(self.buffer.add(offset), self.buffer_size) }
    }

    /// Advance write pointer
    pub fn advance_write(&mut self) {
        self.write_index = (self.write_index + 1) % self.num_buffers;
    }

    /// Check if data is available
    pub fn has_data(&self) -> bool {
        self.read_index != self.write_index
    }

    /// Read data from queue
    pub fn read(&mut self, dest: &mut [u8]) -> Option<usize> {
        if !self.has_data() {
            return None;
        }

        let offset = self.read_index * self.buffer_size;
        let len = dest.len().min(self.buffer_size);
        unsafe {
            ptr::copy_nonoverlapping(self.buffer.add(offset), dest.as_mut_ptr(), len);
        }
        self.read_index = (self.read_index + 1) % self.num_buffers;
        Some(len)
    }
}

// ============================================================================
// Configuration Descriptor Parser
// ============================================================================

/// Iterator over descriptors in a configuration
pub struct DescriptorIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> DescriptorIterator<'a> {
    /// Create a new iterator over configuration descriptor data
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

impl<'a> Iterator for DescriptorIterator<'a> {
    type Item = (u8, &'a [u8]); // (descriptor_type, descriptor_data)

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        let len = self.data[self.offset] as usize;
        if len < 2 || self.offset + len > self.data.len() {
            return None;
        }

        let desc_type = self.data[self.offset + 1];
        let desc_data = &self.data[self.offset..self.offset + len];
        self.offset += len;

        Some((desc_type, desc_data))
    }
}

/// Parse configuration descriptor to find interfaces and endpoints
pub fn parse_configuration(config_data: &[u8]) -> ConfigurationInfo {
    let mut info = ConfigurationInfo::default();

    if config_data.len() < 9 {
        return info;
    }

    let config =
        unsafe { ptr::read_unaligned(config_data.as_ptr() as *const ConfigurationDescriptor) };
    info.configuration_value = config.configuration_value;

    let mut current_interface: Option<InterfaceInfo> = None;

    for (desc_type, desc_data) in DescriptorIterator::new(config_data) {
        match desc_type {
            desc_type::INTERFACE => {
                // Save previous interface if any
                if let Some(iface) = current_interface.take()
                    && info.num_interfaces < 8
                {
                    info.interfaces[info.num_interfaces] = iface;
                    info.num_interfaces += 1;
                }

                if desc_data.len() >= 9 {
                    let iface = unsafe {
                        ptr::read_unaligned(desc_data.as_ptr() as *const InterfaceDescriptor)
                    };
                    current_interface = Some(InterfaceInfo {
                        interface_number: iface.interface_number,
                        alternate_setting: iface.alternate_setting,
                        interface_class: iface.interface_class,
                        interface_subclass: iface.interface_subclass,
                        interface_protocol: iface.interface_protocol,
                        endpoints: [EndpointInfo::control_ep0(8); 4],
                        num_endpoints: 0,
                    });
                }
            }
            desc_type::ENDPOINT => {
                if let Some(ref mut iface) = current_interface
                    && desc_data.len() >= 7
                    && iface.num_endpoints < 4
                {
                    let ep = unsafe {
                        ptr::read_unaligned(desc_data.as_ptr() as *const EndpointDescriptor)
                    };
                    iface.endpoints[iface.num_endpoints] = EndpointInfo::from_descriptor(&ep);
                    iface.num_endpoints += 1;
                }
            }
            _ => {}
        }
    }

    // Save last interface
    if let Some(iface) = current_interface
        && info.num_interfaces < 8
    {
        info.interfaces[info.num_interfaces] = iface;
        info.num_interfaces += 1;
    }

    info
}

/// Parsed configuration information
#[derive(Clone, Default)]
pub struct ConfigurationInfo {
    pub configuration_value: u8,
    pub interfaces: [InterfaceInfo; 8],
    pub num_interfaces: usize,
}

/// Parsed interface information
#[derive(Clone, Copy)]
pub struct InterfaceInfo {
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub endpoints: [EndpointInfo; 4],
    pub num_endpoints: usize,
}

impl Default for InterfaceInfo {
    fn default() -> Self {
        Self {
            interface_number: 0,
            alternate_setting: 0,
            interface_class: 0,
            interface_subclass: 0,
            interface_protocol: 0,
            endpoints: [EndpointInfo::control_ep0(8); 4],
            num_endpoints: 0,
        }
    }
}

impl InterfaceInfo {
    /// Check if this is a mass storage interface (BBB protocol)
    pub fn is_mass_storage(&self) -> bool {
        self.interface_class == class::MASS_STORAGE && self.interface_protocol == 0x50
    }

    /// Check if this is a HID keyboard interface
    pub fn is_hid_keyboard(&self) -> bool {
        self.interface_class == class::HID
            && self.interface_subclass == 0x01 // Boot interface
            && self.interface_protocol == 0x01 // Keyboard
    }

    /// Find bulk IN endpoint
    pub fn find_bulk_in(&self) -> Option<&EndpointInfo> {
        self.endpoints[..self.num_endpoints]
            .iter()
            .find(|ep| ep.transfer_type == EndpointType::Bulk && ep.direction == Direction::In)
    }

    /// Find bulk OUT endpoint
    pub fn find_bulk_out(&self) -> Option<&EndpointInfo> {
        self.endpoints[..self.num_endpoints]
            .iter()
            .find(|ep| ep.transfer_type == EndpointType::Bulk && ep.direction == Direction::Out)
    }

    /// Find interrupt IN endpoint
    pub fn find_interrupt_in(&self) -> Option<&EndpointInfo> {
        self.endpoints[..self.num_endpoints]
            .iter()
            .find(|ep| ep.transfer_type == EndpointType::Interrupt && ep.direction == Direction::In)
    }
}

// ============================================================================
// Device Enumeration Helper
// ============================================================================

/// Helper for enumerating a newly connected USB device
///
/// This function handles the common device enumeration sequence used by all
/// USB host controllers (EHCI, OHCI, UHCI). It performs the following steps:
///
/// 1. Get initial 8-byte device descriptor to discover EP0 max packet size
/// 2. Assign a device address (SET_ADDRESS)
/// 3. Get full device descriptor
/// 4. Get configuration descriptor
/// 5. Parse configuration to find interfaces and endpoints
/// 6. Set configuration
///
/// # Arguments
/// * `device` - Pre-created UsbDevice with address=0 and appropriate speed
/// * `address` - The device address to assign
/// * `do_control` - Callback to perform a control transfer
///
/// # Returns
/// The fully enumerated UsbDevice on success, or an error
pub fn enumerate_device<F>(
    mut device: UsbDevice,
    address: u8,
    mut do_control: F,
) -> Result<UsbDevice, UsbError>
where
    F: FnMut(&UsbDevice, u8, u8, u16, u16, Option<&mut [u8]>) -> Result<usize, UsbError>,
{
    if address >= 128 {
        return Err(UsbError::NoFreeSlots);
    }

    // Step 1: Get initial device descriptor (first 8 bytes) to learn EP0 max packet size
    let mut desc_buf = [0u8; 8];
    do_control(
        &device,
        req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
        request::GET_DESCRIPTOR,
        (desc_type::DEVICE as u16) << 8,
        0,
        Some(&mut desc_buf),
    )?;

    device.ep0_max_packet = desc_buf[7].max(8) as u16;

    // Step 2: Set address
    do_control(
        &device,
        req_type::DIR_OUT | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
        request::SET_ADDRESS,
        address as u16,
        0,
        None,
    )?;

    crate::time::delay_ms(2);
    device.address = address;

    // Step 3: Get full device descriptor (18 bytes)
    let mut desc_buf = [0u8; 18];
    do_control(
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
    log::info!("  Device {}: VID={:04x} PID={:04x}", address, vid, pid);

    // Step 4: Get configuration descriptor
    let mut config_buf = [0u8; 256];
    let mut header = [0u8; 9];

    do_control(
        &device,
        req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
        request::GET_DESCRIPTOR,
        (desc_type::CONFIGURATION as u16) << 8,
        0,
        Some(&mut header),
    )?;

    let total_len = u16::from_le_bytes([header[2], header[3]]) as usize;
    let total_len = total_len.min(config_buf.len());

    do_control(
        &device,
        req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
        request::GET_DESCRIPTOR,
        (desc_type::CONFIGURATION as u16) << 8,
        0,
        Some(&mut config_buf[..total_len]),
    )?;

    // Step 5: Parse configuration
    device.config_info = parse_configuration(&config_buf[..total_len]);

    // Check if this is a hub (device class)
    if device.device_desc.device_class == class::HUB {
        device.is_hub = true;
        log::info!("    USB Hub detected");
    }

    // Find interfaces and their endpoints
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

    // Step 6: Set configuration
    if device.config_info.configuration_value > 0 {
        do_control(
            &device,
            req_type::DIR_OUT | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::SET_CONFIGURATION,
            device.config_info.configuration_value as u16,
            0,
            None,
        )?;
    }

    Ok(device)
}
