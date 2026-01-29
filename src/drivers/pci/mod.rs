//! PCI/PCIe enumeration and configuration
//!
//! This module provides PCI device enumeration and configuration space access.
//! It supports both legacy I/O port-based access (CAM) and memory-mapped access (ECAM).

use heapless::Vec;

use crate::state;

#[cfg(target_arch = "x86_64")]
use x86_64::instructions::port::{Port, PortWriteOnly};

/// Maximum number of PCI devices we can track
const MAX_PCI_DEVICES: usize = 64;

/// PCI configuration space ports (legacy CAM)
const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// PCI class codes for storage controllers
pub const CLASS_STORAGE: u8 = 0x01;
pub const SUBCLASS_SCSI: u8 = 0x00;
pub const SUBCLASS_IDE: u8 = 0x01;
pub const SUBCLASS_FLOPPY: u8 = 0x02;
pub const SUBCLASS_IPI: u8 = 0x03;
pub const SUBCLASS_RAID: u8 = 0x04;
pub const SUBCLASS_ATA: u8 = 0x05;
pub const SUBCLASS_SATA: u8 = 0x06; // AHCI
pub const SUBCLASS_SAS: u8 = 0x07;
pub const SUBCLASS_NVME: u8 = 0x08; // NVMe

/// PCI class codes for other device types
pub const CLASS_NETWORK: u8 = 0x02;
pub const CLASS_DISPLAY: u8 = 0x03;
pub const CLASS_MULTIMEDIA: u8 = 0x04;
pub const CLASS_MEMORY: u8 = 0x05;
pub const CLASS_BRIDGE: u8 = 0x06;
pub const CLASS_SERIAL: u8 = 0x0C;

/// Invalid vendor ID (no device present)
const INVALID_VENDOR_ID: u16 = 0xFFFF;

/// PCI header types
const HEADER_TYPE_NORMAL: u8 = 0x00;
#[allow(dead_code)]
const HEADER_TYPE_BRIDGE: u8 = 0x01;
#[allow(dead_code)]
const HEADER_TYPE_CARDBUS: u8 = 0x02;
const HEADER_TYPE_MULTI_FUNCTION: u8 = 0x80;

/// PCI device location (Bus:Device.Function)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    /// Calculate legacy CAM address for a register
    fn cam_address(&self, offset: u8) -> u32 {
        let mut addr = 1u32 << 31; // Enable bit
        addr |= (self.bus as u32) << 16;
        addr |= (self.device as u32) << 11;
        addr |= (self.function as u32) << 8;
        addr |= (offset as u32) & 0xFC; // Must be 4-byte aligned
        addr
    }
}

impl core::fmt::Display for PciAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.bus, self.device, self.function)
    }
}

/// PCI BAR type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BarType {
    #[default]
    Unused,
    Memory32,
    Memory64,
    Io,
}

/// PCI Base Address Register
#[derive(Debug, Clone, Copy, Default)]
pub struct PciBar {
    pub bar_type: BarType,
    pub address: u64,
    pub size: u64,
    pub prefetchable: bool,
}

/// PCI device information
#[derive(Debug, Clone)]
pub struct PciDevice {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub header_type: u8,
    pub bars: [PciBar; 6],
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
}

impl PciDevice {
    /// Create a new PCI device with default values
    fn new(address: PciAddress) -> Self {
        Self {
            address,
            vendor_id: 0,
            device_id: 0,
            class_code: 0,
            subclass: 0,
            prog_if: 0,
            revision: 0,
            header_type: 0,
            bars: [PciBar::default(); 6],
            interrupt_line: 0,
            interrupt_pin: 0,
        }
    }

    /// Check if this is an NVMe controller
    pub fn is_nvme(&self) -> bool {
        self.class_code == CLASS_STORAGE && self.subclass == SUBCLASS_NVME
    }

    /// Check if this is an AHCI controller
    pub fn is_ahci(&self) -> bool {
        self.class_code == CLASS_STORAGE && self.subclass == SUBCLASS_SATA
    }

    /// Get the MMIO base address for the device (typically BAR0)
    pub fn mmio_base(&self) -> Option<u64> {
        for bar in &self.bars {
            if matches!(bar.bar_type, BarType::Memory32 | BarType::Memory64) {
                return Some(bar.address);
            }
        }
        None
    }

    /// Get the I/O base address for the device
    ///
    /// This is used by controllers like UHCI that use I/O ports instead of MMIO.
    pub fn io_base(&self) -> Option<u64> {
        for bar in &self.bars {
            if bar.bar_type == BarType::Io {
                return Some(bar.address);
            }
        }
        None
    }

    /// Check if this is a USB host controller
    pub fn is_usb_controller(&self) -> bool {
        self.class_code == CLASS_SERIAL && self.subclass == 0x03
    }
}

/// Read a 32-bit value from PCI configuration space using legacy I/O
#[cfg(target_arch = "x86_64")]
fn pci_read_config_u32(addr: PciAddress, offset: u8) -> u32 {
    let mut address_port: PortWriteOnly<u32> = PortWriteOnly::new(PCI_CONFIG_ADDRESS);
    let mut data_port: Port<u32> = Port::new(PCI_CONFIG_DATA);

    unsafe {
        address_port.write(addr.cam_address(offset));
        data_port.read()
    }
}

/// Write a 32-bit value to PCI configuration space using legacy I/O
#[cfg(target_arch = "x86_64")]
fn pci_write_config_u32(addr: PciAddress, offset: u8, value: u32) {
    let mut address_port: PortWriteOnly<u32> = PortWriteOnly::new(PCI_CONFIG_ADDRESS);
    let mut data_port: Port<u32> = Port::new(PCI_CONFIG_DATA);

    unsafe {
        address_port.write(addr.cam_address(offset));
        data_port.write(value);
    }
}

/// Read a 16-bit value from PCI configuration space
#[cfg(target_arch = "x86_64")]
fn pci_read_config_u16(addr: PciAddress, offset: u8) -> u16 {
    let aligned_offset = offset & 0xFC;
    let shift = (offset & 0x02) * 8;
    let value = pci_read_config_u32(addr, aligned_offset);
    ((value >> shift) & 0xFFFF) as u16
}

/// Read an 8-bit value from PCI configuration space
#[cfg(target_arch = "x86_64")]
fn pci_read_config_u8(addr: PciAddress, offset: u8) -> u8 {
    let aligned_offset = offset & 0xFC;
    let shift = (offset & 0x03) * 8;
    let value = pci_read_config_u32(addr, aligned_offset);
    ((value >> shift) & 0xFF) as u8
}

/// Get vendor and device ID for a PCI address
fn get_device_ids(addr: PciAddress) -> (u16, u16) {
    let data = pci_read_config_u32(addr, 0x00);
    ((data & 0xFFFF) as u16, (data >> 16) as u16)
}

/// Probe a single BAR and return its type, address, and size
fn probe_bar(addr: PciAddress, bar_index: usize) -> PciBar {
    let bar_offset = (0x10 + bar_index * 4) as u8;
    let original = pci_read_config_u32(addr, bar_offset);

    // Empty BAR
    if original == 0 {
        return PciBar::default();
    }

    // Check if it's I/O or memory
    if original & 1 == 1 {
        // I/O BAR
        pci_write_config_u32(addr, bar_offset, 0xFFFFFFFF);
        let sized = pci_read_config_u32(addr, bar_offset);
        pci_write_config_u32(addr, bar_offset, original);

        let io_mask = sized | 0x3;
        let size = (!io_mask).wrapping_add(1) as u64;

        return PciBar {
            bar_type: BarType::Io,
            address: (original & 0xFFFFFFFC) as u64,
            size,
            prefetchable: false,
        };
    }

    // Memory BAR - check type (bits 2:1)
    let mem_type = (original >> 1) & 0x3;
    let prefetchable = (original & 0x8) != 0;

    match mem_type {
        0 => {
            // 32-bit memory
            pci_write_config_u32(addr, bar_offset, 0xFFFFFFFF);
            let sized = pci_read_config_u32(addr, bar_offset);
            pci_write_config_u32(addr, bar_offset, original);

            let mem_mask = sized | 0xF;
            let size = (!mem_mask).wrapping_add(1) as u64;

            PciBar {
                bar_type: BarType::Memory32,
                address: (original & 0xFFFFFFF0) as u64,
                size,
                prefetchable,
            }
        }
        2 => {
            // 64-bit memory (consumes two BARs)
            let bar_offset_hi = bar_offset + 4;
            let original_hi = pci_read_config_u32(addr, bar_offset_hi);

            pci_write_config_u32(addr, bar_offset, 0xFFFFFFFF);
            pci_write_config_u32(addr, bar_offset_hi, 0xFFFFFFFF);
            let sized_lo = pci_read_config_u32(addr, bar_offset);
            let sized_hi = pci_read_config_u32(addr, bar_offset_hi);
            pci_write_config_u32(addr, bar_offset, original);
            pci_write_config_u32(addr, bar_offset_hi, original_hi);

            let sized = ((sized_hi as u64) << 32) | (sized_lo as u64);
            let mem_mask = sized | 0xF;
            let size = (!mem_mask).wrapping_add(1);

            let address = ((original_hi as u64) << 32) | ((original & 0xFFFFFFF0) as u64);

            PciBar {
                bar_type: BarType::Memory64,
                address,
                size,
                prefetchable,
            }
        }
        _ => PciBar::default(),
    }
}

/// Scan a single device/function and add to device list if valid
fn scan_device(bus: u8, device: u8, function: u8) -> Option<PciDevice> {
    let addr = PciAddress::new(bus, device, function);
    let (vendor_id, device_id) = get_device_ids(addr);

    if vendor_id == INVALID_VENDOR_ID {
        return None;
    }

    let mut dev = PciDevice::new(addr);
    dev.vendor_id = vendor_id;
    dev.device_id = device_id;

    // Read class/subclass/prog_if/revision (offset 0x08)
    let class_data = pci_read_config_u32(addr, 0x08);
    dev.revision = (class_data & 0xFF) as u8;
    dev.prog_if = ((class_data >> 8) & 0xFF) as u8;
    dev.subclass = ((class_data >> 16) & 0xFF) as u8;
    dev.class_code = ((class_data >> 24) & 0xFF) as u8;

    // Read header type (offset 0x0C, bits 16-23)
    let header_data = pci_read_config_u32(addr, 0x0C);
    dev.header_type = ((header_data >> 16) & 0xFF) as u8;

    // Read interrupt info (offset 0x3C)
    let irq_data = pci_read_config_u32(addr, 0x3C);
    dev.interrupt_line = (irq_data & 0xFF) as u8;
    dev.interrupt_pin = ((irq_data >> 8) & 0xFF) as u8;

    // Only scan BARs for normal (type 0) headers
    if (dev.header_type & 0x7F) == HEADER_TYPE_NORMAL {
        let mut bar_index = 0;
        while bar_index < 6 {
            let bar = probe_bar(addr, bar_index);
            dev.bars[bar_index] = bar;

            // 64-bit BARs consume two slots
            if bar.bar_type == BarType::Memory64 {
                bar_index += 2;
            } else {
                bar_index += 1;
            }
        }
    }

    Some(dev)
}

/// Enable bus mastering, memory space, and I/O space for a device
pub fn enable_device(dev: &PciDevice) {
    let cmd = pci_read_config_u16(dev.address, 0x04);
    // Set bit 0 (I/O space), bit 1 (memory space) and bit 2 (bus master)
    let new_cmd = cmd | 0x07;

    let aligned_offset = 0x04 & 0xFC;
    let current = pci_read_config_u32(dev.address, aligned_offset as u8);
    let new_value = (current & 0xFFFF0000) | (new_cmd as u32);
    pci_write_config_u32(dev.address, aligned_offset as u8, new_value);

    log::debug!(
        "Enabled device {}: cmd {:#06x} -> {:#06x}",
        dev.address,
        cmd,
        new_cmd
    );
}

/// Initialize PCI subsystem and enumerate all devices
pub fn init() {
    log::info!("Initializing PCI subsystem...");

    state::with_drivers_mut(|drivers| {
        let devices = &mut drivers.pci_devices;
        devices.clear();
        init_inner(devices);
    });
}

/// Inner initialization that works with a mutable reference to devices
fn init_inner(devices: &mut heapless::Vec<PciDevice, { state::MAX_PCI_DEVICES }>) {
    // Scan all buses, devices, and functions
    for bus in 0..=255u8 {
        for device in 0..32u8 {
            // First check function 0
            if let Some(dev) = scan_device(bus, device, 0) {
                let is_multi_function = (dev.header_type & HEADER_TYPE_MULTI_FUNCTION) != 0;

                log::debug!(
                    "PCI {}: {:04x}:{:04x} class={:02x}:{:02x}",
                    dev.address,
                    dev.vendor_id,
                    dev.device_id,
                    dev.class_code,
                    dev.subclass
                );

                if devices.push(dev).is_err() {
                    log::warn!("PCI device list full!");
                    return;
                }

                // Check other functions if multi-function
                if is_multi_function {
                    for function in 1..8u8 {
                        if let Some(dev) = scan_device(bus, device, function) {
                            log::debug!(
                                "PCI {}: {:04x}:{:04x} class={:02x}:{:02x}",
                                dev.address,
                                dev.vendor_id,
                                dev.device_id,
                                dev.class_code,
                                dev.subclass
                            );

                            if devices.push(dev).is_err() {
                                log::warn!("PCI device list full!");
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    log::info!("PCI enumeration complete: {} devices found", devices.len());
}

/// Find all NVMe controllers
pub fn find_nvme_controllers() -> Vec<PciDevice, 8> {
    let drivers = state::drivers();
    let devices = &drivers.pci_devices;
    let mut nvme_devices = Vec::new();

    for dev in devices.iter() {
        if dev.is_nvme() {
            log::info!(
                "Found NVMe controller at {}: {:04x}:{:04x}",
                dev.address,
                dev.vendor_id,
                dev.device_id
            );
            let _ = nvme_devices.push(dev.clone());
        }
    }

    nvme_devices
}

/// Find all AHCI controllers
pub fn find_ahci_controllers() -> Vec<PciDevice, 8> {
    let drivers = state::drivers();
    let devices = &drivers.pci_devices;
    let mut ahci_devices = Vec::new();

    for dev in devices.iter() {
        if dev.is_ahci() {
            log::info!(
                "Found AHCI controller at {}: {:04x}:{:04x}",
                dev.address,
                dev.vendor_id,
                dev.device_id
            );
            let _ = ahci_devices.push(dev.clone());
        }
    }

    ahci_devices
}

/// Get all enumerated PCI devices
pub fn get_all_devices() -> Vec<PciDevice, MAX_PCI_DEVICES> {
    state::drivers().pci_devices.clone()
}

/// Print information about all PCI devices
pub fn print_devices() {
    let drivers = state::drivers();
    let devices = &drivers.pci_devices;

    log::info!("PCI Devices:");
    for dev in devices.iter() {
        log::info!(
            "  {}: {:04x}:{:04x} class={:02x}:{:02x} rev={:02x}",
            dev.address,
            dev.vendor_id,
            dev.device_id,
            dev.class_code,
            dev.subclass,
            dev.revision
        );

        for (i, bar) in dev.bars.iter().enumerate() {
            if bar.bar_type != BarType::Unused {
                log::info!(
                    "    BAR{}: {:?} addr={:#x} size={:#x} pf={}",
                    i,
                    bar.bar_type,
                    bar.address,
                    bar.size,
                    bar.prefetchable
                );
            }
        }
    }
}

/// Set ECAM base address (from ACPI MCFG table)
pub fn set_ecam_base(base: u64) {
    state::with_drivers_mut(|drivers| {
        drivers.ecam_base = Some(base);
    });
    log::debug!("ECAM base set to {:#x}", base);
}

// ============================================================================
// Public PCI Configuration Space Access
// ============================================================================

/// Read a 32-bit value from PCI configuration space
pub fn read_config_u32(addr: PciAddress, offset: u8) -> u32 {
    pci_read_config_u32(addr, offset)
}

/// Write a 32-bit value to PCI configuration space
pub fn write_config_u32(addr: PciAddress, offset: u8, value: u32) {
    pci_write_config_u32(addr, offset, value)
}

/// Read a 16-bit value from PCI configuration space
pub fn read_config_u16(addr: PciAddress, offset: u8) -> u16 {
    pci_read_config_u16(addr, offset)
}

/// Write a 16-bit value to PCI configuration space
pub fn write_config_u16(addr: PciAddress, offset: u8, value: u16) {
    let aligned_offset = offset & 0xFC;
    let shift = (offset & 0x02) * 8;
    let current = pci_read_config_u32(addr, aligned_offset);
    let mask = !(0xFFFF_u32 << shift);
    let new_value = (current & mask) | ((value as u32) << shift);
    pci_write_config_u32(addr, aligned_offset, new_value);
}

/// Read an 8-bit value from PCI configuration space
pub fn read_config_u8(addr: PciAddress, offset: u8) -> u8 {
    pci_read_config_u8(addr, offset)
}

/// Write an 8-bit value to PCI configuration space
pub fn write_config_u8(addr: PciAddress, offset: u8, value: u8) {
    let aligned_offset = offset & 0xFC;
    let shift = (offset & 0x03) * 8;
    let current = pci_read_config_u32(addr, aligned_offset);
    let mask = !(0xFF_u32 << shift);
    let new_value = (current & mask) | ((value as u32) << shift);
    pci_write_config_u32(addr, aligned_offset, new_value);
}
