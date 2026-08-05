//! PCI/PCIe Enumeration, Configuration, and Driver Binding
//!
//! This module provides PCI device enumeration, configuration space access,
//! and a driver model for automatic device binding.
//!
//! # Architecture
//!
//! - **access**: PCI config space access abstraction (`PciAccess` trait)
//!   with I/O CAM and PCIe ECAM implementations
//! - **driver**: PCI driver lifecycle trait (`PciDriver`) with table-driven
//!   binding during enumeration
//!
//! # PCI Access
//!
//! The access method is selected at runtime:
//! - If an ECAM base is available (from ACPI MCFG or platform config) → ECAM
//! - Otherwise → legacy I/O ports 0xCF8/0xCFC
//!
//! # Driver Model
//!
//! Each PCI driver registers match criteria (class/subclass) and lifecycle
//! methods (probe/init/shutdown). During `init_and_bind_drivers()`, discovered
//! devices are matched against drivers automatically.

pub mod access;
pub mod driver;

use access::{AnyPciAccess, PciAccess};

use crate::state;
pub use pci_types::{
    BaseClass, CommandRegister, ConfigRegionAccess, DeviceId, DeviceRevision, HeaderType,
    Interface, PciAddress, PciHeader, StatusRegister, SubClass, VendorId,
    device_type::{DeviceType, UsbType},
};

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
pub const CLASS_SYSTEM: u8 = 0x08;
pub const CLASS_SERIAL: u8 = 0x0C;

/// System peripheral subclasses
pub const SUBCLASS_SDHCI: u8 = 0x05; // SD Host Controller

/// Invalid vendor ID (no device present)
const INVALID_VENDOR_ID: u16 = 0xFFFF;
const ECAM_BYTES_PER_BUS: u64 = 1 << 20;

// ============================================================================
// Global PCI Access
// ============================================================================

/// Helper: run a closure with the global PCI access method
fn with_access<F, R>(f: F) -> R
where
    F: FnOnce(&AnyPciAccess) -> R,
{
    let access = &state::drivers().pci.access;
    f(access)
}

// ============================================================================
// PCI Address and Device Types
// ============================================================================

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
    pub vendor_id: VendorId,
    pub device_id: DeviceId,
    pub class_code: BaseClass,
    pub subclass: SubClass,
    pub prog_if: Interface,
    pub revision: DeviceRevision,
    pub header_type: HeaderType,
    multi_function: bool,
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
            header_type: HeaderType::Unknown(0),
            multi_function: false,
            bars: [PciBar::default(); 6],
            interrupt_line: 0,
            interrupt_pin: 0,
        }
    }

    /// Return the standard PCI class/subclass classification.
    pub fn device_type(&self) -> DeviceType {
        (self.class_code, self.subclass).into()
    }

    /// Check if this is an NVMe controller
    pub fn is_nvme(&self) -> bool {
        self.device_type() == DeviceType::NvmeController
    }

    /// Check if this is an AHCI controller
    pub fn is_ahci(&self) -> bool {
        self.device_type() == DeviceType::SataController
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
        self.device_type() == DeviceType::UsbController
    }

    /// Check if this is an SDHCI (SD Host Controller Interface) device
    pub fn is_sdhci(&self) -> bool {
        self.device_type() == DeviceType::SdHostController
    }
}

// ============================================================================
// PCI Enumeration (using PciAccess trait)
// ============================================================================

/// Probe a single BAR and return its type, address, and size
fn probe_bar(access: &AnyPciAccess, addr: PciAddress, bar_index: usize) -> PciBar {
    let bar_offset = (0x10 + bar_index * 4) as u16;
    let original = access.read32(addr, bar_offset);

    // Empty BAR
    if original == 0 {
        return PciBar::default();
    }

    // Check if it's I/O or memory.  Do not size BARs here by writing
    // 0xffffffff: fstart has already assigned and enabled resources, and
    // probing live BARs can transiently break decode or bus mastering while
    // storage/USB devices are active.  CrabEFI drivers only need the assigned
    // base address, so keep enumeration read-only.
    if original & 1 == 1 {
        return PciBar {
            bar_type: BarType::Io,
            address: (original & 0xFFFFFFFC) as u64,
            size: 0,
            prefetchable: false,
        };
    }

    // Memory BAR - check type (bits 2:1)
    let mem_type = (original >> 1) & 0x3;
    let prefetchable = (original & 0x8) != 0;

    match mem_type {
        0 => PciBar {
            bar_type: BarType::Memory32,
            address: (original & 0xFFFFFFF0) as u64,
            size: 0,
            prefetchable,
        },
        2 => {
            // 64-bit memory (consumes two BARs)
            let bar_offset_hi = bar_offset + 4;
            let original_hi = access.read32(addr, bar_offset_hi);
            let address = ((original_hi as u64) << 32) | ((original & 0xFFFFFFF0) as u64);

            PciBar {
                bar_type: BarType::Memory64,
                address,
                size: 0,
                prefetchable,
            }
        }
        _ => PciBar::default(),
    }
}

/// Scan a single device/function and add to device list if valid
fn scan_device(access: &AnyPciAccess, bus: u8, device: u8, function: u8) -> Option<PciDevice> {
    let addr = PciAddress::new(0, bus, device, function);
    let header = PciHeader::new(addr);
    let (vendor_id, device_id) = header.id(access);

    if vendor_id == INVALID_VENDOR_ID {
        return None;
    }

    let mut dev = PciDevice::new(addr);
    dev.vendor_id = vendor_id;
    dev.device_id = device_id;
    (dev.revision, dev.class_code, dev.subclass, dev.prog_if) = header.revision_and_class(access);
    dev.header_type = header.header_type(access);
    dev.multi_function = header.has_multiple_functions(access);

    // Read interrupt info (offset 0x3C)
    let irq_data = access.read32(addr, 0x3C);
    dev.interrupt_line = (irq_data & 0xFF) as u8;
    dev.interrupt_pin = ((irq_data >> 8) & 0xFF) as u8;

    // Only scan BARs for normal (type 0) headers.
    if matches!(dev.header_type, HeaderType::Endpoint) {
        let mut bar_index = 0;
        while bar_index < 6 {
            let bar = probe_bar(access, addr, bar_index);
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
    with_access(|access| {
        let mut header = PciHeader::new(dev.address);
        let command = header.command(access);
        let new_command = command
            | CommandRegister::IO_ENABLE
            | CommandRegister::MEMORY_ENABLE
            | CommandRegister::BUS_MASTER_ENABLE;
        header.update_command(access, |_| new_command);

        log::debug!(
            "Enabled device {}: cmd {:#06x} -> {:#06x}",
            dev.address,
            command.bits(),
            new_command.bits()
        );
    });
}

/// Read a 16-bit PCI configuration-space register.
pub fn read_config16(addr: PciAddress, offset: u16) -> u16 {
    with_access(|access| access.read16(addr, offset))
}

/// Write a 16-bit PCI configuration-space register.
pub fn write_config16(addr: PciAddress, offset: u16, value: u16) {
    with_access(|access| access.write16(addr, offset, value));
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize PCI subsystem: select access method and enumerate devices
///
/// This only enumerates devices. Call `bind_drivers()` separately to
/// initialize device drivers (needed because SPI detection happens between
/// enumeration and driver binding).
pub fn init() {
    log::info!("Initializing PCI subsystem...");

    // Select access method based on ECAM availability
    let pci_state = &state::drivers().pci;
    let ecam_base = pci_state.ecam_base;
    let ecam_size = pci_state.ecam_size;
    let new_access = access::create_access(ecam_base);
    let max_bus = max_bus_for_access(ecam_base, ecam_size);

    // Set access method and enumerate devices in one closure so we can
    // borrow both `pci.access` and `pci.devices` without aliasing issues.
    state::with_drivers_mut(|drivers| {
        drivers.pci.access = new_access;
        let pci = &mut drivers.pci;
        pci.devices.clear();
        if let Some(max_bus) = max_bus {
            enumerate_devices(&pci.access, &mut pci.devices, max_bus);
        }
    });
}

fn max_bus_for_access(ecam_base: Option<u64>, ecam_size: Option<u64>) -> Option<u8> {
    if ecam_base.is_none() {
        return Some(u8::MAX);
    }

    let Some(size) = ecam_size else {
        log::warn!("PCI ECAM size unknown; scanning all 256 buses");
        return Some(u8::MAX);
    };

    let bus_count = size / ECAM_BYTES_PER_BUS;
    if bus_count == 0 {
        log::warn!(
            "PCI ECAM window size {:#x} is smaller than one bus; skipping enumeration",
            size
        );
        return None;
    }

    let max_bus = (bus_count.min(256) - 1) as u8;
    log::debug!(
        "PCI ECAM window size {:#x}: scanning buses 00-{:02x}",
        size,
        max_bus
    );
    Some(max_bus)
}

/// Enumerate all PCI devices
fn enumerate_devices(
    access: &AnyPciAccess,
    devices: &mut heapless::Vec<PciDevice, { state::MAX_PCI_DEVICES }>,
    max_bus: u8,
) {
    for bus in 0..=max_bus {
        for device in 0..32u8 {
            // First check function 0
            if let Some(dev) = scan_device(access, bus, device, 0) {
                let is_multi_function = dev.multi_function;

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
                        if let Some(dev) = scan_device(access, bus, device, function) {
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

/// Bind drivers to all enumerated PCI devices
///
/// This iterates all discovered PCI devices and uses the driver registry
/// to find and initialize appropriate drivers.
///
/// Called from `init_storage()` after SPI controller detection, because
/// SPI needs PCI enumeration but storage drivers need SPI to be done first.
pub fn bind_drivers() {
    log::info!("Binding PCI drivers to devices...");

    let devices = state::drivers().pci.devices.clone();

    let mut bound_count = 0;
    for device in devices.iter() {
        if driver::bind_driver(device).is_some() {
            bound_count += 1;
        }
    }

    log::info!("PCI driver binding complete: {} devices bound", bound_count);
}

/// Shutdown all PCI drivers
///
/// Called during ExitBootServices to cleanly quiesce hardware.
pub fn shutdown_drivers() {
    driver::shutdown_all();
}

/// Clear PCI Bus Master Enable on all enumerated devices.
///
/// This is a conservative OS-handoff safety net: once ExitBootServices has
/// succeeded, firmware-owned DMA rings and bounce buffers are no longer owned
/// by firmware.  Any device left bus-mastering can scribble over pages Linux
/// has already repurposed for early stacks or metadata.
pub fn disable_all_bus_mastering_for_handoff() {
    let devices = state::drivers().pci.devices.clone();
    if devices.is_empty() {
        return;
    }

    let mut changed = 0usize;
    with_access(|access| {
        for dev in devices.iter() {
            let mut header = PciHeader::new(dev.address);
            let command = header.command(access);
            if !command.contains(CommandRegister::BUS_MASTER_ENABLE) {
                continue;
            }
            let new_command = command - CommandRegister::BUS_MASTER_ENABLE;
            header.update_command(access, |_| new_command);
            changed += 1;
            log::debug!(
                "PCI {}: bus master disabled for OS handoff ({:#06x} -> {:#06x})",
                dev.address,
                command.bits(),
                new_command.bits()
            );
        }
    });

    log::info!(
        "PCI: disabled bus mastering on {} device(s) for OS handoff",
        changed
    );
}

// ============================================================================
// Legacy find_*_controllers functions (kept for SPI detection which
// happens before driver binding)
// ============================================================================

/// Find all NVMe controllers
pub fn find_nvme_controllers() -> heapless::Vec<PciDevice, 8> {
    let drivers = state::drivers();
    let devices = &drivers.pci.devices;
    let mut result = heapless::Vec::new();
    for dev in devices.iter() {
        if dev.is_nvme() {
            log::info!(
                "Found NVMe controller at {}: {:04x}:{:04x}",
                dev.address,
                dev.vendor_id,
                dev.device_id
            );
            let _ = result.push(dev.clone());
        }
    }
    result
}

/// Find all AHCI controllers
pub fn find_ahci_controllers() -> heapless::Vec<PciDevice, 8> {
    let drivers = state::drivers();
    let devices = &drivers.pci.devices;
    let mut result = heapless::Vec::new();
    for dev in devices.iter() {
        if dev.is_ahci() {
            log::info!(
                "Found AHCI controller at {}: {:04x}:{:04x}",
                dev.address,
                dev.vendor_id,
                dev.device_id
            );
            let _ = result.push(dev.clone());
        }
    }
    result
}

/// Find all SDHCI controllers
pub fn find_sdhci_controllers() -> heapless::Vec<PciDevice, 8> {
    let drivers = state::drivers();
    let devices = &drivers.pci.devices;
    let mut result = heapless::Vec::new();
    for dev in devices.iter() {
        if dev.is_sdhci() {
            log::info!(
                "Found SDHCI controller at {}: {:04x}:{:04x}",
                dev.address,
                dev.vendor_id,
                dev.device_id
            );
            let _ = result.push(dev.clone());
        }
    }
    result
}

/// Get all enumerated PCI devices
pub fn get_all_devices() -> heapless::Vec<PciDevice, { state::MAX_PCI_DEVICES }> {
    state::drivers().pci.devices.clone()
}

/// Print information about all PCI devices
pub fn print_devices() {
    let drivers = state::drivers();
    let devices = &drivers.pci.devices;

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
    set_ecam_region(base, None);
}

pub fn set_ecam_region(base: u64, size: Option<u64>) {
    state::with_drivers_mut(|drivers| {
        drivers.pci.ecam_base = Some(base);
        drivers.pci.ecam_size = size;
    });
    if let Some(size) = size {
        log::debug!("ECAM region set to {:#x}+{:#x}", base, size);
    } else {
        log::debug!("ECAM base set to {:#x} (size unknown)", base);
    }
}

// ============================================================================
// Public PCI Configuration Space Access (via trait)
// ============================================================================

/// Read a 32-bit value from PCI configuration space
pub fn read_config_u32(addr: PciAddress, offset: u8) -> u32 {
    with_access(|access| access.read32(addr, offset as u16))
}

/// Write a 32-bit value to PCI configuration space
pub fn write_config_u32(addr: PciAddress, offset: u8, value: u32) {
    with_access(|access| access.write32(addr, offset as u16, value))
}

/// Read a 16-bit value from PCI configuration space
pub fn read_config_u16(addr: PciAddress, offset: u8) -> u16 {
    with_access(|access| access.read16(addr, offset as u16))
}

/// Write a 16-bit value to PCI configuration space
pub fn write_config_u16(addr: PciAddress, offset: u8, value: u16) {
    with_access(|access| access.write16(addr, offset as u16, value))
}

/// Read an 8-bit value from PCI configuration space
pub fn read_config_u8(addr: PciAddress, offset: u8) -> u8 {
    with_access(|access| access.read8(addr, offset as u16))
}

/// Write an 8-bit value to PCI configuration space
pub fn write_config_u8(addr: PciAddress, offset: u8, value: u8) {
    with_access(|access| access.write8(addr, offset as u16, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct TestConfig;

    impl ConfigRegionAccess for TestConfig {
        #[allow(unused_unsafe)]
        unsafe fn read(&self, address: PciAddress, offset: u16) -> u32 {
            unsafe {
                assert_eq!(address, PciAddress::new(0x12, 0x34, 0x1a, 0x5));
                match offset {
                    0x00 => 0x5678_1234,
                    0x04 => 0x0010_0007,
                    0x08 => 0x0108_0602,
                    0x0c => 0x0080_0000,
                    _ => 0,
                }
            }
        }

        #[allow(unused_unsafe)]
        unsafe fn write(&self, _address: PciAddress, _offset: u16, _value: u32) {
            unsafe { panic!("header test must not write configuration space") }
        }
    }

    #[test]
    fn pci_types_address_and_header_parse_configuration() {
        let address = PciAddress::new(0x12, 0x34, 0x1a, 0x5);
        assert_eq!(address.segment(), 0x12);
        assert_eq!(address.bus(), 0x34);
        assert_eq!(address.device(), 0x1a);
        assert_eq!(address.function(), 0x5);

        let header = PciHeader::new(address);
        assert_eq!(header.id(TestConfig), (0x1234, 0x5678));
        assert_eq!(
            header.revision_and_class(TestConfig),
            (0x02, CLASS_STORAGE, SUBCLASS_NVME, 0x06)
        );
        assert_eq!(header.header_type(TestConfig), HeaderType::Endpoint);
        assert_eq!(
            DeviceType::from((CLASS_STORAGE, SUBCLASS_NVME)),
            DeviceType::NvmeController
        );
        assert_eq!(UsbType::try_from(0x30), Ok(UsbType::Xhci));
        assert!(header.has_multiple_functions(TestConfig));
        assert!(header.status(TestConfig).has_capability_list());
        assert!(
            header
                .command(TestConfig)
                .contains(CommandRegister::BUS_MASTER_ENABLE)
        );
    }
}
