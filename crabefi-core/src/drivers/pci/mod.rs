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
pub(crate) mod access_rules;
pub(crate) mod capability;
pub(crate) mod command;
pub mod driver;

pub use access::ConfigAccessError;
use access::{AnyPciAccess, PciAccess};

use crate::efi::dma::DmaDomain;
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
fn scan_device(
    access: &AnyPciAccess,
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
) -> Option<PciDevice> {
    let addr = PciAddress::new(segment, bus, device, function);
    let header = PciHeader::new(addr);
    let (vendor_id, device_id) = header.id(access);
    let id = u32::from(vendor_id) | (u32::from(device_id) << 16);
    if !access_rules::valid_device_id(id) {
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

fn enabled_command(dev: &PciDevice, original: CommandRegister) -> CommandRegister {
    let has_io = dev
        .bars
        .iter()
        .any(|bar| bar.bar_type == BarType::Io && bar.address != 0);
    let has_memory = dev.bars.iter().any(|bar| {
        matches!(bar.bar_type, BarType::Memory32 | BarType::Memory64) && bar.address != 0
    });
    CommandRegister::from_bits_retain(command::enabled_command(
        original.bits(),
        has_io,
        has_memory,
        true,
    ))
}

/// Enable only assigned decode types and bus mastering for a DMA driver.
pub fn enable_device(dev: &PciDevice) {
    with_access(|access| {
        let mut header = PciHeader::new(dev.address);
        let original = header.command(access);
        let enabled = enabled_command(dev, original);
        header.update_command(access, |_| enabled);
        log::debug!(
            "Enabled device {}: cmd {:#06x} -> {:#06x}",
            dev.address,
            original.bits(),
            enabled.bits()
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

/// Return the explicitly described DMA domain for a PCI device.
pub fn dma_domain(address: PciAddress) -> Option<DmaDomain> {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = address;
        Some(DmaDomain {
            cpu_base: 0,
            device_base: 0,
            size: u64::MAX,
            coherency: crate::efi::dma::DmaCoherency::Coherent,
        })
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let drivers = state::drivers();
        drivers
            .fdt_info
            .pci_dma_domain(address.segment())
            .or_else(|| drivers.acpi_info.pci_dma_domain(address.segment()))
    }
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
    let (regions, ecam_configured) = {
        let drivers = state::drivers();
        (
            drivers.pci.ecam_regions.clone(),
            drivers.pci.ecam_configured,
        )
    };
    let new_access = access::create_access(regions.as_slice(), !ecam_configured);

    state::with_drivers_mut(|drivers| {
        let pci = &mut drivers.pci;
        pci.access = new_access;
        pci.devices.clear();
        match &pci.access {
            AnyPciAccess::Unavailable => log::info!("PCI enumeration skipped: unavailable"),
            AnyPciAccess::IoCam(_) => {
                enumerate_region(&pci.access, &mut pci.devices, 0, 0, u8::MAX)
            }
            AnyPciAccess::Ecam(ecam) => {
                let regions = ecam.regions();
                for region in regions {
                    log::debug!(
                        "PCI: enumerating segment {} buses {:02x}-{:02x}",
                        region.segment,
                        region.bus_start,
                        region.bus_end
                    );
                    enumerate_region(
                        &pci.access,
                        &mut pci.devices,
                        region.segment,
                        region.bus_start,
                        region.bus_end,
                    );
                    if pci.devices.is_full() {
                        break;
                    }
                }
            }
        }
        log::info!(
            "PCI enumeration complete: {} devices found",
            pci.devices.len()
        );
    });
}

/// Enumerate one declared PCI segment/bus range.
fn enumerate_region(
    access: &AnyPciAccess,
    devices: &mut heapless::Vec<PciDevice, { state::MAX_PCI_DEVICES }>,
    segment: u16,
    bus_start: u8,
    bus_end: u8,
) {
    for bus in bus_start..=bus_end {
        for device in 0..32u8 {
            // First check function 0
            if let Some(dev) = scan_device(access, segment, bus, device, 0) {
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
                        if let Some(dev) = scan_device(access, segment, bus, device, function) {
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

/// Store validated, non-overlapping ECAM allocations for PCI initialization.
pub fn set_ecam_regions(regions: &[crate::platform::PciEcamRegion]) -> Result<(), ()> {
    let mut validated =
        heapless::Vec::<crate::platform::PciEcamRegion, { crate::fdt::MAX_ECAM_REGIONS }>::new();
    for &region in regions {
        let overlaps = validated.iter().any(|current| {
            current.segment == region.segment
                && current.bus_start <= region.bus_end
                && region.bus_start <= current.bus_end
        });
        if !region.is_valid() || overlaps || validated.push(region).is_err() {
            log::error!("PCI: rejected explicit ECAM configuration at {:?}", region);
            state::with_drivers_mut(|drivers| {
                drivers.pci.ecam_regions.clear();
                drivers.pci.ecam_configured = true;
            });
            return Err(());
        }
    }
    state::with_drivers_mut(|drivers| {
        drivers.pci.ecam_regions = validated;
        drivers.pci.ecam_configured = true;
    });
    Ok(())
}

// ============================================================================
// Bounded conventional capability walking
// ============================================================================

/// Find a conventional PCI capability using the header's initial pointer.
pub fn find_capability(
    addr: PciAddress,
    capability_id: u8,
) -> Result<Option<u8>, ConfigAccessError> {
    with_access(|access| {
        let status = access.try_read16(addr, 0x06)?;
        let header_type = access.try_read8(addr, 0x0e)?;
        let Some(pointer_offset) = capability::capability_pointer_offset(status, header_type)
        else {
            return Ok(None);
        };
        let start = access.try_read8(addr, pointer_offset)?;
        capability::find_capability_from(start, capability_id, access.max_offset(), |offset| {
            access.try_read32(addr, offset)
        })
    })
}

/// Find a conventional PCI capability from a controller-supplied start pointer.
pub fn find_capability_from(
    addr: PciAddress,
    start: u8,
    capability_id: u8,
) -> Result<Option<u8>, ConfigAccessError> {
    with_access(|access| {
        if access.try_read16(addr, 0x06)? & (1 << 4) == 0 {
            return Ok(None);
        }
        capability::find_capability_from(start, capability_id, access.max_offset(), |offset| {
            access.try_read32(addr, offset)
        })
    })
}

// ============================================================================
// Public PCI Configuration Space Access (via trait)
// ============================================================================

/// Read a checked 32-bit value from PCI configuration space.
pub fn try_read_config_u32(addr: PciAddress, offset: u16) -> Result<u32, ConfigAccessError> {
    with_access(|access| access.try_read32(addr, offset))
}

/// Write a checked 32-bit value to PCI configuration space.
pub fn try_write_config_u32(
    addr: PciAddress,
    offset: u16,
    value: u32,
) -> Result<(), ConfigAccessError> {
    with_access(|access| access.try_write32(addr, offset, value))
}

/// Read a checked 16-bit value from PCI configuration space.
pub fn try_read_config_u16(addr: PciAddress, offset: u16) -> Result<u16, ConfigAccessError> {
    with_access(|access| access.try_read16(addr, offset))
}

/// Write a checked 16-bit value to PCI configuration space.
pub fn try_write_config_u16(
    addr: PciAddress,
    offset: u16,
    value: u16,
) -> Result<(), ConfigAccessError> {
    with_access(|access| access.try_write16(addr, offset, value))
}

/// Read a checked 8-bit value from PCI configuration space.
pub fn try_read_config_u8(addr: PciAddress, offset: u16) -> Result<u8, ConfigAccessError> {
    with_access(|access| access.try_read8(addr, offset))
}

/// Write a checked 8-bit value to PCI configuration space.
pub fn try_write_config_u8(
    addr: PciAddress,
    offset: u16,
    value: u8,
) -> Result<(), ConfigAccessError> {
    with_access(|access| access.try_write8(addr, offset, value))
}

/// Read a 32-bit value, returning all ones after logging an invalid access.
pub fn read_config_u32(addr: PciAddress, offset: u16) -> u32 {
    with_access(|access| access.read32(addr, offset))
}

/// Write a 32-bit value, logging and ignoring an invalid access.
pub fn write_config_u32(addr: PciAddress, offset: u16, value: u32) {
    with_access(|access| access.write32(addr, offset, value))
}

/// Read a 16-bit value, returning all ones on invalid access.
pub fn read_config_u16(addr: PciAddress, offset: u16) -> u16 {
    with_access(|access| access.read16(addr, offset))
}

/// Write a 16-bit value, ignoring an invalid access.
pub fn write_config_u16(addr: PciAddress, offset: u16, value: u16) {
    with_access(|access| access.write16(addr, offset, value))
}

/// Read an 8-bit value, returning all ones on invalid access.
pub fn read_config_u8(addr: PciAddress, offset: u16) -> u8 {
    with_access(|access| access.read8(addr, offset))
}

/// Write an 8-bit value, ignoring an invalid access.
pub fn write_config_u8(addr: PciAddress, offset: u16, value: u8) {
    with_access(|access| access.write8(addr, offset, value))
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
