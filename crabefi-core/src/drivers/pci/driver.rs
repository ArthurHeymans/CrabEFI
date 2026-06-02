//! PCI Driver Model
//!
//! This module defines the PCI driver trait and a table-driven binding mechanism.
//! Each PCI driver registers match criteria (class/subclass/vendor/device) and
//! lifecycle methods (probe, init, shutdown).
//!
//! During PCI enumeration, the driver registry matches discovered devices against
//! registered drivers and calls their lifecycle methods.

use super::PciDevice;

/// Error type for driver operations
#[derive(Debug)]
pub enum DriverError {
    /// Device initialization failed
    InitFailed,
}

impl core::fmt::Display for DriverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InitFailed => write!(f, "initialization failed"),
        }
    }
}

/// Match criteria for PCI driver binding
///
/// Specifies which PCI devices a driver can handle, based on class codes
/// and optionally vendor/device IDs.
#[derive(Debug, Clone, Copy)]
pub struct PciDriverMatch {
    /// PCI class code (e.g., 0x01 for storage, 0x0C for serial bus)
    pub class: u8,
    /// PCI subclass code (e.g., 0x08 for NVMe, 0x06 for AHCI)
    pub subclass: u8,
    /// Optional programming interface filter (None = match any prog_if)
    pub prog_if: Option<u8>,
}

/// PCI driver lifecycle trait
///
/// All PCI-based device drivers implement this trait to participate in
/// automatic device binding during PCI enumeration.
///
/// # Lifecycle
///
/// 1. **Match**: PCI subsystem checks `match_criteria()` against discovered devices
/// 2. **Probe**: `probe()` is called for matching devices to confirm the driver can handle them
/// 3. **Init**: `init()` is called to initialize the hardware
/// 4. **Shutdown**: `shutdown()` is called during ExitBootServices or system reset
pub trait PciDriver: Sync {
    /// Human-readable driver name
    fn name(&self) -> &'static str;

    /// PCI class/subclass criteria this driver handles
    ///
    /// The driver will be considered for any device matching one of these entries.
    fn match_criteria(&self) -> &'static [PciDriverMatch];

    /// Probe a PCI device to check if this driver can handle it
    ///
    /// Called after match_criteria filtering. This allows drivers to perform
    /// additional checks (e.g., vendor ID filtering, capability checks).
    ///
    /// # Arguments
    /// * `device` - The PCI device to probe
    ///
    /// # Returns
    /// `true` if this driver claims the device
    fn probe(&self, device: &PciDevice) -> bool;

    /// Initialize the device
    ///
    /// Called after `probe()` returns `true`. The driver should:
    /// 1. Enable the device (bus master, memory/IO space)
    /// 2. Configure hardware (queues, ports, DMA, etc.)
    /// 3. Register any discovered sub-devices (namespaces, ports, etc.)
    ///
    /// # Arguments
    /// * `device` - The PCI device to initialize
    fn init(&self, device: &PciDevice) -> Result<(), DriverError>;

    /// Shutdown all devices managed by this driver
    ///
    /// Called during ExitBootServices or system reset. The driver should:
    /// 1. Stop all pending I/O operations
    /// 2. Disable interrupts
    /// 3. Put hardware into a safe state
    fn shutdown(&self) -> Result<(), DriverError>;
}

// ============================================================================
// Driver Registry
// ============================================================================

use crate::drivers::{ahci, nvme, sdhci, usb};

/// NVMe PCI driver
struct NvmePciDriver;

static NVME_MATCH: [PciDriverMatch; 1] = [PciDriverMatch {
    class: super::CLASS_STORAGE,
    subclass: super::SUBCLASS_NVME,
    prog_if: None,
}];

impl PciDriver for NvmePciDriver {
    fn name(&self) -> &'static str {
        "NVMe"
    }

    fn match_criteria(&self) -> &'static [PciDriverMatch] {
        &NVME_MATCH
    }

    fn probe(&self, _device: &PciDevice) -> bool {
        true // Accept all NVMe controllers
    }

    fn init(&self, device: &PciDevice) -> Result<(), DriverError> {
        nvme::init_device(device).map_err(|()| DriverError::InitFailed)
    }

    fn shutdown(&self) -> Result<(), DriverError> {
        nvme::shutdown();
        Ok(())
    }
}

/// AHCI PCI driver
struct AhciPciDriver;

static AHCI_MATCH: [PciDriverMatch; 1] = [PciDriverMatch {
    class: super::CLASS_STORAGE,
    subclass: super::SUBCLASS_SATA,
    prog_if: None,
}];

impl PciDriver for AhciPciDriver {
    fn name(&self) -> &'static str {
        "AHCI"
    }

    fn match_criteria(&self) -> &'static [PciDriverMatch] {
        &AHCI_MATCH
    }

    fn probe(&self, _device: &PciDevice) -> bool {
        true // Accept all AHCI controllers
    }

    fn init(&self, device: &PciDevice) -> Result<(), DriverError> {
        ahci::init_device(device).map_err(|()| DriverError::InitFailed)
    }

    fn shutdown(&self) -> Result<(), DriverError> {
        ahci::shutdown();
        Ok(())
    }
}

/// USB PCI driver (handles xHCI, EHCI, OHCI, UHCI via prog_if)
struct UsbPciDriver;

static USB_MATCH: [PciDriverMatch; 1] = [PciDriverMatch {
    class: super::CLASS_SERIAL,
    subclass: 0x03, // USB controller
    prog_if: None,  // Match all: xHCI(0x30), EHCI(0x20), OHCI(0x10), UHCI(0x00)
}];

impl PciDriver for UsbPciDriver {
    fn name(&self) -> &'static str {
        "USB"
    }

    fn match_criteria(&self) -> &'static [PciDriverMatch] {
        &USB_MATCH
    }

    fn probe(&self, device: &PciDevice) -> bool {
        // Accept known USB controller types
        matches!(device.prog_if, 0x00 | 0x10 | 0x20 | 0x30)
    }

    fn init(&self, device: &PciDevice) -> Result<(), DriverError> {
        usb::init_device(device).map_err(|()| DriverError::InitFailed)
    }

    fn shutdown(&self) -> Result<(), DriverError> {
        usb::shutdown();
        Ok(())
    }
}

/// SDHCI PCI driver
struct SdhciPciDriver;

static SDHCI_MATCH: [PciDriverMatch; 1] = [PciDriverMatch {
    class: super::CLASS_SYSTEM,
    subclass: super::SUBCLASS_SDHCI,
    prog_if: None,
}];

impl PciDriver for SdhciPciDriver {
    fn name(&self) -> &'static str {
        "SDHCI"
    }

    fn match_criteria(&self) -> &'static [PciDriverMatch] {
        &SDHCI_MATCH
    }

    fn probe(&self, _device: &PciDevice) -> bool {
        true
    }

    fn init(&self, device: &PciDevice) -> Result<(), DriverError> {
        sdhci::init_device(device).map_err(|()| DriverError::InitFailed)
    }

    fn shutdown(&self) -> Result<(), DriverError> {
        sdhci::shutdown();
        Ok(())
    }
}

/// Static table of all PCI drivers
///
/// Drivers are probed in order. The first driver that matches and successfully
/// probes a device gets to initialize it.
static PCI_DRIVERS: &[&dyn PciDriver] = &[
    &NvmePciDriver,
    &AhciPciDriver,
    &UsbPciDriver,
    &SdhciPciDriver,
];

/// Bind drivers to a discovered PCI device
///
/// Iterates the driver table and calls probe/init for the first matching driver.
///
/// # Arguments
/// * `device` - The PCI device to bind
///
/// # Returns
/// The name of the driver that claimed the device, or None
pub fn bind_driver(device: &PciDevice) -> Option<&'static str> {
    for driver in PCI_DRIVERS {
        // Check match criteria
        let matches = driver.match_criteria().iter().any(|m| {
            m.class == device.class_code
                && m.subclass == device.subclass
                && m.prog_if.is_none_or(|pif| pif == device.prog_if)
        });

        if !matches {
            continue;
        }

        // Probe the device
        if !driver.probe(device) {
            continue;
        }

        // Initialize
        log::info!(
            "PCI {}: binding {} driver to {:04x}:{:04x}",
            device.address,
            driver.name(),
            device.vendor_id,
            device.device_id
        );

        match driver.init(device) {
            Ok(()) => {
                log::info!(
                    "PCI {}: {} driver initialized successfully",
                    device.address,
                    driver.name()
                );
                return Some(driver.name());
            }
            Err(e) => {
                log::error!(
                    "PCI {}: {} driver init failed: {}",
                    device.address,
                    driver.name(),
                    e
                );
                // Continue to try other drivers
            }
        }
    }

    None
}

/// Shutdown all PCI drivers
///
/// Called during ExitBootServices to cleanly stop all hardware.
pub fn shutdown_all() {
    for driver in PCI_DRIVERS {
        if let Err(e) = driver.shutdown() {
            log::warn!("{} driver shutdown failed: {}", driver.name(), e);
        }
    }
}
