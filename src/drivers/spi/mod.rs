//! SPI Flash Controller Drivers
//!
//! This module provides drivers for Intel ICH/PCH and AMD SPI100 flash controllers,
//! allowing direct access to the system SPI flash (SMMSTORE region).
//!
//! # Architecture
//!
//! The SPI flash on x86 systems is typically accessed through the chipset's SPI
//! controller. The exact controller type depends on the platform:
//!
//! - **Intel ICH7**: Original SPI controller, software sequencing only
//! - **Intel ICH8-ICH10**: Hardware sequencing introduced
//! - **Intel PCH100+**: New register layout, often locked to hwseq only
//! - **AMD SPI100**: Found in Ryzen and newer platforms
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::drivers::spi;
//!
//! // Detect and initialize the SPI controller
//! if let Some(mut controller) = spi::detect_and_init() {
//!     // Read from flash
//!     let mut buf = [0u8; 256];
//!     controller.read(0x1000, &mut buf).ok();
//!
//!     // Write to flash (requires erase first)
//!     controller.erase(0x1000, 0x1000).ok(); // Erase 4KB
//!     controller.write(0x1000, &data).ok();
//! }
//! ```
//!
//! # References
//!
//! - flashprog/ichspi.c - Intel SPI controller implementation
//! - flashprog/amd_spi100.c - AMD SPI100 controller implementation

pub mod amd;
pub mod amd_chipsets;
pub mod intel;
pub mod intel_chipsets;
pub mod qemu;
pub mod regs;

use crate::drivers::pci::{self, PciDevice};

/// Intel PCI Vendor ID
pub const INTEL_VID: u16 = 0x8086;

/// AMD PCI Vendor ID
pub const AMD_VID: u16 = 0x1022;

/// Old ATI PCI Vendor ID (used for older AMD southbridges)
pub const ATI_VID: u16 = 0x1002;

/// PCI class code for LPC/eSPI bridge (Intel)
pub const CLASS_BRIDGE: u8 = 0x06;
pub const SUBCLASS_ISA: u8 = 0x01;

/// PCI class code for SMBus controller (AMD)
pub const CLASS_SERIAL: u8 = 0x0C;
pub const SUBCLASS_SMBUS: u8 = 0x05;

/// SPI flash error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpiError {
    /// No supported chipset found
    NoChipset,
    /// Chipset found but not supported
    UnsupportedChipset,
    /// SPI controller initialization failed
    InitFailed,
    /// SPI flash is write-protected
    WriteProtected,
    /// Access denied by hardware (locked region)
    AccessDenied,
    /// Hardware sequencing cycle error
    CycleError,
    /// Operation timed out
    Timeout,
    /// Invalid address or length
    InvalidArgument,
    /// Flash descriptor not valid (Intel)
    InvalidDescriptor,
    /// Operation not supported by this controller
    NotSupported,
}

/// Result type for SPI operations
pub type Result<T> = core::result::Result<T, SpiError>;

/// SPI controller operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpiMode {
    /// Automatic mode selection
    #[default]
    Auto,
    /// Force hardware sequencing
    HardwareSequencing,
    /// Force software sequencing  
    SoftwareSequencing,
}

/// Detected chipset vendor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipsetVendor {
    Intel,
    Amd,
    Qemu,
}

/// Information about a detected chipset
#[derive(Debug, Clone)]
pub struct DetectedChipset {
    /// PCI device information
    pub pci_device: PciDevice,
    /// Chipset vendor
    pub vendor: ChipsetVendor,
    /// Chipset name
    pub name: &'static str,
    /// Intel chipset type (for register layout selection)
    pub intel_type: Option<intel_chipsets::IchChipset>,
    /// AMD chipset type
    pub amd_type: Option<amd_chipsets::AmdChipset>,
}

/// Unified SPI controller trait
pub trait SpiController {
    /// Get the controller name
    fn name(&self) -> &'static str;

    /// Check if the controller is locked
    fn is_locked(&self) -> bool;

    /// Check if BIOS writes are enabled
    fn writes_enabled(&self) -> bool;

    /// Enable BIOS writes if possible
    fn enable_writes(&mut self) -> Result<()>;

    /// Read data from flash
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<()>;

    /// Write data to flash (must be erased first)
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<()>;

    /// Erase a region of flash
    fn erase(&mut self, addr: u32, len: u32) -> Result<()>;

    /// Get the operating mode
    fn mode(&self) -> SpiMode;
}

/// Enum containing Intel, AMD, or QEMU SPI controller
pub enum AnySpiController {
    Intel(intel::IntelSpiController),
    Amd(amd::AmdSpi100Controller),
    Qemu(qemu::QemuPflashController),
}

impl SpiController for AnySpiController {
    fn name(&self) -> &'static str {
        match self {
            Self::Intel(c) => c.name(),
            Self::Amd(c) => c.name(),
            Self::Qemu(c) => c.name(),
        }
    }

    fn is_locked(&self) -> bool {
        match self {
            Self::Intel(c) => c.is_locked(),
            Self::Amd(c) => c.is_locked(),
            Self::Qemu(c) => c.is_locked(),
        }
    }

    fn writes_enabled(&self) -> bool {
        match self {
            Self::Intel(c) => c.writes_enabled(),
            Self::Amd(c) => c.writes_enabled(),
            Self::Qemu(c) => c.writes_enabled(),
        }
    }

    fn enable_writes(&mut self) -> Result<()> {
        match self {
            Self::Intel(c) => c.enable_writes(),
            Self::Amd(c) => c.enable_writes(),
            Self::Qemu(c) => c.enable_writes(),
        }
    }

    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<()> {
        match self {
            Self::Intel(c) => c.read(addr, buf),
            Self::Amd(c) => c.read(addr, buf),
            Self::Qemu(c) => c.read(addr, buf),
        }
    }

    fn write(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        match self {
            Self::Intel(c) => c.write(addr, data),
            Self::Amd(c) => c.write(addr, data),
            Self::Qemu(c) => c.write(addr, data),
        }
    }

    fn erase(&mut self, addr: u32, len: u32) -> Result<()> {
        match self {
            Self::Intel(c) => c.erase(addr, len),
            Self::Amd(c) => c.erase(addr, len),
            Self::Qemu(c) => c.erase(addr, len),
        }
    }

    fn mode(&self) -> SpiMode {
        match self {
            Self::Intel(c) => c.mode(),
            Self::Amd(c) => c.mode(),
            Self::Qemu(c) => c.mode(),
        }
    }
}

/// Detect the system's SPI controller chipset
///
/// Scans the PCI bus for known Intel and AMD chipsets that contain
/// SPI flash controllers.
pub fn detect_chipset() -> Option<DetectedChipset> {
    let devices = pci::get_all_devices();

    // First try Intel chipsets (look for LPC/eSPI bridge at 00:1f.0)
    for dev in devices.iter() {
        if dev.vendor_id == INTEL_VID {
            // Check if this is a known Intel LPC bridge
            if let Some(enable) = intel_chipsets::find_chipset(dev.vendor_id, dev.device_id) {
                log::info!(
                    "Found Intel chipset: {} ({:04x}:{:04x}) at {}",
                    enable.device_name,
                    dev.vendor_id,
                    dev.device_id,
                    dev.address
                );

                return Some(DetectedChipset {
                    pci_device: dev.clone(),
                    vendor: ChipsetVendor::Intel,
                    name: enable.device_name,
                    intel_type: Some(enable.chipset),
                    amd_type: None,
                });
            }
        }
    }

    // Try AMD chipsets (look for SMBus controller)
    for dev in devices.iter() {
        if dev.vendor_id == AMD_VID || dev.vendor_id == ATI_VID {
            // Check if this is a known AMD chipset
            if let Some(enable) =
                amd_chipsets::find_chipset(dev.vendor_id, dev.device_id, dev.revision)
            {
                log::info!(
                    "Found AMD chipset: {} ({:04x}:{:04x} rev {:02x}) at {}",
                    enable.device_name,
                    dev.vendor_id,
                    dev.device_id,
                    dev.revision,
                    dev.address
                );

                return Some(DetectedChipset {
                    pci_device: dev.clone(),
                    vendor: ChipsetVendor::Amd,
                    name: enable.device_name,
                    intel_type: None,
                    amd_type: Some(enable.chipset),
                });
            }
        }
    }

    log::warn!("No supported SPI controller chipset found");
    None
}

/// Detect and initialize the SPI controller
///
/// This is the main entry point for using the SPI flash controller.
/// It detects the chipset type and initializes the appropriate driver.
///
/// Detection order:
/// 1. Check if running in QEMU - if so, prefer pflash backend
/// 2. Try Intel/AMD chipset detection for real hardware
/// 3. Fall back to QEMU pflash if nothing else works
pub fn detect_and_init() -> Option<AnySpiController> {
    // First check if we're running in QEMU - if so, prefer pflash
    // QEMU emulates chipsets like ICH9, but the SPI controller doesn't
    // actually work like real hardware. The pflash backend is more reliable.
    log::debug!("Checking for QEMU environment...");
    let is_qemu = qemu::detect_qemu_pflash();
    log::debug!("QEMU detection result: {}", is_qemu);

    if is_qemu {
        log::info!("QEMU environment detected, trying pflash backend...");
        match qemu::QemuPflashController::new() {
            Ok(controller) => {
                log::info!("QEMU pflash controller initialized");
                return Some(AnySpiController::Qemu(controller));
            }
            Err(e) => {
                log::warn!("QEMU pflash not available: {:?}", e);
                // Fall through to try Intel/AMD
            }
        }
    }

    // Try to detect Intel/AMD chipsets (for real hardware)
    if let Some(chipset) = detect_chipset() {
        match chipset.vendor {
            ChipsetVendor::Intel => {
                let intel_type = chipset.intel_type?;
                match intel::IntelSpiController::new(&chipset.pci_device, intel_type, SpiMode::Auto)
                {
                    Ok(controller) => {
                        log::info!(
                            "Intel SPI controller initialized in {:?} mode",
                            controller.mode()
                        );
                        return Some(AnySpiController::Intel(controller));
                    }
                    Err(e) => {
                        log::error!("Failed to initialize Intel SPI controller: {:?}", e);
                    }
                }
            }
            ChipsetVendor::Amd => {
                let amd_type = chipset.amd_type?;
                match amd::AmdSpi100Controller::new(&chipset.pci_device, amd_type) {
                    Ok(controller) => {
                        log::info!("AMD SPI100 controller initialized");
                        return Some(AnySpiController::Amd(controller));
                    }
                    Err(e) => {
                        log::error!("Failed to initialize AMD SPI100 controller: {:?}", e);
                    }
                }
            }
            ChipsetVendor::Qemu => {
                // Should not happen from detect_chipset, but handle it anyway
                match qemu::QemuPflashController::new() {
                    Ok(controller) => {
                        log::info!("QEMU pflash controller initialized");
                        return Some(AnySpiController::Qemu(controller));
                    }
                    Err(e) => {
                        log::error!("Failed to initialize QEMU pflash controller: {:?}", e);
                    }
                }
            }
        }
    }

    log::warn!("No SPI controller found");
    None
}

/// Delay for a specified number of microseconds
///
/// This is a simple busy-wait delay using the x86 TSC (Time Stamp Counter).
/// On modern CPUs, TSC typically runs at a fixed frequency regardless of
/// CPU frequency scaling.
#[inline]
pub fn delay_us(us: u32) {
    // Use a simple busy loop with approximate timing
    // On modern x86, each iteration is roughly a few nanoseconds
    // We'll use a conservative estimate of 100 iterations per microsecond
    let iterations = us as u64 * 100;
    for _ in 0..iterations {
        core::hint::spin_loop();
    }
}

/// Delay for a specified number of milliseconds
#[inline]
pub fn delay_ms(ms: u32) {
    delay_us(ms * 1000);
}
