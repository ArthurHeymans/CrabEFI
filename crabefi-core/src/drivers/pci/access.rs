//! PCI Configuration Space Access Methods
//!
//! This module provides an abstraction over different PCI configuration space
//! access methods:
//! - **Legacy I/O CAM** (Configuration Access Mechanism): Uses I/O ports 0xCF8/0xCFC,
//!   limited to 256 bytes of config space per function.
//! - **ECAM** (Enhanced Configuration Access Mechanism): Memory-mapped PCIe extended
//!   config space, supporting 4096 bytes per function.
//!
//! The access method is selected at runtime based on whether an ECAM base address
//! is available (typically from ACPI MCFG or platform configuration).

use super::PciAddress;
use pci_types::ConfigRegionAccess;

/// Trait for PCI configuration space access
///
/// Implementations provide read/write access to PCI configuration space
/// registers using different hardware mechanisms.
pub trait PciAccess: ConfigRegionAccess {
    /// Read a 32-bit value from PCI configuration space.
    fn read32(&self, addr: PciAddress, offset: u16) -> u32 {
        // Safety: callers only use valid PCI configuration offsets.
        unsafe { self.read(addr, offset) }
    }

    /// Write a 32-bit value to PCI configuration space.
    fn write32(&self, addr: PciAddress, offset: u16, value: u32) {
        // Safety: callers only write valid PCI configuration offsets.
        unsafe { self.write(addr, offset, value) }
    }

    /// Read a 16-bit value from PCI configuration space
    fn read16(&self, addr: PciAddress, offset: u16) -> u16 {
        let aligned_offset = offset & !0x3;
        let shift = (offset & 0x02) * 8;
        let value = self.read32(addr, aligned_offset);
        ((value >> shift) & 0xFFFF) as u16
    }

    /// Write a 16-bit value to PCI configuration space
    fn write16(&self, addr: PciAddress, offset: u16, value: u16) {
        let aligned_offset = offset & !0x3;
        let shift = (offset & 0x02) * 8;
        let current = self.read32(addr, aligned_offset);
        let mask = !(0xFFFF_u32 << shift);
        let new_value = (current & mask) | ((value as u32) << shift);
        self.write32(addr, aligned_offset, new_value);
    }

    /// Read an 8-bit value from PCI configuration space
    fn read8(&self, addr: PciAddress, offset: u16) -> u8 {
        let aligned_offset = offset & !0x3;
        let shift = (offset & 0x03) * 8;
        let value = self.read32(addr, aligned_offset);
        ((value >> shift) & 0xFF) as u8
    }

    /// Write an 8-bit value to PCI configuration space
    fn write8(&self, addr: PciAddress, offset: u16, value: u8) {
        let aligned_offset = offset & !0x3;
        let shift = (offset & 0x03) * 8;
        let current = self.read32(addr, aligned_offset);
        let mask = !(0xFF_u32 << shift);
        let new_value = (current & mask) | ((value as u32) << shift);
        self.write32(addr, aligned_offset, new_value);
    }

    /// Name of this access method (for logging)
    fn name(&self) -> &'static str;

    /// Maximum config space offset supported
    fn max_offset(&self) -> u16;
}

// ============================================================================
// Legacy I/O CAM Access (ports 0xCF8/0xCFC)
// ============================================================================

/// PCI configuration space ports (legacy CAM)
#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// Legacy I/O port-based PCI Configuration Access Mechanism
///
/// Uses x86 I/O ports 0xCF8 (address) and 0xCFC (data) to access
/// the first 256 bytes of PCI configuration space.
pub struct IoCamAccess;

impl ConfigRegionAccess for IoCamAccess {
    #[cfg(target_arch = "x86_64")]
    unsafe fn read(&self, addr: PciAddress, offset: u16) -> u32 {
        use x86_64::instructions::port::{Port, PortWriteOnly};

        // Legacy CAM only supports 8-bit offsets (0-255)
        debug_assert!(
            offset <= 255,
            "Legacy CAM only supports offsets 0-255, got {}",
            offset
        );
        let offset = offset as u8;
        let mut address_port: PortWriteOnly<u32> = PortWriteOnly::new(PCI_CONFIG_ADDRESS);
        let mut data_port: Port<u32> = Port::new(PCI_CONFIG_DATA);

        unsafe {
            address_port.write(
                (1 << 31)
                    | ((addr.bus() as u32) << 16)
                    | ((addr.device() as u32) << 11)
                    | ((addr.function() as u32) << 8)
                    | ((offset as u32) & 0xFC),
            );
            data_port.read()
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[allow(unused_unsafe)]
    unsafe fn read(&self, _addr: PciAddress, _offset: u16) -> u32 {
        // Safety: non-x86 targets have no I/O CAM backend and make no hardware access.
        unsafe { 0xFFFFFFFF }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn write(&self, addr: PciAddress, offset: u16, value: u32) {
        use x86_64::instructions::port::{Port, PortWriteOnly};

        debug_assert!(
            offset <= 255,
            "Legacy CAM only supports offsets 0-255, got {}",
            offset
        );
        let offset = offset as u8;
        let mut address_port: PortWriteOnly<u32> = PortWriteOnly::new(PCI_CONFIG_ADDRESS);
        let mut data_port: Port<u32> = Port::new(PCI_CONFIG_DATA);

        unsafe {
            address_port.write(
                (1 << 31)
                    | ((addr.bus() as u32) << 16)
                    | ((addr.device() as u32) << 11)
                    | ((addr.function() as u32) << 8)
                    | ((offset as u32) & 0xFC),
            );
            data_port.write(value);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[allow(unused_unsafe)]
    unsafe fn write(&self, _addr: PciAddress, _offset: u16, _value: u32) {
        // Safety: non-x86 targets have no I/O CAM backend and make no hardware access.
        unsafe {}
    }
}

impl PciAccess for IoCamAccess {
    fn name(&self) -> &'static str {
        "Legacy I/O CAM"
    }

    fn max_offset(&self) -> u16 {
        255
    }
}

// ============================================================================
// PCIe ECAM Access (Memory-Mapped)
// ============================================================================

/// PCIe Enhanced Configuration Access Mechanism
///
/// Uses memory-mapped I/O to access the full 4096-byte PCIe extended
/// configuration space. The base address comes from ACPI MCFG or platform
/// configuration.
pub struct EcamAccess {
    /// ECAM base address in physical memory
    base: u64,
}

impl EcamAccess {
    /// Create a new ECAM access instance
    ///
    /// # Arguments
    /// * `base` - Physical base address of the ECAM region
    pub const fn new(base: u64) -> Self {
        Self { base }
    }

    /// Calculate the ECAM address for a given BDF and register offset
    ///
    /// ECAM address = base | (bus << 20) | (device << 15) | (function << 12) | offset
    fn ecam_address(&self, addr: PciAddress, offset: u16) -> u64 {
        debug_assert!(
            offset <= 4095,
            "ECAM offset {:#x} exceeds config space",
            offset
        );
        self.base
            | ((addr.bus() as u64) << 20)
            | ((addr.device() as u64) << 15)
            | ((addr.function() as u64) << 12)
            | ((offset as u64) & 0xFFC) // 4-byte aligned
    }
}

impl ConfigRegionAccess for EcamAccess {
    unsafe fn read(&self, addr: PciAddress, offset: u16) -> u32 {
        let mmio_addr = self.ecam_address(addr, offset) as *const u32;
        // Safety: ECAM region is mapped and valid, we only access aligned addresses
        unsafe { core::ptr::read_volatile(mmio_addr) }
    }

    unsafe fn write(&self, addr: PciAddress, offset: u16, value: u32) {
        let mmio_addr = self.ecam_address(addr, offset) as *mut u32;
        // Safety: ECAM region is mapped and valid, we only access aligned addresses
        unsafe { core::ptr::write_volatile(mmio_addr, value) }
    }
}

impl PciAccess for EcamAccess {
    fn name(&self) -> &'static str {
        "PCIe ECAM"
    }

    fn max_offset(&self) -> u16 {
        4095
    }
}

// ============================================================================
// Runtime-Selected Access Method
// ============================================================================

/// Runtime-selected PCI access method
///
/// Wraps either `IoCamAccess` or `EcamAccess` and delegates all operations.
/// This follows the same enum dispatch pattern used by `AnySpiController`
/// and `AnyBlockDevice` elsewhere in the codebase.
pub enum AnyPciAccess {
    /// Legacy I/O port-based access (0xCF8/0xCFC)
    IoCam(IoCamAccess),
    /// Memory-mapped PCIe ECAM access
    Ecam(EcamAccess),
}

impl ConfigRegionAccess for AnyPciAccess {
    unsafe fn read(&self, addr: PciAddress, offset: u16) -> u32 {
        match self {
            Self::IoCam(a) => unsafe { a.read(addr, offset) },
            Self::Ecam(a) => unsafe { a.read(addr, offset) },
        }
    }

    unsafe fn write(&self, addr: PciAddress, offset: u16, value: u32) {
        match self {
            Self::IoCam(a) => unsafe { a.write(addr, offset, value) },
            Self::Ecam(a) => unsafe { a.write(addr, offset, value) },
        }
    }
}

impl PciAccess for AnyPciAccess {
    fn name(&self) -> &'static str {
        match self {
            Self::IoCam(a) => a.name(),
            Self::Ecam(a) => a.name(),
        }
    }

    fn max_offset(&self) -> u16 {
        match self {
            Self::IoCam(a) => a.max_offset(),
            Self::Ecam(a) => a.max_offset(),
        }
    }
}

/// Create the appropriate PCI access method
///
/// If an ECAM base address is provided, uses memory-mapped ECAM access.
/// Otherwise falls back to legacy I/O port CAM access.
pub fn create_access(ecam_base: Option<u64>) -> AnyPciAccess {
    match ecam_base {
        Some(base) => {
            log::info!("PCI: Using PCIe ECAM access at {:#x}", base);
            AnyPciAccess::Ecam(EcamAccess::new(base))
        }
        None => {
            log::info!("PCI: Using legacy I/O CAM access");
            AnyPciAccess::IoCam(IoCamAccess)
        }
    }
}
