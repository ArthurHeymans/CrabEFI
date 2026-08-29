//! Bounded PCI configuration-space access through legacy CAM or ECAM.

use super::PciAddress;
use super::access_rules::{ecam_offset, valid_config_access};
use crate::fdt::MAX_ECAM_REGIONS;
use crate::platform::PciEcamRegion;
use pci_types::ConfigRegionAccess;

/// Checked PCI configuration access failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigAccessError {
    /// Offset, width, alignment, segment, or bus is unsupported by the backend.
    OutOfRange,
    /// No PCI configuration backend is available.
    Unavailable,
}

/// PCI configuration-space access with release-effective bounds checks.
pub trait PciAccess: ConfigRegionAccess {
    /// Name of this access method (for logging).
    fn name(&self) -> &'static str;

    /// Maximum config-space byte offset supported by this backend.
    fn max_offset(&self) -> u16;

    /// Whether this backend can reach the supplied address.
    fn contains_address(&self, addr: PciAddress) -> bool;

    /// Read a checked 32-bit configuration register.
    fn try_read32(&self, addr: PciAddress, offset: u16) -> Result<u32, ConfigAccessError> {
        if !self.contains_address(addr) || !valid_config_access(self.max_offset(), offset, 4) {
            return Err(ConfigAccessError::OutOfRange);
        }
        // SAFETY: backend membership, alignment, and bounds were checked above.
        Ok(unsafe { self.read(addr, offset) })
    }

    /// Write a checked 32-bit configuration register.
    fn try_write32(
        &self,
        addr: PciAddress,
        offset: u16,
        value: u32,
    ) -> Result<(), ConfigAccessError> {
        if !self.contains_address(addr) || !valid_config_access(self.max_offset(), offset, 4) {
            return Err(ConfigAccessError::OutOfRange);
        }
        // SAFETY: backend membership, alignment, and bounds were checked above.
        unsafe { self.write(addr, offset, value) };
        Ok(())
    }

    /// Read a 32-bit value, returning PCI's all-ones error value on invalid access.
    fn read32(&self, addr: PciAddress, offset: u16) -> u32 {
        self.try_read32(addr, offset).unwrap_or_else(|error| {
            log::warn!(
                "PCI {} read rejected at {} offset {:#x}: {:?}",
                self.name(),
                addr,
                offset,
                error
            );
            u32::MAX
        })
    }

    /// Write a 32-bit value, ignoring invalid accesses.
    fn write32(&self, addr: PciAddress, offset: u16, value: u32) {
        if let Err(error) = self.try_write32(addr, offset, value) {
            log::warn!(
                "PCI {} write rejected at {} offset {:#x}: {:?}",
                self.name(),
                addr,
                offset,
                error
            );
        }
    }

    /// Read a checked 16-bit value.
    fn try_read16(&self, addr: PciAddress, offset: u16) -> Result<u16, ConfigAccessError> {
        if !valid_config_access(self.max_offset(), offset, 2) || !self.contains_address(addr) {
            return Err(ConfigAccessError::OutOfRange);
        }
        let value = self.try_read32(addr, offset & !0x3)?;
        Ok(((value >> ((offset & 0x02) * 8)) & 0xffff) as u16)
    }

    /// Write a checked 16-bit value.
    fn try_write16(
        &self,
        addr: PciAddress,
        offset: u16,
        value: u16,
    ) -> Result<(), ConfigAccessError> {
        if !valid_config_access(self.max_offset(), offset, 2) || !self.contains_address(addr) {
            return Err(ConfigAccessError::OutOfRange);
        }
        let aligned = offset & !0x3;
        let shift = (offset & 0x02) * 8;
        let current = self.try_read32(addr, aligned)?;
        self.try_write32(
            addr,
            aligned,
            (current & !(0xffff_u32 << shift)) | ((value as u32) << shift),
        )
    }

    /// Read a 16-bit value, returning all ones on invalid access.
    fn read16(&self, addr: PciAddress, offset: u16) -> u16 {
        self.try_read16(addr, offset).unwrap_or(u16::MAX)
    }

    /// Write a 16-bit value, ignoring invalid access.
    fn write16(&self, addr: PciAddress, offset: u16, value: u16) {
        let _ = self.try_write16(addr, offset, value);
    }

    /// Read a checked 8-bit value.
    fn try_read8(&self, addr: PciAddress, offset: u16) -> Result<u8, ConfigAccessError> {
        if !valid_config_access(self.max_offset(), offset, 1) || !self.contains_address(addr) {
            return Err(ConfigAccessError::OutOfRange);
        }
        let value = self.try_read32(addr, offset & !0x3)?;
        Ok(((value >> ((offset & 0x03) * 8)) & 0xff) as u8)
    }

    /// Write a checked 8-bit value.
    fn try_write8(
        &self,
        addr: PciAddress,
        offset: u16,
        value: u8,
    ) -> Result<(), ConfigAccessError> {
        if !valid_config_access(self.max_offset(), offset, 1) || !self.contains_address(addr) {
            return Err(ConfigAccessError::OutOfRange);
        }
        let aligned = offset & !0x3;
        let shift = (offset & 0x03) * 8;
        let current = self.try_read32(addr, aligned)?;
        self.try_write32(
            addr,
            aligned,
            (current & !(0xff_u32 << shift)) | ((value as u32) << shift),
        )
    }

    /// Read an 8-bit value, returning all ones on invalid access.
    fn read8(&self, addr: PciAddress, offset: u16) -> u8 {
        self.try_read8(addr, offset).unwrap_or(u8::MAX)
    }

    /// Write an 8-bit value, ignoring invalid access.
    fn write8(&self, addr: PciAddress, offset: u16, value: u8) {
        let _ = self.try_write8(addr, offset, value);
    }
}

#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_ADDRESS: u16 = 0xcf8;
#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_DATA: u16 = 0xcfc;

/// Legacy x86 CF8/CFC configuration mechanism (segment 0, first 256 bytes).
pub struct IoCamAccess;

impl ConfigRegionAccess for IoCamAccess {
    #[cfg(target_arch = "x86_64")]
    unsafe fn read(&self, addr: PciAddress, offset: u16) -> u32 {
        use x86_64::instructions::port::{Port, PortWriteOnly};
        if addr.segment() != 0 || !valid_config_access(255, offset, 4) {
            return u32::MAX;
        }
        let mut address_port: PortWriteOnly<u32> = PortWriteOnly::new(PCI_CONFIG_ADDRESS);
        let mut data_port: Port<u32> = Port::new(PCI_CONFIG_DATA);
        unsafe {
            address_port.write(
                1 << 31
                    | (addr.bus() as u32) << 16
                    | (addr.device() as u32) << 11
                    | (addr.function() as u32) << 8
                    | offset as u32,
            );
            data_port.read()
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn read(&self, _addr: PciAddress, _offset: u16) -> u32 {
        u32::MAX
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn write(&self, addr: PciAddress, offset: u16, value: u32) {
        use x86_64::instructions::port::{Port, PortWriteOnly};
        if addr.segment() != 0 || !valid_config_access(255, offset, 4) {
            return;
        }
        let mut address_port: PortWriteOnly<u32> = PortWriteOnly::new(PCI_CONFIG_ADDRESS);
        let mut data_port: Port<u32> = Port::new(PCI_CONFIG_DATA);
        unsafe {
            address_port.write(
                1 << 31
                    | (addr.bus() as u32) << 16
                    | (addr.device() as u32) << 11
                    | (addr.function() as u32) << 8
                    | offset as u32,
            );
            data_port.write(value);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn write(&self, _addr: PciAddress, _offset: u16, _value: u32) {}
}

impl PciAccess for IoCamAccess {
    fn name(&self) -> &'static str {
        "Legacy I/O CAM"
    }

    fn max_offset(&self) -> u16 {
        255
    }

    fn contains_address(&self, addr: PciAddress) -> bool {
        addr.segment() == 0
    }
}

/// One or more validated PCIe ECAM allocations.
pub struct EcamAccess {
    regions: heapless::Vec<PciEcamRegion, MAX_ECAM_REGIONS>,
}

impl EcamAccess {
    /// Build an ECAM backend from validated, non-overlapping allocations.
    pub fn new(regions: &[PciEcamRegion]) -> Option<Self> {
        let mut stored = heapless::Vec::new();
        for &region in regions {
            if !region.is_valid()
                || stored.iter().any(|current: &PciEcamRegion| {
                    current.segment == region.segment
                        && current.bus_start <= region.bus_end
                        && region.bus_start <= current.bus_end
                })
                || stored.push(region).is_err()
            {
                return None;
            }
        }
        (!stored.is_empty()).then_some(Self { regions: stored })
    }

    /// Return represented regions for bounded enumeration.
    pub fn regions(&self) -> &[PciEcamRegion] {
        self.regions.as_slice()
    }

    fn address(&self, addr: PciAddress, offset: u16) -> Option<u64> {
        let region = self.regions.iter().find(|region| {
            region.segment == addr.segment()
                && region.bus_start <= addr.bus()
                && addr.bus() <= region.bus_end
        })?;
        let relative = ecam_offset(
            region.segment,
            region.bus_start,
            region.bus_end,
            addr.segment(),
            addr.bus(),
            addr.device(),
            addr.function(),
            offset,
            4,
        )?;
        region.base.checked_add(relative)
    }
}

impl ConfigRegionAccess for EcamAccess {
    unsafe fn read(&self, addr: PciAddress, offset: u16) -> u32 {
        let Some(address) = self.address(addr, offset) else {
            return u32::MAX;
        };
        // SAFETY: address is aligned and contained in a validated ECAM allocation.
        unsafe { core::ptr::read_volatile(address as *const u32) }
    }

    unsafe fn write(&self, addr: PciAddress, offset: u16, value: u32) {
        let Some(address) = self.address(addr, offset) else {
            return;
        };
        // SAFETY: address is aligned and contained in a validated ECAM allocation.
        unsafe { core::ptr::write_volatile(address as *mut u32, value) };
    }
}

impl PciAccess for EcamAccess {
    fn name(&self) -> &'static str {
        "PCIe ECAM"
    }

    fn max_offset(&self) -> u16 {
        4095
    }

    fn contains_address(&self, addr: PciAddress) -> bool {
        self.regions.iter().any(|region| {
            region.segment == addr.segment()
                && region.bus_start <= addr.bus()
                && addr.bus() <= region.bus_end
        })
    }
}

/// Runtime-selected PCI configuration backend.
pub enum AnyPciAccess {
    /// PCI is not described on this platform.
    Unavailable,
    /// Legacy x86 CF8/CFC access.
    IoCam(IoCamAccess),
    /// One or more PCIe ECAM allocations.
    Ecam(EcamAccess),
}

impl ConfigRegionAccess for AnyPciAccess {
    unsafe fn read(&self, addr: PciAddress, offset: u16) -> u32 {
        match self {
            Self::Unavailable => u32::MAX,
            Self::IoCam(access) => unsafe { access.read(addr, offset) },
            Self::Ecam(access) => unsafe { access.read(addr, offset) },
        }
    }

    unsafe fn write(&self, addr: PciAddress, offset: u16, value: u32) {
        match self {
            Self::Unavailable => {}
            Self::IoCam(access) => unsafe { access.write(addr, offset, value) },
            Self::Ecam(access) => unsafe { access.write(addr, offset, value) },
        }
    }
}

impl PciAccess for AnyPciAccess {
    fn name(&self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::IoCam(access) => access.name(),
            Self::Ecam(access) => access.name(),
        }
    }

    fn max_offset(&self) -> u16 {
        match self {
            Self::Unavailable => 0,
            Self::IoCam(access) => access.max_offset(),
            Self::Ecam(access) => access.max_offset(),
        }
    }

    fn contains_address(&self, addr: PciAddress) -> bool {
        match self {
            Self::Unavailable => false,
            Self::IoCam(access) => access.contains_address(addr),
            Self::Ecam(access) => access.contains_address(addr),
        }
    }

    fn try_read32(&self, addr: PciAddress, offset: u16) -> Result<u32, ConfigAccessError> {
        if matches!(self, Self::Unavailable) {
            Err(ConfigAccessError::Unavailable)
        } else if !self.contains_address(addr) || !valid_config_access(self.max_offset(), offset, 4)
        {
            Err(ConfigAccessError::OutOfRange)
        } else {
            // SAFETY: membership, alignment, and bounds were checked above.
            Ok(unsafe { self.read(addr, offset) })
        }
    }
}

/// Select ECAM when described, otherwise x86 legacy CAM or unavailable PCI.
pub fn create_access(regions: &[PciEcamRegion]) -> AnyPciAccess {
    if let Some(ecam) = EcamAccess::new(regions) {
        log::info!("PCI: using {} ECAM allocation(s)", ecam.regions().len());
        return AnyPciAccess::Ecam(ecam);
    }

    #[cfg(target_arch = "x86_64")]
    {
        log::info!("PCI: no ECAM; using legacy segment-0 I/O CAM");
        AnyPciAccess::IoCam(IoCamAccess)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        log::warn!("PCI unavailable: no valid ECAM allocation");
        AnyPciAccess::Unavailable
    }
}
