//! Bounded PCI configuration-space access through legacy CAM or ECAM.

use super::PciAddress;
use super::access_rules::{ecam_offset, valid_config_access};
use crate::drivers::mmio::MmioRegion;
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
        // A 32-bit RMW would acknowledge neighboring W1C status bits. A
        // backend must implement an actual halfword transaction instead.
        let _ = value;
        Err(ConfigAccessError::OutOfRange)
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
        // Never synthesize byte enables with a neighboring-register RMW.
        let _ = value;
        Err(ConfigAccessError::OutOfRange)
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

impl IoCamAccess {
    #[cfg(target_arch = "x86_64")]
    fn select(&self, addr: PciAddress, offset: u16, width: u16) -> Result<(), ConfigAccessError> {
        use x86_64::instructions::port::PortWriteOnly;
        if addr.segment() != 0 || !valid_config_access(255, offset, width) {
            return Err(ConfigAccessError::OutOfRange);
        }
        let mut port: PortWriteOnly<u32> = PortWriteOnly::new(PCI_CONFIG_ADDRESS);
        // The address selects a dword; data-port lane and transaction width
        // supply byte enables. Local PCI ownership is still single-CPU only.
        unsafe {
            port.write(
                1 << 31
                    | (addr.bus() as u32) << 16
                    | (addr.device() as u32) << 11
                    | (addr.function() as u32) << 8
                    | u32::from(offset & !3),
            );
        }
        Ok(())
    }
}

impl ConfigRegionAccess for IoCamAccess {
    #[cfg(target_arch = "x86_64")]
    unsafe fn read(&self, addr: PciAddress, offset: u16) -> u32 {
        use x86_64::instructions::port::Port;
        if self.select(addr, offset, 4).is_err() {
            return u32::MAX;
        }
        let mut data_port: Port<u32> = Port::new(PCI_CONFIG_DATA);
        unsafe { data_port.read() }
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn read(&self, _addr: PciAddress, _offset: u16) -> u32 {
        u32::MAX
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn write(&self, addr: PciAddress, offset: u16, value: u32) {
        use x86_64::instructions::port::Port;
        if self.select(addr, offset, 4).is_err() {
            return;
        }
        let mut data_port: Port<u32> = Port::new(PCI_CONFIG_DATA);
        unsafe { data_port.write(value) };
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn write(&self, _addr: PciAddress, _offset: u16, _value: u32) {}
}

impl PciAccess for IoCamAccess {
    fn try_read8(&self, addr: PciAddress, offset: u16) -> Result<u8, ConfigAccessError> {
        #[cfg(target_arch = "x86_64")]
        {
            use x86_64::instructions::port::Port;
            self.select(addr, offset, 1)?;
            let mut port: Port<u8> = Port::new(PCI_CONFIG_DATA + (offset & 3));
            Ok(unsafe { port.read() })
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (addr, offset);
            Err(ConfigAccessError::Unavailable)
        }
    }

    fn try_read16(&self, addr: PciAddress, offset: u16) -> Result<u16, ConfigAccessError> {
        #[cfg(target_arch = "x86_64")]
        {
            use x86_64::instructions::port::Port;
            self.select(addr, offset, 2)?;
            let mut port: Port<u16> = Port::new(PCI_CONFIG_DATA + (offset & 3));
            Ok(unsafe { port.read() })
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (addr, offset);
            Err(ConfigAccessError::Unavailable)
        }
    }

    fn try_write8(
        &self,
        addr: PciAddress,
        offset: u16,
        value: u8,
    ) -> Result<(), ConfigAccessError> {
        #[cfg(target_arch = "x86_64")]
        {
            use x86_64::instructions::port::Port;
            self.select(addr, offset, 1)?;
            let mut port: Port<u8> = Port::new(PCI_CONFIG_DATA + (offset & 3));
            unsafe { port.write(value) };
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (addr, offset, value);
            Err(ConfigAccessError::Unavailable)
        }
    }

    fn try_write16(
        &self,
        addr: PciAddress,
        offset: u16,
        value: u16,
    ) -> Result<(), ConfigAccessError> {
        #[cfg(target_arch = "x86_64")]
        {
            use x86_64::instructions::port::Port;
            self.select(addr, offset, 2)?;
            let mut port: Port<u16> = Port::new(PCI_CONFIG_DATA + (offset & 3));
            unsafe { port.write(value) };
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (addr, offset, value);
            Err(ConfigAccessError::Unavailable)
        }
    }

    fn name(&self) -> &'static str {
        "Legacy I/O CAM"
    }

    fn max_offset(&self) -> u16 {
        255
    }

    fn contains_address(&self, addr: PciAddress) -> bool {
        cfg!(target_arch = "x86_64") && addr.segment() == 0
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

    fn register(&self, addr: PciAddress, offset: u16, width: u16) -> Option<MmioRegion> {
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
            width,
        )?;
        let address = region.base.checked_add(relative)?;
        // SAFETY: the platform supplied mapped ECAM and the exact aligned
        // transaction lies inside its validated function/region bounds.
        unsafe { MmioRegion::try_new(address, usize::from(width)).ok() }
    }
}

impl ConfigRegionAccess for EcamAccess {
    unsafe fn read(&self, addr: PciAddress, offset: u16) -> u32 {
        self.register(addr, offset, 4)
            .map_or(u32::MAX, |register| register.read32(0))
    }

    unsafe fn write(&self, addr: PciAddress, offset: u16, value: u32) {
        if let Some(register) = self.register(addr, offset, 4) {
            register.write32(0, value);
        }
    }
}

impl PciAccess for EcamAccess {
    fn try_read8(&self, addr: PciAddress, offset: u16) -> Result<u8, ConfigAccessError> {
        self.register(addr, offset, 1)
            .map(|register| register.read8(0))
            .ok_or(ConfigAccessError::OutOfRange)
    }

    fn try_read16(&self, addr: PciAddress, offset: u16) -> Result<u16, ConfigAccessError> {
        self.register(addr, offset, 2)
            .map(|register| register.read16(0))
            .ok_or(ConfigAccessError::OutOfRange)
    }

    fn try_write8(
        &self,
        addr: PciAddress,
        offset: u16,
        value: u8,
    ) -> Result<(), ConfigAccessError> {
        self.register(addr, offset, 1)
            .ok_or(ConfigAccessError::OutOfRange)?
            .write8(0, value);
        Ok(())
    }

    fn try_write16(
        &self,
        addr: PciAddress,
        offset: u16,
        value: u16,
    ) -> Result<(), ConfigAccessError> {
        self.register(addr, offset, 2)
            .ok_or(ConfigAccessError::OutOfRange)?
            .write16(0, value);
        Ok(())
    }

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
    fn try_read8(&self, addr: PciAddress, offset: u16) -> Result<u8, ConfigAccessError> {
        match self {
            Self::Unavailable => Err(ConfigAccessError::Unavailable),
            Self::IoCam(access) => access.try_read8(addr, offset),
            Self::Ecam(access) => access.try_read8(addr, offset),
        }
    }

    fn try_read16(&self, addr: PciAddress, offset: u16) -> Result<u16, ConfigAccessError> {
        match self {
            Self::Unavailable => Err(ConfigAccessError::Unavailable),
            Self::IoCam(access) => access.try_read16(addr, offset),
            Self::Ecam(access) => access.try_read16(addr, offset),
        }
    }

    fn try_write8(
        &self,
        addr: PciAddress,
        offset: u16,
        value: u8,
    ) -> Result<(), ConfigAccessError> {
        match self {
            Self::Unavailable => Err(ConfigAccessError::Unavailable),
            Self::IoCam(access) => access.try_write8(addr, offset, value),
            Self::Ecam(access) => access.try_write8(addr, offset, value),
        }
    }

    fn try_write16(
        &self,
        addr: PciAddress,
        offset: u16,
        value: u16,
    ) -> Result<(), ConfigAccessError> {
        match self {
            Self::Unavailable => Err(ConfigAccessError::Unavailable),
            Self::IoCam(access) => access.try_write16(addr, offset, value),
            Self::Ecam(access) => access.try_write16(addr, offset, value),
        }
    }

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

/// Select ECAM when validly described, otherwise an explicitly permitted legacy CAM.
pub fn create_access(regions: &[PciEcamRegion], allow_legacy_cam: bool) -> AnyPciAccess {
    if let Some(ecam) = EcamAccess::new(regions) {
        log::info!("PCI: using {} ECAM allocation(s)", ecam.regions().len());
        return AnyPciAccess::Ecam(ecam);
    }

    #[cfg(target_arch = "x86_64")]
    {
        if allow_legacy_cam {
            log::info!("PCI: no ECAM supplied; using legacy segment-0 I/O CAM");
            AnyPciAccess::IoCam(IoCamAccess)
        } else {
            log::error!("PCI unavailable: explicit ECAM configuration was invalid");
            AnyPciAccess::Unavailable
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = allow_legacy_cam;
        log::warn!("PCI unavailable: no valid ECAM allocation");
        AnyPciAccess::Unavailable
    }
}

#[cfg(test)]
#[path = "access_tests.rs"]
mod tests;
