//! SPI Flash Controller Drivers
//!
//! Intel ICH/PCH and AMD SPI100 internal programming is provided by the
//! sibling `rflasher-internal` crate. CrabEFI keeps only the firmware-facing
//! adapter and the QEMU pflash backend here.

pub mod qemu;

use rflasher_internal::{Bdf, HostAccess, MmioAccess, PciConfigAccess};

use crate::drivers::{mmio::MmioRegion, pci};
use crate::platform::{FirmwareStorage, FirmwareStorageRegion, StorageError};

/// PCI access adapter backed by CrabEFI's selected PCI config-space backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct CrabEfiPciAccess;

impl CrabEfiPciAccess {
    fn addr(bdf: Bdf) -> pci::PciAddress {
        // CrabEFI currently enumerates PCI segment 0 only.
        pci::PciAddress::new(bdf.bus, bdf.device, bdf.function)
    }

    fn offset_to_u8(bdf: Bdf, offset: u16, write: bool) -> rflasher_internal::Result<u8> {
        if offset > u8::MAX as u16 {
            let error = if write {
                rflasher_internal::PciAccessError::ConfigWrite {
                    bus: bdf.bus,
                    device: bdf.device,
                    function: bdf.function,
                    register: offset,
                }
            } else {
                rflasher_internal::PciAccessError::ConfigRead {
                    bus: bdf.bus,
                    device: bdf.device,
                    function: bdf.function,
                    register: offset,
                }
            };
            return Err(rflasher_internal::InternalError::PciAccess(error));
        }

        Ok(offset as u8)
    }
}

impl PciConfigAccess for CrabEfiPciAccess {
    fn read8(&self, bdf: Bdf, offset: u16) -> rflasher_internal::Result<u8> {
        let offset = Self::offset_to_u8(bdf, offset, false)?;
        Ok(pci::read_config_u8(Self::addr(bdf), offset))
    }

    fn read16(&self, bdf: Bdf, offset: u16) -> rflasher_internal::Result<u16> {
        let offset = Self::offset_to_u8(bdf, offset, false)?;
        Ok(pci::read_config_u16(Self::addr(bdf), offset))
    }

    fn read32(&self, bdf: Bdf, offset: u16) -> rflasher_internal::Result<u32> {
        let offset = Self::offset_to_u8(bdf, offset, false)?;
        Ok(pci::read_config_u32(Self::addr(bdf), offset))
    }

    fn write8(&self, bdf: Bdf, offset: u16, value: u8) -> rflasher_internal::Result<()> {
        let offset = Self::offset_to_u8(bdf, offset, true)?;
        pci::write_config_u8(Self::addr(bdf), offset, value);
        Ok(())
    }

    fn write16(&self, bdf: Bdf, offset: u16, value: u16) -> rflasher_internal::Result<()> {
        let offset = Self::offset_to_u8(bdf, offset, true)?;
        pci::write_config_u16(Self::addr(bdf), offset, value);
        Ok(())
    }

    fn write32(&self, bdf: Bdf, offset: u16, value: u32) -> rflasher_internal::Result<()> {
        let offset = Self::offset_to_u8(bdf, offset, true)?;
        pci::write_config_u32(Self::addr(bdf), offset, value);
        Ok(())
    }
}

impl MmioAccess for MmioRegion {
    fn read8(&self, offset: usize) -> u8 {
        MmioRegion::read8(self, offset as u64)
    }

    fn read16(&self, offset: usize) -> u16 {
        MmioRegion::read16(self, offset as u64)
    }

    fn read32(&self, offset: usize) -> u32 {
        MmioRegion::read32(self, offset as u64)
    }

    fn write8(&self, offset: usize, value: u8) {
        MmioRegion::write8(self, offset as u64, value);
    }

    fn write16(&self, offset: usize, value: u16) {
        MmioRegion::write16(self, offset as u64, value);
    }

    fn write32(&self, offset: usize, value: u32) {
        MmioRegion::write32(self, offset as u64, value);
    }
}

impl HostAccess for CrabEfiPciAccess {
    type MmioRegion = MmioRegion;

    unsafe fn map_mmio(
        &self,
        phys_addr: u64,
        size: usize,
    ) -> rflasher_internal::Result<Self::MmioRegion> {
        // SAFETY: rflasher only requests controller register windows discovered
        // from chipset PCI configuration. CrabEFI runs with identity-mapped MMIO.
        Ok(unsafe { MmioRegion::new(phys_addr, size) })
    }

    fn delay_us(&self, us: u32) {
        crate::time::delay_us(us as u64);
    }
}

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
    /// Address out of range for flash size
    AddressOutOfRange,
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

/// Unified SPI controller trait used by CrabEFI's variable-store backend.
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

    /// Get the BIOS region from flash descriptor (Intel IFD)
    ///
    /// Returns (base, limit) in flash offsets, or None if not available.
    fn get_bios_region(&self) -> Option<(u32, u32)>;
}

/// Enum containing an rflasher Intel/AMD controller or CrabEFI QEMU pflash.
pub enum AnySpiController {
    Intel(rflasher_internal::IchSpiController<CrabEfiPciAccess>),
    Amd(rflasher_internal::Spi100Controller<CrabEfiPciAccess>),
    Qemu(qemu::QemuPflashController),
}

impl FirmwareStorage for AnySpiController {
    fn name(&self) -> &str {
        SpiController::name(self)
    }

    fn capacity(&self) -> Option<u64> {
        match self {
            Self::Qemu(c) => Some(c.flash_size() as u64),
            Self::Intel(_) | Self::Amd(_) => None,
        }
    }

    fn validate_region(&self, region: FirmwareStorageRegion) -> Option<FirmwareStorageRegion> {
        if region.size == 0 {
            return None;
        }

        let end = region.offset.checked_add(region.size)?;
        if end > u32::MAX as u64 + 1 {
            return None;
        }

        if let Some(capacity) = self.capacity()
            && end > capacity
        {
            return None;
        }

        Some(region)
    }

    fn enable_writes(&mut self) -> core::result::Result<(), StorageError> {
        SpiController::enable_writes(self).map_err(spi_error_to_storage_error)
    }

    fn read(&mut self, offset: u64, buffer: &mut [u8]) -> core::result::Result<(), StorageError> {
        let offset = u32::try_from(offset).map_err(|_| StorageError::InvalidArgument)?;
        SpiController::read(self, offset, buffer).map_err(spi_error_to_storage_error)
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> core::result::Result<(), StorageError> {
        let offset = u32::try_from(offset).map_err(|_| StorageError::InvalidArgument)?;
        SpiController::write(self, offset, data).map_err(spi_error_to_storage_error)
    }

    fn erase(&mut self, offset: u64, size: u64) -> core::result::Result<(), StorageError> {
        let offset = u32::try_from(offset).map_err(|_| StorageError::InvalidArgument)?;
        let size = u32::try_from(size).map_err(|_| StorageError::InvalidArgument)?;
        SpiController::erase(self, offset, size).map_err(spi_error_to_storage_error)
    }
}

fn spi_error_to_storage_error(e: SpiError) -> StorageError {
    match e {
        SpiError::WriteProtected => StorageError::WriteProtected,
        SpiError::AccessDenied => StorageError::AccessDenied,
        SpiError::Timeout => StorageError::Timeout,
        SpiError::InvalidArgument | SpiError::AddressOutOfRange => StorageError::InvalidArgument,
        SpiError::NotSupported => StorageError::NotSupported,
        _ => StorageError::IoError,
    }
}

impl SpiController for AnySpiController {
    fn name(&self) -> &'static str {
        match self {
            Self::Intel(_) => "Intel ICH/PCH SPI",
            Self::Amd(_) => "AMD SPI100",
            Self::Qemu(c) => c.name(),
        }
    }

    fn is_locked(&self) -> bool {
        use rflasher_internal::controller::Controller;

        match self {
            Self::Intel(c) => c.is_locked(),
            Self::Amd(c) => c.is_locked(),
            Self::Qemu(c) => c.is_locked(),
        }
    }

    fn writes_enabled(&self) -> bool {
        use rflasher_internal::controller::Controller;

        match self {
            Self::Intel(c) => c.writes_enabled(),
            Self::Amd(c) => c.writes_enabled(),
            Self::Qemu(c) => c.writes_enabled(),
        }
    }

    fn enable_writes(&mut self) -> Result<()> {
        use rflasher_internal::controller::Controller;

        match self {
            Self::Intel(c) => c.enable_bios_write().map_err(map_internal_error),
            Self::Amd(c) => c.enable_bios_write().map_err(map_internal_error),
            Self::Qemu(c) => c.enable_writes(),
        }
    }

    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<()> {
        use rflasher_internal::controller::Controller;

        match self {
            Self::Intel(c) => c.controller_read(addr, buf, 0).map_err(map_core_error),
            Self::Amd(c) => c.controller_read(addr, buf, 0).map_err(map_core_error),
            Self::Qemu(c) => c.read(addr, buf),
        }
    }

    fn write(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        use rflasher_internal::controller::Controller;

        match self {
            Self::Intel(c) => c.controller_write(addr, data).map_err(map_core_error),
            Self::Amd(c) => c.controller_write(addr, data).map_err(map_core_error),
            Self::Qemu(c) => c.write(addr, data),
        }
    }

    fn erase(&mut self, addr: u32, len: u32) -> Result<()> {
        use rflasher_internal::controller::Controller;

        match self {
            Self::Intel(c) => c.controller_erase(addr, len).map_err(map_core_error),
            Self::Amd(c) => c.controller_erase(addr, len).map_err(map_core_error),
            Self::Qemu(c) => c.erase(addr, len),
        }
    }

    fn mode(&self) -> SpiMode {
        match self {
            Self::Intel(c) => match c.mode() {
                rflasher_internal::SpiMode::Auto => SpiMode::Auto,
                rflasher_internal::SpiMode::HardwareSequencing => SpiMode::HardwareSequencing,
                rflasher_internal::SpiMode::SoftwareSequencing => SpiMode::SoftwareSequencing,
            },
            Self::Amd(_) => SpiMode::SoftwareSequencing,
            Self::Qemu(c) => c.mode(),
        }
    }

    fn get_bios_region(&self) -> Option<(u32, u32)> {
        match self {
            Self::Intel(c) => c.get_bios_region(),
            Self::Amd(_) => None,
            Self::Qemu(c) => c.get_bios_region(),
        }
    }
}

fn map_internal_error(error: rflasher_internal::InternalError) -> SpiError {
    match error {
        rflasher_internal::InternalError::NoChipset => SpiError::NoChipset,
        rflasher_internal::InternalError::UnsupportedChipset { .. } => SpiError::UnsupportedChipset,
        rflasher_internal::InternalError::MultipleChipsets => SpiError::UnsupportedChipset,
        rflasher_internal::InternalError::PciAccess(_) => SpiError::InitFailed,
        rflasher_internal::InternalError::MemoryMap { .. } => SpiError::InitFailed,
        rflasher_internal::InternalError::ChipsetEnable(_) => SpiError::InitFailed,
        rflasher_internal::InternalError::SpiInit(_) => SpiError::InitFailed,
        rflasher_internal::InternalError::AccessDenied { .. } => SpiError::AccessDenied,
        rflasher_internal::InternalError::InvalidDescriptor => SpiError::InvalidDescriptor,
        rflasher_internal::InternalError::NotSupported(_) => SpiError::NotSupported,
        rflasher_internal::InternalError::Io(_) => SpiError::CycleError,
    }
}

fn map_core_error(error: rflasher_core::error::Error) -> SpiError {
    use rflasher_core::error::Error;

    match error {
        Error::SpiTimeout | Error::Timeout => SpiError::Timeout,
        Error::AddressOutOfBounds => SpiError::AddressOutOfRange,
        Error::InvalidAlignment | Error::BufferTooSmall => SpiError::InvalidArgument,
        Error::WriteProtected => SpiError::WriteProtected,
        Error::RegionProtected => SpiError::AccessDenied,
        Error::OpcodeNotSupported | Error::IoModeNotSupported => SpiError::NotSupported,
        Error::EraseError(_) | Error::WriteError { .. } | Error::ReadError { .. } => {
            SpiError::CycleError
        }
        _ => SpiError::CycleError,
    }
}

type RflasherPciDevices =
    heapless::Vec<rflasher_internal::PciDevice, { crate::state::MAX_PCI_DEVICES }>;

fn rflasher_pci_device(dev: &pci::PciDevice) -> rflasher_internal::PciDevice {
    let class =
        ((dev.class_code as u32) << 16) | ((dev.subclass as u32) << 8) | (dev.prog_if as u32);

    rflasher_internal::PciDevice {
        domain: 0,
        bus: dev.address.bus,
        device: dev.address.device,
        function: dev.address.function,
        vendor_id: dev.vendor_id,
        device_id: dev.device_id,
        revision_id: dev.revision,
        class,
    }
}

fn rflasher_pci_devices() -> RflasherPciDevices {
    let devices = pci::get_all_devices();
    let mut result = heapless::Vec::new();

    for rdev in devices.iter().map(rflasher_pci_device) {
        if result.push(rdev).is_err() {
            log::warn!("rflasher PCI device list full");
            break;
        }
    }

    result
}

/// Detect and initialize the SPI controller.
///
/// Detection order:
/// 1. Check if running in QEMU - if so, prefer pflash backend.
/// 2. Try rflasher's Intel/AMD internal programmer support for real hardware.
/// 3. Fall back to QEMU pflash if nothing else works.
pub fn detect_and_init() -> Option<AnySpiController> {
    if cfg!(target_arch = "aarch64") || cfg!(target_arch = "riscv64") {
        log::debug!("SPI flash detection skipped on non-x86 (no memory-mapped SPI flash)");
        return None;
    }

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
            Err(e) => log::warn!("QEMU pflash not available: {:?}", e),
        }
    }

    let devices = rflasher_pci_devices();

    match rflasher_internal::find_intel_chipset_in_devices(&devices) {
        Ok(Some(chipset)) => {
            log::info!(
                "Found Intel chipset: {} {}",
                chipset.vendor(),
                chipset.name()
            );
            chipset.log_warnings();
            match rflasher_internal::IchSpiController::new_with_host(
                CrabEfiPciAccess,
                &chipset,
                rflasher_internal::SpiMode::Auto,
            ) {
                Ok(controller) => {
                    log::info!(
                        "Intel SPI controller initialized in {} mode",
                        controller.mode()
                    );
                    return Some(AnySpiController::Intel(controller));
                }
                Err(e) => log::error!("Failed to initialize Intel SPI controller: {}", e),
            }
        }
        Ok(None) => {}
        Err(e) => log::warn!("Intel SPI chipset detection failed: {}", e),
    }

    match rflasher_internal::find_amd_chipset_in_devices(&devices) {
        Ok(Some(chipset)) => {
            log::info!("Found AMD chipset: {} {}", chipset.vendor(), chipset.name());
            chipset.log_warnings();
            match rflasher_internal::enable_amd_spi100_with_host(
                &CrabEfiPciAccess,
                chipset.enable,
                Bdf::with_segment(chipset.domain, chipset.bus, chipset.device, 0),
                chipset.revision_id,
            )
            .and_then(|info| info.create_controller_with_host(CrabEfiPciAccess))
            {
                Ok(controller) => {
                    log::info!("AMD SPI100 controller initialized");
                    return Some(AnySpiController::Amd(controller));
                }
                Err(e) => log::error!("Failed to initialize AMD SPI100 controller: {}", e),
            }
        }
        Ok(None) => {}
        Err(e) => log::warn!("AMD SPI chipset detection failed: {}", e),
    }

    log::warn!("No SPI controller found");
    None
}

// Re-export delay functions from the calibrated time module for the QEMU backend.
pub use crate::time::{delay_ms, delay_us};
