//! QEMU pflash SPI Storage Backend
//!
//! This module implements a storage backend for QEMU's pflash device.
//! QEMU's -pflash option provides both firmware storage and UEFI variable
//! storage through memory-mapped flash.
//!
//! # Architecture
//!
//! QEMU's pflash is memory-mapped at the end of the 32-bit address space.
//! Platforms can provide the exact mapping before detection, or the driver can
//! fall back to probing common QEMU pflash addresses.
//!
//! For example, a 16MB flash might be mapped as:
//! - flash_base=0x000000, host_base=0xFF000000, size=0x1000000
//!
//! # Detection
//!
//! QEMU is detected by:
//! 1. Presence of QEMU-specific PCI devices (fw_cfg, bochs-display, etc.)
//! 2. Direct probing of flash at expected addresses
//!
//! # Platform configuration
//!
//! Platform code that already knows the pflash host mapping can call
//! [`configure_pflash()`] before SPI detection. Otherwise, detection probes
//! common QEMU mappings.

use spin::Mutex;

use super::{Result, SpiController, SpiError, SpiMode};
use crate::drivers::mmio::MmioRegion;
use crate::drivers::pci;

/// QEMU ISA bridge vendor ID (Intel)
pub const QEMU_ISA_VID: u16 = 0x8086;
/// QEMU ISA bridge device IDs
pub const QEMU_ISA_PIIX3: u16 = 0x7000;
pub const QEMU_ISA_PIIX4: u16 = 0x7110;
pub const QEMU_ISA_ICH9: u16 = 0x2918;

/// Red Hat / QEMU vendor ID
pub const QEMU_RH_VID: u16 = 0x1b36;
/// QEMU fw_cfg device ID
pub const QEMU_FW_CFG_DID: u16 = 0x0005;
/// QEMU NVMe controller device ID  
pub const QEMU_NVME_DID: u16 = 0x0010;
/// QEMU XHCI controller device ID
pub const QEMU_XHCI_DID: u16 = 0x000d;
/// QEMU VGA device (bochs-display)
pub const QEMU_VGA_VID: u16 = 0x1234;
pub const QEMU_VGA_DID: u16 = 0x1111;

/// Flash erase block size (4KB typical for NOR flash emulation)
const ERASE_BLOCK_SIZE: u32 = 4096;

/// Flash command: Read Array (return to normal read mode)
const CMD_READ_ARRAY: u8 = 0xFF;
/// Flash command: Write Byte (QEMU pflash uses 0x10, not 0x40)
const CMD_WRITE_BYTE: u8 = 0x10;
/// Flash command: Block Erase Setup
const CMD_ERASE_SETUP: u8 = 0x20;
/// Flash command: Block Erase Confirm
const CMD_ERASE_CONFIRM: u8 = 0xD0;
/// Flash command: Read Status
const CMD_READ_STATUS: u8 = 0x70;
/// Flash command: Clear Status
const CMD_CLEAR_STATUS: u8 = 0x50;

/// Cleared array status (flash ready, no errors)
const CLEARED_ARRAY_STATUS: u8 = 0x00;
/// Status register: Program error bit
const STATUS_PROGRAM_ERROR: u8 = 0x10;

/// Explicit QEMU pflash configuration provided by platform code.
#[derive(Clone, Copy, Debug)]
pub struct QemuPflashConfig {
    /// Host physical base address where pflash is mapped.
    pub host_base: u64,
    /// Total flash size in bytes.
    pub flash_size: u32,
}

static PFLASH_CONFIG: Mutex<Option<QemuPflashConfig>> = Mutex::new(None);

/// Configure QEMU pflash mapping before SPI detection.
pub fn configure_pflash(host_base: u64, flash_size: u32) {
    *PFLASH_CONFIG.lock() = Some(QemuPflashConfig {
        host_base,
        flash_size,
    });
}

/// QEMU pflash Controller
///
/// This controller provides direct access to QEMU's pflash device.
/// QEMU emulates Intel-style NOR flash (P30 family) which supports:
/// - CFI query for device identification
/// - Byte/word programming
/// - Block erase
pub struct QemuPflashController {
    /// Memory-mapped pflash region
    pflash: MmioRegion,
    /// Host base address where flash is mapped
    host_base: u64,
    /// Total flash size in bytes
    flash_size: u32,
    /// Whether CFI was detected (use command sequences vs direct writes)
    cfi_detected: bool,
}

impl QemuPflashController {
    /// Create a new QEMU pflash controller
    ///
    /// This first tries explicit platform configuration, then falls back to
    /// probing known QEMU pflash mappings.
    pub fn new() -> Result<Self> {
        // First verify we're running on QEMU by checking for QEMU devices
        if !Self::is_qemu_environment() {
            log::debug!("Not running in QEMU environment");
            return Err(SpiError::NoChipset);
        }

        if let Some(config) = *PFLASH_CONFIG.lock() {
            log::info!(
                "QEMU pflash: using platform config: host={:#x}, size={} MB",
                config.host_base,
                config.flash_size / (1024 * 1024)
            );
            return Self::init_with_config(config.host_base, config.flash_size);
        }

        // Fall back to probing known addresses
        log::info!("QEMU pflash: no platform config, probing...");
        Self::probe_and_init()
    }

    /// Initialize with a specific pflash mapping.
    /// Return total flash size in bytes.
    pub fn flash_size(&self) -> u32 {
        self.flash_size
    }

    fn init_with_config(host_base: u64, flash_size: u32) -> Result<Self> {
        // SAFETY: host_base is a platform-provided or known QEMU pflash MMIO
        // base address, valid for the flash region.
        let pflash = unsafe {
            MmioRegion::try_new(host_base, flash_size as usize).map_err(|e| {
                log::error!("QEMU pflash MMIO region invalid at {host_base:#x}: {e}");
                SpiError::InvalidArgument
            })?
        };

        let mut controller = Self {
            pflash,
            host_base,
            flash_size,
            cfi_detected: false,
        };

        // Probe to detect CFI vs direct mode
        controller.detect_flash_mode()?;

        Ok(controller)
    }

    /// Probe known addresses and initialize
    fn probe_and_init() -> Result<Self> {
        // Try different possible pflash configurations
        // QEMU maps pflash from top of 4GB downward
        let configs_to_try: &[(u64, u32)] = &[
            (0xFF000000, 16 * 1024 * 1024), // 16MB flash
            (0xFE000000, 32 * 1024 * 1024), // 32MB flash
            (0xFF800000, 8 * 1024 * 1024),  // 8MB flash
            (0xFFC00000, 4 * 1024 * 1024),  // 4MB flash
        ];

        for &(host_base, flash_size) in configs_to_try {
            log::info!(
                "QEMU pflash: probing {} MB at {:#x}...",
                flash_size / (1024 * 1024),
                host_base
            );

            if let Ok(controller) = Self::try_init_at(host_base, flash_size) {
                return Ok(controller);
            }
        }

        log::error!("QEMU pflash: no writable flash found at any address");
        Err(SpiError::WriteProtected)
    }

    /// Try to initialize pflash at a specific address
    fn try_init_at(host_base: u64, flash_size: u32) -> Result<Self> {
        // SAFETY: host_base is a candidate pflash MMIO address from a known
        // QEMU configuration, validated by subsequent read probes below.
        let pflash = unsafe {
            MmioRegion::try_new(host_base, flash_size as usize).map_err(|e| {
                log::debug!("QEMU pflash probe at {host_base:#x} rejected: {e}");
                SpiError::InvalidArgument
            })?
        };

        // Verify this is pflash by probing for plausible flash contents.
        // Try to find a suitable test byte (not 0xFF, not ending in 0)
        let mut test_offset = 0u64;
        let mut found_suitable = false;

        while test_offset < 0x1000 {
            let byte = pflash.read8(test_offset);
            if byte != 0xFF && (byte & 0x0F) != 0 {
                found_suitable = true;
                break;
            }
            test_offset += 1;
        }

        if !found_suitable {
            // Try blank flash detection
            test_offset = 0;
            pflash.write8(test_offset, CMD_CLEAR_STATUS);
            pflash.write8(test_offset, CMD_READ_STATUS);
            let status = pflash.read8(test_offset);

            if status != CLEARED_ARRAY_STATUS {
                pflash.write8(test_offset, CMD_READ_ARRAY);
                return Err(SpiError::NoChipset);
            }
        }

        let original = pflash.read8(test_offset);

        // Write CLEAR_STATUS_CMD to detect flash type
        pflash.write8(test_offset, CMD_CLEAR_STATUS);
        let readback = pflash.read8(test_offset);

        if readback == CMD_CLEAR_STATUS {
            // RAM mode - direct writes work
            pflash.write8(test_offset, original);
            log::info!("QEMU pflash at {:#x}: RAM mode (direct writes)", host_base);

            return Ok(Self {
                pflash,
                host_base,
                flash_size,
                cfi_detected: false,
            });
        }

        // Check if it's pflash
        pflash.write8(test_offset, CMD_READ_STATUS);
        let status = pflash.read8(test_offset);

        if status == original {
            // ROM - read only
            return Err(SpiError::WriteProtected);
        }

        if status == CLEARED_ARRAY_STATUS {
            // pflash detected - test writability
            pflash.write8(test_offset, CMD_WRITE_BYTE);
            pflash.write8(test_offset, original);

            pflash.write8(test_offset, CMD_READ_STATUS);
            let write_status = pflash.read8(test_offset);

            pflash.write8(test_offset, CMD_READ_ARRAY);

            if (write_status & STATUS_PROGRAM_ERROR) != 0 {
                return Err(SpiError::WriteProtected);
            }

            log::info!(
                "QEMU pflash at {:#x}: {} MB writable flash",
                host_base,
                flash_size / (1024 * 1024)
            );

            return Ok(Self {
                pflash,
                host_base,
                flash_size,
                cfi_detected: true,
            });
        }

        Err(SpiError::NoChipset)
    }

    /// Detect flash mode (CFI command sequences vs direct writes)
    fn detect_flash_mode(&mut self) -> Result<()> {
        // Try to find a suitable test byte
        let mut test_offset = 0u64;

        while test_offset < 0x1000 {
            let byte = self.pflash.read8(test_offset);
            if byte != 0xFF && (byte & 0x0F) != 0 {
                break;
            }
            test_offset += 1;
        }

        let original = self.pflash.read8(test_offset);

        // Write CLEAR_STATUS_CMD to detect flash type
        self.pflash.write8(test_offset, CMD_CLEAR_STATUS);
        let readback = self.pflash.read8(test_offset);

        if readback == CMD_CLEAR_STATUS {
            // RAM mode
            self.pflash.write8(test_offset, original);
            self.cfi_detected = false;
            log::info!(
                "QEMU pflash: RAM mode at {:#x}, {} MB",
                self.host_base,
                self.flash_size / (1024 * 1024)
            );
            return Ok(());
        }

        // Check pflash status
        self.pflash.write8(test_offset, CMD_READ_STATUS);
        let status = self.pflash.read8(test_offset);
        self.pflash.write8(test_offset, CMD_READ_ARRAY);

        if status == CLEARED_ARRAY_STATUS {
            self.cfi_detected = true;
            log::info!(
                "QEMU pflash: CFI mode at {:#x}, {} MB",
                self.host_base,
                self.flash_size / (1024 * 1024)
            );
            return Ok(());
        }

        // Could be ROM or unknown - try anyway
        self.cfi_detected = false;
        log::warn!(
            "QEMU pflash: unknown mode at {:#x}, trying direct writes",
            self.host_base
        );
        Ok(())
    }

    /// Check if we're running in a QEMU environment
    fn is_qemu_environment() -> bool {
        let devices = pci::get_all_devices();

        log::debug!("QEMU detection: checking {} PCI devices", devices.len());

        // Look for QEMU-specific devices
        for dev in devices.iter() {
            // QEMU fw_cfg device (Red Hat vendor)
            if dev.vendor_id == QEMU_RH_VID && dev.device_id == QEMU_FW_CFG_DID {
                log::info!("Found QEMU fw_cfg device - running in QEMU");
                return true;
            }

            // QEMU NVMe controller (Red Hat vendor)
            if dev.vendor_id == QEMU_RH_VID && dev.device_id == QEMU_NVME_DID {
                log::info!("Found QEMU NVMe controller - running in QEMU");
                return true;
            }

            // QEMU XHCI controller (Red Hat vendor)
            if dev.vendor_id == QEMU_RH_VID && dev.device_id == QEMU_XHCI_DID {
                log::info!("Found QEMU XHCI controller - running in QEMU");
                return true;
            }

            // QEMU VGA (bochs-display with vendor 1234:1111)
            if dev.vendor_id == QEMU_VGA_VID && dev.device_id == QEMU_VGA_DID {
                log::info!("Found QEMU VGA (bochs-display) - running in QEMU");
                return true;
            }
        }

        log::debug!(
            "No QEMU-specific devices found in {} devices",
            devices.len()
        );
        false
    }

    /// Convert flash offset to host memory address
    #[inline]
    fn flash_to_host(&self, flash_offset: u32) -> u64 {
        self.host_base + flash_offset as u64
    }

    /// Read data from pflash at a flash offset
    fn pflash_read(&self, flash_offset: u32, buf: &mut [u8]) -> Result<()> {
        // Bounds check
        if flash_offset as u64 + buf.len() as u64 > self.flash_size as u64 {
            log::error!(
                "pflash read out of bounds: offset={:#x}, len={}, flash_size={:#x}",
                flash_offset,
                buf.len(),
                self.flash_size
            );
            return Err(SpiError::InvalidArgument);
        }

        let host_addr = self.flash_to_host(flash_offset);

        log::trace!(
            "pflash read: flash_offset={:#x} -> host={:#x}, len={}",
            flash_offset,
            host_addr,
            buf.len()
        );

        // Direct memory read
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = self.pflash.read8(flash_offset as u64 + i as u64);
        }

        Ok(())
    }

    /// Write data to pflash at a flash offset
    fn pflash_write(&mut self, flash_offset: u32, data: &[u8]) -> Result<()> {
        // Bounds check
        if flash_offset as u64 + data.len() as u64 > self.flash_size as u64 {
            log::error!(
                "pflash write out of bounds: offset={:#x}, len={}, flash_size={:#x}",
                flash_offset,
                data.len(),
                self.flash_size
            );
            return Err(SpiError::InvalidArgument);
        }

        log::trace!(
            "pflash write: flash_offset={:#x}, len={}",
            flash_offset,
            data.len()
        );

        if self.cfi_detected {
            self.cfi_write(flash_offset as u64, data)
        } else {
            self.direct_write(flash_offset as u64, data)
        }
    }

    /// Write using QEMU pflash command sequence
    fn cfi_write(&self, offset: u64, data: &[u8]) -> Result<()> {
        for (i, &byte) in data.iter().enumerate() {
            let addr = offset + i as u64;

            // QEMU pflash byte program sequence:
            // 1. Write 0x10 (WRITE_BYTE_CMD) to target address
            // 2. Write data byte to target address
            self.pflash.write8(addr, CMD_WRITE_BYTE);
            self.pflash.write8(addr, byte);
        }

        // Return to read mode
        if !data.is_empty() {
            self.pflash.write8(offset, CMD_READ_ARRAY);
        }

        Ok(())
    }

    /// Direct write (for QEMU's simple pflash emulation)
    fn direct_write(&self, offset: u64, data: &[u8]) -> Result<()> {
        for (i, &byte) in data.iter().enumerate() {
            self.pflash.write8(offset + i as u64, byte);
        }

        // Verify write
        for (i, &byte) in data.iter().enumerate() {
            let read_back = self.pflash.read8(offset + i as u64);
            if read_back != byte {
                log::warn!(
                    "pflash write verify failed at {:#x}: wrote {:#x}, read {:#x}",
                    offset + i as u64,
                    byte,
                    read_back
                );
                return Err(SpiError::CycleError);
            }
        }

        Ok(())
    }

    /// Erase a region of pflash
    fn pflash_erase(&mut self, flash_offset: u32, len: u32) -> Result<()> {
        let end = flash_offset
            .checked_add(len)
            .ok_or(SpiError::AddressOutOfRange)?;
        if end > self.flash_size {
            log::warn!(
                "pflash erase out of bounds: offset={:#x}, len={:#x}, flash_size={:#x}",
                flash_offset,
                len,
                self.flash_size
            );
            return Err(SpiError::AddressOutOfRange);
        }

        // Align to erase block boundaries
        let aligned_offset = flash_offset & !(ERASE_BLOCK_SIZE - 1);
        let aligned_len = len
            .div_ceil(ERASE_BLOCK_SIZE)
            .checked_mul(ERASE_BLOCK_SIZE)
            .ok_or(SpiError::AddressOutOfRange)?;
        let aligned_end = aligned_offset
            .checked_add(aligned_len)
            .ok_or(SpiError::AddressOutOfRange)?;
        if aligned_end > self.flash_size {
            log::warn!(
                "pflash erase alignment out of bounds: offset={:#x}, len={:#x}, aligned_offset={:#x}, aligned_len={:#x}, flash_size={:#x}",
                flash_offset,
                len,
                aligned_offset,
                aligned_len,
                self.flash_size
            );
            return Err(SpiError::AddressOutOfRange);
        }

        log::debug!(
            "pflash erase: offset={:#x}, len={:#x} (aligned: offset={:#x}, len={:#x})",
            flash_offset,
            len,
            aligned_offset,
            aligned_len
        );

        if self.cfi_detected {
            self.cfi_erase(aligned_offset as u64, aligned_len)
        } else {
            self.direct_erase(aligned_offset as u64, aligned_len)
        }
    }

    /// Erase using QEMU pflash command sequence
    fn cfi_erase(&self, offset: u64, len: u32) -> Result<()> {
        log::info!(
            "pflash erase: offset={:#x}, len={:#x} ({} KB)",
            offset,
            len,
            len / 1024
        );

        let mut current = offset;
        let end = offset + len as u64;

        while current < end {
            // QEMU pflash block erase sequence
            self.pflash.write8(current, CMD_ERASE_SETUP);
            self.pflash.write8(current, CMD_ERASE_CONFIRM);
            current += ERASE_BLOCK_SIZE as u64;
        }

        // Return to read mode
        self.pflash.write8(offset, CMD_READ_ARRAY);

        log::info!("pflash erase complete");
        Ok(())
    }

    /// Direct erase (fill with 0xFF)
    fn direct_erase(&self, offset: u64, len: u32) -> Result<()> {
        log::info!(
            "pflash direct erase: offset={:#x}, len={:#x} ({} KB)",
            offset,
            len,
            len / 1024
        );

        // Write 0xFF using 64-bit writes where possible
        let mut current = 0u64;
        let end = len as u64;

        while current + 8 <= end {
            self.pflash.write64(offset + current, 0xFFFFFFFFFFFFFFFF);
            current += 8;
        }

        while current < end {
            self.pflash.write8(offset + current, 0xFF);
            current += 1;
        }

        log::info!("pflash erase complete");
        Ok(())
    }
}

impl SpiController for QemuPflashController {
    fn name(&self) -> &'static str {
        "QEMU pflash"
    }

    fn is_locked(&self) -> bool {
        false
    }

    fn writes_enabled(&self) -> bool {
        true
    }

    fn enable_writes(&mut self) -> Result<()> {
        Ok(())
    }

    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<()> {
        self.pflash_read(addr, buf)
    }

    fn write(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        self.pflash_write(addr, data)
    }

    fn erase(&mut self, addr: u32, len: u32) -> Result<()> {
        self.pflash_erase(addr, len)
    }

    fn mode(&self) -> SpiMode {
        SpiMode::HardwareSequencing
    }

    fn get_bios_region(&self) -> Option<(u32, u32)> {
        self.flash_size.checked_sub(1).map(|limit| (0, limit))
    }
}

/// Detect QEMU pflash
///
/// Returns true if we appear to be running in QEMU with pflash available.
pub fn detect_qemu_pflash() -> bool {
    QemuPflashController::is_qemu_environment()
}
