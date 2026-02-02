//! QEMU pflash SPI Storage Backend
//!
//! This module implements a storage backend for QEMU's pflash device.
//! QEMU's -pflash option provides both firmware storage and UEFI variable
//! storage through memory-mapped flash.
//!
//! # Architecture
//!
//! QEMU's pflash is memory-mapped at the end of the 32-bit address space:
//! - Typical mapping for 4MB flash: 0xFFC00000 - 0xFFFFFFFF
//! - Typical mapping for 16MB flash: 0xFF000000 - 0xFFFFFFFF
//!
//! The pflash can be divided into regions:
//! - Firmware region (read-only during runtime)
//! - Variable store region (read-write)
//!
//! # Detection
//!
//! QEMU is detected by:
//! 1. Absence of known Intel/AMD SPI controllers
//! 2. Presence of QEMU-specific PCI devices (fw_cfg, etc.)
//! 3. Direct probing of flash at expected addresses
//!
//! # Usage with QEMU
//!
//! ```sh
//! qemu-system-x86_64 \
//!     -pflash firmware.fd \
//!     -pflash varstore.fd
//! ```
//!
//! Or with a single pflash for combined storage:
//! ```sh
//! qemu-system-x86_64 -pflash combined.fd
//! ```

use super::{delay_us, Result, SpiController, SpiError, SpiMode};
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

/// Default pflash base address for QEMU (4MB flash at top of 32-bit space)
/// This is where QEMU maps pflash unit 0 (firmware)
const DEFAULT_PFLASH_BASE: u64 = 0xFFC00000;

/// Default pflash size (4MB is typical for QEMU/OVMF)
const DEFAULT_PFLASH_SIZE: u64 = 4 * 1024 * 1024;

/// Pflash unit 1 base address (varstore)
/// When using two pflash units, unit 1 is mapped below unit 0
/// For 4MB firmware + 4MB varstore: unit 1 is at 0xFF800000
const PFLASH_UNIT1_BASE: u64 = 0xFF800000;

/// Variable store offset within pflash unit 1
/// When using a dedicated varstore pflash, variables start near the beginning
const DEFAULT_VARSTORE_OFFSET: u32 = 0;

/// Variable store size (use the entire pflash for varstore)
const DEFAULT_VARSTORE_SIZE: u32 = 4 * 1024 * 1024;

/// Flash erase block size (4KB typical for NOR flash emulation)
const ERASE_BLOCK_SIZE: u32 = 4096;

/// Pflash CFI (Common Flash Interface) signature
const CFI_SIGNATURE: [u8; 3] = [b'Q', b'R', b'Y'];

/// CFI query offset (in bytes, after shift for word access)
const CFI_QUERY_OFFSET: u64 = 0x10;

/// Flash command: Read Array (return to normal read mode)
const CMD_READ_ARRAY: u8 = 0xFF;
/// Flash command: CFI Query
const CMD_CFI_QUERY: u8 = 0x98;
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

/// QEMU pflash Controller
///
/// This controller provides direct access to QEMU's pflash device.
/// QEMU emulates Intel-style NOR flash (P30 family) which supports:
/// - CFI query for device identification
/// - Byte/word programming
/// - Block erase
pub struct QemuPflashController {
    /// Memory-mapped pflash region for variable store
    pflash: MmioRegion,
    /// Base address of the pflash
    pflash_base: u64,
    /// Total pflash size
    pflash_size: u64,
    /// Offset to variable store region within pflash
    varstore_offset: u32,
    /// Size of variable store region
    varstore_size: u32,
    /// Whether CFI was detected
    cfi_detected: bool,
}

impl QemuPflashController {
    /// Create a new QEMU pflash controller
    ///
    /// This probes the expected pflash addresses and verifies the flash
    /// is accessible and writable using the coreboot-style detection.
    ///
    /// With two pflash units:
    /// - Unit 0 (firmware): at top of 32-bit space (e.g., 0xFFC00000 for 4MB)
    /// - Unit 1 (varstore): mapped below unit 0 (e.g., 0xFF800000 for 4MB)
    pub fn new() -> Result<Self> {
        // First verify we're running on QEMU by checking for QEMU devices
        if !Self::is_qemu_environment() {
            log::debug!("Not running in QEMU environment");
            return Err(SpiError::NoChipset);
        }

        // Try different possible pflash addresses
        // QEMU maps pflash from top of 4GB downward
        let addresses_to_try = [
            PFLASH_UNIT1_BASE,   // 0xFF800000 - expected for unit 1 with 4MB each
            0xFF400000u64,       // Alternative: 8MB below top
            DEFAULT_PFLASH_BASE, // 0xFFC00000 - unit 0 / combined flash
        ];

        for &pflash_base in &addresses_to_try {
            log::info!("QEMU pflash: probing at {:#x}...", pflash_base);

            let pflash = MmioRegion::new(pflash_base, DEFAULT_PFLASH_SIZE as usize);

            // Use coreboot-style detection:
            // 1. Find a byte that's not 0xFF and not ending in 0
            // 2. Write CLEAR_STATUS_CMD (0x50) and read back
            // 3. If readback == 0x50, it's RAM (direct writes work)
            // 4. Otherwise write READ_STATUS_CMD (0x70) and check response

            // Find a suitable test byte (not 0xFF, not ending in 0)
            // If flash is blank (all 0x00 or 0xFF), we'll use offset 0 anyway
            let mut test_offset = 0u64;
            let mut original = pflash.read8(test_offset);
            let mut found_suitable = false;

            while test_offset < 0x1000 {
                original = pflash.read8(test_offset);
                if original != 0xFF && (original & 0x0F) != 0 {
                    found_suitable = true;
                    break;
                }
                test_offset += 1;
            }

            // If no suitable byte found, use offset 0 with special handling
            // This handles blank (zeroed) varstore images
            if !found_suitable {
                log::debug!(
                    "  No suitable test byte found at {:#x}, trying blank flash detection",
                    pflash_base
                );
                test_offset = 0;
                original = pflash.read8(test_offset);

                // For blank flash (all 0x00 or 0xFF), try directly testing pflash commands
                // Write CLEAR_STATUS then READ_STATUS to detect pflash
                pflash.write8(test_offset, CMD_CLEAR_STATUS);
                pflash.write8(test_offset, CMD_READ_STATUS);
                let status = pflash.read8(test_offset);

                log::debug!(
                    "  Blank flash test: original={:#02x}, status after cmds={:#02x}",
                    original,
                    status
                );

                if status == CLEARED_ARRAY_STATUS {
                    // It's pflash - test writability
                    log::debug!(
                        "  {:#x}: blank pflash detected, testing writability...",
                        pflash_base
                    );

                    // Try writing a test pattern
                    pflash.write8(test_offset, CMD_WRITE_BYTE);
                    pflash.write8(test_offset, 0xAA);

                    // Read status
                    pflash.write8(test_offset, CMD_READ_STATUS);
                    let write_status = pflash.read8(test_offset);

                    // Return to read mode and check what we wrote
                    pflash.write8(test_offset, CMD_READ_ARRAY);
                    let written = pflash.read8(test_offset);

                    if (write_status & STATUS_PROGRAM_ERROR) != 0 {
                        log::info!("QEMU pflash at {:#x}: write-protected (blank)", pflash_base);
                        continue;
                    }

                    if written == 0xAA {
                        log::info!(
                            "QEMU pflash at {:#x}: writable blank flash detected!",
                            pflash_base
                        );

                        // Erase the test byte back to 0xFF
                        pflash.write8(test_offset, CMD_ERASE_SETUP);
                        pflash.write8(test_offset, CMD_ERASE_CONFIRM);
                        pflash.write8(test_offset, CMD_READ_ARRAY);

                        let controller = Self {
                            pflash,
                            pflash_base,
                            pflash_size: DEFAULT_PFLASH_SIZE,
                            varstore_offset: DEFAULT_VARSTORE_OFFSET,
                            varstore_size: DEFAULT_VARSTORE_SIZE,
                            cfi_detected: true,
                        };
                        return Ok(controller);
                    }
                }

                // Not pflash or not writable, try next address
                pflash.write8(test_offset, CMD_READ_ARRAY);
                continue;
            }

            log::debug!(
                "  Testing at offset {:#x}, original byte = {:#02x}",
                test_offset,
                original
            );

            // Write CLEAR_STATUS_CMD to detect flash type
            pflash.write8(test_offset, CMD_CLEAR_STATUS);
            let readback = pflash.read8(test_offset);

            if readback == CMD_CLEAR_STATUS {
                log::info!(
                    "QEMU pflash at {:#x}: behaves as RAM (direct writes)",
                    pflash_base
                );
                // Restore original content
                pflash.write8(test_offset, original);

                // RAM mode - direct writes work
                let controller = Self {
                    pflash,
                    pflash_base,
                    pflash_size: DEFAULT_PFLASH_SIZE,
                    varstore_offset: DEFAULT_VARSTORE_OFFSET,
                    varstore_size: DEFAULT_VARSTORE_SIZE,
                    cfi_detected: false, // Use direct mode
                };
                return Ok(controller);
            }

            // Not RAM - check if it's pflash or ROM
            pflash.write8(test_offset, CMD_READ_STATUS);
            let status = pflash.read8(test_offset);

            if status == original {
                log::debug!("  {:#x}: behaves as ROM (read-only)", pflash_base);
                continue; // Try next address
            }

            if status == CLEARED_ARRAY_STATUS {
                // It's pflash! Test if writable
                log::debug!(
                    "  {:#x}: pflash detected, testing writability...",
                    pflash_base
                );

                // Try writing original value back
                pflash.write8(test_offset, CMD_WRITE_BYTE);
                pflash.write8(test_offset, original);

                // Read status
                pflash.write8(test_offset, CMD_READ_STATUS);
                let write_status = pflash.read8(test_offset);

                // Return to read mode
                pflash.write8(test_offset, CMD_READ_ARRAY);

                if (write_status & STATUS_PROGRAM_ERROR) != 0 {
                    log::info!("QEMU pflash at {:#x}: write-protected", pflash_base);
                    continue; // Try next address
                }

                log::info!(
                    "QEMU pflash at {:#x}: writable flash detected!",
                    pflash_base
                );

                let controller = Self {
                    pflash,
                    pflash_base,
                    pflash_size: DEFAULT_PFLASH_SIZE,
                    varstore_offset: DEFAULT_VARSTORE_OFFSET,
                    varstore_size: DEFAULT_VARSTORE_SIZE,
                    cfi_detected: true, // Use command sequences
                };
                return Ok(controller);
            }

            log::debug!("  {:#x}: unexpected status {:#02x}", pflash_base, status);
        }

        log::error!("QEMU pflash: no writable flash found at any address");
        Err(SpiError::WriteProtected)
    }

    /// Create a new QEMU pflash controller with custom parameters
    pub fn new_with_params(
        pflash_base: u64,
        pflash_size: u64,
        varstore_offset: u32,
        varstore_size: u32,
    ) -> Result<Self> {
        log::info!(
            "QEMU pflash: custom config at {:#x}, varstore at offset {:#x}",
            pflash_base,
            varstore_offset
        );

        let pflash = MmioRegion::new(pflash_base, pflash_size as usize);

        let mut controller = Self {
            pflash,
            pflash_base,
            pflash_size,
            varstore_offset,
            varstore_size,
            cfi_detected: false,
        };

        controller.init()?;

        Ok(controller)
    }

    /// Check if we're running in a QEMU environment
    fn is_qemu_environment() -> bool {
        let devices = pci::get_all_devices();

        log::debug!("QEMU detection: checking {} PCI devices", devices.len());

        // Look for QEMU-specific devices
        for dev in devices.iter() {
            log::debug!(
                "  Checking {:04x}:{:04x} at {:?}",
                dev.vendor_id,
                dev.device_id,
                dev.address
            );

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

    /// Initialize the pflash controller
    fn init(&mut self) -> Result<()> {
        // Try to detect CFI-compatible flash
        // QEMU's pflash_cfi01 device supports CFI and requires command sequences
        if self.probe_cfi() {
            log::info!("QEMU pflash: CFI flash detected - using command sequences for writes");
            self.cfi_detected = true;
            // Return flash to read array mode after CFI probe
            self.reset_to_read_mode();
        } else {
            log::warn!("QEMU pflash: CFI not detected");
            log::warn!(
                "Direct memory writes may not work - pflash typically requires CFI commands"
            );
            // Try anyway with direct mode as fallback
        }

        // Verify we can read from the pflash
        let test_byte = self.pflash.read8(0);
        log::debug!("QEMU pflash: test read at offset 0 = {:#02x}", test_byte);

        log::info!(
            "QEMU pflash initialized: varstore at {:#x}, size {} MB, CFI={}",
            self.pflash_base,
            self.pflash_size / (1024 * 1024),
            self.cfi_detected
        );

        Ok(())
    }

    /// Probe for CFI-compatible flash
    fn probe_cfi(&self) -> bool {
        // QEMU's pflash_cfi01 uses word (16-bit) addressing
        // CFI query command goes to address 0x55 (word address)
        let cfi_cmd_addr = 0x55 * 2; // Convert to byte address

        // Enter CFI query mode by writing 0x98 to address 0x55
        self.pflash.write8(cfi_cmd_addr, CMD_CFI_QUERY);

        // Small delay for mode switch
        delay_us(100);

        // Read CFI signature at offset 0x10 (word addresses)
        // In byte addresses: 0x10 * 2 = 0x20
        // CFI signature is "QRY" at word offsets 0x10, 0x11, 0x12
        let sig_q = self.pflash.read8(0x10 * 2);
        let sig_r = self.pflash.read8(0x11 * 2);
        let sig_y = self.pflash.read8(0x12 * 2);

        log::debug!(
            "CFI probe: signature bytes = {:02x} {:02x} {:02x} ('{}{}{}'), expected 'QRY'",
            sig_q,
            sig_r,
            sig_y,
            sig_q as char,
            sig_r as char,
            sig_y as char
        );

        // Return to read mode
        self.pflash.write8(0, CMD_READ_ARRAY);
        delay_us(100);

        sig_q == b'Q' && sig_r == b'R' && sig_y == b'Y'
    }

    /// Reset flash to read array mode
    #[allow(dead_code)]
    fn reset_to_read_mode(&self) {
        self.pflash.write8(0, CMD_READ_ARRAY);
        delay_us(10);
    }

    /// Read data from pflash
    ///
    /// For QEMU pflash, we can simply read directly from the memory-mapped region.
    /// The addr parameter is treated as an offset within this pflash unit.
    ///
    /// Note: The persistence layer may pass addresses like 0xF00000 (15MB offset)
    /// which assume a 16MB flash. For QEMU's dedicated varstore pflash, we remap
    /// these high addresses by taking the offset from 0xF00000 (the SMMSTORE base).
    fn pflash_read(&self, addr: u32, buf: &mut [u8]) -> Result<()> {
        // SMMSTORE typically starts at 0xF00000 (15MB) for 16MB flash
        // For QEMU's 4MB varstore pflash, remap by subtracting the SMMSTORE base
        const SMMSTORE_BASE: u32 = 0xF00000;

        let actual_addr = if addr >= SMMSTORE_BASE {
            // Remap from SMMSTORE address space to pflash offset
            let offset = addr - SMMSTORE_BASE;
            log::debug!(
                "pflash read: remapping addr {:#x} to offset {:#x}",
                addr,
                offset
            );
            self.varstore_offset as u64 + offset as u64
        } else {
            self.varstore_offset as u64 + addr as u64
        };

        // Bounds check
        if actual_addr + buf.len() as u64 > self.pflash_size {
            log::error!(
                "pflash read out of bounds: addr={:#x}, len={}, size={:#x}",
                actual_addr,
                buf.len(),
                self.pflash_size
            );
            return Err(SpiError::InvalidArgument);
        }

        log::debug!(
            "pflash read: requested={:#x}, actual={:#x}, len={}, physical={:#x}",
            addr,
            actual_addr,
            buf.len(),
            self.pflash_base + actual_addr
        );

        // Direct memory read - no CFI commands needed for QEMU's simple pflash
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = self.pflash.read8(actual_addr + i as u64);
        }

        // Log first few bytes for debugging
        if buf.len() >= 4 {
            log::debug!(
                "pflash read data: {:02x} {:02x} {:02x} {:02x}...",
                buf[0],
                buf[1],
                buf[2],
                buf[3]
            );
        }

        Ok(())
    }

    /// Write data to pflash
    ///
    /// For CFI flash, we need to use the write command sequence.
    /// For simple QEMU pflash, direct writes may work.
    fn pflash_write(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        // SMMSTORE typically starts at 0xF00000 (15MB) for 16MB flash
        const SMMSTORE_BASE: u32 = 0xF00000;

        let actual_addr = if addr >= SMMSTORE_BASE {
            let offset = addr - SMMSTORE_BASE;
            log::debug!(
                "pflash write: remapping addr {:#x} to offset {:#x}",
                addr,
                offset
            );
            self.varstore_offset as u64 + offset as u64
        } else {
            self.varstore_offset as u64 + addr as u64
        };

        // Bounds check
        if actual_addr + data.len() as u64 > self.pflash_size {
            log::error!(
                "pflash write out of bounds: addr={:#x}, len={}, size={:#x}",
                actual_addr,
                data.len(),
                self.pflash_size
            );
            return Err(SpiError::InvalidArgument);
        }

        if self.cfi_detected {
            // Use CFI write sequence
            self.cfi_write(actual_addr, data)
        } else {
            // Try direct write (works with some QEMU configurations)
            self.direct_write(actual_addr, data)
        }
    }

    /// Write using QEMU pflash command sequence
    /// Based on coreboot's qemu pflash implementation
    fn cfi_write(&self, addr: u64, data: &[u8]) -> Result<()> {
        log::debug!("pflash cfi_write: addr={:#x}, len={}", addr, data.len());

        for (i, &byte) in data.iter().enumerate() {
            let byte_addr = addr + i as u64;

            // QEMU pflash byte program sequence:
            // 1. Write 0x10 (WRITE_BYTE_CMD) to target address
            // 2. Write data byte to target address
            self.pflash.write8(byte_addr, CMD_WRITE_BYTE);
            self.pflash.write8(byte_addr, byte);

            // Log progress every 4KB
            if i > 0 && i % 4096 == 0 {
                log::debug!("pflash write progress: {} / {} bytes", i, data.len());
            }
        }

        // Return to read mode
        if !data.is_empty() {
            self.pflash
                .write8(addr + data.len() as u64 - 1, CMD_READ_ARRAY);

            // Verify first few bytes were written correctly
            let verify_len = data.len().min(4);
            let mut verify_ok = true;
            for i in 0..verify_len {
                let written = self.pflash.read8(addr + i as u64);
                if written != data[i] {
                    log::warn!(
                        "pflash write verify failed at {:#x}: wrote {:#02x}, read {:#02x}",
                        addr + i as u64,
                        data[i],
                        written
                    );
                    verify_ok = false;
                }
            }
            if verify_ok && !data.is_empty() {
                log::debug!(
                    "pflash write verified OK: first bytes {:02x} {:02x} {:02x} {:02x}",
                    data.get(0).copied().unwrap_or(0),
                    data.get(1).copied().unwrap_or(0),
                    data.get(2).copied().unwrap_or(0),
                    data.get(3).copied().unwrap_or(0)
                );
            }
        }

        Ok(())
    }

    /// Direct write (for QEMU's simple pflash emulation)
    fn direct_write(&self, addr: u64, data: &[u8]) -> Result<()> {
        log::debug!(
            "pflash direct write: addr={:#x}, len={}, physical={:#x}",
            addr,
            data.len(),
            self.pflash_base + addr
        );

        // QEMU's pflash in "-pflash" mode may support direct writes
        // depending on configuration
        for (i, &byte) in data.iter().enumerate() {
            self.pflash.write8(addr + i as u64, byte);
        }

        // Verify write (helps detect read-only pflash)
        let mut verify_failed = false;
        for (i, &byte) in data.iter().enumerate() {
            let read_back = self.pflash.read8(addr + i as u64);
            if read_back != byte {
                if !verify_failed {
                    log::warn!(
                        "pflash write verify failed at {:#x}: wrote {:#x}, read {:#x}",
                        addr + i as u64,
                        byte,
                        read_back
                    );
                    log::warn!("pflash may be read-only - check QEMU pflash configuration");
                    verify_failed = true;
                }
            }
        }

        if verify_failed {
            return Err(SpiError::CycleError);
        }

        Ok(())
    }

    /// Erase a region of pflash
    fn pflash_erase(&mut self, addr: u32, len: u32) -> Result<()> {
        // SMMSTORE typically starts at 0xF00000 (15MB) for 16MB flash
        const SMMSTORE_BASE: u32 = 0xF00000;

        let actual_addr = if addr >= SMMSTORE_BASE {
            let offset = addr - SMMSTORE_BASE;
            log::debug!(
                "pflash erase: remapping addr {:#x} to offset {:#x}",
                addr,
                offset
            );
            self.varstore_offset as u64 + offset as u64
        } else {
            self.varstore_offset as u64 + addr as u64
        };

        // Use the smaller of requested length or pflash size for erase
        let actual_len = if actual_addr + len as u64 > self.pflash_size {
            log::debug!(
                "pflash erase: clamping len from {:#x} to {:#x}",
                len,
                self.pflash_size as u32 - actual_addr as u32
            );
            self.pflash_size as u32 - actual_addr as u32
        } else {
            len
        };

        // Verify alignment (relax this for QEMU)
        let aligned_addr = actual_addr & !(ERASE_BLOCK_SIZE as u64 - 1);
        let aligned_len =
            ((actual_len + ERASE_BLOCK_SIZE - 1) / ERASE_BLOCK_SIZE) * ERASE_BLOCK_SIZE;

        log::debug!(
            "pflash erase: addr={:#x}, len={:#x} (aligned: addr={:#x}, len={:#x})",
            actual_addr,
            actual_len,
            aligned_addr,
            aligned_len
        );

        if self.cfi_detected {
            // Use CFI erase sequence
            self.cfi_erase(aligned_addr, aligned_len)
        } else {
            // Direct fill with 0xFF (for QEMU's simple pflash emulation)
            self.direct_erase(aligned_addr, aligned_len)
        }
    }

    /// Erase using QEMU pflash command sequence
    /// Based on coreboot's qemu pflash implementation
    fn cfi_erase(&self, addr: u64, len: u32) -> Result<()> {
        log::info!(
            "pflash erase: addr={:#x}, len={:#x} ({} KB)",
            addr,
            len,
            len / 1024
        );

        let mut current_addr = addr;
        let end_addr = addr + len as u64;
        let mut block_count = 0u32;

        while current_addr < end_addr {
            // QEMU pflash block erase sequence:
            // 1. Write 0x20 (BLOCK_ERASE_CMD) to block address
            // 2. Write 0xD0 (BLOCK_ERASE_CONFIRM_CMD) to same address
            self.pflash.write8(current_addr, CMD_ERASE_SETUP);
            self.pflash.write8(current_addr, CMD_ERASE_CONFIRM);

            current_addr += ERASE_BLOCK_SIZE as u64;
            block_count += 1;

            if block_count % 64 == 0 {
                log::debug!(
                    "pflash erase progress: {} blocks ({} KB)",
                    block_count,
                    block_count * 4
                );
            }
        }

        // Return to read mode
        if len > 0 {
            self.pflash.write8(addr, CMD_READ_ARRAY);
        }

        log::info!(
            "pflash erase complete: {} blocks ({} KB)",
            block_count,
            block_count * 4
        );
        Ok(())
    }

    /// Direct erase (fill with 0xFF for QEMU's simple pflash)
    fn direct_erase(&self, addr: u64, len: u32) -> Result<()> {
        log::info!(
            "pflash direct erase: addr={:#x}, len={:#x} ({} KB)",
            addr,
            len,
            len / 1024
        );

        // First verify pflash is writable by testing one byte
        let test_addr = addr;
        let original = self.pflash.read8(test_addr);
        self.pflash.write8(test_addr, 0xFF);
        let written = self.pflash.read8(test_addr);

        if written != 0xFF && original != 0xFF {
            log::error!(
                "pflash appears read-only: wrote 0xFF, read back {:#02x}",
                written
            );
            log::error!("Check QEMU pflash configuration - varstore needs to be writable");
            return Err(SpiError::WriteProtected);
        }

        // Write 0xFF in chunks for better performance
        // Use 64-bit writes where possible
        let mut offset = 0u64;
        let end = len as u64;

        // Write 64-bit aligned chunks
        while offset + 8 <= end {
            self.pflash.write64(addr + offset, 0xFFFFFFFFFFFFFFFF);
            offset += 8;

            // Log progress every 64KB
            if offset % 0x10000 == 0 {
                log::debug!(
                    "pflash erase progress: {} KB / {} KB",
                    offset / 1024,
                    len / 1024
                );
            }
        }

        // Write remaining bytes
        while offset < end {
            self.pflash.write8(addr + offset, 0xFF);
            offset += 1;
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
        // QEMU pflash is not locked
        false
    }

    fn writes_enabled(&self) -> bool {
        // QEMU pflash is always writable (if configured with pflash)
        true
    }

    fn enable_writes(&mut self) -> Result<()> {
        // No action needed for QEMU
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
        // QEMU pflash uses memory-mapped access, similar to hardware sequencing
        SpiMode::HardwareSequencing
    }
}

/// Detect QEMU pflash
///
/// Returns true if we appear to be running in QEMU with pflash available.
pub fn detect_qemu_pflash() -> bool {
    QemuPflashController::is_qemu_environment()
}
