//! Flash access through the payload MM image (crabefi-mm) in SMRAM.
//!
//! The platform loads the MM image and registers its communication buffer with
//! [`register`]. Reads use the memory-mapped flash, which stays readable from
//! ring 0; erase and write are forwarded to SMM because the flash only accepts
//! writes from SMM (AMD ROM Armor 3, QEMU `cfi.pflash01` with `secure=on`).

use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

use super::{Result, SpiController, SpiError, SpiMode};

/// Wire format shared with crabefi-mm (`CommHeader`).
#[repr(C)]
#[derive(Clone, Copy)]
struct CommHeader {
    magic: u64,
    version: u32,
    command: u32,
    status: u32,
    offset: u32,
    length: u32,
    reserved: u32,
}

const COMM_MAGIC: u64 = 0x0043_4d4d_4241_5243; // "CRABMMC\0"
const COMM_VERSION: u32 = 1;
const HEADER_SIZE: usize = core::mem::size_of::<CommHeader>();
const CMD_PING: u32 = 1;
const CMD_ERASE: u32 = 2;
const CMD_WRITE: u32 = 3;
const STATUS_SUCCESS: u32 = 0;
const STATUS_RANGE: u32 = 2;
const STATUS_PENDING: u32 = 0xffff_ffff;
const MAX_TRANSFER: usize = 64 * 1024;

/// What the platform learned while loading the MM image.
#[derive(Clone, Copy, Debug)]
pub struct MmFlashConfig {
    /// Communication buffer registered with the MM image (normal RAM).
    pub comm_base: u64,
    pub comm_size: u64,
    /// Value written to the APM control port to raise the software SMI.
    pub apm_cmd: u8,
    /// Memory-mapped flash (reads only).
    pub flash_base: u64,
    pub flash_size: u32,
}

static CONFIG: Mutex<Option<MmFlashConfig>> = Mutex::new(None);

/// Route firmware flash access through the MM image from now on.
pub fn register(config: MmFlashConfig) {
    *CONFIG.lock() = Some(config);
}

/// The registered MM flash service, if any.
pub fn controller() -> Option<MmFlashController> {
    CONFIG.lock().map(|config| MmFlashController { config })
}

pub struct MmFlashController {
    config: MmFlashConfig,
}

/// Raise a software SMI through the APM control port.
fn trigger_smi(apm_cmd: u8) {
    // SAFETY: port 0xb2 is the chipset APM control port; writing it only raises an SMI.
    unsafe {
        core::arch::asm!("out 0xb2, al", in("al") apm_cmd, options(nomem, nostack, preserves_flags));
    }
}

impl MmFlashController {
    pub fn flash_size(&self) -> u32 {
        self.config.flash_size
    }

    fn max_chunk(&self) -> usize {
        MAX_TRANSFER.min(self.config.comm_size as usize - HEADER_SIZE)
    }

    /// Send one request; `data` is copied behind the header for writes.
    fn request(&self, command: u32, offset: u32, length: u32, data: &[u8]) -> Result<()> {
        let header_ptr = self.config.comm_base as *mut CommHeader;
        let payload = (self.config.comm_base as usize + HEADER_SIZE) as *mut u8;
        // SAFETY: the communication buffer is owned by this driver and registered with MM.
        unsafe {
            for (i, &byte) in data.iter().enumerate() {
                write_volatile(payload.add(i), byte);
            }
            write_volatile(
                header_ptr,
                CommHeader {
                    magic: COMM_MAGIC,
                    version: COMM_VERSION,
                    command,
                    status: STATUS_PENDING,
                    offset,
                    length,
                    reserved: 0,
                },
            );
        }
        trigger_smi(self.config.apm_cmd);
        // SAFETY: as above; MM wrote the status before the SMI returned.
        let status = unsafe { read_volatile(core::ptr::addr_of!((*header_ptr).status)) };
        match status {
            STATUS_SUCCESS => Ok(()),
            STATUS_PENDING => {
                log::error!("payload MM did not handle the request (command {command})");
                Err(SpiError::CycleError)
            }
            STATUS_RANGE => Err(SpiError::AccessDenied),
            other => {
                log::error!("payload MM request {command} at {offset:#x} failed: {other}");
                Err(SpiError::CycleError)
            }
        }
    }

    /// Check that the MM image answers.
    pub fn ping(&self) -> Result<()> {
        self.request(CMD_PING, 0, 0, &[])
    }
}

impl SpiController for MmFlashController {
    fn name(&self) -> &'static str {
        "payload MM flash"
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
        let end = (addr as u64)
            .checked_add(buf.len() as u64)
            .ok_or(SpiError::AddressOutOfRange)?;
        if end > self.config.flash_size as u64 {
            return Err(SpiError::AddressOutOfRange);
        }
        let base = (self.config.flash_base + addr as u64) as *const u8;
        for (i, byte) in buf.iter_mut().enumerate() {
            // SAFETY: inside the memory-mapped flash window checked above.
            *byte = unsafe { read_volatile(base.add(i)) };
        }
        Ok(())
    }

    fn write(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        let chunk = self.max_chunk();
        for (i, part) in data.chunks(chunk).enumerate() {
            let offset = addr
                .checked_add((i * chunk) as u32)
                .ok_or(SpiError::AddressOutOfRange)?;
            self.request(CMD_WRITE, offset, part.len() as u32, part)?;
        }
        Ok(())
    }

    fn erase(&mut self, addr: u32, len: u32) -> Result<()> {
        self.request(CMD_ERASE, addr, len, &[])
    }

    fn mode(&self) -> SpiMode {
        SpiMode::HardwareSequencing
    }

    fn get_bios_region(&self) -> Option<(u32, u32)> {
        self.config
            .flash_size
            .checked_sub(1)
            .map(|limit| (0, limit))
    }
}
