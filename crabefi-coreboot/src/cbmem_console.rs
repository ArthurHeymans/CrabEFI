//! Coreboot CBMEM console output
//!
//! This module exposes coreboot's in-memory CBMEM console as a CrabEFI
//! [`DebugOutput`](crabefi::DebugOutput) sink. The coreboot payload injects this
//! sink into CrabEFI's serial subsystem so log output and EFI console bytes are
//! mirrored into CBMEM while the physical buffer is valid.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};

use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Mask for the cursor offset bits in coreboot's CBMEM console header.
const CURSOR_MASK: u32 = (1 << 28) - 1;
/// Cursor flag indicating that the ring buffer has wrapped.
const OVERFLOW: u32 = 1 << 31;
/// Largest buffer representable by the cursor offset bits.
const MAX_CONSOLE_SIZE: u32 = CURSOR_MASK;

/// CBMEM console structure header.
///
/// The actual console buffer follows immediately after this header.
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CbmemConsoleHeader {
    /// Size of the console buffer, not including this header.
    size: u32,
    /// Current cursor position, with overflow flag in bit 31.
    cursor: u32,
}

static CBMEM_CONSOLE_ADDR: AtomicU64 = AtomicU64::new(0);

/// Debug output sink for the coreboot CBMEM console.
pub struct CbmemConsole;

impl CbmemConsole {
    /// Create a CBMEM console debug-output sink.
    pub const fn new() -> Self {
        Self
    }

    fn write_raw_byte(&mut self, byte: u8) {
        write_bytes(&[byte]);
    }
}

impl Write for CbmemConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_raw_byte(b'\r');
            }
            self.write_raw_byte(byte);
        }
        Ok(())
    }
}

impl crabefi::DebugOutput for CbmemConsole {
    fn write_byte(&mut self, byte: u8) {
        self.write_raw_byte(byte);
    }
}

/// Initialize the CBMEM console with the given physical address.
///
/// # Arguments
/// * `addr` - Physical address of the CBMEM console structure
///
/// # Returns
/// `true` when the console header is valid and output was enabled.
pub fn init(addr: u64) -> bool {
    if addr == 0 {
        return false;
    }

    match read_size(addr) {
        Some(size) if (1024..=MAX_CONSOLE_SIZE).contains(&size) => {
            CBMEM_CONSOLE_ADDR.store(addr, Ordering::Release);
            log::debug!(
                "CBMEM console initialized: addr={:#x}, size={} bytes",
                addr,
                size
            );
            true
        }
        Some(size) => {
            log::warn!(
                "CBMEM console has invalid size: {} bytes at {:#x}",
                size,
                addr
            );
            false
        }
        None => false,
    }
}

/// Disable the CBMEM console.
///
/// Called at ExitBootServices and SetVirtualAddressMap to prevent runtime code
/// from accessing the physical-only CBMEM buffer.
pub fn disable() {
    CBMEM_CONSOLE_ADDR.store(0, Ordering::Release);
}

fn console_addr() -> Option<u64> {
    let addr = CBMEM_CONSOLE_ADDR.load(Ordering::Acquire);
    (addr != 0).then_some(addr)
}

fn read_size(addr: u64) -> Option<u32> {
    let header = addr as *const CbmemConsoleHeader;
    if header.is_null() {
        return None;
    }

    // SAFETY: `addr` comes from the validated coreboot table. The structure is
    // packed, so use unaligned raw-field access instead of taking references to
    // fields.
    Some(unsafe { core::ptr::addr_of!((*header).size).read_unaligned() })
}

fn read_cursor(addr: u64) -> u32 {
    let header = addr as *const CbmemConsoleHeader;
    // SAFETY: `addr` is the enabled CBMEM console address. The header is packed.
    unsafe { core::ptr::addr_of!((*header).cursor).read_unaligned() }
}

fn write_cursor(addr: u64, cursor: u32) {
    let header = addr as *mut CbmemConsoleHeader;
    // SAFETY: `addr` is the enabled CBMEM console address. The header is packed.
    unsafe { core::ptr::addr_of_mut!((*header).cursor).write_unaligned(cursor) };
}

fn body_ptr(addr: u64) -> *mut u8 {
    // SAFETY: Pointer arithmetic only constructs the body pointer immediately
    // after the fixed-size header.
    unsafe { (addr as *mut u8).add(core::mem::size_of::<CbmemConsoleHeader>()) }
}

fn write_chunk(addr: u64, offset: usize, bytes: &[u8]) {
    let body = body_ptr(addr);
    for (i, byte) in bytes.iter().copied().enumerate() {
        // SAFETY: Callers ensure `offset + bytes.len()` is within the console
        // body. Volatile writes keep the firmware-visible log side effect.
        unsafe { body.add(offset + i).write_volatile(byte) };
    }
}

fn write_bytes(mut bytes: &[u8]) {
    let Some(addr) = console_addr() else {
        return;
    };
    let Some(size) = read_size(addr) else {
        disable();
        return;
    };
    if !(1024..=MAX_CONSOLE_SIZE).contains(&size) {
        disable();
        return;
    }

    let size = size as usize;
    while !bytes.is_empty() {
        let cursor = read_cursor(addr);
        let offset = (cursor & CURSOR_MASK) as usize;
        if offset >= size {
            write_cursor(addr, (cursor & !CURSOR_MASK) | OVERFLOW);
            continue;
        }

        let remaining = size - offset;
        if bytes.len() >= remaining {
            let (chunk, rest) = bytes.split_at(remaining);
            write_chunk(addr, offset, chunk);
            let new_cursor = cursor.wrapping_add(remaining as u32);
            write_cursor(addr, (new_cursor & !CURSOR_MASK) | OVERFLOW);
            bytes = rest;
        } else {
            write_chunk(addr, offset, bytes);
            write_cursor(addr, cursor.wrapping_add(bytes.len() as u32));
            break;
        }
    }
}
