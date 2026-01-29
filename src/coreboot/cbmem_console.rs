//! Coreboot CBMEM Console Driver
//!
//! This module provides write access to the coreboot in-memory console (CBMEM console).
//! The CBMEM console is a ring buffer maintained by coreboot that persists across
//! boot stages, allowing early boot messages to be preserved and read later.
//!
//! Reference: coreboot/payloads/libpayload/drivers/cbmem_console.c

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};

/// CBMEM console structure header
///
/// The actual console buffer follows immediately after this header.
#[repr(C, packed)]
struct CbmemConsoleHeader {
    /// Size of the console buffer (not including this header)
    size: u32,
    /// Current cursor position, with overflow flag in bit 31
    cursor: u32,
    // body: [u8] follows
}

/// Mask for the cursor position (bits 0-27)
const CURSOR_MASK: u32 = (1 << 28) - 1;

/// Overflow flag (bit 31) - set when buffer has wrapped around
const OVERFLOW: u32 = 1 << 31;

/// Global CBMEM console address (0 = not initialized)
static CBMEM_CONSOLE_ADDR: AtomicU64 = AtomicU64::new(0);

/// Initialize the CBMEM console with the given physical address
///
/// # Arguments
/// * `addr` - Physical address of the CBMEM console structure
///
/// # Safety
/// The address must point to a valid CBMEM console structure that remains
/// valid for the lifetime of the program.
pub fn init(addr: u64) {
    if addr == 0 {
        return;
    }

    // Verify the console looks valid before enabling
    let header = addr as *const CbmemConsoleHeader;
    unsafe {
        let size = core::ptr::addr_of!((*header).size).read_unaligned();
        // Sanity check: size should be reasonable (at least 1KB, at most 1MB)
        if size >= 1024 && size <= 1024 * 1024 {
            CBMEM_CONSOLE_ADDR.store(addr, Ordering::Release);
            log::debug!(
                "CBMEM console initialized: addr={:#x}, size={} bytes",
                addr,
                size
            );
        } else {
            log::warn!(
                "CBMEM console has invalid size: {} bytes at {:#x}",
                size,
                addr
            );
        }
    }
}

/// Check if CBMEM console is available
pub fn is_available() -> bool {
    CBMEM_CONSOLE_ADDR.load(Ordering::Acquire) != 0
}

/// Write bytes to the CBMEM console (ring buffer)
///
/// This function handles buffer wraparound following libpayload's implementation:
/// when the write would exceed the buffer size, it writes what fits, sets the
/// overflow flag, wraps to the beginning, and continues writing.
///
/// The cursor field uses:
/// - Bits 0-27: Current write position (CURSOR_MASK)
/// - Bit 31: Overflow flag (set when buffer has wrapped at least once)
pub fn write_bytes(data: &[u8]) {
    let addr = CBMEM_CONSOLE_ADDR.load(Ordering::Acquire);
    if addr == 0 {
        return;
    }

    let header = addr as *mut CbmemConsoleHeader;

    unsafe {
        let size = core::ptr::addr_of!((*header).size).read_unaligned();
        let cursor_ptr = core::ptr::addr_of_mut!((*header).cursor);
        let body = (addr as *mut u8).add(core::mem::size_of::<CbmemConsoleHeader>());

        let mut buffer = data.as_ptr();
        let mut count = data.len();

        // Handle wraparound (following libpayload's cbmem_console_write pattern)
        // Keep looping while the write would overflow the buffer
        while {
            let cursor = cursor_ptr.read_unaligned();
            let cursor_pos = (cursor & CURSOR_MASK) as usize;
            cursor_pos + count >= size as usize
        } {
            let cursor = cursor_ptr.read_unaligned();
            let cursor_pos = (cursor & CURSOR_MASK) as usize;
            let still_fits = (size as usize).saturating_sub(cursor_pos);

            if still_fits > 0 {
                // Write what fits at the end of the buffer
                core::ptr::copy_nonoverlapping(buffer, body.add(cursor_pos), still_fits);
            }

            // Wrap cursor to 0 and set overflow flag (matches libpayload exactly)
            let mut new_cursor = cursor;
            new_cursor &= !CURSOR_MASK; // Clear position to 0
            new_cursor |= OVERFLOW; // Set overflow flag
            cursor_ptr.write_unaligned(new_cursor);

            // Advance buffer pointer and decrease count
            buffer = buffer.add(still_fits);
            count -= still_fits;
        }

        // Write remaining data (guaranteed to fit now)
        if count > 0 {
            let cursor = cursor_ptr.read_unaligned();
            let cursor_pos = (cursor & CURSOR_MASK) as usize;

            core::ptr::copy_nonoverlapping(buffer, body.add(cursor_pos), count);

            // Update cursor position (just add count, preserves overflow flag)
            cursor_ptr.write_unaligned(cursor + count as u32);
        }
    }
}

/// Write a single byte to the CBMEM console
#[inline]
pub fn write_byte(byte: u8) {
    write_bytes(&[byte]);
}

/// Writer struct that implements `core::fmt::Write`
pub struct CbmemConsoleWriter;

impl Write for CbmemConsoleWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_bytes(s.as_bytes());
        Ok(())
    }
}

/// Write formatted output to the CBMEM console
pub fn write_fmt(args: fmt::Arguments) {
    let mut writer = CbmemConsoleWriter;
    let _ = writer.write_fmt(args);
}

/// Macro for printing to CBMEM console
#[macro_export]
macro_rules! cbmem_print {
    ($($arg:tt)*) => {
        $crate::coreboot::cbmem_console::write_fmt(format_args!($($arg)*))
    };
}

/// Macro for printing to CBMEM console with newline
#[macro_export]
macro_rules! cbmem_println {
    () => ($crate::cbmem_print!("\n"));
    ($($arg:tt)*) => ($crate::cbmem_print!("{}\n", format_args!($($arg)*)));
}
