//! Runtime Services Log Buffer
//!
//! A fixed-address, warm-reboot-persistent ring buffer for logging what the
//! OS does via Runtime Services (primarily SetVariable calls).
//!
//! # Memory layout  (64 KB at 0x70000, NOLOAD / PT_NULL)
//!
//! ```text
//! +------------------+  <- _rt_log_start
//! | Header (16 bytes)|
//! |   Magic "CRTL"   |  4 bytes
//! |   write_pos      |  4 bytes — next byte to write (wraps at DATA_SIZE)
//! |   wrapped        |  1 byte  — 1 if the ring has wrapped at least once
//! |   _pad           |  7 bytes
//! +------------------+
//! | Data ring        |  rest of 64 KB
//! +------------------+  <- _rt_log_end
//! ```
//!
//! Lines are plain ASCII / UTF-8, newline-terminated.  On wrap the oldest
//! data is silently overwritten — this is a best-effort debug aid.
//!
//! # Safety
//!
//! These functions are called from runtime services context after
//! ExitBootServices.  No allocator, no `log` crate, no locks — only
//! raw pointer writes and simple atomics.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};

// Linker symbols
unsafe extern "C" {
    static _rt_log_start: u8;
    static _rt_log_end: u8;
}

const MAGIC: u32 = 0x4c545243; // "CRTL"
const HEADER_SIZE: usize = 16;

/// Whether the log has been initialised this boot session.
static INITIALISED: AtomicBool = AtomicBool::new(false);

#[repr(C)]
struct Header {
    magic: u32,
    write_pos: u32, // offset into data area (0..DATA_SIZE-1)
    wrapped: u8,
    _pad: [u8; 7],
}

#[inline]
fn base() -> *mut u8 {
    unsafe { &_rt_log_start as *const u8 as *mut u8 }
}

#[inline]
fn total_size() -> usize {
    unsafe {
        let s = &_rt_log_start as *const u8 as usize;
        let e = &_rt_log_end as *const u8 as usize;
        e - s
    }
}

#[inline]
fn data_size() -> usize {
    total_size() - HEADER_SIZE
}

#[inline]
fn header() -> *mut Header {
    base() as *mut Header
}

#[inline]
fn data_base() -> *mut u8 {
    // SAFETY: base + HEADER_SIZE is within the linker-allocated region.
    unsafe { base().add(HEADER_SIZE) }
}

/// Initialise a fresh log for this boot session.
///
/// Call this AFTER [`dump`] so the previous boot's data has been printed.
pub fn init() {
    let h = header();
    // SAFETY: pointer is within the NOLOAD section we own.
    unsafe {
        (*h).magic = MAGIC;
        (*h).write_pos = 0;
        (*h).wrapped = 0;
        (*h)._pad = [0u8; 7];
    }
    INITIALISED.store(true, Ordering::Relaxed);
}

/// Dump the previous boot's log to the `log` crate (called early on next boot).
///
/// Returns the number of bytes dumped, or 0 if the buffer was empty / invalid.
pub fn dump() -> usize {
    let h = header();
    // SAFETY: reading our own NOLOAD section.
    let (magic, write_pos, wrapped) =
        unsafe { ((*h).magic, (*h).write_pos as usize, (*h).wrapped) };

    if magic != MAGIC {
        log::debug!(
            "[rtlog] No valid runtime log from previous boot (magic={:#010x})",
            magic
        );
        return 0;
    }

    let ds = data_size();
    let write_pos = write_pos.min(ds);

    if write_pos == 0 && wrapped == 0 {
        log::info!("[rtlog] Previous runtime log is empty");
        return 0;
    }

    log::info!("[rtlog] ── Runtime services log from previous boot ──");

    let db = data_base();

    // Build a contiguous slice (start..end of valid data).
    // If wrapped: data is [write_pos..ds] ++ [0..write_pos]
    // If not:     data is [0..write_pos]
    let total_bytes = if wrapped != 0 { ds } else { write_pos };

    // Print line by line so each line goes through the log formatter.
    let mut printed = 0usize;
    let mut line_start = 0usize;

    // Helper: byte at logical offset `i`
    let byte_at = |i: usize| -> u8 {
        let phys = if wrapped != 0 {
            (write_pos + i) % ds
        } else {
            i
        };
        // SAFETY: phys < ds, data_base() + ds is within our section.
        unsafe { *db.add(phys) }
    };

    for i in 0..=total_bytes {
        let is_end = i == total_bytes;
        let b = if is_end { b'\n' } else { byte_at(i) };

        if b == b'\n' || is_end {
            let line_len = i - line_start;
            if line_len > 0 {
                // Collect into a small stack buffer for logging
                let mut buf = [0u8; 256];
                let capped = line_len.min(buf.len() - 1);
                for (j, slot) in buf[..capped].iter_mut().enumerate() {
                    *slot = byte_at(line_start + j);
                }
                if let Ok(s) = core::str::from_utf8(&buf[..capped]) {
                    log::info!("[rtlog] {}", s);
                }
                printed += line_len;
            }
            line_start = i + 1;
        }
    }

    log::info!("[rtlog] ── end of runtime log ({} bytes) ──", total_bytes);
    printed
}

/// Append a string to the runtime log ring buffer.
///
/// Safe to call from any context after ExitBootServices — no allocations,
/// no locks, no `log` crate.  Silently drops data when the buffer is full
/// (ring wraps).
pub fn append(s: &str) {
    if !INITIALISED.load(Ordering::Relaxed) {
        return;
    }

    let h = header();
    // SAFETY: our NOLOAD section, no concurrent writers (single-threaded runtime).
    let ds = data_size();
    let db = data_base();

    for &b in s.as_bytes() {
        let pos = unsafe { (*h).write_pos as usize };
        // SAFETY: pos < ds guaranteed by the modulo below.
        unsafe {
            *db.add(pos) = b;
            let next = pos + 1;
            if next >= ds {
                (*h).write_pos = 0;
                (*h).wrapped = 1;
            } else {
                (*h).write_pos = next as u32;
            }
        }
    }
}

/// Append a string followed by a newline.
#[inline]
pub fn appendln(s: &str) {
    append(s);
    append("\n");
}

/// Append formatted text using a fixed-size stack buffer.
///
/// Runtime error paths must not use `alloc::format!` after ExitBootServices.
/// Messages longer than the buffer are safely truncated.
pub fn append_fmt(args: fmt::Arguments<'_>) {
    struct StackBuffer {
        bytes: [u8; 128],
        len: usize,
    }

    impl Write for StackBuffer {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let remaining = self.bytes.len().saturating_sub(self.len);
            let mut copy_len = remaining.min(s.len());
            while copy_len > 0 && !s.is_char_boundary(copy_len) {
                copy_len -= 1;
            }
            self.bytes[self.len..self.len + copy_len].copy_from_slice(&s.as_bytes()[..copy_len]);
            self.len += copy_len;
            Ok(())
        }
    }

    let mut buffer = StackBuffer {
        bytes: [0; 128],
        len: 0,
    };
    let _ = buffer.write_fmt(args);
    // SAFETY: `fmt::Write::write_str` only receives valid UTF-8 and copies
    // complete byte prefixes from those strings.
    let text = unsafe { core::str::from_utf8_unchecked(&buffer.bytes[..buffer.len]) };
    append(text);
}

/// Append formatted text followed by a newline.
#[inline]
pub fn append_fmtln(args: fmt::Arguments<'_>) {
    append_fmt(args);
    append("\n");
}

/// Append a decimal u64.
pub fn append_u64(v: u64) {
    if v == 0 {
        append("0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    let mut n = v;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    // SAFETY: buf[i..] contains valid ASCII digits.
    if let Ok(s) = core::str::from_utf8(&buf[i..]) {
        append(s);
    }
}

/// Append a hex u64 with "0x" prefix.
pub fn append_hex(v: u64) {
    append("0x");
    if v == 0 {
        append("0");
        return;
    }
    let mut buf = [0u8; 16];
    let mut i = buf.len();
    let mut n = v;
    while n > 0 {
        i -= 1;
        let nibble = (n & 0xF) as u8;
        buf[i] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
        n >>= 4;
    }
    // SAFETY: buf[i..] contains valid ASCII hex chars.
    if let Ok(s) = core::str::from_utf8(&buf[i..]) {
        append(s);
    }
}

/// Register the rt_log region as RuntimeServicesData so the OS preserves it.
pub fn register_region() {
    use crate::efi::allocator::{MemoryType, PAGE_SIZE};

    let buf_base = unsafe { &_rt_log_start as *const u8 as u64 };
    let buf_pages = (total_size() as u64).div_ceil(PAGE_SIZE);

    // carve_out_region splits the containing map entry; force_add_region
    // would push an overlapping duplicate that breaks Linux's EFI mapping.
    if let Err(e) = crate::efi::allocator::carve_out_region(
        buf_base,
        buf_pages,
        MemoryType::RuntimeServicesData,
    ) {
        log::warn!(
            "[rtlog] Could not register rt_log region at {:#x}: {:?}",
            buf_base,
            e
        );
    } else {
        log::info!(
            "[rtlog] Runtime log buffer at {:#x} ({} pages) registered as RuntimeServicesData",
            buf_base,
            buf_pages
        );
    }
}
