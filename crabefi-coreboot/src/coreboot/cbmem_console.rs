//! Coreboot CBMEM Console Handoff
//!
//! This module tracks the coreboot in-memory console (CBMEM console) only so
//! the payload can disable it before handing control to the OS. The generic
//! CrabEFI logger is intentionally unaware of CBMEM.

use core::sync::atomic::{AtomicU64, Ordering};

use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

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

/// Initialize the CBMEM console with the given physical address.
///
/// # Arguments
/// * `addr` - Physical address of the CBMEM console structure
pub fn init(addr: u64) {
    if addr == 0 {
        return;
    }

    // Verify the console looks valid before enabling.
    unsafe {
        let header = &*(addr as *const CbmemConsoleHeader);
        let size = header.size;
        if (1024..=1024 * 1024).contains(&size) {
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

/// Disable the CBMEM console.
///
/// Called at ExitBootServices and SetVirtualAddressMap to prevent runtime code
/// from accessing the physical-only CBMEM buffer.
pub fn disable() {
    CBMEM_CONSOLE_ADDR.store(0, Ordering::Release);
}
