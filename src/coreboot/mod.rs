//! Coreboot table parsing and system information
//!
//! This module parses the coreboot tables to extract information about
//! the system hardware, including memory map, serial port, framebuffer,
//! CBMEM console, and ACPI tables.

pub mod cbmem_console;
pub mod framebuffer;
pub mod memory;
pub mod tables;

use spin::Mutex;

pub use framebuffer::FramebufferInfo;
pub use memory::{MemoryRegion, MemoryType};
pub use tables::{CorebootInfo, SerialInfo, Smmstorev2Info};

/// Global framebuffer info storage
///
/// This is populated during coreboot table parsing and can be accessed
/// by other modules (like the boot menu) for framebuffer rendering.
static GLOBAL_FRAMEBUFFER: Mutex<Option<FramebufferInfo>> = Mutex::new(None);

/// Global SMMSTORE v2 info storage
///
/// This is populated during coreboot table parsing and can be accessed
/// by the variable store persistence layer for UEFI variable storage.
static GLOBAL_SMMSTOREV2: Mutex<Option<Smmstorev2Info>> = Mutex::new(None);

/// Store framebuffer info globally for later access
pub fn store_framebuffer(fb: FramebufferInfo) {
    *GLOBAL_FRAMEBUFFER.lock() = Some(fb);
}

/// Get access to the global framebuffer info
///
/// Returns a clone of the framebuffer info if available.
pub fn get_framebuffer() -> Option<FramebufferInfo> {
    GLOBAL_FRAMEBUFFER.lock().clone()
}

/// Store SMMSTORE v2 info globally for later access
pub fn store_smmstorev2(smmstore: Smmstorev2Info) {
    *GLOBAL_SMMSTOREV2.lock() = Some(smmstore);
}

/// Get access to the global SMMSTORE v2 info
///
/// Returns a clone of the SMMSTORE v2 info if available.
pub fn get_smmstorev2() -> Option<Smmstorev2Info> {
    GLOBAL_SMMSTOREV2.lock().clone()
}
