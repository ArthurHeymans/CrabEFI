//! Coreboot table parsing and system information
//!
//! This module parses the coreboot tables to extract information about
//! the system hardware, including memory map, serial port, framebuffer,
//! CBMEM console, and ACPI tables.
//!
//! It also provides FMAP (Flash Map) parsing for locating flash regions
//! like SMMSTORE. The FMAP location is obtained from coreboot's
//! LB_TAG_BOOT_MEDIA_PARAMS table entry.

pub mod cbmem_console;
pub mod fmap;
pub mod framebuffer;
pub mod memory;
pub mod tables;

pub use framebuffer::FramebufferInfo;
pub use memory::{MemoryRegion, MemoryType};
pub use tables::{
    BootMediaInfo, CorebootInfo, FlashMmapWindow, SerialInfo, Smmstorev2Info, SpiFlashInfo,
};

/// Store framebuffer info in global state
pub fn store_framebuffer(fb: FramebufferInfo) {
    crate::state::with_drivers_mut(|drivers| {
        drivers.framebuffer = Some(fb);
    });
}

/// Get access to the global framebuffer info
///
/// Returns a clone of the framebuffer info if available.
pub fn get_framebuffer() -> Option<FramebufferInfo> {
    crate::state::try_get().and_then(|state| state.drivers.framebuffer.clone())
}

/// Store SMMSTORE v2 info in global state
pub fn store_smmstorev2(smmstore: Smmstorev2Info) {
    crate::state::with_drivers_mut(|drivers| {
        drivers.smmstorev2 = Some(smmstore);
    });
}

/// Get access to the global SMMSTORE v2 info
///
/// Returns a clone of the SMMSTORE v2 info if available.
pub fn get_smmstorev2() -> Option<Smmstorev2Info> {
    crate::state::try_get().and_then(|state| state.drivers.smmstorev2.clone())
}

/// Store SPI flash info in global state
pub fn store_spi_flash(spi_flash: SpiFlashInfo) {
    crate::state::with_drivers_mut(|drivers| {
        drivers.spi_flash = Some(spi_flash);
    });
}

/// Get access to the global SPI flash info
///
/// Returns a clone of the SPI flash info if available.
pub fn get_spi_flash() -> Option<SpiFlashInfo> {
    crate::state::try_get().and_then(|state| state.drivers.spi_flash.clone())
}

/// Store boot media params in global state
pub fn store_boot_media(boot_media: BootMediaInfo) {
    crate::state::with_drivers_mut(|drivers| {
        drivers.boot_media = Some(boot_media);
    });
}

/// Get access to the global boot media params
///
/// Returns a clone of the boot media info if available.
/// This includes the FMAP offset which can be used to locate flash regions.
pub fn get_boot_media() -> Option<BootMediaInfo> {
    crate::state::try_get().and_then(|state| state.drivers.boot_media.clone())
}
