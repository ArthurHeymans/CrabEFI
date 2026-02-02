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

use spin::Mutex;

pub use framebuffer::FramebufferInfo;
pub use memory::{MemoryRegion, MemoryType};
pub use tables::{
    BootMediaInfo, CorebootInfo, FlashMmapWindow, SerialInfo, Smmstorev2Info, SpiFlashInfo,
};

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

/// Global SPI flash info storage
///
/// This is populated during coreboot table parsing and provides
/// information about the system's SPI flash chip.
static GLOBAL_SPI_FLASH: Mutex<Option<SpiFlashInfo>> = Mutex::new(None);

/// Global boot media params storage
///
/// This is populated during coreboot table parsing and provides
/// information about the boot media layout including FMAP location.
static GLOBAL_BOOT_MEDIA: Mutex<Option<BootMediaInfo>> = Mutex::new(None);

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

/// Store SPI flash info globally for later access
pub fn store_spi_flash(spi_flash: SpiFlashInfo) {
    *GLOBAL_SPI_FLASH.lock() = Some(spi_flash);
}

/// Get access to the global SPI flash info
///
/// Returns a clone of the SPI flash info if available.
pub fn get_spi_flash() -> Option<SpiFlashInfo> {
    GLOBAL_SPI_FLASH.lock().clone()
}

/// Store boot media params globally for later access
pub fn store_boot_media(boot_media: BootMediaInfo) {
    *GLOBAL_BOOT_MEDIA.lock() = Some(boot_media);
}

/// Get access to the global boot media params
///
/// Returns a clone of the boot media info if available.
/// This includes the FMAP offset which can be used to locate flash regions.
pub fn get_boot_media() -> Option<BootMediaInfo> {
    GLOBAL_BOOT_MEDIA.lock().clone()
}
