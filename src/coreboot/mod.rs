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

/// Store the coreboot framebuffer record address for later invalidation
pub fn store_framebuffer_record_addr(addr: u64) {
    crate::state::with_drivers_mut(|drivers| {
        drivers.coreboot_fb_record_addr = Some(addr);
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

/// Invalidate the coreboot framebuffer record in the coreboot tables.
///
/// This should be called at ExitBootServices to prevent a race condition
/// where Linux tries to use both the coreboot framebuffer (via simplefb)
/// and the EFI framebuffer (via efifb). By changing the record tag to
/// CB_TAG_UNUSED (0x0000), Linux will ignore the coreboot framebuffer
/// and only use the EFI GOP framebuffer.
///
/// # Safety
///
/// This function modifies memory in the coreboot tables area. It must only
/// be called when it's safe to modify that memory (at ExitBootServices).
pub unsafe fn invalidate_framebuffer_record() {
    let addr = crate::state::try_get().and_then(|state| state.drivers.coreboot_fb_record_addr);

    if let Some(record_addr) = addr {
        // The tag is the first 4 bytes of the record (u32)
        // Change it from CB_TAG_FRAMEBUFFER (0x0012) to CB_TAG_UNUSED (0x0000)
        //
        // Coreboot table records are aligned to LB_ENTRY_ALIGN (4 bytes), so this is safe.
        debug_assert!(
            record_addr % 4 == 0,
            "Coreboot framebuffer record address {:#x} not 4-byte aligned",
            record_addr
        );
        let tag_ptr = record_addr as *mut u32;
        let old_tag = tag_ptr.read_volatile();

        if old_tag == tables::tags::CB_TAG_FRAMEBUFFER {
            tag_ptr.write_volatile(tables::tags::CB_TAG_UNUSED);
            log::info!(
                "Invalidated coreboot framebuffer record at {:#x} (tag: {:#x} -> {:#x})",
                record_addr,
                old_tag,
                tables::tags::CB_TAG_UNUSED
            );
        } else {
            log::warn!(
                "Coreboot framebuffer record at {:#x} has unexpected tag {:#x}, not invalidating",
                record_addr,
                old_tag
            );
        }
    } else {
        log::debug!("No coreboot framebuffer record to invalidate");
    }
}
