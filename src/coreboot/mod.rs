//! Coreboot table parsing and system information
//!
//! This module parses the coreboot tables to extract information about
//! the system hardware, including memory map, serial port, framebuffer,
//! CBMEM console, and ACPI tables.
//!
//! It also provides FMAP (Flash Map) parsing for locating flash regions
//! like SMMSTORE. The FMAP location is obtained from coreboot's
//! LB_TAG_BOOT_MEDIA_PARAMS table entry.
//!
//! CFR (Coreboot Form Representation) parsing is also supported for
//! exposing firmware configuration options to the user.

pub mod cbmem_console;
pub mod cfr;
pub mod fmap;
pub mod framebuffer;
pub mod memory;
pub mod tables;

pub use cfr::{CfrForm, CfrInfo, CfrOption, CfrOptionType, CfrValue};
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
/// Returns the framebuffer info if available.
pub fn get_framebuffer() -> Option<FramebufferInfo> {
    crate::state::try_get().and_then(|state| state.drivers.framebuffer)
}

/// Store SMMSTORE v2 info in global state
pub fn store_smmstorev2(smmstore: Smmstorev2Info) {
    crate::state::with_drivers_mut(|drivers| {
        drivers.smmstorev2 = Some(smmstore);
    });
}

/// Get access to the global SMMSTORE v2 info
///
/// Returns the SMMSTORE v2 info if available.
pub fn get_smmstorev2() -> Option<Smmstorev2Info> {
    crate::state::try_get().and_then(|state| state.drivers.smmstorev2)
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
/// Returns the boot media info if available.
/// This includes the FMAP offset which can be used to locate flash regions.
pub fn get_boot_media() -> Option<BootMediaInfo> {
    crate::state::try_get().and_then(|state| state.drivers.boot_media)
}

// CFR info is stored separately because it can be very large with nested heapless::Vec.
// We use a heap-allocated Box stored via AtomicPtr to avoid stack overflow.
use alloc::boxed::Box;
use core::sync::atomic::{AtomicPtr, Ordering};

static CFR_PTR: AtomicPtr<CfrInfo> = AtomicPtr::new(core::ptr::null_mut());

/// Store CFR info in global state (heap-allocated).
///
/// # Panics
///
/// Panics if called more than once. The single-call invariant ensures that
/// `&'static` references handed out by [`get_cfr`] remain valid.
pub(crate) fn store_cfr(cfr: CfrInfo) {
    let boxed = Box::new(cfr);
    let ptr = Box::into_raw(boxed);
    let old = CFR_PTR.swap(ptr, Ordering::SeqCst);
    assert!(
        old.is_null(),
        "store_cfr must only be called once (existing CfrInfo would be freed while &'static refs may exist)"
    );
}

/// Get access to the global CFR info
///
/// Returns a reference to the CFR info if available. The data lives on the
/// heap and is never freed, so the reference is valid for the lifetime of
/// the program.
pub fn get_cfr() -> Option<&'static CfrInfo> {
    let ptr = CFR_PTR.load(Ordering::SeqCst);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: ptr was created from Box::into_raw in store_cfr() and remains
        // valid because store_cfr() is only called once during single-threaded init.
        // The data is never freed, so the 'static lifetime is sound.
        Some(unsafe { &*ptr })
    }
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
