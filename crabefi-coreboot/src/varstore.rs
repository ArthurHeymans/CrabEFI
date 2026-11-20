//! SPI flash windows and persistent variable store discovery.

use crate::{fmap, tables};

pub(crate) fn configure_pflash(cb_info: &tables::CorebootInfo) {
    if let Some(ref spi_flash) = cb_info.spi_flash
        && let Some(window) = spi_flash.mmap_windows.first()
    {
        crabefi::drivers::spi::qemu::configure_pflash(
            window.host_base as u64,
            spi_flash.flash_size,
        );
    } else if let Some(boot_media) = cb_info.boot_media
        && let Ok(flash_size) = u32::try_from(boot_media.boot_media_size)
        && let Some(host_base) = 0x1_0000_0000u64.checked_sub(boot_media.boot_media_size)
    {
        crabefi::drivers::spi::qemu::configure_pflash(host_base, flash_size);
    }
}

/// Coreboot-backed locator for CrabEFI's persistent variable store.
///
/// Coreboot can describe the store either directly via SMMSTORE v2 tables, or
/// indirectly via an FMAP region on the boot medium. Both mechanisms are
/// coreboot-specific, so they live in the coreboot payload instead of the
/// platform-agnostic CrabEFI persistence path.
pub(crate) struct CorebootVariableStoreLocator {
    smmstorev2: Option<tables::Smmstorev2Info>,
    boot_media: Option<tables::BootMediaInfo>,
    spi_flash: Option<tables::SpiFlashInfo>,
}

impl CorebootVariableStoreLocator {
    pub(crate) fn new(cb_info: &tables::CorebootInfo) -> Self {
        Self {
            smmstorev2: cb_info.smmstorev2,
            boot_media: cb_info.boot_media,
            spi_flash: cb_info.spi_flash.clone(),
        }
    }

    fn resolve_mapped_region(
        &self,
        phys_base: u64,
        size: u64,
    ) -> Option<crabefi::FirmwareStorageRegion> {
        if size == 0 {
            return None;
        }

        if let Some(spi_flash) = self.spi_flash.as_ref() {
            if let Some(region) = spi_flash.mmap_windows.iter().find_map(|window| {
                let window_phys = window.host_base as u64;
                let relative = phys_base.checked_sub(window_phys)?;
                let mapped_end = relative.checked_add(size)?;
                if mapped_end > window.size as u64 {
                    return None;
                }

                let offset = (window.flash_base as u64).checked_add(relative)?;
                let end = offset.checked_add(size)?;
                if end > spi_flash.flash_size as u64 {
                    return None;
                }

                Some(crabefi::FirmwareStorageRegion { offset, size })
            }) {
                return Some(region);
            }

            if let Some(region) =
                Self::resolve_top_of_4g_mapping(phys_base, size, spi_flash.flash_size as u64)
            {
                return Some(region);
            }
        }

        self.boot_media.and_then(|boot_media| {
            Self::resolve_top_of_4g_mapping(phys_base, size, boot_media.boot_media_size)
        })
    }

    fn resolve_top_of_4g_mapping(
        phys_base: u64,
        size: u64,
        flash_size: u64,
    ) -> Option<crabefi::FirmwareStorageRegion> {
        if flash_size == 0 {
            return None;
        }

        let mmap_base = 0x1_0000_0000u64.checked_sub(flash_size)?;
        let relative = phys_base.checked_sub(mmap_base)?;
        let end = relative.checked_add(size)?;
        if end > flash_size {
            return None;
        }

        Some(crabefi::FirmwareStorageRegion {
            offset: relative,
            size,
        })
    }
}

impl crabefi::VariableStoreLocator for CorebootVariableStoreLocator {
    fn locate_variable_store(
        &self,
        storage: &mut dyn crabefi::FirmwareStorage,
    ) -> Option<crabefi::VariableStoreRegion> {
        if let Some(smmstore) = self.smmstorev2 {
            log::info!(
                "Found SMMSTORE v2 in coreboot tables: {} blocks x {} KB at {:#x}",
                smmstore.num_blocks,
                smmstore.block_size / 1024,
                smmstore.mmap_addr
            );

            if let Some(size) = smmstore
                .num_blocks
                .checked_mul(smmstore.block_size)
                .map(u64::from)
                && size != 0
                && smmstore.mmap_addr != 0
                && let Some(region) = self.resolve_mapped_region(smmstore.mmap_addr, size)
            {
                return Some(crabefi::VariableStoreRegion::from_offset_with_mapped_read(
                    "SMMSTORE",
                    region.offset,
                    smmstore.mmap_addr,
                    region.size,
                ));
            }

            log::warn!(
                "Ignoring unresolvable SMMSTORE v2 mapping: mmap_addr={:#x}, num_blocks={}, block_size={}",
                smmstore.mmap_addr,
                smmstore.num_blocks,
                smmstore.block_size
            );
        }

        let fmap_offset = self.boot_media.map(|boot_media| boot_media.fmap_offset);
        let region = fmap::get_smmstore_from_fmap(storage, fmap_offset)?;

        log::info!(
            "Found '{}' in FMAP: offset={:#x}, size={} KB",
            region.name.as_str(),
            region.offset,
            region.size / 1024
        );

        Some(crabefi::VariableStoreRegion::from_offset(
            region.name.as_str(),
            region.offset,
            region.size as u64,
        ))
    }
}
