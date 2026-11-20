//! Capsule backend for coreboot SPI/FMAP and payload MM.

#[cfg(all(feature = "payload-mm", not(feature = "ab-test-slots")))]
use crate::amd_ab;
#[cfg(feature = "payload-mm")]
use crate::payload_mm;
use crate::{fmap, tables};
#[cfg(feature = "ab-test-slots")]
mod ab_test;

/// Coreboot SPI/FMAP implementation of the platform capsule backend.
pub(crate) struct CorebootCapsuleBackend {
    firmware_info: Option<crabefi::FirmwareInfo>,
    fmap_offset: Option<u64>,
    boot_media: Option<tables::BootMediaInfo>,
    fmap_loaded: bool,
    fmap_regions: alloc::vec::Vec<crabefi::FmapRegion>,
}

impl CorebootCapsuleBackend {
    pub(crate) fn new(
        firmware_info: Option<crabefi::FirmwareInfo>,
        boot_media: Option<tables::BootMediaInfo>,
    ) -> Self {
        Self {
            firmware_info,
            fmap_offset: boot_media.map(|media| media.fmap_offset),
            boot_media,
            fmap_loaded: false,
            fmap_regions: alloc::vec::Vec::new(),
        }
    }

    fn load_fmap(&mut self) {
        if self.fmap_loaded {
            return;
        }
        self.fmap_loaded = true;
        #[cfg(feature = "ab-test-slots")]
        self.fmap_regions.extend(ab_test::regions());
        // Payload MM owns the flash; the FMAP is read from the mapped flash.
        #[cfg(feature = "payload-mm")]
        if crabefi::efi::payload_mm::active()
            && let Some(boot_media) = self.boot_media
        {
            let regions = &mut self.fmap_regions;
            if payload_mm::for_each_fmap_area(boot_media, |name, offset, size| {
                let mut region_name = heapless::String::new();
                if region_name.push_str(name).is_ok() {
                    regions.push(crabefi::FmapRegion {
                        name: region_name,
                        offset,
                        size,
                    });
                }
            })
            .is_none()
            {
                log::warn!("Capsule backend could not load FMAP");
            }
            return;
        }
        let parsed = crabefi::efi::varstore::with_spi_storage_mut(|storage| {
            fmap::read_fmap(storage.controller_mut(), self.fmap_offset)
        })
        .flatten();
        let Some(parsed) = parsed else {
            log::warn!("Capsule backend could not load FMAP");
            return;
        };
        for area in parsed.areas {
            self.fmap_regions.push(crabefi::FmapRegion {
                name: area.name,
                offset: area.offset,
                size: area.size,
            });
        }
    }
}

#[cfg(all(feature = "payload-mm", not(feature = "ab-test-slots")))]
impl CorebootCapsuleBackend {
    /// AMD PSP A/B slot headers and the FMAP region of each slot: the largest
    /// area holding that slot's PSP L2 directory but not the other's.
    fn slot_regions(&mut self) -> Option<([amd_ab::Ish; 2], [crabefi::FmapRegion; 2])> {
        if !crabefi::efi::payload_mm::active() {
            return None;
        }
        let boot_media = self.boot_media?;
        let ishes = amd_ab::read_ishes(&mut |offset, buf: &mut [u8]| {
            payload_mm::read_flash(boot_media, offset, buf)
        })?;
        self.load_fmap();
        let holds = |region: &crabefi::FmapRegion, at: u32| {
            (region.offset..region.offset.saturating_add(region.size)).contains(&at)
        };
        let region_of = |mine: u32, other: u32| {
            self.fmap_regions
                .iter()
                .filter(|region| holds(region, mine) && !holds(region, other))
                .max_by_key(|region| region.size)
                .cloned()
        };
        let a = region_of(ishes[0].pl2, ishes[1].pl2)?;
        let b = region_of(ishes[1].pl2, ishes[0].pl2)?;
        Some((ishes, [a, b]))
    }

    /// AMD PSP A/B: the running slot holds the CBFS coreboot booted from.
    fn psp_firmware_slots(&mut self) -> Option<crabefi::FirmwareSlots> {
        let (ishes, regions) = self.slot_regions()?;
        let running = crabefi::CapsuleBackend::running_firmware_offset(self)?;
        let index = regions
            .iter()
            .position(|region| (region.offset..region.offset + region.size).contains(&running))?;
        log::info!(
            "A/B slots: running '{}' (priority {:#x}), inactive '{}' (priority {:#x})",
            regions[index].name,
            ishes[index].priority,
            regions[1 - index].name,
            ishes[1 - index].priority
        );
        Some(crabefi::FirmwareSlots {
            running: regions[index].clone(),
            inactive: regions[1 - index].clone(),
        })
    }

    /// AMD PSP A/B: raise the slot's directory priority over the other's.
    /// Only a capsule-update boot may write the slot headers
    /// (`WriteProtected` otherwise).
    fn psp_activate_slot(
        &mut self,
        slot: &crabefi::FmapRegion,
    ) -> Result<(), crabefi::StorageError> {
        let (ishes, regions) = self
            .slot_regions()
            .ok_or(crabefi::StorageError::NotSupported)?;
        let target = regions
            .iter()
            .position(|region| region.name == slot.name && region.offset == slot.offset)
            .ok_or(crabefi::StorageError::InvalidArgument)?;
        let boot_media = self
            .boot_media
            .ok_or(crabefi::StorageError::NotInitialized)?;
        let writes = amd_ab::activation(&ishes[target], &ishes[1 - target]);
        // Both slots share the memory training cache, and the ABL reuses it even
        // when the other slot's APCB differs (e.g. the UMA size): the next boot
        // must train again. Erased first, so a power loss before the header
        // write only costs the old slot one training boot.
        if let Some(cache) = self
            .fmap_regions
            .iter()
            .find(|region| region.name.as_str() == "RW_MRC_CACHE")
            .filter(|_| !writes.is_empty())
        {
            let status = crabefi::efi::payload_mm::firmware_erase(
                u64::from(cache.offset),
                u64::from(cache.size),
            );
            if status == r_efi::efi::Status::WRITE_PROTECTED {
                return Err(crabefi::StorageError::WriteProtected);
            }
            if status != r_efi::efi::Status::SUCCESS {
                log::error!("Erasing RW_MRC_CACHE failed: {:?}", status);
                return Err(crabefi::StorageError::IoError);
            }
        }
        for (offset, header) in writes {
            // The header has its own sector: rewrite the sector with it.
            let sector = offset & !0xFFF;
            let mut data = alloc::vec![0u8; 0x1000];
            if !payload_mm::read_flash(boot_media, sector, &mut data) {
                return Err(crabefi::StorageError::IoError);
            }
            let at = (offset - sector) as usize;
            data[at..at + header.len()].copy_from_slice(&header);
            let status = match crabefi::efi::payload_mm::firmware_erase(u64::from(sector), 0x1000) {
                r_efi::efi::Status::SUCCESS => {
                    crabefi::efi::payload_mm::firmware_write(u64::from(sector), &data)
                }
                status => status,
            };
            if status == r_efi::efi::Status::WRITE_PROTECTED {
                // Not a capsule-update boot.
                return Err(crabefi::StorageError::WriteProtected);
            }
            if status != r_efi::efi::Status::SUCCESS {
                log::error!(
                    "Writing the slot header at {:#x} failed: {:?}",
                    offset,
                    status
                );
                return Err(crabefi::StorageError::IoError);
            }
        }
        Ok(())
    }
}

// Capsule signing roots from CRABEFI_CAPSULE_TRUST_CERTS (build.rs).
include!(concat!(env!("OUT_DIR"), "/capsule_trust.rs"));

impl crabefi::CapsuleBackend for CorebootCapsuleBackend {
    fn firmware_info(&self) -> Option<&crabefi::FirmwareInfo> {
        self.firmware_info.as_ref()
    }

    fn capsule_trust_store(&self) -> &[&[u8]] {
        CAPSULE_TRUST_STORE
    }

    #[cfg(feature = "payload-mm")]
    fn firmware_slots(&mut self) -> Option<crabefi::FirmwareSlots> {
        #[cfg(feature = "ab-test-slots")]
        return ab_test::firmware_slots(self);
        #[cfg(not(feature = "ab-test-slots"))]
        self.psp_firmware_slots()
    }

    #[cfg(feature = "payload-mm")]
    fn firmware_slots_expected(&mut self) -> bool {
        #[cfg(feature = "ab-test-slots")]
        return true;
        // From the FMAP, which a lost slot header leaves intact. The PSP
        // directory is no guide: AMD's PSP firmware lists A/B slot headers
        // even in single-image layouts, where both point into one CBFS.
        #[cfg(not(feature = "ab-test-slots"))]
        {
            self.load_fmap();
            self.fmap_regions
                .iter()
                .any(|region| matches!(region.name.as_str(), "COREBOOT_B" | "RECOVERY_B"))
        }
    }

    #[cfg(feature = "payload-mm")]
    fn activate_slot(&mut self, slot: &crabefi::FmapRegion) -> Result<(), crabefi::StorageError> {
        #[cfg(feature = "ab-test-slots")]
        return ab_test::activate_slot(self, slot);
        #[cfg(not(feature = "ab-test-slots"))]
        self.psp_activate_slot(slot)
    }

    fn read_firmware_region(
        &mut self,
        region_name: &str,
        offset: u32,
        buffer: &mut [u8],
    ) -> Result<(), crabefi::StorageError> {
        self.load_fmap();
        let region = self
            .fmap_regions
            .iter()
            .find(|region| region.name.as_str() == region_name)
            .ok_or(crabefi::StorageError::InvalidArgument)?;
        if u64::from(offset) + buffer.len() as u64 > u64::from(region.size) {
            return Err(crabefi::StorageError::InvalidArgument);
        }
        let at = region.offset + offset;
        // Through MM, which reaches all of the flash the writes reach (the
        // window mapped below 4 GiB holds at most 16 MiB).
        #[cfg(feature = "payload-mm")]
        if crabefi::efi::payload_mm::active() {
            return match crabefi::efi::payload_mm::firmware_read(u64::from(at), buffer) {
                r_efi::efi::Status::SUCCESS => Ok(()),
                _ => Err(crabefi::StorageError::IoError),
            };
        }
        crabefi::efi::varstore::with_spi_storage_mut(|storage| {
            crabefi::FirmwareStorage::read(storage.controller_mut(), u64::from(at), buffer)
        })
        .ok_or(crabefi::StorageError::NotInitialized)?
    }

    fn running_firmware_offset(&self) -> Option<u32> {
        // coreboot reports the CBFS it booted from (COREBOOT or COREBOOT_B with PSP A/B).
        u32::try_from(self.boot_media?.cbfs_offset).ok()
    }

    fn write_firmware_region(
        &mut self,
        region_name: &str,
        offset: u32,
        data: &[u8],
    ) -> Result<(), crabefi::StorageError> {
        self.load_fmap();
        let region = self
            .fmap_regions
            .iter()
            .find(|region| region.name.as_str() == region_name)
            .ok_or(crabefi::StorageError::InvalidArgument)?;
        let write_offset = region
            .offset
            .checked_add(offset)
            .ok_or(crabefi::StorageError::InvalidArgument)?;
        if offset as u64 + data.len() as u64 > u64::from(region.size) {
            return Err(crabefi::StorageError::InvalidArgument);
        }
        // With payload MM only SMM may write the flash (firmware phase only).
        #[cfg(feature = "payload-mm")]
        if crabefi::efi::payload_mm::active() {
            let erased = crabefi::efi::payload_mm::firmware_erase(
                u64::from(region.offset),
                u64::from(region.size),
            );
            let status = if erased == r_efi::efi::Status::SUCCESS {
                crabefi::efi::payload_mm::firmware_write(u64::from(write_offset), data)
            } else {
                erased
            };
            return match status {
                r_efi::efi::Status::SUCCESS => Ok(()),
                r_efi::efi::Status::ACCESS_DENIED => Err(crabefi::StorageError::AccessDenied),
                _ => Err(crabefi::StorageError::IoError),
            };
        }
        crabefi::efi::varstore::with_spi_storage_mut(|storage| {
            let controller = storage.controller_mut();
            crabefi::FirmwareStorage::enable_writes(controller)?;
            crabefi::FirmwareStorage::erase(
                controller,
                u64::from(region.offset),
                u64::from(region.size),
            )?;
            crabefi::FirmwareStorage::write(controller, u64::from(write_offset), data)
        })
        .ok_or(crabefi::StorageError::NotInitialized)?
    }

    fn fmap_regions(&mut self) -> &[crabefi::FmapRegion] {
        self.load_fmap();
        &self.fmap_regions
    }
}
