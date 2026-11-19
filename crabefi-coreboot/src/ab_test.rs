//! Test-only A/B slots for QEMU (feature `ab-test-slots`, ab-update-test).
//!
//! QEMU has no firmware slot selector, so this backend plays one: two slots
//! and a selector block in the blank lower half of the payload MM fixture's
//! 8 MiB flash, outside its FMAP. The selector byte stands for the decision an
//! early boot stage would make; the payload does not actually run from the
//! slot. Like a platform without an FMAP (fstart, for one), it describes its
//! layout through `fmap_regions` and `firmware_slots` only, and like AMD's PSP
//! it lets the slot change only in a capsule-update boot.

use super::CorebootCapsuleBackend;

const SLOT_A: (&str, u32) = ("AB_TEST_A", 0x10_0000);
const SLOT_B: (&str, u32) = ("AB_TEST_B", 0x20_0000);
const SLOT_SIZE: u32 = 0x10_0000;
/// One erase block; byte 0 is 0x01 when slot B boots.
const SELECTOR: u32 = 0x30_0000;
const SELECTOR_SIZE: u64 = 0x1000;

fn region((name, offset): (&str, u32)) -> crabefi::FmapRegion {
    let mut region_name = heapless::String::new();
    let _ = region_name.push_str(name);
    crabefi::FmapRegion {
        name: region_name,
        offset,
        size: SLOT_SIZE,
    }
}

/// The two slots, added to the FMAP regions a capsule may name.
pub fn regions() -> [crabefi::FmapRegion; 2] {
    [region(SLOT_A), region(SLOT_B)]
}

pub fn firmware_slots(backend: &mut CorebootCapsuleBackend) -> Option<crabefi::FirmwareSlots> {
    let boot_media = backend.boot_media?;
    let mut selector = [0u8; 1];
    if !super::payload_mm::read_flash(boot_media, SELECTOR, &mut selector) {
        return None;
    }
    let (running, inactive) = if selector[0] == 1 {
        (SLOT_B, SLOT_A)
    } else {
        (SLOT_A, SLOT_B)
    };
    log::info!(
        "A/B slots: running '{}', inactive '{}'",
        running.0,
        inactive.0
    );
    Some(crabefi::FirmwareSlots {
        running: region(running),
        inactive: region(inactive),
    })
}

pub fn activate_slot(
    _backend: &mut CorebootCapsuleBackend,
    slot: &crabefi::FmapRegion,
) -> Result<(), crabefi::StorageError> {
    let value = match (slot.name.as_str(), slot.offset) {
        (name, offset) if (name, offset) == SLOT_A => 0x00,
        (name, offset) if (name, offset) == SLOT_B => 0x01,
        _ => return Err(crabefi::StorageError::InvalidArgument),
    };
    if !crabefi::efi::capsule::update_boot() {
        return Err(crabefi::StorageError::WriteProtected);
    }
    let erased = crabefi::efi::payload_mm::firmware_erase(u64::from(SELECTOR), SELECTOR_SIZE);
    let status = if erased == r_efi::efi::Status::SUCCESS {
        crabefi::efi::payload_mm::firmware_write(u64::from(SELECTOR), &[value])
    } else {
        erased
    };
    if status != r_efi::efi::Status::SUCCESS {
        log::error!("Writing the A/B test selector failed: {:?}", status);
        return Err(crabefi::StorageError::IoError);
    }
    Ok(())
}
