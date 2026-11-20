//! Discover bootable entries on storage devices.

use super::{BootCategory, BootEntry, BootEntryKind, BootMenu, EFI_BOOT_PATH};
use crate::drivers::block::BlockDevice;
use crate::drivers::storage::{self, StorageDevice};
use crate::fs::boot::{self as boot_fs, BootFilesystem, Kind as FilesystemKind};
use crate::fs::{fat::FatFilesystem, gpt, iso9660};
use core::fmt::Write;
use heapless::String;

/// Discover boot entries from all storage devices
///
/// Scans every storage device for ESPs containing the arch-specific EFI
/// bootloader, falling back to El Torito on disks without a partition table.
///
/// # Returns
///
/// A `BootMenu` containing all discovered boot entries.
pub fn discover_boot_entries() -> BootMenu {
    discover_entries::<false>()
}

pub(crate) fn discover_entries<const NATIVE: bool>() -> BootMenu {
    let mut menu = BootMenu::new();

    log::info!("Discovering boot entries...");

    let mut devices = storage::devices();
    devices.retain(crate::boot_policy::menu_boot_allowed);
    if !crate::boot_policy::automatic_external_allowed() {
        // Internal entries first, so the default entry is internal.
        devices.sort_by_key(crate::boot_policy::device_is_external);
    }
    for device in &devices {
        match storage::with_disk(device.id, gpt::read_partitions_auto) {
            Ok(Ok(partitions)) => {
                discover_entries_on_disk::<NATIVE>(device, &partitions, &mut menu)
            }
            Ok(Err(gpt::GptError::OutOfMemory)) => {
                log::error!(
                    "Boot menu: out of heap scanning partitions on {}",
                    device.label
                );
            }
            _ if !NATIVE => try_el_torito_fallback(device, &mut menu),
            _ => {}
        }
    }

    // Keep FAT volumes and El Torito images ahead of ext boot entries.
    #[cfg(all(feature = "ext4", target_arch = "x86_64"))]
    if NATIVE || !crate::efi::auth::is_secure_boot_enabled() {
        discover_ext_entries(&devices, &mut menu);
    }

    log::info!("Found {} boot entries", menu.entry_count());

    menu
}

/// Discover boot entries on the partitions of one disk.
///
/// Check ESP candidates for FAT boot entries.
///
/// # Arguments
///
/// * `device` - Disk holding the partitions
/// * `partitions` - Partition table of the disk
/// * `menu` - Boot menu to add entries to
fn discover_entries_on_disk<const NATIVE: bool>(
    device: &StorageDevice,
    partitions: &[gpt::Partition],
    menu: &mut BootMenu,
) {
    for partition in partitions {
        let partition_num = partition.number;

        if partition.is_esp || is_potential_esp(partition) {
            boot_fs::with_filesystem(device.id, partition, FilesystemKind::Fat, |fs| {
                // An empty file cannot be a bootloader.
                if !NATIVE && matches!(fs.file_size(EFI_BOOT_PATH), Ok(1..)) {
                    let mut name: String<64> = String::new();
                    let _ = write!(name, "Boot Entry ({})", device.label);
                    if !menu.add_entry(BootEntry::new(
                        &name,
                        EFI_BOOT_PATH,
                        device,
                        partition_num,
                        partition.clone(),
                    )) {
                        return;
                    }
                }
                scan_partition_for_entries::<NATIVE>(
                    fs,
                    FilesystemKind::Fat,
                    device,
                    partition_num,
                    partition,
                    menu,
                );
            });
        }
    }
}

#[cfg(all(feature = "ext4", target_arch = "x86_64"))]
fn discover_ext_entries(devices: &[StorageDevice], menu: &mut BootMenu) {
    for device in devices.iter().filter(|device| !device.info.removable) {
        let partitions = match storage::with_disk(device.id, gpt::read_partitions_auto) {
            Ok(Ok(partitions)) => partitions,
            Ok(Err(gpt::GptError::OutOfMemory)) => {
                log::error!(
                    "Boot menu: out of heap scanning ext partitions on {}",
                    device.label
                );
                continue;
            }
            _ => continue,
        };
        let kind = FilesystemKind::Ext {
            media: device.info,
            discovery: true,
        };
        for partition in partitions.iter().filter(|partition| !partition.is_esp) {
            boot_fs::with_filesystem(device.id, partition, kind, |fs| {
                if !scan_bls_from(fs, kind, device, partition, "", menu) {
                    // On a root volume, BLS paths are relative to /boot.
                    scan_bls_from(fs, kind, device, partition, "boot/", menu);
                }
            });
        }
    }
}

/// Try El Torito (ISO9660) boot on a disk without a partition table
fn try_el_torito_fallback(device: &StorageDevice, menu: &mut BootMenu) {
    let _ = storage::with_disk(device.id, |disk| {
        let efi_image = match iso9660::find_efi_boot_image(disk) {
            Ok(img) => img,
            Err(_) => return,
        };

        if efi_image.sector_count == 0 {
            log::warn!("El Torito: EFI image has unknown size, skipping");
            return;
        }

        log::info!(
            "El Torito: boot image start_sector={}, sector_count={}, size_bytes={}",
            efi_image.start_sector,
            efi_image.sector_count,
            efi_image.size_bytes
        );

        // Create a synthetic partition for the El Torito boot image
        let block_size = disk.info().block_size;
        let partition = gpt::Partition {
            type_guid: [0u8; 16],
            partition_guid: [0u8; 16],
            first_lba: efi_image.start_sector,
            last_lba: efi_image.start_sector + efi_image.sector_count as u64 - 1,
            attributes: 0,
            is_esp: true,
            block_size,
            mbr_disk_signature: None,
            number: 0,
        };

        if !check_bootloader_exists(disk, efi_image.start_sector) {
            return;
        }

        let mut name: String<64> = String::new();
        let _ = write!(name, "ISO Boot ({})", device.label);

        let entry = BootEntry::new(
            &name,
            EFI_BOOT_PATH,
            device,
            0, // No partition number for El Torito
            partition,
        );

        menu.add_entry(entry);
    });
}

/// Check if a partition might be an ESP (fallback heuristic)
fn is_potential_esp(partition: &gpt::Partition) -> bool {
    // Small partitions (< 512 MB) are more likely to be boot partitions
    let size_mb = partition.size_bytes() / (1024 * 1024);
    size_mb > 0 && size_mb < 512 && partition.first_lba > 0
}

/// Resolve a configured path relative to the boot directory without truncating it.
fn boot_path(prefix: &str, path: &str) -> Option<String<128>> {
    boot_fs::check_path(path).ok()?;
    let relative = path.trim_start_matches(['/', '\\']);
    if relative.is_empty() {
        return None;
    }
    let mut result = String::new();
    result.push_str(prefix).ok()?;
    for c in relative.chars() {
        result.push(if c == '\\' { '/' } else { c }).ok()?;
    }
    Some(result)
}

/// Check if a bootloader exists on the given partition
fn check_bootloader_exists(disk: &mut dyn BlockDevice, partition_start: u64) -> bool {
    match FatFilesystem::new(disk, partition_start) {
        Ok(mut fat) => match fat.file_size(EFI_BOOT_PATH) {
            Ok(size) => {
                log::info!(
                    "Found {} ({} bytes) at LBA {}",
                    EFI_BOOT_PATH,
                    size,
                    partition_start
                );
                size > 0
            }
            Err(e) => {
                log::debug!("Bootloader not found at LBA {}: {:?}", partition_start, e);
                false
            }
        },
        Err(e) => {
            log::debug!("FAT mount failed at LBA {}: {:?}", partition_start, e);
            false
        }
    }
}

/// Scan a mounted volume for same-volume BLS and GRUB direct Linux entries.
fn scan_partition_for_entries<const NATIVE: bool>(
    fs: &mut dyn BootFilesystem,
    filesystem: FilesystemKind,
    device: &StorageDevice,
    partition_num: u32,
    partition: &gpt::Partition,
    menu: &mut BootMenu,
) {
    if !NATIVE && crate::efi::auth::is_secure_boot_enabled() {
        log::debug!("Secure Boot active: skipping direct Linux boot entry discovery");
        return;
    }

    scan_bls_from(fs, filesystem, device, partition, "", menu);

    // 2. Scan for GRUB config entries - only if Secure Boot is off
    // NOTE: GRUB entries from grub.cfg often reference kernels on the root partition,
    // not the ESP where grub.cfg lives. We only add entries if the kernel file
    // actually exists on this partition (for direct boot to work).
    // Direct boot bypasses signature verification, so we disable it with Secure Boot
    if let Ok(grub_config) = crate::grub::parse_config(fs) {
        // If GRUB has blscfg directive, BLS entries were already added above
        // Only add GRUB entries that have explicit linux/initrd paths AND
        // where the kernel file actually exists on this partition
        for grub_entry in grub_config.entries.iter() {
            if !grub_entry.linux.is_empty() {
                let Some(path) = boot_path("", &grub_entry.linux) else {
                    continue;
                };

                if fs.file_size(&path).is_ok() {
                    let mut name: String<64> = String::new();
                    let _ = name.push_str(&grub_entry.title);

                    let Some(initrd_paths) = grub_entry
                        .initrds
                        .iter()
                        .map(|path| boot_path("", path))
                        .collect::<Option<crate::bls::Initrds>>()
                    else {
                        continue;
                    };

                    let mut entry = BootEntry::new_with_kind(
                        &name,
                        &path,
                        device,
                        partition_num,
                        partition.clone(),
                        BootEntryKind::GrubLinux {
                            linux_path: path.clone(),
                            initrd_paths,
                            cmdline: grub_entry.options.clone(),
                        },
                        BootCategory::Grub,
                    );
                    entry.filesystem = filesystem;

                    if !menu.add_entry(entry) {
                        return; // Out of heap
                    }

                    log::debug!(
                        "Added GRUB entry '{}' (kernel exists on partition)",
                        grub_entry.title
                    );
                } else {
                    log::debug!(
                        "Skipping GRUB entry '{}' (kernel '{}' not found on this partition)",
                        grub_entry.title,
                        path
                    );
                }
            }
        }
    }

    // Payload discovery stays disabled until payload chainloading works.
}

/// Add only usable BLS entries. Return whether this location yielded an entry.
fn scan_bls_from(
    fs: &mut dyn BootFilesystem,
    filesystem: FilesystemKind,
    device: &StorageDevice,
    partition: &gpt::Partition,
    prefix: &str,
    menu: &mut BootMenu,
) -> bool {
    let Ok(discovery) = crate::bls::discover_entries_at(fs, prefix) else {
        return false;
    };
    let mut added = false;
    for config in &discovery.entries {
        let Some(path) = boot_path(prefix, &config.linux) else {
            continue;
        };
        let Some(initrd_paths) = config
            .initrds
            .iter()
            .map(|path| boot_path(prefix, path))
            .collect::<Option<crate::bls::Initrds>>()
        else {
            continue;
        };
        if core::iter::once(&path)
            .chain(&initrd_paths)
            .any(|path| !matches!(fs.file_size(path), Ok(1..)))
        {
            continue;
        }
        let mut entry = BootEntry::new_with_kind(
            config.display_title(),
            &path,
            device,
            partition.number,
            partition.clone(),
            BootEntryKind::BlsLinux {
                linux_path: path.clone(),
                initrd_paths,
                cmdline: config.options.clone(),
            },
            BootCategory::Bls,
        );
        entry.filesystem = filesystem.for_boot();
        if !menu.add_entry(entry) {
            break;
        }
        added = true;
        if !menu.default_chosen && discovery.is_default(config) {
            menu.selected = menu.entry_count() - 1;
            menu.default_chosen = true;
            log::info!("loader.conf default: '{}'", config.display_title());
        }
    }
    added
}
