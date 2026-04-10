//! ESP Capsule-on-Disk Scanner
//!
//! Scans the EFI System Partition for capsule files placed by the OS in
//! `\EFI\UpdateCapsule\`, as defined by the UEFI specification.
//!
//! # Flow
//!
//! 1. Check `OsIndications` for `EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED`
//! 2. Locate the EFI System Partition
//! 3. Read all files from `\EFI\UpdateCapsule\`
//! 4. Return capsule data buffers for processing
//!
//! # References
//!
//! - UEFI Specification 2.10, Section 8.5.5 — Delivery of Capsules via file on Mass Storage device

use alloc::vec;
use alloc::vec::Vec;

/// The directory on the ESP where capsule files are placed.
pub const CAPSULE_FILE_DIRECTORY: &str = "EFI\\UpdateCapsule";

/// `OsIndications` bit for FMP capsule support.
pub const EFI_OS_INDICATIONS_FMP_CAPSULE_SUPPORTED: u64 = 0x0000_0000_0000_0001;

/// `OsIndications` bit for file-based capsule delivery support.
pub const EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED: u64 = 0x0000_0000_0000_0004;

/// Capsule data loaded from the ESP.
pub struct DiskCapsule {
    /// File name (for logging).
    pub filename: heapless::String<256>,
    /// Raw capsule file contents.
    pub data: Vec<u8>,
}

/// Check if file-based capsule delivery was requested via `OsIndications`.
///
/// Reads the `OsIndications` EFI variable and checks whether the
/// `FILE_CAPSULE_DELIVERY_SUPPORTED` bit is set.
pub fn is_file_capsule_delivery_requested() -> bool {
    use crate::efi::auth::EFI_GLOBAL_VARIABLE_GUID;
    use crate::state;

    let efi = state::efi();
    let os_ind_name: &[u16] = &[
        'O' as u16, 's' as u16, 'I' as u16, 'n' as u16, 'd' as u16, 'i' as u16, 'c' as u16,
        'a' as u16, 't' as u16, 'i' as u16, 'o' as u16, 'n' as u16, 's' as u16, 0,
    ];
    for var in &efi.variables {
        if !var.in_use {
            continue;
        }
        if var.vendor_guid != EFI_GLOBAL_VARIABLE_GUID {
            continue;
        }
        if crate::efi::utils::ucs2_eq(&var.name, os_ind_name) && var.data_size >= 8 {
            let value = u64::from_le_bytes([
                var.data[0],
                var.data[1],
                var.data[2],
                var.data[3],
                var.data[4],
                var.data[5],
                var.data[6],
                var.data[7],
            ]);
            return (value & EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED) != 0;
        }
    }
    false
}

/// Scan the ESP for capsule files and return their contents.
///
/// This uses CrabEFI's existing filesystem infrastructure (FAT/GPT)
/// to read files from `\EFI\UpdateCapsule\` on the ESP.
///
/// Returns an empty vec if no capsules are found or if the ESP is not
/// accessible.
pub fn scan_esp_for_capsules() -> Vec<DiskCapsule> {
    log::info!(
        "Scanning ESP for capsule files in {}",
        CAPSULE_FILE_DIRECTORY
    );

    let mut capsules = Vec::new();

    // Use the auth module's disk search infrastructure to find block devices
    // and scan for the ESP.
    crate::efi::auth::search_all_disks(|block_dev, dev_type| {
        scan_device_for_capsules(block_dev, dev_type, &mut capsules)
    });

    if capsules.is_empty() {
        log::info!("No capsule files found on ESP");
    } else {
        log::info!("Found {} capsule file(s) on ESP", capsules.len());
    }

    capsules
}

/// Scan a single block device for capsule files on the ESP.
fn scan_device_for_capsules(
    block_dev: &mut dyn crate::drivers::block::BlockDevice,
    dev_type: &'static str,
    capsules: &mut Vec<DiskCapsule>,
) -> Option<()> {
    use crate::fs::fat::FatFilesystem;
    use crate::fs::gpt;

    // Parse GPT header
    let header = match gpt::read_gpt_header(block_dev) {
        Ok(h) => h,
        Err(_) => return None,
    };

    // Read partition table
    let partitions = match gpt::read_partitions(block_dev, &header) {
        Ok(p) => p,
        Err(_) => return None,
    };

    for part in &partitions {
        if !part.is_esp {
            continue;
        }

        log::info!(
            "Found ESP on {} at LBA {}..{}",
            dev_type,
            part.first_lba,
            part.last_lba
        );

        // Mount the FAT filesystem on the ESP
        let mut fat_fs = match FatFilesystem::new(block_dev, part.first_lba) {
            Ok(fs) => fs,
            Err(e) => {
                log::warn!("Failed to mount FAT filesystem on ESP: {:?}", e);
                continue;
            }
        };

        // List capsule files in the UpdateCapsule directory
        // Look for all file types (.cap, .bin, or any other)
        let file_names = match fat_fs.list_directory_files(CAPSULE_FILE_DIRECTORY, "") {
            Ok(names) => names,
            Err(_) => {
                log::debug!("No {} directory on this ESP", CAPSULE_FILE_DIRECTORY);
                continue;
            }
        };

        for name in &file_names {
            let path = alloc::format!("{}\\{}", CAPSULE_FILE_DIRECTORY, name);

            // Get file size
            let file_size = match fat_fs.file_size(&path) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("Failed to get size of {}: {:?}", path, e);
                    continue;
                }
            };

            if file_size == 0 {
                continue;
            }

            // Read the file
            let mut buffer = vec![0u8; file_size as usize];
            match fat_fs.read_file_all(&path, buffer.as_mut_slice()) {
                Ok(bytes_read) => {
                    buffer.truncate(bytes_read);
                    log::info!("Loaded capsule file: {} ({} bytes)", name, bytes_read);

                    capsules.push(DiskCapsule {
                        filename: name.clone(),
                        data: buffer,
                    });
                }
                Err(e) => {
                    log::warn!("Failed to read capsule file {}: {:?}", path, e);
                }
            }
        }
    }

    // Return None to keep searching other devices
    None
}

/// Install the `OsIndicationsSupported` EFI variable.
///
/// This tells the OS which capsule delivery mechanisms are available.
/// Called during boot initialization.
pub fn install_os_indications_supported() {
    use crate::efi::auth::EFI_GLOBAL_VARIABLE_GUID;

    let supported = EFI_OS_INDICATIONS_FMP_CAPSULE_SUPPORTED
        | EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED;

    let name: &[u16] = &[
        'O' as u16, 's' as u16, 'I' as u16, 'n' as u16, 'd' as u16, 'i' as u16, 'c' as u16,
        'a' as u16, 't' as u16, 'i' as u16, 'o' as u16, 'n' as u16, 's' as u16, 'S' as u16,
        'u' as u16, 'p' as u16, 'p' as u16, 'o' as u16, 'r' as u16, 't' as u16, 'e' as u16,
        'd' as u16, 0,
    ];

    let data = supported.to_le_bytes();

    // BS + RT (read-only, not NV — the firmware always sets it)
    let attributes = 0x06u32; // BS | RT

    crate::efi::varstore::update_variable_in_memory(
        &EFI_GLOBAL_VARIABLE_GUID,
        name,
        attributes,
        &data,
    );

    log::info!(
        "OsIndicationsSupported set: FMP={}, FileCapsule={}",
        (supported & EFI_OS_INDICATIONS_FMP_CAPSULE_SUPPORTED) != 0,
        (supported & EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED) != 0
    );
}

/// Clear the capsule-related bits in `OsIndications` after processing.
///
/// This prevents re-processing on subsequent boots.
pub fn clear_os_indications_capsule_bits() {
    use crate::efi::auth::EFI_GLOBAL_VARIABLE_GUID;
    use crate::state;

    let os_ind_name: &[u16] = &[
        'O' as u16, 's' as u16, 'I' as u16, 'n' as u16, 'd' as u16, 'i' as u16, 'c' as u16,
        'a' as u16, 't' as u16, 'i' as u16, 'o' as u16, 'n' as u16, 's' as u16, 0,
    ];

    state::with_efi_mut(|efi| {
        for var in &mut efi.variables {
            if !var.in_use {
                continue;
            }
            if var.vendor_guid != EFI_GLOBAL_VARIABLE_GUID {
                continue;
            }
            if crate::efi::utils::ucs2_eq(&var.name, os_ind_name) && var.data_size >= 8 {
                let mut value = u64::from_le_bytes([
                    var.data[0],
                    var.data[1],
                    var.data[2],
                    var.data[3],
                    var.data[4],
                    var.data[5],
                    var.data[6],
                    var.data[7],
                ]);

                // Clear capsule-related bits
                value &= !(EFI_OS_INDICATIONS_FMP_CAPSULE_SUPPORTED
                    | EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED);

                let bytes = value.to_le_bytes();
                var.data[..8].copy_from_slice(&bytes);

                log::info!("Cleared capsule bits in OsIndications");
                return;
            }
        }
    });
}
