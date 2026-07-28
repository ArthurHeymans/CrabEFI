//! Disk Image Creation
//!
//! This module provides functionality to create GPT disk images with FAT32
//! EFI System Partitions for testing CrabEFI.

use anyhow::{Context, Result, bail};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;

use crate::Arch;

/// Disk geometry constants for a 64MB disk
const DISK_SIZE: u64 = 64 * 1024 * 1024;
const SECTOR_SIZE: u64 = 512;
const TOTAL_SECTORS: u64 = DISK_SIZE / SECTOR_SIZE;
/// ESP starts at 1MiB to leave room for GPT
const ESP_START_SECTOR: u64 = 2048; // 1MiB / 512
/// ESP ends at last usable sector (leaving 33 sectors for backup GPT)
const ESP_END_SECTOR: u64 = TOTAL_SECTORS - 34;

/// GPT signature "EFI PART"
const GPT_SIGNATURE: u64 = 0x5452415020494645;
/// GPT Header size
const GPT_HEADER_SIZE: u32 = 92;
/// GPT Partition entry size
const GPT_ENTRY_SIZE: u32 = 128;
/// Number of partition entries
const GPT_NUM_ENTRIES: u32 = 128;

/// EFI System Partition GUID: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
const ESP_TYPE_GUID: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];

/// Return an mtools image specifier for the ESP inside a generated disk image.
///
/// # Arguments
/// * `disk_path` - Path to the raw GPT disk image
///
/// # Returns
/// An mtools `-i` argument that points at the ESP byte offset.
pub fn mtools_esp_image(disk_path: &Path) -> String {
    format!(
        "{}@@{}",
        disk_path.to_string_lossy(),
        ESP_START_SECTOR * SECTOR_SIZE
    )
}

/// Create a test disk image with GPT partition table and FAT32 ESP
///
/// # Arguments
/// * `output` - Path for the output disk image
/// * `efi_app` - Optional path to an EFI application to install as boot application
/// * `arch` - Target architecture (determines EFI boot path name)
pub fn create_test_disk(output: &str, efi_app: Option<&str>, arch: Arch) -> Result<()> {
    println!("Creating test disk: {}", output);

    // Create empty disk image
    let mut file = File::create(output).context("failed to create disk image")?;
    file.set_len(DISK_SIZE)?;

    // Write protective MBR
    write_protective_mbr(&mut file)?;

    // Write primary GPT header and partition entries
    write_gpt_header(&mut file, true)?;
    write_gpt_partition_entries(&mut file, true)?;

    // Write backup GPT header and partition entries
    write_gpt_partition_entries(&mut file, false)?;
    write_gpt_header(&mut file, false)?;

    file.flush()?;
    drop(file);

    // Create FAT32 filesystem in the ESP partition
    create_fat32_in_partition(output, ESP_START_SECTOR, ESP_END_SECTOR)?;

    // If we have an EFI app, copy it
    if let Some(app_path) = efi_app {
        install_efi_app(output, app_path, arch)?;
    }

    println!("Created: {}", output);
    Ok(())
}

/// Write a protective MBR for GPT
fn write_protective_mbr(file: &mut File) -> Result<()> {
    let mut mbr = [0u8; 512];

    // Boot signature
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    // Partition entry 1 (at offset 446)
    // Status: 0x00 (not bootable)
    mbr[446] = 0x00;
    // CHS start: 0x000200 (head=0, sector=2, cylinder=0)
    mbr[447] = 0x00;
    mbr[448] = 0x02;
    mbr[449] = 0x00;
    // Type: 0xEE (GPT protective)
    mbr[450] = 0xEE;
    // CHS end: 0xFFFFFF (max CHS)
    mbr[451] = 0xFF;
    mbr[452] = 0xFF;
    mbr[453] = 0xFF;
    // LBA start: 1
    mbr[454..458].copy_from_slice(&1u32.to_le_bytes());
    // LBA count: total sectors - 1
    let sectors = (TOTAL_SECTORS - 1).min(0xFFFFFFFF) as u32;
    mbr[458..462].copy_from_slice(&sectors.to_le_bytes());

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&mbr)?;
    Ok(())
}

/// Write GPT header (primary or backup)
fn write_gpt_header(file: &mut File, primary: bool) -> Result<()> {
    let mut header = [0u8; 512];

    // Signature "EFI PART"
    header[0..8].copy_from_slice(&GPT_SIGNATURE.to_le_bytes());

    // Revision 1.0
    header[8..12].copy_from_slice(&0x00010000u32.to_le_bytes());

    // Header size
    header[12..16].copy_from_slice(&GPT_HEADER_SIZE.to_le_bytes());

    // Header CRC32 (will be calculated after filling other fields)
    // Skip for now, fill with 0

    // Reserved
    header[20..24].copy_from_slice(&0u32.to_le_bytes());

    // Current LBA
    let current_lba = if primary { 1 } else { TOTAL_SECTORS - 1 };
    header[24..32].copy_from_slice(&current_lba.to_le_bytes());

    // Backup LBA
    let backup_lba = if primary { TOTAL_SECTORS - 1 } else { 1 };
    header[32..40].copy_from_slice(&backup_lba.to_le_bytes());

    // First usable LBA (after primary GPT + partition entries)
    let first_usable = 34u64; // LBA 34 typically
    header[40..48].copy_from_slice(&first_usable.to_le_bytes());

    // Last usable LBA (before backup GPT)
    let last_usable = TOTAL_SECTORS - 34;
    header[48..56].copy_from_slice(&last_usable.to_le_bytes());

    // Disk GUID (random but deterministic for testing)
    let disk_guid: [u8; 16] = [
        0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
        0xF0,
    ];
    header[56..72].copy_from_slice(&disk_guid);

    // Partition entries starting LBA
    let entries_lba = if primary { 2 } else { TOTAL_SECTORS - 33 };
    header[72..80].copy_from_slice(&entries_lba.to_le_bytes());

    // Number of partition entries
    header[80..84].copy_from_slice(&GPT_NUM_ENTRIES.to_le_bytes());

    // Size of partition entry
    header[84..88].copy_from_slice(&GPT_ENTRY_SIZE.to_le_bytes());

    // CRC32 of partition entries (calculated separately)
    let entries_crc = calculate_partition_entries_crc()?;
    header[88..92].copy_from_slice(&entries_crc.to_le_bytes());

    // Calculate header CRC32
    let header_crc = crc32(&header[0..GPT_HEADER_SIZE as usize]);
    header[16..20].copy_from_slice(&header_crc.to_le_bytes());

    // Write header
    let offset = current_lba * SECTOR_SIZE;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&header)?;

    Ok(())
}

/// Write GPT partition entries
fn write_gpt_partition_entries(file: &mut File, primary: bool) -> Result<()> {
    // Each entry is 128 bytes, we have 128 entries = 16384 bytes = 32 sectors
    let entries_size = (GPT_NUM_ENTRIES * GPT_ENTRY_SIZE) as usize;
    let mut entries = vec![0u8; entries_size];

    // First entry: EFI System Partition
    let entry = &mut entries[0..128];

    // Partition type GUID (ESP)
    entry[0..16].copy_from_slice(&ESP_TYPE_GUID);

    // Unique partition GUID
    let part_guid: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    entry[16..32].copy_from_slice(&part_guid);

    // Starting LBA
    entry[32..40].copy_from_slice(&ESP_START_SECTOR.to_le_bytes());

    // Ending LBA
    entry[40..48].copy_from_slice(&ESP_END_SECTOR.to_le_bytes());

    // Attributes (none)
    entry[48..56].copy_from_slice(&0u64.to_le_bytes());

    // Partition name (UTF-16LE): "EFI System"
    let name = "EFI System";
    for (i, c) in name.chars().enumerate() {
        let offset = 56 + i * 2;
        entry[offset..offset + 2].copy_from_slice(&(c as u16).to_le_bytes());
    }

    // Write entries
    let entries_lba = if primary { 2 } else { TOTAL_SECTORS - 33 };
    let offset = entries_lba * SECTOR_SIZE;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&entries)?;

    Ok(())
}

/// Calculate CRC32 of partition entries (for GPT header)
fn calculate_partition_entries_crc() -> Result<u32> {
    let entries_size = (GPT_NUM_ENTRIES * GPT_ENTRY_SIZE) as usize;
    let mut entries = vec![0u8; entries_size];

    // Recreate the first entry
    let entry = &mut entries[0..128];
    entry[0..16].copy_from_slice(&ESP_TYPE_GUID);
    let part_guid: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    entry[16..32].copy_from_slice(&part_guid);
    entry[32..40].copy_from_slice(&ESP_START_SECTOR.to_le_bytes());
    entry[40..48].copy_from_slice(&ESP_END_SECTOR.to_le_bytes());
    let name = "EFI System";
    for (i, c) in name.chars().enumerate() {
        let offset = 56 + i * 2;
        entry[offset..offset + 2].copy_from_slice(&(c as u16).to_le_bytes());
    }

    Ok(crc32(&entries))
}

/// Simple CRC32 implementation (IEEE polynomial)
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Create FAT32 filesystem in the partition
fn create_fat32_in_partition(disk_path: &str, start_sector: u64, end_sector: u64) -> Result<()> {
    // Calculate partition size in sectors
    let partition_sectors = end_sector - start_sector + 1;
    let partition_size = partition_sectors * SECTOR_SIZE;

    // Create a temporary file for the FAT32 image
    let fat_temp = format!("{}.fat", disk_path);

    // Create empty FAT image
    let mut fat_file = File::create(&fat_temp)?;
    fat_file.set_len(partition_size)?;
    fat_file.flush()?;
    drop(fat_file);

    // Format with mkfs.fat
    let status = Command::new("mkfs.fat")
        .args(["-F", "32", "-n", "ESP", &fat_temp])
        .status()
        .context("Failed to run mkfs.fat")?;

    if !status.success() {
        let _ = std::fs::remove_file(&fat_temp);
        bail!("mkfs.fat failed");
    }

    // Copy FAT image into the disk at the partition offset
    let mut fat_file = File::open(&fat_temp)?;
    let mut disk_file = OpenOptions::new().write(true).open(disk_path)?;

    let offset = start_sector * SECTOR_SIZE;
    disk_file.seek(SeekFrom::Start(offset))?;

    // Copy in chunks
    let mut buffer = vec![0u8; 1024 * 1024]; // 1MB buffer
    loop {
        let bytes_read = fat_file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        disk_file.write_all(&buffer[..bytes_read])?;
    }

    disk_file.flush()?;

    // Clean up temp file
    let _ = std::fs::remove_file(&fat_temp);

    Ok(())
}

/// Get the EFI boot filename for the given architecture
fn efi_boot_filename(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => "BOOTX64.EFI",
        Arch::Aarch64 => "BOOTAA64.EFI",
        Arch::Riscv64 => "BOOTRISCV64.EFI",
    }
}

/// Install EFI application to the disk
fn install_efi_app(disk_path: &str, app_path: &str, arch: Arch) -> Result<()> {
    if !Path::new(app_path).exists() {
        bail!("EFI application not found: {}", app_path);
    }

    // Use mtools -i option with @@ offset syntax to access partition
    let disk_with_offset = format!("{}@@{}", disk_path, ESP_START_SECTOR * SECTOR_SIZE);

    // Create directory structure
    let _ = Command::new("mmd")
        .args(["-i", &disk_with_offset, "::/EFI"])
        .status();

    let _ = Command::new("mmd")
        .args(["-i", &disk_with_offset, "::/EFI/BOOT"])
        .status();

    // Copy EFI application
    let boot_filename = efi_boot_filename(arch);
    let dest = format!("::/EFI/BOOT/{}", boot_filename);
    let status = Command::new("mcopy")
        .args(["-i", &disk_with_offset, app_path, &dest])
        .status()
        .context("Failed to run mcopy")?;

    if status.success() {
        println!("Installed {} as {}", app_path, boot_filename);
    } else {
        bail!("Failed to install EFI application");
    }

    Ok(())
}

/// Install EFI application and populate \EFI\Linux with LFN test files.
///
/// Creates a disk image with:
///   - \EFI\BOOT\<BOOT_EFI>  (the test app, arch-dependent name)
///   - \EFI\Linux\nixos-kernel-6.12.9-linux-x86_64-5kg0k0b55f3mz75b7bl2fvkl0cqkzmam.efi  (71 chars)
///   - \EFI\Linux\nixos-6.6.0.efi  (short name)
///
/// The long filename is specifically chosen to exceed 64 characters, which
/// previously triggered a truncation bug in the FAT LFN -> heapless::String<64>
/// conversion.
pub fn create_directory_test_disk(output: &str, efi_app: &str, arch: Arch) -> Result<()> {
    // Start with a normal test disk that has the EFI app
    create_test_disk(output, Some(efi_app), arch)?;

    let disk_with_offset = format!("{}@@{}", output, ESP_START_SECTOR * SECTOR_SIZE);

    // Create \EFI\Linux directory
    let _ = Command::new("mmd")
        .args(["-i", &disk_with_offset, "::/EFI/Linux"])
        .status();

    // Create a small fake PE file to use as UKI stubs.
    // A valid PE needs at least a DOS header with the magic 'MZ'.
    let fake_efi = tempfile::NamedTempFile::new()?;
    {
        let mut f = std::io::BufWriter::new(fake_efi.as_file());
        let mut pe = vec![0u8; 4096];
        pe[0] = b'M';
        pe[1] = b'Z';
        f.write_all(&pe)?;
        f.flush()?;
    }
    let fake_path = fake_efi.path().to_string_lossy().to_string();

    // Long filename: 71 characters - exceeds old 64-byte heapless::String limit
    let long_name = "nixos-kernel-6.12.9-linux-x86_64-5kg0k0b55f3mz75b7bl2fvkl0cqkzmam.efi";
    let long_dest = format!("::/EFI/Linux/{}", long_name);
    let status = Command::new("mcopy")
        .args(["-i", &disk_with_offset, &fake_path, &long_dest])
        .status()
        .context("Failed to copy long-name file")?;
    if !status.success() {
        bail!("Failed to install long-name file");
    }
    println!("Installed {} (len={})", long_name, long_name.len());

    // Short filename (< 64 chars)
    let short_name = "nixos-6.6.0.efi";
    let short_dest = format!("::/EFI/Linux/{}", short_name);
    let status = Command::new("mcopy")
        .args(["-i", &disk_with_offset, &fake_path, &short_dest])
        .status()
        .context("Failed to copy short-name file")?;
    if !status.success() {
        bail!("Failed to install short-name file");
    }
    println!("Installed {}", short_name);

    Ok(())
}

/// Create a disk image for the GRUB + Linux boot-chain test.
///
/// Disk layout:
///   /EFI/BOOT/BOOTX64.EFI          GRUB standalone EFI binary
///   /boot/grub/grub.cfg             GRUB configuration
///   /vmlinuz                        Linux kernel
///   /initramfs.cpio                 u-root initramfs
///
/// CrabEFI discovers the ESP, loads GRUB as the default UEFI boot
/// application, GRUB reads its embedded config, loads the kernel and
/// initramfs, and boots Linux into a u-root userspace that prints a
/// test marker to the serial console.
pub fn create_grub_linux_disk(
    output: &str,
    grub_efi: &str,
    kernel: &str,
    initramfs: &str,
    grub_cfg: &str,
    arch: Arch,
) -> Result<()> {
    // Sanity-check inputs
    for (label, path) in [
        ("GRUB EFI", grub_efi),
        ("kernel", kernel),
        ("initramfs", initramfs),
        ("grub.cfg", grub_cfg),
    ] {
        if !Path::new(path).exists() {
            bail!("{} not found: {}", label, path);
        }
    }

    println!("Creating GRUB+Linux test disk: {}", output);

    // Start with a bare GPT + ESP disk
    create_test_disk(output, None, arch)?;

    let disk_with_offset = format!("{}@@{}", output, ESP_START_SECTOR * SECTOR_SIZE);

    // ── Install GRUB as the default UEFI boot application ────────────
    let _ = Command::new("mmd")
        .args(["-i", &disk_with_offset, "::/EFI"])
        .status();
    let _ = Command::new("mmd")
        .args(["-i", &disk_with_offset, "::/EFI/BOOT"])
        .status();

    let boot_filename = efi_boot_filename(arch);
    let dest = format!("::/EFI/BOOT/{}", boot_filename);
    let status = Command::new("mcopy")
        .args(["-i", &disk_with_offset, grub_efi, &dest])
        .status()
        .context("mcopy GRUB EFI")?;
    if !status.success() {
        bail!("Failed to install GRUB EFI binary");
    }
    println!("  Installed GRUB as EFI/BOOT/{}", boot_filename);

    // ── Install grub.cfg on disk ─────────────────────────────────────
    let _ = Command::new("mmd")
        .args(["-i", &disk_with_offset, "::/boot"])
        .status();
    let _ = Command::new("mmd")
        .args(["-i", &disk_with_offset, "::/boot/grub"])
        .status();

    let status = Command::new("mcopy")
        .args(["-i", &disk_with_offset, grub_cfg, "::/boot/grub/grub.cfg"])
        .status()
        .context("mcopy grub.cfg")?;
    if !status.success() {
        bail!("Failed to install grub.cfg");
    }
    println!("  Installed boot/grub/grub.cfg");

    // ── Install the Linux kernel ─────────────────────────────────────
    let status = Command::new("mcopy")
        .args(["-i", &disk_with_offset, kernel, "::/vmlinuz"])
        .status()
        .context("mcopy vmlinuz")?;
    if !status.success() {
        bail!("Failed to install vmlinuz");
    }
    println!("  Installed vmlinuz");

    // ── Install the initramfs ────────────────────────────────────────
    let status = Command::new("mcopy")
        .args(["-i", &disk_with_offset, initramfs, "::/initramfs.cpio"])
        .status()
        .context("mcopy initramfs")?;
    if !status.success() {
        bail!("Failed to install initramfs");
    }
    println!("  Installed initramfs.cpio");

    println!("Created: {}", output);
    Ok(())
}

/// Create a disk image for the UEFI SCT smoke test.
///
/// Disk layout:
///   /EFI/BOOT/<BOOT_EFI>          EDK2 UEFI Shell
///   /startup.nsh                  Shell script that launches SCT
///   /Sct/...                      Contents of the SCT architecture directory
///   /Sct/Sequence/smoke.seq       Minimal sequence file
///
/// # Arguments
/// * `output` - Path for the output disk image
/// * `shell_efi` - Path to a UEFI Shell binary for `arch`
/// * `sct_dir` - Path to the SCT architecture directory, e.g. `SctPackageX64/X64`
/// * `arch` - Target architecture
///
/// # Returns
/// `Ok(())` when the disk image is created and populated.
pub fn create_uefi_sct_smoke_disk(
    output: &str,
    shell_efi: &str,
    sct_dir: &Path,
    arch: Arch,
) -> Result<()> {
    if !Path::new(shell_efi).exists() {
        bail!("UEFI Shell binary not found: {}", shell_efi);
    }
    if !sct_dir.join("SCT.efi").exists() {
        bail!(
            "SCT.efi not found in {}. Pass the architecture directory, e.g. SctPackageX64/X64",
            sct_dir.display()
        );
    }

    println!("Creating UEFI SCT smoke test disk: {}", output);
    create_test_disk(output, Some(shell_efi), arch)?;

    let disk_with_offset = mtools_esp_image(Path::new(output));

    write_text_file_to_esp(
        &disk_with_offset,
        "::/startup.nsh",
        r#"echo -off
echo CRABEFI_SCT_SMOKE_START

for %i in 0 1 2 3 4 5 6 7 8 9 A B C D E F
  if exist FS%i:\Sct\SCT.efi then
    FS%i:
    cd Sct
    Sct -s smoke.seq -v
    echo CRABEFI_SCT_SMOKE_DONE
    reset -s
    goto Done
  endif
endfor

echo CRABEFI_SCT_SMOKE_NOT_FOUND
reset -s

:Done
"#,
    )?;

    create_mtools_dir(&disk_with_offset, "::/Sct")?;
    copy_tree_to_esp(&disk_with_offset, sct_dir, "::/Sct")?;
    write_text_file_to_esp(&disk_with_offset, "::/Sct/.passive.mode", "\n")?;

    create_mtools_dir(&disk_with_offset, "::/Sct/Sequence")?;
    write_text_file_to_esp(
        &disk_with_offset,
        "::/Sct/Sequence/smoke.seq",
        UEFI_SCT_SMOKE_SEQUENCE,
    )?;

    println!("Installed UEFI Shell and SCT smoke sequence");
    Ok(())
}

const UEFI_SCT_SMOKE_SEQUENCE: &str = r#"[Test Case]
Revision   = 0x00010000
Guid       = 539675B8-D9B3-4DC7-A8D0-FF19BBA13B86
Name       = Stall_Func
Order      = 0x00000000
Iterations = 0x00000001

[Test Case]
Revision   = 0x00010000
Guid       = 4397A610-8D5D-441B-8E7D-C23377F3EB67
Name       = CopyMem_Func
Order      = 0x00000001
Iterations = 0x00000001

[Test Case]
Revision   = 0x00010000
Guid       = 315BE343-A32D-461D-A3CC-5E6895CC2CBA
Name       = SetMem_Func
Order      = 0x00000002
Iterations = 0x00000001

[Test Case]
Revision   = 0x00010000
Guid       = B510F99F-FEE9-4AF6-BB0F-3C958EF7F166
Name       = CalculateCrc32_Func
Order      = 0x00000003
Iterations = 0x00000001

[Test Case]
Revision   = 0x00010000
Guid       = 90023546-6C92-430A-B253-70110D9EFDFF
Name       = AllocatePool_Conf
Order      = 0x00000004
Iterations = 0x00000001

[Test Case]
Revision   = 0x00010000
Guid       = 49709F9F-A4D8-42D6-A684-4975EE0099DB
Name       = FreePool_Conf
Order      = 0x00000005
Iterations = 0x00000001
"#;

fn mtools_dir_exists(disk_with_offset: &str, path: &str) -> Result<bool> {
    let output = Command::new("mdir")
        .args(["-i", disk_with_offset, "-b", path])
        .output()
        .context("Failed to run mdir")?;
    Ok(output.status.success())
}

fn create_mtools_dir(disk_with_offset: &str, path: &str) -> Result<()> {
    // `mmd` fails when the directory already exists and offers no reliable way
    // to tell that apart from a real failure, so probe first and only create
    // when missing. Callers ensure parent directories repeatedly, so this needs
    // to stay idempotent without swallowing genuine errors.
    if mtools_dir_exists(disk_with_offset, path)? {
        return Ok(());
    }

    let status = Command::new("mmd")
        .args(["-i", disk_with_offset, path])
        .status()
        .context("Failed to run mmd")?;

    if !status.success() {
        // Tolerate a lost race / mtools quirk only when the directory is
        // actually there afterwards.
        if mtools_dir_exists(disk_with_offset, path)? {
            return Ok(());
        }
        anyhow::bail!("mmd failed to create {path} ({status})");
    }

    Ok(())
}

fn copy_tree_to_esp(disk_with_offset: &str, source_dir: &Path, dest_dir: &str) -> Result<()> {
    for entry in walkdir(source_dir)? {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(source_dir)?;
        if rel.as_os_str().is_empty() {
            continue;
        }

        let rel_mtools = rel
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let dest = format!("{}/{}", dest_dir, rel_mtools);

        if path.is_dir() {
            create_mtools_dir(disk_with_offset, &dest)?;
        } else if path.is_file() {
            if let Some(parent) = dest.rsplit_once('/') {
                create_mtools_dir(disk_with_offset, parent.0)?;
            }
            let status = Command::new("mcopy")
                .args(["-o", "-i", disk_with_offset])
                .arg(&path)
                .arg(&dest)
                .status()
                .context("Failed to run mcopy")?;
            if !status.success() {
                bail!("Failed to copy {} to {}", path.display(), dest);
            }
        }
    }

    Ok(())
}

fn write_text_file_to_esp(disk_with_offset: &str, dest: &str, contents: &str) -> Result<()> {
    let temp = tempfile::NamedTempFile::new()?;
    {
        let mut f = std::io::BufWriter::new(temp.as_file());
        f.write_all(contents.as_bytes())?;
        f.flush()?;
    }

    let status = Command::new("mcopy")
        .args(["-o", "-i", disk_with_offset])
        .arg(temp.path())
        .arg(dest)
        .status()
        .context("Failed to run mcopy")?;
    if !status.success() {
        bail!("Failed to write {}", dest);
    }

    Ok(())
}

fn walkdir(root: &Path) -> Result<Vec<Result<std::fs::DirEntry, std::io::Error>>> {
    let mut entries = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let mut children = std::fs::read_dir(&dir)
            .with_context(|| format!("Failed to read directory {}", dir.display()))?
            .collect::<Vec<_>>();
        children.sort_by_key(|entry| {
            entry
                .as_ref()
                .map(|e| e.path())
                .unwrap_or_else(|_| Path::new("").to_path_buf())
        });

        for child in children {
            if let Ok(ref entry) = child {
                if entry.path().is_dir() {
                    stack.push(entry.path());
                }
            }
            entries.push(child);
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_which() {
        // `ls` should exist on any Unix system
        assert!(which("ls").is_some());
        // This should not exist
        assert!(which("nonexistent_command_12345").is_none());
    }
}
