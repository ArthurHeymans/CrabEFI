//! Disk Image Creation
//!
//! This module provides functionality to create GPT disk images with FAT32
//! EFI System Partitions for testing CrabEFI.

use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;

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

/// Create a test disk image with GPT partition table and FAT32 ESP
///
/// # Arguments
/// * `output` - Path for the output disk image
/// * `efi_app` - Optional path to an EFI application to install as BOOTX64.EFI
pub fn create_test_disk(output: &str, efi_app: Option<&str>) -> Result<()> {
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
        install_efi_app(output, app_path)?;
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

/// Install EFI application to the disk
fn install_efi_app(disk_path: &str, app_path: &str) -> Result<()> {
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
    let status = Command::new("mcopy")
        .args(["-i", &disk_with_offset, app_path, "::/EFI/BOOT/BOOTX64.EFI"])
        .status()
        .context("Failed to run mcopy")?;

    if status.success() {
        println!("Installed {} as BOOTX64.EFI", app_path);
    } else {
        bail!("Failed to install EFI application");
    }

    Ok(())
}

/// Find a command in PATH
fn which(cmd: &str) -> Option<String> {
    Command::new("which")
        .arg(cmd)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
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
