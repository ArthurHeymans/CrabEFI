//! ROM Preparation
//!
//! This module handles preparing the coreboot ROM with CrabEFI payload.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{project_root, Arch, Machine};

/// Prepared firmware files ready for QEMU
pub struct PreparedFirmware {
    /// Path to the main coreboot ROM (with CrabEFI payload)
    pub coreboot_rom: PathBuf,
    /// Path to TF-A flash image (aarch64 only, used as pflash0)
    pub tfa_flash: Option<PathBuf>,
}

/// Prepare a coreboot ROM with CrabEFI as the payload
///
/// This function:
/// 1. Decompresses the base ROM from firmware/
/// 2. Uses cbfstool to add the CrabEFI payload
/// 3. Returns the prepared firmware paths
///
/// For aarch64 (SBSA), also decompresses the TF-A flash image.
pub fn prepare_rom(
    crabefi_elf: &Path,
    output_dir: &Path,
    arch: Arch,
    machine: Machine,
) -> Result<PreparedFirmware> {
    if !crabefi_elf.exists() {
        bail!(
            "CrabEFI ELF not found: {}\n\
            Build with: ./x build",
            crabefi_elf.display()
        );
    }

    match (arch, machine) {
        (Arch::X86_64, _) => prepare_rom_x86_64(crabefi_elf, output_dir),
        (Arch::Aarch64, Machine::Sbsa) => prepare_rom_aarch64_sbsa(crabefi_elf, output_dir),
        (Arch::Aarch64, Machine::Virt) => prepare_rom_aarch64_virt(crabefi_elf, output_dir),
        (Arch::Riscv64, _) => prepare_rom_riscv64(crabefi_elf, output_dir),
    }
}

/// Prepare x86_64 (Q35) firmware
fn prepare_rom_x86_64(crabefi_elf: &Path, output_dir: &Path) -> Result<PreparedFirmware> {
    let compressed_rom = project_root().join("firmware/coreboot-qemu-q35.rom.zst");

    if !compressed_rom.exists() {
        bail!(
            "Base coreboot ROM not found: {}\n\
            Please ensure firmware/coreboot-qemu-q35.rom.zst exists",
            compressed_rom.display()
        );
    }

    let output_rom = output_dir.join("coreboot.rom");

    // Decompress the ROM
    println!("Decompressing base ROM...");
    let status = Command::new("zstd")
        .args(["-d", "-f"])
        .arg(&compressed_rom)
        .arg("-o")
        .arg(&output_rom)
        .status()
        .context("Failed to run zstd. Is it installed? (nix develop or nix-shell -p zstd)")?;

    if !status.success() {
        bail!("Failed to decompress ROM");
    }

    inject_crabefi_payload(&output_rom, crabefi_elf)?;

    println!("ROM prepared: {}", output_rom.display());
    Ok(PreparedFirmware {
        coreboot_rom: output_rom,
        tfa_flash: None,
    })
}

/// Prepare aarch64 (SBSA) firmware — coreboot ROM + TF-A flash
fn prepare_rom_aarch64_sbsa(crabefi_elf: &Path, output_dir: &Path) -> Result<PreparedFirmware> {
    let compressed_tfa = project_root().join("firmware/tfa-sbsa.fd.zst");
    let compressed_rom = project_root().join("firmware/coreboot-qemu-sbsa.rom.zst");

    if !compressed_tfa.exists() {
        bail!(
            "TF-A flash not found: {}\n\
            Please ensure firmware/tfa-sbsa.fd.zst exists",
            compressed_tfa.display()
        );
    }

    if !compressed_rom.exists() {
        bail!(
            "Base coreboot SBSA ROM not found: {}\n\
            Please ensure firmware/coreboot-qemu-sbsa.rom.zst exists",
            compressed_rom.display()
        );
    }

    let output_tfa = output_dir.join("tfa-sbsa.fd");
    let output_rom = output_dir.join("coreboot-sbsa.rom");

    // Decompress TF-A flash
    println!("Decompressing TF-A flash...");
    let status = Command::new("zstd")
        .args(["-d", "-f"])
        .arg(&compressed_tfa)
        .arg("-o")
        .arg(&output_tfa)
        .status()
        .context("Failed to run zstd. Is it installed? (nix develop or nix-shell -p zstd)")?;

    if !status.success() {
        bail!("Failed to decompress TF-A flash");
    }

    // Decompress coreboot SBSA ROM
    println!("Decompressing coreboot SBSA ROM...");
    let status = Command::new("zstd")
        .args(["-d", "-f"])
        .arg(&compressed_rom)
        .arg("-o")
        .arg(&output_rom)
        .status()
        .context("Failed to run zstd")?;

    if !status.success() {
        bail!("Failed to decompress coreboot SBSA ROM");
    }

    inject_crabefi_payload(&output_rom, crabefi_elf)?;

    println!("Firmware prepared:");
    println!("  TF-A flash: {}", output_tfa.display());
    println!("  coreboot ROM: {}", output_rom.display());

    Ok(PreparedFirmware {
        coreboot_rom: output_rom,
        tfa_flash: Some(output_tfa),
    })
}

/// Prepare aarch64 (virt) firmware — single coreboot ROM (BL31 embedded)
fn prepare_rom_aarch64_virt(crabefi_elf: &Path, output_dir: &Path) -> Result<PreparedFirmware> {
    let compressed_rom = project_root().join("firmware/coreboot-qemu-aarch64.rom.zst");

    if !compressed_rom.exists() {
        bail!(
            "Base coreboot aarch64-virt ROM not found: {}\n\
            Please ensure firmware/coreboot-qemu-aarch64.rom.zst exists",
            compressed_rom.display()
        );
    }

    let output_rom = output_dir.join("coreboot-aarch64.rom");

    // Decompress the ROM
    println!("Decompressing coreboot aarch64-virt ROM...");
    let status = Command::new("zstd")
        .args(["-d", "-f"])
        .arg(&compressed_rom)
        .arg("-o")
        .arg(&output_rom)
        .status()
        .context("Failed to run zstd. Is it installed?")?;

    if !status.success() {
        bail!("Failed to decompress coreboot aarch64-virt ROM");
    }

    inject_crabefi_payload(&output_rom, crabefi_elf)?;

    // QEMU virt pflash0 requires a 64MB image. The coreboot ROM is 16MB,
    // so pad with zeros to 64MB.
    pad_rom(&output_rom, 64 * 1024 * 1024)?;

    println!("Firmware prepared:");
    println!("  coreboot ROM: {} (padded to 64MB)", output_rom.display());

    Ok(PreparedFirmware {
        coreboot_rom: output_rom,
        tfa_flash: None,
    })
}

/// Pad a ROM file to the given size with zeros (if smaller).
fn pad_rom(rom_path: &Path, target_size: u64) -> Result<()> {
    let metadata = std::fs::metadata(rom_path)?;
    let current_size = metadata.len();
    if current_size < target_size {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(rom_path)
            .context("Failed to open ROM for padding")?;
        file.set_len(target_size)
            .context("Failed to pad ROM to target size")?;
        println!(
            "  Padded ROM from {} to {} bytes",
            current_size, target_size
        );
    }
    Ok(())
}

/// Inject CrabEFI as the coreboot payload using cbfstool
fn inject_crabefi_payload(rom_path: &Path, crabefi_elf: &Path) -> Result<()> {
    // Remove existing payload if any
    println!("Preparing ROM with CrabEFI payload...");
    let _ = Command::new("cbfstool")
        .arg(rom_path)
        .args(["remove", "-n", "fallback/payload"])
        .status();

    // Add CrabEFI as payload
    let status = Command::new("cbfstool")
        .arg(rom_path)
        .args(["add-payload", "-f"])
        .arg(crabefi_elf)
        .args(["-n", "fallback/payload", "-c", "lzma"])
        .status()
        .context(
            "Failed to run cbfstool. Is it installed? (nix develop or nix-shell -p coreboot-utils)",
        )?;

    if !status.success() {
        bail!("Failed to add CrabEFI payload to ROM");
    }

    Ok(())
}

/// Add a small raw CBFS file used to verify CrabEFI discovers flash payload entries.
pub fn add_test_cbfs_payload(rom_path: &Path, name: &str) -> Result<()> {
    let payload = rom_path.with_extension("cbfs-test-payload.bin");
    std::fs::write(&payload, b"CrabEFI CBFS payload discovery test\n")
        .context("Failed to create CBFS test payload")?;

    let _ = Command::new("cbfstool")
        .arg(rom_path)
        .args(["remove", "-n", name])
        .status();

    let status = Command::new("cbfstool")
        .arg(rom_path)
        .args(["add", "-f"])
        .arg(&payload)
        .args(["-n", name, "-t", "raw"])
        .status()
        .context("Failed to run cbfstool to add CBFS test payload")?;

    if !status.success() {
        bail!("Failed to add CBFS test payload to ROM");
    }

    Ok(())
}

/// Prepare riscv64 (QEMU virt) firmware — single coreboot ROM (OpenSBI embedded)
fn prepare_rom_riscv64(crabefi_elf: &Path, output_dir: &Path) -> Result<PreparedFirmware> {
    let compressed_rom = project_root().join("firmware/coreboot-qemu-riscv64.rom.zst");

    if !compressed_rom.exists() {
        bail!(
            "Base coreboot riscv64 ROM not found: {}\n\
            Please ensure firmware/coreboot-qemu-riscv64.rom.zst exists",
            compressed_rom.display()
        );
    }

    let output_rom = output_dir.join("coreboot-riscv64.rom");

    // Decompress the ROM
    println!("Decompressing coreboot riscv64 ROM...");
    let status = Command::new("zstd")
        .args(["-d", "-f"])
        .arg(&compressed_rom)
        .arg("-o")
        .arg(&output_rom)
        .status()
        .context("Failed to run zstd. Is it installed?")?;

    if !status.success() {
        bail!("Failed to decompress coreboot riscv64 ROM");
    }

    inject_crabefi_payload(&output_rom, crabefi_elf)?;

    println!("Firmware prepared:");
    println!("  coreboot ROM: {}", output_rom.display());

    Ok(PreparedFirmware {
        coreboot_rom: output_rom,
        tfa_flash: None,
    })
}

/// Get the path to the CrabEFI ELF
pub fn get_crabefi_elf(arch: Arch) -> PathBuf {
    let target_triple = match arch {
        Arch::X86_64 => "x86_64-unknown-none",
        Arch::Aarch64 => "aarch64-unknown-none",
        Arch::Riscv64 => "riscv64gc-unknown-none-elf",
    };
    project_root().join(format!("target/{}/release/crabefi", target_triple))
}
