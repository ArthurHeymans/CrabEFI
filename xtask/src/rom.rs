//! ROM Preparation
//!
//! This module handles preparing the coreboot ROM with CrabEFI payload.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::project_root;

/// Prepare a coreboot ROM with CrabEFI as the payload
///
/// This function:
/// 1. Decompresses the base ROM from firmware/coreboot-qemu-q35.rom.zst
/// 2. Uses cbfstool to add the CrabEFI payload
/// 3. Returns the path to the prepared ROM
pub fn prepare_rom(crabefi_elf: &Path, output_dir: &Path) -> Result<PathBuf> {
    let compressed_rom = project_root().join("firmware/coreboot-qemu-q35.rom.zst");

    if !compressed_rom.exists() {
        bail!(
            "Base coreboot ROM not found: {}\n\
            Please ensure firmware/coreboot-qemu-q35.rom.zst exists",
            compressed_rom.display()
        );
    }

    if !crabefi_elf.exists() {
        bail!(
            "CrabEFI ELF not found: {}\n\
            Build with: ./x build",
            crabefi_elf.display()
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

    // Remove existing payload if any
    println!("Preparing ROM with CrabEFI payload...");
    let _ = Command::new("cbfstool")
        .arg(&output_rom)
        .args(["remove", "-n", "fallback/payload"])
        .status();

    // Add CrabEFI as payload
    let status = Command::new("cbfstool")
        .arg(&output_rom)
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

    println!("ROM prepared: {}", output_rom.display());
    Ok(output_rom)
}

/// Get the path to the CrabEFI ELF
pub fn get_crabefi_elf() -> PathBuf {
    project_root().join("target/x86_64-unknown-none/release/crabefi")
}
