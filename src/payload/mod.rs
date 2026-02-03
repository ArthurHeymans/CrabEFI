//! Coreboot Payload Chainloading
//!
//! This module allows CrabEFI to load and execute other coreboot payloads
//! from disk, enabling scenarios like:
//!
//! - SeaBIOS for legacy BIOS compatibility
//! - Other UEFI implementations (EDK2)
//! - Custom payloads for testing/debugging
//!
//! # Supported Formats
//!
//! - **ELF**: Standard ELF64 executables
//! - **Flat binary**: Raw binary loaded to a fixed address
//!
//! # Entry Convention
//!
//! On x86-64, coreboot payloads receive the coreboot table pointer in RDI.
//! CrabEFI already has this pointer from its own initialization.

pub mod elf;

pub use elf::{Elf64, ElfError};

use crate::fs::fat::FatFilesystem;
use heapless::{String, Vec};

/// Maximum number of payload entries
const MAX_PAYLOAD_ENTRIES: usize = 8;

/// Maximum payload file size (16 MB)
const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// Common paths to search for payloads
const PAYLOAD_PATHS: &[&str] = &["payloads", "boot\\payloads", "coreboot", "boot\\coreboot"];

/// Supported payload file extensions
const PAYLOAD_EXTENSIONS: &[(&str, PayloadFormat)] = &[
    (".elf", PayloadFormat::Elf),
    (
        ".bin",
        PayloadFormat::FlatBinary {
            load_addr: 0x100000,
        },
    ),
    (
        ".fd",
        PayloadFormat::FlatBinary {
            load_addr: 0x100000,
        },
    ),
];

/// Payload format type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFormat {
    /// Standard ELF executable
    Elf,
    /// Flat binary loaded to a fixed address
    FlatBinary {
        /// Address to load the binary
        load_addr: u64,
    },
}

/// A discovered payload entry
#[derive(Debug, Clone)]
pub struct PayloadEntry {
    /// Display name for the menu
    pub name: String<64>,
    /// Path to the payload file
    pub path: String<128>,
    /// Payload format
    pub format: PayloadFormat,
    /// File size in bytes
    pub size: u32,
}

/// Error during payload operations
#[derive(Debug)]
pub enum PayloadError {
    /// Payload not found
    NotFound,
    /// Failed to read payload
    ReadError,
    /// Invalid payload format
    InvalidFormat,
    /// ELF loading error
    ElfError(ElfError),
    /// Payload too large
    TooLarge,
    /// Memory allocation failed
    MemoryError,
}

impl From<ElfError> for PayloadError {
    fn from(e: ElfError) -> Self {
        PayloadError::ElfError(e)
    }
}

/// Discover payload files on a filesystem
///
/// # Arguments
///
/// * `fs` - FAT filesystem to search
pub fn discover_payloads(fs: &mut FatFilesystem<'_>) -> Vec<PayloadEntry, MAX_PAYLOAD_ENTRIES> {
    let mut entries = Vec::new();

    // Try common payload filenames
    let common_payloads = [
        ("seabios.elf", "SeaBIOS (Legacy BIOS)", PayloadFormat::Elf),
        (
            "seabios.bin",
            "SeaBIOS (Legacy BIOS)",
            PayloadFormat::FlatBinary {
                load_addr: 0x100000,
            },
        ),
        ("coreinfo.elf", "Coreinfo (Diagnostic)", PayloadFormat::Elf),
        (
            "edk2.fd",
            "EDK2 UEFI",
            PayloadFormat::FlatBinary {
                load_addr: 0x100000,
            },
        ),
        (
            "tianocore.fd",
            "TianoCore UEFI",
            PayloadFormat::FlatBinary {
                load_addr: 0x100000,
            },
        ),
    ];

    for base_path in PAYLOAD_PATHS {
        for (filename, name, format) in common_payloads.iter() {
            let mut path: String<128> = String::new();
            let _ = core::fmt::write(&mut path, format_args!("{}\\{}", base_path, filename));

            if let Ok(size) = fs.file_size(&path)
                && size > 0
                && size <= MAX_PAYLOAD_SIZE as u32
            {
                let mut entry = PayloadEntry {
                    name: String::new(),
                    path: String::new(),
                    format: *format,
                    size,
                };
                let _ = entry.name.push_str(name);
                let _ = entry.path.push_str(&path);

                log::debug!("Found payload: {} at {} ({} bytes)", name, path, size);
                let _ = entries.push(entry);
            }
        }
    }

    entries
}

/// Check if a filesystem has any payloads
pub fn has_payloads(fs: &mut FatFilesystem<'_>) -> bool {
    for base_path in PAYLOAD_PATHS {
        let mut path: String<128> = String::new();
        let _ = core::fmt::write(&mut path, format_args!("{}\\seabios.elf", base_path));
        if fs.file_size(&path).is_ok() {
            return true;
        }
    }
    false
}

/// Load and execute a payload
///
/// # Arguments
///
/// * `fs` - FAT filesystem containing the payload
/// * `entry` - Payload entry to load
/// * `cbtable_ptr` - Pointer to coreboot tables
///
/// # Safety
///
/// This function jumps to the payload and does not return.
pub unsafe fn chainload_payload(
    fs: &mut FatFilesystem<'_>,
    entry: &PayloadEntry,
    cbtable_ptr: *const u8,
) -> Result<!, PayloadError> {
    log::info!("Loading payload: {} from {}", entry.name, entry.path);

    // Allocate buffer for payload
    // In a real implementation, we'd use the EFI allocator
    // For now, we'll use a static buffer (limited)
    static mut PAYLOAD_BUFFER: [u8; MAX_PAYLOAD_SIZE] = [0; MAX_PAYLOAD_SIZE];

    let buffer = &mut PAYLOAD_BUFFER[..entry.size as usize];

    // Read payload file
    let bytes_read = fs
        .read_file_all(&entry.path, buffer)
        .map_err(|_| PayloadError::ReadError)?;

    if bytes_read != entry.size as usize {
        return Err(PayloadError::ReadError);
    }

    // Load based on format
    let entry_point = match entry.format {
        PayloadFormat::Elf => {
            let elf = Elf64::parse(buffer)?;
            elf.load(buffer)?;
            elf.entry_point()
        }
        PayloadFormat::FlatBinary { load_addr } => {
            // Copy flat binary to load address
            let dst = load_addr as *mut u8;
            core::ptr::copy_nonoverlapping(buffer.as_ptr(), dst, bytes_read);
            load_addr
        }
    };

    log::info!("Jumping to payload at {:#x}", entry_point);

    // Jump to payload
    jump_to_payload(entry_point, cbtable_ptr)
}

/// Jump to a loaded payload
///
/// # Arguments
///
/// * `entry` - Entry point address
/// * `cbtable` - Pointer to coreboot tables (passed in RDI)
///
/// # Safety
///
/// The payload must be loaded at the entry address and be valid.
unsafe fn jump_to_payload(entry: u64, cbtable: *const u8) -> ! {
    // Disable interrupts
    core::arch::asm!("cli");

    // Clear registers and jump to payload
    // Pass coreboot table pointer in RDI (x86-64 calling convention)
    core::arch::asm!(
        "mov rdi, {cbtable}",   // Coreboot table pointer
        "xor rsi, rsi",         // Clear RSI
        "xor rdx, rdx",         // Clear RDX
        "xor rcx, rcx",         // Clear RCX
        "xor r8, r8",           // Clear R8
        "xor r9, r9",           // Clear R9
        "xor r10, r10",         // Clear R10
        "xor r11, r11",         // Clear R11
        "jmp {entry}",
        cbtable = in(reg) cbtable as u64,
        entry = in(reg) entry,
        options(noreturn)
    );
}

/// Determine payload format from file extension
///
/// Checks if the path ends with a known payload extension (case-insensitive).
pub fn format_from_extension(path: &str) -> Option<PayloadFormat> {
    // Use alloc::string::String for to_ascii_lowercase
    // (available since we have `extern crate alloc`)
    let lower_path = path.to_ascii_lowercase();
    for (ext, format) in PAYLOAD_EXTENSIONS {
        if lower_path.ends_with(ext) {
            return Some(*format);
        }
    }
    None
}
