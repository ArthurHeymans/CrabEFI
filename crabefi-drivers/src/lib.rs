//! Standard Hardware Drivers for CrabEFI
//!
//! This crate provides hardware driver implementations for common PC and
//! embedded peripherals. Each driver implements the appropriate trait from
//! the `crabefi` core library.
//!
//! # Available Drivers
//!
//! | Driver | Trait Implemented | Description |
//! |--------|-------------------|-------------|
//! | NVMe | `BlockDevice` | NVMe SSD controller |
//! | AHCI | `BlockDevice` | SATA/AHCI controller |
//! | USB Mass Storage | `BlockDevice` | USB bulk-only transport |
//! | SDHCI | `BlockDevice` | SD Host Controller |
//! | SPI Flash | `StorageBackend` | Intel/AMD/QEMU SPI controllers |
//! | 16550 UART | `DebugOutput` | Standard PC serial port |
//! | PL011 UART | `DebugOutput` | ARM PrimeCell UART |
//! | PS/2 Keyboard | `ConsoleInput` | i8042 PS/2 controller |
//! | USB HID Keyboard | `ConsoleInput` | USB boot-protocol keyboard |
//!
//! # Usage
//!
//! Drivers are initialized by platform-specific code (e.g., `crabefi-coreboot`)
//! and passed to `crabefi::PlatformConfig` as trait objects.

#![no_std]

// Drivers will be moved here from the main crate in subsequent steps.
// For now this crate is a placeholder to establish the workspace structure.
