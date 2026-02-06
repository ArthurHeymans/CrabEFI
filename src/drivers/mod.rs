//! Hardware Drivers for CrabEFI
//!
//! This module contains drivers for hardware devices needed to boot.
//!
//! # Driver Model
//!
//! PCI-based drivers implement the `pci::driver::PciDriver` trait with lifecycle
//! methods (`probe`, `init`, `shutdown`). During PCI enumeration, the driver
//! registry automatically binds matching drivers to discovered devices.
//!
//! Platform drivers (serial, keyboard, SPI) are initialized directly from
//! hardware info provided by coreboot tables.
//!
//! # Storage Abstraction
//!
//! All storage drivers provide:
//! - `init_device(&PciDevice)` — Initialize from a discovered PCI device
//! - `shutdown()` — Clean shutdown for OS handoff
//! - `BlockDevice` trait implementation for unified I/O
//!
//! The `block` module provides the `BlockDevice` trait and `AnyBlockDevice`
//! enum for type-safe dispatch across storage types.

pub mod ahci;
pub mod block;
pub mod keyboard;
pub mod mmio;
pub mod nvme;
pub mod pci;
pub mod sdhci;
pub mod serial;
pub mod spi;
pub mod storage;
pub mod usb;
