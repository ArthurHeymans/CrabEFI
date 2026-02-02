//! Storage Backend Abstraction
//!
//! This module provides a trait for abstracting storage backends,
//! allowing the variable store to work with different storage types:
//! - SPI flash (Intel, AMD, QEMU pflash)
//! - Memory-backed storage (for testing)
//! - Future backends (NVMe namespaces, etc.)
//!
//! # Architecture
//!
//! The `StorageBackend` trait provides a minimal interface for block storage:
//! - Read/write/erase operations
//! - Write enable control
//! - Basic device info
//!
//! This abstracts away the details of how storage is accessed, allowing
//! the variable store persistence layer to be storage-agnostic.

// Note: alloc imports are used by MemoryBackend in tests
#[cfg(test)]
use alloc::string::String;
#[cfg(test)]
use alloc::vec;
#[cfg(test)]
use alloc::vec::Vec;

/// Errors that can occur during storage operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    /// Storage device not initialized
    NotInitialized,
    /// Storage device is write-protected
    WriteProtected,
    /// Access denied (locked region)
    AccessDenied,
    /// Operation timed out
    Timeout,
    /// Invalid address or length
    InvalidArgument,
    /// Generic I/O error
    IoError,
    /// Operation not supported by this backend
    NotSupported,
}

/// Result type for storage operations
pub type Result<T> = core::result::Result<T, StorageError>;

/// Storage backend trait
///
/// This trait abstracts storage operations, allowing different backends
/// (SPI flash, memory, etc.) to be used interchangeably by the variable store.
///
/// # Implementation Notes
///
/// - `read` should work on any valid offset within the storage size
/// - `write` may require the region to be erased first (flash semantics)
/// - `erase` sets bytes to 0xFF (NOR flash erased state)
/// - `enable_writes` may be a no-op for some backends (e.g., memory)
pub trait StorageBackend: Send {
    /// Get the backend name (for logging/debugging)
    fn name(&self) -> &str;

    /// Get the total storage size in bytes
    fn size(&self) -> u32;

    /// Check if the storage is write-protected
    fn is_write_protected(&self) -> bool;

    /// Enable writes to the storage
    ///
    /// This may need to clear write-protection bits on some hardware.
    /// Returns Ok(()) if writes are enabled, or an error if they cannot be enabled.
    fn enable_writes(&mut self) -> Result<()>;

    /// Read data from storage
    ///
    /// # Arguments
    /// - `offset`: Byte offset within the storage
    /// - `buffer`: Buffer to read data into
    ///
    /// # Errors
    /// - `InvalidArgument` if offset + buffer.len() exceeds storage size
    /// - `IoError` if the read operation fails
    fn read(&mut self, offset: u32, buffer: &mut [u8]) -> Result<()>;

    /// Write data to storage
    ///
    /// # Arguments
    /// - `offset`: Byte offset within the storage
    /// - `data`: Data to write
    ///
    /// # Notes
    /// For flash storage, the region should be erased first (bytes must be 0xFF).
    /// Writing can only clear bits (1->0), not set them.
    ///
    /// # Errors
    /// - `WriteProtected` if writes are not enabled
    /// - `InvalidArgument` if offset + data.len() exceeds storage size
    /// - `IoError` if the write operation fails
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<()>;

    /// Erase a region of storage
    ///
    /// Sets all bytes in the region to 0xFF (NOR flash erased state).
    ///
    /// # Arguments
    /// - `offset`: Starting byte offset (may be aligned to erase block size)
    /// - `size`: Number of bytes to erase (may be rounded up to erase block size)
    ///
    /// # Errors
    /// - `WriteProtected` if writes are not enabled
    /// - `InvalidArgument` if offset + size exceeds storage size
    /// - `IoError` if the erase operation fails
    fn erase(&mut self, offset: u32, size: u32) -> Result<()>;
}

/// Wrapper to adapt SPI controllers to the StorageBackend trait
///
/// This wrapper allows existing SPI controller implementations to be used
/// as storage backends without modifying them.
pub struct SpiStorageBackend {
    /// The underlying SPI controller (boxed for dynamic dispatch)
    controller: crate::drivers::spi::AnySpiController,
    /// Storage size (typically SMMSTORE size)
    storage_size: u32,
    /// Base offset within the flash for this storage region
    base_offset: u32,
}

impl SpiStorageBackend {
    /// Create a new SPI storage backend
    ///
    /// # Arguments
    /// - `controller`: The SPI controller to use
    /// - `base_offset`: Base offset within SPI flash for storage region
    /// - `storage_size`: Size of the storage region in bytes
    pub fn new(
        controller: crate::drivers::spi::AnySpiController,
        base_offset: u32,
        storage_size: u32,
    ) -> Self {
        Self {
            controller,
            storage_size,
            base_offset,
        }
    }

    /// Get a reference to the underlying SPI controller
    pub fn controller(&self) -> &crate::drivers::spi::AnySpiController {
        &self.controller
    }

    /// Get a mutable reference to the underlying SPI controller
    pub fn controller_mut(&mut self) -> &mut crate::drivers::spi::AnySpiController {
        &mut self.controller
    }

    /// Get the BIOS region from the flash descriptor (if available)
    ///
    /// This is used for calculating SPI offsets from memory-mapped addresses.
    pub fn get_bios_region(&self) -> Option<(u32, u32)> {
        use crate::drivers::spi::SpiController;
        self.controller.get_bios_region()
    }

    /// Get the base offset
    pub fn base_offset(&self) -> u32 {
        self.base_offset
    }

    /// Update the base offset (e.g., after detecting SMMSTORE location)
    pub fn set_base_offset(&mut self, offset: u32) {
        self.base_offset = offset;
    }

    /// Update the storage size
    pub fn set_storage_size(&mut self, size: u32) {
        self.storage_size = size;
    }
}

impl StorageBackend for SpiStorageBackend {
    fn name(&self) -> &str {
        use crate::drivers::spi::SpiController;
        self.controller.name()
    }

    fn size(&self) -> u32 {
        self.storage_size
    }

    fn is_write_protected(&self) -> bool {
        use crate::drivers::spi::SpiController;
        !self.controller.writes_enabled()
    }

    fn enable_writes(&mut self) -> Result<()> {
        use crate::drivers::spi::SpiController;
        self.controller.enable_writes().map_err(|e| {
            log::warn!("SPI enable_writes failed: {:?}", e);
            match e {
                crate::drivers::spi::SpiError::WriteProtected => StorageError::WriteProtected,
                crate::drivers::spi::SpiError::AccessDenied => StorageError::AccessDenied,
                crate::drivers::spi::SpiError::Timeout => StorageError::Timeout,
                _ => StorageError::IoError,
            }
        })
    }

    fn read(&mut self, offset: u32, buffer: &mut [u8]) -> Result<()> {
        use crate::drivers::spi::SpiController;

        // Check bounds
        if offset as u64 + buffer.len() as u64 > self.storage_size as u64 {
            return Err(StorageError::InvalidArgument);
        }

        // Read from flash at base_offset + offset
        let flash_addr = self
            .base_offset
            .checked_add(offset)
            .ok_or(StorageError::InvalidArgument)?;

        self.controller.read(flash_addr, buffer).map_err(|e| {
            log::warn!("SPI read failed at {:#x}: {:?}", flash_addr, e);
            match e {
                crate::drivers::spi::SpiError::InvalidArgument => StorageError::InvalidArgument,
                crate::drivers::spi::SpiError::Timeout => StorageError::Timeout,
                _ => StorageError::IoError,
            }
        })
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<()> {
        use crate::drivers::spi::SpiController;

        // Check bounds
        if offset as u64 + data.len() as u64 > self.storage_size as u64 {
            return Err(StorageError::InvalidArgument);
        }

        // Write to flash at base_offset + offset
        let flash_addr = self
            .base_offset
            .checked_add(offset)
            .ok_or(StorageError::InvalidArgument)?;

        self.controller.write(flash_addr, data).map_err(|e| {
            log::warn!("SPI write failed at {:#x}: {:?}", flash_addr, e);
            match e {
                crate::drivers::spi::SpiError::WriteProtected => StorageError::WriteProtected,
                crate::drivers::spi::SpiError::AccessDenied => StorageError::AccessDenied,
                crate::drivers::spi::SpiError::InvalidArgument => StorageError::InvalidArgument,
                crate::drivers::spi::SpiError::Timeout => StorageError::Timeout,
                _ => StorageError::IoError,
            }
        })
    }

    fn erase(&mut self, offset: u32, size: u32) -> Result<()> {
        use crate::drivers::spi::SpiController;

        // Check bounds
        if offset as u64 + size as u64 > self.storage_size as u64 {
            return Err(StorageError::InvalidArgument);
        }

        // Erase flash at base_offset + offset
        let flash_addr = self
            .base_offset
            .checked_add(offset)
            .ok_or(StorageError::InvalidArgument)?;

        self.controller.erase(flash_addr, size).map_err(|e| {
            log::warn!("SPI erase failed at {:#x}: {:?}", flash_addr, e);
            match e {
                crate::drivers::spi::SpiError::WriteProtected => StorageError::WriteProtected,
                crate::drivers::spi::SpiError::AccessDenied => StorageError::AccessDenied,
                crate::drivers::spi::SpiError::InvalidArgument => StorageError::InvalidArgument,
                crate::drivers::spi::SpiError::Timeout => StorageError::Timeout,
                _ => StorageError::IoError,
            }
        })
    }
}

/// Memory-backed storage backend for testing
///
/// This backend stores data in memory, simulating flash behavior:
/// - Erase sets bytes to 0xFF
/// - Write can only clear bits (1->0)
#[cfg(test)]
pub struct MemoryBackend {
    /// Storage data
    data: Vec<u8>,
    /// Backend name
    name: String,
    /// Write protection flag
    write_protected: bool,
}

#[cfg(test)]
impl MemoryBackend {
    /// Create a new memory backend with the given size
    ///
    /// The storage is initialized to all 0xFF (erased state).
    pub fn new(size: u32, name: &str) -> Self {
        Self {
            data: vec![0xFF; size as usize],
            name: String::from(name),
            write_protected: false,
        }
    }

    /// Create a memory backend from existing data
    pub fn from_data(data: Vec<u8>, name: &str) -> Self {
        Self {
            data,
            name: String::from(name),
            write_protected: false,
        }
    }

    /// Set write protection state
    pub fn set_write_protected(&mut self, protected: bool) {
        self.write_protected = protected;
    }

    /// Get a reference to the underlying data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the underlying data (bypasses flash semantics)
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

#[cfg(test)]
impl StorageBackend for MemoryBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn size(&self) -> u32 {
        self.data.len() as u32
    }

    fn is_write_protected(&self) -> bool {
        self.write_protected
    }

    fn enable_writes(&mut self) -> Result<()> {
        self.write_protected = false;
        Ok(())
    }

    fn read(&mut self, offset: u32, buffer: &mut [u8]) -> Result<()> {
        let start = offset as usize;
        let end = start
            .checked_add(buffer.len())
            .ok_or(StorageError::InvalidArgument)?;

        if end > self.data.len() {
            return Err(StorageError::InvalidArgument);
        }

        buffer.copy_from_slice(&self.data[start..end]);
        Ok(())
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<()> {
        if self.write_protected {
            return Err(StorageError::WriteProtected);
        }

        let start = offset as usize;
        let end = start
            .checked_add(data.len())
            .ok_or(StorageError::InvalidArgument)?;

        if end > self.data.len() {
            return Err(StorageError::InvalidArgument);
        }

        // Flash write semantics: can only clear bits (1->0)
        for (i, &byte) in data.iter().enumerate() {
            self.data[start + i] &= byte;
        }

        Ok(())
    }

    fn erase(&mut self, offset: u32, size: u32) -> Result<()> {
        if self.write_protected {
            return Err(StorageError::WriteProtected);
        }

        let start = offset as usize;
        let end = start
            .checked_add(size as usize)
            .ok_or(StorageError::InvalidArgument)?;

        if end > self.data.len() {
            return Err(StorageError::InvalidArgument);
        }

        // Flash erase sets bytes to 0xFF
        for byte in &mut self.data[start..end] {
            *byte = 0xFF;
        }

        Ok(())
    }
}

// Make StorageBackend object-safe by ensuring it can be used with dyn
// This allows: Box<dyn StorageBackend>, &dyn StorageBackend, etc.
#[cfg(test)]
mod tests {
    use super::*;

    fn _assert_object_safe(_: &dyn StorageBackend) {}
}
