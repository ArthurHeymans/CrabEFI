//! Port-Mapped I/O Register Types
//!
//! This module provides tock-registers compatible types for x86 port I/O,
//! enabling type-safe access with named bitfields.
//!
//! # Example
//!
//! ```ignore
//! use tock_registers::register_bitfields;
//! use crate::arch::x86_64::port_regs::PortReadOnly;
//!
//! register_bitfields![u8,
//!     Status [
//!         OUTPUT_FULL OFFSET(0) NUMBITS(1) [],
//!         INPUT_FULL  OFFSET(1) NUMBITS(1) [],
//!     ],
//! ];
//!
//! let status = PortReadOnly::<u8, Status::Register>::new(0x64);
//! if status.is_set(Status::OUTPUT_FULL) {
//!     // Data is available
//! }
//! ```

use core::marker::PhantomData;

use tock_registers::RegisterLongName;
use tock_registers::interfaces::{Readable, Writeable};

use super::io;

/// Read-only 8-bit port register
pub struct PortReadOnly8<R: RegisterLongName> {
    port: u16,
    _reg: PhantomData<R>,
}

impl<R: RegisterLongName> PortReadOnly8<R> {
    /// Create a new read-only port register at the given I/O port address
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _reg: PhantomData,
        }
    }

    /// Get the I/O port address
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl<R: RegisterLongName> Readable for PortReadOnly8<R> {
    type T = u8;
    type R = R;

    #[inline]
    fn get(&self) -> u8 {
        // Safety: Port I/O is inherently unsafe but we trust the caller
        // to provide a valid port address at construction time
        unsafe { io::inb(self.port) }
    }
}

/// Write-only 8-bit port register
pub struct PortWriteOnly8<R: RegisterLongName> {
    port: u16,
    _reg: PhantomData<R>,
}

impl<R: RegisterLongName> PortWriteOnly8<R> {
    /// Create a new write-only port register at the given I/O port address
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _reg: PhantomData,
        }
    }

    /// Get the I/O port address
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl<R: RegisterLongName> Writeable for PortWriteOnly8<R> {
    type T = u8;
    type R = R;

    #[inline]
    fn set(&self, value: u8) {
        // Safety: Port I/O is inherently unsafe but we trust the caller
        // to provide a valid port address at construction time
        unsafe { io::outb(self.port, value) }
    }
}

/// Read-write 8-bit port register
pub struct PortReadWrite8<R: RegisterLongName> {
    port: u16,
    _reg: PhantomData<R>,
}

impl<R: RegisterLongName> PortReadWrite8<R> {
    /// Create a new read-write port register at the given I/O port address
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _reg: PhantomData,
        }
    }

    /// Get the I/O port address
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl<R: RegisterLongName> Readable for PortReadWrite8<R> {
    type T = u8;
    type R = R;

    #[inline]
    fn get(&self) -> u8 {
        unsafe { io::inb(self.port) }
    }
}

impl<R: RegisterLongName> Writeable for PortReadWrite8<R> {
    type T = u8;
    type R = R;

    #[inline]
    fn set(&self, value: u8) {
        unsafe { io::outb(self.port, value) }
    }
}

/// Aliased 8-bit port register with different read and write semantics
///
/// Used for registers where reading and writing have different meanings,
/// such as the PS/2 controller port 0x64 (Status when read, Command when written).
pub struct PortAliased8<R: RegisterLongName, W: RegisterLongName> {
    port: u16,
    _read: PhantomData<R>,
    _write: PhantomData<W>,
}

impl<R: RegisterLongName, W: RegisterLongName> PortAliased8<R, W> {
    /// Create a new aliased port register at the given I/O port address
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _read: PhantomData,
            _write: PhantomData,
        }
    }
}

impl<R: RegisterLongName, W: RegisterLongName> Readable for PortAliased8<R, W> {
    type T = u8;
    type R = R;

    #[inline]
    fn get(&self) -> u8 {
        unsafe { io::inb(self.port) }
    }
}

impl<R: RegisterLongName, W: RegisterLongName> Writeable for PortAliased8<R, W> {
    type T = u8;
    type R = W;

    #[inline]
    fn set(&self, value: u8) {
        unsafe { io::outb(self.port, value) }
    }
}

// ============================================================================
// 16-bit port registers (for UHCI and similar)
// ============================================================================

/// Read-only 16-bit port register
pub struct PortReadOnly16<R: RegisterLongName> {
    port: u16,
    _reg: PhantomData<R>,
}

impl<R: RegisterLongName> PortReadOnly16<R> {
    /// Create a new read-only 16-bit port register
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _reg: PhantomData,
        }
    }
}

impl<R: RegisterLongName> Readable for PortReadOnly16<R> {
    type T = u16;
    type R = R;

    #[inline]
    fn get(&self) -> u16 {
        unsafe { io::inw(self.port) }
    }
}

/// Write-only 16-bit port register
pub struct PortWriteOnly16<R: RegisterLongName> {
    port: u16,
    _reg: PhantomData<R>,
}

impl<R: RegisterLongName> PortWriteOnly16<R> {
    /// Create a new write-only 16-bit port register
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _reg: PhantomData,
        }
    }
}

impl<R: RegisterLongName> Writeable for PortWriteOnly16<R> {
    type T = u16;
    type R = R;

    #[inline]
    fn set(&self, value: u16) {
        unsafe { io::outw(self.port, value) }
    }
}

/// Read-write 16-bit port register
pub struct PortReadWrite16<R: RegisterLongName> {
    port: u16,
    _reg: PhantomData<R>,
}

impl<R: RegisterLongName> PortReadWrite16<R> {
    /// Create a new read-write 16-bit port register
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _reg: PhantomData,
        }
    }
}

impl<R: RegisterLongName> Readable for PortReadWrite16<R> {
    type T = u16;
    type R = R;

    #[inline]
    fn get(&self) -> u16 {
        unsafe { io::inw(self.port) }
    }
}

impl<R: RegisterLongName> Writeable for PortReadWrite16<R> {
    type T = u16;
    type R = R;

    #[inline]
    fn set(&self, value: u16) {
        unsafe { io::outw(self.port, value) }
    }
}

// ============================================================================
// 32-bit port registers (for ACPI PM timer, PCI config, etc.)
// ============================================================================

/// Read-only 32-bit port register
pub struct PortReadOnly32<R: RegisterLongName> {
    port: u16,
    _reg: PhantomData<R>,
}

impl<R: RegisterLongName> PortReadOnly32<R> {
    /// Create a new read-only 32-bit port register
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _reg: PhantomData,
        }
    }
}

impl<R: RegisterLongName> Readable for PortReadOnly32<R> {
    type T = u32;
    type R = R;

    #[inline]
    fn get(&self) -> u32 {
        unsafe { io::inl(self.port) }
    }
}

/// Write-only 32-bit port register
pub struct PortWriteOnly32<R: RegisterLongName> {
    port: u16,
    _reg: PhantomData<R>,
}

impl<R: RegisterLongName> PortWriteOnly32<R> {
    /// Create a new write-only 32-bit port register
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _reg: PhantomData,
        }
    }
}

impl<R: RegisterLongName> Writeable for PortWriteOnly32<R> {
    type T = u32;
    type R = R;

    #[inline]
    fn set(&self, value: u32) {
        unsafe { io::outl(self.port, value) }
    }
}

/// Read-write 32-bit port register
pub struct PortReadWrite32<R: RegisterLongName> {
    port: u16,
    _reg: PhantomData<R>,
}

impl<R: RegisterLongName> PortReadWrite32<R> {
    /// Create a new read-write 32-bit port register
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _reg: PhantomData,
        }
    }
}

impl<R: RegisterLongName> Readable for PortReadWrite32<R> {
    type T = u32;
    type R = R;

    #[inline]
    fn get(&self) -> u32 {
        unsafe { io::inl(self.port) }
    }
}

impl<R: RegisterLongName> Writeable for PortReadWrite32<R> {
    type T = u32;
    type R = R;

    #[inline]
    fn set(&self, value: u32) {
        unsafe { io::outl(self.port, value) }
    }
}
