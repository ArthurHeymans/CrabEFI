//! UHCI Register Definitions using tock-registers
//!
//! This module defines UHCI (USB 1.1) Universal Host Controller Interface
//! registers using type-safe tock-registers bitfields.
//!
//! UHCI registers are port-I/O based (not MMIO), so instead of a `#[repr(C)]`
//! register struct we provide a `UhciRegs` helper that constructs typed port
//! register accessors on the fly from a runtime base address.
//!
//! # Register widths
//! - USBCMD, USBSTS, USBINTR, FRNUM, PORTSC1, PORTSC2: 16-bit
//! - FLBASEADD: 32-bit
//! - SOFMOD: 8-bit (but usually accessed as 16-bit; we keep 32-bit for outl)
//!
//! # References
//! - UHCI Design Guide Revision 1.1

use tock_registers::register_bitfields;

use crate::arch::x86_64::port_regs::{PortReadWrite16, PortReadWrite32};

// ============================================================================
// Register Offsets
// ============================================================================

/// USB Command register offset (16-bit)
pub const USBCMD_OFFSET: u16 = 0x00;
/// USB Status register offset (16-bit)
pub const USBSTS_OFFSET: u16 = 0x02;
/// USB Interrupt Enable register offset (16-bit)
pub const USBINTR_OFFSET: u16 = 0x04;
/// Frame Number register offset (16-bit)
pub const FRNUM_OFFSET: u16 = 0x06;
/// Frame List Base Address register offset (32-bit)
pub const FLBASEADD_OFFSET: u16 = 0x08;
/// Start of Frame Modify register offset
pub const SOFMOD_OFFSET: u16 = 0x0C;
/// Port 1 Status/Control register offset (16-bit)
pub const PORTSC1_OFFSET: u16 = 0x10;
/// Port 2 Status/Control register offset (16-bit)
pub const PORTSC2_OFFSET: u16 = 0x12;

// ============================================================================
// Register Bitfield Definitions
// ============================================================================

register_bitfields! [
    u16,
    /// USB Command Register (offset 0x00)
    pub USBCMD [
        /// Run/Stop
        RS OFFSET(0) NUMBITS(1) [],
        /// Host Controller Reset
        HCRESET OFFSET(1) NUMBITS(1) [],
        /// Global Reset
        GRESET OFFSET(2) NUMBITS(1) [],
        /// Enter Global Suspend Mode
        EGSM OFFSET(3) NUMBITS(1) [],
        /// Force Global Resume
        FGR OFFSET(4) NUMBITS(1) [],
        /// Software Debug
        SWDBG OFFSET(5) NUMBITS(1) [],
        /// Configure Flag
        CF OFFSET(6) NUMBITS(1) [],
        /// Max Packet (1 = 64 bytes)
        MAXP OFFSET(7) NUMBITS(1) []
    ],

    /// USB Status Register (offset 0x02)
    pub USBSTS [
        /// USB Interrupt
        USBINT OFFSET(0) NUMBITS(1) [],
        /// USB Error Interrupt
        USBERRINT OFFSET(1) NUMBITS(1) [],
        /// Resume Detect
        RESDET OFFSET(2) NUMBITS(1) [],
        /// Host System Error
        HSERR OFFSET(3) NUMBITS(1) [],
        /// Host Controller Process Error
        HCPE OFFSET(4) NUMBITS(1) [],
        /// Host Controller Halted
        HCHALTED OFFSET(5) NUMBITS(1) []
    ],

    /// USB Interrupt Enable Register (offset 0x04)
    pub USBINTR [
        /// Timeout/CRC Interrupt Enable
        TOCRC OFFSET(0) NUMBITS(1) [],
        /// Resume Interrupt Enable
        RESUME OFFSET(1) NUMBITS(1) [],
        /// Interrupt On Complete Enable
        IOC OFFSET(2) NUMBITS(1) [],
        /// Short Packet Interrupt Enable
        SP OFFSET(3) NUMBITS(1) []
    ],

    /// Frame Number Register (offset 0x06)
    pub FRNUM [
        /// Frame Number (0-1023)
        FN OFFSET(0) NUMBITS(11) []
    ],

    /// Port Status/Control Register (offset 0x10 / 0x12)
    pub PORTSC [
        /// Current Connect Status (RO)
        CCS OFFSET(0) NUMBITS(1) [],
        /// Connect Status Change (RWC)
        CSC OFFSET(1) NUMBITS(1) [],
        /// Port Enabled (RW)
        PE OFFSET(2) NUMBITS(1) [],
        /// Port Enable Change (RWC)
        PEC OFFSET(3) NUMBITS(1) [],
        /// Line Status D+ (RO)
        LS_DPLUS OFFSET(4) NUMBITS(1) [],
        /// Line Status D- (RO)
        LS_DMINUS OFFSET(5) NUMBITS(1) [],
        /// Resume Detect (RW)
        RD OFFSET(6) NUMBITS(1) [],
        /// Reserved (always 1)
        RESERVED OFFSET(7) NUMBITS(1) [],
        /// Low Speed Device Attached (RO)
        LSDA OFFSET(8) NUMBITS(1) [],
        /// Port Reset (RW)
        PR OFFSET(9) NUMBITS(1) [],
        /// Suspend (RW)
        SUSPEND OFFSET(12) NUMBITS(1) []
    ]
];

// ============================================================================
// UHCI Port I/O Register Accessors
// ============================================================================

/// UHCI register accessors via port I/O
///
/// Since UHCI uses port-mapped I/O (not MMIO), we cannot use a `#[repr(C)]`
/// struct cast. Instead, this struct stores the base I/O port address and
/// provides methods that construct typed port register accessors on the fly.
pub struct UhciRegs {
    base: u16,
}

impl UhciRegs {
    /// Create a new UHCI register accessor for the given I/O base address
    pub const fn new(base: u16) -> Self {
        Self { base }
    }

    /// USB Command register (16-bit RW)
    #[inline]
    pub fn usbcmd(&self) -> PortReadWrite16<USBCMD::Register> {
        PortReadWrite16::new(self.base + USBCMD_OFFSET)
    }

    /// USB Status register (16-bit RW)
    #[inline]
    pub fn usbsts(&self) -> PortReadWrite16<USBSTS::Register> {
        PortReadWrite16::new(self.base + USBSTS_OFFSET)
    }

    /// USB Interrupt Enable register (16-bit RW)
    #[inline]
    pub fn usbintr(&self) -> PortReadWrite16<USBINTR::Register> {
        PortReadWrite16::new(self.base + USBINTR_OFFSET)
    }

    /// Frame Number register (16-bit RW)
    #[inline]
    pub fn frnum(&self) -> PortReadWrite16<FRNUM::Register> {
        PortReadWrite16::new(self.base + FRNUM_OFFSET)
    }

    /// Frame List Base Address register (32-bit RW, no bitfields)
    #[inline]
    pub fn flbaseadd(&self) -> PortReadWrite32<()> {
        PortReadWrite32::new(self.base + FLBASEADD_OFFSET)
    }

    /// Port Status/Control register for a given port (0 or 1)
    ///
    /// # Panics
    /// Panics in debug mode if `port > 1`.
    #[inline]
    pub fn portsc(&self, port: u8) -> PortReadWrite16<PORTSC::Register> {
        debug_assert!(port <= 1, "UHCI only has 2 ports (0 and 1)");
        PortReadWrite16::new(self.base + PORTSC1_OFFSET + (port as u16) * 2)
    }
}
