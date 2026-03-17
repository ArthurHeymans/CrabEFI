//! Serial Port Register Definitions
//!
//! This module defines register bitfields for the two UART types supported
//! by CrabEFI:
//!
//! - **16550 UART** (x86): 8-bit port I/O registers with tock-registers
//!   bitfields and a `Uart16550Regs` accessor struct.
//! - **PL011 UART** (aarch64): 32-bit MMIO registers with a `#[repr(C)]`
//!   register struct for direct pointer casting.

// ============================================================================
// 16550 UART Register Definitions (x86 port I/O)
// ============================================================================

#[cfg(target_arch = "x86_64")]
pub mod uart16550 {
    use tock_registers::register_bitfields;

    use crate::arch::x86_64::port_regs::{PortAliased8, PortReadOnly8, PortReadWrite8};

    // Register offsets from the base I/O port address
    const DATA_OFFSET: u16 = 0; // THR (write) / RBR (read), DLL when DLAB=1
    const IER_OFFSET: u16 = 1; // Interrupt Enable, DLM when DLAB=1
    const IIR_FCR_OFFSET: u16 = 2; // IIR (read) / FCR (write)
    const LCR_OFFSET: u16 = 3; // Line Control Register
    const MCR_OFFSET: u16 = 4; // Modem Control Register
    const LSR_OFFSET: u16 = 5; // Line Status Register
    const MSR_OFFSET: u16 = 6; // Modem Status Register
    const SCRATCH_OFFSET: u16 = 7; // Scratch Register

    register_bitfields![u8,
        /// Interrupt Enable Register (offset 1)
        pub IER [
            /// Enable Received Data Available Interrupt
            ERBFI OFFSET(0) NUMBITS(1) [],
            /// Enable Transmitter Holding Register Empty Interrupt
            ETBEI OFFSET(1) NUMBITS(1) [],
            /// Enable Receiver Line Status Interrupt
            ELSI OFFSET(2) NUMBITS(1) [],
            /// Enable Modem Status Interrupt
            EDSSI OFFSET(3) NUMBITS(1) [],
        ],

        /// Interrupt Identification Register (offset 2, read-only)
        pub IIR [
            /// Interrupt Pending (0 = interrupt pending)
            INT_PEND OFFSET(0) NUMBITS(1) [],
            /// Interrupt ID
            INT_ID OFFSET(1) NUMBITS(3) [
                ModemStatus = 0,
                TxEmpty = 1,
                RxAvailable = 2,
                LineStatus = 3,
                CharTimeout = 6,
            ],
            /// FIFOs Enabled
            FIFOS_ENABLED OFFSET(6) NUMBITS(2) [],
        ],

        /// FIFO Control Register (offset 2, write-only)
        pub FCR [
            /// FIFO Enable
            FIFOE OFFSET(0) NUMBITS(1) [],
            /// Receiver FIFO Reset
            RFIFOR OFFSET(1) NUMBITS(1) [],
            /// Transmitter FIFO Reset
            XFIFOR OFFSET(2) NUMBITS(1) [],
            /// DMA Mode Select
            DMA OFFSET(3) NUMBITS(1) [],
            /// Receiver Trigger Level
            RCVR_TRIGGER OFFSET(6) NUMBITS(2) [
                Bytes1 = 0,
                Bytes4 = 1,
                Bytes8 = 2,
                Bytes14 = 3,
            ],
        ],

        /// Line Control Register (offset 3)
        pub LCR [
            /// Word Length Select
            WLS OFFSET(0) NUMBITS(2) [
                Bits5 = 0,
                Bits6 = 1,
                Bits7 = 2,
                Bits8 = 3,
            ],
            /// Number of Stop Bits (0 = 1 stop bit, 1 = 1.5/2 stop bits)
            STB OFFSET(2) NUMBITS(1) [],
            /// Parity Enable
            PEN OFFSET(3) NUMBITS(1) [],
            /// Even Parity Select
            EPS OFFSET(4) NUMBITS(1) [],
            /// Set Break
            SBRK OFFSET(6) NUMBITS(1) [],
            /// Divisor Latch Access Bit
            DLAB OFFSET(7) NUMBITS(1) [],
        ],

        /// Modem Control Register (offset 4)
        pub MCR [
            /// Data Terminal Ready
            DTR OFFSET(0) NUMBITS(1) [],
            /// Request To Send
            RTS OFFSET(1) NUMBITS(1) [],
            /// Out1
            OUT1 OFFSET(2) NUMBITS(1) [],
            /// Out2 (enables IRQ in PC-compatible mode)
            OUT2 OFFSET(3) NUMBITS(1) [],
            /// Loopback Mode
            LOOP_MODE OFFSET(4) NUMBITS(1) [],
        ],

        /// Line Status Register (offset 5, read-only)
        pub LSR [
            /// Data Ready
            DR OFFSET(0) NUMBITS(1) [],
            /// Overrun Error
            OE OFFSET(1) NUMBITS(1) [],
            /// Parity Error
            PE OFFSET(2) NUMBITS(1) [],
            /// Framing Error
            FE OFFSET(3) NUMBITS(1) [],
            /// Break Interrupt
            BI OFFSET(4) NUMBITS(1) [],
            /// Transmitter Holding Register Empty
            THRE OFFSET(5) NUMBITS(1) [],
            /// Transmitter Empty
            TEMT OFFSET(6) NUMBITS(1) [],
            /// Error in Receiver FIFO
            ERFIFO OFFSET(7) NUMBITS(1) [],
        ],

        /// Modem Status Register (offset 6, read-only)
        pub MSR [
            /// Delta Clear To Send
            DCTS OFFSET(0) NUMBITS(1) [],
            /// Delta Data Set Ready
            DDSR OFFSET(1) NUMBITS(1) [],
            /// Trailing Edge Ring Indicator
            TERI OFFSET(2) NUMBITS(1) [],
            /// Delta Data Carrier Detect
            DDCD OFFSET(3) NUMBITS(1) [],
            /// Clear To Send
            CTS OFFSET(4) NUMBITS(1) [],
            /// Data Set Ready
            DSR OFFSET(5) NUMBITS(1) [],
            /// Ring Indicator
            RI OFFSET(6) NUMBITS(1) [],
            /// Data Carrier Detect
            DCD OFFSET(7) NUMBITS(1) [],
        ],
    ];

    /// 16550 UART register accessors via port I/O
    ///
    /// Since the 16550 on x86 uses port-mapped I/O, we cannot cast a
    /// `#[repr(C)]` struct. Instead, this struct stores the base I/O port
    /// address and provides methods that construct typed port register
    /// accessors on the fly (same pattern as `UhciRegs`).
    pub struct Uart16550Regs {
        base: u16,
    }

    impl Uart16550Regs {
        /// Create a new 16550 register accessor for the given I/O base address
        pub const fn new(base: u16) -> Self {
            Self { base }
        }

        /// Data register: THR (write) / RBR (read) — plain u8, no bitfields.
        /// When DLAB=1, this is the Divisor Latch Low byte (DLL).
        #[inline]
        pub fn data(&self) -> PortReadWrite8<()> {
            PortReadWrite8::new(self.base + DATA_OFFSET)
        }

        /// Interrupt Enable Register (or DLM when DLAB=1) — plain u8 accessor
        /// for divisor high byte writes; use `ier()` for typed bitfield access.
        #[inline]
        pub fn dlm(&self) -> PortReadWrite8<()> {
            PortReadWrite8::new(self.base + IER_OFFSET)
        }

        /// Interrupt Enable Register with typed bitfields
        #[inline]
        pub fn ier(&self) -> PortReadWrite8<IER::Register> {
            PortReadWrite8::new(self.base + IER_OFFSET)
        }

        /// IIR (read) / FCR (write) — aliased register
        #[inline]
        pub fn iir_fcr(&self) -> PortAliased8<IIR::Register, FCR::Register> {
            PortAliased8::new(self.base + IIR_FCR_OFFSET)
        }

        /// Line Control Register
        #[inline]
        pub fn lcr(&self) -> PortReadWrite8<LCR::Register> {
            PortReadWrite8::new(self.base + LCR_OFFSET)
        }

        /// Modem Control Register
        #[inline]
        pub fn mcr(&self) -> PortReadWrite8<MCR::Register> {
            PortReadWrite8::new(self.base + MCR_OFFSET)
        }

        /// Line Status Register (read-only)
        #[inline]
        pub fn lsr(&self) -> PortReadOnly8<LSR::Register> {
            PortReadOnly8::new(self.base + LSR_OFFSET)
        }

        /// Modem Status Register (read-only)
        #[inline]
        #[allow(dead_code)]
        pub fn msr(&self) -> PortReadOnly8<MSR::Register> {
            PortReadOnly8::new(self.base + MSR_OFFSET)
        }

        /// Scratch Register — plain u8, used for hardware detection
        #[inline]
        pub fn scratch(&self) -> PortReadWrite8<()> {
            PortReadWrite8::new(self.base + SCRATCH_OFFSET)
        }
    }
}

// ============================================================================
// PL011 UART Register Definitions (aarch64 MMIO)
// ============================================================================

#[cfg(target_arch = "aarch64")]
pub mod pl011 {
    use tock_registers::register_bitfields;
    use tock_registers::registers::{ReadOnly, ReadWrite, WriteOnly};

    register_bitfields![u32,
        /// Flag Register (UARTFR, offset 0x18)
        pub FR [
            /// Clear To Send
            CTS OFFSET(0) NUMBITS(1) [],
            /// Data Set Ready
            DSR OFFSET(1) NUMBITS(1) [],
            /// Data Carrier Detect
            DCD OFFSET(2) NUMBITS(1) [],
            /// UART Busy
            BUSY OFFSET(3) NUMBITS(1) [],
            /// Receive FIFO Empty
            RXFE OFFSET(4) NUMBITS(1) [],
            /// Transmit FIFO Full
            TXFF OFFSET(5) NUMBITS(1) [],
            /// Receive FIFO Full
            RXFF OFFSET(6) NUMBITS(1) [],
            /// Transmit FIFO Empty
            TXFE OFFSET(7) NUMBITS(1) [],
            /// Ring Indicator
            RI OFFSET(8) NUMBITS(1) [],
        ],

        /// Line Control Register (UARTLCR_H, offset 0x2C)
        pub LCR_H [
            /// Send Break
            BRK OFFSET(0) NUMBITS(1) [],
            /// Parity Enable
            PEN OFFSET(1) NUMBITS(1) [],
            /// Even Parity Select
            EPS OFFSET(2) NUMBITS(1) [],
            /// Two Stop Bits Select
            STP2 OFFSET(3) NUMBITS(1) [],
            /// FIFO Enable
            FEN OFFSET(4) NUMBITS(1) [],
            /// Word Length
            WLEN OFFSET(5) NUMBITS(2) [
                Bits5 = 0b00,
                Bits6 = 0b01,
                Bits7 = 0b10,
                Bits8 = 0b11,
            ],
            /// Stick Parity Select
            SPS OFFSET(7) NUMBITS(1) [],
        ],

        /// Control Register (UARTCR, offset 0x30)
        pub CR [
            /// UART Enable
            UARTEN OFFSET(0) NUMBITS(1) [],
            /// SIR Enable
            SIREN OFFSET(1) NUMBITS(1) [],
            /// SIR Low-Power IrDA Mode
            SIRLP OFFSET(2) NUMBITS(1) [],
            /// Loopback Enable
            LBE OFFSET(7) NUMBITS(1) [],
            /// Transmit Enable
            TXE OFFSET(8) NUMBITS(1) [],
            /// Receive Enable
            RXE OFFSET(9) NUMBITS(1) [],
            /// Data Transmit Ready
            DTR OFFSET(10) NUMBITS(1) [],
            /// Request To Send
            RTS OFFSET(11) NUMBITS(1) [],
            /// Out1
            OUT1 OFFSET(12) NUMBITS(1) [],
            /// Out2
            OUT2 OFFSET(13) NUMBITS(1) [],
            /// RTS Hardware Flow Control Enable
            CTSE OFFSET(14) NUMBITS(1) [],
            /// CTS Hardware Flow Control Enable
            RTSE OFFSET(15) NUMBITS(1) [],
        ],
    ];

    /// PL011 UART MMIO register layout
    ///
    /// Cast a pointer to the PL011 base address to `&Pl011Registers` for
    /// type-safe register access. The reserved fields ensure correct offset
    /// alignment matching the PL011 TRM.
    #[repr(C)]
    pub struct Pl011Registers {
        /// Data Register (0x00)
        pub dr: ReadWrite<u32>,
        /// Receive Status / Error Clear (0x04)
        pub rsr_ecr: ReadWrite<u32>,
        /// Reserved (0x08–0x14)
        _reserved0: [u32; 4],
        /// Flag Register (0x18)
        pub fr: ReadOnly<u32, FR::Register>,
        /// Reserved (0x1C)
        _reserved1: u32,
        /// IrDA Low-Power Counter (0x20)
        pub ilpr: ReadWrite<u32>,
        /// Integer Baud Rate Divisor (0x24)
        pub ibrd: ReadWrite<u32>,
        /// Fractional Baud Rate Divisor (0x28)
        pub fbrd: ReadWrite<u32>,
        /// Line Control Register (0x2C)
        pub lcr_h: ReadWrite<u32, LCR_H::Register>,
        /// Control Register (0x30)
        pub cr: ReadWrite<u32, CR::Register>,
        /// Interrupt FIFO Level Select (0x34)
        pub ifls: ReadWrite<u32>,
        /// Interrupt Mask Set/Clear (0x38)
        pub imsc: ReadWrite<u32>,
        /// Raw Interrupt Status (0x3C)
        pub ris: ReadOnly<u32>,
        /// Masked Interrupt Status (0x40)
        pub mis: ReadOnly<u32>,
        /// Interrupt Clear Register (0x44)
        pub icr: WriteOnly<u32>,
    }
}
