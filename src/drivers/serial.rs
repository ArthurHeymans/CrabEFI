//! 16550 UART serial port driver
//!
//! This module provides a simple driver for the 16550-compatible UART
//! typically found in PC-compatible systems.

use core::fmt::{self, Write};

use spin::Mutex;
use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::register_bitfields;

use crate::arch::x86_64::port_regs::{PortReadOnly8, PortReadWrite8, PortWriteOnly8};

// ============================================================================
// Register Definitions using tock-registers
// ============================================================================

register_bitfields![u8,
    /// Line Status Register (LSR) - read only
    pub LSR [
        /// Data ready - set when data available in receive buffer
        DATA_READY OFFSET(0) NUMBITS(1) [],
        /// Overrun error - receive buffer was full when new data arrived
        OVERRUN_ERR OFFSET(1) NUMBITS(1) [],
        /// Parity error - received character had wrong parity
        PARITY_ERR OFFSET(2) NUMBITS(1) [],
        /// Framing error - received character had invalid stop bit
        FRAMING_ERR OFFSET(3) NUMBITS(1) [],
        /// Break indicator - break condition detected on line
        BREAK_IND OFFSET(4) NUMBITS(1) [],
        /// Transmitter Holding Register Empty - ready to accept data
        TX_EMPTY OFFSET(5) NUMBITS(1) [],
        /// Transmitter Empty - transmitter idle (shift register empty)
        TX_IDLE OFFSET(6) NUMBITS(1) [],
        /// FIFO Error - at least one error in FIFO
        FIFO_ERR OFFSET(7) NUMBITS(1) [],
    ],

    /// Line Control Register (LCR)
    pub LCR [
        /// Word length
        WORD_LEN OFFSET(0) NUMBITS(2) [
            Bits5 = 0,
            Bits6 = 1,
            Bits7 = 2,
            Bits8 = 3,
        ],
        /// Number of stop bits (0 = 1 stop bit, 1 = 2 stop bits)
        STOP_BITS OFFSET(2) NUMBITS(1) [
            One = 0,
            Two = 1,
        ],
        /// Parity enable
        PARITY_EN OFFSET(3) NUMBITS(1) [],
        /// Even parity select (when parity enabled)
        EVEN_PAR OFFSET(4) NUMBITS(1) [],
        /// Stick parity
        STICK_PAR OFFSET(5) NUMBITS(1) [],
        /// Set break - force break condition on line
        BREAK OFFSET(6) NUMBITS(1) [],
        /// Divisor Latch Access Bit - enables access to baud rate divisor
        DLAB OFFSET(7) NUMBITS(1) [],
    ],

    /// Modem Control Register (MCR)
    pub MCR [
        /// Data Terminal Ready
        DTR OFFSET(0) NUMBITS(1) [],
        /// Request To Send
        RTS OFFSET(1) NUMBITS(1) [],
        /// Out1 (auxiliary output 1)
        OUT1 OFFSET(2) NUMBITS(1) [],
        /// Out2 (auxiliary output 2, often used for IRQ enable)
        OUT2 OFFSET(3) NUMBITS(1) [],
        /// Loopback mode
        LOOPBACK OFFSET(4) NUMBITS(1) [],
    ],

    /// FIFO Control Register (FCR) - write only
    pub FCR [
        /// FIFO enable
        FIFO_EN OFFSET(0) NUMBITS(1) [],
        /// Receive FIFO reset
        RX_FIFO_RST OFFSET(1) NUMBITS(1) [],
        /// Transmit FIFO reset
        TX_FIFO_RST OFFSET(2) NUMBITS(1) [],
        /// DMA mode select
        DMA_MODE OFFSET(3) NUMBITS(1) [],
        /// Receive FIFO trigger level
        RX_TRIGGER OFFSET(6) NUMBITS(2) [
            Bytes1 = 0,
            Bytes4 = 1,
            Bytes8 = 2,
            Bytes14 = 3,
        ],
    ],

    /// Interrupt Enable Register (IER)
    pub IER [
        /// Enable Received Data Available Interrupt
        RX_AVAIL OFFSET(0) NUMBITS(1) [],
        /// Enable Transmitter Holding Register Empty Interrupt
        TX_EMPTY OFFSET(1) NUMBITS(1) [],
        /// Enable Receiver Line Status Interrupt
        RX_LINE_STATUS OFFSET(2) NUMBITS(1) [],
        /// Enable Modem Status Interrupt
        MODEM_STATUS OFFSET(3) NUMBITS(1) [],
    ],
];

/// Standard COM1 port address
pub const COM1: u16 = 0x3F8;

/// Standard COM2 port address
pub const COM2: u16 = 0x2F8;

/// Serial port register offsets
mod offsets {
    pub const DATA: u16 = 0; // Data register (read/write), also DLL when DLAB=1
    pub const IER: u16 = 1; // Interrupt Enable Register, also DLH when DLAB=1
    pub const FCR: u16 = 2; // FIFO Control Register (write)
    pub const LCR: u16 = 3; // Line Control Register
    pub const MCR: u16 = 4; // Modem Control Register
    pub const LSR: u16 = 5; // Line Status Register
    pub const SCRATCH: u16 = 7; // Scratch register
}

/// Global serial port instance
static SERIAL: Mutex<Option<SerialPort>> = Mutex::new(None);

/// Maximum iterations to wait for TX ready (prevents infinite loop on missing hardware)
const TX_TIMEOUT_ITERATIONS: u32 = 100_000;

// ============================================================================
// Serial Port Registers
// ============================================================================

/// Serial port I/O registers
struct SerialRegs {
    /// Data register - read/write (also DLL when DLAB=1)
    data: PortReadWrite8<()>,
    /// Interrupt Enable Register (also DLH when DLAB=1)
    ier: PortReadWrite8<IER::Register>,
    /// FIFO Control Register (write-only)
    fcr: PortWriteOnly8<FCR::Register>,
    /// Line Control Register
    lcr: PortReadWrite8<LCR::Register>,
    /// Modem Control Register
    mcr: PortReadWrite8<MCR::Register>,
    /// Line Status Register (read-only)
    lsr: PortReadOnly8<LSR::Register>,
    /// Scratch register (for detection)
    scratch: PortReadWrite8<()>,
}

impl SerialRegs {
    /// Create serial port registers at the given base address
    const fn new(base: u16) -> Self {
        Self {
            data: PortReadWrite8::new(base + offsets::DATA),
            ier: PortReadWrite8::new(base + offsets::IER),
            fcr: PortWriteOnly8::new(base + offsets::FCR),
            lcr: PortReadWrite8::new(base + offsets::LCR),
            mcr: PortReadWrite8::new(base + offsets::MCR),
            lsr: PortReadOnly8::new(base + offsets::LSR),
            scratch: PortReadWrite8::new(base + offsets::SCRATCH),
        }
    }
}

impl SerialRegs {
    /// Get divisor latch low register (DLL - same port as DATA when DLAB=1)
    const fn dll(&self) -> &PortReadWrite8<()> {
        &self.data
    }

    /// Get divisor latch high register (DLH - same port as IER when DLAB=1)
    fn dlh(&self) -> PortReadWrite8<()> {
        // DLH is at same address as IER
        PortReadWrite8::new(self.ier.port())
    }
}

// ============================================================================
// Serial Port Driver
// ============================================================================

/// A 16550 UART serial port
pub struct SerialPort {
    /// Port registers
    regs: SerialRegs,
    /// Whether this port has been detected as functional
    functional: bool,
}

impl SerialPort {
    /// Create a new serial port at the given base address
    ///
    /// # Safety
    ///
    /// The base address must be a valid I/O port for a 16550 UART.
    pub const unsafe fn new(base: u16) -> Self {
        SerialPort {
            regs: SerialRegs::new(base),
            functional: false,
        }
    }

    /// Check if a serial port exists at this address
    ///
    /// Uses the scratch register test: write a value, read it back.
    /// If we get back what we wrote, a UART is likely present.
    fn detect(&self) -> bool {
        // Try writing and reading back a test pattern
        self.regs.scratch.set(0x55);
        if self.regs.scratch.get() != 0x55 {
            return false;
        }

        self.regs.scratch.set(0xAA);
        if self.regs.scratch.get() != 0xAA {
            return false;
        }

        // Also check that LSR doesn't return 0xFF (unpopulated port)
        if self.regs.lsr.get() == 0xFF {
            return false;
        }

        true
    }

    /// Initialize the serial port with the given baud rate
    ///
    /// Returns true if initialization succeeded, false if no serial port detected.
    pub fn init(&mut self, baud: u32) -> bool {
        // First check if a serial port exists
        if !self.detect() {
            self.functional = false;
            return false;
        }

        let divisor = 115200 / baud;

        // Disable interrupts
        self.regs.ier.set(0x00);

        // Enable DLAB to set baud rate divisor
        self.regs.lcr.write(LCR::DLAB::SET);

        // Set divisor
        self.regs.dll().set((divisor & 0xFF) as u8);
        self.regs.dlh().set(((divisor >> 8) & 0xFF) as u8);

        // 8 bits, no parity, one stop bit (clear DLAB at the same time)
        self.regs
            .lcr
            .write(LCR::WORD_LEN::Bits8 + LCR::STOP_BITS::One + LCR::PARITY_EN::CLEAR);

        // Enable FIFO, clear them, with 14-byte threshold
        self.regs.fcr.write(
            FCR::FIFO_EN::SET
                + FCR::RX_FIFO_RST::SET
                + FCR::TX_FIFO_RST::SET
                + FCR::RX_TRIGGER::Bytes14,
        );

        // IRQs enabled, RTS/DSR set
        self.regs
            .mcr
            .write(MCR::DTR::SET + MCR::RTS::SET + MCR::OUT2::SET);

        self.functional = true;
        true
    }

    /// Write a byte to the serial port
    pub fn write_byte(&mut self, byte: u8) {
        if !self.functional {
            return;
        }

        // Wait for transmit buffer to be empty, with timeout
        let mut timeout = TX_TIMEOUT_ITERATIONS;
        while !self.regs.lsr.is_set(LSR::TX_EMPTY) {
            timeout -= 1;
            if timeout == 0 {
                // Serial port not responding, mark as non-functional
                self.functional = false;
                return;
            }
            core::hint::spin_loop();
        }

        self.regs.data.set(byte);
    }

    /// Read a byte from the serial port (blocking)
    pub fn read_byte(&mut self) -> u8 {
        // Wait for data to be available
        while !self.regs.lsr.is_set(LSR::DATA_READY) {
            core::hint::spin_loop();
        }

        self.regs.data.get()
    }

    /// Try to read a byte from the serial port (non-blocking)
    pub fn try_read_byte(&mut self) -> Option<u8> {
        if self.regs.lsr.is_set(LSR::DATA_READY) {
            Some(self.regs.data.get())
        } else {
            None
        }
    }

    /// Check if the serial port is ready to receive data
    pub fn can_receive(&self) -> bool {
        self.regs.lsr.is_set(LSR::DATA_READY)
    }

    /// Check if the serial port is ready to send data
    pub fn can_send(&self) -> bool {
        self.regs.lsr.is_set(LSR::TX_EMPTY)
    }
}

impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
        Ok(())
    }
}

// ============================================================================
// Global API
// ============================================================================

/// Initialize the global serial port for early debug output
///
/// This is a no-op now - we wait for coreboot tables to tell us the serial port.
/// Call `init_from_coreboot()` after parsing coreboot tables.
pub fn init_early() {
    // Don't initialize serial until we know from coreboot tables if one exists
    // and what address it's at. This prevents hanging on systems without serial.
}

/// Initialize serial port from coreboot table information
///
/// # Arguments
/// * `base_addr` - I/O port base address from coreboot serial info
/// * `baud` - Baud rate (typically 115200)
pub fn init_from_coreboot(base_addr: u32, baud: u32) {
    let mut serial = unsafe { SerialPort::new(base_addr as u16) };

    if serial.init(baud) {
        // Test the serial port
        let _ = serial.write_str("\r\n[CrabEFI] Serial initialized from coreboot\r\n");
        *SERIAL.lock() = Some(serial);
    }
    // If no serial port detected, SERIAL remains None and all output is silently dropped
}

/// Write a string to the serial port
pub fn write_str(s: &str) {
    if let Some(ref mut serial) = *SERIAL.lock() {
        let _ = serial.write_str(s);
    }
}

/// Write formatted output to the serial port
pub fn write_fmt(args: fmt::Arguments) {
    if let Some(ref mut serial) = *SERIAL.lock() {
        let _ = serial.write_fmt(args);
    }
}

/// Write a single byte to the serial port
pub fn write_byte(byte: u8) {
    if let Some(ref mut serial) = *SERIAL.lock() {
        serial.write_byte(byte);
    }
}

/// Check if there is input available on the serial port
pub fn has_input() -> bool {
    if let Some(ref serial) = *SERIAL.lock() {
        serial.can_receive()
    } else {
        false
    }
}

/// Try to read a byte from the serial port (non-blocking)
pub fn try_read() -> Option<u8> {
    if let Some(ref mut serial) = *SERIAL.lock() {
        serial.try_read_byte()
    } else {
        None
    }
}

/// Macro for printing to serial
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::drivers::serial::write_fmt(format_args!($($arg)*))
    };
}

/// Macro for printing to serial with newline
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}
