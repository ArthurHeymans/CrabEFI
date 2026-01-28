//! 16550 UART serial port driver
//!
//! This module provides a simple driver for the 16550-compatible UART
//! typically found in PC-compatible systems.

use core::fmt::{self, Write};
use spin::Mutex;

/// Standard COM1 port address
pub const COM1: u16 = 0x3F8;

/// Standard COM2 port address
pub const COM2: u16 = 0x2F8;

/// Serial port register offsets
mod registers {
    pub const DATA: u16 = 0; // Data register (read/write)
    pub const IER: u16 = 1; // Interrupt Enable Register
    pub const FCR: u16 = 2; // FIFO Control Register
    pub const LCR: u16 = 3; // Line Control Register
    pub const MCR: u16 = 4; // Modem Control Register
    pub const LSR: u16 = 5; // Line Status Register
    pub const DLL: u16 = 0; // Divisor Latch Low (when DLAB=1)
    pub const DLH: u16 = 1; // Divisor Latch High (when DLAB=1)
}

/// Line Status Register bits
mod lsr {
    pub const DATA_READY: u8 = 1 << 0;
    pub const OVERRUN_ERROR: u8 = 1 << 1;
    pub const PARITY_ERROR: u8 = 1 << 2;
    pub const FRAMING_ERROR: u8 = 1 << 3;
    pub const BREAK_INDICATOR: u8 = 1 << 4;
    pub const TX_EMPTY: u8 = 1 << 5;
    pub const TX_IDLE: u8 = 1 << 6;
    pub const FIFO_ERROR: u8 = 1 << 7;
}

/// Line Control Register bits
mod lcr {
    pub const WORD_LENGTH_8: u8 = 0x03;
    pub const STOP_BIT_1: u8 = 0x00;
    pub const NO_PARITY: u8 = 0x00;
    pub const DLAB: u8 = 0x80;
}

/// Global serial port instance
static SERIAL: Mutex<Option<SerialPort>> = Mutex::new(None);

/// A 16550 UART serial port
pub struct SerialPort {
    /// Base I/O port address
    base: u16,
}

impl SerialPort {
    /// Create a new serial port at the given base address
    ///
    /// # Safety
    ///
    /// The base address must be a valid I/O port for a 16550 UART.
    pub const unsafe fn new(base: u16) -> Self {
        SerialPort { base }
    }

    /// Initialize the serial port with the given baud rate
    pub fn init(&mut self, baud: u32) {
        let divisor = 115200 / baud;

        unsafe {
            // Disable interrupts
            self.write_reg(registers::IER, 0x00);

            // Enable DLAB to set baud rate divisor
            self.write_reg(registers::LCR, lcr::DLAB);

            // Set divisor
            self.write_reg(registers::DLL, (divisor & 0xFF) as u8);
            self.write_reg(registers::DLH, ((divisor >> 8) & 0xFF) as u8);

            // 8 bits, no parity, one stop bit
            self.write_reg(
                registers::LCR,
                lcr::WORD_LENGTH_8 | lcr::STOP_BIT_1 | lcr::NO_PARITY,
            );

            // Enable FIFO, clear them, with 14-byte threshold
            self.write_reg(registers::FCR, 0xC7);

            // IRQs enabled, RTS/DSR set
            self.write_reg(registers::MCR, 0x0B);
        }
    }

    /// Write a byte to the serial port
    pub fn write_byte(&mut self, byte: u8) {
        unsafe {
            // Wait for transmit buffer to be empty
            while (self.read_reg(registers::LSR) & lsr::TX_EMPTY) == 0 {
                core::hint::spin_loop();
            }

            self.write_reg(registers::DATA, byte);
        }
    }

    /// Read a byte from the serial port (blocking)
    pub fn read_byte(&mut self) -> u8 {
        unsafe {
            // Wait for data to be available
            while (self.read_reg(registers::LSR) & lsr::DATA_READY) == 0 {
                core::hint::spin_loop();
            }

            self.read_reg(registers::DATA)
        }
    }

    /// Try to read a byte from the serial port (non-blocking)
    pub fn try_read_byte(&mut self) -> Option<u8> {
        unsafe {
            if (self.read_reg(registers::LSR) & lsr::DATA_READY) != 0 {
                Some(self.read_reg(registers::DATA))
            } else {
                None
            }
        }
    }

    /// Check if the serial port is ready to receive data
    pub fn can_receive(&self) -> bool {
        unsafe { (self.read_reg(registers::LSR) & lsr::DATA_READY) != 0 }
    }

    /// Check if the serial port is ready to send data
    pub fn can_send(&self) -> bool {
        unsafe { (self.read_reg(registers::LSR) & lsr::TX_EMPTY) != 0 }
    }

    /// Read a register
    unsafe fn read_reg(&self, offset: u16) -> u8 {
        let port = self.base + offset;
        let value: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nostack, preserves_flags)
        );
        value
    }

    /// Write a register
    unsafe fn write_reg(&self, offset: u16, value: u8) {
        let port = self.base + offset;
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nostack, preserves_flags)
        );
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

/// Initialize the global serial port for early debug output
pub fn init_early() {
    let mut serial = unsafe { SerialPort::new(COM1) };
    serial.init(115200);

    // Test the serial port
    let _ = serial.write_str("\r\n");

    *SERIAL.lock() = Some(serial);
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
