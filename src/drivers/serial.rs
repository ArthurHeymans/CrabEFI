//! Serial port driver
//!
//! Supports two backends:
//! - **x86 port I/O**: 16550 UART at traditional I/O port addresses (COM1 etc.)
//! - **MMIO**: 16550-compatible or PL011 UART via memory-mapped registers
//!
//! The backend is selected at runtime based on coreboot's serial info.
//! On aarch64 platforms (e.g., QEMU SBSA with PL011), only MMIO is available.

use core::fmt::{self, Write};

use spin::Mutex;

// ============================================================================
// Register offsets (16550-compatible)
// ============================================================================

mod offsets {
    pub const DATA: usize = 0; // Data register (read/write), also DLL when DLAB=1
    pub const IER: usize = 1; // Interrupt Enable Register, also DLH when DLAB=1
    pub const FCR: usize = 2; // FIFO Control Register (write)
    pub const LCR: usize = 3; // Line Control Register
    pub const MCR: usize = 4; // Modem Control Register
    pub const LSR: usize = 5; // Line Status Register
    pub const SCRATCH: usize = 7; // Scratch register
}

/// LSR bit: Transmitter Holding Register Empty
const LSR_TX_EMPTY: u8 = 0x20;
/// LSR bit: Data Ready
const LSR_DATA_READY: u8 = 0x01;
/// LCR bit: DLAB (Divisor Latch Access Bit)
const LCR_DLAB: u8 = 0x80;

/// Global serial port instance
static SERIAL: Mutex<Option<SerialPort>> = Mutex::new(None);

/// Maximum iterations to wait for TX ready (prevents infinite loop on missing hardware)
const TX_TIMEOUT_ITERATIONS: u32 = 100_000;

// ============================================================================
// Register access abstraction
// ============================================================================

/// Backend for accessing serial port registers
#[derive(Clone, Copy)]
enum SerialBackend {
    /// x86 I/O port-based access (16550 UART at I/O port address)
    #[cfg(target_arch = "x86_64")]
    PortIo { base: u16 },
    /// Memory-mapped register access (16550 or PL011)
    Mmio { base: u64 },
}

impl SerialBackend {
    /// Read an 8-bit register
    #[inline]
    fn read(&self, offset: usize) -> u8 {
        match self {
            #[cfg(target_arch = "x86_64")]
            SerialBackend::PortIo { base } => unsafe {
                crate::arch::x86_64::io::inb(*base + offset as u16)
            },
            SerialBackend::Mmio { base } => unsafe {
                let addr = (*base + offset as u64) as *const u8;
                core::ptr::read_volatile(addr)
            },
        }
    }

    /// Write an 8-bit register
    #[inline]
    fn write(&self, offset: usize, value: u8) {
        match self {
            #[cfg(target_arch = "x86_64")]
            SerialBackend::PortIo { base } => unsafe {
                crate::arch::x86_64::io::outb(*base + offset as u16, value);
            },
            SerialBackend::Mmio { base } => unsafe {
                let addr = (*base + offset as u64) as *mut u8;
                core::ptr::write_volatile(addr, value);
            },
        }
    }
}

// ============================================================================
// Serial Port Driver
// ============================================================================

/// A serial port (16550 or PL011 compatible)
pub struct SerialPort {
    /// Register access backend
    backend: SerialBackend,
    /// Whether this port has been detected as functional
    functional: bool,
}

impl SerialPort {
    /// Check if a serial port exists at this address
    ///
    /// Uses the scratch register test for 16550: write a value, read it back.
    fn detect(&self) -> bool {
        // Try writing and reading back a test pattern
        self.backend.write(offsets::SCRATCH, 0x55);
        if self.backend.read(offsets::SCRATCH) != 0x55 {
            return false;
        }

        self.backend.write(offsets::SCRATCH, 0xAA);
        if self.backend.read(offsets::SCRATCH) != 0xAA {
            return false;
        }

        // Also check that LSR doesn't return 0xFF (unpopulated port)
        if self.backend.read(offsets::LSR) == 0xFF {
            return false;
        }

        true
    }

    /// Initialize the serial port with the given baud rate (16550 mode)
    ///
    /// Returns true if initialization succeeded, false if no serial port detected.
    pub fn init_16550(&mut self, baud: u32) -> bool {
        // First check if a serial port exists
        if !self.detect() {
            self.functional = false;
            return false;
        }

        if baud == 0 {
            self.functional = false;
            return false;
        }
        let divisor = 115200 / baud;

        // Disable interrupts
        self.backend.write(offsets::IER, 0x00);

        // Enable DLAB to set baud rate divisor
        self.backend.write(offsets::LCR, LCR_DLAB);

        // Set divisor
        self.backend.write(offsets::DATA, (divisor & 0xFF) as u8);
        self.backend
            .write(offsets::IER, ((divisor >> 8) & 0xFF) as u8);

        // 8 bits, no parity, one stop bit (clear DLAB at the same time)
        self.backend.write(offsets::LCR, 0x03);

        // Enable FIFO, clear them, with 14-byte threshold
        self.backend.write(offsets::FCR, 0xC7);

        // IRQs enabled, RTS/DSR set
        self.backend.write(offsets::MCR, 0x0B);

        self.functional = true;
        true
    }

    /// Initialize as a PL011 UART (already configured by firmware/TF-A)
    ///
    /// On SBSA platforms, the PL011 UART is already initialized by TF-A.
    /// We just need to verify it's there and start using it.
    pub fn init_pl011(&mut self) -> bool {
        // PL011 doesn't have a scratch register, so we can't do the 16550
        // detection. Instead, just check the UART Flag Register (UARTFR at
        // offset 0x18) for a sane value.
        // For simplicity and because TF-A already set it up, just mark as functional.
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
        while self.backend.read(offsets::LSR) & LSR_TX_EMPTY == 0 {
            timeout -= 1;
            if timeout == 0 {
                self.functional = false;
                return;
            }
            core::hint::spin_loop();
        }

        self.backend.write(offsets::DATA, byte);
    }

    /// Try to read a byte from the serial port (non-blocking)
    pub fn try_read_byte(&mut self) -> Option<u8> {
        if self.backend.read(offsets::LSR) & LSR_DATA_READY != 0 {
            Some(self.backend.read(offsets::DATA))
        } else {
            None
        }
    }

    /// Check if the serial port is ready to receive data
    pub fn can_receive(&self) -> bool {
        self.functional && self.backend.read(offsets::LSR) & LSR_DATA_READY != 0
    }

    /// Check if the serial port is ready to send data
    pub fn can_send(&self) -> bool {
        self.functional && self.backend.read(offsets::LSR) & LSR_TX_EMPTY != 0
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
// PL011 UART support (aarch64)
// ============================================================================

/// PL011 UART register offsets
mod pl011 {
    pub const UARTDR: usize = 0x000; // Data Register
    pub const UARTFR: usize = 0x018; // Flag Register
                                     // Flag register bits
    pub const FR_TXFF: u16 = 1 << 5; // Transmit FIFO Full
    pub const FR_RXFE: u16 = 1 << 4; // Receive FIFO Empty
}

/// PL011 serial port backend
///
/// Separate from the 16550 backend because register layout differs significantly.
struct Pl011Port {
    base: u64,
    functional: bool,
}

impl Pl011Port {
    fn new(base: u64) -> Self {
        Self {
            base,
            functional: true, // TF-A already initialized it
        }
    }

    #[inline]
    fn read16(&self, offset: usize) -> u16 {
        unsafe {
            let addr = (self.base + offset as u64) as *const u16;
            core::ptr::read_volatile(addr)
        }
    }

    #[inline]
    fn write32(&self, offset: usize, value: u32) {
        unsafe {
            let addr = (self.base + offset as u64) as *mut u32;
            core::ptr::write_volatile(addr, value);
        }
    }

    fn write_byte(&mut self, byte: u8) {
        if !self.functional {
            return;
        }
        // Wait for TX FIFO not full
        let mut timeout = TX_TIMEOUT_ITERATIONS;
        while self.read16(pl011::UARTFR) & pl011::FR_TXFF != 0 {
            timeout -= 1;
            if timeout == 0 {
                self.functional = false;
                return;
            }
            core::hint::spin_loop();
        }
        self.write32(pl011::UARTDR, byte as u32);
    }

    fn try_read_byte(&mut self) -> Option<u8> {
        if self.read16(pl011::UARTFR) & pl011::FR_RXFE == 0 {
            Some(unsafe {
                let addr = (self.base + pl011::UARTDR as u64) as *const u32;
                core::ptr::read_volatile(addr) as u8
            })
        } else {
            None
        }
    }

    fn can_receive(&self) -> bool {
        self.functional && self.read16(pl011::UARTFR) & pl011::FR_RXFE == 0
    }

    fn can_send(&self) -> bool {
        self.functional && self.read16(pl011::UARTFR) & pl011::FR_TXFF == 0
    }
}

impl Write for Pl011Port {
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
// Unified serial port wrapper
// ============================================================================

/// Runtime-selected serial port type
enum AnySerial {
    Uart16550(SerialPort),
    Pl011(Pl011Port),
}

static ANY_SERIAL: Mutex<Option<AnySerial>> = Mutex::new(None);

// ============================================================================
// Global API
// ============================================================================

/// Standard COM1 port address (x86)
#[cfg(target_arch = "x86_64")]
pub const COM1: u16 = 0x3F8;

/// Initialize serial port from coreboot table information
///
/// # Arguments
/// * `base_addr` - I/O port or MMIO base address from coreboot serial info
/// * `baud` - Baud rate (typically 115200)
/// * `is_mmio` - Whether the address is MMIO (true) or I/O port (false)
pub fn init_from_coreboot(base_addr: u32, baud: u32, is_mmio: bool) {
    if is_mmio {
        // MMIO UART - could be 16550 or PL011
        // On aarch64 SBSA platforms, it's typically PL011
        #[cfg(target_arch = "aarch64")]
        {
            let mut port = Pl011Port::new(base_addr as u64);
            if port.functional {
                let _ = port.write_str("\r\n[CrabEFI] PL011 serial initialized from coreboot\r\n");
                *ANY_SERIAL.lock() = Some(AnySerial::Pl011(port));
                // Also set up the legacy SERIAL for code that uses it directly
                return;
            }
        }

        // Fall back to MMIO 16550
        let mut serial = SerialPort {
            backend: SerialBackend::Mmio {
                base: base_addr as u64,
            },
            functional: false,
        };
        if serial.init_16550(baud) {
            let _ = serial.write_str("\r\n[CrabEFI] MMIO serial initialized from coreboot\r\n");
            *ANY_SERIAL.lock() = Some(AnySerial::Uart16550(serial));
        }
    } else {
        // I/O port UART (x86 only)
        #[cfg(target_arch = "x86_64")]
        {
            let mut serial = SerialPort {
                backend: SerialBackend::PortIo {
                    base: base_addr as u16,
                },
                functional: false,
            };
            if serial.init_16550(baud) {
                let _ = serial.write_str("\r\n[CrabEFI] Serial initialized from coreboot\r\n");
                *ANY_SERIAL.lock() = Some(AnySerial::Uart16550(serial));
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            // I/O port serial not supported on non-x86
            let _ = (base_addr, baud);
        }
    }
}

/// Write a string to the serial port
pub fn write_str(s: &str) {
    if let Some(serial) = &mut *ANY_SERIAL.lock() {
        match serial {
            AnySerial::Uart16550(uart) => {
                let _ = uart.write_str(s);
            }
            AnySerial::Pl011(pl011) => {
                let _ = pl011.write_str(s);
            }
        }
    }
}

/// Write formatted output to the serial port
pub fn write_fmt(args: fmt::Arguments) {
    if let Some(serial) = &mut *ANY_SERIAL.lock() {
        match serial {
            AnySerial::Uart16550(uart) => {
                let _ = uart.write_fmt(args);
            }
            AnySerial::Pl011(pl011) => {
                let _ = pl011.write_fmt(args);
            }
        }
    }
}

/// Write a single byte to the serial port
pub fn write_byte(byte: u8) {
    if let Some(serial) = &mut *ANY_SERIAL.lock() {
        match serial {
            AnySerial::Uart16550(uart) => uart.write_byte(byte),
            AnySerial::Pl011(pl011) => pl011.write_byte(byte),
        }
    }
}

/// Check if there is input available on the serial port
pub fn has_input() -> bool {
    if let Some(serial) = &*ANY_SERIAL.lock() {
        match serial {
            AnySerial::Uart16550(uart) => uart.can_receive(),
            AnySerial::Pl011(pl011) => pl011.can_receive(),
        }
    } else {
        false
    }
}

/// Try to read a byte from the serial port (non-blocking)
pub fn try_read() -> Option<u8> {
    if let Some(serial) = &mut *ANY_SERIAL.lock() {
        match serial {
            AnySerial::Uart16550(uart) => uart.try_read_byte(),
            AnySerial::Pl011(pl011) => pl011.try_read_byte(),
        }
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
