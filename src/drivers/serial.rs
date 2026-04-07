//! Serial port driver
//!
//! Supports two backends:
//! - **x86 port I/O**: 16550 UART at traditional I/O port addresses (COM1 etc.)
//! - **MMIO**: 16550-compatible or PL011 UART via memory-mapped registers
//!
//! The backend is selected at runtime based on coreboot's serial info.
//! On aarch64 platforms (e.g., QEMU SBSA with PL011), only MMIO is available.
//! On AMD systems the UART is memory-mapped with a 4-byte register stride
//! (`regwidth = 4` in the coreboot serial table).

use core::fmt::{self, Write};

use tock_registers::interfaces::{Readable, Writeable};

#[cfg(target_arch = "aarch64")]
use super::serial_regs::pl011::{self, FR};
#[cfg(target_arch = "x86_64")]
use super::serial_regs::uart16550::{self, FCR, LCR, MCR, Uart16550Regs};

/// Maximum iterations to wait for TX ready (prevents infinite loop on missing hardware)
const TX_TIMEOUT_ITERATIONS: u32 = 100_000;

// ============================================================================
// 16550 UART Backend (x86 port I/O + MMIO fallback)
// ============================================================================

/// Backend for accessing 16550 UART registers
#[derive(Clone, Copy)]
enum Uart16550Backend {
    /// x86 I/O port-based access
    #[cfg(target_arch = "x86_64")]
    PortIo { base: u16 },
    /// Memory-mapped register access (16550-compatible).
    ///
    /// `reg_stride` is the spacing between consecutive 8-bit registers in
    /// bytes, taken from coreboot's `regwidth` field.  Traditional 8250/16550
    /// devices use stride 1; many AMD SoC UARTs use stride 4 (each 8-bit
    /// register occupies a 32-bit slot and must be accessed with 32-bit
    /// reads/writes).
    Mmio { base: u64, reg_stride: u32 },
}

impl Uart16550Backend {
    /// Read an 8-bit UART register by index (0-7).
    ///
    /// For I/O ports, issues `inb(base + reg)`.
    /// For MMIO, reads at `base + reg * reg_stride` using the access width
    /// implied by the stride: 32-bit for stride >= 4, 16-bit for stride 2,
    /// 8-bit otherwise.
    #[inline]
    fn read(&self, reg: usize) -> u8 {
        match self {
            #[cfg(target_arch = "x86_64")]
            Uart16550Backend::PortIo { base } => unsafe {
                crate::arch::x86_64::io::inb(*base + reg as u16)
            },
            Uart16550Backend::Mmio { base, reg_stride } => unsafe {
                let addr = base + reg as u64 * *reg_stride as u64;
                if *reg_stride >= 4 {
                    (core::ptr::read_volatile(addr as *const u32) & 0xFF) as u8
                } else if *reg_stride == 2 {
                    (core::ptr::read_volatile(addr as *const u16) & 0xFF) as u8
                } else {
                    core::ptr::read_volatile(addr as *const u8)
                }
            },
        }
    }

    /// Write an 8-bit UART register by index (0-7).
    ///
    /// For I/O ports, issues `outb(base + reg, value)`.
    /// For MMIO, writes at `base + reg * reg_stride` using the appropriate
    /// access width (32-bit for stride >= 4, 16-bit for stride 2, 8-bit
    /// otherwise).
    #[inline]
    fn write(&self, reg: usize, value: u8) {
        match self {
            #[cfg(target_arch = "x86_64")]
            Uart16550Backend::PortIo { base } => unsafe {
                crate::arch::x86_64::io::outb(*base + reg as u16, value);
            },
            Uart16550Backend::Mmio { base, reg_stride } => unsafe {
                let addr = base + reg as u64 * *reg_stride as u64;
                if *reg_stride >= 4 {
                    core::ptr::write_volatile(addr as *mut u32, value as u32);
                } else if *reg_stride == 2 {
                    core::ptr::write_volatile(addr as *mut u16, value as u16);
                } else {
                    core::ptr::write_volatile(addr as *mut u8, value);
                }
            },
        }
    }
}

// Register offsets for the MMIO fallback path (no tock-registers for MMIO 16550)
mod offsets {
    pub const DATA: usize = 0;
    pub const IER: usize = 1;
    pub const FCR: usize = 2;
    pub const LCR: usize = 3;
    pub const MCR: usize = 4;
    pub const LSR: usize = 5;
    pub const SCRATCH: usize = 7;
}

/// LSR bit: Transmitter Holding Register Empty (MMIO fallback)
const LSR_TX_EMPTY: u8 = 0x20;
/// LSR bit: Data Ready (MMIO fallback)
const LSR_DATA_READY: u8 = 0x01;
/// LCR bit: DLAB (MMIO fallback)
const LCR_DLAB: u8 = 0x80;

/// A 16550-compatible serial port
pub struct SerialPort {
    backend: Uart16550Backend,
    /// Whether this port has been detected as functional
    functional: bool,
}

impl SerialPort {
    /// Check if a serial port exists at this address
    ///
    /// Uses the scratch register test: write a value, read it back.
    fn detect(&self) -> bool {
        match self.backend {
            #[cfg(target_arch = "x86_64")]
            Uart16550Backend::PortIo { base } => {
                let regs = Uart16550Regs::new(base);
                // Write and read back test patterns via scratch register
                regs.scratch().set(0x55);
                if regs.scratch().get() != 0x55 {
                    return false;
                }
                regs.scratch().set(0xAA);
                if regs.scratch().get() != 0xAA {
                    return false;
                }
                // Check that LSR doesn't return 0xFF (unpopulated port)
                regs.lsr().get() != 0xFF
            }
            Uart16550Backend::Mmio { .. } => {
                // MMIO fallback: raw offset access
                self.backend.write(offsets::SCRATCH, 0x55);
                if self.backend.read(offsets::SCRATCH) != 0x55 {
                    return false;
                }
                self.backend.write(offsets::SCRATCH, 0xAA);
                if self.backend.read(offsets::SCRATCH) != 0xAA {
                    return false;
                }
                self.backend.read(offsets::LSR) != 0xFF
            }
        }
    }

    /// Initialize the serial port with the given baud rate (16550 mode)
    ///
    /// # Arguments
    /// * `baud` - Baud rate (e.g. 115200)
    /// * `input_hertz` - UART input clock frequency.  When non-zero the divisor
    ///   is computed as `input_hertz / (16 * baud)` (handles non-standard
    ///   clocks such as the 48 MHz oscillator on many AMD SoCs).  When zero the
    ///   legacy formula `115200 / baud` is used (assumes the standard 1.8432 MHz
    ///   crystal where 1 843 200 / 16 = 115 200).
    ///
    /// Returns true if initialization succeeded, false if no serial port detected.
    pub fn init_16550(&mut self, baud: u32, input_hertz: u32) -> bool {
        if !self.detect() {
            self.functional = false;
            return false;
        }
        if baud == 0 {
            self.functional = false;
            return false;
        }
        // Calculate baud rate divisor.
        let divisor = if input_hertz > 0 {
            // General formula: clock / (16 * baud).
            // Ensures at least 1 to avoid a divide-by-zero or zero divisor.
            (input_hertz / (16 * baud)).max(1)
        } else {
            // Legacy formula for the standard 1.8432 MHz crystal.
            115200 / baud
        };

        match self.backend {
            #[cfg(target_arch = "x86_64")]
            Uart16550Backend::PortIo { base } => {
                let regs = Uart16550Regs::new(base);

                // Disable interrupts
                regs.ier().set(0);

                // Enable DLAB to set baud rate divisor
                regs.lcr().write(LCR::DLAB::SET);

                // Set divisor low/high bytes
                regs.data().set((divisor & 0xFF) as u8);
                regs.dlm().set(((divisor >> 8) & 0xFF) as u8);

                // 8 bits, no parity, one stop bit (clears DLAB)
                regs.lcr().write(LCR::WLS::Bits8);

                // Enable FIFO, clear them, 14-byte trigger level
                regs.iir_fcr().write(
                    FCR::FIFOE::SET
                        + FCR::RFIFOR::SET
                        + FCR::XFIFOR::SET
                        + FCR::RCVR_TRIGGER::Bytes14,
                );

                // DTR + RTS + OUT2 (enables IRQs)
                regs.mcr()
                    .write(MCR::DTR::SET + MCR::RTS::SET + MCR::OUT2::SET);
            }
            Uart16550Backend::Mmio { .. } => {
                // MMIO fallback: raw register writes
                self.backend.write(offsets::IER, 0x00);
                self.backend.write(offsets::LCR, LCR_DLAB);
                self.backend.write(offsets::DATA, (divisor & 0xFF) as u8);
                self.backend
                    .write(offsets::IER, ((divisor >> 8) & 0xFF) as u8);
                self.backend.write(offsets::LCR, 0x03);
                self.backend.write(offsets::FCR, 0xC7);
                self.backend.write(offsets::MCR, 0x0B);
            }
        }

        self.functional = true;
        true
    }

    /// Initialize as a PL011 UART (already configured by firmware/TF-A)
    ///
    /// On SBSA platforms, the PL011 UART is already initialized by TF-A.
    /// We just need to verify it's there and start using it.
    pub fn init_pl011(&mut self) -> bool {
        self.functional = true;
        true
    }

    /// Write a byte to the serial port
    pub fn write_byte(&mut self, byte: u8) {
        if !self.functional {
            return;
        }

        match self.backend {
            #[cfg(target_arch = "x86_64")]
            Uart16550Backend::PortIo { base } => {
                let regs = Uart16550Regs::new(base);
                // Wait for transmit buffer to be empty, with timeout
                let mut timeout = TX_TIMEOUT_ITERATIONS;
                while !regs.lsr().is_set(uart16550::LSR::THRE) {
                    timeout -= 1;
                    if timeout == 0 {
                        self.functional = false;
                        return;
                    }
                    core::hint::spin_loop();
                }
                regs.data().set(byte);
            }
            Uart16550Backend::Mmio { .. } => {
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
        }
    }

    /// Try to read a byte from the serial port (non-blocking)
    pub fn try_read_byte(&mut self) -> Option<u8> {
        match self.backend {
            #[cfg(target_arch = "x86_64")]
            Uart16550Backend::PortIo { base } => {
                let regs = Uart16550Regs::new(base);
                if regs.lsr().is_set(uart16550::LSR::DR) {
                    Some(regs.data().get())
                } else {
                    None
                }
            }
            Uart16550Backend::Mmio { .. } => {
                if self.backend.read(offsets::LSR) & LSR_DATA_READY != 0 {
                    Some(self.backend.read(offsets::DATA))
                } else {
                    None
                }
            }
        }
    }

    /// Check if the serial port is ready to receive data
    pub fn can_receive(&self) -> bool {
        if !self.functional {
            return false;
        }
        match self.backend {
            #[cfg(target_arch = "x86_64")]
            Uart16550Backend::PortIo { base } => {
                let regs = Uart16550Regs::new(base);
                regs.lsr().is_set(uart16550::LSR::DR)
            }
            Uart16550Backend::Mmio { .. } => self.backend.read(offsets::LSR) & LSR_DATA_READY != 0,
        }
    }

    /// Check if the serial port is ready to send data
    pub fn can_send(&self) -> bool {
        if !self.functional {
            return false;
        }
        match self.backend {
            #[cfg(target_arch = "x86_64")]
            Uart16550Backend::PortIo { base } => {
                let regs = Uart16550Regs::new(base);
                regs.lsr().is_set(uart16550::LSR::THRE)
            }
            Uart16550Backend::Mmio { .. } => self.backend.read(offsets::LSR) & LSR_TX_EMPTY != 0,
        }
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

#[cfg(target_arch = "aarch64")]
/// PL011 serial port backend using tock-registers MMIO struct
///
/// Separate from the 16550 backend because register layout differs significantly.
pub(crate) struct Pl011Port {
    regs: &'static pl011::Pl011Registers,
    functional: bool,
}

#[cfg(target_arch = "aarch64")]
impl Pl011Port {
    fn new(base: u64) -> Self {
        // Safety: The PL011 base address is provided by coreboot tables and
        // is valid MMIO for the UART's lifetime (the entire firmware run).
        let regs = unsafe { &*(base as *const pl011::Pl011Registers) };
        Self {
            regs,
            functional: true, // TF-A already initialized it
        }
    }

    fn write_byte(&mut self, byte: u8) {
        if !self.functional {
            return;
        }
        // Wait for TX FIFO not full
        let mut timeout = TX_TIMEOUT_ITERATIONS;
        while self.regs.fr.is_set(FR::TXFF) {
            timeout -= 1;
            if timeout == 0 {
                self.functional = false;
                return;
            }
            core::hint::spin_loop();
        }
        self.regs.dr.set(byte as u32);
    }

    fn try_read_byte(&mut self) -> Option<u8> {
        if !self.regs.fr.is_set(FR::RXFE) {
            Some(self.regs.dr.get() as u8)
        } else {
            None
        }
    }

    fn can_receive(&self) -> bool {
        self.functional && !self.regs.fr.is_set(FR::RXFE)
    }
}

#[cfg(target_arch = "aarch64")]
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
// Platform-provided serial backend (for init_platform() path)
// ============================================================================

/// Adapter that wraps a platform-provided `DebugOutput` trait object.
///
/// Stores a raw pointer because the serial subsystem is accessed via
/// `drivers_mut_ptr()` (raw pointers) throughout CrabEFI to avoid
/// aliasing with active `&mut FirmwareState` references in closures.
pub(crate) struct PlatformSerial {
    /// Raw pointer to the platform's debug output trait object.
    /// Valid for the entire firmware lifetime (caller guarantees this).
    inner: *mut dyn crate::platform::DebugOutput,
}

impl PlatformSerial {
    /// Write a single byte to the platform debug output.
    fn write_byte(&mut self, byte: u8) {
        // SAFETY: Single-threaded firmware. Pointer is valid for firmware lifetime.
        unsafe { &mut *self.inner }.write_byte(byte);
    }

    /// Try to read a byte (non-blocking).
    fn try_read_byte(&mut self) -> Option<u8> {
        // SAFETY: Single-threaded firmware.
        unsafe { &mut *self.inner }.try_read_byte()
    }

    /// Check if input is available.
    fn has_input(&self) -> bool {
        // SAFETY: Single-threaded firmware.
        unsafe { &*self.inner }.has_input()
    }
}

impl Write for PlatformSerial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // SAFETY: Single-threaded firmware.
        unsafe { &mut *self.inner }.write_str(s)
    }
}

// ============================================================================
// Unified serial port wrapper
// ============================================================================

/// Runtime-selected serial port type
pub(crate) enum AnySerial {
    Uart16550(SerialPort),
    #[cfg(target_arch = "aarch64")]
    Pl011(Pl011Port),
    /// Platform-provided debug output (used by `init_platform()` path).
    Platform(PlatformSerial),
}

// ============================================================================
// Global API
// ============================================================================

/// Standard COM1 port address (x86)
#[cfg(target_arch = "x86_64")]
pub const COM1: u16 = 0x3F8;

/// Initialize serial port from coreboot table information
///
/// Uses `serial_type` to choose I/O port vs MMIO access, `regwidth` for the
/// MMIO register stride, and `input_hertz` for an accurate baud divisor.
///
/// # Arguments
/// * `info` - Serial port configuration parsed from coreboot tables
pub fn init_from_coreboot(info: &crate::coreboot::tables::SerialInfo) {
    if info.mmio() {
        // MMIO UART - could be 16550 or PL011
        // On aarch64 SBSA platforms, it's typically PL011
        #[cfg(target_arch = "aarch64")]
        {
            let mut port = Pl011Port::new(info.baseaddr as u64);
            if port.functional {
                let _ = port.write_str("\r\n[CrabEFI] PL011 serial initialized from coreboot\r\n");
                // SAFETY: Single-threaded firmware; raw pointer avoids re-entrancy
                // issues since serial is called from log macros inside other state closures.
                unsafe {
                    (*crate::state::drivers_mut_ptr()).serial.driver = Some(AnySerial::Pl011(port));
                }
                return;
            }
        }

        // MMIO 16550 (or 16550-compatible).
        // `regwidth` from coreboot tells us how far apart registers are; default
        // to 1-byte stride when coreboot doesn't specify (regwidth == 0).
        let reg_stride = if info.regwidth > 0 { info.regwidth } else { 1 };
        let mut serial = SerialPort {
            backend: Uart16550Backend::Mmio {
                base: info.baseaddr as u64,
                reg_stride,
            },
            functional: false,
        };
        if serial.init_16550(info.baud, info.input_hertz) {
            let _ = serial.write_str("\r\n[CrabEFI] MMIO serial initialized from coreboot\r\n");
            // SAFETY: Single-threaded firmware; raw pointer avoids re-entrancy
            // issues since serial is called from log macros inside other state closures.
            unsafe {
                (*crate::state::drivers_mut_ptr()).serial.driver =
                    Some(AnySerial::Uart16550(serial));
            }
        }
    } else {
        // I/O port UART (x86 only)
        #[cfg(target_arch = "x86_64")]
        {
            let mut serial = SerialPort {
                backend: Uart16550Backend::PortIo {
                    base: info.baseaddr as u16,
                },
                functional: false,
            };
            if serial.init_16550(info.baud, info.input_hertz) {
                let _ = serial.write_str("\r\n[CrabEFI] Serial initialized from coreboot\r\n");
                // SAFETY: Single-threaded firmware; raw pointer avoids re-entrancy
                // issues since serial is called from log macros inside other state closures.
                unsafe {
                    (*crate::state::drivers_mut_ptr()).serial.driver =
                        Some(AnySerial::Uart16550(serial));
                }
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            // I/O port serial not supported on non-x86
            let _ = info;
        }
    }
}

/// Initialize serial output from a raw pointer to a platform `DebugOutput`.
///
/// Used by `init_platform()` to inject an external serial driver (e.g., from
/// fstart's PL011 or NS16550 driver) without going through coreboot tables.
///
/// # Safety
///
/// `raw` must point to a valid `DebugOutput` that lives for the entire
/// firmware lifetime (i.e., at least until `init_platform()` returns).
pub unsafe fn init_from_platform_raw(raw: *mut dyn crate::platform::DebugOutput) {
    let plat = PlatformSerial { inner: raw };
    // SAFETY: Single-threaded firmware; raw pointer avoids re-entrancy
    // issues since serial is called from log macros inside other state closures.
    unsafe {
        (*crate::state::drivers_mut_ptr()).serial.driver = Some(AnySerial::Platform(plat));
    }
}

/// Write a string to the serial port
pub fn write_str(s: &str) {
    // SAFETY: Single-threaded firmware; raw pointer avoids re-entrancy
    // issues since serial is called from log macros inside other state closures.
    let driver = unsafe { &mut (*crate::state::drivers_mut_ptr()).serial.driver };
    if let Some(serial) = driver {
        match serial {
            AnySerial::Uart16550(uart) => {
                let _ = uart.write_str(s);
            }
            #[cfg(target_arch = "aarch64")]
            AnySerial::Pl011(pl011) => {
                let _ = pl011.write_str(s);
            }
            AnySerial::Platform(plat) => {
                let _ = plat.write_str(s);
            }
        }
    }
}

/// Write formatted output to the serial port
pub fn write_fmt(args: fmt::Arguments) {
    // SAFETY: Single-threaded firmware; raw pointer avoids re-entrancy
    // issues since serial is called from log macros inside other state closures.
    let driver = unsafe { &mut (*crate::state::drivers_mut_ptr()).serial.driver };
    if let Some(serial) = driver {
        match serial {
            AnySerial::Uart16550(uart) => {
                let _ = uart.write_fmt(args);
            }
            #[cfg(target_arch = "aarch64")]
            AnySerial::Pl011(pl011) => {
                let _ = pl011.write_fmt(args);
            }
            AnySerial::Platform(plat) => {
                let _ = plat.write_fmt(args);
            }
        }
    }
}

/// Write a single byte to the serial port
pub fn write_byte(byte: u8) {
    // SAFETY: Single-threaded firmware; raw pointer avoids re-entrancy
    // issues since serial is called from log macros inside other state closures.
    let driver = unsafe { &mut (*crate::state::drivers_mut_ptr()).serial.driver };
    if let Some(serial) = driver {
        match serial {
            AnySerial::Uart16550(uart) => uart.write_byte(byte),
            #[cfg(target_arch = "aarch64")]
            AnySerial::Pl011(pl011) => pl011.write_byte(byte),
            AnySerial::Platform(plat) => plat.write_byte(byte),
        }
    }
}

/// Check if there is input available on the serial port
pub fn has_input() -> bool {
    // Read-only check -- use immutable access (no raw pointer needed).
    if let Some(serial) = &crate::state::drivers().serial.driver {
        match serial {
            AnySerial::Uart16550(uart) => uart.can_receive(),
            #[cfg(target_arch = "aarch64")]
            AnySerial::Pl011(pl011) => pl011.can_receive(),
            AnySerial::Platform(plat) => plat.has_input(),
        }
    } else {
        false
    }
}

/// Try to read a byte from the serial port (non-blocking)
pub fn try_read() -> Option<u8> {
    // SAFETY: Single-threaded firmware; raw pointer avoids re-entrancy
    // issues since serial is called from log macros inside other state closures.
    let driver = unsafe { &mut (*crate::state::drivers_mut_ptr()).serial.driver };
    if let Some(serial) = driver {
        match serial {
            AnySerial::Uart16550(uart) => uart.try_read_byte(),
            #[cfg(target_arch = "aarch64")]
            AnySerial::Pl011(pl011) => pl011.try_read_byte(),
            AnySerial::Platform(plat) => plat.try_read_byte(),
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
