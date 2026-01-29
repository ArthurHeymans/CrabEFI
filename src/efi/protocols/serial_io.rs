//! EFI Serial IO Protocol
//!
//! This protocol provides access to serial port devices. It wraps our
//! 16550 UART serial driver to provide UEFI-compatible serial access.
//!
//! Reference: UEFI Specification 2.10, Section 12.8

use core::ffi::c_void;

use r_efi::efi::{Guid, Status};

use crate::drivers::serial::{self, COM1};
use crate::efi::allocator::{MemoryType, allocate_pool};

/// Serial IO Protocol GUID
/// {BB25CF6F-F1D4-11D2-9A0C-0090273FC1FD}
pub const SERIAL_IO_PROTOCOL_GUID: Guid = Guid::from_fields(
    0xBB25CF6F,
    0xF1D4,
    0x11D2,
    0x9A,
    0x0C,
    &[0x00, 0x90, 0x27, 0x3F, 0xC1, 0xFD],
);

/// Protocol revision
pub const EFI_SERIAL_IO_PROTOCOL_REVISION: u32 = 0x00010000;
pub const EFI_SERIAL_IO_PROTOCOL_REVISION1P1: u32 = 0x00010001;

/// Control bit masks (read-only)
pub const EFI_SERIAL_CLEAR_TO_SEND: u32 = 0x00000010;
pub const EFI_SERIAL_DATA_SET_READY: u32 = 0x00000020;
pub const EFI_SERIAL_RING_INDICATE: u32 = 0x00000040;
pub const EFI_SERIAL_CARRIER_DETECT: u32 = 0x00000080;
pub const EFI_SERIAL_INPUT_BUFFER_EMPTY: u32 = 0x00000100;
pub const EFI_SERIAL_OUTPUT_BUFFER_EMPTY: u32 = 0x00000200;

/// Control bit masks (write-only)
pub const EFI_SERIAL_REQUEST_TO_SEND: u32 = 0x00000002;
pub const EFI_SERIAL_DATA_TERMINAL_READY: u32 = 0x00000001;

/// Control bit masks (read-write)
pub const EFI_SERIAL_HARDWARE_LOOPBACK_ENABLE: u32 = 0x00001000;
pub const EFI_SERIAL_SOFTWARE_LOOPBACK_ENABLE: u32 = 0x00002000;
pub const EFI_SERIAL_HARDWARE_FLOW_CONTROL_ENABLE: u32 = 0x00004000;

/// Parity types
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ParityType {
    DefaultParity = 0,
    NoParity = 1,
    EvenParity = 2,
    OddParity = 3,
    MarkParity = 4,
    SpaceParity = 5,
}

/// Stop bits types
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StopBitsType {
    DefaultStopBits = 0,
    OneStopBit = 1,
    OneFiveStopBits = 2,
    TwoStopBits = 3,
}

/// Serial IO Mode structure - contains current settings
#[repr(C)]
pub struct SerialIoMode {
    pub control_mask: u32,
    pub timeout: u32,
    pub baud_rate: u64,
    pub receive_fifo_depth: u32,
    pub data_bits: u32,
    pub parity: u32,
    pub stop_bits: u32,
}

/// EFI Serial IO Protocol structure
#[repr(C)]
pub struct Protocol {
    pub revision: u32,
    pub reset: extern "efiapi" fn(this: *mut Protocol) -> Status,
    pub set_attributes: extern "efiapi" fn(
        this: *mut Protocol,
        baud_rate: u64,
        receive_fifo_depth: u32,
        timeout: u32,
        parity: ParityType,
        data_bits: u8,
        stop_bits: StopBitsType,
    ) -> Status,
    pub set_control: extern "efiapi" fn(this: *mut Protocol, control: u32) -> Status,
    pub get_control: extern "efiapi" fn(this: *mut Protocol, control: *mut u32) -> Status,
    pub write: extern "efiapi" fn(
        this: *mut Protocol,
        buffer_size: *mut usize,
        buffer: *const c_void,
    ) -> Status,
    pub read: extern "efiapi" fn(
        this: *mut Protocol,
        buffer_size: *mut usize,
        buffer: *mut c_void,
    ) -> Status,
    pub mode: *mut SerialIoMode,
    pub device_type_guid: *const Guid, // Revision 1.1
}

/// Reset the serial device
extern "efiapi" fn serial_reset(_this: *mut Protocol) -> Status {
    log::debug!("SerialIO.Reset()");

    // Re-initialize the serial port
    // Our serial driver is already initialized, just return success
    log::debug!("  -> SUCCESS");
    Status::SUCCESS
}

/// Set serial port attributes
extern "efiapi" fn serial_set_attributes(
    this: *mut Protocol,
    baud_rate: u64,
    receive_fifo_depth: u32,
    timeout: u32,
    parity: ParityType,
    data_bits: u8,
    stop_bits: StopBitsType,
) -> Status {
    log::debug!(
        "SerialIO.SetAttributes(baud={}, fifo={}, timeout={}, parity={:?}, data={}, stop={:?})",
        baud_rate,
        receive_fifo_depth,
        timeout,
        parity,
        data_bits,
        stop_bits
    );

    // For now, we only support 115200 8N1
    // A full implementation would reconfigure the UART here

    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Update mode structure with requested values (or defaults)
    unsafe {
        let mode = (*this).mode;
        if !mode.is_null() {
            (*mode).baud_rate = if baud_rate == 0 { 115200 } else { baud_rate };
            (*mode).receive_fifo_depth = if receive_fifo_depth == 0 {
                16
            } else {
                receive_fifo_depth
            };
            (*mode).timeout = timeout;
            (*mode).parity = if parity == ParityType::DefaultParity {
                ParityType::NoParity as u32
            } else {
                parity as u32
            };
            (*mode).data_bits = if data_bits == 0 { 8 } else { data_bits as u32 };
            (*mode).stop_bits = if stop_bits == StopBitsType::DefaultStopBits {
                StopBitsType::OneStopBit as u32
            } else {
                stop_bits as u32
            };
        }
    }

    log::debug!("  -> SUCCESS");
    Status::SUCCESS
}

/// Set control bits
extern "efiapi" fn serial_set_control(_this: *mut Protocol, control: u32) -> Status {
    log::debug!("SerialIO.SetControl(control={:#x})", control);

    // We don't implement hardware flow control, but accept the call
    log::debug!("  -> SUCCESS (ignored)");
    Status::SUCCESS
}

/// Get control bits
extern "efiapi" fn serial_get_control(_this: *mut Protocol, control: *mut u32) -> Status {
    log::debug!("SerialIO.GetControl()");

    if control.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Return status bits
    // We always report CTS, DSR active and buffers ready
    let mut bits: u32 = 0;

    // Check if we can send (output buffer empty)
    bits |= EFI_SERIAL_OUTPUT_BUFFER_EMPTY;

    // Check if there's no data waiting (input buffer empty)
    bits |= EFI_SERIAL_INPUT_BUFFER_EMPTY;

    // Pretend modem signals are active
    bits |= EFI_SERIAL_CLEAR_TO_SEND;
    bits |= EFI_SERIAL_DATA_SET_READY;
    bits |= EFI_SERIAL_CARRIER_DETECT;

    unsafe {
        *control = bits;
    }

    log::debug!("  -> SUCCESS (control={:#x})", bits);
    Status::SUCCESS
}

/// Write data to serial port
extern "efiapi" fn serial_write(
    _this: *mut Protocol,
    buffer_size: *mut usize,
    buffer: *const c_void,
) -> Status {
    if buffer_size.is_null() || buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let size = unsafe { *buffer_size };
    if size == 0 {
        return Status::SUCCESS;
    }

    log::debug!("SerialIO.Write(size={})", size);

    let data = unsafe { core::slice::from_raw_parts(buffer as *const u8, size) };

    // Write each byte to the serial port
    for &byte in data {
        serial::write_byte(byte);
    }

    // All bytes written
    log::debug!("  -> SUCCESS (wrote {} bytes)", size);
    Status::SUCCESS
}

/// Read data from serial port
extern "efiapi" fn serial_read(
    _this: *mut Protocol,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    if buffer_size.is_null() || buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let requested_size = unsafe { *buffer_size };
    if requested_size == 0 {
        return Status::SUCCESS;
    }

    log::debug!("SerialIO.Read(size={})", requested_size);

    // For now, we don't implement reading from serial
    // A full implementation would check for available data and read it
    // Return 0 bytes read (no data available)
    unsafe {
        *buffer_size = 0;
    }

    log::debug!("  -> SUCCESS (read 0 bytes, no data available)");
    Status::SUCCESS
}

/// Static mode structure for the serial port
static mut SERIAL_MODE: SerialIoMode = SerialIoMode {
    control_mask: EFI_SERIAL_CLEAR_TO_SEND
        | EFI_SERIAL_DATA_SET_READY
        | EFI_SERIAL_RING_INDICATE
        | EFI_SERIAL_CARRIER_DETECT
        | EFI_SERIAL_INPUT_BUFFER_EMPTY
        | EFI_SERIAL_OUTPUT_BUFFER_EMPTY
        | EFI_SERIAL_REQUEST_TO_SEND
        | EFI_SERIAL_DATA_TERMINAL_READY,
    timeout: 1000000, // 1 second in microseconds
    baud_rate: 115200,
    receive_fifo_depth: 16,
    data_bits: 8,
    parity: 1,    // NoParity
    stop_bits: 1, // OneStopBit
};

/// Create and initialize the Serial IO Protocol
///
/// # Returns
/// A pointer to the protocol instance, or null on allocation failure
pub fn create_protocol() -> *mut Protocol {
    let size = core::mem::size_of::<Protocol>();

    let ptr = match allocate_pool(MemoryType::BootServicesData, size) {
        Ok(p) => p as *mut Protocol,
        Err(_) => {
            log::error!("Failed to allocate SerialIoProtocol");
            return core::ptr::null_mut();
        }
    };

    unsafe {
        (*ptr).revision = EFI_SERIAL_IO_PROTOCOL_REVISION1P1;
        (*ptr).reset = serial_reset;
        (*ptr).set_attributes = serial_set_attributes;
        (*ptr).set_control = serial_set_control;
        (*ptr).get_control = serial_get_control;
        (*ptr).write = serial_write;
        (*ptr).read = serial_read;
        (*ptr).mode = &raw mut SERIAL_MODE;
        (*ptr).device_type_guid = core::ptr::null(); // No specific device type
    }

    log::info!("SerialIoProtocol created (COM1 @ {:#x})", COM1);
    ptr
}
