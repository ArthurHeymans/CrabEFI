//! Storage Security Command Protocol test module
//!
//! Tests the EFI_STORAGE_SECURITY_COMMAND_PROTOCOL implementation.

use core::ffi::c_void;
use r_efi::efi::{Guid, Handle, Status};

use crate::{console, efi_helpers};

/// Storage Security Command Protocol GUID
/// {C88B0B6D-0DFC-49A7-9CB4-49074B4C3A78}
pub const STORAGE_SECURITY_COMMAND_GUID: Guid = Guid::from_fields(
    0xC88B0B6D,
    0x0DFC,
    0x49A7,
    0x9C,
    0xB4,
    &[0x49, 0x07, 0x4B, 0x4C, 0x3A, 0x78],
);

/// Storage Security Command Protocol structure
#[repr(C)]
pub struct StorageSecurityCommandProtocol {
    /// Receive data from security subsystem
    pub receive_data: extern "efiapi" fn(
        this: *mut StorageSecurityCommandProtocol,
        media_id: u32,
        timeout: u64,
        security_protocol_id: u8,
        security_protocol_specific: u16,
        payload_buffer_size: usize,
        payload_buffer: *mut c_void,
        payload_transfer_size: *mut usize,
    ) -> Status,

    /// Send data to security subsystem
    pub send_data: extern "efiapi" fn(
        this: *mut StorageSecurityCommandProtocol,
        media_id: u32,
        timeout: u64,
        security_protocol_id: u8,
        security_protocol_specific: u16,
        payload_buffer_size: usize,
        payload_buffer: *const c_void,
    ) -> Status,
}

/// Test Storage Security Command Protocol
pub fn test_storage_security_protocol() -> bool {
    // Find all handles with Storage Security Command Protocol
    let mut handles: [Handle; 16] = [core::ptr::null_mut(); 16];
    let count = efi_helpers::locate_handle_buffer(&STORAGE_SECURITY_COMMAND_GUID, &mut handles);

    if count == 0 {
        console().print_line("    No Storage Security devices found");
        return false;
    }

    console().print("    Found ");
    console().print_dec(count as u64);
    console().print_line(" device(s) with Storage Security support");

    let mut success = false;

    for i in 0..count {
        let handle = handles[i];
        if handle.is_null() {
            continue;
        }

        console().print("    Device ");
        console().print_dec(i as u64);
        console().print(": ");

        // Open the protocol
        let protocol: *mut StorageSecurityCommandProtocol =
            efi_helpers::open_protocol(handle, &STORAGE_SECURITY_COMMAND_GUID);

        if protocol.is_null() {
            console().print_line("Failed to open protocol");
            continue;
        }

        // Try to query supported security protocols (Security Protocol 0x00)
        let mut buffer: [u8; 512] = [0; 512];
        let mut transfer_size: usize = 0;

        let status = unsafe {
            ((*protocol).receive_data)(
                protocol,
                0,      // media_id - use 0 for test
                0,      // timeout - wait forever
                0x00,   // Security Protocol 0x00 - Supported Protocol List
                0x0000, // Security Protocol Specific
                buffer.len(),
                buffer.as_mut_ptr() as *mut c_void,
                &mut transfer_size,
            )
        };

        if status == Status::SUCCESS {
            console().print_line("OK");
            console().print("      Received ");
            console().print_dec(transfer_size as u64);
            console().print_line(" bytes from Security Protocol 0x00");

            // Parse supported protocols
            if transfer_size >= 8 {
                let list_length = u16::from_be_bytes([buffer[6], buffer[7]]) as usize;
                console().print("      Supported protocols: ");
                for j in 0..list_length.min((transfer_size - 8).min(16)) {
                    console().print_hex(buffer[8 + j] as u64);
                    console().print(" ");
                }
                console().print_line("");
            }
            success = true;
        } else {
            console().print("Error (status not SUCCESS)");
            console().print_line("");
        }

        efi_helpers::close_protocol(handle, &STORAGE_SECURITY_COMMAND_GUID);
    }

    success
}

/// Send a TCG Discovery0 command using Storage Security Protocol
pub fn send_discovery0(
    protocol: *mut StorageSecurityCommandProtocol,
    media_id: u32,
    buffer: &mut [u8],
) -> Result<usize, Status> {
    if protocol.is_null() || buffer.is_empty() {
        return Err(Status::INVALID_PARAMETER);
    }

    let mut transfer_size: usize = 0;

    let status = unsafe {
        ((*protocol).receive_data)(
            protocol,
            media_id,
            0,      // timeout - wait forever
            0x01,   // Security Protocol 0x01 - TCG
            0x0001, // ComID for Discovery
            buffer.len(),
            buffer.as_mut_ptr() as *mut c_void,
            &mut transfer_size,
        )
    };

    if status == Status::SUCCESS {
        Ok(transfer_size)
    } else {
        Err(status)
    }
}
