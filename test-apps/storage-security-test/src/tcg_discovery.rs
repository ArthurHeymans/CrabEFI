//! TCG Opal Discovery test module
//!
//! Tests TCG Discovery0 command to detect Opal-capable self-encrypting drives.

use core::ffi::c_void;
use r_efi::efi::{Handle, Status};

use crate::storage_security::{StorageSecurityCommandProtocol, STORAGE_SECURITY_COMMAND_GUID};
use crate::{console, efi_helpers};

/// TCG Feature Codes
const FEATURE_TPER: u16 = 0x0001;
const FEATURE_LOCKING: u16 = 0x0002;
const FEATURE_GEOMETRY: u16 = 0x0003;
const FEATURE_OPAL_SSC_V100: u16 = 0x0200;
const FEATURE_OPAL_SSC_V200: u16 = 0x0203;
const FEATURE_ENTERPRISE_SSC: u16 = 0x0100;
const FEATURE_PYRITE_V100: u16 = 0x0302;
const FEATURE_PYRITE_V200: u16 = 0x0303;

/// Test TCG Discovery0 on all Storage Security devices
pub fn test_tcg_discovery() -> bool {
    // Find all handles with Storage Security Command Protocol
    let mut handles: [Handle; 16] = [core::ptr::null_mut(); 16];
    let count = efi_helpers::locate_handle_buffer(&STORAGE_SECURITY_COMMAND_GUID, &mut handles);

    if count == 0 {
        console().print_line("    No Storage Security devices found");
        return false;
    }

    let mut found_opal = false;

    for i in 0..count {
        let handle = handles[i];
        if handle.is_null() {
            continue;
        }

        // Open the protocol
        let protocol: *mut StorageSecurityCommandProtocol =
            efi_helpers::open_protocol(handle, &STORAGE_SECURITY_COMMAND_GUID);

        if protocol.is_null() {
            continue;
        }

        // Send Discovery0 command
        let mut buffer: [u8; 2048] = [0; 2048];
        let mut transfer_size: usize = 0;

        let status = unsafe {
            ((*protocol).receive_data)(
                protocol,
                0,      // media_id - use 0 for test
                0,      // timeout - wait forever
                0x01,   // Security Protocol 0x01 - TCG
                0x0001, // ComID for Discovery (0x0001)
                buffer.len(),
                buffer.as_mut_ptr() as *mut c_void,
                &mut transfer_size,
            )
        };

        if status == Status::SUCCESS && transfer_size >= 48 {
            console().print("    Device ");
            console().print_dec(i as u64);
            console().print_line(":");

            // Parse Discovery0 response
            found_opal |= parse_discovery0(&buffer[..transfer_size]);
        }

        efi_helpers::close_protocol(handle, &STORAGE_SECURITY_COMMAND_GUID);
    }

    found_opal
}

/// Parse and display Discovery0 response
fn parse_discovery0(data: &[u8]) -> bool {
    if data.len() < 48 {
        console().print_line("      Discovery0 response too small");
        return false;
    }

    // Discovery0 header (48 bytes)
    // Bytes 0-3: Length of parameter data (big-endian)
    // Bytes 4-7: Data structure revision
    // Bytes 8-9: Reserved
    // Bytes 10-11: Comms Features (0x0000 for sync comms)
    // Bytes 12-47: Reserved

    let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let revision = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    console().print("      TCG Discovery: length=");
    console().print_dec(length as u64);
    console().print(", revision=");
    console().print_dec(revision as u64);
    console().print_line("");

    // Parse feature descriptors starting at byte 48
    let mut offset = 48;
    let mut found_opal = false;

    while offset + 4 <= data.len() && offset + 4 <= length + 4 {
        // Feature descriptor header
        // Bytes 0-1: Feature code (big-endian)
        // Byte 2: Version & Reserved
        // Byte 3: Length of feature descriptor data

        let feature_code = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let _version = data[offset + 2];
        let desc_len = data[offset + 3] as usize;

        console().print("      Feature ");
        console().print_hex(feature_code as u64);
        console().print(": ");

        match feature_code {
            FEATURE_TPER => {
                console().print_line("TPer");
                if desc_len >= 4 && offset + 4 + 4 <= data.len() {
                    let flags = data[offset + 4];
                    if flags & 0x01 != 0 {
                        console().print("        Sync ");
                    }
                    if flags & 0x02 != 0 {
                        console().print("Async ");
                    }
                    if flags & 0x04 != 0 {
                        console().print("AckNak ");
                    }
                    if flags & 0x08 != 0 {
                        console().print("BufferMgmt ");
                    }
                    if flags & 0x10 != 0 {
                        console().print("Streaming ");
                    }
                    if flags & 0x20 != 0 {
                        console().print("ComIDMgmt ");
                    }
                    console().print_line("");
                }
            }
            FEATURE_LOCKING => {
                console().print_line("Locking");
                if desc_len >= 4 && offset + 4 + 4 <= data.len() {
                    let flags = data[offset + 4];
                    console().print("        ");
                    if flags & 0x01 != 0 {
                        console().print("LockingSupported ");
                    }
                    if flags & 0x02 != 0 {
                        console().print("LockingEnabled ");
                    }
                    if flags & 0x04 != 0 {
                        console().print("Locked ");
                    }
                    if flags & 0x08 != 0 {
                        console().print("MediaEncryption ");
                    }
                    if flags & 0x10 != 0 {
                        console().print("MBREnabled ");
                    }
                    if flags & 0x20 != 0 {
                        console().print("MBRDone ");
                    }
                    console().print_line("");
                }
            }
            FEATURE_GEOMETRY => {
                console().print_line("Geometry Reporting");
            }
            FEATURE_OPAL_SSC_V100 => {
                console().print_line("Opal SSC V1.00");
                found_opal = true;
            }
            FEATURE_OPAL_SSC_V200 => {
                console().print_line("Opal SSC V2.00");
                found_opal = true;
            }
            FEATURE_ENTERPRISE_SSC => {
                console().print_line("Enterprise SSC");
                found_opal = true;
            }
            FEATURE_PYRITE_V100 => {
                console().print_line("Pyrite SSC V1.00");
            }
            FEATURE_PYRITE_V200 => {
                console().print_line("Pyrite SSC V2.00");
            }
            _ => {
                console().print_line("(unknown)");
            }
        }

        // Move to next feature descriptor
        offset += 4 + desc_len;
    }

    if found_opal {
        console().print_line("      --> TCG Opal capable drive detected!");
    }

    found_opal
}
