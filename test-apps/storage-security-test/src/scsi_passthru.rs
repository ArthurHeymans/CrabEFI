//! SCSI Pass Through Protocol test module
//!
//! Tests the EFI_EXT_SCSI_PASS_THRU_PROTOCOL implementation.

use core::ffi::c_void;
use r_efi::efi::{Event, Guid, Handle, Status};
use r_efi::protocols::device_path::Protocol as DevicePathProtocol;

use crate::{console, efi_helpers};

/// Extended SCSI Pass Thru Protocol GUID
/// {143B7632-B81B-4CB7-ABD3-B625A5B9BFFE}
pub const EXT_SCSI_PASS_THRU_GUID: Guid = Guid::from_fields(
    0x143b7632,
    0xb81b,
    0x4cb7,
    0xab,
    0xd3,
    &[0xb6, 0x25, 0xa5, 0xb9, 0xbf, 0xfe],
);

/// Maximum target ID bytes
pub const TARGET_MAX_BYTES: usize = 16;

/// SCSI Pass Thru Mode
#[repr(C)]
pub struct ExtScsiPassThruMode {
    pub adapter_id: u32,
    pub attributes: u32,
    pub io_align: u32,
}

/// SCSI Request Packet
#[repr(C)]
pub struct ExtScsiPassThruScsiRequestPacket {
    pub timeout: u64,
    pub in_data_buffer: *mut c_void,
    pub out_data_buffer: *mut c_void,
    pub sense_data: *mut c_void,
    pub cdb: *mut c_void,
    pub in_transfer_length: u32,
    pub out_transfer_length: u32,
    pub cdb_length: u8,
    pub data_direction: u8,
    pub host_adapter_status: u8,
    pub target_status: u8,
    pub sense_data_length: u8,
}

/// SCSI Pass Thru Protocol
#[repr(C)]
pub struct ExtScsiPassThruProtocol {
    pub mode: *mut ExtScsiPassThruMode,
    pub pass_thru: extern "efiapi" fn(
        this: *mut ExtScsiPassThruProtocol,
        target: *mut u8,
        lun: u64,
        packet: *mut ExtScsiPassThruScsiRequestPacket,
        event: Event,
    ) -> Status,
    pub get_next_target_lun: extern "efiapi" fn(
        this: *mut ExtScsiPassThruProtocol,
        target: *mut *mut u8,
        lun: *mut u64,
    ) -> Status,
    pub build_device_path: extern "efiapi" fn(
        this: *mut ExtScsiPassThruProtocol,
        target: *mut u8,
        lun: u64,
        device_path: *mut *mut DevicePathProtocol,
    ) -> Status,
    pub get_target_lun: extern "efiapi" fn(
        this: *mut ExtScsiPassThruProtocol,
        device_path: *mut DevicePathProtocol,
        target: *mut *mut u8,
        lun: *mut u64,
    ) -> Status,
    pub reset_channel: extern "efiapi" fn(this: *mut ExtScsiPassThruProtocol) -> Status,
    pub reset_target_lun:
        extern "efiapi" fn(this: *mut ExtScsiPassThruProtocol, target: *mut u8, lun: u64) -> Status,
    pub get_next_target:
        extern "efiapi" fn(this: *mut ExtScsiPassThruProtocol, target: *mut *mut u8) -> Status,
}

/// Test SCSI Pass Through Protocol
pub fn test_scsi_pass_thru() -> bool {
    // Find all handles with SCSI Pass Through Protocol
    let mut handles: [Handle; 16] = [core::ptr::null_mut(); 16];
    let count = efi_helpers::locate_handle_buffer(&EXT_SCSI_PASS_THRU_GUID, &mut handles);

    if count == 0 {
        console().print_line("    No SCSI/USB mass storage controllers found");
        return false;
    }

    console().print("    Found ");
    console().print_dec(count as u64);
    console().print_line(" SCSI controller(s)");

    let mut success = false;

    for i in 0..count {
        let handle = handles[i];
        if handle.is_null() {
            continue;
        }

        console().print("    Controller ");
        console().print_dec(i as u64);
        console().print(": ");

        // Open the protocol
        let protocol: *mut ExtScsiPassThruProtocol =
            efi_helpers::open_protocol(handle, &EXT_SCSI_PASS_THRU_GUID);

        if protocol.is_null() {
            console().print_line("Failed to open protocol");
            continue;
        }

        // Check mode info
        unsafe {
            let mode = (*protocol).mode;
            if !mode.is_null() {
                console().print("Adapter ID ");
                console().print_dec((*mode).adapter_id as u64);
                console().print(", ");
            }
        }

        // Enumerate targets
        let mut target: [u8; TARGET_MAX_BYTES] = [0xFF; TARGET_MAX_BYTES];
        let mut target_ptr: *mut u8 = target.as_mut_ptr();
        let mut lun: u64 = 0;
        let mut target_count = 0u32;

        loop {
            let status =
                unsafe { ((*protocol).get_next_target_lun)(protocol, &mut target_ptr, &mut lun) };

            if status != Status::SUCCESS {
                break;
            }

            target_count += 1;
            console().print("Target");
            console().print_dec(target[0] as u64);
            console().print(":LUN");
            console().print_dec(lun);
            console().print(" ");
        }

        if target_count > 0 {
            console().print("(");
            console().print_dec(target_count as u64);
            console().print_line(" device(s))");
            success = true;
        } else {
            console().print_line("No targets found");
        }

        efi_helpers::close_protocol(handle, &EXT_SCSI_PASS_THRU_GUID);
    }

    success
}
