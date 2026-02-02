//! NVMe Pass Through Protocol test module
//!
//! Tests the EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL implementation.

use core::ffi::c_void;
use r_efi::efi::{Event, Guid, Handle, Status};
use r_efi::protocols::device_path::Protocol as DevicePathProtocol;

use crate::{console, efi_helpers};

/// NVM Express Pass Thru Protocol GUID
/// {52C78312-8EDC-4233-98F2-1A1AA5E388A5}
pub const NVM_EXPRESS_PASS_THRU_GUID: Guid = Guid::from_fields(
    0x52c78312,
    0x8edc,
    0x4233,
    0x98,
    0xf2,
    &[0x1a, 0x1a, 0xa5, 0xe3, 0x88, 0xa5],
);

/// Queue type for admin commands
pub const NVME_ADMIN_QUEUE: u8 = 0x00;

/// NVM Express Pass Thru Mode
#[repr(C)]
pub struct NvmExpressPassThruMode {
    pub attributes: u32,
    pub io_align: u32,
    pub nvme_version: u32,
}

/// NVM Express Command Structure
#[repr(C)]
pub struct NvmExpressCommand {
    pub cdw0: u32,
    pub flags: u8,
    pub _reserved: [u8; 3],
    pub nsid: u32,
    pub cdw2: u32,
    pub cdw3: u32,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

/// NVM Express Completion Structure
#[repr(C)]
pub struct NvmExpressCompletion {
    pub dw0: u32,
    pub dw1: u32,
    pub dw2: u32,
    pub dw3: u32,
}

/// NVM Express Pass Thru Command Packet
#[repr(C)]
pub struct NvmExpressPassThruCommandPacket {
    pub command_timeout: u64,
    pub transfer_buffer: *mut c_void,
    pub transfer_length: u32,
    pub metadata_buffer: *mut c_void,
    pub metadata_length: u32,
    pub queue_type: u8,
    pub _reserved: [u8; 3],
    pub nvme_cmd: *mut NvmExpressCommand,
    pub nvme_completion: *mut NvmExpressCompletion,
}

/// NVM Express Pass Thru Protocol
#[repr(C)]
pub struct NvmExpressPassThruProtocol {
    pub mode: *mut NvmExpressPassThruMode,
    pub pass_thru: extern "efiapi" fn(
        this: *mut NvmExpressPassThruProtocol,
        namespace_id: u32,
        packet: *mut NvmExpressPassThruCommandPacket,
        event: Event,
    ) -> Status,
    pub get_next_namespace:
        extern "efiapi" fn(this: *mut NvmExpressPassThruProtocol, namespace_id: *mut u32) -> Status,
    pub build_device_path: extern "efiapi" fn(
        this: *mut NvmExpressPassThruProtocol,
        namespace_id: u32,
        device_path: *mut *mut DevicePathProtocol,
    ) -> Status,
    pub get_namespace: extern "efiapi" fn(
        this: *mut NvmExpressPassThruProtocol,
        device_path: *mut DevicePathProtocol,
        namespace_id: *mut u32,
    ) -> Status,
}

/// Test NVMe Pass Through Protocol
pub fn test_nvme_pass_thru() -> bool {
    // Find all handles with NVMe Pass Through Protocol
    let mut handles: [Handle; 16] = [core::ptr::null_mut(); 16];
    let count = efi_helpers::locate_handle_buffer(&NVM_EXPRESS_PASS_THRU_GUID, &mut handles);

    if count == 0 {
        console().print_line("    No NVMe controllers found");
        return false;
    }

    console().print("    Found ");
    console().print_dec(count as u64);
    console().print_line(" NVMe controller(s)");

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
        let protocol: *mut NvmExpressPassThruProtocol =
            efi_helpers::open_protocol(handle, &NVM_EXPRESS_PASS_THRU_GUID);

        if protocol.is_null() {
            console().print_line("Failed to open protocol");
            continue;
        }

        // Check mode info
        unsafe {
            let mode = (*protocol).mode;
            if !mode.is_null() {
                console().print("NVMe ver ");
                let major = ((*mode).nvme_version >> 16) & 0xFFFF;
                let minor = ((*mode).nvme_version >> 8) & 0xFF;
                console().print_dec(major as u64);
                console().print(".");
                console().print_dec(minor as u64);
                console().print(", ");
            }
        }

        // Enumerate namespaces
        let mut nsid: u32 = 0xFFFFFFFF; // Start enumeration
        let mut ns_count = 0u32;

        loop {
            let status = unsafe { ((*protocol).get_next_namespace)(protocol, &mut nsid) };

            if status != Status::SUCCESS {
                break;
            }

            ns_count += 1;
            console().print("NS");
            console().print_dec(nsid as u64);
            console().print(" ");
        }

        if ns_count > 0 {
            console().print("(");
            console().print_dec(ns_count as u64);
            console().print_line(" namespace(s))");
            success = true;
        } else {
            console().print_line("No namespaces found");
        }

        efi_helpers::close_protocol(handle, &NVM_EXPRESS_PASS_THRU_GUID);
    }

    success
}
