//! ATA Pass Through Protocol test module
//!
//! Tests the EFI_ATA_PASS_THRU_PROTOCOL implementation.

use core::ffi::c_void;
use r_efi::efi::{Event, Guid, Handle, Status};
use r_efi::protocols::device_path::Protocol as DevicePathProtocol;

use crate::{console, efi_helpers};

/// ATA Pass Thru Protocol GUID
/// {1D3DE7F0-0807-424F-AA69-11A54E19A46F}
pub const ATA_PASS_THRU_GUID: Guid = Guid::from_fields(
    0x1d3de7f0,
    0x0807,
    0x424f,
    0xaa,
    0x69,
    &[0x11, 0xa5, 0x4e, 0x19, 0xa4, 0x6f],
);

/// ATA Pass Thru Mode
#[repr(C)]
pub struct AtaPassThruMode {
    pub attributes: u32,
    pub io_align: u32,
}

/// ATA Command Block
#[repr(C)]
pub struct AtaCommandBlock {
    pub reserved1: [u8; 2],
    pub ata_command: u8,
    pub ata_features: u8,
    pub ata_sector_number: u8,
    pub ata_cylinder_low: u8,
    pub ata_cylinder_high: u8,
    pub ata_device_head: u8,
    pub ata_sector_number_exp: u8,
    pub ata_cylinder_low_exp: u8,
    pub ata_cylinder_high_exp: u8,
    pub ata_features_exp: u8,
    pub ata_sector_count: u8,
    pub ata_sector_count_exp: u8,
    pub reserved2: [u8; 6],
}

/// ATA Status Block
#[repr(C)]
pub struct AtaStatusBlock {
    pub reserved1: [u8; 2],
    pub ata_status: u8,
    pub ata_error: u8,
    pub ata_sector_number: u8,
    pub ata_cylinder_low: u8,
    pub ata_cylinder_high: u8,
    pub ata_device_head: u8,
    pub ata_sector_number_exp: u8,
    pub ata_cylinder_low_exp: u8,
    pub ata_cylinder_high_exp: u8,
    pub reserved2: u8,
    pub ata_sector_count: u8,
    pub ata_sector_count_exp: u8,
    pub reserved3: [u8; 6],
}

/// ATA Pass Thru Command Packet
#[repr(C)]
pub struct AtaPassThruCommandPacket {
    pub asb: *mut AtaStatusBlock,
    pub acb: *mut AtaCommandBlock,
    pub timeout: u64,
    pub in_data_buffer: *mut c_void,
    pub out_data_buffer: *mut c_void,
    pub in_transfer_length: u32,
    pub out_transfer_length: u32,
    pub protocol: u8,
    pub length: u8,
}

/// ATA Pass Thru Protocol
#[repr(C)]
pub struct AtaPassThruProtocol {
    pub mode: *mut AtaPassThruMode,
    pub pass_thru: extern "efiapi" fn(
        this: *mut AtaPassThruProtocol,
        port: u16,
        port_multiplier_port: u16,
        packet: *mut AtaPassThruCommandPacket,
        event: Event,
    ) -> Status,
    pub get_next_port: extern "efiapi" fn(this: *mut AtaPassThruProtocol, port: *mut u16) -> Status,
    pub get_next_device: extern "efiapi" fn(
        this: *mut AtaPassThruProtocol,
        port: u16,
        port_multiplier_port: *mut u16,
    ) -> Status,
    pub build_device_path: extern "efiapi" fn(
        this: *mut AtaPassThruProtocol,
        port: u16,
        port_multiplier_port: u16,
        device_path: *mut *mut DevicePathProtocol,
    ) -> Status,
    pub get_device: extern "efiapi" fn(
        this: *mut AtaPassThruProtocol,
        device_path: *mut DevicePathProtocol,
        port: *mut u16,
        port_multiplier_port: *mut u16,
    ) -> Status,
    pub reset_port: extern "efiapi" fn(this: *mut AtaPassThruProtocol, port: u16) -> Status,
    pub reset_device: extern "efiapi" fn(
        this: *mut AtaPassThruProtocol,
        port: u16,
        port_multiplier_port: u16,
    ) -> Status,
}

/// Test ATA Pass Through Protocol
pub fn test_ata_pass_thru() -> bool {
    // Find all handles with ATA Pass Through Protocol
    let mut handles: [Handle; 16] = [core::ptr::null_mut(); 16];
    let count = efi_helpers::locate_handle_buffer(&ATA_PASS_THRU_GUID, &mut handles);

    if count == 0 {
        console().print_line("    No ATA/SATA controllers found");
        return false;
    }

    console().print("    Found ");
    console().print_dec(count as u64);
    console().print_line(" AHCI/SATA controller(s)");

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
        let protocol: *mut AtaPassThruProtocol =
            efi_helpers::open_protocol(handle, &ATA_PASS_THRU_GUID);

        if protocol.is_null() {
            console().print_line("Failed to open protocol");
            continue;
        }

        // Enumerate ports
        let mut port: u16 = 0xFFFF; // Start enumeration
        let mut port_count = 0u32;

        loop {
            let status = unsafe { ((*protocol).get_next_port)(protocol, &mut port) };

            if status != Status::SUCCESS {
                break;
            }

            port_count += 1;
            console().print("Port");
            console().print_dec(port as u64);
            console().print(" ");
        }

        if port_count > 0 {
            console().print("(");
            console().print_dec(port_count as u64);
            console().print_line(" port(s))");
            success = true;
        } else {
            console().print_line("No ports found");
        }

        efi_helpers::close_protocol(handle, &ATA_PASS_THRU_GUID);
    }

    success
}
