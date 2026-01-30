//! EFI ATA Pass Through Protocol
//!
//! This module implements the EFI_ATA_PASS_THRU_PROTOCOL which provides raw ATA
//! command access for applications requiring direct AHCI/SATA controller access.
//!
//! The protocol allows sending arbitrary ATA commands to SATA devices, which is
//! necessary for TCG Opal self-encrypting drive management and other advanced
//! storage operations.

use core::ffi::c_void;

use r_efi::efi::{Event, Guid, Status};
use r_efi::protocols::device_path::Protocol as DevicePathProtocol;

use crate::drivers::ahci;
use crate::efi::protocols::device_path::{self, SataDevicePathNode};
use crate::efi::utils::allocate_protocol_with_log;

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

// ============================================================================
// Attribute Flags
// ============================================================================

/// Protocol supports physical SATA devices
pub const ATTRIBUTES_PHYSICAL: u32 = 0x0001;
/// Protocol supports logical SATA devices
pub const ATTRIBUTES_LOGICAL: u32 = 0x0002;
/// Protocol supports non-blocking I/O
pub const ATTRIBUTES_NONBLOCKIO: u32 = 0x0004;

// ============================================================================
// ATA Protocol Types
// ============================================================================

/// ATA Hardware Reset
pub const PROTOCOL_ATA_HARDWARE_RESET: u8 = 0x00;
/// ATA Software Reset
pub const PROTOCOL_ATA_SOFTWARE_RESET: u8 = 0x01;
/// ATA Non-Data command
pub const PROTOCOL_ATA_NON_DATA: u8 = 0x02;
/// PIO Data In
pub const PROTOCOL_PIO_DATA_IN: u8 = 0x04;
/// PIO Data Out
pub const PROTOCOL_PIO_DATA_OUT: u8 = 0x05;
/// DMA
pub const PROTOCOL_DMA: u8 = 0x06;
/// DMA Queued
pub const PROTOCOL_DMA_QUEUED: u8 = 0x07;
/// UDMA Data In
pub const PROTOCOL_UDMA_DATA_IN: u8 = 0x0A;
/// UDMA Data Out
pub const PROTOCOL_UDMA_DATA_OUT: u8 = 0x0B;
/// FPDMA (NCQ)
pub const PROTOCOL_FPDMA: u8 = 0x0C;

/// Length field values
pub const ATA_LENGTH_NO_DATA: u8 = 0x00;
pub const ATA_LENGTH_SECTOR_COUNT: u8 = 0x01;
pub const ATA_LENGTH_BYTES: u8 = 0x02;
pub const ATA_LENGTH_MASK: u8 = 0x03;

// ============================================================================
// Protocol Data Structures
// ============================================================================

/// ATA Pass Thru Mode
///
/// Describes the capabilities of the ATA Pass Thru protocol instance.
#[repr(C)]
pub struct AtaPassThruMode {
    /// Attribute flags indicating protocol capabilities
    pub attributes: u32,
    /// I/O alignment requirement (must be power of 2)
    pub io_align: u32,
}

/// ATA Command Block (ACB)
///
/// Contains the ATA command to be sent to the device.
#[repr(C)]
pub struct AtaCommandBlock {
    /// Reserved
    pub reserved1: [u8; 2],
    /// ATA Command register value
    pub ata_command: u8,
    /// ATA Features register value (low byte)
    pub ata_features: u8,
    /// ATA Sector Number register value
    pub ata_sector_number: u8,
    /// ATA Cylinder Low register value
    pub ata_cylinder_low: u8,
    /// ATA Cylinder High register value
    pub ata_cylinder_high: u8,
    /// ATA Device/Head register value
    pub ata_device_head: u8,
    /// ATA Sector Number Exp register value (for 48-bit LBA)
    pub ata_sector_number_exp: u8,
    /// ATA Cylinder Low Exp register value (for 48-bit LBA)
    pub ata_cylinder_low_exp: u8,
    /// ATA Cylinder High Exp register value (for 48-bit LBA)
    pub ata_cylinder_high_exp: u8,
    /// ATA Features Exp register value (for 48-bit LBA)
    pub ata_features_exp: u8,
    /// ATA Sector Count register value
    pub ata_sector_count: u8,
    /// ATA Sector Count Exp register value (for 48-bit LBA)
    pub ata_sector_count_exp: u8,
    /// Reserved
    pub reserved2: [u8; 6],
}

/// ATA Status Block (ASB)
///
/// Contains the status returned from the device after command execution.
#[repr(C)]
pub struct AtaStatusBlock {
    /// Reserved
    pub reserved1: [u8; 2],
    /// ATA Status register value
    pub ata_status: u8,
    /// ATA Error register value
    pub ata_error: u8,
    /// ATA Sector Number register value
    pub ata_sector_number: u8,
    /// ATA Cylinder Low register value
    pub ata_cylinder_low: u8,
    /// ATA Cylinder High register value
    pub ata_cylinder_high: u8,
    /// ATA Device/Head register value
    pub ata_device_head: u8,
    /// ATA Sector Number Exp register value
    pub ata_sector_number_exp: u8,
    /// ATA Cylinder Low Exp register value
    pub ata_cylinder_low_exp: u8,
    /// ATA Cylinder High Exp register value
    pub ata_cylinder_high_exp: u8,
    /// Reserved
    pub reserved2: u8,
    /// ATA Sector Count register value
    pub ata_sector_count: u8,
    /// ATA Sector Count Exp register value
    pub ata_sector_count_exp: u8,
    /// Reserved
    pub reserved3: [u8; 6],
}

/// ATA Pass Thru Command Packet
///
/// Contains all information needed to execute an ATA command.
#[repr(C)]
pub struct AtaPassThruCommandPacket {
    /// Pointer to the ATA Status Block to receive status
    pub asb: *mut AtaStatusBlock,
    /// Pointer to the ATA Command Block
    pub acb: *mut AtaCommandBlock,
    /// Timeout in 100ns units (0 = wait forever)
    pub timeout: u64,
    /// Data buffer for read operations
    pub in_data_buffer: *mut c_void,
    /// Data buffer for write operations
    pub out_data_buffer: *mut c_void,
    /// Input data buffer size in bytes
    pub in_transfer_length: u32,
    /// Output data buffer size in bytes
    pub out_transfer_length: u32,
    /// ATA protocol type
    pub protocol: u8,
    /// Length indicator (how to interpret transfer lengths)
    pub length: u8,
}

/// ATA Pass Thru Protocol
#[repr(C)]
pub struct AtaPassThruProtocol {
    /// Protocol mode information
    pub mode: *mut AtaPassThruMode,
    /// Pass through function
    pub pass_thru: extern "efiapi" fn(
        this: *mut AtaPassThruProtocol,
        port: u16,
        port_multiplier_port: u16,
        packet: *mut AtaPassThruCommandPacket,
        event: Event,
    ) -> Status,
    /// Get next port function
    pub get_next_port: extern "efiapi" fn(
        this: *mut AtaPassThruProtocol,
        port: *mut u16,
    ) -> Status,
    /// Get next device on a port
    pub get_next_device: extern "efiapi" fn(
        this: *mut AtaPassThruProtocol,
        port: u16,
        port_multiplier_port: *mut u16,
    ) -> Status,
    /// Build device path function
    pub build_device_path: extern "efiapi" fn(
        this: *mut AtaPassThruProtocol,
        port: u16,
        port_multiplier_port: u16,
        device_path: *mut *mut DevicePathProtocol,
    ) -> Status,
    /// Get device from device path
    pub get_device: extern "efiapi" fn(
        this: *mut AtaPassThruProtocol,
        device_path: *mut DevicePathProtocol,
        port: *mut u16,
        port_multiplier_port: *mut u16,
    ) -> Status,
    /// Reset a port
    pub reset_port: extern "efiapi" fn(
        this: *mut AtaPassThruProtocol,
        port: u16,
    ) -> Status,
    /// Reset a device
    pub reset_device: extern "efiapi" fn(
        this: *mut AtaPassThruProtocol,
        port: u16,
        port_multiplier_port: u16,
    ) -> Status,
}

/// Internal context for ATA Pass Thru protocol instance
struct AtaPassThruContext {
    /// Controller index in the global controller list
    controller_index: usize,
    /// PCI device number
    pci_device: u8,
    /// PCI function number
    pci_function: u8,
}

/// Maximum number of ATA Pass Thru protocol instances
const MAX_INSTANCES: usize = 8;

/// Global storage for contexts
static mut CONTEXTS: [Option<AtaPassThruContext>; MAX_INSTANCES] = [const { None }; MAX_INSTANCES];

/// Protocol instance to context mapping
static mut PROTOCOL_TO_CONTEXT: [Option<*mut AtaPassThruProtocol>; MAX_INSTANCES] =
    [const { None }; MAX_INSTANCES];

/// Find context index for a protocol instance
fn find_context_index(protocol: *mut AtaPassThruProtocol) -> Option<usize> {
    unsafe {
        let proto_map = core::ptr::addr_of!(PROTOCOL_TO_CONTEXT);
        for (i, p) in (*proto_map).iter().enumerate() {
            if let Some(ptr) = p
                && *ptr == protocol
            {
                return Some(i);
            }
        }
    }
    None
}

/// Get context for a protocol instance
fn get_context(protocol: *mut AtaPassThruProtocol) -> Option<&'static AtaPassThruContext> {
    let idx = find_context_index(protocol)?;
    unsafe {
        let contexts = core::ptr::addr_of!(CONTEXTS);
        (*contexts)[idx].as_ref()
    }
}

// ============================================================================
// Protocol Functions
// ============================================================================

/// Execute an ATA command via pass-through
extern "efiapi" fn ata_pass_thru(
    this: *mut AtaPassThruProtocol,
    port: u16,
    _port_multiplier_port: u16,
    packet: *mut AtaPassThruCommandPacket,
    _event: Event,
) -> Status {
    if this.is_null() || packet.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx = match get_context(this) {
        Some(c) => c,
        None => {
            log::error!("AtaPassThru.PassThru: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    let packet = unsafe { &mut *packet };

    if packet.acb.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let acb = unsafe { &*packet.acb };
    let command = acb.ata_command;

    log::debug!(
        "AtaPassThru.PassThru: port={}, command={:#x}, protocol={:#x}",
        port,
        command,
        packet.protocol
    );

    // Get the controller
    let controller = match ahci::get_controller(ctx.controller_index) {
        Some(c) => c,
        None => {
            log::error!("AtaPassThru.PassThru: controller not found");
            return Status::DEVICE_ERROR;
        }
    };

    // Find the port index that matches the requested port number
    let port_index = {
        let mut found = None;
        for i in 0..controller.num_active_ports() {
            if let Some(p) = controller.get_port(i) {
                if p.port_num as u16 == port {
                    found = Some(i);
                    break;
                }
            }
        }
        match found {
            Some(idx) => idx,
            None => {
                log::error!("AtaPassThru.PassThru: port {} not found", port);
                return Status::INVALID_PARAMETER;
            }
        }
    };

    // Handle specific commands
    match command {
        0x5C => {
            // TRUSTED RECEIVE DMA
            if !packet.in_data_buffer.is_null() && packet.in_transfer_length > 0 {
                let buffer = unsafe {
                    core::slice::from_raw_parts_mut(
                        packet.in_data_buffer as *mut u8,
                        packet.in_transfer_length as usize,
                    )
                };
                let protocol_id = acb.ata_features;
                let sp_specific = ((acb.ata_device_head & 0x0F) as u16) | ((acb.ata_cylinder_high as u16) << 8);

                match controller.trusted_receive(port_index, protocol_id, sp_specific, buffer) {
                    Ok(bytes) => {
                        if !packet.asb.is_null() {
                            let asb = unsafe { &mut *packet.asb };
                            asb.ata_status = 0x50; // Ready, no error
                            asb.ata_error = 0;
                        }
                        packet.in_transfer_length = bytes as u32;
                        return Status::SUCCESS;
                    }
                    Err(e) => {
                        log::error!("AtaPassThru: TRUSTED RECEIVE failed: {:?}", e);
                        if !packet.asb.is_null() {
                            let asb = unsafe { &mut *packet.asb };
                            asb.ata_status = 0x51; // Error
                            asb.ata_error = 0x04; // Aborted command
                        }
                        return Status::DEVICE_ERROR;
                    }
                }
            }
        }
        0x5E => {
            // TRUSTED SEND DMA
            if !packet.out_data_buffer.is_null() && packet.out_transfer_length > 0 {
                let buffer = unsafe {
                    core::slice::from_raw_parts(
                        packet.out_data_buffer as *const u8,
                        packet.out_transfer_length as usize,
                    )
                };
                let protocol_id = acb.ata_features;
                let sp_specific = ((acb.ata_device_head & 0x0F) as u16) | ((acb.ata_cylinder_high as u16) << 8);

                match controller.trusted_send(port_index, protocol_id, sp_specific, buffer) {
                    Ok(()) => {
                        if !packet.asb.is_null() {
                            let asb = unsafe { &mut *packet.asb };
                            asb.ata_status = 0x50; // Ready, no error
                            asb.ata_error = 0;
                        }
                        return Status::SUCCESS;
                    }
                    Err(e) => {
                        log::error!("AtaPassThru: TRUSTED SEND failed: {:?}", e);
                        if !packet.asb.is_null() {
                            let asb = unsafe { &mut *packet.asb };
                            asb.ata_status = 0x51; // Error
                            asb.ata_error = 0x04; // Aborted command
                        }
                        return Status::DEVICE_ERROR;
                    }
                }
            }
        }
        _ => {
            log::warn!("AtaPassThru: unsupported command {:#x}", command);
            return Status::UNSUPPORTED;
        }
    }

    Status::INVALID_PARAMETER
}

/// Get the next port number
///
/// Used to enumerate ports. Pass 0xFFFF to get the first port.
extern "efiapi" fn ata_get_next_port(
    this: *mut AtaPassThruProtocol,
    port: *mut u16,
) -> Status {
    if this.is_null() || port.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx = match get_context(this) {
        Some(c) => c,
        None => {
            log::error!("AtaPassThru.GetNextPort: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    let controller = match ahci::get_controller(ctx.controller_index) {
        Some(c) => c,
        None => {
            return Status::DEVICE_ERROR;
        }
    };

    let current_port = unsafe { *port };

    log::debug!(
        "AtaPassThru.GetNextPort: current={:#x}, num_ports={}",
        current_port,
        controller.num_active_ports()
    );

    if current_port == 0xFFFF {
        // Return first port
        if let Some(p) = controller.get_port(0) {
            unsafe { *port = p.port_num as u16 };
            return Status::SUCCESS;
        }
        return Status::NOT_FOUND;
    }

    // Find current port and return the next one
    for i in 0..controller.num_active_ports() {
        if let Some(p) = controller.get_port(i) {
            if p.port_num as u16 == current_port {
                // Found current, return next
                if let Some(next_p) = controller.get_port(i + 1) {
                    unsafe { *port = next_p.port_num as u16 };
                    return Status::SUCCESS;
                }
                return Status::NOT_FOUND;
            }
        }
    }

    Status::NOT_FOUND
}

/// Get the next device on a port (port multiplier support)
///
/// Currently we don't support port multipliers, so each port has exactly one device.
extern "efiapi" fn ata_get_next_device(
    this: *mut AtaPassThruProtocol,
    port: u16,
    port_multiplier_port: *mut u16,
) -> Status {
    if this.is_null() || port_multiplier_port.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx = match get_context(this) {
        Some(c) => c,
        None => {
            log::error!("AtaPassThru.GetNextDevice: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    let controller = match ahci::get_controller(ctx.controller_index) {
        Some(c) => c,
        None => {
            return Status::DEVICE_ERROR;
        }
    };

    // Verify the port exists
    let port_exists = (0..controller.num_active_ports()).any(|i| {
        controller.get_port(i).is_some_and(|p| p.port_num as u16 == port)
    });

    if !port_exists {
        return Status::INVALID_PARAMETER;
    }

    let current_pmp = unsafe { *port_multiplier_port };

    log::debug!(
        "AtaPassThru.GetNextDevice: port={}, current_pmp={:#x}",
        port,
        current_pmp
    );

    // No port multiplier support - each port has device at PMP 0xFFFF
    if current_pmp == 0xFFFF {
        // 0xFFFF means "get first device", return 0xFFFF (no port multiplier)
        unsafe { *port_multiplier_port = 0xFFFF };
        return Status::SUCCESS;
    }

    // Already returned the only device
    Status::NOT_FOUND
}

/// Build a device path for an ATA device
extern "efiapi" fn ata_build_device_path(
    this: *mut AtaPassThruProtocol,
    port: u16,
    _port_multiplier_port: u16,
    device_path: *mut *mut DevicePathProtocol,
) -> Status {
    if this.is_null() || device_path.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx = match get_context(this) {
        Some(c) => c,
        None => {
            log::error!("AtaPassThru.BuildDevicePath: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    log::debug!(
        "AtaPassThru.BuildDevicePath: port={}",
        port
    );

    // Create SATA device path
    let path = device_path::create_sata_device_path(
        ctx.pci_device,
        ctx.pci_function,
        port,
    );

    if path.is_null() {
        return Status::OUT_OF_RESOURCES;
    }

    unsafe { *device_path = path };
    Status::SUCCESS
}

/// Get device (port/pmp) from a device path
extern "efiapi" fn ata_get_device(
    this: *mut AtaPassThruProtocol,
    device_path: *mut DevicePathProtocol,
    port: *mut u16,
    port_multiplier_port: *mut u16,
) -> Status {
    if this.is_null() || device_path.is_null() || port.is_null() || port_multiplier_port.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Parse the device path to find the SATA node
    // Device path format: ACPI/PCI/SATA/End
    let mut current = device_path;

    loop {
        let header = unsafe { &*current };

        // Check for end node
        if header.r#type == 0x7F {
            break;
        }

        // Check for SATA device path node (Type 0x03, SubType 0x12)
        if header.r#type == 0x03 && header.sub_type == 0x12 {
            let sata_node = current as *const SataDevicePathNode;
            let found_port = unsafe { (*sata_node).hba_port };
            let found_pmp = unsafe { (*sata_node).port_multiplier_port };
            log::debug!("AtaPassThru.GetDevice: found port={}, pmp={}", found_port, found_pmp);
            unsafe {
                *port = found_port;
                *port_multiplier_port = found_pmp;
            }
            return Status::SUCCESS;
        }

        // Move to next node
        let length = u16::from_le_bytes(header.length) as usize;
        if length < 4 {
            break;
        }
        current = unsafe { (current as *const u8).add(length) as *mut DevicePathProtocol };
    }

    log::debug!("AtaPassThru.GetDevice: no SATA node found in device path");
    Status::NOT_FOUND
}

/// Reset a port
extern "efiapi" fn ata_reset_port(
    this: *mut AtaPassThruProtocol,
    port: u16,
) -> Status {
    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx = match get_context(this) {
        Some(c) => c,
        None => {
            log::error!("AtaPassThru.ResetPort: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    log::info!("AtaPassThru.ResetPort: port={}", port);

    let controller = match ahci::get_controller(ctx.controller_index) {
        Some(c) => c,
        None => {
            return Status::DEVICE_ERROR;
        }
    };

    // Verify the port exists
    let port_exists = (0..controller.num_active_ports()).any(|i| {
        controller.get_port(i).is_some_and(|p| p.port_num as u16 == port)
    });

    if !port_exists {
        return Status::INVALID_PARAMETER;
    }

    // TODO: Implement actual port reset via AHCI COMRESET
    // For now, just return success
    log::warn!("AtaPassThru.ResetPort: port reset not fully implemented");
    Status::SUCCESS
}

/// Reset a device
extern "efiapi" fn ata_reset_device(
    this: *mut AtaPassThruProtocol,
    port: u16,
    _port_multiplier_port: u16,
) -> Status {
    // Device reset is essentially the same as port reset when there's no port multiplier
    ata_reset_port(this, port)
}

// ============================================================================
// Protocol Creation
// ============================================================================

/// Create an ATA Pass Thru Protocol instance
///
/// # Arguments
/// * `controller_index` - Index of the AHCI controller
/// * `pci_device` - PCI device number
/// * `pci_function` - PCI function number
///
/// # Returns
/// Pointer to the protocol instance, or null on failure
pub fn create_ata_pass_thru_protocol(
    controller_index: usize,
    pci_device: u8,
    pci_function: u8,
) -> *mut AtaPassThruProtocol {
    // Find a free context slot
    let ctx_idx = unsafe {
        let mut found = None;
        let contexts = core::ptr::addr_of!(CONTEXTS);
        for (i, slot) in (*contexts).iter().enumerate() {
            if slot.is_none() {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => {
                log::error!("AtaPassThru: no free context slots");
                return core::ptr::null_mut();
            }
        }
    };

    // Verify controller exists
    if ahci::get_controller(controller_index).is_none() {
        log::error!("AtaPassThru: controller {} not found", controller_index);
        return core::ptr::null_mut();
    }

    // Allocate mode structure
    let mode_ptr = allocate_protocol_with_log::<AtaPassThruMode>(
        "AtaPassThruMode",
        |m| {
            m.attributes = ATTRIBUTES_PHYSICAL | ATTRIBUTES_LOGICAL;
            m.io_align = 4; // 4-byte alignment
        },
    );

    if mode_ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Allocate protocol structure
    let protocol_ptr = allocate_protocol_with_log::<AtaPassThruProtocol>(
        "AtaPassThruProtocol",
        |p| {
            p.mode = mode_ptr;
            p.pass_thru = ata_pass_thru;
            p.get_next_port = ata_get_next_port;
            p.get_next_device = ata_get_next_device;
            p.build_device_path = ata_build_device_path;
            p.get_device = ata_get_device;
            p.reset_port = ata_reset_port;
            p.reset_device = ata_reset_device;
        },
    );

    if protocol_ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Store context
    unsafe {
        let contexts = core::ptr::addr_of_mut!(CONTEXTS);
        (*contexts)[ctx_idx] = Some(AtaPassThruContext {
            controller_index,
            pci_device,
            pci_function,
        });
        let proto_map = core::ptr::addr_of_mut!(PROTOCOL_TO_CONTEXT);
        (*proto_map)[ctx_idx] = Some(protocol_ptr);
    }

    log::info!(
        "AtaPassThru: created protocol for controller {} (PCI {:02x}:{:x})",
        controller_index,
        pci_device,
        pci_function,
    );

    protocol_ptr
}
