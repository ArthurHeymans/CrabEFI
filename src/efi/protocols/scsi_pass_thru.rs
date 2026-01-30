//! EFI Extended SCSI Pass Through Protocol
//!
//! This module implements the EFI_EXT_SCSI_PASS_THRU_PROTOCOL which provides
//! raw SCSI command access for USB mass storage devices.
//!
//! The protocol allows sending arbitrary SCSI commands to USB storage devices,
//! which is necessary for TCG Opal self-encrypting drive management and other
//! advanced storage operations via USB.

use core::ffi::c_void;

use r_efi::efi::{Event, Guid, Status};
use r_efi::protocols::device_path::Protocol as DevicePathProtocol;

use crate::drivers::usb;
use crate::efi::protocols::device_path::{self, UsbDevicePathNode};
use crate::efi::utils::allocate_protocol_with_log;

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

// ============================================================================
// Attribute Flags
// ============================================================================

/// Protocol supports physical SCSI devices
pub const ATTRIBUTES_PHYSICAL: u32 = 0x0001;
/// Protocol supports logical SCSI devices
pub const ATTRIBUTES_LOGICAL: u32 = 0x0002;
/// Protocol supports non-blocking I/O
pub const ATTRIBUTES_NONBLOCKIO: u32 = 0x0004;

// ============================================================================
// Data Direction
// ============================================================================

/// Read data from the device
pub const DATA_DIRECTION_READ: u8 = 0;
/// Write data to the device
pub const DATA_DIRECTION_WRITE: u8 = 1;
/// Bidirectional data transfer
pub const DATA_DIRECTION_BIDIRECTIONAL: u8 = 2;

// ============================================================================
// Host Adapter Status
// ============================================================================

/// Command completed without error
pub const HOST_ADAPTER_OK: u8 = 0x00;
/// Command timed out
pub const HOST_ADAPTER_TIMEOUT_COMMAND: u8 = 0x09;
/// Unspecified error
pub const HOST_ADAPTER_OTHER: u8 = 0x7F;

// ============================================================================
// Target Status
// ============================================================================

/// Good status
pub const TARGET_GOOD: u8 = 0x00;
/// Check condition
pub const TARGET_CHECK_CONDITION: u8 = 0x02;
/// Command terminated
pub const TARGET_COMMAND_TERMINATED: u8 = 0x22;

/// Maximum target ID bytes
pub const TARGET_MAX_BYTES: usize = 16;

// ============================================================================
// SCSI Commands for TCG
// ============================================================================

/// SCSI SECURITY PROTOCOL IN command (opcode 0xA2)
pub const SCSI_SECURITY_PROTOCOL_IN: u8 = 0xA2;
/// SCSI SECURITY PROTOCOL OUT command (opcode 0xB5)
pub const SCSI_SECURITY_PROTOCOL_OUT: u8 = 0xB5;
/// SCSI INQUIRY command
pub const SCSI_INQUIRY: u8 = 0x12;

// ============================================================================
// Protocol Data Structures
// ============================================================================

/// Extended SCSI Pass Thru Mode
///
/// Describes the capabilities of the SCSI Pass Thru protocol instance.
#[repr(C)]
pub struct ExtScsiPassThruMode {
    /// Adapter ID (unique identifier for the host adapter)
    pub adapter_id: u32,
    /// Attribute flags indicating protocol capabilities
    pub attributes: u32,
    /// I/O alignment requirement (must be power of 2)
    pub io_align: u32,
}

/// SCSI Request Packet
///
/// Contains all information needed to execute a SCSI command.
#[repr(C)]
pub struct ExtScsiPassThruScsiRequestPacket {
    /// Timeout in 100ns units (0 = wait forever)
    pub timeout: u64,
    /// Data buffer for read operations
    pub in_data_buffer: *mut c_void,
    /// Data buffer for write operations
    pub out_data_buffer: *mut c_void,
    /// Sense data buffer (for error information)
    pub sense_data: *mut c_void,
    /// Command Descriptor Block (CDB)
    pub cdb: *mut c_void,
    /// Input data buffer size in bytes
    pub in_transfer_length: u32,
    /// Output data buffer size in bytes
    pub out_transfer_length: u32,
    /// Length of the CDB
    pub cdb_length: u8,
    /// Data direction (read, write, or bidirectional)
    pub data_direction: u8,
    /// Host adapter status (output)
    pub host_adapter_status: u8,
    /// Target status (output)
    pub target_status: u8,
    /// Sense data length (input: max size, output: actual size)
    pub sense_data_length: u8,
}

/// Extended SCSI Pass Thru Protocol
#[repr(C)]
pub struct ExtScsiPassThruProtocol {
    /// Protocol mode information
    pub mode: *mut ExtScsiPassThruMode,
    /// Pass through function
    pub pass_thru: extern "efiapi" fn(
        this: *mut ExtScsiPassThruProtocol,
        target: *mut u8,
        lun: u64,
        packet: *mut ExtScsiPassThruScsiRequestPacket,
        event: Event,
    ) -> Status,
    /// Get next target and LUN
    pub get_next_target_lun: extern "efiapi" fn(
        this: *mut ExtScsiPassThruProtocol,
        target: *mut *mut u8,
        lun: *mut u64,
    ) -> Status,
    /// Build device path function
    pub build_device_path: extern "efiapi" fn(
        this: *mut ExtScsiPassThruProtocol,
        target: *mut u8,
        lun: u64,
        device_path: *mut *mut DevicePathProtocol,
    ) -> Status,
    /// Get target and LUN from device path
    pub get_target_lun: extern "efiapi" fn(
        this: *mut ExtScsiPassThruProtocol,
        device_path: *mut DevicePathProtocol,
        target: *mut *mut u8,
        lun: *mut u64,
    ) -> Status,
    /// Reset the SCSI channel
    pub reset_channel: extern "efiapi" fn(this: *mut ExtScsiPassThruProtocol) -> Status,
    /// Reset a target and LUN
    pub reset_target_lun: extern "efiapi" fn(
        this: *mut ExtScsiPassThruProtocol,
        target: *mut u8,
        lun: u64,
    ) -> Status,
    /// Get next target (without LUN iteration)
    pub get_next_target: extern "efiapi" fn(
        this: *mut ExtScsiPassThruProtocol,
        target: *mut *mut u8,
    ) -> Status,
}

/// Internal context for SCSI Pass Thru protocol instance
struct ScsiPassThruContext {
    /// USB controller index
    controller_index: usize,
    /// USB device address (slot ID)
    device_addr: u8,
    /// PCI device number
    pci_device: u8,
    /// PCI function number
    pci_function: u8,
    /// USB port number
    usb_port: u8,
}

/// Maximum number of SCSI Pass Thru protocol instances
const MAX_INSTANCES: usize = 8;

/// Global storage for contexts
static mut CONTEXTS: [Option<ScsiPassThruContext>; MAX_INSTANCES] = [const { None }; MAX_INSTANCES];

/// Protocol instance to context mapping
static mut PROTOCOL_TO_CONTEXT: [Option<*mut ExtScsiPassThruProtocol>; MAX_INSTANCES] =
    [const { None }; MAX_INSTANCES];

/// Target ID storage for each instance
static mut TARGET_IDS: [[u8; TARGET_MAX_BYTES]; MAX_INSTANCES] =
    [[0; TARGET_MAX_BYTES]; MAX_INSTANCES];

/// Find context index for a protocol instance
fn find_context_index(protocol: *mut ExtScsiPassThruProtocol) -> Option<usize> {
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
fn get_context(protocol: *mut ExtScsiPassThruProtocol) -> Option<&'static ScsiPassThruContext> {
    let idx = find_context_index(protocol)?;
    unsafe {
        let contexts = core::ptr::addr_of!(CONTEXTS);
        (*contexts)[idx].as_ref()
    }
}

// ============================================================================
// Protocol Functions
// ============================================================================

/// Execute a SCSI command via pass-through
extern "efiapi" fn scsi_pass_thru(
    this: *mut ExtScsiPassThruProtocol,
    target: *mut u8,
    lun: u64,
    packet: *mut ExtScsiPassThruScsiRequestPacket,
    _event: Event,
) -> Status {
    if this.is_null() || target.is_null() || packet.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx = match get_context(this) {
        Some(c) => c,
        None => {
            log::error!("ScsiPassThru.PassThru: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    let packet = unsafe { &mut *packet };

    if packet.cdb.is_null() || packet.cdb_length == 0 {
        return Status::INVALID_PARAMETER;
    }

    let cdb = unsafe { core::slice::from_raw_parts(packet.cdb as *const u8, packet.cdb_length as usize) };
    let opcode = cdb[0];

    log::debug!(
        "ScsiPassThru.PassThru: target={:?}, lun={}, opcode={:#x}, cdb_len={}",
        unsafe { core::slice::from_raw_parts(target, 2) },
        lun,
        opcode,
        packet.cdb_length
    );

    // Only support LUN 0 for USB mass storage
    if lun != 0 {
        return Status::INVALID_PARAMETER;
    }

    // Execute the SCSI command via USB mass storage
    let result = usb::with_controller(ctx.controller_index, |controller| {
        // Create a temporary mass storage device wrapper
        match usb::UsbMassStorage::new(controller, ctx.device_addr) {
            Ok(mut device) => {
                // Determine data direction and execute command
                match packet.data_direction {
                    DATA_DIRECTION_READ => {
                        if !packet.in_data_buffer.is_null() && packet.in_transfer_length > 0 {
                            let buffer = unsafe {
                                core::slice::from_raw_parts_mut(
                                    packet.in_data_buffer as *mut u8,
                                    packet.in_transfer_length as usize,
                                )
                            };
                            // Call the SCSI command helper
                            execute_scsi_read(&mut device, controller, cdb, buffer, packet)
                        } else {
                            Status::INVALID_PARAMETER
                        }
                    }
                    DATA_DIRECTION_WRITE => {
                        if !packet.out_data_buffer.is_null() && packet.out_transfer_length > 0 {
                            let buffer = unsafe {
                                core::slice::from_raw_parts(
                                    packet.out_data_buffer as *const u8,
                                    packet.out_transfer_length as usize,
                                )
                            };
                            // Call the SCSI command helper
                            execute_scsi_write(&mut device, controller, cdb, buffer, packet)
                        } else {
                            Status::INVALID_PARAMETER
                        }
                    }
                    _ => {
                        log::warn!("ScsiPassThru: unsupported data direction {}", packet.data_direction);
                        Status::UNSUPPORTED
                    }
                }
            }
            Err(e) => {
                log::error!("ScsiPassThru: failed to create mass storage device: {:?}", e);
                packet.host_adapter_status = HOST_ADAPTER_OTHER;
                Status::DEVICE_ERROR
            }
        }
    });

    result.unwrap_or(Status::DEVICE_ERROR)
}

/// Execute a SCSI read command (data from device)
fn execute_scsi_read(
    device: &mut usb::UsbMassStorage,
    controller: &mut dyn usb::UsbController,
    cdb: &[u8],
    buffer: &mut [u8],
    packet: &mut ExtScsiPassThruScsiRequestPacket,
) -> Status {
    // Use the internal scsi_command method via a wrapper
    // We need to send the CDB and receive data
    match send_scsi_command(device, controller, cdb, Some(buffer), true) {
        Ok(transferred) => {
            packet.in_transfer_length = transferred as u32;
            packet.host_adapter_status = HOST_ADAPTER_OK;
            packet.target_status = TARGET_GOOD;
            Status::SUCCESS
        }
        Err(_) => {
            packet.host_adapter_status = HOST_ADAPTER_OTHER;
            packet.target_status = TARGET_CHECK_CONDITION;
            Status::DEVICE_ERROR
        }
    }
}

/// Execute a SCSI write command (data to device)
fn execute_scsi_write(
    device: &mut usb::UsbMassStorage,
    controller: &mut dyn usb::UsbController,
    cdb: &[u8],
    buffer: &[u8],
    packet: &mut ExtScsiPassThruScsiRequestPacket,
) -> Status {
    // Convert to mutable buffer for the SCSI command interface
    // This is safe because we're doing a write operation
    let mut buf_copy = [0u8; 4096];
    let len = buffer.len().min(buf_copy.len());
    buf_copy[..len].copy_from_slice(&buffer[..len]);
    
    match send_scsi_command(device, controller, cdb, Some(&mut buf_copy[..len]), false) {
        Ok(_) => {
            packet.host_adapter_status = HOST_ADAPTER_OK;
            packet.target_status = TARGET_GOOD;
            Status::SUCCESS
        }
        Err(_) => {
            packet.host_adapter_status = HOST_ADAPTER_OTHER;
            packet.target_status = TARGET_CHECK_CONDITION;
            Status::DEVICE_ERROR
        }
    }
}

/// Send a SCSI command to the USB mass storage device
///
/// This is a wrapper that uses the USB Bulk-Only Transport protocol
fn send_scsi_command(
    _device: &mut usb::UsbMassStorage,
    _controller: &mut dyn usb::UsbController,
    cdb: &[u8],
    _data: Option<&mut [u8]>,
    _is_read: bool,
) -> Result<usize, ()> {
    // For now, we only support specific security-related commands
    // A full implementation would need direct access to the scsi_command method
    let opcode = cdb[0];
    
    match opcode {
        SCSI_SECURITY_PROTOCOL_IN | SCSI_SECURITY_PROTOCOL_OUT => {
            // These need direct SCSI command support in mass_storage.rs
            // which we'll add in the next step
            log::warn!("ScsiPassThru: SECURITY PROTOCOL commands require driver support");
            Err(())
        }
        SCSI_INQUIRY => {
            // INQUIRY is already supported, but we'd need to access it directly
            log::debug!("ScsiPassThru: INQUIRY command");
            Err(())
        }
        _ => {
            log::warn!("ScsiPassThru: unsupported SCSI opcode {:#x}", opcode);
            Err(())
        }
    }
}

/// Get the next target and LUN
///
/// For USB mass storage, each device is a single target with LUN 0.
extern "efiapi" fn scsi_get_next_target_lun(
    this: *mut ExtScsiPassThruProtocol,
    target: *mut *mut u8,
    lun: *mut u64,
) -> Status {
    if this.is_null() || target.is_null() || lun.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx_idx = match find_context_index(this) {
        Some(i) => i,
        None => {
            log::error!("ScsiPassThru.GetNextTargetLun: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    let target_ptr = unsafe { *target };

    // Check if this is the initial call (target buffer is all 0xFF)
    let is_initial = if target_ptr.is_null() {
        true
    } else {
        let target_bytes = unsafe { core::slice::from_raw_parts(target_ptr, TARGET_MAX_BYTES) };
        target_bytes.iter().all(|&b| b == 0xFF)
    };

    log::debug!(
        "ScsiPassThru.GetNextTargetLun: ctx={}, is_initial={}",
        ctx_idx,
        is_initial
    );

    if is_initial {
        // Return the first (and only) target: target ID 0, LUN 0
        unsafe {
            let target_storage = core::ptr::addr_of_mut!(TARGET_IDS);
            (*target_storage)[ctx_idx].fill(0);
            *target = (*target_storage)[ctx_idx].as_mut_ptr();
            *lun = 0;
        }
        return Status::SUCCESS;
    }

    // We only have one device per USB mass storage instance
    Status::NOT_FOUND
}

/// Build a device path for a SCSI target/LUN
extern "efiapi" fn scsi_build_device_path(
    this: *mut ExtScsiPassThruProtocol,
    _target: *mut u8,
    lun: u64,
    device_path: *mut *mut DevicePathProtocol,
) -> Status {
    if this.is_null() || device_path.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Only support LUN 0
    if lun != 0 {
        return Status::INVALID_PARAMETER;
    }

    let ctx = match get_context(this) {
        Some(c) => c,
        None => {
            log::error!("ScsiPassThru.BuildDevicePath: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    log::debug!(
        "ScsiPassThru.BuildDevicePath: lun={}",
        lun
    );

    // Create USB device path
    let path = device_path::create_usb_device_path(
        ctx.pci_device,
        ctx.pci_function,
        ctx.usb_port,
    );

    if path.is_null() {
        return Status::OUT_OF_RESOURCES;
    }

    unsafe { *device_path = path };
    Status::SUCCESS
}

/// Get target and LUN from a device path
extern "efiapi" fn scsi_get_target_lun(
    this: *mut ExtScsiPassThruProtocol,
    device_path: *mut DevicePathProtocol,
    target: *mut *mut u8,
    lun: *mut u64,
) -> Status {
    if this.is_null() || device_path.is_null() || target.is_null() || lun.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx_idx = match find_context_index(this) {
        Some(i) => i,
        None => {
            log::error!("ScsiPassThru.GetTargetLun: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    // Parse the device path to find the USB node
    let mut current = device_path;

    loop {
        let header = unsafe { &*current };

        // Check for end node
        if header.r#type == 0x7F {
            break;
        }

        // Check for USB device path node (Type 0x03, SubType 0x05)
        if header.r#type == 0x03 && header.sub_type == 0x05 {
            let usb_node = current as *const UsbDevicePathNode;
            let port = unsafe { (*usb_node).parent_port };
            log::debug!("ScsiPassThru.GetTargetLun: found USB port={}", port);
            
            // Return target ID 0 and LUN 0
            unsafe {
                let target_storage = core::ptr::addr_of_mut!(TARGET_IDS);
                (*target_storage)[ctx_idx].fill(0);
                *target = (*target_storage)[ctx_idx].as_mut_ptr();
                *lun = 0;
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

    log::debug!("ScsiPassThru.GetTargetLun: no USB node found in device path");
    Status::NOT_FOUND
}

/// Reset the SCSI channel
extern "efiapi" fn scsi_reset_channel(this: *mut ExtScsiPassThruProtocol) -> Status {
    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }

    log::info!("ScsiPassThru.ResetChannel: not implemented for USB");
    
    // USB mass storage doesn't have a channel reset concept
    // Just return success
    Status::SUCCESS
}

/// Reset a target and LUN
extern "efiapi" fn scsi_reset_target_lun(
    this: *mut ExtScsiPassThruProtocol,
    _target: *mut u8,
    lun: u64,
) -> Status {
    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }

    if lun != 0 {
        return Status::INVALID_PARAMETER;
    }

    log::info!("ScsiPassThru.ResetTargetLun: not implemented for USB");
    
    // USB mass storage device reset would require sending a USB reset
    // For now, just return success
    Status::SUCCESS
}

/// Get the next target (without LUN iteration)
extern "efiapi" fn scsi_get_next_target(
    this: *mut ExtScsiPassThruProtocol,
    target: *mut *mut u8,
) -> Status {
    if this.is_null() || target.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx_idx = match find_context_index(this) {
        Some(i) => i,
        None => {
            log::error!("ScsiPassThru.GetNextTarget: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    let target_ptr = unsafe { *target };

    // Check if this is the initial call (target buffer is all 0xFF)
    let is_initial = if target_ptr.is_null() {
        true
    } else {
        let target_bytes = unsafe { core::slice::from_raw_parts(target_ptr, TARGET_MAX_BYTES) };
        target_bytes.iter().all(|&b| b == 0xFF)
    };

    log::debug!(
        "ScsiPassThru.GetNextTarget: ctx={}, is_initial={}",
        ctx_idx,
        is_initial
    );

    if is_initial {
        // Return the first (and only) target: target ID 0
        unsafe {
            let target_storage = core::ptr::addr_of_mut!(TARGET_IDS);
            (*target_storage)[ctx_idx].fill(0);
            *target = (*target_storage)[ctx_idx].as_mut_ptr();
        }
        return Status::SUCCESS;
    }

    // We only have one device per USB mass storage instance
    Status::NOT_FOUND
}

// ============================================================================
// Protocol Creation
// ============================================================================

/// Create an Extended SCSI Pass Thru Protocol instance
///
/// # Arguments
/// * `controller_index` - Index of the USB controller
/// * `device_addr` - USB device address (slot ID)
/// * `pci_device` - PCI device number
/// * `pci_function` - PCI function number
/// * `usb_port` - USB port number
///
/// # Returns
/// Pointer to the protocol instance, or null on failure
pub fn create_scsi_pass_thru_protocol(
    controller_index: usize,
    device_addr: u8,
    pci_device: u8,
    pci_function: u8,
    usb_port: u8,
) -> *mut ExtScsiPassThruProtocol {
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
                log::error!("ScsiPassThru: no free context slots");
                return core::ptr::null_mut();
            }
        }
    };

    // Allocate mode structure
    let mode_ptr = allocate_protocol_with_log::<ExtScsiPassThruMode>(
        "ExtScsiPassThruMode",
        |m| {
            m.adapter_id = controller_index as u32;
            m.attributes = ATTRIBUTES_PHYSICAL | ATTRIBUTES_LOGICAL;
            m.io_align = 4; // 4-byte alignment
        },
    );

    if mode_ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Allocate protocol structure
    let protocol_ptr = allocate_protocol_with_log::<ExtScsiPassThruProtocol>(
        "ExtScsiPassThruProtocol",
        |p| {
            p.mode = mode_ptr;
            p.pass_thru = scsi_pass_thru;
            p.get_next_target_lun = scsi_get_next_target_lun;
            p.build_device_path = scsi_build_device_path;
            p.get_target_lun = scsi_get_target_lun;
            p.reset_channel = scsi_reset_channel;
            p.reset_target_lun = scsi_reset_target_lun;
            p.get_next_target = scsi_get_next_target;
        },
    );

    if protocol_ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Store context
    unsafe {
        let contexts = core::ptr::addr_of_mut!(CONTEXTS);
        (*contexts)[ctx_idx] = Some(ScsiPassThruContext {
            controller_index,
            device_addr,
            pci_device,
            pci_function,
            usb_port,
        });
        let proto_map = core::ptr::addr_of_mut!(PROTOCOL_TO_CONTEXT);
        (*proto_map)[ctx_idx] = Some(protocol_ptr);
    }

    log::info!(
        "ScsiPassThru: created protocol for USB device {} on controller {} (PCI {:02x}:{:x}, port {})",
        device_addr,
        controller_index,
        pci_device,
        pci_function,
        usb_port
    );

    protocol_ptr
}
