//! EFI NVM Express Pass Through Protocol
//!
//! This module implements the EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL which provides
//! raw NVMe command access for applications requiring direct controller access.
//!
//! The protocol allows sending arbitrary admin and I/O commands to NVMe controllers,
//! which is necessary for TCG Opal self-encrypting drive management and other
//! advanced storage operations.

use core::ffi::c_void;

use r_efi::efi::{Event, Guid, Status};
use r_efi::protocols::device_path::Protocol as DevicePathProtocol;

use crate::drivers::nvme;
use crate::efi::protocols::device_path::{self, NvmeDevicePathNode};
use crate::efi::utils::allocate_protocol_with_log;

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

// ============================================================================
// Attribute Flags
// ============================================================================

/// Protocol supports physical NVMe devices
pub const ATTRIBUTES_PHYSICAL: u32 = 0x0001;
/// Protocol supports logical NVMe namespaces
pub const ATTRIBUTES_LOGICAL: u32 = 0x0002;
/// Protocol supports non-blocking I/O
pub const ATTRIBUTES_NONBLOCKIO: u32 = 0x0004;
/// Protocol supports NVM command set
pub const ATTRIBUTES_CMD_SET_NVM: u32 = 0x0008;

/// Queue type for admin commands
pub const NVME_ADMIN_QUEUE: u8 = 0x00;
/// Queue type for I/O commands  
pub const NVME_IO_QUEUE: u8 = 0x01;

// ============================================================================
// Protocol Data Structures
// ============================================================================

/// NVM Express Pass Thru Mode
///
/// Describes the capabilities of the NVMe Pass Thru protocol instance.
#[repr(C)]
pub struct NvmExpressPassThruMode {
    /// Attribute flags indicating protocol capabilities
    pub attributes: u32,
    /// I/O alignment requirement (must be power of 2)
    pub io_align: u32,
    /// NVMe version (from VS register)
    pub nvme_version: u32,
}

/// NVM Express Command Structure
///
/// Represents an NVMe command to be sent via pass-through.
#[repr(C)]
pub struct NvmExpressCommand {
    /// Command Dword 0: Opcode[7:0], Fused[9:8], Reserved[15:10], CID[31:16]
    pub cdw0: u32,
    /// Flags indicating which CDWs are valid
    pub flags: u8,
    /// Reserved
    pub _reserved: [u8; 3],
    /// Namespace ID
    pub nsid: u32,
    /// Command Dword 2
    pub cdw2: u32,
    /// Command Dword 3
    pub cdw3: u32,
    /// Command Dword 10
    pub cdw10: u32,
    /// Command Dword 11
    pub cdw11: u32,
    /// Command Dword 12
    pub cdw12: u32,
    /// Command Dword 13
    pub cdw13: u32,
    /// Command Dword 14
    pub cdw14: u32,
    /// Command Dword 15
    pub cdw15: u32,
}

/// NVM Express Completion Structure
///
/// Represents the completion status from an NVMe command.
#[repr(C)]
pub struct NvmExpressCompletion {
    /// Dword 0 - Command specific result
    pub dw0: u32,
    /// Dword 1 - Reserved
    pub dw1: u32,
    /// Dword 2 - SQ Head Pointer[15:0], SQ Identifier[31:16]
    pub dw2: u32,
    /// Dword 3 - CID[15:0], Phase[16], Status[31:17]
    pub dw3: u32,
}

/// NVM Express Pass Thru Command Packet
///
/// Contains all information needed to execute an NVMe command.
#[repr(C)]
pub struct NvmExpressPassThruCommandPacket {
    /// Timeout in 100ns units (0 = wait forever)
    pub command_timeout: u64,
    /// Transfer buffer for data
    pub transfer_buffer: *mut c_void,
    /// Transfer buffer length
    pub transfer_length: u32,
    /// Metadata buffer (optional)
    pub metadata_buffer: *mut c_void,
    /// Metadata buffer length
    pub metadata_length: u32,
    /// Queue type (NVME_ADMIN_QUEUE or NVME_IO_QUEUE)
    pub queue_type: u8,
    /// Reserved
    pub _reserved: [u8; 3],
    /// Pointer to NVMe command
    pub nvme_cmd: *mut NvmExpressCommand,
    /// Pointer to NVMe completion (output)
    pub nvme_completion: *mut NvmExpressCompletion,
}

/// NVM Express Pass Thru Protocol
#[repr(C)]
pub struct NvmExpressPassThruProtocol {
    /// Protocol mode information
    pub mode: *mut NvmExpressPassThruMode,
    /// Pass through function
    pub pass_thru: extern "efiapi" fn(
        this: *mut NvmExpressPassThruProtocol,
        namespace_id: u32,
        packet: *mut NvmExpressPassThruCommandPacket,
        event: Event,
    ) -> Status,
    /// Get next namespace function
    pub get_next_namespace: extern "efiapi" fn(
        this: *mut NvmExpressPassThruProtocol,
        namespace_id: *mut u32,
    ) -> Status,
    /// Build device path function
    pub build_device_path: extern "efiapi" fn(
        this: *mut NvmExpressPassThruProtocol,
        namespace_id: u32,
        device_path: *mut *mut DevicePathProtocol,
    ) -> Status,
    /// Get namespace from device path
    pub get_namespace: extern "efiapi" fn(
        this: *mut NvmExpressPassThruProtocol,
        device_path: *mut DevicePathProtocol,
        namespace_id: *mut u32,
    ) -> Status,
}

/// Internal context for NVMe Pass Thru protocol instance
struct NvmePassThruContext {
    /// Controller index in the global controller list
    controller_index: usize,
    /// PCI device number
    pci_device: u8,
    /// PCI function number
    pci_function: u8,
}

/// Maximum number of NVMe Pass Thru protocol instances
const MAX_INSTANCES: usize = 8;

/// Global storage for contexts
static mut CONTEXTS: [Option<NvmePassThruContext>; MAX_INSTANCES] = [const { None }; MAX_INSTANCES];

/// Protocol instance to context mapping
static mut PROTOCOL_TO_CONTEXT: [Option<*mut NvmExpressPassThruProtocol>; MAX_INSTANCES] =
    [const { None }; MAX_INSTANCES];

/// Find context index for a protocol instance
fn find_context_index(protocol: *mut NvmExpressPassThruProtocol) -> Option<usize> {
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
fn get_context(protocol: *mut NvmExpressPassThruProtocol) -> Option<&'static NvmePassThruContext> {
    let idx = find_context_index(protocol)?;
    unsafe {
        let contexts = core::ptr::addr_of!(CONTEXTS);
        (*contexts)[idx].as_ref()
    }
}

// ============================================================================
// Protocol Functions
// ============================================================================

/// Execute an NVMe command via pass-through
extern "efiapi" fn nvme_pass_thru(
    this: *mut NvmExpressPassThruProtocol,
    namespace_id: u32,
    packet: *mut NvmExpressPassThruCommandPacket,
    _event: Event,
) -> Status {
    if this.is_null() || packet.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx = match get_context(this) {
        Some(c) => c,
        None => {
            log::error!("NvmePassThru.PassThru: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    let packet = unsafe { &mut *packet };
    
    if packet.nvme_cmd.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let cmd = unsafe { &*packet.nvme_cmd };
    let opcode = (cmd.cdw0 & 0xFF) as u8;
    
    log::debug!(
        "NvmePassThru.PassThru: nsid={}, opcode={:#x}, queue_type={}",
        namespace_id,
        opcode,
        packet.queue_type
    );

    // Get the controller
    let controller = match nvme::get_controller(ctx.controller_index) {
        Some(c) => c,
        None => {
            log::error!("NvmePassThru.PassThru: controller not found");
            return Status::DEVICE_ERROR;
        }
    };

    // For now, we support a limited set of commands via the existing API
    // In a full implementation, we would submit raw commands to the queues
    
    // Check if this is a security command
    if packet.queue_type == NVME_ADMIN_QUEUE {
        match opcode {
            0x82 => {
                // Security Receive
                if !packet.transfer_buffer.is_null() && packet.transfer_length > 0 {
                    let buffer = unsafe {
                        core::slice::from_raw_parts_mut(
                            packet.transfer_buffer as *mut u8,
                            packet.transfer_length as usize,
                        )
                    };
                    let protocol_id = ((cmd.cdw10 >> 24) & 0xFF) as u8;
                    let sp_specific = (cmd.cdw10 & 0xFFFF) as u16;
                    
                    match controller.security_receive(namespace_id, protocol_id, sp_specific, buffer) {
                        Ok(bytes) => {
                            if !packet.nvme_completion.is_null() {
                                let completion = unsafe { &mut *packet.nvme_completion };
                                completion.dw0 = bytes as u32;
                                completion.dw1 = 0;
                                completion.dw2 = 0;
                                completion.dw3 = 0; // Success
                            }
                            return Status::SUCCESS;
                        }
                        Err(_) => return Status::DEVICE_ERROR,
                    }
                }
            }
            0x81 => {
                // Security Send
                if !packet.transfer_buffer.is_null() && packet.transfer_length > 0 {
                    let buffer = unsafe {
                        core::slice::from_raw_parts(
                            packet.transfer_buffer as *const u8,
                            packet.transfer_length as usize,
                        )
                    };
                    let protocol_id = ((cmd.cdw10 >> 24) & 0xFF) as u8;
                    let sp_specific = (cmd.cdw10 & 0xFFFF) as u16;
                    
                    match controller.security_send(namespace_id, protocol_id, sp_specific, buffer) {
                        Ok(()) => {
                            if !packet.nvme_completion.is_null() {
                                let completion = unsafe { &mut *packet.nvme_completion };
                                completion.dw0 = 0;
                                completion.dw1 = 0;
                                completion.dw2 = 0;
                                completion.dw3 = 0; // Success
                            }
                            return Status::SUCCESS;
                        }
                        Err(_) => return Status::DEVICE_ERROR,
                    }
                }
            }
            _ => {
                log::warn!("NvmePassThru: unsupported admin opcode {:#x}", opcode);
                return Status::UNSUPPORTED;
            }
        }
    } else {
        // I/O commands - for now just return unsupported
        log::warn!("NvmePassThru: I/O commands not yet implemented");
        return Status::UNSUPPORTED;
    }

    Status::INVALID_PARAMETER
}

/// Get the next namespace ID
///
/// Used to enumerate namespaces. Pass 0xFFFFFFFF to get the first namespace.
extern "efiapi" fn nvme_get_next_namespace(
    this: *mut NvmExpressPassThruProtocol,
    namespace_id: *mut u32,
) -> Status {
    if this.is_null() || namespace_id.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx = match get_context(this) {
        Some(c) => c,
        None => {
            log::error!("NvmePassThru.GetNextNamespace: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    let controller = match nvme::get_controller(ctx.controller_index) {
        Some(c) => c,
        None => {
            return Status::DEVICE_ERROR;
        }
    };

    let namespaces = controller.namespaces();
    let current_nsid = unsafe { *namespace_id };

    log::debug!(
        "NvmePassThru.GetNextNamespace: current={:#x}, total={}",
        current_nsid,
        namespaces.len()
    );

    if current_nsid == 0xFFFFFFFF {
        // Return first namespace
        if let Some(ns) = namespaces.first() {
            unsafe { *namespace_id = ns.nsid };
            return Status::SUCCESS;
        }
        return Status::NOT_FOUND;
    }

    // Find current namespace and return the next one
    for (i, ns) in namespaces.iter().enumerate() {
        if ns.nsid == current_nsid {
            if let Some(next) = namespaces.get(i + 1) {
                unsafe { *namespace_id = next.nsid };
                return Status::SUCCESS;
            }
            return Status::NOT_FOUND;
        }
    }

    Status::NOT_FOUND
}

/// Build a device path for a namespace
extern "efiapi" fn nvme_build_device_path(
    this: *mut NvmExpressPassThruProtocol,
    namespace_id: u32,
    device_path: *mut *mut DevicePathProtocol,
) -> Status {
    if this.is_null() || device_path.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx = match get_context(this) {
        Some(c) => c,
        None => {
            log::error!("NvmePassThru.BuildDevicePath: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    log::debug!(
        "NvmePassThru.BuildDevicePath: nsid={}",
        namespace_id
    );

    // Create NVMe device path
    let path = device_path::create_nvme_device_path(
        ctx.pci_device,
        ctx.pci_function,
        namespace_id,
    );

    if path.is_null() {
        return Status::OUT_OF_RESOURCES;
    }

    unsafe { *device_path = path };
    Status::SUCCESS
}

/// Get namespace ID from a device path
extern "efiapi" fn nvme_get_namespace(
    this: *mut NvmExpressPassThruProtocol,
    device_path: *mut DevicePathProtocol,
    namespace_id: *mut u32,
) -> Status {
    if this.is_null() || device_path.is_null() || namespace_id.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Parse the device path to find the NVMe node
    // Device path format: ACPI/PCI/NVMe/End
    let mut current = device_path;
    
    loop {
        let header = unsafe { &*current };
        
        // Check for end node
        if header.r#type == 0x7F {
            break;
        }
        
        // Check for NVMe namespace node (Type 0x03, SubType 0x17)
        if header.r#type == 0x03 && header.sub_type == 0x17 {
            let nvme_node = current as *const NvmeDevicePathNode;
            let nsid = unsafe { (*nvme_node).namespace_id };
            log::debug!("NvmePassThru.GetNamespace: found nsid={}", nsid);
            unsafe { *namespace_id = nsid };
            return Status::SUCCESS;
        }
        
        // Move to next node
        let length = u16::from_le_bytes(header.length) as usize;
        if length < 4 {
            break;
        }
        current = unsafe { (current as *const u8).add(length) as *mut DevicePathProtocol };
    }

    log::debug!("NvmePassThru.GetNamespace: no NVMe node found in device path");
    Status::NOT_FOUND
}

// ============================================================================
// Protocol Creation
// ============================================================================

/// Create an NVM Express Pass Thru Protocol instance
///
/// # Arguments
/// * `controller_index` - Index of the NVMe controller
/// * `pci_device` - PCI device number
/// * `pci_function` - PCI function number
///
/// # Returns
/// Pointer to the protocol instance, or null on failure
pub fn create_nvme_pass_thru_protocol(
    controller_index: usize,
    pci_device: u8,
    pci_function: u8,
) -> *mut NvmExpressPassThruProtocol {
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
                log::error!("NvmePassThru: no free context slots");
                return core::ptr::null_mut();
            }
        }
    };

    // Get controller to read version
    let nvme_version = match nvme::get_controller(controller_index) {
        Some(c) => c.nvme_version(),
        None => {
            log::error!("NvmePassThru: controller {} not found", controller_index);
            return core::ptr::null_mut();
        }
    };

    // Allocate mode structure
    let mode_ptr = allocate_protocol_with_log::<NvmExpressPassThruMode>(
        "NvmExpressPassThruMode",
        |m| {
            m.attributes = ATTRIBUTES_PHYSICAL | ATTRIBUTES_LOGICAL | ATTRIBUTES_CMD_SET_NVM;
            m.io_align = 4; // 4-byte alignment
            m.nvme_version = nvme_version;
        },
    );
    
    if mode_ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Allocate protocol structure
    let protocol_ptr = allocate_protocol_with_log::<NvmExpressPassThruProtocol>(
        "NvmExpressPassThruProtocol",
        |p| {
            p.mode = mode_ptr;
            p.pass_thru = nvme_pass_thru;
            p.get_next_namespace = nvme_get_next_namespace;
            p.build_device_path = nvme_build_device_path;
            p.get_namespace = nvme_get_namespace;
        },
    );
    
    if protocol_ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Store context
    unsafe {
        let contexts = core::ptr::addr_of_mut!(CONTEXTS);
        (*contexts)[ctx_idx] = Some(NvmePassThruContext {
            controller_index,
            pci_device,
            pci_function,
        });
        let proto_map = core::ptr::addr_of_mut!(PROTOCOL_TO_CONTEXT);
        (*proto_map)[ctx_idx] = Some(protocol_ptr);
    }

    log::info!(
        "NvmePassThru: created protocol for controller {} (PCI {:02x}:{:x}, NVMe version {:#x})",
        controller_index,
        pci_device,
        pci_function,
        nvme_version
    );

    protocol_ptr
}
