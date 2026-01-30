//! EFI Storage Security Command Protocol
//!
//! This module implements the EFI_STORAGE_SECURITY_COMMAND_PROTOCOL which provides
//! a unified interface for TCG Opal and other security operations across all storage
//! types (NVMe, SATA/AHCI, USB SCSI).
//!
//! The protocol abstracts the underlying storage-specific security commands:
//! - NVMe: Security Send (0x81) / Security Receive (0x82)
//! - ATA/SATA: TRUSTED SEND (0x5E) / TRUSTED RECEIVE (0x5C)
//! - SCSI: SECURITY PROTOCOL OUT (0xB5) / SECURITY PROTOCOL IN (0xA2)

use core::ffi::c_void;

use r_efi::efi::{Guid, Status};

use crate::drivers::{ahci, nvme, usb};
use crate::efi::utils::allocate_protocol_with_log;

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

/// Storage type enumeration for internal dispatch
#[derive(Clone, Copy, Debug)]
pub enum StorageType {
    /// NVMe storage with controller index and namespace ID
    Nvme {
        controller_index: usize,
        nsid: u32,
    },
    /// AHCI/SATA storage with controller index and port number
    Ahci {
        controller_index: usize,
        port: usize,
    },
    /// USB Mass Storage with device index
    UsbScsi {
        device_index: usize,
    },
}

/// Storage Security Command Protocol
///
/// This protocol provides security protocol commands for storage devices.
/// It is used by TCG Opal and other security subsystems.
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

/// Internal context for Storage Security protocol instance
struct StorageSecurityContext {
    /// Media ID (for validation)
    media_id: u32,
    /// Storage type and device identifier
    storage_type: StorageType,
}

/// Maximum number of Storage Security protocol instances
const MAX_INSTANCES: usize = 16;

/// Global storage for contexts
static mut CONTEXTS: [Option<StorageSecurityContext>; MAX_INSTANCES] = [const { None }; MAX_INSTANCES];

/// Protocol instance to context mapping
static mut PROTOCOL_TO_CONTEXT: [Option<*mut StorageSecurityCommandProtocol>; MAX_INSTANCES] =
    [const { None }; MAX_INSTANCES];

/// Find context index for a protocol instance
fn find_context_index(protocol: *mut StorageSecurityCommandProtocol) -> Option<usize> {
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
fn get_context(protocol: *mut StorageSecurityCommandProtocol) -> Option<&'static StorageSecurityContext> {
    let idx = find_context_index(protocol)?;
    unsafe {
        let contexts = core::ptr::addr_of!(CONTEXTS);
        (*contexts)[idx].as_ref()
    }
}

/// Receive data from security subsystem
///
/// # Arguments
/// * `this` - Protocol instance
/// * `media_id` - Media ID (must match the device)
/// * `timeout` - Timeout in 100ns units (0 = wait forever)
/// * `security_protocol_id` - Security Protocol ID (0x00=enumerate, 0x01=TCG, 0xEE=IEEE 1667)
/// * `security_protocol_specific` - Protocol-specific value (e.g., ComID for TCG)
/// * `payload_buffer_size` - Size of the payload buffer
/// * `payload_buffer` - Buffer to receive data
/// * `payload_transfer_size` - Actual bytes transferred (output)
extern "efiapi" fn storage_security_receive_data(
    this: *mut StorageSecurityCommandProtocol,
    media_id: u32,
    _timeout: u64,
    security_protocol_id: u8,
    security_protocol_specific: u16,
    payload_buffer_size: usize,
    payload_buffer: *mut c_void,
    payload_transfer_size: *mut usize,
) -> Status {
    log::debug!(
        "StorageSecurity.ReceiveData(protocol={:#x}, sp_specific={:#x}, size={})",
        security_protocol_id,
        security_protocol_specific,
        payload_buffer_size
    );

    if this.is_null() || payload_buffer.is_null() || payload_transfer_size.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let ctx = match get_context(this) {
        Some(c) => c,
        None => {
            log::error!("StorageSecurity.ReceiveData: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    // Verify media ID
    if media_id != ctx.media_id {
        log::debug!(
            "StorageSecurity.ReceiveData: media_id mismatch ({} vs {})",
            media_id,
            ctx.media_id
        );
        return Status::MEDIA_CHANGED;
    }

    // Create buffer slice
    let buffer = unsafe {
        core::slice::from_raw_parts_mut(payload_buffer as *mut u8, payload_buffer_size)
    };

    // Dispatch based on storage type
    let result = match ctx.storage_type {
        StorageType::Nvme { controller_index, nsid } => {
            nvme_security_receive(controller_index, nsid, security_protocol_id, security_protocol_specific, buffer)
        }
        StorageType::Ahci { controller_index, port } => {
            ahci_security_receive(controller_index, port, security_protocol_id, security_protocol_specific, buffer)
        }
        StorageType::UsbScsi { device_index } => {
            usb_security_receive(device_index, security_protocol_id, security_protocol_specific, buffer)
        }
    };

    match result {
        Ok(bytes_transferred) => {
            unsafe { *payload_transfer_size = bytes_transferred };
            log::debug!("StorageSecurity.ReceiveData: transferred {} bytes", bytes_transferred);
            Status::SUCCESS
        }
        Err(e) => {
            log::error!("StorageSecurity.ReceiveData: failed: {:?}", e);
            Status::DEVICE_ERROR
        }
    }
}

/// Send data to security subsystem
///
/// # Arguments
/// * `this` - Protocol instance
/// * `media_id` - Media ID (must match the device)
/// * `timeout` - Timeout in 100ns units (0 = wait forever)
/// * `security_protocol_id` - Security Protocol ID (0x00=enumerate, 0x01=TCG, 0xEE=IEEE 1667)
/// * `security_protocol_specific` - Protocol-specific value (e.g., ComID for TCG)
/// * `payload_buffer_size` - Size of the payload buffer
/// * `payload_buffer` - Buffer containing data to send
extern "efiapi" fn storage_security_send_data(
    this: *mut StorageSecurityCommandProtocol,
    media_id: u32,
    _timeout: u64,
    security_protocol_id: u8,
    security_protocol_specific: u16,
    payload_buffer_size: usize,
    payload_buffer: *const c_void,
) -> Status {
    log::debug!(
        "StorageSecurity.SendData(protocol={:#x}, sp_specific={:#x}, size={})",
        security_protocol_id,
        security_protocol_specific,
        payload_buffer_size
    );

    if this.is_null() || (payload_buffer_size > 0 && payload_buffer.is_null()) {
        return Status::INVALID_PARAMETER;
    }

    let ctx = match get_context(this) {
        Some(c) => c,
        None => {
            log::error!("StorageSecurity.SendData: unknown protocol instance");
            return Status::INVALID_PARAMETER;
        }
    };

    // Verify media ID
    if media_id != ctx.media_id {
        log::debug!(
            "StorageSecurity.SendData: media_id mismatch ({} vs {})",
            media_id,
            ctx.media_id
        );
        return Status::MEDIA_CHANGED;
    }

    // Create buffer slice
    let buffer = unsafe {
        core::slice::from_raw_parts(payload_buffer as *const u8, payload_buffer_size)
    };

    // Dispatch based on storage type
    let result = match ctx.storage_type {
        StorageType::Nvme { controller_index, nsid } => {
            nvme_security_send(controller_index, nsid, security_protocol_id, security_protocol_specific, buffer)
        }
        StorageType::Ahci { controller_index, port } => {
            ahci_security_send(controller_index, port, security_protocol_id, security_protocol_specific, buffer)
        }
        StorageType::UsbScsi { device_index } => {
            usb_security_send(device_index, security_protocol_id, security_protocol_specific, buffer)
        }
    };

    match result {
        Ok(()) => {
            log::debug!("StorageSecurity.SendData: success");
            Status::SUCCESS
        }
        Err(e) => {
            log::error!("StorageSecurity.SendData: failed: {:?}", e);
            Status::DEVICE_ERROR
        }
    }
}

// ============================================================================
// NVMe Security Commands
// ============================================================================

/// NVMe Security Receive (admin opcode 0x82)
fn nvme_security_receive(
    controller_index: usize,
    nsid: u32,
    protocol_id: u8,
    sp_specific: u16,
    buffer: &mut [u8],
) -> Result<usize, &'static str> {
    let controller = nvme::get_controller(controller_index)
        .ok_or("NVMe controller not found")?;
    
    controller.security_receive(nsid, protocol_id, sp_specific, buffer)
        .map_err(|_| "NVMe security receive failed")
}

/// NVMe Security Send (admin opcode 0x81)
fn nvme_security_send(
    controller_index: usize,
    nsid: u32,
    protocol_id: u8,
    sp_specific: u16,
    buffer: &[u8],
) -> Result<(), &'static str> {
    let controller = nvme::get_controller(controller_index)
        .ok_or("NVMe controller not found")?;
    
    controller.security_send(nsid, protocol_id, sp_specific, buffer)
        .map_err(|_| "NVMe security send failed")
}

// ============================================================================
// AHCI/SATA Security Commands (ATA TRUSTED SEND/RECEIVE)
// ============================================================================

/// AHCI TRUSTED RECEIVE (ATA command 0x5C)
fn ahci_security_receive(
    controller_index: usize,
    port: usize,
    protocol_id: u8,
    sp_specific: u16,
    buffer: &mut [u8],
) -> Result<usize, &'static str> {
    let controller = ahci::get_controller(controller_index)
        .ok_or("AHCI controller not found")?;
    
    controller.trusted_receive(port, protocol_id, sp_specific, buffer)
        .map_err(|_| "AHCI trusted receive failed")
}

/// AHCI TRUSTED SEND (ATA command 0x5E)
fn ahci_security_send(
    controller_index: usize,
    port: usize,
    protocol_id: u8,
    sp_specific: u16,
    buffer: &[u8],
) -> Result<(), &'static str> {
    let controller = ahci::get_controller(controller_index)
        .ok_or("AHCI controller not found")?;
    
    controller.trusted_send(port, protocol_id, sp_specific, buffer)
        .map_err(|_| "AHCI trusted send failed")
}

// ============================================================================
// USB SCSI Security Commands
// ============================================================================

/// USB SCSI SECURITY PROTOCOL IN (opcode 0xA2)
fn usb_security_receive(
    controller_index: usize,
    protocol_id: u8,
    sp_specific: u16,
    buffer: &mut [u8],
) -> Result<usize, &'static str> {
    // Execute with the USB controller
    let result = usb::with_controller(controller_index, |controller| {
        // Get the device address from the global mass storage
        let Some(device) = usb::mass_storage::get_global_device() else {
            return Err("No USB mass storage device configured");
        };

        // Call security_protocol_in on the device
        device.security_protocol_in(controller, protocol_id, sp_specific, buffer)
            .map_err(|_| "USB security protocol in failed")
    });

    match result {
        Some(Ok(bytes)) => Ok(bytes),
        Some(Err(e)) => Err(e),
        None => Err("USB controller not available"),
    }
}

/// USB SCSI SECURITY PROTOCOL OUT (opcode 0xB5)
fn usb_security_send(
    controller_index: usize,
    protocol_id: u8,
    sp_specific: u16,
    buffer: &[u8],
) -> Result<(), &'static str> {
    // Execute with the USB controller
    let result = usb::with_controller(controller_index, |controller| {
        // Get the device address from the global mass storage
        let Some(device) = usb::mass_storage::get_global_device() else {
            return Err("No USB mass storage device configured");
        };

        // Call security_protocol_out on the device
        device.security_protocol_out(controller, protocol_id, sp_specific, buffer)
            .map_err(|_| "USB security protocol out failed")
    });

    match result {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(e),
        None => Err("USB controller not available"),
    }
}

// ============================================================================
// Protocol Creation
// ============================================================================

/// Create a Storage Security Command Protocol instance
///
/// # Arguments
/// * `media_id` - Media ID for validation
/// * `storage_type` - Storage type and device identifier
///
/// # Returns
/// Pointer to the protocol instance, or null on failure
pub fn create_storage_security_protocol(
    media_id: u32,
    storage_type: StorageType,
) -> *mut StorageSecurityCommandProtocol {
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
                log::error!("StorageSecurity: no free context slots");
                return core::ptr::null_mut();
            }
        }
    };

    // Allocate protocol structure
    let protocol_ptr = allocate_protocol_with_log::<StorageSecurityCommandProtocol>(
        "StorageSecurityCommandProtocol",
        |p| {
            p.receive_data = storage_security_receive_data;
            p.send_data = storage_security_send_data;
        },
    );
    
    if protocol_ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Store context
    unsafe {
        let contexts = core::ptr::addr_of_mut!(CONTEXTS);
        (*contexts)[ctx_idx] = Some(StorageSecurityContext {
            media_id,
            storage_type,
        });
        let proto_map = core::ptr::addr_of_mut!(PROTOCOL_TO_CONTEXT);
        (*proto_map)[ctx_idx] = Some(protocol_ptr);
    }

    log::info!(
        "StorageSecurity: created protocol (media={}, type={:?})",
        media_id,
        storage_type
    );

    protocol_ptr
}
