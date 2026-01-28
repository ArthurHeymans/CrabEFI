//! EFI Memory Attribute Protocol
//!
//! This protocol provides retrieval and update services for memory attributes.
//! It allows querying and modifying memory protection attributes (read/write/execute).
//!
//! Reference: UEFI Specification 2.10, Section 7.2

use r_efi::efi::{Guid, PhysicalAddress, Status};

use crate::efi::allocator::{allocate_pool, MemoryType};

/// Memory Attribute Protocol GUID
/// {f4560cf6-40ec-4b4a-a192-bf1d57d0b189}
pub const MEMORY_ATTRIBUTE_PROTOCOL_GUID: Guid = Guid::from_fields(
    0xf4560cf6,
    0x40ec,
    0x4b4a,
    0xa1,
    0x92,
    &[0xbf, 0x1d, 0x57, 0xd0, 0xb1, 0x89],
);

/// Memory attribute bits
/// Read Protect - memory cannot be read
pub const EFI_MEMORY_RP: u64 = 0x0000000000002000;
/// Execute Protect (NX) - memory cannot be executed
pub const EFI_MEMORY_XP: u64 = 0x0000000000004000;
/// Read Only - memory cannot be written
pub const EFI_MEMORY_RO: u64 = 0x0000000000020000;

/// Mask of all valid memory protection attributes
pub const EFI_MEMORY_ACCESS_MASK: u64 = EFI_MEMORY_RP | EFI_MEMORY_XP | EFI_MEMORY_RO;

/// EFI Memory Attribute Protocol structure
#[repr(C)]
pub struct Protocol {
    pub get_memory_attributes: extern "efiapi" fn(
        this: *mut Protocol,
        base_address: PhysicalAddress,
        length: u64,
        attributes: *mut u64,
    ) -> Status,
    pub set_memory_attributes: extern "efiapi" fn(
        this: *mut Protocol,
        base_address: PhysicalAddress,
        length: u64,
        attributes: u64,
    ) -> Status,
    pub clear_memory_attributes: extern "efiapi" fn(
        this: *mut Protocol,
        base_address: PhysicalAddress,
        length: u64,
        attributes: u64,
    ) -> Status,
}

/// Get memory attributes for a region
///
/// This stub implementation returns 0 (read-write-execute) for all memory,
/// since we don't track per-page attributes.
extern "efiapi" fn get_memory_attributes(
    _this: *mut Protocol,
    base_address: PhysicalAddress,
    length: u64,
    attributes: *mut u64,
) -> Status {
    log::debug!(
        "MemAttr.GetMemoryAttributes(base={:#x}, len={:#x})",
        base_address,
        length
    );

    if length == 0 {
        log::debug!("  -> INVALID_PARAMETER (length is 0)");
        return Status::INVALID_PARAMETER;
    }

    if attributes.is_null() {
        log::debug!("  -> INVALID_PARAMETER (attributes is null)");
        return Status::INVALID_PARAMETER;
    }

    // Return 0 = no protection attributes (read-write-execute allowed)
    // This is the default for conventional memory
    unsafe {
        *attributes = 0;
    }

    log::debug!("  -> SUCCESS (attributes=0x0)");
    Status::SUCCESS
}

/// Set memory attributes for a region
///
/// This stub implementation logs the request but doesn't modify page tables.
/// Returns SUCCESS to allow the bootloader to proceed.
extern "efiapi" fn set_memory_attributes(
    _this: *mut Protocol,
    base_address: PhysicalAddress,
    length: u64,
    attributes: u64,
) -> Status {
    log::debug!(
        "MemAttr.SetMemoryAttributes(base={:#x}, len={:#x}, attr={:#x})",
        base_address,
        length,
        attributes
    );

    if length == 0 {
        log::debug!("  -> INVALID_PARAMETER (length is 0)");
        return Status::INVALID_PARAMETER;
    }

    if attributes == 0 {
        log::debug!("  -> INVALID_PARAMETER (attributes is 0)");
        return Status::INVALID_PARAMETER;
    }

    // Validate that only valid attribute bits are set
    if (attributes & !EFI_MEMORY_ACCESS_MASK) != 0 {
        log::debug!("  -> INVALID_PARAMETER (invalid attribute bits)");
        return Status::INVALID_PARAMETER;
    }

    // Log what attributes are being set
    let mut attr_str = heapless::String::<64>::new();
    if attributes & EFI_MEMORY_RP != 0 {
        let _ = attr_str.push_str("RP ");
    }
    if attributes & EFI_MEMORY_XP != 0 {
        let _ = attr_str.push_str("XP ");
    }
    if attributes & EFI_MEMORY_RO != 0 {
        let _ = attr_str.push_str("RO ");
    }
    log::debug!("  -> SUCCESS (stubbed, requested: {})", attr_str.as_str());

    // In a full implementation, we would modify page table entries here
    // to set the appropriate protection bits (NX, read-only, etc.)
    // For now, we just return success to allow the bootloader to proceed.

    Status::SUCCESS
}

/// Clear memory attributes for a region
///
/// This stub implementation logs the request but doesn't modify page tables.
/// Returns SUCCESS to allow the bootloader to proceed.
extern "efiapi" fn clear_memory_attributes(
    _this: *mut Protocol,
    base_address: PhysicalAddress,
    length: u64,
    attributes: u64,
) -> Status {
    log::debug!(
        "MemAttr.ClearMemoryAttributes(base={:#x}, len={:#x}, attr={:#x})",
        base_address,
        length,
        attributes
    );

    if length == 0 {
        log::debug!("  -> INVALID_PARAMETER (length is 0)");
        return Status::INVALID_PARAMETER;
    }

    // Validate that only valid attribute bits are set
    if (attributes & !EFI_MEMORY_ACCESS_MASK) != 0 {
        log::debug!("  -> INVALID_PARAMETER (invalid attribute bits)");
        return Status::INVALID_PARAMETER;
    }

    // Log what attributes are being cleared
    let mut attr_str = heapless::String::<64>::new();
    if attributes & EFI_MEMORY_RP != 0 {
        let _ = attr_str.push_str("RP ");
    }
    if attributes & EFI_MEMORY_XP != 0 {
        let _ = attr_str.push_str("XP ");
    }
    if attributes & EFI_MEMORY_RO != 0 {
        let _ = attr_str.push_str("RO ");
    }
    log::debug!("  -> SUCCESS (stubbed, clearing: {})", attr_str.as_str());

    Status::SUCCESS
}

/// Create and initialize the Memory Attribute Protocol
///
/// # Returns
/// A pointer to the protocol instance, or null on allocation failure
pub fn create_protocol() -> *mut Protocol {
    let size = core::mem::size_of::<Protocol>();

    let ptr = match allocate_pool(MemoryType::BootServicesData, size) {
        Ok(p) => p as *mut Protocol,
        Err(_) => {
            log::error!("Failed to allocate MemoryAttributeProtocol");
            return core::ptr::null_mut();
        }
    };

    unsafe {
        (*ptr).get_memory_attributes = get_memory_attributes;
        (*ptr).set_memory_attributes = set_memory_attributes;
        (*ptr).clear_memory_attributes = clear_memory_attributes;
    }

    log::info!("MemoryAttributeProtocol created");
    ptr
}
