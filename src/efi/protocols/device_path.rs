//! EFI Device Path Protocol
//!
//! This module provides device path construction for boot devices.
//! A device path is a sequence of nodes describing the path to a device,
//! terminated by an End node.

use r_efi::efi::Guid;
use r_efi::protocols::device_path::{
    self, End, HardDriveMedia, Media, Protocol, TYPE_END, TYPE_MEDIA,
};

use crate::efi::allocator::{MemoryType, allocate_pool};

/// Re-export the GUID for external use
pub const DEVICE_PATH_PROTOCOL_GUID: Guid = device_path::PROTOCOL_GUID;

/// Signature type for GPT partitions
const SIGNATURE_TYPE_GUID: u8 = 0x02;

/// Partition format for GPT
const PARTITION_FORMAT_GPT: u8 = 0x02;

/// Device path for a hard drive partition (ESP)
///
/// This is a packed structure containing:
/// 1. HardDriveMedia node (describes the partition)
/// 2. End node (terminates the device path)
#[repr(C, packed)]
pub struct HardDriveDevicePath {
    pub hard_drive: HardDriveMedia,
    pub end: End,
}

/// Create a device path for a GPT hard drive partition (like the ESP)
///
/// # Arguments
/// * `partition_number` - The partition number (1-based)
/// * `partition_start` - Start LBA of the partition
/// * `partition_size` - Size of the partition in sectors
/// * `partition_guid` - The GPT partition GUID (unique identifier)
///
/// # Returns
/// A pointer to the device path protocol, or null on failure
pub fn create_hard_drive_device_path(
    partition_number: u32,
    partition_start: u64,
    partition_size: u64,
    partition_guid: &[u8; 16],
) -> *mut Protocol {
    let size = core::mem::size_of::<HardDriveDevicePath>();

    let ptr = match allocate_pool(MemoryType::BootServicesData, size) {
        Ok(p) => p as *mut HardDriveDevicePath,
        Err(_) => {
            log::error!("Failed to allocate device path");
            return core::ptr::null_mut();
        }
    };

    unsafe {
        init_hard_drive_node(
            core::ptr::addr_of_mut!((*ptr).hard_drive),
            partition_number,
            partition_start,
            partition_size,
            partition_guid,
        );
        init_end_node(core::ptr::addr_of_mut!((*ptr).end));
    }

    log::debug!(
        "Created HardDrive device path: partition={}, start={}, size={}",
        partition_number,
        partition_start,
        partition_size
    );

    ptr as *mut Protocol
}

/// USB device path for a USB mass storage device (whole disk)
///
/// Contains a USB Class node followed by an End node.
#[repr(C, packed)]
pub struct UsbDevicePath {
    /// USB device path node (Type 0x03, SubType 0x05)
    pub usb: UsbDevicePathNode,
    /// End node
    pub end: End,
}

/// USB Device Path Node (UEFI Spec 10.3.4.5)
#[repr(C, packed)]
pub struct UsbDevicePathNode {
    pub r#type: u8,
    pub sub_type: u8,
    pub length: [u8; 2],
    /// Parent port number
    pub parent_port: u8,
    /// USB interface number
    pub interface: u8,
}

/// ACPI device path for the PCI root bridge
#[repr(C, packed)]
pub struct AcpiDevicePathNode {
    pub r#type: u8,
    pub sub_type: u8,
    pub length: [u8; 2],
    pub hid: u32,
    pub uid: u32,
}

/// PCI device path node
#[repr(C, packed)]
pub struct PciDevicePathNode {
    pub r#type: u8,
    pub sub_type: u8,
    pub length: [u8; 2],
    pub function: u8,
    pub device: u8,
}

/// Full USB device path: ACPI + PCI + USB + End
#[repr(C, packed)]
pub struct FullUsbDevicePath {
    pub acpi: AcpiDevicePathNode,
    pub pci: PciDevicePathNode,
    pub usb: UsbDevicePathNode,
    pub end: End,
}

/// Type for Messaging device paths
const TYPE_MESSAGING: u8 = 0x03;
/// Sub-type for USB device path
const SUBTYPE_USB: u8 = 0x05;
/// Type for ACPI device paths
const TYPE_ACPI: u8 = 0x02;
/// Sub-type for ACPI device path
const SUBTYPE_ACPI: u8 = 0x01;
/// Type for Hardware device paths
const TYPE_HARDWARE: u8 = 0x01;
/// Sub-type for PCI device path
const SUBTYPE_PCI: u8 = 0x01;

/// PNP ID for PCI root bridge (ACPI HID: PNP0A03 or PNP0A08)
const EISA_PNP_ID_PCI_ROOT: u32 = 0x0a0341d0; // EISA ID for PNP0A03

// ============================================================================
// Node Initialization Helpers
// ============================================================================

/// Initialize an ACPI device path node for the PCI root bridge
///
/// # Safety
/// `node` must point to valid, writable memory of size `AcpiDevicePathNode`
#[inline]
unsafe fn init_acpi_node(node: *mut AcpiDevicePathNode, uid: u32) {
    (*node).r#type = TYPE_ACPI;
    (*node).sub_type = SUBTYPE_ACPI;
    (*node).length = (core::mem::size_of::<AcpiDevicePathNode>() as u16).to_le_bytes();
    (*node).hid = EISA_PNP_ID_PCI_ROOT;
    (*node).uid = uid;
}

/// Initialize a PCI device path node
///
/// # Safety
/// `node` must point to valid, writable memory of size `PciDevicePathNode`
#[inline]
unsafe fn init_pci_node(node: *mut PciDevicePathNode, device: u8, function: u8) {
    (*node).r#type = TYPE_HARDWARE;
    (*node).sub_type = SUBTYPE_PCI;
    (*node).length = (core::mem::size_of::<PciDevicePathNode>() as u16).to_le_bytes();
    (*node).device = device;
    (*node).function = function;
}

/// Initialize an End device path node
///
/// # Safety
/// `node` must point to valid, writable memory of size `End`
#[inline]
unsafe fn init_end_node(node: *mut End) {
    (*node).header.r#type = TYPE_END;
    (*node).header.sub_type = End::SUBTYPE_ENTIRE;
    (*node).header.length = (core::mem::size_of::<End>() as u16).to_le_bytes();
}

/// Initialize a HardDrive (partition) device path node
///
/// # Safety
/// `node` must point to valid, writable memory of size `HardDriveMedia`
#[inline]
unsafe fn init_hard_drive_node(
    node: *mut HardDriveMedia,
    partition_number: u32,
    partition_start: u64,
    partition_size: u64,
    partition_guid: &[u8; 16],
) {
    (*node).header.r#type = TYPE_MEDIA;
    (*node).header.sub_type = Media::SUBTYPE_HARDDRIVE;
    (*node).header.length = (core::mem::size_of::<HardDriveMedia>() as u16).to_le_bytes();
    (*node).partition_number = partition_number;
    (*node).partition_start = partition_start;
    (*node).partition_size = partition_size;
    (*node).partition_signature.copy_from_slice(partition_guid);
    (*node).partition_format = PARTITION_FORMAT_GPT;
    (*node).signature_type = SIGNATURE_TYPE_GUID;
}

/// Initialize a USB device path node
///
/// # Safety
/// `node` must point to valid, writable memory of size `UsbDevicePathNode`
#[inline]
unsafe fn init_usb_node(node: *mut UsbDevicePathNode, port: u8, interface: u8) {
    (*node).r#type = TYPE_MESSAGING;
    (*node).sub_type = SUBTYPE_USB;
    (*node).length = (core::mem::size_of::<UsbDevicePathNode>() as u16).to_le_bytes();
    (*node).parent_port = port;
    (*node).interface = interface;
}

/// Initialize an NVMe device path node
///
/// # Safety
/// `node` must point to valid, writable memory of size `NvmeDevicePathNode`
#[inline]
unsafe fn init_nvme_node(node: *mut NvmeDevicePathNode, namespace_id: u32) {
    (*node).r#type = TYPE_MESSAGING;
    (*node).sub_type = SUBTYPE_NVME;
    (*node).length = (core::mem::size_of::<NvmeDevicePathNode>() as u16).to_le_bytes();
    (*node).namespace_id = namespace_id;
    (*node).eui64 = [0; 8]; // EUI-64 is optional, use zeros
}

/// Initialize a SATA device path node
///
/// # Safety
/// `node` must point to valid, writable memory of size `SataDevicePathNode`
#[inline]
unsafe fn init_sata_node(node: *mut SataDevicePathNode, port: u16) {
    (*node).r#type = TYPE_MESSAGING;
    (*node).sub_type = SUBTYPE_SATA;
    (*node).length = (core::mem::size_of::<SataDevicePathNode>() as u16).to_le_bytes();
    (*node).hba_port = port;
    (*node).port_multiplier_port = 0xFFFF; // No port multiplier
    (*node).lun = 0;
}

/// Create a device path for a USB mass storage device (whole disk)
///
/// Creates a device path: ACPI(PNP0A03,0)/PCI(dev,func)/USB(port,0)/End
///
/// # Arguments
/// * `pci_device` - PCI device number of the xHCI controller
/// * `pci_function` - PCI function number
/// * `usb_port` - USB port number
///
/// # Returns
/// A pointer to the device path protocol, or null on failure
pub fn create_usb_device_path(pci_device: u8, pci_function: u8, usb_port: u8) -> *mut Protocol {
    let size = core::mem::size_of::<FullUsbDevicePath>();

    let ptr = match allocate_pool(MemoryType::BootServicesData, size) {
        Ok(p) => p as *mut FullUsbDevicePath,
        Err(_) => {
            log::error!("Failed to allocate USB device path");
            return core::ptr::null_mut();
        }
    };

    unsafe {
        init_acpi_node(core::ptr::addr_of_mut!((*ptr).acpi), 0);
        init_pci_node(
            core::ptr::addr_of_mut!((*ptr).pci),
            pci_device,
            pci_function,
        );
        init_usb_node(core::ptr::addr_of_mut!((*ptr).usb), usb_port, 0);
        init_end_node(core::ptr::addr_of_mut!((*ptr).end));
    }

    log::debug!(
        "Created USB device path: ACPI/PCI({:02x},{:x})/USB({},0)",
        pci_device,
        pci_function,
        usb_port
    );

    ptr as *mut Protocol
}

/// Full USB partition device path: ACPI + PCI + USB + HardDrive + End
///
/// This is the proper device path for a partition on a USB disk.
/// GRUB uses device path prefixes to match partitions to their parent disk.
#[repr(C, packed)]
pub struct FullUsbPartitionDevicePath {
    pub acpi: AcpiDevicePathNode,
    pub pci: PciDevicePathNode,
    pub usb: UsbDevicePathNode,
    pub hard_drive: HardDriveMedia,
    pub end: End,
}

/// Create a device path for a partition on a USB mass storage device
///
/// Creates a device path: ACPI(PNP0A03,0)/PCI(dev,func)/USB(port,0)/HD(part,...)/End
///
/// This is the proper hierarchical device path that allows GRUB to match
/// partitions to their parent disk.
///
/// # Arguments
/// * `pci_device` - PCI device number of the xHCI controller
/// * `pci_function` - PCI function number
/// * `usb_port` - USB port number
/// * `partition_number` - The partition number (1-based)
/// * `partition_start` - Start LBA of the partition
/// * `partition_size` - Size of the partition in sectors
/// * `partition_guid` - The GPT partition GUID (unique identifier)
///
/// # Returns
/// A pointer to the device path protocol, or null on failure
pub fn create_usb_partition_device_path(
    pci_device: u8,
    pci_function: u8,
    usb_port: u8,
    partition_number: u32,
    partition_start: u64,
    partition_size: u64,
    partition_guid: &[u8; 16],
) -> *mut Protocol {
    let size = core::mem::size_of::<FullUsbPartitionDevicePath>();

    let ptr = match allocate_pool(MemoryType::BootServicesData, size) {
        Ok(p) => p as *mut FullUsbPartitionDevicePath,
        Err(_) => {
            log::error!("Failed to allocate USB partition device path");
            return core::ptr::null_mut();
        }
    };

    unsafe {
        init_acpi_node(core::ptr::addr_of_mut!((*ptr).acpi), 0);
        init_pci_node(
            core::ptr::addr_of_mut!((*ptr).pci),
            pci_device,
            pci_function,
        );
        init_usb_node(core::ptr::addr_of_mut!((*ptr).usb), usb_port, 0);
        init_hard_drive_node(
            core::ptr::addr_of_mut!((*ptr).hard_drive),
            partition_number,
            partition_start,
            partition_size,
            partition_guid,
        );
        init_end_node(core::ptr::addr_of_mut!((*ptr).end));
    }

    log::debug!(
        "Created USB partition device path: ACPI/PCI({:02x},{:x})/USB({},0)/HD({},{},{})",
        pci_device,
        pci_function,
        usb_port,
        partition_number,
        partition_start,
        partition_size
    );

    ptr as *mut Protocol
}

/// Create a minimal "end-only" device path
///
/// This is the simplest possible device path, just an end node.
/// Some bootloaders accept this when they don't need detailed device info.
pub fn create_end_device_path() -> *mut Protocol {
    let size = core::mem::size_of::<End>();

    let ptr = match allocate_pool(MemoryType::BootServicesData, size) {
        Ok(p) => p as *mut End,
        Err(_) => {
            log::error!("Failed to allocate end device path");
            return core::ptr::null_mut();
        }
    };

    unsafe {
        (*ptr).header.r#type = TYPE_END;
        (*ptr).header.sub_type = End::SUBTYPE_ENTIRE;
        (*ptr).header.length = (size as u16).to_le_bytes();
    }

    log::debug!("Created minimal end-only device path");

    ptr as *mut Protocol
}

/// File path device path node for describing file locations
#[repr(C, packed)]
pub struct FilePathDevicePath {
    pub header: Protocol,
    // Path name follows (variable length, null-terminated UCS-2)
}

// ============================================================================
// NVMe Device Paths
// ============================================================================

/// NVMe Namespace Device Path Node (UEFI Spec 10.3.4.17)
#[repr(C, packed)]
pub struct NvmeDevicePathNode {
    pub r#type: u8,
    pub sub_type: u8,
    pub length: [u8; 2],
    /// Namespace Identifier (NSID)
    pub namespace_id: u32,
    /// IEEE Extended Unique Identifier (EUI-64)
    pub eui64: [u8; 8],
}

/// Sub-type for NVMe namespace device path
const SUBTYPE_NVME: u8 = 0x17;

/// Full NVMe device path: ACPI + PCI + NVMe + End
#[repr(C, packed)]
pub struct FullNvmeDevicePath {
    pub acpi: AcpiDevicePathNode,
    pub pci: PciDevicePathNode,
    pub nvme: NvmeDevicePathNode,
    pub end: End,
}

/// Full NVMe partition device path: ACPI + PCI + NVMe + HardDrive + End
#[repr(C, packed)]
pub struct FullNvmePartitionDevicePath {
    pub acpi: AcpiDevicePathNode,
    pub pci: PciDevicePathNode,
    pub nvme: NvmeDevicePathNode,
    pub hard_drive: HardDriveMedia,
    pub end: End,
}

/// Create a device path for an NVMe namespace (whole disk)
///
/// Creates a device path: ACPI(PNP0A03,0)/PCI(dev,func)/NVMe(nsid,eui64)/End
///
/// # Arguments
/// * `pci_device` - PCI device number of the NVMe controller
/// * `pci_function` - PCI function number
/// * `namespace_id` - NVMe namespace ID
///
/// # Returns
/// A pointer to the device path protocol, or null on failure
pub fn create_nvme_device_path(
    pci_device: u8,
    pci_function: u8,
    namespace_id: u32,
) -> *mut Protocol {
    let size = core::mem::size_of::<FullNvmeDevicePath>();

    let ptr = match allocate_pool(MemoryType::BootServicesData, size) {
        Ok(p) => p as *mut FullNvmeDevicePath,
        Err(_) => {
            log::error!("Failed to allocate NVMe device path");
            return core::ptr::null_mut();
        }
    };

    unsafe {
        init_acpi_node(core::ptr::addr_of_mut!((*ptr).acpi), 0);
        init_pci_node(
            core::ptr::addr_of_mut!((*ptr).pci),
            pci_device,
            pci_function,
        );
        init_nvme_node(core::ptr::addr_of_mut!((*ptr).nvme), namespace_id);
        init_end_node(core::ptr::addr_of_mut!((*ptr).end));
    }

    log::debug!(
        "Created NVMe device path: ACPI/PCI({:02x},{:x})/NVMe({})",
        pci_device,
        pci_function,
        namespace_id
    );

    ptr as *mut Protocol
}

/// Create a device path for a partition on an NVMe namespace
///
/// Creates a device path: ACPI(PNP0A03,0)/PCI(dev,func)/NVMe(nsid,eui64)/HD(part,...)/End
///
/// This is the proper hierarchical device path that allows GRUB to match
/// partitions to their parent disk.
///
/// # Arguments
/// * `pci_device` - PCI device number of the NVMe controller
/// * `pci_function` - PCI function number
/// * `namespace_id` - NVMe namespace ID
/// * `partition_number` - The partition number (1-based)
/// * `partition_start` - Start LBA of the partition
/// * `partition_size` - Size of the partition in sectors
/// * `partition_guid` - The GPT partition GUID (unique identifier)
///
/// # Returns
/// A pointer to the device path protocol, or null on failure
pub fn create_nvme_partition_device_path(
    pci_device: u8,
    pci_function: u8,
    namespace_id: u32,
    partition_number: u32,
    partition_start: u64,
    partition_size: u64,
    partition_guid: &[u8; 16],
) -> *mut Protocol {
    let size = core::mem::size_of::<FullNvmePartitionDevicePath>();

    let ptr = match allocate_pool(MemoryType::BootServicesData, size) {
        Ok(p) => p as *mut FullNvmePartitionDevicePath,
        Err(_) => {
            log::error!("Failed to allocate NVMe partition device path");
            return core::ptr::null_mut();
        }
    };

    unsafe {
        init_acpi_node(core::ptr::addr_of_mut!((*ptr).acpi), 0);
        init_pci_node(
            core::ptr::addr_of_mut!((*ptr).pci),
            pci_device,
            pci_function,
        );
        init_nvme_node(core::ptr::addr_of_mut!((*ptr).nvme), namespace_id);
        init_hard_drive_node(
            core::ptr::addr_of_mut!((*ptr).hard_drive),
            partition_number,
            partition_start,
            partition_size,
            partition_guid,
        );
        init_end_node(core::ptr::addr_of_mut!((*ptr).end));
    }

    log::debug!(
        "Created NVMe partition device path: ACPI/PCI({:02x},{:x})/NVMe({})/HD({},{},{})",
        pci_device,
        pci_function,
        namespace_id,
        partition_number,
        partition_start,
        partition_size
    );

    ptr as *mut Protocol
}

// ============================================================================
// SATA (AHCI) Device Paths
// ============================================================================

/// SATA Device Path Node (UEFI Spec 10.3.4.6)
#[repr(C, packed)]
pub struct SataDevicePathNode {
    pub r#type: u8,
    pub sub_type: u8,
    pub length: [u8; 2],
    /// HBA Port Number
    pub hba_port: u16,
    /// Port Multiplier Port Number (0xFFFF if no port multiplier)
    pub port_multiplier_port: u16,
    /// Logical Unit Number
    pub lun: u16,
}

/// Sub-type for SATA device path
const SUBTYPE_SATA: u8 = 0x12;

/// Full SATA device path: ACPI + PCI + SATA + End
#[repr(C, packed)]
pub struct FullSataDevicePath {
    pub acpi: AcpiDevicePathNode,
    pub pci: PciDevicePathNode,
    pub sata: SataDevicePathNode,
    pub end: End,
}

/// Full SATA partition device path: ACPI + PCI + SATA + HardDrive + End
#[repr(C, packed)]
pub struct FullSataPartitionDevicePath {
    pub acpi: AcpiDevicePathNode,
    pub pci: PciDevicePathNode,
    pub sata: SataDevicePathNode,
    pub hard_drive: HardDriveMedia,
    pub end: End,
}

/// Create a device path for a SATA device (whole disk)
///
/// Creates a device path: ACPI(PNP0A03,0)/PCI(dev,func)/SATA(port,0xFFFF,0)/End
///
/// # Arguments
/// * `pci_device` - PCI device number of the AHCI controller
/// * `pci_function` - PCI function number
/// * `port` - AHCI port number
///
/// # Returns
/// A pointer to the device path protocol, or null on failure
pub fn create_sata_device_path(pci_device: u8, pci_function: u8, port: u16) -> *mut Protocol {
    let size = core::mem::size_of::<FullSataDevicePath>();

    let ptr = match allocate_pool(MemoryType::BootServicesData, size) {
        Ok(p) => p as *mut FullSataDevicePath,
        Err(_) => {
            log::error!("Failed to allocate SATA device path");
            return core::ptr::null_mut();
        }
    };

    unsafe {
        init_acpi_node(core::ptr::addr_of_mut!((*ptr).acpi), 0);
        init_pci_node(
            core::ptr::addr_of_mut!((*ptr).pci),
            pci_device,
            pci_function,
        );
        init_sata_node(core::ptr::addr_of_mut!((*ptr).sata), port);
        init_end_node(core::ptr::addr_of_mut!((*ptr).end));
    }

    log::debug!(
        "Created SATA device path: ACPI/PCI({:02x},{:x})/SATA({})",
        pci_device,
        pci_function,
        port
    );

    ptr as *mut Protocol
}

/// Create a device path for a partition on a SATA device
///
/// Creates a device path: ACPI(PNP0A03,0)/PCI(dev,func)/SATA(port,0xFFFF,0)/HD(part,...)/End
///
/// # Arguments
/// * `pci_device` - PCI device number of the AHCI controller
/// * `pci_function` - PCI function number
/// * `port` - AHCI port number
/// * `partition_number` - The partition number (1-based)
/// * `partition_start` - Start LBA of the partition
/// * `partition_size` - Size of the partition in sectors
/// * `partition_guid` - The GPT partition GUID (unique identifier)
///
/// # Returns
/// A pointer to the device path protocol, or null on failure
pub fn create_sata_partition_device_path(
    pci_device: u8,
    pci_function: u8,
    port: u16,
    partition_number: u32,
    partition_start: u64,
    partition_size: u64,
    partition_guid: &[u8; 16],
) -> *mut Protocol {
    let size = core::mem::size_of::<FullSataPartitionDevicePath>();

    let ptr = match allocate_pool(MemoryType::BootServicesData, size) {
        Ok(p) => p as *mut FullSataPartitionDevicePath,
        Err(_) => {
            log::error!("Failed to allocate SATA partition device path");
            return core::ptr::null_mut();
        }
    };

    unsafe {
        init_acpi_node(core::ptr::addr_of_mut!((*ptr).acpi), 0);
        init_pci_node(
            core::ptr::addr_of_mut!((*ptr).pci),
            pci_device,
            pci_function,
        );
        init_sata_node(core::ptr::addr_of_mut!((*ptr).sata), port);
        init_hard_drive_node(
            core::ptr::addr_of_mut!((*ptr).hard_drive),
            partition_number,
            partition_start,
            partition_size,
            partition_guid,
        );
        init_end_node(core::ptr::addr_of_mut!((*ptr).end));
    }

    log::debug!(
        "Created SATA partition device path: ACPI/PCI({:02x},{:x})/SATA({})/HD({},{},{})",
        pci_device,
        pci_function,
        port,
        partition_number,
        partition_start,
        partition_size
    );

    ptr as *mut Protocol
}

// ============================================================================
// File Path Device Paths
// ============================================================================

/// Create a file path device path for a bootloader path like "\EFI\BOOT\BOOTX64.EFI"
///
/// # Arguments
/// * `path` - The file path (ASCII, will be converted to UCS-2)
///
/// # Returns
/// A pointer to the device path, or null on failure
pub fn create_file_path_device_path(path: &str) -> *mut Protocol {
    // Calculate size: header + path in UCS-2 (2 bytes per char) + null terminator + end node
    let path_size = (path.len() + 1) * 2; // UCS-2 with null terminator
    let file_node_size = 4 + path_size; // header (4 bytes) + path
    let end_size = core::mem::size_of::<End>();
    let total_size = file_node_size + end_size;

    let ptr = match allocate_pool(MemoryType::BootServicesData, total_size) {
        Ok(p) => p,
        Err(_) => {
            log::error!("Failed to allocate file path device path");
            return core::ptr::null_mut();
        }
    };

    unsafe {
        // File path node header
        *ptr.add(0) = TYPE_MEDIA;
        *ptr.add(1) = Media::SUBTYPE_FILE_PATH;
        let len_bytes = (file_node_size as u16).to_le_bytes();
        *ptr.add(2) = len_bytes[0];
        *ptr.add(3) = len_bytes[1];

        // Path in UCS-2 (simple ASCII to UCS-2 conversion)
        let path_ptr = ptr.add(4) as *mut u16;
        for (i, c) in path.chars().enumerate() {
            // Convert backslashes and handle ASCII chars
            let ch = if c == '/' { '\\' } else { c };
            *path_ptr.add(i) = ch as u16;
        }
        // Null terminator
        *path_ptr.add(path.len()) = 0;

        // End node
        let end_ptr = ptr.add(file_node_size);
        *end_ptr.add(0) = TYPE_END;
        *end_ptr.add(1) = End::SUBTYPE_ENTIRE;
        let end_len = (end_size as u16).to_le_bytes();
        *end_ptr.add(2) = end_len[0];
        *end_ptr.add(3) = end_len[1];
    }

    log::debug!("Created file path device path: {}", path);

    ptr as *mut Protocol
}

/// ACPI device path for video/graphics output
///
/// Contains just an ACPI node followed by End node.
/// This is used for the GOP handle to indicate it's a display device.
#[repr(C, packed)]
pub struct AcpiVideoDevicePath {
    pub acpi: AcpiDevicePathNode,
    pub end: End,
}

/// Create a device path for the video/graphics output device
///
/// Creates a simple ACPI device path: ACPI(PNP0A03,0)/End
/// This indicates the graphics output is on the PCI bus root.
/// GRUB needs a device path on the GOP handle to recognize it.
///
/// # Returns
/// A pointer to the device path protocol, or null on failure
pub fn create_video_device_path() -> *mut Protocol {
    let size = core::mem::size_of::<AcpiVideoDevicePath>();

    let ptr = match allocate_pool(MemoryType::BootServicesData, size) {
        Ok(p) => p as *mut AcpiVideoDevicePath,
        Err(_) => {
            log::error!("Failed to allocate video device path");
            return core::ptr::null_mut();
        }
    };

    unsafe {
        // ACPI node - using PCI root bridge HID
        // In a real system this would point to the actual GPU
        init_acpi_node(core::ptr::addr_of_mut!((*ptr).acpi), 0);
        init_end_node(core::ptr::addr_of_mut!((*ptr).end));
    }

    log::debug!("Created video device path: ACPI(PNP0A03,0)");

    ptr as *mut Protocol
}
