//! EFI Device Path Protocol
//!
//! This module provides device path construction for boot devices.
//! A device path is a sequence of nodes describing the path to a device,
//! terminated by an End node.

use r_efi::efi::Guid;
use r_efi::protocols::device_path::{
    self, End, HardDriveMedia, Media, Protocol, TYPE_END, TYPE_MEDIA,
};

use crate::efi::allocator::{allocate_pool, MemoryType};

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
        // Initialize HardDriveMedia node
        (*ptr).hard_drive.header.r#type = TYPE_MEDIA;
        (*ptr).hard_drive.header.sub_type = Media::SUBTYPE_HARDDRIVE;
        (*ptr).hard_drive.header.length =
            (core::mem::size_of::<HardDriveMedia>() as u16).to_le_bytes();
        (*ptr).hard_drive.partition_number = partition_number;
        (*ptr).hard_drive.partition_start = partition_start;
        (*ptr).hard_drive.partition_size = partition_size;
        (*ptr)
            .hard_drive
            .partition_signature
            .copy_from_slice(partition_guid);
        (*ptr).hard_drive.partition_format = PARTITION_FORMAT_GPT;
        (*ptr).hard_drive.signature_type = SIGNATURE_TYPE_GUID;

        // Initialize End node
        (*ptr).end.header.r#type = TYPE_END;
        (*ptr).end.header.sub_type = End::SUBTYPE_ENTIRE;
        (*ptr).end.header.length = (core::mem::size_of::<End>() as u16).to_le_bytes();
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
        // ACPI node for PCI root bridge
        (*ptr).acpi.r#type = TYPE_ACPI;
        (*ptr).acpi.sub_type = SUBTYPE_ACPI;
        (*ptr).acpi.length = (core::mem::size_of::<AcpiDevicePathNode>() as u16).to_le_bytes();
        (*ptr).acpi.hid = EISA_PNP_ID_PCI_ROOT;
        (*ptr).acpi.uid = 0;

        // PCI node for xHCI controller
        (*ptr).pci.r#type = TYPE_HARDWARE;
        (*ptr).pci.sub_type = SUBTYPE_PCI;
        (*ptr).pci.length = (core::mem::size_of::<PciDevicePathNode>() as u16).to_le_bytes();
        (*ptr).pci.function = pci_function;
        (*ptr).pci.device = pci_device;

        // USB node
        (*ptr).usb.r#type = TYPE_MESSAGING;
        (*ptr).usb.sub_type = SUBTYPE_USB;
        (*ptr).usb.length = (core::mem::size_of::<UsbDevicePathNode>() as u16).to_le_bytes();
        (*ptr).usb.parent_port = usb_port;
        (*ptr).usb.interface = 0;

        // End node
        (*ptr).end.header.r#type = TYPE_END;
        (*ptr).end.header.sub_type = End::SUBTYPE_ENTIRE;
        (*ptr).end.header.length = (core::mem::size_of::<End>() as u16).to_le_bytes();
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
        // ACPI node for PCI root bridge
        (*ptr).acpi.r#type = TYPE_ACPI;
        (*ptr).acpi.sub_type = SUBTYPE_ACPI;
        (*ptr).acpi.length = (core::mem::size_of::<AcpiDevicePathNode>() as u16).to_le_bytes();
        (*ptr).acpi.hid = EISA_PNP_ID_PCI_ROOT;
        (*ptr).acpi.uid = 0;

        // PCI node for xHCI controller
        (*ptr).pci.r#type = TYPE_HARDWARE;
        (*ptr).pci.sub_type = SUBTYPE_PCI;
        (*ptr).pci.length = (core::mem::size_of::<PciDevicePathNode>() as u16).to_le_bytes();
        (*ptr).pci.function = pci_function;
        (*ptr).pci.device = pci_device;

        // USB node
        (*ptr).usb.r#type = TYPE_MESSAGING;
        (*ptr).usb.sub_type = SUBTYPE_USB;
        (*ptr).usb.length = (core::mem::size_of::<UsbDevicePathNode>() as u16).to_le_bytes();
        (*ptr).usb.parent_port = usb_port;
        (*ptr).usb.interface = 0;

        // HardDrive node for partition
        (*ptr).hard_drive.header.r#type = TYPE_MEDIA;
        (*ptr).hard_drive.header.sub_type = Media::SUBTYPE_HARDDRIVE;
        (*ptr).hard_drive.header.length =
            (core::mem::size_of::<HardDriveMedia>() as u16).to_le_bytes();
        (*ptr).hard_drive.partition_number = partition_number;
        (*ptr).hard_drive.partition_start = partition_start;
        (*ptr).hard_drive.partition_size = partition_size;
        (*ptr)
            .hard_drive
            .partition_signature
            .copy_from_slice(partition_guid);
        (*ptr).hard_drive.partition_format = PARTITION_FORMAT_GPT;
        (*ptr).hard_drive.signature_type = SIGNATURE_TYPE_GUID;

        // End node
        (*ptr).end.header.r#type = TYPE_END;
        (*ptr).end.header.sub_type = End::SUBTYPE_ENTIRE;
        (*ptr).end.header.length = (core::mem::size_of::<End>() as u16).to_le_bytes();
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
        Ok(p) => p as *mut u8,
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
