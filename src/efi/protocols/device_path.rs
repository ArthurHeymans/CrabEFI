//! EFI Device Path Protocol
//!
//! This module provides device path construction for boot devices.
//! A device path is a sequence of nodes describing the path to a device,
//! terminated by an End node.

use core::ptr;

use r_efi::efi::Guid;
use r_efi::protocols::device_path::{
    self, End, HardDriveMedia, Media, Protocol, TYPE_END, TYPE_MEDIA,
};

use crate::efi::allocator::{MemoryType, allocate_pool};

/// Allocate a device path on the EFI heap and write a stack-built value into it.
///
/// This is the shared helper for all fixed-size device path constructors.
/// The value is `Copy` so it can be written via `ptr::write` without drop issues.
///
/// # Returns
/// A pointer to the device path protocol, or null on allocation failure.
fn allocate_device_path<T: Copy>(value: T) -> *mut Protocol {
    let size = core::mem::size_of::<T>();
    let dest = match allocate_pool(MemoryType::BootServicesData, size) {
        Ok(p) => p as *mut T,
        Err(_) => {
            log::error!("Failed to allocate device path ({} bytes)", size);
            return core::ptr::null_mut();
        }
    };
    // Safety: dest points to valid, properly aligned memory of sufficient size
    unsafe { ptr::write(dest, value) };
    dest as *mut Protocol
}

/// Re-export the GUID for external use
pub const DEVICE_PATH_PROTOCOL_GUID: Guid = device_path::PROTOCOL_GUID;

/// No partition signature (e.g., El Torito / synthetic partitions)
const SIGNATURE_TYPE_NONE: u8 = 0x00;

/// Signature type for GPT partitions
const SIGNATURE_TYPE_GUID: u8 = 0x02;

/// No defined partition format
const PARTITION_FORMAT_NONE: u8 = 0x00;

/// Partition format for GPT
const PARTITION_FORMAT_GPT: u8 = 0x02;

/// Device path for a hard drive partition (ESP)
///
/// This is a packed structure containing:
/// 1. HardDriveMedia node (describes the partition)
/// 2. End node (terminates the device path)
#[repr(C, packed)]
#[derive(Clone, Copy)]
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
    let dp = HardDriveDevicePath {
        hard_drive: create_hard_drive_node(
            partition_number,
            partition_start,
            partition_size,
            partition_guid,
        ),
        end: create_end_node(),
    };
    log::debug!(
        "Created HardDrive device path: partition={}, start={}, size={}",
        partition_number,
        partition_start,
        partition_size
    );
    allocate_device_path(dp)
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
#[derive(Clone, Copy)]
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
#[derive(Clone, Copy)]
pub struct AcpiDevicePathNode {
    pub r#type: u8,
    pub sub_type: u8,
    pub length: [u8; 2],
    pub hid: u32,
    pub uid: u32,
}

/// PCI device path node
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PciDevicePathNode {
    pub r#type: u8,
    pub sub_type: u8,
    pub length: [u8; 2],
    pub function: u8,
    pub device: u8,
}

/// Full USB device path: ACPI + PCI + USB + End
#[repr(C, packed)]
#[derive(Clone, Copy)]
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
// Safe Node Constructors
// ============================================================================

impl AcpiDevicePathNode {
    /// Create an ACPI device path node for the PCI root bridge
    #[inline]
    const fn new(uid: u32) -> Self {
        Self {
            r#type: TYPE_ACPI,
            sub_type: SUBTYPE_ACPI,
            length: (core::mem::size_of::<Self>() as u16).to_le_bytes(),
            hid: EISA_PNP_ID_PCI_ROOT,
            uid,
        }
    }
}

impl PciDevicePathNode {
    /// Create a PCI device path node
    #[inline]
    const fn new(device: u8, function: u8) -> Self {
        Self {
            r#type: TYPE_HARDWARE,
            sub_type: SUBTYPE_PCI,
            length: (core::mem::size_of::<Self>() as u16).to_le_bytes(),
            device,
            function,
        }
    }
}

impl UsbDevicePathNode {
    /// Create a USB device path node
    #[inline]
    const fn new(port: u8, interface: u8) -> Self {
        Self {
            r#type: TYPE_MESSAGING,
            sub_type: SUBTYPE_USB,
            length: (core::mem::size_of::<Self>() as u16).to_le_bytes(),
            parent_port: port,
            interface,
        }
    }
}

/// Create an End device path node (safe)
#[inline]
const fn create_end_node() -> End {
    End {
        header: Protocol {
            r#type: TYPE_END,
            sub_type: End::SUBTYPE_ENTIRE,
            length: (core::mem::size_of::<End>() as u16).to_le_bytes(),
        },
    }
}

/// Create a HardDrive (partition) device path node (safe)
#[inline]
fn create_hard_drive_node(
    partition_number: u32,
    partition_start: u64,
    partition_size: u64,
    partition_guid: &[u8; 16],
) -> HardDriveMedia {
    // Use GPT signature type when we have a real partition GUID,
    // otherwise use no signature (e.g., El Torito synthetic partitions).
    let has_guid = partition_guid.iter().any(|&b| b != 0);
    let (sig_type, fmt) = if has_guid {
        (SIGNATURE_TYPE_GUID, PARTITION_FORMAT_GPT)
    } else {
        (SIGNATURE_TYPE_NONE, PARTITION_FORMAT_NONE)
    };

    let mut node = HardDriveMedia {
        header: Protocol {
            r#type: TYPE_MEDIA,
            sub_type: Media::SUBTYPE_HARDDRIVE,
            length: (core::mem::size_of::<HardDriveMedia>() as u16).to_le_bytes(),
        },
        partition_number,
        partition_start,
        partition_size,
        partition_signature: [0; 16],
        partition_format: fmt,
        signature_type: sig_type,
    };
    node.partition_signature.copy_from_slice(partition_guid);
    node
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
    let dp = FullUsbDevicePath {
        acpi: AcpiDevicePathNode::new(0),
        pci: PciDevicePathNode::new(pci_device, pci_function),
        usb: UsbDevicePathNode::new(usb_port, 0),
        end: create_end_node(),
    };
    log::debug!(
        "Created USB device path: ACPI/PCI({:02x},{:x})/USB({},0)",
        pci_device,
        pci_function,
        usb_port
    );
    allocate_device_path(dp)
}

/// Full USB partition device path: ACPI + PCI + USB + HardDrive + End
///
/// This is the proper device path for a partition on a USB disk.
/// GRUB uses device path prefixes to match partitions to their parent disk.
#[repr(C, packed)]
#[derive(Clone, Copy)]
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
    let dp = FullUsbPartitionDevicePath {
        acpi: AcpiDevicePathNode::new(0),
        pci: PciDevicePathNode::new(pci_device, pci_function),
        usb: UsbDevicePathNode::new(usb_port, 0),
        hard_drive: create_hard_drive_node(
            partition_number,
            partition_start,
            partition_size,
            partition_guid,
        ),
        end: create_end_node(),
    };
    log::debug!(
        "Created USB partition device path: ACPI/PCI({:02x},{:x})/USB({},0)/HD({},{},{})",
        pci_device,
        pci_function,
        usb_port,
        partition_number,
        partition_start,
        partition_size
    );
    allocate_device_path(dp)
}

/// Create a minimal "end-only" device path
///
/// This is the simplest possible device path, just an end node.
/// Some bootloaders accept this when they don't need detailed device info.
pub fn create_end_device_path() -> *mut Protocol {
    log::debug!("Created minimal end-only device path");
    allocate_device_path(create_end_node())
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
#[derive(Clone, Copy)]
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

impl NvmeDevicePathNode {
    /// Create an NVMe device path node
    #[inline]
    const fn new(namespace_id: u32) -> Self {
        Self {
            r#type: TYPE_MESSAGING,
            sub_type: SUBTYPE_NVME,
            length: (core::mem::size_of::<Self>() as u16).to_le_bytes(),
            namespace_id,
            eui64: [0; 8], // EUI-64 is optional, use zeros
        }
    }
}

/// Full NVMe device path: ACPI + PCI + NVMe + End
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FullNvmeDevicePath {
    pub acpi: AcpiDevicePathNode,
    pub pci: PciDevicePathNode,
    pub nvme: NvmeDevicePathNode,
    pub end: End,
}

/// Full NVMe partition device path: ACPI + PCI + NVMe + HardDrive + End
#[repr(C, packed)]
#[derive(Clone, Copy)]
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
    let dp = FullNvmeDevicePath {
        acpi: AcpiDevicePathNode::new(0),
        pci: PciDevicePathNode::new(pci_device, pci_function),
        nvme: NvmeDevicePathNode::new(namespace_id),
        end: create_end_node(),
    };
    log::debug!(
        "Created NVMe device path: ACPI/PCI({:02x},{:x})/NVMe({})",
        pci_device,
        pci_function,
        namespace_id
    );
    allocate_device_path(dp)
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
    let dp = FullNvmePartitionDevicePath {
        acpi: AcpiDevicePathNode::new(0),
        pci: PciDevicePathNode::new(pci_device, pci_function),
        nvme: NvmeDevicePathNode::new(namespace_id),
        hard_drive: create_hard_drive_node(
            partition_number,
            partition_start,
            partition_size,
            partition_guid,
        ),
        end: create_end_node(),
    };
    log::debug!(
        "Created NVMe partition device path: ACPI/PCI({:02x},{:x})/NVMe({})/HD({},{},{})",
        pci_device,
        pci_function,
        namespace_id,
        partition_number,
        partition_start,
        partition_size
    );
    allocate_device_path(dp)
}

// ============================================================================
// SATA (AHCI) Device Paths
// ============================================================================

/// SATA Device Path Node (UEFI Spec 10.3.4.6)
#[repr(C, packed)]
#[derive(Clone, Copy)]
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

impl SataDevicePathNode {
    /// Create a SATA device path node
    #[inline]
    const fn new(port: u16) -> Self {
        Self {
            r#type: TYPE_MESSAGING,
            sub_type: SUBTYPE_SATA,
            length: (core::mem::size_of::<Self>() as u16).to_le_bytes(),
            hba_port: port,
            port_multiplier_port: 0xFFFF, // No port multiplier
            lun: 0,
        }
    }
}

/// Full SATA device path: ACPI + PCI + SATA + End
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FullSataDevicePath {
    pub acpi: AcpiDevicePathNode,
    pub pci: PciDevicePathNode,
    pub sata: SataDevicePathNode,
    pub end: End,
}

/// Full SATA partition device path: ACPI + PCI + SATA + HardDrive + End
#[repr(C, packed)]
#[derive(Clone, Copy)]
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
    let dp = FullSataDevicePath {
        acpi: AcpiDevicePathNode::new(0),
        pci: PciDevicePathNode::new(pci_device, pci_function),
        sata: SataDevicePathNode::new(port),
        end: create_end_node(),
    };
    log::debug!(
        "Created SATA device path: ACPI/PCI({:02x},{:x})/SATA({})",
        pci_device,
        pci_function,
        port
    );
    allocate_device_path(dp)
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
    let dp = FullSataPartitionDevicePath {
        acpi: AcpiDevicePathNode::new(0),
        pci: PciDevicePathNode::new(pci_device, pci_function),
        sata: SataDevicePathNode::new(port),
        hard_drive: create_hard_drive_node(
            partition_number,
            partition_start,
            partition_size,
            partition_guid,
        ),
        end: create_end_node(),
    };
    log::debug!(
        "Created SATA partition device path: ACPI/PCI({:02x},{:x})/SATA({})/HD({},{},{})",
        pci_device,
        pci_function,
        port,
        partition_number,
        partition_start,
        partition_size
    );
    allocate_device_path(dp)
}

// ============================================================================
// CD-ROM Device Paths (El Torito)
// ============================================================================

/// CD-ROM Device Path Node (UEFI Spec 10.3.5.2)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CdromDevicePathNode {
    pub r#type: u8,
    pub sub_type: u8,
    pub length: [u8; 2],
    /// Boot Entry number from El Torito boot catalog
    pub boot_entry: u32,
    /// Starting LBA of the partition
    pub partition_start: u64,
    /// Size of the partition in blocks
    pub partition_size: u64,
}

/// Sub-type for CD-ROM device path (Media type)
const SUBTYPE_CDROM: u8 = 0x02;

impl CdromDevicePathNode {
    /// Create a CD-ROM device path node
    #[inline]
    const fn new(boot_entry: u32, partition_start: u64, partition_size: u64) -> Self {
        Self {
            r#type: TYPE_MEDIA,
            sub_type: SUBTYPE_CDROM,
            length: (core::mem::size_of::<Self>() as u16).to_le_bytes(),
            boot_entry,
            partition_start,
            partition_size,
        }
    }
}

/// Full SATA CD-ROM device path: ACPI + PCI + SATA + CDROM + End
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FullSataCdromDevicePath {
    pub acpi: AcpiDevicePathNode,
    pub pci: PciDevicePathNode,
    pub sata: SataDevicePathNode,
    pub cdrom: CdromDevicePathNode,
    pub end: End,
}

/// Create a device path for a CD-ROM El Torito boot image on SATA
///
/// Creates a device path: ACPI(PNP0A03,0)/PCI(dev,func)/SATA(port)/CDROM(entry,start,size)/End
///
/// This is used when booting from an ISO image via El Torito boot specification.
///
/// # Arguments
/// * `pci_device` - PCI device number of the AHCI controller
/// * `pci_function` - PCI function number
/// * `port` - AHCI port number
/// * `boot_entry` - El Torito boot catalog entry number
/// * `partition_start` - Start LBA of the boot image
/// * `partition_size` - Size of the boot image in blocks
///
/// # Returns
/// A pointer to the device path protocol, or null on failure
pub fn create_sata_cdrom_device_path(
    pci_device: u8,
    pci_function: u8,
    port: u16,
    boot_entry: u32,
    partition_start: u64,
    partition_size: u64,
) -> *mut Protocol {
    let dp = FullSataCdromDevicePath {
        acpi: AcpiDevicePathNode::new(0),
        pci: PciDevicePathNode::new(pci_device, pci_function),
        sata: SataDevicePathNode::new(port),
        cdrom: CdromDevicePathNode::new(boot_entry, partition_start, partition_size),
        end: create_end_node(),
    };
    log::debug!(
        "Created SATA CDROM device path: ACPI/PCI({:02x},{:x})/SATA({})/CDROM({},{},{})",
        pci_device,
        pci_function,
        port,
        boot_entry,
        partition_start,
        partition_size
    );
    allocate_device_path(dp)
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

/// Return the total byte length of a device path (including the End node).
///
/// Walks the node chain until the End-Entire node is found.
/// Returns 0 if the pointer is null or invalid.
fn device_path_size(dp: *const Protocol) -> usize {
    if dp.is_null() {
        return 0;
    }
    unsafe {
        let mut p = dp as *const u8;
        loop {
            let node_type = *p;
            let node_len = u16::from_le_bytes([*p.add(2), *p.add(3)]) as usize;
            if node_len < 4 {
                break 0;
            }
            if node_type == TYPE_END {
                return (p as usize - dp as usize) + node_len;
            }
            p = p.add(node_len);
        }
    }
}

/// Create a loaded image device path by appending a file path node to a device path.
///
/// This is used for `EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL`.
/// The result is: `<device_path_nodes> / FilePath(path) / End`
///
/// # Arguments
/// * `device_dp` - Device path of the device (partition) handle
/// * `file_path` - ASCII file path (e.g. `EFI\BOOT\BOOTX64.EFI`)
///
/// # Returns
/// A new device path, or null on failure
pub fn create_loaded_image_device_path(
    device_dp: *const Protocol,
    file_path: &str,
) -> *mut Protocol {
    if device_dp.is_null() {
        return create_file_path_device_path(file_path);
    }

    let dp_size = device_path_size(device_dp);
    if dp_size == 0 {
        return create_file_path_device_path(file_path);
    }

    // Size of the device path nodes WITHOUT the End node
    let end_size = core::mem::size_of::<End>();
    let dp_nodes_size = dp_size - end_size;

    // File path node: header(4) + UCS-2 path + null terminator
    let path_ucs2_size = (file_path.len() + 1) * 2;
    let file_node_size = 4 + path_ucs2_size;

    let total_size = dp_nodes_size + file_node_size + end_size;

    let ptr = match allocate_pool(MemoryType::BootServicesData, total_size) {
        Ok(p) => p,
        Err(_) => return ptr::null_mut(),
    };

    unsafe {
        // Copy device path nodes (without End)
        ptr::copy_nonoverlapping(device_dp as *const u8, ptr, dp_nodes_size);

        // Append file path node
        let fp = ptr.add(dp_nodes_size);
        *fp.add(0) = TYPE_MEDIA;
        *fp.add(1) = Media::SUBTYPE_FILE_PATH;
        let len_bytes = (file_node_size as u16).to_le_bytes();
        *fp.add(2) = len_bytes[0];
        *fp.add(3) = len_bytes[1];

        let path_ptr = fp.add(4) as *mut u16;
        for (i, c) in file_path.chars().enumerate() {
            let ch = if c == '/' { '\\' } else { c };
            *path_ptr.add(i) = ch as u16;
        }
        *path_ptr.add(file_path.len()) = 0;

        // Append End node
        let end = fp.add(file_node_size);
        *end.add(0) = TYPE_END;
        *end.add(1) = End::SUBTYPE_ENTIRE;
        let end_len = (end_size as u16).to_le_bytes();
        *end.add(2) = end_len[0];
        *end.add(3) = end_len[1];
    }

    ptr as *mut Protocol
}

/// ACPI device path for video/graphics output
///
/// Contains just an ACPI node followed by End node.
/// This is used for the GOP handle to indicate it's a display device.
#[repr(C, packed)]
#[derive(Clone, Copy)]
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
    let dp = AcpiVideoDevicePath {
        acpi: AcpiDevicePathNode::new(0),
        end: create_end_node(),
    };
    log::debug!("Created video device path: ACPI(PNP0A03,0)");
    allocate_device_path(dp)
}

// ============================================================================
// Unified Device Path Info (Driver Model)
// ============================================================================

/// Device-specific information needed to construct EFI device paths
///
/// This enum captures the differences between storage device types for
/// device path construction, allowing a single generic boot path to
/// work with any storage device.
#[derive(Debug, Clone, Copy)]
pub enum DevicePathInfo {
    /// NVMe namespace
    Nvme {
        pci_device: u8,
        pci_function: u8,
        namespace_id: u32,
    },
    /// AHCI/SATA port
    Ahci {
        pci_device: u8,
        pci_function: u8,
        port: u16,
    },
    /// USB mass storage
    Usb {
        pci_device: u8,
        pci_function: u8,
        usb_port: u8,
    },
    /// AHCI/SATA CD-ROM (El Torito)
    AhciCdrom {
        pci_device: u8,
        pci_function: u8,
        port: u16,
        /// El Torito boot catalog entry number (usually 0)
        boot_entry: u32,
        /// Start LBA of the El Torito boot image
        partition_start: u64,
        /// Size of the El Torito boot image in blocks
        partition_size: u64,
    },
    /// SDHCI (SD card) - uses USB device path with port=0
    Sdhci { pci_device: u8, pci_function: u8 },
}

/// Create a whole-disk device path from a DevicePathInfo
///
/// # Arguments
/// * `info` - Device-specific path information
///
/// # Returns
/// A pointer to the device path protocol, or null on failure
pub fn create_disk_device_path(info: &DevicePathInfo) -> *mut Protocol {
    match *info {
        DevicePathInfo::Nvme {
            pci_device,
            pci_function,
            namespace_id,
        } => create_nvme_device_path(pci_device, pci_function, namespace_id),
        DevicePathInfo::Ahci {
            pci_device,
            pci_function,
            port,
        } => create_sata_device_path(pci_device, pci_function, port),
        DevicePathInfo::AhciCdrom {
            pci_device,
            pci_function,
            port,
            ..
        } => create_sata_device_path(pci_device, pci_function, port),
        DevicePathInfo::Usb {
            pci_device,
            pci_function,
            usb_port,
        } => create_usb_device_path(pci_device, pci_function, usb_port),
        DevicePathInfo::Sdhci {
            pci_device,
            pci_function,
        } => create_usb_device_path(pci_device, pci_function, 0),
    }
}

/// Create a partition device path from a DevicePathInfo
///
/// # Arguments
/// * `info` - Device-specific path information
/// * `partition_number` - 1-based partition number
/// * `partition_start` - Start LBA of the partition
/// * `partition_size` - Size of the partition in sectors
/// * `partition_guid` - GPT partition GUID
///
/// # Returns
/// A pointer to the device path protocol, or null on failure
pub fn create_partition_device_path(
    info: &DevicePathInfo,
    partition_number: u32,
    partition_start: u64,
    partition_size: u64,
    partition_guid: &[u8; 16],
) -> *mut Protocol {
    match *info {
        DevicePathInfo::Nvme {
            pci_device,
            pci_function,
            namespace_id,
        } => create_nvme_partition_device_path(
            pci_device,
            pci_function,
            namespace_id,
            partition_number,
            partition_start,
            partition_size,
            partition_guid,
        ),
        DevicePathInfo::Ahci {
            pci_device,
            pci_function,
            port,
        } => create_sata_partition_device_path(
            pci_device,
            pci_function,
            port,
            partition_number,
            partition_start,
            partition_size,
            partition_guid,
        ),
        DevicePathInfo::AhciCdrom {
            pci_device,
            pci_function,
            port,
            boot_entry,
            partition_start: cdrom_start,
            partition_size: cdrom_size,
        } => create_sata_cdrom_device_path(
            pci_device,
            pci_function,
            port,
            boot_entry,
            cdrom_start,
            cdrom_size,
        ),
        DevicePathInfo::Usb {
            pci_device,
            pci_function,
            usb_port,
        } => create_usb_partition_device_path(
            pci_device,
            pci_function,
            usb_port,
            partition_number,
            partition_start,
            partition_size,
            partition_guid,
        ),
        DevicePathInfo::Sdhci {
            pci_device,
            pci_function,
        } => create_usb_partition_device_path(
            pci_device,
            pci_function,
            0,
            partition_number,
            partition_start,
            partition_size,
            partition_guid,
        ),
    }
}
