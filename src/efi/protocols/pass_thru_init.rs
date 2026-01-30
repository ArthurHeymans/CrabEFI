//! Pass-Through Protocol Initialization
//!
//! This module initializes pass-through protocols for all detected storage devices.
//! These protocols are used by TCG Opal and other security applications.

use core::ffi::c_void;

use crate::drivers::{ahci, nvme, usb};
use crate::efi::boot_services;
use crate::efi::protocols::ata_pass_thru::{self, ATA_PASS_THRU_GUID};
use crate::efi::protocols::device_path;
use crate::efi::protocols::nvme_pass_thru::{self, NVM_EXPRESS_PASS_THRU_GUID};
use crate::efi::protocols::scsi_pass_thru::{self, EXT_SCSI_PASS_THRU_GUID};
use crate::efi::protocols::storage_security::{self, StorageType, STORAGE_SECURITY_COMMAND_GUID};

/// Initialize all pass-through protocols for detected storage devices
///
/// This function should be called after storage drivers are initialized.
/// It creates protocol instances and installs them on device handles.
pub fn init() {
    log::info!("Initializing pass-through protocols...");

    init_nvme_pass_thru();
    init_ahci_pass_thru();
    init_usb_pass_thru();

    log::info!("Pass-through protocol initialization complete");
}

/// Initialize NVMe pass-through protocols
fn init_nvme_pass_thru() {
    // Iterate over all NVMe controllers
    for controller_index in 0..8 {
        let Some(controller) = nvme::get_controller(controller_index) else {
            break;
        };

        let pci_addr = controller.pci_address();
        let namespaces = controller.namespaces();

        if namespaces.is_empty() {
            continue;
        }

        log::info!(
            "Installing NVMe pass-through protocols for controller {} (PCI {:02x}:{:x})",
            controller_index,
            pci_addr.device,
            pci_addr.function
        );

        // Create a handle for the NVMe controller
        let controller_handle = match boot_services::create_handle() {
            Some(h) => h,
            None => {
                log::error!(
                    "Failed to create handle for NVMe controller {}",
                    controller_index
                );
                continue;
            }
        };

        // Install device path on controller handle
        let controller_device_path = device_path::create_nvme_device_path(
            pci_addr.device,
            pci_addr.function,
            0, // Controller-level device path (no specific namespace)
        );
        if !controller_device_path.is_null() {
            boot_services::install_protocol(
                controller_handle,
                &device_path::DEVICE_PATH_PROTOCOL_GUID,
                controller_device_path as *mut c_void,
            );
        }

        // Install NVM Express Pass Through Protocol on controller handle
        let pass_thru = nvme_pass_thru::create_nvme_pass_thru_protocol(
            controller_index,
            pci_addr.device,
            pci_addr.function,
        );
        if !pass_thru.is_null() {
            boot_services::install_protocol(
                controller_handle,
                &NVM_EXPRESS_PASS_THRU_GUID,
                pass_thru as *mut c_void,
            );
            log::debug!(
                "Installed NVM Express Pass Thru Protocol on handle {:?}",
                controller_handle
            );
        }

        // Install Storage Security Command Protocol on each namespace
        for ns in namespaces.iter() {
            // Create a handle for the namespace
            let ns_handle = match boot_services::create_handle() {
                Some(h) => h,
                None => {
                    log::error!("Failed to create handle for NVMe namespace {}", ns.nsid);
                    continue;
                }
            };

            // Install device path on namespace handle
            let ns_device_path =
                device_path::create_nvme_device_path(pci_addr.device, pci_addr.function, ns.nsid);
            if !ns_device_path.is_null() {
                boot_services::install_protocol(
                    ns_handle,
                    &device_path::DEVICE_PATH_PROTOCOL_GUID,
                    ns_device_path as *mut c_void,
                );
            }

            // Install Storage Security Command Protocol
            let storage_security = storage_security::create_storage_security_protocol(
                ns.nsid, // Use nsid as media_id
                StorageType::Nvme {
                    controller_index,
                    nsid: ns.nsid,
                },
            );
            if !storage_security.is_null() {
                boot_services::install_protocol(
                    ns_handle,
                    &STORAGE_SECURITY_COMMAND_GUID,
                    storage_security as *mut c_void,
                );
                log::debug!(
                    "Installed Storage Security Protocol on NVMe namespace {} handle {:?}",
                    ns.nsid,
                    ns_handle
                );
            }
        }
    }
}

/// Initialize AHCI/SATA pass-through protocols
fn init_ahci_pass_thru() {
    // Iterate over all AHCI controllers
    for controller_index in 0..4 {
        let Some(controller) = ahci::get_controller(controller_index) else {
            break;
        };

        let pci_addr = controller.pci_address();
        let num_ports = controller.num_active_ports();

        if num_ports == 0 {
            continue;
        }

        log::info!(
            "Installing AHCI pass-through protocols for controller {} (PCI {:02x}:{:x})",
            controller_index,
            pci_addr.device,
            pci_addr.function
        );

        // Create a handle for the AHCI controller
        let controller_handle = match boot_services::create_handle() {
            Some(h) => h,
            None => {
                log::error!(
                    "Failed to create handle for AHCI controller {}",
                    controller_index
                );
                continue;
            }
        };

        // Install device path on controller handle
        let controller_device_path = device_path::create_sata_device_path(
            pci_addr.device,
            pci_addr.function,
            0xFFFF, // Controller-level device path (no specific port)
        );
        if !controller_device_path.is_null() {
            boot_services::install_protocol(
                controller_handle,
                &device_path::DEVICE_PATH_PROTOCOL_GUID,
                controller_device_path as *mut c_void,
            );
        }

        // Install ATA Pass Through Protocol on controller handle
        let ata_pass_thru = ata_pass_thru::create_ata_pass_thru_protocol(
            controller_index,
            pci_addr.device,
            pci_addr.function,
        );
        if !ata_pass_thru.is_null() {
            boot_services::install_protocol(
                controller_handle,
                &ATA_PASS_THRU_GUID,
                ata_pass_thru as *mut c_void,
            );
            log::debug!(
                "Installed ATA Pass Thru Protocol on handle {:?}",
                controller_handle
            );
        }

        // For each active port, install Storage Security Command Protocol
        for port_index in 0..num_ports {
            let Some(port) = controller.get_port(port_index) else {
                continue;
            };

            // Skip non-SATA devices (no TCG Opal support)
            if port.device_type != ahci::DeviceType::Sata {
                continue;
            }

            // Create a handle for the SATA device
            let device_handle = match boot_services::create_handle() {
                Some(h) => h,
                None => {
                    log::error!("Failed to create handle for AHCI port {}", port.port_num);
                    continue;
                }
            };

            // Install device path on device handle
            let device_path_ptr = device_path::create_sata_device_path(
                pci_addr.device,
                pci_addr.function,
                port.port_num as u16,
            );
            if !device_path_ptr.is_null() {
                boot_services::install_protocol(
                    device_handle,
                    &device_path::DEVICE_PATH_PROTOCOL_GUID,
                    device_path_ptr as *mut c_void,
                );
            }

            // Install Storage Security Command Protocol
            let storage_security = storage_security::create_storage_security_protocol(
                port.port_num as u32, // Use port number as media_id
                StorageType::Ahci {
                    controller_index,
                    port: port_index,
                },
            );
            if !storage_security.is_null() {
                boot_services::install_protocol(
                    device_handle,
                    &STORAGE_SECURITY_COMMAND_GUID,
                    storage_security as *mut c_void,
                );
                log::debug!(
                    "Installed Storage Security Protocol on AHCI port {} handle {:?}",
                    port.port_num,
                    device_handle
                );
            }
        }
    }
}

/// Initialize USB SCSI pass-through protocols
fn init_usb_pass_thru() {
    // Find all USB mass storage devices
    log::info!("Scanning for USB mass storage devices...");
    let Some((controller_index, device_addr)) = usb::find_mass_storage() else {
        log::info!("No USB mass storage devices found for pass-through protocols");
        return;
    };

    log::info!(
        "Installing USB SCSI pass-through protocols for device {} on controller {}",
        device_addr,
        controller_index
    );

    // Create a handle for the USB mass storage device
    let device_handle = match boot_services::create_handle() {
        Some(h) => h,
        None => {
            log::error!("Failed to create handle for USB mass storage device");
            return;
        }
    };

    // Get PCI info for the USB controller (use defaults if not available)
    // USB controllers are typically at function 0, device varies
    let pci_device = 0x14; // Common xHCI device number
    let pci_function = 0;
    let usb_port = device_addr; // Use device address as port for simplicity

    // Install device path on device handle
    let device_path_ptr = device_path::create_usb_device_path(pci_device, pci_function, usb_port);
    if !device_path_ptr.is_null() {
        boot_services::install_protocol(
            device_handle,
            &device_path::DEVICE_PATH_PROTOCOL_GUID,
            device_path_ptr as *mut c_void,
        );
    }

    // Install Extended SCSI Pass Through Protocol
    let scsi_pass_thru = scsi_pass_thru::create_scsi_pass_thru_protocol(
        controller_index,
        device_addr,
        pci_device,
        pci_function,
        usb_port,
    );
    if !scsi_pass_thru.is_null() {
        boot_services::install_protocol(
            device_handle,
            &EXT_SCSI_PASS_THRU_GUID,
            scsi_pass_thru as *mut c_void,
        );
        log::debug!(
            "Installed Ext SCSI Pass Thru Protocol on handle {:?}",
            device_handle
        );
    }

    // Install Storage Security Command Protocol for USB device
    let storage_security = storage_security::create_storage_security_protocol(
        device_addr as u32, // Use device address as media_id
        StorageType::UsbScsi {
            device_index: controller_index,
        },
    );
    if !storage_security.is_null() {
        boot_services::install_protocol(
            device_handle,
            &STORAGE_SECURITY_COMMAND_GUID,
            storage_security as *mut c_void,
        );
        log::debug!(
            "Installed Storage Security Protocol on USB device handle {:?}",
            device_handle
        );
    }
}
