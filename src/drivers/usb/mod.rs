//! USB drivers for CrabEFI
//!
//! This module provides USB host controller and device class drivers:
//!
//! # Host Controllers
//! - xHCI (USB 3.0) - Primary controller for modern systems
//! - EHCI (USB 2.0) - High-speed USB 2.0 controller
//! - OHCI (USB 1.1) - Full/Low-speed USB 1.x controller
//! - UHCI (USB 1.1) - Intel's USB 1.x controller
//!
//! # Device Classes
//! - Mass Storage (Bulk-Only Transport with SCSI)
//! - HID Keyboard (Boot Protocol)
//!
//! # Architecture
//!
//! All host controllers implement the `UsbController` trait from the `core`
//! module, allowing device class drivers to work with any controller type.

pub mod core;
pub mod ehci;
pub mod hid_keyboard;
pub mod mass_storage;
pub mod ohci;
pub mod uhci;
pub mod xhci;

pub use self::core::{DeviceInfo, UsbController, UsbError, UsbSpeed};
pub use mass_storage::UsbMassStorage;
pub use xhci::{get_controller, XhciController, XhciError};

use crate::drivers::pci;
use crate::efi;
use spin::Mutex;

// Re-import from standard library (use :: prefix to avoid conflict with our core module)
use ::core::mem;
use ::core::ptr;

// ============================================================================
// Controller Type Abstraction
// ============================================================================

/// Unified USB controller handle
pub enum UsbControllerHandle {
    Xhci(*mut XhciController),
    Ehci(*mut ehci::EhciController),
    Ohci(*mut ohci::OhciController),
    Uhci(*mut uhci::UhciController),
}

// Safety: Controllers are only accessed with proper synchronization
unsafe impl Send for UsbControllerHandle {}

/// Global list of all USB controllers
static ALL_CONTROLLERS: Mutex<heapless::Vec<UsbControllerHandle, 8>> =
    Mutex::new(heapless::Vec::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize all USB host controllers
///
/// This function scans for and initializes all supported USB host controllers:
/// - xHCI (USB 3.0) - class 0x0C, subclass 0x03, prog_if 0x30
/// - EHCI (USB 2.0) - class 0x0C, subclass 0x03, prog_if 0x20
/// - OHCI (USB 1.1) - class 0x0C, subclass 0x03, prog_if 0x10
/// - UHCI (USB 1.1) - class 0x0C, subclass 0x03, prog_if 0x00
pub fn init() {
    log::info!("Initializing USB controllers...");

    let devices = pci::get_all_devices();
    let mut controllers = ALL_CONTROLLERS.lock();

    let mut xhci_count = 0;
    let mut ehci_count = 0;
    let mut ohci_count = 0;
    let mut uhci_count = 0;

    for dev in devices.iter() {
        // Check for USB host controller (class 0x0C, subclass 0x03)
        if dev.class_code != 0x0C || dev.subclass != 0x03 {
            continue;
        }

        match dev.prog_if {
            // xHCI (USB 3.0)
            0x30 => {
                log::info!(
                    "Found xHCI controller at {}: {:04x}:{:04x}",
                    dev.address,
                    dev.vendor_id,
                    dev.device_id
                );

                match XhciController::new(dev) {
                    Ok(controller) => {
                        let size = mem::size_of::<XhciController>();
                        let pages = (size + 4095) / 4096;
                        if let Some(p) = efi::allocate_pages(pages as u64) {
                            let controller_ptr = p as *mut XhciController;
                            unsafe { ptr::write(controller_ptr, controller) };
                            let _ = controllers.push(UsbControllerHandle::Xhci(controller_ptr));
                            xhci_count += 1;
                            log::info!("  xHCI controller initialized");
                        }
                    }
                    Err(e) => log::error!("  Failed to init xHCI: {:?}", e),
                }
            }

            // EHCI (USB 2.0)
            0x20 => {
                log::info!(
                    "Found EHCI controller at {}: {:04x}:{:04x}",
                    dev.address,
                    dev.vendor_id,
                    dev.device_id
                );

                match ehci::EhciController::new(dev) {
                    Ok(controller) => {
                        let size = mem::size_of::<ehci::EhciController>();
                        let pages = (size + 4095) / 4096;
                        if let Some(p) = efi::allocate_pages(pages as u64) {
                            let controller_ptr = p as *mut ehci::EhciController;
                            unsafe { ptr::write(controller_ptr, controller) };
                            let _ = controllers.push(UsbControllerHandle::Ehci(controller_ptr));
                            ehci_count += 1;
                            log::info!("  EHCI controller initialized");
                        }
                    }
                    Err(e) => log::error!("  Failed to init EHCI: {:?}", e),
                }
            }

            // OHCI (USB 1.1)
            0x10 => {
                log::info!(
                    "Found OHCI controller at {}: {:04x}:{:04x}",
                    dev.address,
                    dev.vendor_id,
                    dev.device_id
                );

                match ohci::OhciController::new(dev) {
                    Ok(controller) => {
                        let size = mem::size_of::<ohci::OhciController>();
                        let pages = (size + 4095) / 4096;
                        if let Some(p) = efi::allocate_pages(pages as u64) {
                            let controller_ptr = p as *mut ohci::OhciController;
                            unsafe { ptr::write(controller_ptr, controller) };
                            let _ = controllers.push(UsbControllerHandle::Ohci(controller_ptr));
                            ohci_count += 1;
                            log::info!("  OHCI controller initialized");
                        }
                    }
                    Err(e) => log::error!("  Failed to init OHCI: {:?}", e),
                }
            }

            // UHCI (USB 1.1)
            0x00 => {
                log::info!(
                    "Found UHCI controller at {}: {:04x}:{:04x}",
                    dev.address,
                    dev.vendor_id,
                    dev.device_id
                );

                match uhci::UhciController::new(dev) {
                    Ok(controller) => {
                        let size = mem::size_of::<uhci::UhciController>();
                        let pages = (size + 4095) / 4096;
                        if let Some(p) = efi::allocate_pages(pages as u64) {
                            let controller_ptr = p as *mut uhci::UhciController;
                            unsafe { ptr::write(controller_ptr, controller) };
                            let _ = controllers.push(UsbControllerHandle::Uhci(controller_ptr));
                            uhci_count += 1;
                            log::info!("  UHCI controller initialized");
                        }
                    }
                    Err(e) => log::error!("  Failed to init UHCI: {:?}", e),
                }
            }

            _ => {
                log::debug!(
                    "Unknown USB controller prog_if {:#x} at {}",
                    dev.prog_if,
                    dev.address
                );
            }
        }
    }

    log::info!(
        "USB initialization complete: {} xHCI, {} EHCI, {} OHCI, {} UHCI",
        xhci_count,
        ehci_count,
        ohci_count,
        uhci_count
    );
}

/// Initialize all USB subsystems (controllers + keyboards)
pub fn init_all() {
    // Initialize all controllers
    init();

    // Also run the legacy xhci::init() for compatibility
    xhci::init();

    // Initialize USB keyboards
    init_keyboards();
}

/// Initialize USB keyboards from all controllers
fn init_keyboards() {
    let controllers = ALL_CONTROLLERS.lock();

    for (idx, handle) in controllers.iter().enumerate() {
        match handle {
            UsbControllerHandle::Xhci(ptr) => {
                let controller = unsafe { &mut **ptr };
                if let Err(e) = hid_keyboard::init_keyboard(controller, idx) {
                    log::debug!("No HID keyboard on xHCI controller {}: {:?}", idx, e);
                }
            }
            UsbControllerHandle::Ehci(ptr) => {
                let controller = unsafe { &mut **ptr };
                if let Err(e) = hid_keyboard::init_keyboard(controller, idx) {
                    log::debug!("No HID keyboard on EHCI controller {}: {:?}", idx, e);
                }
            }
            UsbControllerHandle::Ohci(ptr) => {
                let controller = unsafe { &mut **ptr };
                if let Err(e) = hid_keyboard::init_keyboard(controller, idx) {
                    log::debug!("No HID keyboard on OHCI controller {}: {:?}", idx, e);
                }
            }
            UsbControllerHandle::Uhci(ptr) => {
                let controller = unsafe { &mut **ptr };
                if let Err(e) = hid_keyboard::init_keyboard(controller, idx) {
                    log::debug!("No HID keyboard on UHCI controller {}: {:?}", idx, e);
                }
            }
        }
    }
}

/// Get the number of controllers
pub fn controller_count() -> usize {
    ALL_CONTROLLERS.lock().len()
}

/// Find a mass storage device across all controllers
///
/// Returns (controller_index, device_address) if found
pub fn find_mass_storage() -> Option<(usize, u8)> {
    let controllers = ALL_CONTROLLERS.lock();

    for (idx, handle) in controllers.iter().enumerate() {
        let device = match handle {
            UsbControllerHandle::Xhci(ptr) => {
                let controller = unsafe { &**ptr };
                controller.find_mass_storage()
            }
            UsbControllerHandle::Ehci(ptr) => {
                let controller = unsafe { &**ptr };
                controller.find_mass_storage()
            }
            UsbControllerHandle::Ohci(ptr) => {
                let controller = unsafe { &**ptr };
                controller.find_mass_storage()
            }
            UsbControllerHandle::Uhci(ptr) => {
                let controller = unsafe { &**ptr };
                controller.find_mass_storage()
            }
        };

        if let Some(addr) = device {
            return Some((idx, addr));
        }
    }

    None
}

/// Poll USB keyboards
pub fn poll_keyboards() {
    let controllers = ALL_CONTROLLERS.lock();

    for (idx, handle) in controllers.iter().enumerate() {
        // Only poll the controller that has the keyboard
        if !hid_keyboard::is_available() {
            continue;
        }

        match handle {
            UsbControllerHandle::Xhci(ptr) => {
                let controller = unsafe { &mut **ptr };
                hid_keyboard::poll(controller);
            }
            UsbControllerHandle::Ehci(ptr) => {
                let controller = unsafe { &mut **ptr };
                hid_keyboard::poll(controller);
            }
            UsbControllerHandle::Ohci(ptr) => {
                let controller = unsafe { &mut **ptr };
                hid_keyboard::poll(controller);
            }
            UsbControllerHandle::Uhci(ptr) => {
                let controller = unsafe { &mut **ptr };
                hid_keyboard::poll(controller);
            }
        }
    }
}

/// Check if USB keyboard has input
pub fn keyboard_has_key() -> bool {
    hid_keyboard::has_key()
}

/// Get key from USB keyboard
pub fn keyboard_get_key() -> Option<(u16, u16)> {
    hid_keyboard::get_key()
}

// ============================================================================
// Controller Access
// ============================================================================

/// Execute a function with a controller
pub fn with_controller<F, R>(index: usize, f: F) -> Option<R>
where
    F: FnOnce(&mut dyn UsbController) -> R,
{
    let controllers = ALL_CONTROLLERS.lock();
    let handle = controllers.get(index)?;

    let result = match handle {
        UsbControllerHandle::Xhci(ptr) => {
            let controller = unsafe { &mut **ptr };
            f(controller)
        }
        UsbControllerHandle::Ehci(ptr) => {
            let controller = unsafe { &mut **ptr };
            f(controller)
        }
        UsbControllerHandle::Ohci(ptr) => {
            let controller = unsafe { &mut **ptr };
            f(controller)
        }
        UsbControllerHandle::Uhci(ptr) => {
            let controller = unsafe { &mut **ptr };
            f(controller)
        }
    };

    Some(result)
}

// ============================================================================
// UsbController impl for XhciController (for compatibility)
// ============================================================================

impl UsbController for XhciController {
    fn controller_type(&self) -> &'static str {
        "xHCI"
    }

    fn control_transfer(
        &mut self,
        device: u8,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: Option<&mut [u8]>,
    ) -> Result<usize, self::core::UsbError> {
        // Call the xHCI-specific control transfer via inherent method
        // Convert XhciError to UsbError
        let result =
            xhci::do_control_transfer(self, device, request_type, request, value, index, data);
        result.map_err(|e| match e {
            XhciError::Timeout => self::core::UsbError::Timeout,
            XhciError::StallError => self::core::UsbError::Stall,
            XhciError::DeviceNotFound => self::core::UsbError::DeviceNotFound,
            _ => self::core::UsbError::TransactionError,
        })
    }

    fn bulk_transfer(
        &mut self,
        device: u8,
        endpoint: u8,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<usize, self::core::UsbError> {
        let result = xhci::do_bulk_transfer(self, device, endpoint, is_in, data);
        result.map_err(|e| match e {
            XhciError::Timeout => self::core::UsbError::Timeout,
            XhciError::StallError => self::core::UsbError::Stall,
            XhciError::DeviceNotFound => self::core::UsbError::DeviceNotFound,
            _ => self::core::UsbError::TransactionError,
        })
    }

    fn create_interrupt_queue(
        &mut self,
        _device: u8,
        _endpoint: u8,
        _is_in: bool,
        _max_packet: u16,
        _interval: u8,
    ) -> Result<u32, self::core::UsbError> {
        // TODO: Implement interrupt queue support for xHCI
        Err(self::core::UsbError::NotReady)
    }

    fn poll_interrupt_queue(&mut self, _queue: u32, _data: &mut [u8]) -> Option<usize> {
        None
    }

    fn destroy_interrupt_queue(&mut self, _queue: u32) {}

    fn find_mass_storage(&self) -> Option<u8> {
        xhci::XhciController::find_mass_storage(self)
    }

    fn find_hid_keyboard(&self) -> Option<u8> {
        // Check all slots for HID devices
        for slot_id in 0..4u8 {
            if let Some(slot) = self.get_slot(slot_id) {
                // Check device class - HID is 0x03
                let class = slot.device_desc.device_class;
                if class == 0x03 || class == 0x00 {
                    // Could be HID, check interface
                    return Some(slot_id);
                }
            }
        }
        None
    }

    fn get_device_info(&self, device: u8) -> Option<self::core::DeviceInfo> {
        let slot = self.get_slot(device)?;
        Some(self::core::DeviceInfo {
            address: device,
            speed: self::core::UsbSpeed::from_xhci(slot.speed)
                .unwrap_or(self::core::UsbSpeed::High),
            vendor_id: slot.device_desc.vendor_id,
            product_id: slot.device_desc.product_id,
            device_class: slot.device_desc.device_class,
            is_mass_storage: slot.is_mass_storage,
            is_hid: slot.device_desc.device_class == 0x03,
            is_keyboard: false, // Would need to check interface
        })
    }

    fn get_bulk_endpoints(
        &self,
        device: u8,
    ) -> Option<(self::core::EndpointInfo, self::core::EndpointInfo)> {
        let slot = self.get_slot(device)?;
        if !slot.is_mass_storage {
            return None;
        }

        let bulk_in = self::core::EndpointInfo {
            number: slot.bulk_in_ep,
            direction: self::core::Direction::In,
            transfer_type: self::core::EndpointType::Bulk,
            max_packet_size: slot.bulk_max_packet,
            interval: 0,
            toggle: false,
        };

        let bulk_out = self::core::EndpointInfo {
            number: slot.bulk_out_ep,
            direction: self::core::Direction::Out,
            transfer_type: self::core::EndpointType::Bulk,
            max_packet_size: slot.bulk_max_packet,
            interval: 0,
            toggle: false,
        };

        Some((bulk_in, bulk_out))
    }

    fn get_interrupt_endpoint(&self, _device: u8) -> Option<self::core::EndpointInfo> {
        // xHCI doesn't store interrupt endpoint info currently
        // Would need to re-parse config descriptor
        None
    }
}
