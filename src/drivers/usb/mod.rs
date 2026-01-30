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

pub mod controller;
pub mod ehci;
pub mod ehci_regs;
pub mod hid_keyboard;
pub mod mass_storage;
pub mod ohci;
pub mod uhci;
pub mod xhci;
pub mod xhci_regs;

pub use self::controller::{DeviceInfo, UsbController, UsbError, UsbSpeed};
pub use mass_storage::UsbMassStorage;
pub use xhci::{XhciController, XhciError};

use crate::drivers::pci;
use crate::efi;
use spin::Mutex;

use core::mem;
use core::ptr;

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

// SAFETY: UsbControllerHandle wraps raw pointers to USB controller structs (xHCI, EHCI, etc.)
// allocated via the EFI page allocator. These pointers:
// 1. Remain valid for the firmware's lifetime
// 2. Are only accessed through ALL_CONTROLLERS mutex-protected array
// 3. Point to structs that themselves have MMIO and DMA buffer pointers, but
//    all hardware access is serialized through this handle abstraction
// The firmware is single-threaded; no concurrent USB operations are possible.
unsafe impl Send for UsbControllerHandle {}

/// Macro to dispatch to the appropriate controller type
///
/// This reduces repetition when implementing functions that need to work
/// with any USB controller type through the UsbController trait.
macro_rules! with_usb_controller {
    // Mutable access version
    ($handle:expr, mut |$controller:ident| $body:expr) => {
        match $handle {
            UsbControllerHandle::Xhci(ptr) => {
                let $controller = unsafe { &mut **ptr };
                $body
            }
            UsbControllerHandle::Ehci(ptr) => {
                let $controller = unsafe { &mut **ptr };
                $body
            }
            UsbControllerHandle::Ohci(ptr) => {
                let $controller = unsafe { &mut **ptr };
                $body
            }
            UsbControllerHandle::Uhci(ptr) => {
                let $controller = unsafe { &mut **ptr };
                $body
            }
        }
    };
    // Immutable access version
    ($handle:expr, |$controller:ident| $body:expr) => {
        match $handle {
            UsbControllerHandle::Xhci(ptr) => {
                let $controller = unsafe { &**ptr };
                $body
            }
            UsbControllerHandle::Ehci(ptr) => {
                let $controller = unsafe { &**ptr };
                $body
            }
            UsbControllerHandle::Ohci(ptr) => {
                let $controller = unsafe { &**ptr };
                $body
            }
            UsbControllerHandle::Uhci(ptr) => {
                let $controller = unsafe { &**ptr };
                $body
            }
        }
    };
}

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
                        let pages = size.div_ceil(4096);
                        if let Some(mem) = efi::allocate_pages(pages as u64) {
                            let controller_ptr = mem.as_mut_ptr() as *mut XhciController;
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
                        let pages = size.div_ceil(4096);
                        if let Some(mem) = efi::allocate_pages(pages as u64) {
                            let controller_ptr = mem.as_mut_ptr() as *mut ehci::EhciController;
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
                        let pages = size.div_ceil(4096);
                        if let Some(mem) = efi::allocate_pages(pages as u64) {
                            let controller_ptr = mem.as_mut_ptr() as *mut ohci::OhciController;
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
                        let pages = size.div_ceil(4096);
                        if let Some(mem) = efi::allocate_pages(pages as u64) {
                            let controller_ptr = mem.as_mut_ptr() as *mut uhci::UhciController;
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

    // Initialize USB keyboards
    init_keyboards();
}

/// Initialize USB keyboards from all controllers
fn init_keyboards() {
    let controllers = ALL_CONTROLLERS.lock();

    for (idx, handle) in controllers.iter().enumerate() {
        with_usb_controller!(handle, mut |controller| {
            if let Err(e) = hid_keyboard::init_keyboard(controller, idx) {
                log::debug!(
                    "No HID keyboard on {} controller {}: {:?}",
                    controller.controller_type(),
                    idx,
                    e
                );
            }
        });
    }
}

/// Clean up all USB controllers before ExitBootServices
///
/// This must be called before handing off to the OS to ensure Linux's
/// USB drivers can properly initialize the controllers. Following
/// libpayload's shutdown patterns for each controller type.
pub fn cleanup() {
    log::info!("USB cleanup: stopping all controllers for OS handoff");

    let mut controllers = ALL_CONTROLLERS.lock();

    for handle in controllers.iter_mut() {
        with_usb_controller!(handle, mut |controller| {
            controller.cleanup();
        });
    }

    log::info!("USB cleanup complete");
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

    log::debug!("find_mass_storage: checking {} controllers", controllers.len());
    
    controllers.iter().enumerate().find_map(|(idx, handle)| {
        let device = with_usb_controller!(handle, |controller| {
            let result = controller.find_mass_storage();
            log::debug!("  Controller {}: find_mass_storage() = {:?}", idx, result);
            result
        });
        device.map(|addr| (idx, addr))
    })
}

/// Poll USB keyboards
pub fn poll_keyboards() {
    // Get which controller has the keyboard
    let keyboard_ctrl_idx = match hid_keyboard::controller_idx() {
        Some(idx) => idx,
        None => return, // No keyboard initialized
    };

    let controllers = ALL_CONTROLLERS.lock();

    // Only poll the specific controller that has the keyboard
    if let Some(handle) = controllers.get(keyboard_ctrl_idx) {
        with_usb_controller!(handle, mut |controller| {
            hid_keyboard::poll(controller);
        });
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

    let result = with_usb_controller!(handle, mut |controller| f(controller));

    Some(result)
}

/// Get a raw pointer to a controller
///
/// This is useful when you need to store the controller pointer for later use,
/// such as in global_read_sector. The pointer remains valid for the entire boot
/// process since controllers are allocated via efi::allocate_pages and never freed.
///
/// # Safety
/// The caller must ensure the controller is not accessed after ExitBootServices.
pub fn get_controller_ptr(index: usize) -> Option<*mut dyn UsbController> {
    let controllers = ALL_CONTROLLERS.lock();
    let handle = controllers.get(index)?;

    let ptr: *mut dyn UsbController = match handle {
        UsbControllerHandle::Xhci(p) => *p as *mut dyn UsbController,
        UsbControllerHandle::Ehci(p) => *p as *mut dyn UsbController,
        UsbControllerHandle::Ohci(p) => *p as *mut dyn UsbController,
        UsbControllerHandle::Uhci(p) => *p as *mut dyn UsbController,
    };

    Some(ptr)
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
    ) -> Result<usize, self::controller::UsbError> {
        // Call the xHCI-specific control transfer via inherent method
        // Convert XhciError to UsbError
        let result =
            xhci::do_control_transfer(self, device, request_type, request, value, index, data);
        result.map_err(|e| match e {
            XhciError::Timeout => self::controller::UsbError::Timeout,
            XhciError::StallError => self::controller::UsbError::Stall,
            XhciError::DeviceNotFound => self::controller::UsbError::DeviceNotFound,
            _ => self::controller::UsbError::TransactionError,
        })
    }

    fn bulk_transfer(
        &mut self,
        device: u8,
        endpoint: u8,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<usize, self::controller::UsbError> {
        let result = xhci::do_bulk_transfer(self, device, endpoint, is_in, data);
        result.map_err(|e| match e {
            XhciError::Timeout => self::controller::UsbError::Timeout,
            XhciError::StallError => self::controller::UsbError::Stall,
            XhciError::DeviceNotFound => self::controller::UsbError::DeviceNotFound,
            _ => self::controller::UsbError::TransactionError,
        })
    }

    fn create_interrupt_queue(
        &mut self,
        _device: u8,
        _endpoint: u8,
        _is_in: bool,
        _max_packet: u16,
        _interval: u8,
    ) -> Result<u32, self::controller::UsbError> {
        // TODO: Implement interrupt queue support for xHCI
        Err(self::controller::UsbError::NotReady)
    }

    fn poll_interrupt_queue(&mut self, _queue: u32, _data: &mut [u8]) -> Option<usize> {
        None
    }

    fn destroy_interrupt_queue(&mut self, _queue: u32) {}

    fn find_mass_storage(&self) -> Option<u8> {
        xhci::XhciController::find_mass_storage(self)
    }

    fn find_hid_keyboard(&self) -> Option<u8> {
        // Check all slots for HID keyboard devices
        (0..4u8).find(|&slot_id| {
            self.get_slot(slot_id)
                .map(|slot| slot.is_hid_keyboard)
                .unwrap_or(false)
        })
    }

    fn get_device_info(&self, device: u8) -> Option<self::controller::DeviceInfo> {
        let slot = self.get_slot(device)?;
        Some(self::controller::DeviceInfo {
            address: device,
            speed: self::controller::UsbSpeed::from_xhci(slot.speed)
                .unwrap_or(self::controller::UsbSpeed::High),
            vendor_id: slot.device_desc.vendor_id,
            product_id: slot.device_desc.product_id,
            device_class: slot.device_desc.device_class,
            is_mass_storage: slot.is_mass_storage,
            is_hid: slot.is_hid_keyboard || slot.device_desc.device_class == 0x03,
            is_keyboard: slot.is_hid_keyboard,
            is_hub: slot.device_desc.device_class == 0x09,
        })
    }

    fn get_bulk_endpoints(
        &self,
        device: u8,
    ) -> Option<(
        self::controller::EndpointInfo,
        self::controller::EndpointInfo,
    )> {
        let slot = self.get_slot(device)?;
        if !slot.is_mass_storage {
            return None;
        }

        let bulk_in = self::controller::EndpointInfo {
            number: slot.bulk_in_ep,
            direction: self::controller::Direction::In,
            transfer_type: self::controller::EndpointType::Bulk,
            max_packet_size: slot.bulk_max_packet,
            interval: 0,
            toggle: false,
        };

        let bulk_out = self::controller::EndpointInfo {
            number: slot.bulk_out_ep,
            direction: self::controller::Direction::Out,
            transfer_type: self::controller::EndpointType::Bulk,
            max_packet_size: slot.bulk_max_packet,
            interval: 0,
            toggle: false,
        };

        Some((bulk_in, bulk_out))
    }

    fn get_interrupt_endpoint(&self, device: u8) -> Option<self::controller::EndpointInfo> {
        let slot = self.get_slot(device)?;
        if !slot.is_hid_keyboard || slot.interrupt_in_ep == 0 {
            return None;
        }

        Some(self::controller::EndpointInfo {
            number: slot.interrupt_in_ep,
            direction: self::controller::Direction::In,
            transfer_type: self::controller::EndpointType::Interrupt,
            max_packet_size: slot.interrupt_max_packet,
            interval: slot.interrupt_interval,
            toggle: false,
        })
    }
}
