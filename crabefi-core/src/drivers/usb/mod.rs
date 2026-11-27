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
#[cfg(feature = "ui")]
pub mod hid_mouse;
pub mod mass_storage;
pub mod ohci;
pub mod ohci_regs;
mod port;
#[cfg(target_arch = "x86_64")]
pub mod uhci;
#[cfg(target_arch = "x86_64")]
pub mod uhci_regs;
#[cfg(feature = "xhci")]
pub mod xhci;

pub use self::controller::{DeviceInfo, UsbController, UsbError, UsbSpeed};
pub use mass_storage::UsbMassStorage;
#[cfg(feature = "xhci")]
pub use xhci::{XhciController, XhciError};

use crate::drivers::pci;
use crate::efi;
use alloc::boxed::Box;
use spin::Mutex;

use core::mem;
use core::ptr;

// ============================================================================
// Controller Type Abstraction
// ============================================================================

/// Unified USB controller handle
pub enum UsbControllerHandle {
    #[cfg(feature = "xhci")]
    Xhci(*mut XhciController),
    Ehci(*mut ehci::EhciController),
    Ohci(*mut ohci::OhciController),
    #[cfg(target_arch = "x86_64")]
    Uhci(*mut uhci::UhciController),
}

// SAFETY: UsbControllerHandle wraps raw pointers to USB controller structs (xHCI, EHCI, etc.)
// allocated via the EFI page allocator. These pointers:
// 1. Remain valid for the firmware's lifetime
// 2. Are only accessed through the ALL_CONTROLLERS mutex-protected list
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
            #[cfg(feature = "xhci")]
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
            #[cfg(target_arch = "x86_64")]
            UsbControllerHandle::Uhci(ptr) => {
                let $controller = unsafe { &mut **ptr };
                $body
            }
        }
    };
    // Immutable access version
    ($handle:expr, |$controller:ident| $body:expr) => {
        match $handle {
            #[cfg(feature = "xhci")]
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
            #[cfg(target_arch = "x86_64")]
            UsbControllerHandle::Uhci(ptr) => {
                let $controller = unsafe { &**ptr };
                $body
            }
        }
    };
}

/// Global list of all USB controllers, grown from the boot-services heap.
///
/// Controllers are never removed, so a controller's index is stable.
static ALL_CONTROLLERS: Mutex<alloc::vec::Vec<UsbControllerHandle>> =
    Mutex::new(alloc::vec::Vec::new());

/// Set once [`cleanup()`] has stopped every controller for OS handoff.
static STOPPED: crate::cell::LocalCell<bool> = crate::cell::LocalCell::new(false);

/// Changes when the set of available USB disks changes.
static STORAGE_REVISION: crate::cell::LocalCell<u32> = crate::cell::LocalCell::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Allocate, write, and register a USB controller instance.
///
/// Handles the common pattern of allocating pages for a controller struct,
/// writing it into the allocation, and pushing it into the controller list.
///
/// # Arguments
/// * `controller` - The initialized controller to store
/// * `wrap` - Closure to wrap the raw pointer into the appropriate `UsbControllerHandle` variant
/// * `discard` - Stops the controller if publication fails
/// * `name` - Controller type name for logging
/// * `address` - PCI address for logging
fn store_controller<T>(
    controller: T,
    wrap: fn(*mut T) -> UsbControllerHandle,
    discard: impl FnOnce(T),
    name: &str,
    address: pci::PciAddress,
) -> Result<(), ()> {
    // Grow the list first, so a full heap never strands controller pages.
    let mut controllers = ALL_CONTROLLERS.lock();
    if controllers.try_reserve(1).is_err() {
        drop(controllers);
        log::error!(
            "USB: out of heap registering {} controller at {}",
            name,
            address
        );
        discard(controller);
        return Err(());
    }
    const { assert!(mem::align_of::<T>() <= 4096) };
    let pages = mem::size_of::<T>().div_ceil(4096).max(1);
    let Some(alloc) = efi::allocate_pages(pages as u64) else {
        drop(controllers);
        log::error!(
            "USB: out of pages registering {} controller at {}",
            name,
            address
        );
        discard(controller);
        return Err(());
    };
    let controller_ptr = alloc.as_mut_ptr() as *mut T;
    unsafe { ptr::write(controller_ptr, controller) };
    if controllers.is_empty() {
        crate::exec::spawn(port::buses());
    }
    controllers.push(wrap(controller_ptr));
    log::info!("  {} controller initialized", name);
    Ok(())
}

/// A USB host controller that finished bring-up but is not yet registered.
pub enum InitializedController {
    #[cfg(feature = "xhci")]
    Xhci(Box<XhciController>),
    Ehci(Box<ehci::EhciController>),
    Ohci(Box<ohci::OhciController>),
    #[cfg(target_arch = "x86_64")]
    Uhci(Box<uhci::UhciController>),
}

/// Initialize a single USB controller from a PCI device
///
/// Called by the PCI driver model when a USB host controller is discovered.
/// Dispatches to the appropriate controller type based on prog_if.
///
/// # Arguments
/// * `dev` - The PCI device to initialize as a USB controller
// Failures are logged at the error site; callers only branch on success.
#[allow(clippy::result_unit_err)]
pub fn init_device(dev: &pci::PciDevice) -> Result<(), ()> {
    crate::exec::block_on(init_controller(dev)).and_then(|c| register_controller(dev.address, c))
}

/// USB 1.1 companion controllers (UHCI/OHCI) currently initializing, by PCI
/// segment/bus/device.
///
/// Until EHCI sets CONFIGFLAG its ports are routed to the companions, so a
/// companion's resets must not overlap EHCI taking the ports over. Companions
/// sit at lower function numbers than their EHCI and therefore start
/// initializing first; EHCI waits here until they are done.
static COMPANIONS_INITIALIZING: crate::cell::Local<alloc::vec::Vec<(u16, u8, u8)>> =
    crate::cell::Local::new(alloc::vec::Vec::new());

fn companion_slot(address: pci::PciAddress) -> (u16, u8, u8) {
    (address.segment(), address.bus(), address.device())
}

/// Bring up a USB host controller without registering it.
// Failures are logged at the error site; callers only branch on success.
#[allow(clippy::result_unit_err)]
pub async fn init_controller(dev: &pci::PciDevice) -> Result<InitializedController, ()> {
    /// Helper macro to reduce per-controller-type boilerplate.
    /// Logs init and calls the constructor.
    macro_rules! init_usb_controller {
        ($name:expr, $ty:ty, $variant:ident) => {{
            log::info!(
                "Initializing {} controller at {}: {:04x}:{:04x}",
                $name,
                dev.address,
                dev.vendor_id,
                dev.device_id
            );
            <$ty>::new(dev)
                .await
                .map(|c| InitializedController::$variant(Box::new(c)))
                .map_err(|e| log::error!("  Failed to init {} at {}: {:?}", $name, dev.address, e))
        }};
    }

    let slot = companion_slot(dev.address);
    match dev.prog_if {
        #[cfg(feature = "xhci")]
        0x30 => init_usb_controller!("xHCI", XhciController, Xhci),
        0x20 => {
            while COMPANIONS_INITIALIZING.borrow().contains(&slot) {
                crate::exec::yield_now().await;
            }
            init_usb_controller!("EHCI", ehci::EhciController, Ehci)
        }
        0x10 | 0x00 => {
            COMPANIONS_INITIALIZING.borrow_mut().push(slot);
            let controller = if dev.prog_if == 0x10 {
                init_usb_controller!("OHCI", ohci::OhciController, Ohci)
            } else {
                init_uhci(dev).await
            };
            COMPANIONS_INITIALIZING.with_mut(|initializing| {
                if let Some(index) = initializing.iter().position(|s| *s == slot) {
                    initializing.swap_remove(index);
                }
            });
            controller
        }
        _ => {
            log::debug!(
                "Unknown USB controller prog_if {:#x} at {}",
                dev.prog_if,
                dev.address
            );
            Err(())
        }
    }
}

#[cfg(target_arch = "x86_64")]
async fn init_uhci(dev: &pci::PciDevice) -> Result<InitializedController, ()> {
    log::info!(
        "Initializing UHCI controller at {}: {:04x}:{:04x}",
        dev.address,
        dev.vendor_id,
        dev.device_id
    );
    uhci::UhciController::new(dev)
        .await
        .map(|c| InitializedController::Uhci(Box::new(c)))
        .map_err(|e| log::error!("  Failed to init UHCI at {}: {:?}", dev.address, e))
}

#[cfg(not(target_arch = "x86_64"))]
async fn init_uhci(dev: &pci::PciDevice) -> Result<InitializedController, ()> {
    log::debug!("UHCI controller at {} is not supported here", dev.address);
    Err(())
}

/// Register a controller from [`init_controller`] for device access.
// Failures are logged at the error site; callers only branch on success.
#[allow(clippy::result_unit_err)]
pub fn register_controller(
    address: pci::PciAddress,
    controller: InitializedController,
) -> Result<(), ()> {
    match controller {
        #[cfg(feature = "xhci")]
        InitializedController::Xhci(c) => store_controller(
            *c,
            UsbControllerHandle::Xhci,
            XhciController::discard_unregistered,
            "xHCI",
            address,
        ),
        InitializedController::Ehci(c) => store_controller(
            *c,
            UsbControllerHandle::Ehci,
            |mut controller| controller.cleanup(),
            "EHCI",
            address,
        ),
        InitializedController::Ohci(c) => store_controller(
            *c,
            UsbControllerHandle::Ohci,
            |mut controller| controller.cleanup(),
            "OHCI",
            address,
        ),
        #[cfg(target_arch = "x86_64")]
        InitializedController::Uhci(c) => store_controller(
            *c,
            UsbControllerHandle::Uhci,
            |mut controller| controller.cleanup(),
            "UHCI",
            address,
        ),
    }
}

/// Shutdown all USB controllers
///
/// Delegates to the existing cleanup() function which properly stops
/// each controller type for OS handoff.
pub fn shutdown() {
    cleanup();
}

/// Initialize all USB host controllers by scanning PCI bus (legacy entry point)
///
/// Prefer using `init_device()` via the PCI driver model instead.
pub fn init() {
    log::info!("Initializing USB controllers...");

    pci::with_devices(|devices| {
        for dev in devices {
            if dev.class_code != 0x0C || dev.subclass != 0x03 {
                continue;
            }
            let _ = init_device(dev);
        }
    });

    let controllers = ALL_CONTROLLERS.lock();
    log::info!(
        "USB initialization complete: {} controllers",
        controllers.len()
    );
}

/// Initialize all USB subsystems (controllers + keyboards)
pub fn init_all() {
    // Initialize all controllers
    init();

    settle_buses();
}

/// Run the normal bus tasks after all companion controllers have been bound.
/// In particular, UHCI must not touch its ports before EHCI sets CONFIGFLAG.
pub fn settle_buses() {
    crate::exec::block_on(port::settle());
}

/// Clean up all USB controllers before ExitBootServices
///
/// This must be called before handing off to the OS to ensure Linux's
/// USB drivers can properly initialize the controllers. Following
/// libpayload's shutdown patterns for each controller type.
pub fn cleanup() {
    crate::exec::stop_background();
    log::info!("USB cleanup: stopping all controllers for OS handoff");

    let mut controllers = ALL_CONTROLLERS.lock();

    for handle in controllers.iter_mut() {
        with_usb_controller!(handle, mut |controller| {
            controller.cleanup();
        });
    }

    STOPPED.set(true);
    log::info!("USB cleanup complete");
}

/// Get the number of controllers
pub fn controller_count() -> usize {
    ALL_CONTROLLERS.lock().len()
}

/// Revision of the set of USB disks, for consumers with cached entries.
pub fn storage_revision() -> u32 {
    STORAGE_REVISION.get()
}

async fn bind_input(pipe: port::Pipe) -> Option<DeviceInfo> {
    let info = with_controller(pipe.controller, |c| c.get_device_info(pipe.address)).flatten()?;
    if info.is_keyboard {
        match hid_keyboard::bind(pipe).await {
            Ok(keyboard) => {
                crate::drivers::keyboard_common::register(Box::new(keyboard));
                log::info!(
                    "USB: attached keyboard on controller {} device {}",
                    pipe.controller,
                    pipe.address
                );
            }
            Err(error) => log::warn!("USB keyboard {} unusable: {:?}", pipe.address, error),
        }
    }
    #[cfg(feature = "ui")]
    if info.is_mouse {
        match hid_mouse::bind(pipe).await {
            Ok(mouse) => {
                crate::drivers::pointer::register(Box::new(mouse));
                log::info!(
                    "USB: attached mouse on controller {} device {}",
                    pipe.controller,
                    pipe.address
                );
            }
            Err(error) => log::warn!("USB mouse {} unusable: {:?}", pipe.address, error),
        }
    }
    Some(info)
}

async fn publish_storage(pipe: port::Pipe) -> Result<(), mass_storage::MassStorageError> {
    if mass_storage::probe(pipe).await? {
        STORAGE_REVISION.update(|revision| *revision = revision.wrapping_add(1));
        log::info!(
            "USB: attached storage on controller {} device {}",
            pipe.controller,
            pipe.address
        );
    }
    Ok(())
}

fn unbind_device(controller: usize, address: u8) {
    crate::drivers::keyboard_common::unregister_usb(controller, address);
    #[cfg(feature = "ui")]
    crate::drivers::pointer::unregister_usb(controller, address);
    if let Some(attachment_id) = mass_storage::remove(controller, address) {
        crate::efi::protocols::block_io::mark_usb_removed(controller, address, attachment_id);
        STORAGE_REVISION.update(|revision| *revision = revision.wrapping_add(1));
        log::info!("USB: detached storage on controller {controller} device {address}");
    }
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

fn with_port_controller<R>(
    index: usize,
    f: impl FnOnce(&mut dyn port::PortController) -> R,
) -> Option<R> {
    let controllers = ALL_CONTROLLERS.lock();
    let handle = controllers.get(index)?;
    Some(with_usb_controller!(handle, mut |controller| f(controller)))
}

#[cfg(feature = "xhci")]
fn with_xhci<R>(index: usize, f: impl FnOnce(&mut XhciController) -> R) -> Option<R> {
    let controllers = ALL_CONTROLLERS.lock();
    let UsbControllerHandle::Xhci(ptr) = controllers.get(index)? else {
        return None;
    };
    // SAFETY: the controller list owns the pointer and serializes access.
    Some(f(unsafe { &mut **ptr }))
}

// ============================================================================
// UsbController impl for XhciController (for compatibility)
// ============================================================================

#[cfg(feature = "xhci")]
impl UsbController for XhciController {
    fn controller_type(&self) -> &'static str {
        "xHCI"
    }

    fn max_bulk_transfer_size(&self) -> usize {
        1024 * 1024
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
            XhciError::TransferFailed(Ok(
                ::xhci::ring::trb::event::CompletionCode::BabbleDetectedError,
            )) => self::controller::UsbError::Babble,
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
            XhciError::TransferFailed(Ok(
                ::xhci::ring::trb::event::CompletionCode::BabbleDetectedError,
            )) => self::controller::UsbError::Babble,
            _ => self::controller::UsbError::TransactionError,
        })
    }

    fn interrupt_transfer(
        &mut self,
        device: u8,
        endpoint: u8,
        data: &mut [u8],
    ) -> Result<usize, self::controller::UsbError> {
        let result = xhci::do_interrupt_transfer(self, device, endpoint, data);
        result.map_err(|e| match e {
            XhciError::Timeout => self::controller::UsbError::Nak,
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

    fn get_mouse_interrupt_endpoint(&self, device: u8) -> Option<self::controller::EndpointInfo> {
        let slot = self.get_slot(device)?;
        if !slot.is_hid_mouse || slot.mouse_interrupt_in_ep == 0 {
            return None;
        }

        Some(self::controller::EndpointInfo {
            number: slot.mouse_interrupt_in_ep,
            direction: self::controller::Direction::In,
            transfer_type: self::controller::EndpointType::Interrupt,
            max_packet_size: slot.mouse_interrupt_max_packet,
            interval: slot.mouse_interrupt_interval,
            toggle: false,
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
            mass_storage_interface: slot.mass_storage_interface,
            is_hid: slot.is_hid_keyboard
                || slot.is_hid_mouse
                || slot.device_desc.device_class == 0x03,
            is_keyboard: slot.is_hid_keyboard,
            is_mouse: slot.is_hid_mouse,
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
            max_packet_size: slot.bulk_in_max_packet,
            interval: 0,
            toggle: false,
        };

        let bulk_out = self::controller::EndpointInfo {
            number: slot.bulk_out_ep,
            direction: self::controller::Direction::Out,
            transfer_type: self::controller::EndpointType::Bulk,
            max_packet_size: slot.bulk_out_max_packet,
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
