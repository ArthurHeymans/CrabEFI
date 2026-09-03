//! USB HID Mouse Driver
//!
//! This module implements USB HID mouse support using the boot protocol.
//! Boot protocol mice send 3-byte reports: buttons, X delta, Y delta.
//!
//! # Polling Strategy
//!
//! Many USB mice do NOT implement the HID class GET_REPORT request (they
//! stall the control pipe).  The only reliable way to read mouse data is
//! via interrupt IN transfers on the device's interrupt endpoint.
//!
//! We use interrupt IN transfers exclusively.  If the xHCI controller does
//! not have interrupt transfer support configured for the endpoint, we fall
//! back to GET_REPORT but give up after a few stalls to avoid chewing
//! through the command ring endlessly.
//!
//! # References
//! - USB HID Specification 1.11, Appendix B.2 (Boot Interface — Mouse)
//! - libpayload: `payloads/libpayload/drivers/usb/usbhid.c`

use super::controller::{UsbController, UsbError, hid_request, req_type};
use crate::time::Timeout;
use spin::Mutex;

// ============================================================================
// HID Boot Protocol Mouse
// ============================================================================

/// Boot protocol mouse report (3+ bytes)
///
/// The boot protocol defines a fixed 3-byte report:
/// - Byte 0: Button state (bit 0=left, 1=right, 2=middle)
/// - Byte 1: X displacement (signed 8-bit)
/// - Byte 2: Y displacement (signed 8-bit)
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct MouseReport {
    /// Button state (bit 0=left, 1=right, 2=middle)
    pub buttons: u8,
    /// X displacement (signed)
    pub x: i8,
    /// Y displacement (signed)
    pub y: i8,
}

// ============================================================================
// USB HID Mouse State
// ============================================================================

/// USB HID mouse state
pub struct UsbHidMouse {
    /// Controller index
    controller_idx: usize,
    /// Device address
    device_address: u8,
    /// Interrupt endpoint number
    endpoint: u8,
    /// Max packet size
    #[allow(dead_code)] // Endpoint descriptor shadow; completeness for re-enumeration.
    max_packet: u16,
    /// Polling interval in ms
    #[allow(dead_code)] // Endpoint descriptor shadow; completeness for re-enumeration.
    interval: u8,
    /// Accumulated X relative motion
    rel_x: i32,
    /// Accumulated Y relative motion
    rel_y: i32,
    /// Current button state
    buttons: u32,
    /// Consecutive GET_REPORT stall count (if using fallback)
    stall_count: u32,
    /// Whether GET_REPORT has been disabled due to persistent stalls
    get_report_disabled: bool,
}

impl UsbHidMouse {
    /// Create a new USB HID mouse
    fn new(
        controller_idx: usize,
        device_address: u8,
        endpoint: u8,
        max_packet: u16,
        interval: u8,
    ) -> Self {
        Self {
            controller_idx,
            device_address,
            endpoint,
            max_packet,
            interval,
            rel_x: 0,
            rel_y: 0,
            buttons: 0,
            stall_count: 0,
            get_report_disabled: false,
        }
    }

    /// Set boot protocol mode
    fn set_boot_protocol<C: UsbController>(&self, controller: &mut C) -> Result<(), UsbError> {
        controller.control_transfer(
            self.device_address,
            req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE,
            hid_request::SET_PROTOCOL,
            0, // Boot protocol
            0, // Interface 0
            None,
        )?;
        Ok(())
    }

    /// Set idle rate
    fn set_idle<C: UsbController>(&self, controller: &mut C, rate_ms: u8) -> Result<(), UsbError> {
        let duration = rate_ms / 4;
        controller.control_transfer(
            self.device_address,
            req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE,
            hid_request::SET_IDLE,
            (duration as u16) << 8,
            0,
            None,
        )?;
        Ok(())
    }

    /// Process a mouse report
    fn process_report(&mut self, report: &MouseReport) {
        self.rel_x += report.x as i32;
        self.rel_y += report.y as i32;
        self.buttons = (report.buttons & 0x07) as u32;
    }

    /// Get device address
    pub fn device_address(&self) -> u8 {
        self.device_address
    }

    /// Get controller index
    pub fn controller_idx(&self) -> usize {
        self.controller_idx
    }

    /// Get interrupt endpoint number
    pub fn endpoint(&self) -> u8 {
        self.endpoint
    }
}

// ============================================================================
// Global USB Mouse
// ============================================================================

/// Global USB mouse instance
static USB_MOUSE: Mutex<Option<UsbHidMouse>> = Mutex::new(None);

/// Minimum poll interval in milliseconds
const MIN_POLL_INTERVAL_MS: u64 = 8;

/// Number of consecutive GET_REPORT stalls before giving up.
const MAX_CONSECUTIVE_STALLS: u32 = 3;

/// Next poll timeout
static NEXT_POLL_TIMEOUT: Mutex<Option<Timeout>> = Mutex::new(None);

/// Initialize USB mouse from a controller.
///
/// Called during USB device enumeration when a HID mouse is detected.
pub fn init_mouse<C: UsbController>(
    controller: &mut C,
    controller_idx: usize,
) -> Result<(), UsbError> {
    // Find HID mouse device
    let device_addr = controller
        .find_hid_mouse()
        .ok_or(UsbError::DeviceNotFound)?;

    // Get interrupt endpoint
    let ep_info = controller
        .get_mouse_interrupt_endpoint(device_addr)
        .ok_or(UsbError::DeviceNotFound)?;

    log::info!(
        "USB HID mouse found: device {}, endpoint {}, max_pkt {}, interval {}ms",
        device_addr,
        ep_info.number,
        ep_info.max_packet_size,
        ep_info.interval
    );

    let mouse = UsbHidMouse::new(
        controller_idx,
        device_addr,
        ep_info.number,
        ep_info.max_packet_size,
        ep_info.interval,
    );

    // Set boot protocol
    if let Err(e) = mouse.set_boot_protocol(controller) {
        log::warn!("Failed to set mouse boot protocol: {:?}", e);
    }

    // Set idle rate to 0 (infinite — only report on change)
    // This is the correct setting for interrupt-driven polling.
    if let Err(e) = mouse.set_idle(controller, 0) {
        log::debug!("Failed to set mouse idle rate: {:?}", e);
    }

    *USB_MOUSE.lock() = Some(mouse);

    log::info!("USB HID mouse initialized");
    Ok(())
}

/// Poll USB mouse for new reports.
///
/// Tries interrupt IN transfer first (the correct HID approach).
/// Falls back to GET_REPORT only if interrupt transfers are not available,
/// and gives up after [`MAX_CONSECUTIVE_STALLS`] to avoid hammering the
/// xHCI command ring.
pub fn poll<C: UsbController>(controller: &mut C) {
    // Rate limit polling
    {
        let mut timeout_guard = NEXT_POLL_TIMEOUT.lock();
        if let Some(ref timeout) = *timeout_guard
            && !timeout.is_expired()
        {
            return;
        }
        *timeout_guard = Some(Timeout::from_ms(MIN_POLL_INTERVAL_MS));
    }

    let mut mouse_guard = USB_MOUSE.lock();
    let mouse = match mouse_guard.as_mut() {
        Some(m) => m,
        None => return,
    };

    // If GET_REPORT has been permanently disabled due to stalls, and we
    // don't have interrupt transfer support yet, there's nothing to do.
    if mouse.get_report_disabled {
        return;
    }

    // Try interrupt IN transfer first — this is the proper way to poll a HID mouse.
    let dev_addr = mouse.device_address();
    let ep = mouse.endpoint();
    let mut report_buf = [0u8; 8];
    let result = controller.interrupt_transfer(dev_addr, ep, &mut report_buf);

    match result {
        Ok(bytes_read) if bytes_read >= 3 => {
            mouse.stall_count = 0;
            let report = MouseReport {
                buttons: report_buf[0],
                x: report_buf[1] as i8,
                y: report_buf[2] as i8,
            };
            mouse.process_report(&report);
            return;
        }
        Ok(_) => {
            // Short read — might be NAK (no data). Not an error.
            return;
        }
        Err(UsbError::NotSupported) => {
            // Controller doesn't implement interrupt_transfer — fall through
            // to GET_REPORT below.
        }
        Err(_) => {
            // Transfer error or NAK — not fatal for interrupt endpoints.
            return;
        }
    }

    // ── Fallback: GET_REPORT via control transfer ──
    let mut ctrl_buf = [0u8; 4];
    let result = controller.control_transfer(
        dev_addr,
        req_type::DIR_IN | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE,
        hid_request::GET_REPORT,
        0x0100, // Report type = Input (1), Report ID = 0
        0,      // Interface 0
        Some(&mut ctrl_buf),
    );

    match result {
        Ok(_) => {
            mouse.stall_count = 0;
            let report = MouseReport {
                buttons: ctrl_buf[0],
                x: ctrl_buf[1] as i8,
                y: ctrl_buf[2] as i8,
            };
            mouse.process_report(&report);
        }
        Err(_) => {
            mouse.stall_count += 1;
            if mouse.stall_count >= MAX_CONSECUTIVE_STALLS {
                log::warn!(
                    "USB mouse: GET_REPORT stalled {} times, disabling \
                     (device does not support HID class GET_REPORT)",
                    mouse.stall_count
                );
                mouse.get_report_disabled = true;
            }
        }
    }
}

/// Get accumulated relative motion and reset it.
pub fn get_relative_motion() -> (i32, i32) {
    let mut guard = USB_MOUSE.lock();
    let mouse = match guard.as_mut() {
        Some(m) => m,
        None => return (0, 0),
    };
    let dx = mouse.rel_x;
    let dy = mouse.rel_y;
    mouse.rel_x = 0;
    mouse.rel_y = 0;
    (dx, dy)
}

/// Get current button state.
pub fn get_buttons() -> u32 {
    USB_MOUSE.lock().as_ref().map(|m| m.buttons).unwrap_or(0)
}

/// Check if USB mouse is available.
pub fn is_available() -> bool {
    USB_MOUSE.lock().is_some()
}

/// Check if USB mouse has pending motion.
pub fn has_motion() -> bool {
    USB_MOUSE
        .lock()
        .as_ref()
        .map(|m| m.rel_x != 0 || m.rel_y != 0)
        .unwrap_or(false)
}

/// Get the controller index that has the mouse.
pub fn controller_idx() -> Option<usize> {
    USB_MOUSE.lock().as_ref().map(|m| m.controller_idx())
}
