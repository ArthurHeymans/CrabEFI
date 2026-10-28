//! Pointing devices
//!
//! PS/2 mice, USB HID mice and platform peripherals each register a
//! [`PointerDevice`]. One [`poll`] collects every device into a single pending
//! report that the boot-manager cursor or EFI Simple Pointer consumes with
//! [`take`].

use crate::cell::Local;
use alloc::{boxed::Box, vec::Vec};

/// Relative motion since the previous report and the current button level.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PointerReport {
    pub dx: i32,
    pub dy: i32,
    pub dz: i32,
    /// Bit 0: left, bit 1: right, bit 2: middle. A level, not an edge:
    /// releases are reported as cleared bits.
    pub buttons: u32,
}

/// A relative pointing device.
pub trait PointerDevice {
    /// Return motion since the previous call and the current button level,
    /// or `None` when idle. Must not wait for user input.
    fn poll(&mut self) -> Option<PointerReport>;

    /// Quiesce the device before ExitBootServices. Must not allocate or
    /// change the EFI memory map.
    fn stop(&mut self) {}
}

struct Entry {
    device: Box<dyn PointerDevice>,
    buttons: u32,
}

struct Pending {
    dx: i32,
    dy: i32,
    dz: i32,
    buttons: u32,
    /// Button level at the last [`take`].
    reported: u32,
}

impl Pending {
    const fn new() -> Self {
        Self {
            dx: 0,
            dy: 0,
            dz: 0,
            buttons: 0,
            reported: 0,
        }
    }

    fn has_transition(&self) -> bool {
        self.buttons != self.reported
    }

    fn is_ready(&self) -> bool {
        self.dx != 0 || self.dy != 0 || self.dz != 0 || self.has_transition()
    }

    fn add(&mut self, motion: PointerReport, buttons: u32) {
        self.dx = self.dx.saturating_add(motion.dx);
        self.dy = self.dy.saturating_add(motion.dy);
        self.dz = self.dz.saturating_add(motion.dz);
        self.buttons = buttons;
    }

    fn take(&mut self) -> PointerReport {
        let report = PointerReport {
            dx: core::mem::take(&mut self.dx),
            dy: core::mem::take(&mut self.dy),
            dz: core::mem::take(&mut self.dz),
            buttons: self.buttons,
        };
        self.reported = self.buttons;
        report
    }
}

static DEVICES: Local<Vec<Entry>> = Local::new(Vec::new());
static PENDING: Local<Pending> = Local::new(Pending::new());

/// Register a pointing device for the rest of boot services.
pub fn register(device: Box<dyn PointerDevice>) {
    DEVICES.borrow_mut().push(Entry { device, buttons: 0 });
}

/// Register the PS/2 mouse. USB mice register when USB is enumerated.
pub(crate) fn init() {
    #[cfg(target_arch = "x86_64")]
    register(Box::new(super::mouse::Ps2Mouse));
}

/// Poll every device into the pending report.
pub fn poll() {
    // Keep a button transition until a consumer reads it, so a press is not
    // replaced by its release on a later poll.
    if PENDING.borrow().has_transition() {
        return;
    }
    // Never hold a borrow across a device callback.
    let mut devices = core::mem::take(&mut *DEVICES.borrow_mut());
    let motion = devices
        .iter_mut()
        .filter_map(|entry| {
            let report = entry.device.poll()?;
            entry.buttons = report.buttons;
            Some(report)
        })
        .fold(PointerReport::default(), |sum, report| PointerReport {
            dx: sum.dx.saturating_add(report.dx),
            dy: sum.dy.saturating_add(report.dy),
            dz: sum.dz.saturating_add(report.dz),
            buttons: 0,
        });
    let buttons = devices.iter().fold(0, |level, entry| level | entry.buttons);
    let mut registered = DEVICES.borrow_mut();
    devices.append(&mut registered);
    *registered = devices;
    drop(registered);
    PENDING.borrow_mut().add(motion, buttons);
}

/// Whether motion or a button transition is waiting, without consuming it.
pub fn is_ready() -> bool {
    PENDING.borrow().is_ready()
}

/// Consume pending motion and acknowledge the current button level.
pub fn take() -> PointerReport {
    PENDING.borrow_mut().take()
}

/// Stop every device before the OS takes ownership.
pub(crate) fn stop() {
    let mut devices = core::mem::take(&mut *DEVICES.borrow_mut());
    devices.iter_mut().for_each(|entry| entry.device.stop());
    // No deallocation during the handoff.
    core::mem::forget(devices);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_transitions_are_reported_once_and_motion_accumulates() {
        let mut pending = Pending::new();
        pending.add(
            PointerReport {
                dx: 4,
                ..Default::default()
            },
            1,
        );
        pending.add(
            PointerReport {
                dx: 3,
                dy: -2,
                ..Default::default()
            },
            1,
        );
        assert!(pending.has_transition());
        assert_eq!(
            pending.take(),
            PointerReport {
                dx: 7,
                dy: -2,
                dz: 0,
                buttons: 1
            }
        );
        assert!(!pending.is_ready());
        pending.add(PointerReport::default(), 0);
        assert!(pending.is_ready());
        assert_eq!(pending.take().buttons, 0);
        assert!(!pending.is_ready());
    }
}
