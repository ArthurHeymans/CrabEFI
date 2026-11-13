//! Boot device policy: when USB comes up.
//!
//! The platform selects it through [`crate::PlatformConfig`].

use crate::cell::LocalCell;

/// When CrabEFI brings up USB host controllers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UsbInit {
    /// Before boot dispatch, like every other controller.
    #[default]
    Always,
    /// Only when no internal boot option starts, or for the boot menu.
    OnDemand,
}

/// Boot device policy selected by the platform.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BootPolicy {
    pub usb_init: UsbInit,
}

static POLICY: LocalCell<BootPolicy> = LocalCell::new(BootPolicy {
    usb_init: UsbInit::Always,
});

pub(crate) fn configure(policy: BootPolicy) {
    POLICY.set(policy);
}

pub(crate) fn get() -> BootPolicy {
    POLICY.get()
}
