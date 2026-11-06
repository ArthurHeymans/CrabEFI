//! Platform-owned settings share the native shell and focus contracts.

use super::{NavItem, ScreenNav};
use crate::FramebufferConfig;

pub fn show(fb: &FramebufferConfig) -> ScreenNav {
    if let Some(hooks) = crate::handoff::callbacks().hooks
        && hooks.firmware_settings_available()
    {
        return hooks.show_graphical_firmware_settings();
    }
    super::empty_screen(
        fb,
        NavItem::Firmware,
        "No firmware settings",
        "This platform does not expose configurable settings. Boot and Security remain available through the navigation bar.",
    )
}
