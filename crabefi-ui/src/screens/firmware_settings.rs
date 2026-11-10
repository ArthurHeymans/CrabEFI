//! Platform-owned settings share the native shell and focus contracts.
use super::{NavItem, ScreenNav};
use crate::{FirmwarePage, Surface};

pub async fn show(fb: &Surface) -> ScreenNav {
    match fb.firmware_page() {
        #[cfg(feature = "cfr")]
        Some(FirmwarePage::Cfr(model)) => {
            super::cfr_settings::show_graphical_firmware_settings(model.as_ref(), fb).await
        }
        Some(FirmwarePage::Platform(show)) => show(),
        None => {
            super::empty_screen(
                fb,
                NavItem::Firmware,
                "No firmware settings",
                "This platform does not expose configurable settings. Boot and Security remain available through the navigation bar.",
            )
            .await
        }
    }
}
