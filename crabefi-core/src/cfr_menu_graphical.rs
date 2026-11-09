//! Firmware adapter for the CFR page in `crabefi-ui`.
use crate::{
    FramebufferConfig,
    cfr::{self, CfrInfo},
    ui,
};

pub fn show_graphical_firmware_settings() -> ui::ScreenNav {
    let Some(fb) = crate::handoff::framebuffer().filter(ui::supports_framebuffer) else {
        return ui::ScreenNav::Back;
    };
    let empty = CfrInfo::new();
    show_cfr_menu_graphical(cfr::get_cfr().unwrap_or(&empty), &fb)
}

pub(super) fn show_cfr_menu_graphical(model: &CfrInfo, fb: &FramebufferConfig) -> ui::ScreenNav {
    let surface = ui::surface(fb);
    ui::finish(embassy_futures::block_on(
        crabefi_ui::screens::cfr_settings::show_cfr_menu_graphical(model, &surface),
    ))
}
