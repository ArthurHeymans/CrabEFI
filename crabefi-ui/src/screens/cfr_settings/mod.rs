//! Graphical Firmware page ("Ledger"): sections | options | help pane.
//!
//! The settings model owns drafts, dependency evaluation and persistence; this
//! module owns layout, focus and pointer handling.

mod geometry;
#[cfg(test)]
mod graphical_tests;
mod input;
mod operations;
mod paint;
mod state;
mod values;

pub use input::{show_cfr_menu_graphical, show_graphical_firmware_settings};

use super as ui;
use super::{
    NavItem,
    controls::{self, Focus},
    dialog,
};
use crate::Surface as FramebufferInfo;
use crate::cfr::SettingsModel;

type Rect = dialog::Rect;
type CfrInfo<'a> = dyn SettingsModel + 'a;

pub(super) struct GraphicalState {
    pub(super) focus: Focus,
    /// Item index of the current section's FormHeader.
    pub(super) section: usize,
    pub(super) selected: usize,
    pub(super) hovered: Option<usize>,
    /// FormHeader item index of the section row under the pointer.
    pub(super) hovered_section: Option<usize>,
    /// First visible row of the Sections list.
    pub(super) section_offset: usize,
    pub(super) scroll_offset: usize,
    pub(super) status_message: Option<(&'static str, bool)>,
    pub(super) save_result: Option<(usize, usize)>,
}

impl GraphicalState {
    pub(super) fn new(selected: usize) -> Self {
        let mut focus = Focus::new(ui::nav_item_index(NavItem::Firmware));
        focus.order = controls::SECTIONED_ORDER;
        Self {
            focus,
            section: 0,
            selected,
            hovered: None,
            hovered_section: None,
            section_offset: 0,
            scroll_offset: 0,
            status_message: None,
            save_result: None,
        }
    }
}
