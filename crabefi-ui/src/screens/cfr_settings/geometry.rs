use super::{FramebufferInfo, GraphicalState, Rect, ui};
use crate::screens::controls;
use crate::screens::kit;
use crate::screens::layout::Metrics;
use crate::screens::render;

pub(super) struct FwLayout {
    pub(super) strip: Rect,
    pub(super) sections: Rect,
    pub(super) sec_rows_y: i32,
    pub(super) sec_slots: usize,
    pub(super) options: Rect,
    pub(super) rows_y: i32,
    pub(super) slots: usize,
    pub(super) help: Option<Rect>,
    pub(super) marker_w: u32,
    pub(super) label_w: u32,
}
pub(super) fn fw_layout(fb: &FramebufferInfo) -> FwLayout {
    let m = Metrics::for_fb(fb);
    let (cx, cy, cw, ch) = ui::canvas(fb);
    let bottom = cy + ch as i32;
    let strip = (cx, cy, cw, kit::strip_height(fb));
    let top = cy + (strip.3 + m.gap) as i32;
    let sw = m.sections_width(cw);
    let help_w = m.help_width(cw);
    let ow = cw - sw - m.gap - help_w.map_or(0, |h| h + m.gap);
    let title_h = render::font_height(m.title) + 8;
    let head_h = render::font_height(m.small) + 12;
    let ox = cx + (sw + m.gap) as i32;
    let rows_y = top + (title_h + head_h) as i32;
    let marker_w = render::font_width(m.body) * 2 + 8;
    let label_w = (ow * 55 / 100).min(if m.large { 440 } else { 270 });
    FwLayout {
        strip,
        sections: (cx, top, sw, (bottom - top) as u32),
        sec_rows_y: top + title_h as i32,
        sec_slots: (((bottom - top - title_h as i32).max(0) as u32) / m.row).max(1) as usize,
        options: (ox, top, ow, (bottom - top) as u32),
        rows_y,
        slots: (((bottom - rows_y).max(0) as u32) / m.row).max(1) as usize,
        help: help_w.map(|h| (ox + (ow + m.gap) as i32, top, h, (bottom - top) as u32)),
        marker_w,
        label_w,
    }
}

/// Row of the `pos`-th visible section, if it is inside the viewport.
pub(super) fn section_rect(
    fb: &FramebufferInfo,
    l: &FwLayout,
    state: &GraphicalState,
    pos: usize,
    total: usize,
) -> Option<Rect> {
    let m = Metrics::for_fb(fb);
    if pos < state.section_offset || pos >= state.section_offset + l.sec_slots {
        return None;
    }
    let gutter = if total > l.sec_slots {
        controls::SCROLL_GUTTER
    } else {
        0
    };
    Some((
        l.sections.0,
        l.sec_rows_y + ((pos - state.section_offset) as u32 * m.row) as i32,
        l.sections.2 - gutter,
        m.row,
    ))
}

pub(super) fn sections_area(fb: &FramebufferInfo, l: &FwLayout) -> Rect {
    (
        l.sections.0,
        l.sec_rows_y,
        l.sections.2,
        l.sec_slots as u32 * Metrics::for_fb(fb).row,
    )
}

pub(super) fn row_rect(
    l: &FwLayout,
    fb: &FramebufferInfo,
    pos: usize,
    offset: usize,
    total: usize,
) -> Option<Rect> {
    let m = Metrics::for_fb(fb);
    if pos < offset || pos >= offset + l.slots {
        return None;
    }
    let gutter = if total > l.slots {
        controls::SCROLL_GUTTER
    } else {
        0
    };
    Some((
        l.options.0,
        l.rows_y + ((pos - offset) as u32 * m.row) as i32,
        l.options.2 - gutter,
        m.row,
    ))
}
