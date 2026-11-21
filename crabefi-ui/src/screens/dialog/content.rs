use super::{Rect, wrap_lines};
use crate::Surface;
use crate::screens::controls::{ButtonKind, Control, Role};
use crate::screens::layout::Metrics;
use crate::screens::render::Rgb;
use crate::screens::{controls, render, theme};
use alloc::string::String;
use alloc::vec::Vec;

pub enum Block {
    Text(String),
    Muted(String),
    Fact {
        key: String,
        value: String,
        color: Rgb,
        bold: bool,
    },
    /// "name   from -> to", the new value emphasised as an unsaved draft.
    Change {
        name: String,
        from: String,
        to: String,
    },
}
impl Block {
    pub fn text(text: &str) -> Self {
        Self::Text(String::from(text))
    }
    pub fn muted(text: &str) -> Self {
        Self::Muted(String::from(text))
    }
    pub fn fact(key: &str, value: &str) -> Self {
        Self::Fact {
            key: String::from(key),
            value: String::from(value),
            color: theme::INK2,
            bold: false,
        }
    }
    pub fn strong_fact(key: &str, value: &str) -> Self {
        Self::Fact {
            key: String::from(key),
            value: String::from(value),
            color: theme::INK,
            bold: true,
        }
    }
    pub fn change(name: &str, from: &str, to: &str) -> Self {
        Self::Change {
            name: String::from(name),
            from: String::from(from),
            to: String::from(to),
        }
    }
}

pub struct Choice<'a> {
    pub label: &'a str,
    pub key: Option<&'a str>,
    pub kind: ButtonKind,
}
impl<'a> Choice<'a> {
    pub const fn new(label: &'a str, key: Option<&'a str>, kind: ButtonKind) -> Self {
        Self { label, key, kind }
    }
}

fn block_key_width(fb: &Surface, blocks: &[Block]) -> u32 {
    let m = Metrics::for_fb(fb);
    blocks
        .iter()
        .filter_map(|b| match b {
            Block::Fact { key, .. } => Some(render::text_width(key, m.body)),
            Block::Change { name, .. } => Some(render::text_width(name, m.body)),
            _ => None,
        })
        .max()
        .map_or(0, |w| w + 16)
}

/// Lays out blocks, optionally painting. Returns the height used.
pub(super) fn blocks(fb: &Surface, x: i32, y: i32, w: u32, blocks: &[Block], paint: bool) -> u32 {
    let m = Metrics::for_fb(fb);
    let cols = (w / render::font_width(m.body)).max(1) as usize;
    let key_w = block_key_width(fb, blocks).min(w / 2);
    let value_cols = ((w - key_w) / render::font_width(m.body)).max(1) as usize;
    let mut cy = y;
    let mut previous_fact = false;
    for (i, block) in blocks.iter().enumerate() {
        let fact = matches!(block, Block::Fact { .. } | Block::Change { .. });
        if i > 0 && !(fact && previous_fact) {
            cy += (m.gap / 2) as i32;
        }
        previous_fact = fact;
        match block {
            Block::Text(text) | Block::Muted(text) => {
                let color = if matches!(block, Block::Text(_)) {
                    theme::INK
                } else {
                    theme::INK2
                };
                for line in wrap_lines(text, cols) {
                    if paint {
                        render::draw_text(fb, x, cy, &line, m.body, color, None);
                    }
                    cy += m.line as i32;
                }
            }
            Block::Fact {
                key,
                value,
                color,
                bold,
            } => {
                if paint {
                    render::draw_text_bold(fb, x, cy, key, m.body, theme::INK, None);
                }
                for line in wrap_lines(value, value_cols) {
                    if paint {
                        render::draw_text_weight(
                            fb,
                            x + key_w as i32,
                            cy,
                            &line,
                            m.body,
                            *bold,
                            *color,
                            None,
                        );
                    }
                    cy += m.line as i32;
                }
            }
            Block::Change { name, from, to } => {
                if paint {
                    render::draw_text(fb, x, cy, name, m.body, theme::INK, None);
                    let vx = x + key_w as i32;
                    let lead = change_lead(from, w - key_w, m.body);
                    let lw = render::draw_text(
                        fb,
                        vx,
                        cy,
                        &render::ellipsize(&lead, w - key_w, m.body),
                        m.body,
                        theme::INK3,
                        None,
                    );
                    render::draw_text_bold(
                        fb,
                        vx + lw as i32,
                        cy,
                        &render::ellipsize(to, (w - key_w).saturating_sub(lw), m.body),
                        m.body,
                        theme::WARN,
                        None,
                    );
                }
                cy += m.line as i32;
            }
        }
    }
    (cy - y) as u32
}

fn change_lead(from: &str, width: u32, font: render::FontSize) -> String {
    let reserved = render::text_width(" -> ", font);
    alloc::format!(
        "{} -> ",
        render::ellipsize(from, width.saturating_sub(reserved) / 2, font)
    )
}

fn choice_widths(fb: &Surface, choices: &[Choice<'_>]) -> Vec<u32> {
    let m = Metrics::for_fb(fb);
    choices
        .iter()
        .map(|c| controls::button_width(fb, c.label, c.key).max(if m.large { 180 } else { 140 }))
        .collect()
}

pub(super) fn choice_height(fb: &Surface, width: u32, choices: &[Choice<'_>]) -> u32 {
    let widths = choice_widths(fb, choices);
    let total = widths.iter().sum::<u32>() + 12 * widths.len().saturating_sub(1) as u32;
    let m = Metrics::for_fb(fb);
    if total <= width {
        m.button
    } else {
        choices.len() as u32 * (m.button + 8) - 8
    }
}

/// Right-aligned choices, stacked when a complete row will not fit.
pub(super) fn choice_row(
    fb: &Surface,
    right: i32,
    y: i32,
    available: u32,
    choices: &[Choice<'_>],
    focused: Option<usize>,
    enabled: &[bool],
) -> Vec<Rect> {
    let m = Metrics::for_fb(fb);
    let widths = choice_widths(fb, choices);
    let total: u32 = widths.iter().sum::<u32>() + 12 * widths.len().saturating_sub(1) as u32;
    let stacked = total > available;
    let mut x = right - total as i32;
    let mut rects = Vec::new();
    for (i, (choice, w)) in choices.iter().zip(&widths).enumerate() {
        let rect = if stacked {
            let w = (*w).min(available);
            (
                right - w as i32,
                y + i as i32 * (m.button + 8) as i32,
                w,
                m.button,
            )
        } else {
            (x, y, *w, m.button)
        };
        let mut c = Control::new(i as u64, Role::Button, choice.label);
        c.focused = focused == Some(i);
        c.enabled = enabled.get(i).copied().unwrap_or(true);
        controls::button_with_key(fb, rect, &c, choice.kind, choice.key);
        rects.push(rect);
        x += *w as i32 + 12;
    }
    rects
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_saved_values_leave_space_for_the_proposed_value() {
        let width = 240;
        let font = render::FontSize::Normal;
        let lead = change_lead(&"old value".repeat(40), width, font);
        let remaining = width - render::text_width(&lead, font);
        assert!(remaining >= (width - render::text_width(" -> ", font)) / 2);
        assert!(!render::ellipsize("new value", remaining, font).is_empty());
    }
}
