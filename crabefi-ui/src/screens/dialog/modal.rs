use super::content::{blocks, choice_height, choice_row};
use super::pagination::{
    block_sections, layout_section, paginate, paint_vlines, section_label_width,
};
use super::{
    Backdrop, Block, Choice, center_modal, contains, modal_backdrop, modal_keys, modal_width,
};
use crate::KeyPress;
use crate::cursor::CursorRenderer;
use crate::screens::controls::ButtonKind;
use crate::screens::kit::Tone;
use crate::screens::layout::Metrics;
use crate::screens::{Hover, kit, layout, poll_and_render_cursor, track_hover};
use alloc::string::String;
use alloc::vec::Vec;

fn shortcut_choice(choices: &[Choice<'_>], key: KeyPress) -> Option<usize> {
    (key == KeyPress::F10)
        .then(|| choices.iter().position(|choice| choice.key == Some("F10")))
        .flatten()
}

/// Focus starts on, and Escape returns, choice 0: callers put the safe
/// option first.
pub async fn modal(
    fb: &crate::Surface,
    backdrop: Backdrop<'_>,
    tone: Tone,
    title: &str,
    content: &[Block],
    choices: &[Choice<'_>],
) -> usize {
    let _scope = fb.dialog_scope(title);
    assert!(!choices.is_empty() && choices.len() <= 3);
    let mut cursor = CursorRenderer::new();
    let mut focused = 0usize;
    let mut page = 0usize;
    loop {
        cursor.hide(fb);
        let m = Metrics::for_fb(fb);
        let w = modal_width(fb, if m.large { 820 } else { 720 });
        let inner = w - m.pad * 2;
        let body_h = blocks(fb, 0, 0, inner, content, false);
        let buttons_h = choice_height(fb, inner, choices);
        let chrome = kit::modal_head_height(fb) + m.gap * 3 + buttons_h + 4;
        let room = fb.height.saturating_sub(m.header + m.footer + 16 + chrome);
        // Stacking choices must not merely move clipping into the body. Page
        // long confirmations/results on short displays, like trust reviews.
        let sections = block_sections(content);
        let label_w = section_label_width(fb, &sections);
        let lines: Vec<_> = sections
            .iter()
            .map(|section| layout_section(fb, inner, label_w, section))
            .collect();
        let overflow = body_h > room;
        let pages = paginate(&lines, room);
        let page_count = if overflow { pages.len() } else { 1 };
        page = page.min(page_count - 1);
        let title = if page_count > 1 {
            alloc::format!("{title} ({}/{page_count})", page + 1)
        } else {
            String::from(title)
        };
        let h = chrome + body_h.min(room);
        let rect = center_modal(fb, w, h);
        modal_backdrop(fb, backdrop);
        let body = kit::modal_frame(fb, rect, tone, &title);
        if overflow {
            let mut y = body.1;
            for (s, range) in &pages[page] {
                y += paint_vlines(
                    fb,
                    body.0,
                    y,
                    inner,
                    label_w,
                    &sections[*s].label,
                    &lines[*s][range.clone()],
                ) as i32;
            }
        } else {
            blocks(fb, body.0, body.1, body.2, content, true);
        }
        let by = rect.1 + rect.3 as i32 - buttons_h as i32 - m.gap as i32;
        let rects = choice_row(
            fb,
            body.0 + body.2 as i32,
            by,
            inner,
            choices,
            Some(focused),
            &[],
        );
        modal_keys(
            fb,
            choices[0].label,
            if page_count > 1 {
                &[("PgUp PgDn", "Details")]
            } else {
                &[]
            },
        );
        let mut hover = Hover::default();
        loop {
            poll_and_render_cursor(fb, &mut cursor);
            track_hover(fb, &mut cursor, &mut hover, None);
            if let Some(key) = fb.key() {
                let activation = match key {
                    KeyPress::Escape => {
                        cursor.hide(fb);
                        return 0;
                    }
                    KeyPress::F8 => {
                        layout::toggle_text_size(fb);
                        page = 0;
                        break;
                    }
                    KeyPress::PageUp | KeyPress::PageDown | KeyPress::MouseScroll(_) => {
                        if key == KeyPress::PageUp
                            || matches!(key, KeyPress::MouseScroll(z) if z > 0)
                        {
                            page = page.saturating_sub(1);
                        } else {
                            page = (page + 1).min(page_count - 1);
                        }
                        break;
                    }
                    KeyPress::Tab | KeyPress::Right | KeyPress::Down => {
                        focused = (focused + 1) % choices.len();
                        break;
                    }
                    KeyPress::BackTab | KeyPress::Left | KeyPress::Up => {
                        focused = (focused + choices.len() - 1) % choices.len();
                        break;
                    }
                    KeyPress::F10 => shortcut_choice(choices, key),
                    KeyPress::Enter | KeyPress::Char(' ') => Some(focused),
                    KeyPress::MouseClick { x, y } => {
                        rects.iter().position(|r| contains(*r, x as i32, y as i32))
                    }
                    _ => None,
                };
                if let Some(i) = activation {
                    cursor.hide(fb);
                    return i;
                }
            }
            fb.wait_for_frame().await;
        }
    }
}

fn choice_kind(label: &str, index: usize) -> ButtonKind {
    if index == 0 {
        ButtonKind::Neutral
    } else if matches!(
        label,
        "Discard" | "Clear keys" | "Clear all keys" | "Disable"
    ) {
        ButtonKind::Danger
    } else if matches!(label, "Enroll" | "Import") {
        ButtonKind::Accent
    } else {
        ButtonKind::Primary
    }
}

/// Compatibility choice API: one paragraph, safe choice first.
pub async fn choose(
    fb: &crate::Surface,
    backdrop: Backdrop<'_>,
    title: &str,
    message: &str,
    labels: &[&str],
) -> usize {
    let choices: Vec<Choice<'_>> = labels
        .iter()
        .enumerate()
        .map(|(i, l)| Choice::new(l, (i == 0).then_some("Esc"), choice_kind(l, i)))
        .collect();
    let content: Vec<Block> = message.split("\n\n").map(Block::text).collect();
    modal(fb, backdrop, Tone::Neutral, title, &content, &choices).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screens::controls;

    #[test]
    fn narrow_modal_choices_fit_and_repaints_replace_the_hover_registry() {
        let mut pixels = std::vec![0u32; 640 * 480];
        let fb = crate::test_surface(crate::FramebufferConfig {
            physical_address: pixels.as_mut_ptr() as u64,
            width: 640,
            height: 480,
            stride: 640,
            bits_per_pixel: 32,
            red_mask_pos: 16,
            red_mask_size: 8,
            green_mask_pos: 8,
            green_mask_size: 8,
            blue_mask_pos: 0,
            blue_mask_size: 8,
        });
        let choices = [
            Choice::new("Keep editing", Some("Esc"), ButtonKind::Neutral),
            Choice::new("Discard and restart", None, ButtonKind::Danger),
            Choice::new("Save and restart", Some("F10"), ButtonKind::Primary),
        ];
        let w = 520;
        let h = choice_height(&fb, w, &choices);
        assert!(h > Metrics::for_fb(&fb).button);
        for _ in 0..3 {
            modal_backdrop(&fb, &|| {});
            let rects = choice_row(&fb, 580, 100, w, &choices, Some(0), &[]);
            for r in &rects {
                assert!(r.0 >= 60 && r.0 + r.2 as i32 <= 580);
                assert!(r.1 + r.3 as i32 <= 100 + h as i32);
            }
            assert_eq!(
                controls::button_at(&fb, rects[0].0 + 5, rects[0].1 + 5),
                Some(0)
            );
        }
        assert_eq!(shortcut_choice(&choices, KeyPress::F10), Some(2));
        assert_eq!(shortcut_choice(&choices, KeyPress::Enter), None);
    }
}
