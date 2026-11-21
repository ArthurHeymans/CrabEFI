use super::content::{blocks, choice_height, choice_row};
use super::pagination::{
    ReviewSection, VLine, block_sections, layout_section, mark_shown, paginate, paint_vlines,
    section_label_width, unseen_pages, vlines_height,
};
use super::{
    Backdrop, Block, Choice, center_modal, contains, modal_backdrop, modal_keys, modal_width,
};
use crate::KeyPress;
use crate::cursor::CursorRenderer;
use crate::screens::controls::ButtonKind;
use crate::screens::kit::Tone;
use crate::screens::layout::Metrics;
use crate::screens::{
    Hover, controls, kit, layout, poll_and_render_cursor, render, theme, track_hover,
};
use alloc::string::String;
use alloc::vec::Vec;

/// Identity-before-consent review. Normally `intro`/`outro` stay fixed and
/// sections page by whole blocks; on short screens they join the pages.
/// Confirm stays unavailable until every line was actually on screen.
pub async fn review(
    fb: &crate::Surface,
    backdrop: Backdrop<'_>,
    title: &str,
    intro: &[Block],
    sections: &[ReviewSection],
    outro: &[Block],
    confirm: Option<&str>,
) -> bool {
    let _scope = fb.dialog_scope(title);
    let mut cursor = CursorRenderer::new();
    let mut page = 0usize;
    let mut focused = 0usize;
    // Shown lines per (paged entry, visual line); reset when the layout changes.
    let mut shown: Vec<Vec<bool>> = Vec::new();
    let mut layout_key = None;
    loop {
        cursor.hide(fb);
        let m = Metrics::for_fb(fb);
        let w = modal_width(fb, if m.large { 1000 } else { 984 });
        let inner = w - m.pad * 2;
        let counter_h = m.small_line + 8;
        let avail = fb.height.saturating_sub(m.header + m.footer + 16);
        let intro_h = blocks(fb, 0, 0, inner, intro, false);
        let outro_h = blocks(fb, 0, 0, inner, outro, false);
        let choices = match confirm {
            Some(confirm) => alloc::vec![
                Choice::new("Cancel", Some("Esc"), ButtonKind::Neutral),
                Choice::new(confirm, None, ButtonKind::Accent),
            ],
            None => alloc::vec![Choice::new("Close", Some("Esc"), ButtonKind::Neutral)],
        };
        let buttons_h = choice_height(fb, inner, &choices);
        let base = kit::modal_head_height(fb) + m.gap * 3 + buttons_h + counter_h;
        let normal_fixed = base + m.gap * 2 + intro_h + outro_h;
        let label_w_of = |entries: &[ReviewSection]| section_label_width(fb, entries);
        let tallest = {
            let lw = label_w_of(sections);
            sections
                .iter()
                .map(|s| vlines_height(&layout_section(fb, inner - controls::SCROLL_GUTTER, lw, s)))
                .max()
                .unwrap_or(0)
        };
        // Short screens: page the summary too, rather than squeeze identities.
        let compact = avail.saturating_sub(normal_fixed) < tallest.max(m.line * 3);
        let entries: Vec<ReviewSection> = if compact {
            let mut all = block_sections(intro);
            all.extend(sections.iter().cloned());
            all.extend(block_sections(outro));
            all
        } else {
            sections.to_vec()
        };
        let fixed = if compact { base } else { normal_fixed };
        let room = avail.saturating_sub(fixed).max(m.line * 3);
        let label_w = label_w_of(&entries);
        let lay = |w| -> Vec<Vec<VLine>> {
            entries
                .iter()
                .map(|s| layout_section(fb, w, label_w, s))
                .collect()
        };
        let mut list_w = inner;
        let mut lines = lay(list_w);
        let natural: u32 = lines.iter().map(|l| vlines_height(l)).sum();
        if natural > room {
            list_w = inner - controls::SCROLL_GUTTER;
            lines = lay(list_w);
        }
        let natural: u32 = lines.iter().map(|l| vlines_height(l)).sum();
        let pages = paginate(&lines, room);
        if layout_key != Some((m.large, w, compact)) {
            layout_key = Some((m.large, w, compact));
            shown = lines.iter().map(|l| alloc::vec![false; l.len()]).collect();
            page = 0;
        }
        page = page.min(pages.len() - 1);
        mark_shown(&mut shown, &pages[page]);
        let unseen = unseen_pages(&pages, &shown).count();
        let all_seen = unseen == 0;
        let list_h = if pages.len() == 1 { natural } else { room };
        let h = fixed + list_h;
        let rect = center_modal(fb, w, h);
        modal_backdrop(fb, backdrop);
        let body = kit::modal_frame(fb, rect, Tone::Ok, title);
        let mut y = body.1;
        if !compact {
            blocks(fb, body.0, y, inner, intro, true);
            y += (intro_h + m.gap) as i32;
        }
        let list_top = y;
        for (s, range) in &pages[page] {
            y += paint_vlines(
                fb,
                body.0,
                y,
                list_w,
                label_w,
                &entries[*s].label,
                &lines[*s][range.clone()],
            ) as i32;
        }
        let list = (body.0, list_top, inner, list_h);
        controls::scrollbar(fb, list, pages.len(), page, 1);
        y = list_top + list_h as i32 + 4;
        render::fill_rect(fb, body.0, y - 4, inner, 1, theme::RULE);
        let counter = if pages.len() > 1 {
            alloc::format!("Page {} of {}", page + 1, pages.len())
        } else {
            alloc::format!(
                "All {} {} shown",
                entries.len(),
                if entries.len() == 1 { "item" } else { "items" }
            )
        };
        render::draw_text(fb, body.0, y + 2, &counter, m.small, theme::INK2, None);
        if pages.len() > 1 {
            let hint = if page + 1 < pages.len() {
                String::from("PgDn shows the next page")
            } else {
                String::from("PgUp shows earlier pages")
            };
            render::draw_text_right(fb, body.0, y + 2, inner, &hint, m.small, theme::INK3, None);
        }
        y += counter_h as i32 + m.gap as i32 / 2;
        if !compact {
            blocks(fb, body.0, y, inner, outro, true);
        }
        let by = rect.1 + rect.3 as i32 - buttons_h as i32 - m.gap as i32;
        focused = focused.min(choices.len() - 1);
        let rects = choice_row(
            fb,
            body.0 + inner as i32,
            by,
            inner,
            &choices,
            Some(focused),
            &[true, all_seen],
        );
        if !all_seen && confirm.is_some() {
            let note = alloc::format!(
                "Review {} more {} first",
                unseen,
                if unseen == 1 { "page" } else { "pages" }
            );
            render::draw_text_right(
                fb,
                body.0,
                by + ((m.button - render::font_height(m.small)) / 2) as i32,
                inner
                    .saturating_sub(rects.iter().map(|r| r.2 + 12).sum::<u32>())
                    .saturating_sub(8),
                &note,
                m.small,
                theme::WARN,
                None,
            );
        }
        modal_keys(
            fb,
            if confirm.is_some() { "Cancel" } else { "Close" },
            if pages.len() > 1 {
                &[("PgUp PgDn", "Scroll")]
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
                        return false;
                    }
                    KeyPress::F8 => {
                        layout::toggle_text_size(fb);
                        break;
                    }
                    KeyPress::Tab | KeyPress::Right | KeyPress::BackTab | KeyPress::Left => {
                        focused = (focused + 1) % choices.len();
                        break;
                    }
                    KeyPress::PageDown | KeyPress::Down => {
                        page = (page + 1).min(pages.len() - 1);
                        break;
                    }
                    KeyPress::PageUp | KeyPress::Up => {
                        page = page.saturating_sub(1);
                        break;
                    }
                    KeyPress::End => {
                        page = pages.len() - 1;
                        break;
                    }
                    KeyPress::Home => {
                        page = 0;
                        break;
                    }
                    KeyPress::MouseScroll(dz) => {
                        controls::scroll(&mut page, dz, pages.len(), 1);
                        break;
                    }
                    KeyPress::Enter | KeyPress::Char(' ') => Some(focused),
                    KeyPress::MouseClick { x, y } => {
                        if controls::scroll_track(
                            &mut page,
                            list,
                            (x as i32, y as i32),
                            pages.len(),
                            1,
                        ) {
                            break;
                        }
                        rects.iter().position(|r| contains(*r, x as i32, y as i32))
                    }
                    _ => None,
                };
                match activation {
                    Some(0) => {
                        cursor.hide(fb);
                        return false;
                    }
                    // Unseen identities: confirm moves to the first page that
                    // still has unseen lines instead of committing.
                    Some(_) if !all_seen => {
                        page = unseen_pages(&pages, &shown).next().unwrap_or(page);
                        break;
                    }
                    Some(_) => {
                        cursor.hide(fb);
                        return true;
                    }
                    None => {}
                }
            }
            fb.wait_for_frame().await;
        }
    }
}
