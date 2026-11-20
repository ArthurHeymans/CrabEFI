use super::{Block, wrap_lines};
use crate::Surface;
use crate::screens::layout::Metrics;
use crate::screens::{render, theme};
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineKind {
    Body,
    /// "SHA-256 <hex groups>", prefix drawn quieter.
    Fingerprint,
    Note,
    Warn,
}
#[derive(Clone)]
pub struct ReviewLine {
    pub kind: LineKind,
    pub text: String,
}
/// One identity or fact group; kept whole on a page whenever it fits.
#[derive(Clone)]
pub struct ReviewSection {
    pub label: String,
    pub lines: Vec<ReviewLine>,
}
impl ReviewSection {
    pub fn new(label: &str, text: &str) -> Self {
        Self {
            label: String::from(label),
            lines: alloc::vec![ReviewLine {
                kind: LineKind::Body,
                text: String::from(text),
            }],
        }
    }
    pub fn labelled(label: &str) -> Self {
        Self {
            label: String::from(label),
            lines: Vec::new(),
        }
    }
    pub fn line(mut self, kind: LineKind, text: &str) -> Self {
        self.lines.push(ReviewLine {
            kind,
            text: String::from(text),
        });
        self
    }
    /// Text of the section, for tests and serial logs.
    pub fn text(&self) -> String {
        let mut s = String::new();
        for line in &self.lines {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(&line.text);
        }
        s
    }
}

pub(super) fn section_label_width(fb: &Surface, sections: &[ReviewSection]) -> u32 {
    let m = Metrics::for_fb(fb);
    sections
        .iter()
        .map(|s| render::text_width(&s.label, m.body))
        .max()
        .unwrap_or(0)
        .max(if m.large { 70 } else { 40 })
        + 14
}

/// One painted line of a review section.
pub(super) struct VLine {
    kind: LineKind,
    text: String,
    /// Space above this line (paragraph spacing inside a section).
    gap: u32,
    advance: u32,
    /// First wrapped line of a fingerprint keeps its quieter "SHA-256" prefix.
    first: bool,
}

/// Section chrome around its lines: rule plus padding above, padding below.
const SECTION_TOP: u32 = 8;
const SECTION_BOTTOM: u32 = 6;

pub(super) fn layout_section(
    fb: &Surface,
    w: u32,
    label_w: u32,
    section: &ReviewSection,
) -> Vec<VLine> {
    let m = Metrics::for_fb(fb);
    let tw = w.saturating_sub(label_w);
    let mut out = Vec::new();
    for (i, line) in section.lines.iter().enumerate() {
        let (size, advance) = if line.kind == LineKind::Note {
            (m.small, m.small_line)
        } else {
            (m.body, m.line)
        };
        let cols = (tw / render::font_width(size)).max(1) as usize;
        for (j, text) in wrap_lines(&line.text, cols).into_iter().enumerate() {
            out.push(VLine {
                kind: line.kind,
                text,
                gap: if i > 0 && j == 0 && line.kind == LineKind::Body {
                    4
                } else {
                    0
                },
                advance,
                first: j == 0,
            });
        }
    }
    out
}

pub(super) fn vlines_height(lines: &[VLine]) -> u32 {
    lines.iter().map(|l| l.gap + l.advance).sum::<u32>() + SECTION_TOP + SECTION_BOTTOM
}

pub(super) fn paint_vlines(
    fb: &Surface,
    x: i32,
    y: i32,
    w: u32,
    label_w: u32,
    label: &str,
    lines: &[VLine],
) -> u32 {
    let m = Metrics::for_fb(fb);
    let tx = x + label_w as i32;
    render::fill_rect(fb, x, y, w, 1, theme::RULE);
    render::draw_text_bold(
        fb,
        x,
        y + SECTION_TOP as i32,
        label,
        m.body,
        theme::INK,
        None,
    );
    let mut cy = y + SECTION_TOP as i32;
    for line in lines {
        cy += line.gap as i32;
        let size = if line.kind == LineKind::Note {
            m.small
        } else {
            m.body
        };
        match line.kind {
            LineKind::Fingerprint if line.first && line.text.starts_with("SHA-256 ") => {
                let pw = render::draw_text(fb, tx, cy, "SHA-256 ", size, theme::INK3, None);
                render::draw_text(
                    fb,
                    tx + pw as i32,
                    cy,
                    &line.text[8..],
                    size,
                    theme::INK,
                    None,
                );
            }
            LineKind::Note => {
                render::draw_text(fb, tx, cy, &line.text, size, theme::INK3, None);
            }
            LineKind::Warn => {
                render::draw_text_bold(fb, tx, cy, &line.text, size, theme::WARN, None);
            }
            _ => {
                render::draw_text(fb, tx, cy, &line.text, size, theme::INK, None);
            }
        }
        cy += line.advance as i32;
    }
    (cy - y) as u32 + SECTION_BOTTOM
}

/// A page shows, for each listed section, a range of its visual lines.
pub(super) type Page = Vec<(usize, core::ops::Range<usize>)>;

/// Whole sections per page where they fit. A section taller than a page is
/// split between its lines, preferring line-group (fingerprint) boundaries,
/// so nothing is ever painted outside the list area.
pub(super) fn paginate(sections: &[Vec<VLine>], room: u32) -> Vec<Page> {
    let mut pages: Vec<Page> = Vec::new();
    let mut page: Page = Vec::new();
    let mut used = 0;
    let body_room = room.saturating_sub(SECTION_TOP + SECTION_BOTTOM).max(1);
    for (s, lines) in sections.iter().enumerate() {
        let h = vlines_height(lines);
        if h <= room {
            if used + h > room && !page.is_empty() {
                pages.push(core::mem::take(&mut page));
                used = 0;
            }
            page.push((s, 0..lines.len()));
            used += h;
            continue;
        }
        if !page.is_empty() {
            pages.push(core::mem::take(&mut page));
            used = 0;
        }
        let mut start = 0;
        while start < lines.len() {
            let mut end = start;
            let mut acc = 0;
            while end < lines.len() {
                let line_h = lines[end].gap + lines[end].advance;
                if end > start && acc + line_h > body_room {
                    // Prefer not to split a wrapped line group across pages.
                    let group_start = (start..=end).rev().find(|i| lines[*i].first).unwrap_or(end);
                    if group_start > start {
                        end = group_start;
                    }
                    break;
                }
                acc += line_h;
                end += 1;
            }
            pages.push(alloc::vec![(s, start..end)]);
            start = end;
        }
    }
    if !page.is_empty() || pages.is_empty() {
        pages.push(page);
    }
    pages
}

pub(super) fn mark_shown(shown: &mut [Vec<bool>], page: &Page) {
    for (s, range) in page {
        shown[*s][range.clone()].fill(true);
    }
}

/// Indices of pages that still hold a line the user has not seen.
pub(super) fn unseen_pages<'a>(
    pages: &'a [Page],
    shown: &'a [Vec<bool>],
) -> impl Iterator<Item = usize> + 'a {
    pages
        .iter()
        .enumerate()
        .filter(|(_, p)| p.iter().any(|(s, r)| shown[*s][r.clone()].contains(&false)))
        .map(|(i, _)| i)
}

pub(super) fn block_sections(blocks: &[Block]) -> Vec<ReviewSection> {
    blocks
        .iter()
        .map(|b| match b {
            Block::Text(t) => ReviewSection::labelled("").line(LineKind::Body, t),
            Block::Muted(t) => ReviewSection::labelled("").line(LineKind::Body, t),
            Block::Fact { key, value, .. } => {
                ReviewSection::labelled(key).line(LineKind::Body, value)
            }
            Block::Change { name, from, to } => ReviewSection::labelled(name)
                .line(LineKind::Body, &alloc::format!("{from} -> {to}")),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A section of `groups` line groups, each `per` wrapped lines of 20 px.
    fn section(groups: usize, per: usize) -> Vec<VLine> {
        (0..groups)
            .flat_map(|_g| {
                (0..per).map(move |j| VLine {
                    kind: LineKind::Body,
                    text: String::new(),
                    gap: 0,
                    advance: 20,
                    first: j == 0,
                })
            })
            .collect()
    }
    fn page_height(sections: &[Vec<VLine>], page: &Page) -> u32 {
        page.iter()
            .map(|(s, r)| vlines_height(&sections[*s][r.clone()]))
            .sum()
    }

    #[test]
    fn identities_page_as_whole_blocks() {
        // Section heights: 3 lines = 74 px, 1 line = 34 px.
        let sections = [section(3, 1), section(3, 1), section(1, 1), section(3, 1)];
        let pages = paginate(&sections, 190);
        assert_eq!(pages.len(), 2);
        for page in &pages {
            for (s, r) in page {
                assert_eq!(
                    r.clone(),
                    0..sections[*s].len(),
                    "whole blocks when they fit"
                );
            }
            assert!(page_height(&sections, page) <= 190);
        }
        assert_eq!(paginate(&sections, 10_000).len(), 1);
        assert_eq!(paginate(&[], 100).len(), 1);
    }

    #[test]
    fn oversized_blocks_split_between_lines_and_never_overflow() {
        // A 2-line fingerprint group must not be split when the page can hold it.
        let sections = [section(1, 1), section(6, 2)];
        let room = 110;
        let pages = paginate(&sections, room);
        let mut covered = std::vec![std::vec![0; 1], std::vec![0; 12]];
        for page in &pages {
            assert!(
                page_height(&sections, page) <= room,
                "nothing painted outside"
            );
            for (s, r) in page {
                for i in r.clone() {
                    covered[*s][i] += 1;
                }
                if *s == 1 {
                    assert!(
                        sections[1][r.start].first,
                        "pages start at a group boundary"
                    );
                }
            }
        }
        assert!(
            covered.iter().flatten().all(|n| *n == 1),
            "every line exactly once"
        );
    }

    #[test]
    fn jumping_to_the_last_page_does_not_count_as_review() {
        let sections = [section(4, 1), section(4, 1), section(4, 1)];
        let pages = paginate(&sections, 100);
        assert_eq!(pages.len(), 3);
        let mut shown: Vec<Vec<bool>> =
            sections.iter().map(|s| std::vec![false; s.len()]).collect();
        mark_shown(&mut shown, &pages[0]);
        mark_shown(&mut shown, &pages[2]); // End
        assert_eq!(unseen_pages(&pages, &shown).collect::<Vec<_>>(), [1]);
        mark_shown(&mut shown, &pages[1]);
        assert_eq!(unseen_pages(&pages, &shown).count(), 0);
    }
}
