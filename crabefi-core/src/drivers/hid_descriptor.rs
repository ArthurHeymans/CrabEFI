//! Resource-bounded entry point to the allocating HID descriptor parser.

use alloc::vec::Vec;
use hidreport::hid::{GlobalItem, Item, ItemType, LocalItem, MainItem, ReportDescriptorItems};
use hidreport::{Report, ReportDescriptor};

/// The parser eagerly expands report counts and usage ranges and clones
/// collection metadata into every field. Bound that work *before* parsing,
/// including output/feature reports that our input drivers do not consume.
/// Itemization itself is bounded by the descriptor's byte length.
pub(super) fn parse(bytes: &[u8]) -> Option<ReportDescriptor> {
    if !(1..=4096).contains(&bytes.len()) {
        return None;
    }
    let items = ReportDescriptorItems::try_from(bytes).ok()?;
    #[derive(Clone, Copy, Default)]
    struct State {
        size: usize,
        count: usize,
        page: bool,
        usages: usize,
        minimum: Option<u32>,
        maximum: Option<u32>,
    }
    let mut state = State::default();
    let mut stack = Vec::new();
    let mut collections = Vec::new();
    let mut fields = 0usize;
    let mut bits = 0usize;
    let mut metadata = 0usize;
    for item in items.iter() {
        match item.item().item_type() {
            ItemType::Global(GlobalItem::ReportSize(v)) => state.size = usize::from(v),
            ItemType::Global(GlobalItem::ReportCount(v)) => state.count = usize::from(v),
            ItemType::Global(GlobalItem::UsagePage(_)) => state.page = true,
            ItemType::Global(GlobalItem::Push) => {
                if stack.len() >= 16 {
                    return None;
                }
                // Mirror the parser's local-state cloning on Push/Pop as well.
                stack.push(state);
            }
            ItemType::Global(GlobalItem::Pop) => state = stack.pop()?,
            ItemType::Local(LocalItem::UsageId(_)) => {
                // compile_usages otherwise panics on a missing global page.
                if !state.page {
                    return None;
                }
                state.usages += 1;
            }
            ItemType::Local(LocalItem::Usage(_, _)) => state.usages += 1,
            ItemType::Local(LocalItem::UsageMinimum(v)) => state.minimum = Some(u32::from(v)),
            ItemType::Local(LocalItem::UsageMaximum(v)) => state.maximum = Some(u32::from(v)),
            ItemType::Main(main) => {
                let usages = if let Some(minimum) = state.minimum {
                    let maximum = state.maximum?;
                    if !state.page || maximum < minimum {
                        return None;
                    }
                    usize::try_from(maximum - minimum).ok()?.checked_add(1)?
                } else {
                    state.usages
                };
                if usages > 1024 {
                    return None;
                }
                match main {
                    MainItem::Collection(_) => {
                        if collections.len() >= 16 {
                            return None;
                        }
                        collections.push(usages);
                        metadata = metadata.checked_add(usages + 1)?;
                    }
                    MainItem::EndCollection => {
                        collections.pop()?;
                    }
                    MainItem::Input(_) | MainItem::Output(_) | MainItem::Feature(_) => {
                        // Conservative: charge arrays and padding as if each
                        // element were an individually allocated variable.
                        fields = fields.checked_add(state.count)?;
                        bits = bits.checked_add(state.count.checked_mul(state.size)?)?;
                        let collection_cost = collections.iter().map(|n| n + 1).sum::<usize>();
                        metadata = metadata
                            .checked_add(usages)?
                            .checked_add(state.count.checked_mul(collection_cost + 1)?)?;
                    }
                }
                state.usages = 0;
                state.minimum = None;
                state.maximum = None;
            }
            _ => {}
        }
        if fields > 1024 || bits > 4096 * 8 || metadata > 8192 || state.usages > 1024 {
            return None;
        }
    }
    drop(items);
    ReportDescriptor::try_from(bytes).ok()
}

/// Whole endpoint packets avoid a partial final packet that can babble when
/// the device sends another full packet instead of ending with a short one.
pub(super) fn input_capacity(packet: u16, report_size: usize) -> Option<usize> {
    let packet = usize::from(packet & 0x7ff);
    if packet == 0 || report_size > 4096 {
        return None;
    }
    Some(report_size.max(1).div_ceil(packet) * packet)
}

/// Include unrelated report IDs sharing the same interrupt endpoint.
pub(super) fn input_size(descriptor: &ReportDescriptor) -> usize {
    descriptor
        .input_reports()
        .iter()
        .map(|r| r.size_in_bytes())
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_expansion_bombs_before_allocating_fields_or_usages() {
        // Tiny descriptors can request billions of fields, bits, or usages.
        for bytes in [
            &[
                0x05, 1, 0x09, 2, 0x75, 8, 0x97, 0xff, 0xff, 0xff, 0xff, 0x81, 2,
            ][..],
            &[0x05, 1, 0x19, 0, 0x2b, 0xff, 0xff, 0xff, 0xff, 0xa1, 1][..],
            &[
                0x05, 1, 0x09, 2, 0x77, 0xff, 0xff, 0xff, 0xff, 0x95, 2, 0x81, 2,
            ][..],
            &[0x09, 2, 0xa1, 1][..], // missing usage page must not panic
        ] {
            assert!(parse(bytes).is_none());
        }
    }

    #[test]
    fn bounds_collection_metadata_cloned_into_fields() {
        let bytes = [
            0x05, 1, 0x19, 0, 0x2a, 0xff, 3, 0xa1, 1, // 1024 collection usages
            0x09, 0x30, 0x75, 8, 0x95, 8, 0x81, 2, 0xc0,
        ];
        assert!(parse(&bytes).is_none());
    }

    #[test]
    fn bounds_aggregate_expansion_and_honors_push_pop() {
        let mut bytes = alloc::vec![0x05, 1, 0x09, 2, 0xa1, 1, 0x75, 8, 0x95, 64];
        for _ in 0..17 {
            bytes.extend_from_slice(&[0x09, 0x30, 0x81, 2]);
        }
        assert!(parse(&bytes).is_none());
        let mut bytes = alloc::vec![0x05, 1, 0x09, 2, 0xa1, 1, 0x75, 8, 0x95, 2];
        bytes.extend_from_slice(&[0xa4, 0x95, 1, 0xb4, 0x09, 0x30, 0x81, 2, 0xc0]);
        assert_eq!(input_size(&parse(&bytes).unwrap()), 2);
        let mut bytes = alloc::vec![0x05, 1];
        bytes.extend(core::iter::repeat_n(0xa4, 17));
        assert!(parse(&bytes).is_none());
    }
}
