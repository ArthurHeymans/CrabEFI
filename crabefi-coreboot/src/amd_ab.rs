//! AMD PSP A/B slots (Family 19h model 40h and later, e.g. Strix Point).
//!
//! The PSP L1 directory (from the EFS) points to one Image Slot Header (ISH)
//! per slot (entry types 0x48 = A, 0x4A = B). The PSP boots the slot whose ISH
//! has a valid checksum and the highest priority; 0 means unbootable. An ISH
//! sits in its own flash sector outside both slots, so switching slots is one
//! sector write, and a torn write leaves that ISH invalid: the PSP then boots
//! the other slot.

use alloc::vec::Vec;

/// EFS location in flash of 16 MiB and more.
const EFS_OFFSET: u32 = 0x2_0000;
const EFS_SIGNATURE: u32 = 0x55AA_55AA;
/// EFS field with the PSP L1 directory location.
const EFS_PSP_DIR: u32 = 0x14;
const ISH_TYPE_A: u8 = 0x48;
const ISH_TYPE_B: u8 = 0x4A;
const ISH_SIZE: usize = 32;
const MAX_L1_ENTRIES: u32 = 32;

/// One Image Slot Header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ish {
    /// Flash offset of the header.
    pub offset: u32,
    pub priority: u32,
    /// Flash offset of the slot's PSP L2 directory.
    pub pl2: u32,
    /// Checksum matches and priority is not 0 (unbootable).
    pub bootable: bool,
    raw: [u8; ISH_SIZE],
}

/// Fletcher-32 over 16-bit words, as amdfwtool computes the ISH checksum.
pub fn fletcher32(data: &[u8]) -> u32 {
    let (mut c0, mut c1) = (0xFFFFu32, 0xFFFFu32);
    for block in data.chunks(359 * 2) {
        for word in block.as_chunks::<2>().0 {
            c0 += u32::from(u16::from_le_bytes(*word));
            c1 += c0;
        }
        c0 = (c0 & 0xFFFF) + (c0 >> 16);
        c1 = (c1 & 0xFFFF) + (c1 >> 16);
    }
    c0 = (c0 & 0xFFFF) + (c0 >> 16);
    c1 = (c1 & 0xFFFF) + (c1 >> 16);
    (c1 << 16) | c0
}

fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

/// Flash offset of an L1 directory location (address modes 0 and 1).
fn flash_offset(location: u64) -> Option<u32> {
    match location >> 62 {
        // Mode 1: relative to the start of the flash.
        1 => u32::try_from(location & 0x3FFF_FFFF_FFFF_FFFF).ok(),
        // Mode 0: physical address of the first 16 MiB mapped below 4 GiB.
        0 if (0xFF00_0000..0x1_0000_0000).contains(&location) => Some(location as u32 & 0xFF_FFFF),
        _ => None,
    }
}

fn parse_ish(offset: u32, raw: [u8; ISH_SIZE]) -> Ish {
    let priority = u32_at(&raw, 4);
    Ish {
        offset,
        priority,
        pl2: u32_at(&raw, 16),
        bootable: priority != 0 && fletcher32(&raw[4..]) == u32_at(&raw, 0),
        raw,
    }
}

/// ISH of slot A and B, read with `read(flash offset, buffer)`.
pub fn read_ishes(read: &mut impl FnMut(u32, &mut [u8]) -> bool) -> Option<[Ish; 2]> {
    let mut efs = [0u8; 0x18];
    if !read(EFS_OFFSET, &mut efs) || u32_at(&efs, 0) != EFS_SIGNATURE {
        return None;
    }
    let l1 = u32_at(&efs, EFS_PSP_DIR as usize);
    let mut header = [0u8; 16];
    if !read(l1, &mut header) || &header[..4] != b"$PSP" {
        return None;
    }
    let (mut a, mut b) = (None, None);
    for i in 0..u32_at(&header, 8).min(MAX_L1_ENTRIES) {
        let mut entry = [0u8; 16];
        if !read(l1 + 16 + 16 * i, &mut entry) {
            return None;
        }
        let location = u64::from_le_bytes(entry[8..16].try_into().ok()?);
        let slot = match entry[0] {
            ISH_TYPE_A => &mut a,
            ISH_TYPE_B => &mut b,
            _ => continue,
        };
        let offset = flash_offset(location)?;
        let mut raw = [0u8; ISH_SIZE];
        if !read(offset, &mut raw) {
            return None;
        }
        *slot = Some(parse_ish(offset, raw));
    }
    Some([a?, b?])
}

/// The header with a new priority and checksum.
pub fn with_priority(ish: &Ish, priority: u32) -> [u8; ISH_SIZE] {
    let mut raw = ish.raw;
    raw[4..8].copy_from_slice(&priority.to_le_bytes());
    let checksum = fletcher32(&raw[4..]);
    raw[..4].copy_from_slice(&checksum.to_le_bytes());
    raw
}

/// Header writes, in order, that make `target` boot instead of `other`. Each
/// intermediate state boots one of the two slots.
pub fn activation(target: &Ish, other: &Ish) -> Vec<(u32, [u8; ISH_SIZE])> {
    let mut writes = Vec::new();
    if !other.bootable {
        if !target.bootable {
            writes.push((target.offset, with_priority(target, target.priority.max(1))));
        }
        return writes;
    }
    if target.bootable && target.priority > other.priority {
        return writes;
    }
    let mut floor = other.priority;
    if floor == u32::MAX {
        // Nothing ranks above it: lower the other slot first (it keeps
        // booting until the target is raised).
        floor = 2;
        writes.push((other.offset, with_priority(other, floor)));
    }
    writes.push((target.offset, with_priority(target, floor + 1)));
    writes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ish(offset: u32, priority: u32, pl2: u32) -> Ish {
        // Layout as amdfwtool writes it: reserved bytes stay 0xFF.
        let mut raw = [0xFFu8; ISH_SIZE];
        raw[4..8].copy_from_slice(&priority.to_le_bytes());
        raw[8..12].copy_from_slice(&2u32.to_le_bytes());
        raw[12] = 0;
        raw[16..20].copy_from_slice(&pl2.to_le_bytes());
        raw[20..24].copy_from_slice(&0xBC0E_1000u32.to_le_bytes());
        let checksum = fletcher32(&raw[4..]);
        raw[..4].copy_from_slice(&checksum.to_le_bytes());
        parse_ish(offset, raw)
    }

    #[test]
    fn checksum_matches_amdfwtool() {
        // ISH A and B of the Jaguar 32 MiB A/B ROM (amdfwtool output).
        assert_eq!(
            ish(0x23000, u32::MAX, 0x41000).raw[..4],
            0x8288_DB15u32.to_le_bytes()
        );
        assert_eq!(
            ish(0x24000, 1, 0x100_1000).raw[..4],
            0x897A_DC12u32.to_le_bytes()
        );
    }

    #[test]
    fn activation_from_the_build_defaults() {
        let (a, b) = (ish(0x23000, u32::MAX, 0x41000), ish(0x24000, 1, 0x100_1000));
        let writes = activation(&b, &a);
        assert_eq!(writes.len(), 2);
        let lowered = parse_ish(a.offset, writes[0].1);
        let raised = parse_ish(b.offset, writes[1].1);
        assert_eq!(
            (writes[0].0, lowered.priority, lowered.bootable),
            (0x23000, 2, true)
        );
        assert_eq!(
            (writes[1].0, raised.priority, raised.bootable),
            (0x24000, 3, true)
        );
        assert!(activation(&a, &b).is_empty());
    }

    #[test]
    fn activation_takes_one_write_after_the_first_switch() {
        let (a, b) = (ish(0x23000, 2, 0x41000), ish(0x24000, 3, 0x100_1000));
        let writes = activation(&a, &b);
        assert_eq!(writes.len(), 1);
        assert_eq!(parse_ish(a.offset, writes[0].1).priority, 4);
    }

    #[test]
    fn reads_the_l1_directory() {
        let mut flash = alloc::vec![0xFFu8; 0x30000];
        flash[0x20000..0x20004].copy_from_slice(&EFS_SIGNATURE.to_le_bytes());
        flash[0x20014..0x20018].copy_from_slice(&0x21000u32.to_le_bytes());
        flash[0x21000..0x21004].copy_from_slice(b"$PSP");
        flash[0x21008..0x2100C].copy_from_slice(&2u32.to_le_bytes());
        for (i, (kind, at)) in [(ISH_TYPE_A, 0x23000u64), (ISH_TYPE_B, 0x24000)]
            .iter()
            .enumerate()
        {
            let e = 0x21010 + 16 * i;
            flash[e] = *kind;
            flash[e + 8..e + 16].copy_from_slice(&((1u64 << 62) | at).to_le_bytes());
        }
        flash[0x23000..0x23020].copy_from_slice(&ish(0x23000, u32::MAX, 0x41000).raw);
        flash[0x24000..0x24020].copy_from_slice(&ish(0x24000, 1, 0x100_1000).raw);
        let [a, b] = read_ishes(&mut |offset, buf: &mut [u8]| {
            let o = offset as usize;
            buf.copy_from_slice(&flash[o..o + buf.len()]);
            true
        })
        .unwrap();
        assert_eq!((a.offset, a.pl2, a.bootable), (0x23000, 0x41000, true));
        assert_eq!((b.offset, b.priority, b.bootable), (0x24000, 1, true));
    }
}
