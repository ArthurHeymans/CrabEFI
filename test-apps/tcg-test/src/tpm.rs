//! Independent TPM wire oracles used by the guest measurement test.

/// TPM2_PCR_Read, one SHA-256 selection containing only PCR `index` (0..24).
pub fn read_pcr_sha256(index: u8) -> [u8; 20] {
    let mut command = [
        0x80, 0x01, 0, 0, 0, 20, 0, 0, 0x01, 0x7e, 0, 0, 0, 1, 0, 0x0b, 3, 0, 0, 0,
    ];
    command[17 + usize::from(index / 8)] = 1 << (index % 8);
    command
}

pub fn pcr_sha256(response: &[u8], index: u8) -> Option<[u8; 32]> {
    let size = u32::from_be_bytes(response.get(2..6)?.try_into().ok()?) as usize;
    let response = response.get(..size)?;
    if response.get(..2)? != [0x80, 0x01]
        || response.get(6..10)? != [0, 0, 0, 0]
        || response.get(14..20)? != [0, 0, 0, 1, 0, 0x0b]
    {
        return None;
    }
    // pcrUpdateCounter occupies bytes 10..14. TPMs may return differently
    // sized selection bitmaps; require precisely PCR `index`, not a fixed stride.
    let selection_size = usize::from(*response.get(20)?);
    if !(1..=4).contains(&selection_size) {
        return None;
    }
    let selection = response.get(21..21 + selection_size)?;
    let byte = usize::from(index / 8);
    if selection
        .iter()
        .enumerate()
        .any(|(offset, bits)| *bits != if offset == byte { 1 << (index % 8) } else { 0 })
        || byte >= selection_size
    {
        return None;
    }
    let offset = 21 + selection_size;
    if response.get(offset..offset + 6)? != [0, 0, 0, 1, 0, 32] || size != offset + 6 + 32 {
        return None;
    }
    response.get(offset + 6..)?.try_into().ok()
}

pub const EV_NO_ACTION: u32 = 0x3;

/// Walk a crypto-agile event log from its Specification ID header through
/// the TCG_PCR_EVENT2 at `last`, handing each event's PCR, type and SHA-256
/// digest to `event`. Reads only declared fields; false on a malformed log.
pub fn walk_log(
    mut read: impl FnMut(usize, &mut [u8]) -> bool,
    last: usize,
    mut event: impl FnMut(u32, u32, Option<[u8; 32]>),
) -> bool {
    // TCG_PCClientPCREvent: PCR, EV_NO_ACTION, zero SHA-1, event size.
    let mut header = [0u8; 32];
    if !read(0, &mut header) || header[4..8] != EV_NO_ACTION.to_le_bytes() {
        return false;
    }
    let mut offset = 32 + u32::from_le_bytes(header[28..32].try_into().unwrap()) as usize;
    while offset <= last {
        let start = offset;
        let mut fields = [0u8; 12];
        if !read(offset, &mut fields) {
            return false;
        }
        let word = |at: usize| u32::from_le_bytes(fields[at..at + 4].try_into().unwrap());
        let (pcr, event_type, count) = (word(0), word(4), word(8));
        if !(1..=8).contains(&count) {
            return false;
        }
        offset += 12;
        let mut sha256 = None;
        for _ in 0..count {
            let mut algorithm = [0; 2];
            if !read(offset, &mut algorithm) {
                return false;
            }
            let length = match u16::from_le_bytes(algorithm) {
                0x0004 => 20,
                0x000b => 32,
                0x000c => 48,
                0x000d => 64,
                _ => return false,
            };
            let mut digest = [0; 64];
            if !read(offset + 2, &mut digest[..length]) {
                return false;
            }
            if length == 32 {
                sha256 = digest[..32].try_into().ok();
            }
            offset += 2 + length;
        }
        let mut size = [0; 4];
        if !read(offset, &mut size) {
            return false;
        }
        offset += 4 + u32::from_le_bytes(size) as usize;
        event(pcr, event_type, sha256);
        if start == last {
            return true;
        }
    }
    false
}

/// Verify the last crypto-agile TCG_PCR_EVENT2 using bounded individual reads.
/// The guest reads firmware-owned memory; host tests supply a bounded slice.
/// Never read padding past the declared digests/event data.
pub fn measurement_event_matches(
    mut read: impl FnMut(usize, &mut [u8]) -> bool,
    expected_digest: &[u8; 32],
    expected_event: &[u8],
) -> bool {
    let mut header = [0u8; 12];
    if !read(0, &mut header) || header[..4] != [4, 0, 0, 0] || header[4..8] != [13, 0, 0, 0] {
        return false;
    }
    let count = u32::from_le_bytes(header[8..12].try_into().unwrap());
    if !(1..=8).contains(&count) {
        return false;
    }
    let mut offset = 12;
    let mut found_sha256 = false;
    for _ in 0..count {
        let mut algorithm = [0; 2];
        if !read(offset, &mut algorithm) {
            return false;
        }
        offset += 2;
        let length = match u16::from_le_bytes(algorithm) {
            0x0004 => 20, // SHA-1
            0x000b => 32, // SHA-256
            0x000c => 48, // SHA-384
            0x000d => 64, // SHA-512
            _ => return false,
        };
        let mut digest = [0; 64];
        if !read(offset, &mut digest[..length]) {
            return false;
        }
        offset += length;
        if algorithm == [0x0b, 0] {
            if found_sha256 || digest[..32] != *expected_digest {
                return false;
            }
            found_sha256 = true;
        }
    }
    let mut size = [0; 4];
    if !found_sha256
        || !read(offset, &mut size)
        || u32::from_le_bytes(size) as usize != expected_event.len()
    {
        return false;
    }
    offset += 4;
    for expected in expected_event.chunks(64) {
        let mut actual = [0; 64];
        if !read(offset, &mut actual[..expected.len()]) || actual[..expected.len()] != *expected {
            return false;
        }
        offset += expected.len();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcr_response_requires_success_exact_selection_and_digest() {
        // TPM_ST_NO_SESSIONS, 62-byte response, SUCCESS, update counter 7,
        // one SHA-256 PCR-4 selection and one 32-byte TPM2B_DIGEST.
        let mut response = vec![
            0x80, 1, 0, 0, 0, 62, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0x0b, 3, 0x10, 0, 0, 0, 0,
            0, 1, 0, 32,
        ];
        response.extend_from_slice(&[0x5a; 32]);
        assert_eq!(read_pcr_sha256(4)[17..], [0x10, 0, 0]);
        assert_eq!(pcr_sha256(&response, 4), Some([0x5a; 32]));
        assert_eq!(pcr_sha256(&response, 5), None);
        for length in 0..response.len() {
            assert_eq!(pcr_sha256(&response[..length], 4), None);
        }
        for (offset, value) in [(6, 1), (18, 1), (21, 0x20), (22, 1), (27, 2), (29, 31)] {
            let mut bad = response.clone();
            bad[offset] = value;
            assert_eq!(pcr_sha256(&bad, 4), None);
        }
    }

    #[test]
    fn log_walk_yields_every_event_through_the_last() {
        let mut log = vec![0, 0, 0, 0, 3, 0, 0, 0];
        log.extend_from_slice(&[0; 20]);
        log.extend_from_slice(&[2, 0, 0, 0, 0xaa, 0xbb]);
        let first = log.len();
        for (pcr, digest) in [(7u32, 0x11u8), (4, 0x22)] {
            log.extend_from_slice(&pcr.to_le_bytes());
            log.extend_from_slice(&[4, 0, 0, 0, 2, 0, 0, 0, 4, 0]);
            log.extend_from_slice(&[0; 20]);
            log.extend_from_slice(&[0x0b, 0]);
            log.extend_from_slice(&[digest; 32]);
            log.extend_from_slice(&[1, 0, 0, 0, 0]);
        }
        let last = first + (log.len() - first) / 2;
        let walk = |bytes: &[u8], last: usize| {
            let mut events = Vec::new();
            let ok = walk_log(
                |offset, out| {
                    let Some(source) = bytes.get(offset..offset + out.len()) else {
                        return false;
                    };
                    out.copy_from_slice(source);
                    true
                },
                last,
                |pcr, event_type, sha256| events.push((pcr, event_type, sha256)),
            );
            ok.then_some(events)
        };
        assert_eq!(
            walk(&log, last),
            Some(vec![(7, 4, Some([0x11; 32])), (4, 4, Some([0x22; 32]))])
        );
        assert_eq!(walk(&log, first), Some(vec![(7, 4, Some([0x11; 32]))]));
        assert_eq!(walk(&log, last + 1), None);
        // Event data is skipped, not read; a cut digest is a malformed log.
        assert_eq!(walk(&log[..log.len() - 6], last), None);
    }

    #[test]
    fn measurement_log_requires_pcr_type_digest_and_exact_event_data() {
        let mut entry = vec![4, 0, 0, 0, 13, 0, 0, 0, 1, 0, 0, 0, 0x0b, 0];
        entry.extend_from_slice(&[0x5a; 32]);
        entry.extend_from_slice(&[3, 0, 0, 0, b'a', b'b', b'c']);
        let matches = |bytes: &[u8]| {
            measurement_event_matches(
                |offset, out| {
                    let Some(source) = bytes.get(offset..offset + out.len()) else {
                        return false;
                    };
                    out.copy_from_slice(source);
                    true
                },
                &[0x5a; 32],
                b"abc",
            )
        };
        assert!(matches(&entry));
        for length in 0..entry.len() {
            assert!(!matches(&entry[..length]));
        }
        for offset in [0, 4, 8, 12, 14, 46, 50] {
            let mut bad = entry.clone();
            bad[offset] ^= 1;
            assert!(!matches(&bad), "field at {offset}");
        }
    }
}
