//! Independent TPM wire oracles used by the guest measurement test.

/// TPM2_PCR_Read, one SHA-256 selection containing only PCR 4.
pub const READ_PCR4_SHA256: [u8; 20] = [
    0x80, 0x01, 0, 0, 0, 20, 0, 0, 0x01, 0x7e, 0, 0, 0, 1, 0, 0x0b, 3, 0x10, 0, 0,
];

pub fn pcr4_sha256(response: &[u8]) -> Option<[u8; 32]> {
    let size = u32::from_be_bytes(response.get(2..6)?.try_into().ok()?) as usize;
    let response = response.get(..size)?;
    if response.get(..2)? != [0x80, 0x01]
        || response.get(6..10)? != [0, 0, 0, 0]
        || response.get(14..20)? != [0, 0, 0, 1, 0, 0x0b]
    {
        return None;
    }
    // pcrUpdateCounter occupies bytes 10..14. TPMs may return differently
    // sized selection bitmaps; require precisely PCR 4, not a fixed stride.
    let selection_size = usize::from(*response.get(20)?);
    if !(1..=4).contains(&selection_size) {
        return None;
    }
    let selection = response.get(21..21 + selection_size)?;
    if selection[0] != 0x10 || selection[1..].iter().any(|byte| *byte != 0) {
        return None;
    }
    let offset = 21 + selection_size;
    if response.get(offset..offset + 6)? != [0, 0, 0, 1, 0, 32] || size != offset + 6 + 32 {
        return None;
    }
    response.get(offset + 6..)?.try_into().ok()
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
        assert_eq!(pcr4_sha256(&response), Some([0x5a; 32]));
        for length in 0..response.len() {
            assert_eq!(pcr4_sha256(&response[..length]), None);
        }
        for (offset, value) in [(6, 1), (18, 1), (21, 0x20), (27, 2), (29, 31)] {
            let mut bad = response.clone();
            bad[offset] = value;
            assert_eq!(pcr4_sha256(&bad), None);
        }
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
