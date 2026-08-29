//! Pure SD/MMC response and card-geometry helpers.

/// Normalize SDHCI's stripped 136-bit response registers into canonical
/// `[MSW, ..., LSW]` words containing CSD/CID bits 127:0.
pub fn normalize_r2(raw: [u32; 4]) -> [u32; 4] {
    [
        (raw[3] << 8) | (raw[2] >> 24),
        (raw[2] << 8) | (raw[1] >> 24),
        (raw[1] << 8) | (raw[0] >> 24),
        raw[0] << 8,
    ]
}

/// Extract up to 32 bits from a canonical 128-bit response.
///
/// `start` is numbered from the least-significant response bit, matching the
/// SD/MMC specifications and Linux's `UNSTUFF_BITS` convention.
pub fn extract_bits(response: &[u32; 4], start: u32, size: u32) -> Option<u32> {
    if size == 0 || size > 32 || start.checked_add(size)? > 128 {
        return None;
    }

    let word = 3usize.checked_sub((start / 32) as usize)?;
    let shift = start & 31;
    let mask = if size == 32 {
        u32::MAX
    } else {
        (1u32 << size) - 1
    };
    let mut value = response[word] >> shift;
    if shift + size > 32 {
        value |= response.get(word.checked_sub(1)?)? << (32 - shift);
    }
    Some(value & mask)
}

/// Parse an SD CSD and return the capacity in 512-byte logical blocks.
pub fn parse_sd_csd(csd: &[u32; 4]) -> Option<u64> {
    match extract_bits(csd, 126, 2)? {
        0 => parse_legacy_capacity(csd),
        1 => u64::from(extract_bits(csd, 48, 22)?)
            .checked_add(1)?
            .checked_mul(1024),
        _ => None,
    }
}

/// Parse a legacy MMC CSD and return the capacity in 512-byte logical blocks.
pub fn parse_mmc_csd(csd: &[u32; 4]) -> Option<u64> {
    parse_legacy_capacity(csd)
}

fn parse_legacy_capacity(csd: &[u32; 4]) -> Option<u64> {
    let c_size = u64::from(extract_bits(csd, 62, 12)?);
    let c_size_mult = extract_bits(csd, 47, 3)?;
    let read_bl_len = extract_bits(csd, 80, 4)?;
    if read_bl_len > 31 {
        return None;
    }

    let block_count = c_size
        .checked_add(1)?
        .checked_mul(1u64 << (c_size_mult + 2))?;
    let block_len = 1u64 << read_bl_len;
    block_count.checked_mul(block_len)?.checked_div(512)
}

/// Whether CMD6 check-mode status advertises high-speed function 1.
pub fn cmd6_supports_high_speed(status: &[u8; 64]) -> bool {
    status[13] & (1 << 1) != 0
}

/// Return the selected access-mode function from CMD6 switch-mode status.
pub fn cmd6_selected_function(status: &[u8; 64]) -> u8 {
    status[16] & 0x0f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_bits(response: &mut [u32; 4], start: u32, size: u32, value: u32) {
        for bit in 0..size {
            if value & (1 << bit) != 0 {
                let position = start + bit;
                let word = 3 - (position / 32) as usize;
                response[word] |= 1 << (position & 31);
            }
        }
    }

    #[test]
    fn normalizes_sdhci_r2_registers() {
        let canonical = [0x0123_4567, 0x89ab_cdef, 0x1020_3040, 0x5060_7000];
        let raw = [
            (canonical[3] >> 8) | (canonical[2] << 24),
            (canonical[2] >> 8) | (canonical[1] << 24),
            (canonical[1] >> 8) | (canonical[0] << 24),
            canonical[0] >> 8,
        ];
        assert_eq!(normalize_r2(raw), canonical);
    }

    #[test]
    fn extracts_cross_word_fields() {
        let response = [0x0123_4567, 0x89ab_cdef, 0x1020_3040, 0x5060_7080];
        assert_eq!(extract_bits(&response, 0, 8), Some(0x80));
        assert_eq!(extract_bits(&response, 28, 12), Some(0x405));
        assert_eq!(extract_bits(&response, 126, 2), Some(0));
        assert_eq!(extract_bits(&response, 120, 16), None);
    }

    #[test]
    fn parses_sdsc_sdhc_and_legacy_mmc_capacity() {
        let mut legacy = [0u32; 4];
        set_bits(&mut legacy, 126, 2, 0);
        set_bits(&mut legacy, 62, 12, 1023);
        set_bits(&mut legacy, 47, 3, 3);
        set_bits(&mut legacy, 80, 4, 9);
        assert_eq!(parse_sd_csd(&legacy), Some(32_768));
        assert_eq!(parse_mmc_csd(&legacy), Some(32_768));

        let mut high_capacity = [0u32; 4];
        set_bits(&mut high_capacity, 126, 2, 1);
        set_bits(&mut high_capacity, 48, 22, 0x12345);
        assert_eq!(parse_sd_csd(&high_capacity), Some((0x12345 + 1) * 1024));

        set_bits(&mut high_capacity, 126, 2, 2);
        assert_eq!(parse_sd_csd(&high_capacity), None);
    }

    #[test]
    fn cmd6_support_and_selection_are_distinct() {
        let mut status = [0u8; 64];
        status[13] = 1 << 1;
        assert!(cmd6_supports_high_speed(&status));
        assert_eq!(cmd6_selected_function(&status), 0);
        status[16] = 1;
        assert_eq!(cmd6_selected_function(&status), 1);
    }
}
