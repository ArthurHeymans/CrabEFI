//! Pure AHCI/ATA geometry, signature, DMA-range, and FIS calculations.

/// Device class represented by an exact SATA signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    /// ATA disk.
    Sata,
    /// ATAPI packet device.
    Satapi,
    /// Enclosure-management bridge.
    Semb,
    /// Port multiplier.
    PortMultiplier,
}

/// ATA disk addressing mode selected from IDENTIFY data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtaAddressing {
    /// 28-bit LBA commands.
    Lba28,
    /// 48-bit LBA commands.
    Lba48,
}

/// Validated ATA disk geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtaGeometry {
    /// Addressing command family.
    pub addressing: AtaAddressing,
    /// Number of logical sectors.
    pub sector_count: u64,
    /// Logical sector size in bytes.
    pub sector_size: u32,
}

/// Classify only signatures defined by the AHCI specification.
pub const fn classify_signature(signature: u32) -> Option<SignatureKind> {
    match signature {
        0x0000_0101 => Some(SignatureKind::Sata),
        0xeb14_0101 => Some(SignatureKind::Satapi),
        0xc33c_0101 => Some(SignatureKind::Semb),
        0x9669_0101 => Some(SignatureKind::PortMultiplier),
        _ => None,
    }
}

/// Parse validated LBA capability, capacity, and logical sector size.
pub fn identify_geometry(words: &[u16; 256]) -> Option<AtaGeometry> {
    // ATA word 49 bit 9: LBA supported.
    if words[49] & (1 << 9) == 0 {
        return None;
    }
    let lba28 = u64::from(words[60]) | (u64::from(words[61]) << 16);
    if lba28 == 0 {
        return None;
    }
    // Linux ata_id_has_lba48(): validity bits 15:14 must be 01 and bit 10 set.
    let word83 = words[83];
    let lba48_supported = word83 & 0xc000 == 0x4000 && word83 & (1 << 10) != 0;
    let lba48 = u64::from(words[100])
        | (u64::from(words[101]) << 16)
        | (u64::from(words[102]) << 32)
        | (u64::from(words[103]) << 48);
    let (addressing, sector_count) = if lba48_supported && lba48 != 0 {
        (AtaAddressing::Lba48, lba48)
    } else {
        (AtaAddressing::Lba28, lba28.min(1 << 28))
    };

    // Word 106 is valid only when bits 15:14 are 01. Bit 12 then selects the
    // words 117-118 logical-sector word count.
    let word106 = words[106];
    let sector_size = if word106 & 0xd000 == 0x5000 {
        let words_per_sector = u32::from(words[117]) | (u32::from(words[118]) << 16);
        words_per_sector
            .checked_mul(2)
            .filter(|size| *size >= 512)?
    } else {
        512
    };
    Some(AtaGeometry {
        addressing,
        sector_count,
        sector_size,
    })
}

/// Return whether the complete byte range is visible through a DMA mask.
pub const fn dma_range_fits(address: u64, byte_len: usize, max_address: u64) -> bool {
    if byte_len == 0 {
        return false;
    }
    match address.checked_add(byte_len as u64 - 1) {
        Some(last) => last <= max_address,
        None => false,
    }
}

/// Validate an ATA read range and command count encoding.
pub const fn read_range_valid(
    addressing: AtaAddressing,
    sector_count: u64,
    start_lba: u64,
    count: u32,
) -> bool {
    if count == 0 {
        return false;
    }
    let command_limit = match addressing {
        AtaAddressing::Lba28 => 256,
        AtaAddressing::Lba48 => 65536,
    };
    if count > command_limit {
        return false;
    }
    let Some(end) = start_lba.checked_add(count as u64) else {
        return false;
    };
    end <= sector_count
        && match addressing {
            AtaAddressing::Lba28 => end <= 1 << 28,
            AtaAddressing::Lba48 => end <= 1 << 48,
        }
}

/// Register-FIS fields required for one ATA DMA read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadFis {
    /// ATA command opcode.
    pub command: u8,
    /// Six LBA bytes, low first.
    pub lba: [u8; 6],
    /// Device/head register.
    pub device: u8,
    /// Low count byte.
    pub count_low: u8,
    /// High count byte.
    pub count_high: u8,
}

/// Encode an LBA28 or LBA48 DMA-read FIS.
pub const fn encode_read_fis(addressing: AtaAddressing, lba: u64, count: u32) -> Option<ReadFis> {
    let limit = match addressing {
        AtaAddressing::Lba28 => 1 << 28,
        AtaAddressing::Lba48 => 1 << 48,
    };
    if lba >= limit || count == 0 {
        return None;
    }
    match addressing {
        AtaAddressing::Lba28 if count <= 256 => Some(ReadFis {
            command: 0xc8,
            lba: [lba as u8, (lba >> 8) as u8, (lba >> 16) as u8, 0, 0, 0],
            device: 0x40 | ((lba >> 24) as u8 & 0x0f),
            count_low: if count == 256 { 0 } else { count as u8 },
            count_high: 0,
        }),
        AtaAddressing::Lba48 if count <= 65536 => Some(ReadFis {
            command: 0x25,
            lba: [
                lba as u8,
                (lba >> 8) as u8,
                (lba >> 16) as u8,
                (lba >> 24) as u8,
                (lba >> 32) as u8,
                (lba >> 40) as u8,
            ],
            device: 0x40,
            count_low: count as u8,
            count_high: (count >> 8) as u8,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_are_strict() {
        assert_eq!(classify_signature(0x101), Some(SignatureKind::Sata));
        assert_eq!(classify_signature(0xeb14_0101), Some(SignatureKind::Satapi));
        assert_eq!(classify_signature(0), None);
        assert_eq!(classify_signature(u32::MAX), None);
        assert_eq!(classify_signature(0x1234_0101), None);
    }

    #[test]
    fn identify_checks_lba48_validity_and_sector_size() {
        let mut words = [0u16; 256];
        assert!(identify_geometry(&words).is_none());
        words[49] = 1 << 9;
        words[60] = 0xffff;
        words[61] = 0x0fff;
        assert_eq!(
            identify_geometry(&words)
                .expect("test fixture should be valid")
                .addressing,
            AtaAddressing::Lba28
        );

        // Nonzero LBA48 words are ignored unless word 83 has valid support bits.
        words[100] = 1;
        assert_eq!(
            identify_geometry(&words)
                .expect("test fixture should be valid")
                .addressing,
            AtaAddressing::Lba28
        );
        words[83] = 0x4400;
        assert_eq!(
            identify_geometry(&words)
                .expect("test fixture should be valid")
                .addressing,
            AtaAddressing::Lba48
        );

        words[106] = 0x5000;
        words[117] = 2048;
        assert_eq!(
            identify_geometry(&words)
                .expect("test fixture should be valid")
                .sector_size,
            4096
        );
        words[117] = 0;
        assert!(identify_geometry(&words).is_none());
        words[117] = 2048;
        words[83] = 0xc400;
        assert_eq!(
            identify_geometry(&words)
                .expect("test fixture should be valid")
                .addressing,
            AtaAddressing::Lba28
        );
    }

    #[test]
    fn dma_boundary_and_fis_encodings() {
        assert!(dma_range_fits(0xffff_f000, 4096, u32::MAX as u64));
        assert!(!dma_range_fits(0xffff_f001, 4096, u32::MAX as u64));
        let lba28 = encode_read_fis(AtaAddressing::Lba28, 0x0abc_def0, 256)
            .expect("test fixture should be valid");
        assert_eq!(
            (lba28.command, lba28.device, lba28.count_low),
            (0xc8, 0x4a, 0)
        );
        let lba48 = encode_read_fis(AtaAddressing::Lba48, 0x1234_5678_9abc, 65536)
            .expect("test fixture should be valid");
        assert_eq!(
            (
                lba48.command,
                lba48.lba[5],
                lba48.count_low,
                lba48.count_high
            ),
            (0x25, 0x12, 0, 0)
        );
        assert!(read_range_valid(
            AtaAddressing::Lba28,
            1 << 28,
            (1 << 28) - 1,
            1
        ));
        assert!(!read_range_valid(
            AtaAddressing::Lba28,
            1 << 28,
            (1 << 28) - 1,
            2
        ));
    }
}
