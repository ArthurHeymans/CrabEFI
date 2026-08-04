use crabefi_runtime_abi::{
    AbiError, EXPORTS_SIZE, HEADER_SIZE, RuntimeExternalRange, RuntimeHandoff, ValidatedImage,
    architecture, feature_bits,
};

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn valid_image() -> Vec<u8> {
    let section_offset = HEADER_SIZE;
    let exports_offset = section_offset + 32;
    let data_offset = exports_offset + EXPORTS_SIZE;
    let mut bytes = vec![0u8; data_offset + 4];
    bytes[..8].copy_from_slice(b"CRABRTI\0");
    write_u16(&mut bytes, 8, 1);
    write_u16(&mut bytes, 10, architecture::X86_64);
    write_u16(&mut bytes, 12, HEADER_SIZE as u16);
    write_u32(&mut bytes, 16, 4096);
    write_u32(&mut bytes, 20, section_offset as u32);
    write_u16(&mut bytes, 24, 1);
    write_u32(&mut bytes, 28, exports_offset as u32);
    write_u32(&mut bytes, 32, 0);
    write_u32(&mut bytes, 36, exports_offset as u32);
    write_u16(&mut bytes, 40, EXPORTS_SIZE as u16);
    write_u32(&mut bytes, 44, 4096);
    bytes[48..56].copy_from_slice(&feature_bits::REQUIRED.to_le_bytes());

    write_u32(&mut bytes, section_offset, data_offset as u32);
    write_u32(&mut bytes, section_offset + 4, 0);
    write_u32(&mut bytes, section_offset + 8, 4);
    write_u32(&mut bytes, section_offset + 12, 4096);
    write_u32(&mut bytes, section_offset + 16, 4096);
    write_u32(&mut bytes, section_offset + 20, 1 | 4 | 8);

    write_u16(&mut bytes, exports_offset, 1);
    write_u16(&mut bytes, exports_offset + 2, EXPORTS_SIZE as u16);
    for index in 0..12 {
        write_u32(
            &mut bytes,
            exports_offset + 8 + index * 4,
            16 + index as u32,
        );
    }
    bytes[data_offset..data_offset + 4].copy_from_slice(b"code");
    bytes
}

#[test]
fn parses_checked_fixture() {
    let bytes = valid_image();
    let image = ValidatedImage::parse(&bytes, architecture::X86_64).unwrap();
    assert_eq!(image.header().image_size, 4096);
    assert_eq!(image.section(0).unwrap().memory_size, 4096);
}

#[test]
fn rejects_architecture_and_unknown_flags() {
    let mut bytes = valid_image();
    assert_eq!(
        ValidatedImage::parse(&bytes, architecture::AARCH64).err(),
        Some(AbiError::BadArchitecture)
    );
    write_u32(&mut bytes, HEADER_SIZE + 20, 1 | 4 | 8 | (1 << 31));
    assert_eq!(
        ValidatedImage::parse(&bytes, architecture::X86_64).err(),
        Some(AbiError::UnknownSectionFlags)
    );
}

#[test]
fn rejects_corrupt_layout_and_exports() {
    fn parse(bytes: &[u8]) -> Result<ValidatedImage<'_>, AbiError> {
        ValidatedImage::parse(bytes, architecture::X86_64)
    }

    let mut bytes = valid_image();
    bytes[0] ^= 0xff;
    assert_eq!(parse(&bytes).err(), Some(AbiError::BadMagic));

    let mut bytes = valid_image();
    write_u32(&mut bytes, 44, 2048);
    assert_eq!(parse(&bytes).err(), Some(AbiError::BadAlignment));

    let mut bytes = valid_image();
    write_u32(&mut bytes, HEADER_SIZE + 20, 1 | 2 | 4 | 8);
    assert_eq!(
        parse(&bytes).err(),
        Some(AbiError::WritableExecutableSection)
    );

    let mut bytes = valid_image();
    let exports_offset = HEADER_SIZE + 32;
    write_u32(&mut bytes, exports_offset + 8, 4096);
    assert_eq!(parse(&bytes).err(), Some(AbiError::BadExports));

    let bytes = valid_image();
    assert!(parse(&bytes[..HEADER_SIZE]).is_err());
}

#[test]
fn rejects_invalid_relocation_slots_and_bounds() {
    let section_offset = HEADER_SIZE;
    let relocation_offset = section_offset + 32;
    let exports_offset = relocation_offset + 24;
    let data_offset = exports_offset + EXPORTS_SIZE;
    let mut bytes = vec![0u8; data_offset + 8];
    bytes[..8].copy_from_slice(b"CRABRTI\0");
    write_u16(&mut bytes, 8, 1);
    write_u16(&mut bytes, 10, architecture::X86_64);
    write_u16(&mut bytes, 12, HEADER_SIZE as u16);
    write_u32(&mut bytes, 16, 4096);
    write_u32(&mut bytes, 20, section_offset as u32);
    write_u16(&mut bytes, 24, 1);
    write_u32(&mut bytes, 28, relocation_offset as u32);
    write_u32(&mut bytes, 32, 1);
    write_u32(&mut bytes, 36, exports_offset as u32);
    write_u16(&mut bytes, 40, EXPORTS_SIZE as u16);
    write_u32(&mut bytes, 44, 4096);
    bytes[48..56].copy_from_slice(&feature_bits::REQUIRED.to_le_bytes());
    write_u32(&mut bytes, section_offset, data_offset as u32);
    write_u32(&mut bytes, section_offset + 8, 8);
    write_u32(&mut bytes, section_offset + 12, 4096);
    write_u32(&mut bytes, section_offset + 16, 4096);
    write_u32(&mut bytes, section_offset + 20, 1 | 4 | 8 | 16);
    write_u32(&mut bytes, relocation_offset, 0);
    write_u32(&mut bytes, relocation_offset + 4, 8);
    write_u16(&mut bytes, relocation_offset + 18, 1);
    write_u16(&mut bytes, exports_offset, 1);
    write_u16(&mut bytes, exports_offset + 2, EXPORTS_SIZE as u16);
    for index in 0..12 {
        write_u32(&mut bytes, exports_offset + 8 + index * 4, index as u32);
    }
    assert!(ValidatedImage::parse(&bytes, architecture::X86_64).is_ok());

    let mut unaligned = bytes.clone();
    write_u32(&mut unaligned, relocation_offset, 4);
    assert_eq!(
        ValidatedImage::parse(&unaligned, architecture::X86_64).err(),
        Some(AbiError::BadRelocation)
    );
    let mut no_slots = bytes.clone();
    write_u32(&mut no_slots, section_offset + 20, 1 | 4 | 8);
    assert_eq!(
        ValidatedImage::parse(&no_slots, architecture::X86_64).err(),
        Some(AbiError::BadRelocation)
    );
    let mut target_outside = bytes.clone();
    write_u32(&mut target_outside, relocation_offset + 4, 4096);
    assert_eq!(
        ValidatedImage::parse(&target_outside, architecture::X86_64).err(),
        Some(AbiError::BadRelocation)
    );
    let mut reserved_addend = bytes;
    reserved_addend[relocation_offset + 8] = 1;
    assert_eq!(
        ValidatedImage::parse(&reserved_addend, architecture::X86_64).err(),
        Some(AbiError::BadRelocation)
    );
}

#[test]
fn handoff_rejects_overlapping_external_ranges() {
    let mut handoff = RuntimeHandoff::empty();
    handoff.architecture = architecture::X86_64;
    handoff.image_base = 0x10_0000;
    handoff.image_size = 0x2000;
    handoff.section_count = 1;
    handoff.sections[0].physical_base = handoff.image_base;
    handoff.sections[0].byte_len = handoff.image_size;
    handoff.deferred_buffer_base = 0x30_0000;
    handoff.deferred_buffer_size = 0x1_0000;
    handoff.range_count = 2;
    handoff.ranges[0] = RuntimeExternalRange {
        physical_base: 0x20_0000,
        byte_len: 0x2000,
        attributes: 1 << 63,
    };
    handoff.ranges[1] = RuntimeExternalRange {
        physical_base: 0x20_1000,
        byte_len: 0x1000,
        attributes: 1 << 63,
    };
    assert!(handoff.validate().is_err());
}

#[test]
fn handoff_rejects_section_provenance_mismatch() {
    let mut handoff = RuntimeHandoff::empty();
    handoff.architecture = architecture::X86_64;
    handoff.image_base = 0x10_0000;
    handoff.image_size = 0x1000;
    handoff.section_count = 1;
    handoff.deferred_buffer_base = 0x30_0000;
    handoff.deferred_buffer_size = 0x1_0000;
    handoff.sections[0].image_offset = 0;
    handoff.sections[0].physical_base = 0x20_0000;
    handoff.sections[0].byte_len = 0x1000;
    assert!(handoff.validate().is_err());
}
