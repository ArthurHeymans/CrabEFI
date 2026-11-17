use crabefi_efi_types::varstore::*;

const NAME: [u16; 2] = [b'A' as u16, 0];

fn checksum(region: &mut [u8]) {
    region[0x32..0x34].fill(0);
    let sum = region[..FV_HEADER_LENGTH]
        .as_chunks::<2>()
        .0
        .iter()
        .fold(0u16, |sum, word| {
            sum.wrapping_add(u16::from_le_bytes(*word))
        });
    region[0x32..0x34].copy_from_slice(&0u16.wrapping_sub(sum).to_le_bytes());
}

fn region(auth: bool, size: u32) -> Vec<u8> {
    let mut region = vec![0xff; 4096];
    region[..VARIABLE_DATA_OFFSET as usize].fill(0);
    region[0x10..0x20].copy_from_slice(&EFI_SYSTEM_NV_DATA_FV_GUID);
    region[0x20..0x28].copy_from_slice(&4096u64.to_le_bytes());
    region[0x28..0x2c].copy_from_slice(&FV_SIGNATURE.to_le_bytes());
    region[0x30..0x32].copy_from_slice(&(FV_HEADER_LENGTH as u16).to_le_bytes());
    region[0x37] = FV_REVISION;
    checksum(&mut region);
    region[FV_HEADER_LENGTH..FV_HEADER_LENGTH + 16].copy_from_slice(if auth {
        &EFI_AUTH_VARIABLE_GUID
    } else {
        &EFI_VARIABLE_GUID
    });
    region[FV_HEADER_LENGTH + 16..FV_HEADER_LENGTH + 20].copy_from_slice(&size.to_le_bytes());
    region[FV_HEADER_LENGTH + 20] = VARIABLE_STORE_FORMATTED;
    region[FV_HEADER_LENGTH + 21] = VARIABLE_STORE_HEALTHY;
    region
}

fn record(region: &mut [u8], offset: usize, auth: bool, state: u8, data: &[u8]) -> usize {
    let header_size = if auth {
        AUTH_VAR_HEADER_SIZE
    } else {
        VAR_HEADER_SIZE
    };
    let (name_size_offset, guid_offset) = if auth { (0x24, 0x2c) } else { (8, 16) };
    region[offset..offset + header_size].fill(0);
    region[offset..offset + 2].copy_from_slice(&VARIABLE_DATA.to_le_bytes());
    region[offset + 2] = state;
    region[offset + 4..offset + 8].copy_from_slice(&7u32.to_le_bytes());
    region[offset + name_size_offset..offset + name_size_offset + 4]
        .copy_from_slice(&4u32.to_le_bytes());
    region[offset + name_size_offset + 4..offset + name_size_offset + 8]
        .copy_from_slice(&(data.len() as u32).to_le_bytes());
    region[offset + guid_offset..offset + guid_offset + 16].copy_from_slice(&COREBOOT_CFR_GUID);
    let name_offset = offset + header_size;
    region[name_offset..name_offset + 4].copy_from_slice(&[b'A', 0, 0, 0]);
    region[name_offset + 4..name_offset + 4 + data.len()].copy_from_slice(data);
    (name_offset + 4 + data.len() + 3) & !3
}

fn read(region: &[u8], out: &mut [u8]) -> Option<usize> {
    read_variable_data_from_region(region, &COREBOOT_CFR_GUID, &NAME, out)
}

#[test]
fn size_conventions_and_invalid_sizes() {
    assert_eq!(variable_data_size(4096 - 72, 4096), Some(3996));
    assert_eq!(variable_data_size(4096 - 100, 4096), Some(3996));
    assert_eq!(variable_data_size(512, 4096), Some(484));
    assert_eq!(variable_data_size(27, 4096), None);
    assert_eq!(variable_data_size(4096, 4096), None);
    assert_eq!(variable_data_size(0, 99), None);
}

#[test]
fn partial_pi_store_rejects_record_crossing_declared_end() {
    for auth in [false, true] {
        let mut region = region(auth, 512);
        let first_data_size =
            460 - if auth {
                AUTH_VAR_HEADER_SIZE
            } else {
                VAR_HEADER_SIZE
            } - 4;
        let next = record(
            &mut region,
            100,
            auth,
            VAR_DELETED,
            &vec![0; first_data_size],
        );
        assert_eq!(next, 560);
        record(&mut region, next, auth, VAR_ADDED, b"boundary");
        assert_eq!(read(&region, &mut [0; 8]), None);
    }
}

#[test]
fn last_match_wins_even_if_an_earlier_match_is_too_large() {
    for auth in [false, true] {
        let mut region = region(auth, 4096 - 72);
        let next = record(&mut region, 100, auth, VAR_ADDED, b"too large");
        record(&mut region, next, auth, VAR_ADDED, b"last");
        let mut out = [0; 4];
        assert_eq!(read(&region, &mut out), Some(4));
        assert_eq!(&out, b"last");
        assert_eq!(read(&region, &mut [0; 3]), None);
    }
}

#[test]
fn oversized_last_match_does_not_return_earlier_data() {
    let mut region = region(false, 4096 - 72);
    let next = record(&mut region, 100, false, VAR_ADDED, b"old");
    record(&mut region, next, false, VAR_ADDED, b"too large");
    let mut out = [0; 4];
    assert_eq!(read(&region, &mut out), None);
    assert_eq!(out, [0; 4]);
}

#[test]
fn lookup_matches_guid_and_terminated_name_and_skips_deleted_records() {
    for auth in [false, true] {
        let mut region = region(auth, 4096 - 72);
        let next = record(&mut region, 100, auth, VAR_ADDED, b"kept");
        record(&mut region, next, auth, VAR_DELETED, b"gone");
        let mut out = [0; 4];
        assert_eq!(
            read_variable_data_from_region(&region, &COREBOOT_CFR_GUID, &NAME[..1], &mut out),
            Some(4)
        );
        assert_eq!(&out, b"kept");
        assert_eq!(
            read_variable_data_from_region(&region, &[0; 16], &NAME, &mut out),
            None
        );
        let header_size = if auth {
            AUTH_VAR_HEADER_SIZE
        } else {
            VAR_HEADER_SIZE
        };
        region[100 + header_size + 2] = b'B';
        assert_eq!(read(&region, &mut out), None);
    }
}

#[test]
fn fv_length_bounds_reads_even_with_a_larger_mapping() {
    let mut region = region(false, 512 - 72);
    region[0x20..0x28].copy_from_slice(&512u64.to_le_bytes());
    checksum(&mut region);
    assert_eq!(validate(&region, 4096).unwrap().data_size, 412);
    let next = record(&mut region, 100, false, VAR_DELETED, &[0; 372]);
    assert_eq!(next, 508);
    record(&mut region, next, false, VAR_ADDED, b"outside");
    assert_eq!(read(&region, &mut [0; 8]), None);
}

#[test]
fn rejects_unsupported_or_inconsistent_fv_headers() {
    for length in [56u16, 70, 74] {
        let mut region = region(false, 512);
        region[0x30..0x32].copy_from_slice(&length.to_le_bytes());
        checksum(&mut region);
        assert!(validate(&region, 4096).is_none());
    }
    for length in [99u64, 4097, u64::MAX] {
        let mut region = region(false, 512);
        region[0x20..0x28].copy_from_slice(&length.to_le_bytes());
        checksum(&mut region);
        assert!(validate(&region, 4096).is_none());
    }
    let mut region = region(false, 512);
    region[0] ^= 1;
    assert!(validate(&region, 4096).is_none());
    assert!(validate(&region[..99], 4096).is_none());
}

#[test]
fn reads_only_the_selected_payload_and_propagates_read_failure() {
    let mut region = region(false, 512);
    let next = record(&mut region, 100, false, VAR_ADDED, b"old");
    record(&mut region, next, false, VAR_ADDED, b"new");
    let selected_data_offset = (next + VAR_HEADER_SIZE + 4) as u32;
    let mut out = [0; 4];
    let mut payload_reads = Vec::new();
    let result = read_variable_data(
        &mut |offset, buf| {
            if buf.len() == 3 {
                payload_reads.push(offset);
                return false;
            }
            buf.copy_from_slice(&region[offset as usize..offset as usize + buf.len()]);
            true
        },
        false,
        484,
        &COREBOOT_CFR_GUID,
        &NAME,
        &mut out,
    );
    assert_eq!(result, None);
    assert_eq!(payload_reads, [selected_data_offset]);
}
