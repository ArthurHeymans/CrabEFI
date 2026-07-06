//! Automatic measured boot infrastructure.
//!
//! This module implements firmware-initiated TCG measurements following the
//! TCG PC Client Platform Firmware Profile (PFP) specification. CrabEFI
//! measures:
//!
//! - **PCR 0**: S-CRTM version (firmware version string)
//! - **PCR 1**: Boot variables (BootOrder, Boot####)
//! - **PCR 2/4**: EFI drivers and applications (PE/COFF authenticode hash)
//! - **PCR 5**: GPT partition tables, ExitBootServices actions
//! - **PCR 7**: Secure Boot policy variables (SecureBoot, PK, KEK, db, dbx)
//! - **PCR 0-7**: Separator events (marking pre-OS to OS transition)
//!
//! # References
//!
//! - TCG PC Client Specific Platform Firmware Profile Specification
//! - TCG EFI Protocol Specification, Family "2.0"
//! - EDK2 SecurityPkg/Tcg/Tcg2Dxe/Tcg2Dxe.c

use alloc::vec::Vec;

use super::types::*;

/// Read an EFI variable's data from the in-memory variable cache.
fn get_efi_variable(guid: &r_efi::efi::Guid, name: &[u16]) -> Option<Vec<u8>> {
    let mut result: Option<Vec<u8>> = None;
    crate::state::with_efi_mut(|efi| {
        result = efi
            .variables
            .iter()
            .find(|var| {
                var.in_use
                    && var.vendor_guid == *guid
                    && crate::efi::utils::ucs2_eq(&var.name, name)
            })
            .map(|var| var.data[..var.data_size].to_vec());
    });
    result
}

// ============================================================================
// UEFI_VARIABLE_DATA structure for PCR 7
// ============================================================================

/// Serialize a `UEFI_VARIABLE_DATA` structure for measuring EFI variables.
///
/// The TCG PFP spec requires that EFI variables measured into PCR 7 use
/// this specific structure as the event data, and the hash is computed
/// over the entire structure (not just the variable value).
///
/// Layout:
/// ```text
/// UEFI_VARIABLE_DATA {
///     EFI_GUID  VariableName;      // 16 bytes
///     UINT64    UnicodeNameLength;  // number of UTF-16 chars (not bytes)
///     UINT64    VariableDataLength; // size of variable data in bytes
///     CHAR16[]  UnicodeName;        // UTF-16LE variable name
///     INT8[]    VariableData;       // raw variable data
/// }
/// ```
fn serialize_uefi_variable_data(
    guid: &r_efi::efi::Guid,
    name_utf16: &[u16],
    variable_data: &[u8],
) -> Option<Vec<u8>> {
    // EDK2 uses StrLen(VariableName) for UnicodeNameLength and copies only
    // that many CHAR16s, excluding the terminating NUL if present.
    let name_len = name_utf16
        .iter()
        .position(|ch| *ch == 0)
        .unwrap_or(name_utf16.len());
    let name = &name_utf16[..name_len];
    let name_bytes = name.len().checked_mul(2)?;
    let total = 16usize
        .checked_add(8)?
        .checked_add(8)?
        .checked_add(name_bytes)?
        .checked_add(variable_data.len())?;
    let mut buf = Vec::new();
    buf.resize(total, 0);

    let mut off = 0;

    // EFI_GUID (16 bytes, same layout as r-efi::Guid)
    let guid_bytes: &[u8; 16] = unsafe { &*(guid as *const r_efi::efi::Guid as *const [u8; 16]) };
    buf[off..off + 16].copy_from_slice(guid_bytes);
    off += 16;

    // UnicodeNameLength (number of UTF-16 code units, not bytes, no NUL)
    buf[off..off + 8].copy_from_slice(&(name.len() as u64).to_le_bytes());
    off += 8;

    // VariableDataLength
    buf[off..off + 8].copy_from_slice(&(variable_data.len() as u64).to_le_bytes());
    off += 8;

    // UnicodeName (UTF-16LE, no NUL)
    for &ch in name {
        buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        off += 2;
    }

    // VariableData
    buf[off..off + variable_data.len()].copy_from_slice(variable_data);

    Some(buf)
}

fn measure_variable_all(
    pcr_index: u32,
    event_type: u32,
    guid: &r_efi::efi::Guid,
    name_utf16: &[u16],
    variable_data: &[u8],
    context: &str,
) {
    let event_buf = match serialize_uefi_variable_data(guid, name_utf16, variable_data) {
        Some(buf) => buf,
        None => {
            log::warn!("Failed to serialize variable data for {}", context);
            return;
        }
    };

    measure_event_all(pcr_index, event_type, &event_buf, &event_buf, context);
}

fn efi_global_variable_guid() -> r_efi::efi::Guid {
    r_efi::efi::Guid::from_fields(
        0x8BE4DF61,
        0x93CA,
        0x11D2,
        0xAA,
        0x0D,
        &[0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
    )
}

fn boot_option_name(option_number: u16) -> [u16; 9] {
    let mut name = [0u16; 9];
    name[0] = b'B' as u16;
    name[1] = b'o' as u16;
    name[2] = b'o' as u16;
    name[3] = b't' as u16;

    let hex_chars = *b"0123456789ABCDEF";
    name[4] = hex_chars[((option_number >> 12) & 0xF) as usize] as u16;
    name[5] = hex_chars[((option_number >> 8) & 0xF) as usize] as u16;
    name[6] = hex_chars[((option_number >> 4) & 0xF) as usize] as u16;
    name[7] = hex_chars[(option_number & 0xF) as usize] as u16;
    name
}

// ============================================================================
// Secure Boot Variable Measurement (PCR 7)
// ============================================================================

fn log_protocol_result(protocol: &str, context: &str, result: Option<Result<(), TcgError>>) {
    if let Some(Err(e)) = result {
        log::warn!("{} measurement failed for {}: {:?}", protocol, context, e);
    }
}

pub fn measure_event_all(
    pcr_index: u32,
    event_type: u32,
    data_to_hash: &[u8],
    event_data: &[u8],
    context: &str,
) {
    log_protocol_result(
        "TCG2",
        context,
        crate::efi::protocols::tcg2::measure_event(pcr_index, event_type, data_to_hash, event_data),
    );
    log_protocol_result(
        "TCG",
        context,
        crate::efi::protocols::tcg::measure_event(pcr_index, event_type, data_to_hash, event_data),
    );
}

/// Measure Secure Boot policy variables through all installed TCG protocols.
pub fn measure_secure_boot_variables_all() {
    let global_guid = r_efi::efi::Guid::from_fields(
        0x8BE4DF61,
        0x93CA,
        0x11D2,
        0xAA,
        0x0D,
        &[0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
    );
    let security_guid = r_efi::efi::Guid::from_fields(
        0xD719B2CB,
        0x3D3A,
        0x4596,
        0xA3,
        0xBC,
        &[0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F],
    );

    let variables: &[(&r_efi::efi::Guid, &[u16], &str)] = &[
        (
            &global_guid,
            &[
                0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x42, 0x6F, 0x6F, 0x74, 0x00,
            ],
            "SecureBoot",
        ),
        (&global_guid, &[0x50, 0x4B, 0x00], "PK"),
        (&global_guid, &[0x4B, 0x45, 0x4B, 0x00], "KEK"),
        (&security_guid, &[0x64, 0x62, 0x00], "db"),
        (&security_guid, &[0x64, 0x62, 0x78, 0x00], "dbx"),
    ];

    for &(guid, name_utf16, display_name) in variables {
        let var_data = get_efi_variable(guid, name_utf16);
        let data = var_data.as_deref().unwrap_or(&[]);

        let event_buf = match serialize_uefi_variable_data(guid, name_utf16, data) {
            Some(buf) => buf,
            None => {
                log::warn!("Failed to serialize variable data for {}", display_name);
                continue;
            }
        };

        measure_event_all(
            7,
            EV_EFI_VARIABLE_DRIVER_CONFIG,
            &event_buf,
            &event_buf,
            display_name,
        );

        log::debug!(
            "Measured {} into PCR 7 ({} bytes)",
            display_name,
            data.len()
        );
    }

    measure_separator_all(7);
}

/// Measure BootOrder and referenced Boot#### variables into PCR 1.
pub fn measure_boot_variables_all() {
    let global_guid = efi_global_variable_guid();
    let boot_order_name: [u16; 10] = [
        b'B' as u16,
        b'o' as u16,
        b'o' as u16,
        b't' as u16,
        b'O' as u16,
        b'r' as u16,
        b'd' as u16,
        b'e' as u16,
        b'r' as u16,
        0,
    ];

    let Some(boot_order) = get_efi_variable(&global_guid, &boot_order_name) else {
        log::debug!("BootOrder not present; skipping PCR 1 boot variable measurements");
        return;
    };

    measure_variable_all(
        1,
        EV_EFI_VARIABLE_BOOT,
        &global_guid,
        &boot_order_name,
        &boot_order,
        "BootOrder",
    );

    for chunk in boot_order.chunks_exact(2) {
        let option_number = u16::from_le_bytes([chunk[0], chunk[1]]);
        let name = boot_option_name(option_number);
        if let Some(data) = get_efi_variable(&global_guid, &name) {
            measure_variable_all(
                1,
                EV_EFI_VARIABLE_BOOT,
                &global_guid,
                &name,
                &data,
                "Boot####",
            );
        }
    }
}

/// Measure EFI handoff/configuration table pointers into PCR 1.
pub fn measure_handoff_tables_all() {
    const ENTRY_SIZE: usize = 16 + 8;
    let mut event_buf = [0u8; 8 + crate::state::MAX_CONFIG_TABLES * ENTRY_SIZE];
    let mut count = 0usize;
    let mut off = 8usize;

    crate::state::with_efi_mut(|efi| {
        for table in efi.config_tables.iter().take(efi.config_table_count) {
            if table.vendor_table.is_null() || off + ENTRY_SIZE > event_buf.len() {
                continue;
            }
            let guid_bytes: &[u8; 16] =
                unsafe { &*(&table.vendor_guid as *const r_efi::efi::Guid as *const [u8; 16]) };
            event_buf[off..off + 16].copy_from_slice(guid_bytes);
            off += 16;
            event_buf[off..off + 8].copy_from_slice(&(table.vendor_table as u64).to_le_bytes());
            off += 8;
            count += 1;
        }
    });

    if count == 0 {
        return;
    }

    event_buf[..8].copy_from_slice(&(count as u64).to_le_bytes());
    measure_event_all(
        1,
        EV_EFI_HANDOFF_TABLES,
        &event_buf[..off],
        &event_buf[..off],
        "EFI handoff tables",
    );
}

/// Measure a separator event through all installed TCG protocols.
pub fn measure_separator_all(pcr_index: u32) {
    let separator_data = 0u32.to_le_bytes();
    measure_event_all(
        pcr_index,
        EV_SEPARATOR,
        &separator_data,
        &separator_data,
        "separator",
    );
}

/// Measure separator events into PCR 0 through 6 through all installed TCG protocols.
pub fn measure_all_separators_all() {
    for pcr in 0..7 {
        measure_separator_all(pcr);
    }
}

/// Measure an EFI action string through all installed TCG protocols.
pub fn measure_action_all(pcr_index: u32, action: &str) {
    measure_event_all(
        pcr_index,
        EV_EFI_ACTION,
        action.as_bytes(),
        action.as_bytes(),
        action,
    );
}

/// Measure the S-CRTM version string through all installed TCG protocols.
pub fn measure_s_crtm_version_all(version: &str) {
    let mut utf16_buf = [0u8; 512];
    let mut off = 0;
    for ch in version.encode_utf16() {
        if off + 2 > utf16_buf.len() {
            break;
        }
        utf16_buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        off += 2;
    }
    if off + 2 <= utf16_buf.len() {
        utf16_buf[off..off + 2].copy_from_slice(&0u16.to_le_bytes());
        off += 2;
    }

    measure_event_all(
        0,
        EV_S_CRTM_VERSION,
        &utf16_buf[..off],
        &utf16_buf[..off],
        "S-CRTM version",
    );
    log::info!("Measured S-CRTM version into PCR 0: \"{}\"", version);
}

/// Precompute Authenticode digests for installed TCG protocols.
pub fn precompute_pe_image_digests_all(
    pe_data: &[u8],
) -> Result<Option<(usize, [TaggedDigest; 5])>, TcgError> {
    let mut first_error = None;
    let mut out = [TaggedDigest::zeroed(0); 5];
    let mut out_count = 0;

    if let Some(result) = crate::efi::protocols::tcg2::precompute_pe_image_digests(pe_data) {
        match result {
            Ok((count, digests)) => merge_digests(&mut out, &mut out_count, &digests[..count]),
            Err(e) => {
                first_error.get_or_insert(e);
                log::warn!("TCG2 PE image digest precompute failed: {:?}", e);
            }
        }
    }

    if let Some(result) = crate::efi::protocols::tcg::precompute_pe_image_digests(pe_data) {
        match result {
            Ok((count, digests)) => merge_digests(&mut out, &mut out_count, &digests[..count]),
            Err(e) => {
                first_error.get_or_insert(e);
                log::warn!("TCG PE image digest precompute failed: {:?}", e);
            }
        }
    }

    if let Some(e) = first_error {
        Err(e)
    } else if out_count == 0 {
        Ok(None)
    } else {
        Ok(Some((out_count, out)))
    }
}

fn merge_digests(out: &mut [TaggedDigest; 5], out_count: &mut usize, digests: &[TaggedDigest]) {
    for digest in digests {
        if out[..*out_count]
            .iter()
            .any(|existing| existing.algorithm == digest.algorithm)
        {
            continue;
        }
        if *out_count >= out.len() {
            break;
        }
        out[*out_count] = *digest;
        *out_count += 1;
    }
}

/// Extend and log a PE/COFF EFI image with precomputed Authenticode digests.
pub fn measure_pe_image_digests_all(
    pcr_index: u32,
    event_type: u32,
    digests: &[TaggedDigest],
    event_data: &[u8],
) -> Result<(), TcgError> {
    let mut first_error = None;

    if let Some(result) = crate::efi::protocols::tcg2::measure_pe_image_digests_event(
        pcr_index, event_type, digests, event_data,
    ) && let Err(e) = result
    {
        first_error.get_or_insert(e);
        log::warn!("TCG2 PE image measurement failed: {:?}", e);
    }

    if let Some(result) = crate::efi::protocols::tcg::measure_pe_image_digests_event(
        pcr_index, event_type, digests, event_data,
    ) && let Err(e) = result
    {
        first_error.get_or_insert(e);
        log::warn!("TCG PE image measurement failed: {:?}", e);
    }

    match first_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Measure a PE/COFF EFI image through all installed TCG protocols.
pub fn measure_pe_image_all(
    pcr_index: u32,
    event_type: u32,
    pe_data: &[u8],
    event_data: &[u8],
) -> Result<(), TcgError> {
    match precompute_pe_image_digests_all(pe_data)? {
        Some((count, digests)) => {
            measure_pe_image_digests_all(pcr_index, event_type, &digests[..count], event_data)
        }
        None => Ok(()),
    }
}

// ============================================================================
// Event type constant missing from types.rs
// ============================================================================

/// S-CRTM version event type.
pub const EV_S_CRTM_VERSION: u32 = 0x0000_0008;
