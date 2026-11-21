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
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use super::types::*;

/// Read an EFI variable's data from the authoritative runtime image store.
fn get_efi_variable(guid: &r_efi::efi::Guid, name: &[u16]) -> Option<Vec<u8>> {
    crate::efi::runtime_image::client::variables::get(guid, name).map(|(_, data)| data)
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
    let mut buf = alloc::vec![0; total];

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

    let data_to_hash = if event_type == EV_EFI_VARIABLE_DRIVER_CONFIG {
        event_buf.as_slice()
    } else {
        variable_data
    };
    measure_event_all(pcr_index, event_type, data_to_hash, &event_buf, context);
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

    let secure_boot_name = [
        0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x42, 0x6F, 0x6F, 0x74, 0x00,
    ];
    let secure_boot = [u8::from(crate::efi::auth::is_secure_boot_enabled())];
    measure_variable_all(
        7,
        EV_EFI_VARIABLE_DRIVER_CONFIG,
        &global_guid,
        &secure_boot_name,
        &secure_boot,
        "SecureBoot",
    );

    let variables: &[(&r_efi::efi::Guid, &[u16], &str)] = &[
        (&global_guid, &[0x50, 0x4B, 0x00], "PK"),
        (&global_guid, &[0x4B, 0x45, 0x4B, 0x00], "KEK"),
        (&security_guid, &[0x64, 0x62, 0x00], "db"),
        (&security_guid, &[0x64, 0x62, 0x78, 0x00], "dbx"),
    ];

    for &(guid, name_utf16, display_name) in variables {
        let var_data = get_efi_variable(guid, name_utf16);
        let data = var_data.as_deref().unwrap_or(&[]);

        measure_variable_all(
            7,
            EV_EFI_VARIABLE_DRIVER_CONFIG,
            guid,
            name_utf16,
            data,
            display_name,
        );

        log::debug!(
            "Measured {} into PCR 7 ({} bytes)",
            display_name,
            data.len()
        );
    }

    let dbt_name = [0x64, 0x62, 0x74, 0x00];
    if let Some(dbt) = get_efi_variable(&security_guid, &dbt_name) {
        measure_variable_all(
            7,
            EV_EFI_VARIABLE_DRIVER_CONFIG,
            &security_guid,
            &dbt_name,
            &dbt,
            "dbt",
        );
    }

    // Recorded like the other pre-OS separators: firmware-only secrets
    // depend on it.
    measure_separators(1 << 7);
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

    for chunk in boot_order.as_chunks::<2>().0 {
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
const fn bounded_configuration_table_count(count: usize) -> usize {
    if count > crabefi_runtime_abi::MAX_CONFIGURATION_TABLES {
        crabefi_runtime_abi::MAX_CONFIGURATION_TABLES
    } else {
        count
    }
}

pub fn measure_handoff_tables_all() {
    const ENTRY_SIZE: usize = 16 + 8;
    let mut event_buf = [0u8; 8 + crabefi_runtime_abi::MAX_CONFIGURATION_TABLES * ENTRY_SIZE];
    let mut count = 0usize;
    let mut off = 8usize;

    let system = crate::efi::get_system_table();
    if !system.is_null() {
        // SAFETY: the runtime image owns a bounded initialized configuration array.
        let (tables, table_count) = unsafe {
            (
                (*system).configuration_table,
                (*system).number_of_table_entries,
            )
        };
        if !tables.is_null() {
            let bounded_count = bounded_configuration_table_count(table_count);
            if bounded_count != table_count {
                log::warn!(
                    "Clamping impossible configuration table count {} to {}",
                    table_count,
                    bounded_count
                );
            }
            for index in 0..bounded_count {
                // SAFETY: the count is clamped to the image-owned fixed array.
                let table = unsafe { &*tables.add(index) };
                if table.vendor_table.is_null() || off + ENTRY_SIZE > event_buf.len() {
                    continue;
                }
                event_buf[off..off + 16].copy_from_slice(table.vendor_guid.as_bytes());
                off += 16;
                event_buf[off..off + 8].copy_from_slice(&(table.vendor_table as u64).to_le_bytes());
                off += 8;
                count += 1;
            }
        }
    }

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

#[cfg(test)]
mod handoff_table_tests {
    use super::bounded_configuration_table_count;

    #[test]
    fn oversized_configuration_count_is_bounded_to_owned_array() {
        assert_eq!(bounded_configuration_table_count(3), 3);
        assert_eq!(
            bounded_configuration_table_count(usize::MAX),
            crabefi_runtime_abi::MAX_CONFIGURATION_TABLES
        );
    }
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
    measure_separators(0x7F);
}

/// PCRs 0-7 whose separator was attempted, one bit each.
static SEPARATORS_MEASURED: AtomicU8 = AtomicU8::new(0);
/// PCRs 0-7 whose separator a hardware TPM recorded.
static SEPARATORS_RECORDED: AtomicU8 = AtomicU8::new(0);
/// The platform described a TPM 2.0, whether or not it came up.
static TPM_EXPECTED: AtomicBool = AtomicBool::new(false);
/// Earlier firmware measured in SHA-1 only: a TPM 2.0 unless the platform
/// identifies a TPM 1.2.
static SHA1_ONLY_MEASUREMENTS: AtomicBool = AtomicBool::new(false);
/// The platform identified a TPM 1.2.
static TPM12_IDENTIFIED: AtomicBool = AtomicBool::new(false);

/// Every pre-OS separator, PCRs 0-7.
pub const ALL_SEPARATORS: u8 = 0xFF;

/// Measure the separators of the PCRs in `mask` (bit n for PCR n) that
/// were not measured yet: each PCR gets one separator per boot.
pub fn measure_separators(mask: u8) {
    let mut measured = SEPARATORS_MEASURED.load(Ordering::SeqCst);
    let mut recorded = SEPARATORS_RECORDED.load(Ordering::SeqCst);
    let before = recorded;
    plan_separators(mask, &mut measured, &mut recorded, separator);
    SEPARATORS_MEASURED.store(measured, Ordering::SeqCst);
    SEPARATORS_RECORDED.store(recorded, Ordering::SeqCst);
    if recorded != before && recorded & mask == mask {
        log::info!("Pre-OS separators measured (PCR mask {mask:#04x})");
    }
}

/// End the pre-OS phase for every PCR 0-7 (see [`measure_separators`]).
///
/// Firmware-only TPM secrets (LUKS2 tokens sealed to pre-boot PCR values)
/// depend on this: once these PCRs move, nothing the firmware starts can
/// unseal them again.
pub fn measure_pre_os_separators() {
    measure_separators(ALL_SEPARATORS);
}

fn plan_separators(
    mask: u8,
    measured: &mut u8,
    recorded: &mut u8,
    mut measure: impl FnMut(u32) -> bool,
) {
    for pcr in 0..8 {
        let bit = 1u8 << pcr;
        if mask & bit == 0 || *measured & bit != 0 {
            continue;
        }
        *measured |= bit;
        if measure(pcr) {
            *recorded |= bit;
        }
    }
}

/// Measure one separator; true when a hardware TPM 2.0 recorded it.
fn separator(pcr: u32) -> bool {
    let separator_data = 0u32.to_le_bytes();
    #[cfg_attr(not(all(feature = "luks", target_arch = "x86_64")), allow(unused_mut))]
    let mut tcg2 = crate::efi::protocols::tcg2::measure_event(
        pcr,
        EV_SEPARATOR,
        &separator_data,
        &separator_data,
    );
    // With `luks`, the PCR must move even when the log is full, or the TPM
    // serves only for the separators: firmware-only TPM secrets depend on
    // it more than the log does. Other builds keep logged-only separators,
    // so PCRs keep matching their logs (and OS unlock policies).
    #[cfg(all(feature = "luks", target_arch = "x86_64"))]
    match tcg2 {
        Some(Err(TcgError::LogFull | TcgError::EventTooLarge)) => {
            log::warn!("Event log full: extending PCR {pcr}'s separator unlogged");
            tcg2 = crate::efi::protocols::tcg2::extend_unlogged(pcr, &separator_data);
        }
        None => tcg2 = crate::efi::protocols::tcg2::extend_unlogged(pcr, &separator_data),
        _ => {}
    }
    let recorded = matches!(tcg2, Some(Ok(())));
    log_protocol_result("TCG2", "separator", tcg2);
    log_protocol_result(
        "TCG",
        "separator",
        crate::efi::protocols::tcg::measure_event(
            pcr,
            EV_SEPARATOR,
            &separator_data,
            &separator_data,
        ),
    );
    recorded
}

/// Whether a TPM 2.0 recorded the separators of every PCR in `mask`.
pub fn separators_recorded(mask: u8) -> bool {
    SEPARATORS_RECORDED.load(Ordering::SeqCst) & mask == mask
}

/// Whether the separator of any PCR in `mask` was measured (or attempted).
pub fn separators_measured(mask: u8) -> bool {
    SEPARATORS_MEASURED.load(Ordering::SeqCst) & mask != 0
}

/// Note that the platform described a TPM 2.0, before bringing it up can
/// fail: a TPM that failed to come up may still serve the next stage.
pub fn expect_hardware_tpm() {
    TPM_EXPECTED.store(true, Ordering::SeqCst);
}

/// Note what an earlier firmware's measurement log says about its TPM.
pub fn note_log_evidence(evidence: super::event_log::LogEvidence) {
    use super::event_log::LogEvidence;
    match evidence {
        LogEvidence::None => {}
        LogEvidence::Sha1Only => SHA1_ONLY_MEASUREMENTS.store(true, Ordering::SeqCst),
        LogEvidence::Tpm2 => expect_hardware_tpm(),
    }
}

/// Note that the platform identified its TPM as a TPM 1.2, which cannot
/// hold TPM 2.0 secrets. Firm TPM 2.0 evidence still wins.
pub fn note_tpm12() {
    TPM12_IDENTIFIED.store(true, Ordering::SeqCst);
}

/// Whether the platform has, or may have, a TPM 2.0: described, or
/// measured into before CrabEFI. SHA-1-only measurements count unless the
/// platform identified a TPM 1.2.
pub fn hardware_tpm_expected() -> bool {
    tpm2_expected(
        TPM_EXPECTED.load(Ordering::SeqCst),
        SHA1_ONLY_MEASUREMENTS.load(Ordering::SeqCst),
        TPM12_IDENTIFIED.load(Ordering::SeqCst),
    )
}

fn tpm2_expected(described: bool, sha1_only: bool, tpm12: bool) -> bool {
    described || (sha1_only && !tpm12)
}

#[cfg(test)]
mod separator_tests {
    use super::{plan_separators, tpm2_expected};

    #[test]
    fn sha1_only_logs_fail_closed_unless_a_tpm12_is_identified() {
        assert!(!tpm2_expected(false, false, false));
        assert!(tpm2_expected(false, true, false));
        assert!(!tpm2_expected(false, true, true));
        // Firm TPM 2.0 evidence wins over a TPM 1.2 description.
        assert!(tpm2_expected(true, true, true));
    }

    #[test]
    fn each_pcr_gets_one_separator_and_masks_are_checked_per_pcr() {
        let (mut measured, mut recorded) = (0, 0);
        let mut calls = alloc::vec::Vec::new();
        plan_separators(0x7F, &mut measured, &mut recorded, |pcr| {
            calls.push(pcr);
            true
        });
        // A later request for PCRs 0-7 measures only PCR 7, and a failed
        // PCR 7 leaves 0-7 unrecorded even though 0-6 were.
        plan_separators(0xFF, &mut measured, &mut recorded, |pcr| {
            calls.push(pcr);
            false
        });
        assert_eq!(calls, [0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!((measured, recorded), (0xFF, 0x7F));
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
