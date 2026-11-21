//! Select the TPM event log family and continue the firmware's log.

#[cfg(target_arch = "x86_64")]
use crate::acpi;
use crate::tables;

pub(crate) fn event_log(cb_info: &tables::CorebootInfo) -> crabefi::TpmEventLogConfig<'_> {
    let (existing_log, format) = match cb_info.tpm_log {
        Some(ref tpm_log) => match tpm_log.cbmem_id {
            // TCG 2.0 crypto-agile log — continue with EFI_TCG2_PROTOCOL.
            0x54504d32 => {
                // SAFETY: coreboot's CBMEM region persists for the entire boot.
                let log_data = unsafe {
                    core::slice::from_raw_parts(tpm_log.address as *const u8, tpm_log.size as usize)
                };
                (Some(log_data), crabefi::TpmLogFormat::CryptoAgile)
            }
            // TCG 1.2 SHA1-only log — continue with EFI_TCG_PROTOCOL.
            0x54445041 => {
                // SAFETY: coreboot's CBMEM region persists for the entire boot.
                let log_data = unsafe {
                    core::slice::from_raw_parts(tpm_log.address as *const u8, tpm_log.size as usize)
                };
                (Some(log_data), crabefi::TpmLogFormat::Sha1Only)
            }
            // coreboot-specific format — start fresh (not directly
            // compatible with either TCG log format).
            _ => {
                log::info!("Coreboot TPM log is in CB-specific format, starting fresh");
                (None, crabefi::TpmLogFormat::Both)
            }
        },
        None => (None, crabefi::TpmLogFormat::Both),
    };
    crabefi::TpmEventLogConfig {
        existing_log,
        log_area: None,
        format,
        // Hardware TPM transport is selected after ACPI namespace discovery.
        // Coreboot's TPM log record does not describe the transport.
        tpm2_device: crabefi::Tpm2DeviceConfig::None,
        tpm1_tis_base: None,
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn discover_tpm(
    rsdp: u64,
    acpi_info: &crabefi::fdt::PlatformInfo,
    config: &mut crabefi::PlatformConfig<'_>,
) {
    // A CRB TPM, such as an AMD fTPM, is described by the TPM2 table:
    // its _CRS names the command buffers, not the registers.
    // SAFETY: coreboot identity maps its ACPI tables.
    let crb = unsafe { acpi::find_tpm2_table(rsdp) }.and_then(|tpm2| {
        let start = match tpm2.start_method {
            7 => crabefi::CrbStart::Crb,
            2 | 8 => crabefi::CrbStart::Acpi,
            _ => return None,
        };
        (tpm2.control_area != 0).then_some((tpm2.control_area, start))
    });
    if let Some((control_area, start)) = crb {
        log::info!("ACPI TPM2 table describes a CRB TPM at {:#x}", control_area);
        if let Some(ref mut tpm) = config.tpm_event_log {
            tpm.tpm2_device = crabefi::Tpm2DeviceConfig::Crb {
                control_area,
                start,
            };
        }
    } else if let Some((tpm_hid, device)) = ["MSFT0101", "PNP0C31"]
        .iter()
        .find_map(|hid| acpi_info.find_device(hid).map(|device| (*hid, device)))
        && device.mmio_base <= 0xfed4_0000
        && device.mmio_base.saturating_add(device.mmio_size) > 0xfed4_0000
    {
        log::info!("ACPI exposes an MMIO TIS TPM at 0xfed40000 ({})", tpm_hid);
        if let Some(ref mut tpm) = config.tpm_event_log {
            match tpm_hid {
                "PNP0C31" => {
                    // A TPM 1.2 platform must not expose EFI_TCG2_PROTOCOL:
                    // Linux otherwise selects it and receives DEVICE_ERROR
                    // for every attempted measurement.
                    if tpm.format != crabefi::TpmLogFormat::Sha1Only {
                        tpm.existing_log = None;
                    }
                    tpm.format = crabefi::TpmLogFormat::Sha1Only;
                    if tpm.existing_log.is_none() {
                        // SAFETY: coreboot maps the TCPA table and its log for the boot.
                        tpm.existing_log = unsafe { acpi::find_tcpa_event_log(rsdp) };
                    }
                    tpm.tpm1_tis_base = Some(0xfed4_0000);
                    tpm.tpm2_device = crabefi::Tpm2DeviceConfig::None;
                }
                "MSFT0101" => {
                    tpm.tpm2_device = crabefi::Tpm2DeviceConfig::TisMmio { base: 0xfed4_0000 };
                }
                _ => unreachable!(),
            }
        }
    } else {
        log::info!("No ACPI MMIO TIS TPM resource; skipping unsafe probe");
    }

    // Linux reads the TPM2 table's log area before the EFI log.
    if let Some(ref mut tpm) = config.tpm_event_log
        && tpm.tpm2_device.is_some()
    {
        // SAFETY: coreboot's ACPI tables are identity mapped RAM.
        tpm.log_area = unsafe {
            acpi::take_tpm2_log_area(rsdp, crabefi::efi::tcg::event_log::DEFAULT_EVENT_LOG_SIZE)
        }
        .map(|area| crabefi::PlatformEventLog { area, used: 0 });
    }
}
