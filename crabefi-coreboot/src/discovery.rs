//! Platform tables and peripherals passed to CrabEFI.

use crate::tables;

pub(crate) fn fdt(cb_info: &tables::CorebootInfo) -> Option<&[u8]> {
    #[cfg(target_arch = "riscv64")]
    if let Some(fdt) = crate::riscv_boot::saved_fdt() {
        return Some(fdt);
    }
    cb_info.devicetree.map(|(addr, size)| {
        // SAFETY: coreboot's devicetree pointer and size are valid.
        unsafe { core::slice::from_raw_parts(addr as *const u8, size as usize) }
    })
}

/// The AML interpreter allocates, so discovery must follow heap initialization.
#[cfg(not(target_arch = "riscv64"))]
pub(crate) fn discover_acpi(config: &mut crabefi::PlatformConfig<'_>) {
    use crate::acpi;
    if let Some(rsdp) = config.acpi_rsdp {
        // SAFETY: coreboot identity maps ACPI tables and device MMIO; no other
        // CrabEFI driver uses the controllers of described peripherals.
        let acpi::Discovery {
            info: acpi_info,
            peripherals,
        } = unsafe { acpi::discover_platform(rsdp) };
        config.peripherals = peripherals;
        #[cfg(all(target_arch = "x86_64", not(feature = "native-only")))]
        crate::measured_boot::discover_tpm(rsdp, &acpi_info, config);
        config.acpi_info = Some(acpi_info);
    }
}
