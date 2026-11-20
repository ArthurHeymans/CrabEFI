//! Coreboot policy, clock, reset and EFI lifecycle callbacks.

use crate::tables;
#[cfg(not(feature = "native-only"))]
use crate::{cbmem_console, framebuffer};

/// Boot device policy selected by Cargo features.
pub(crate) fn boot_policy() -> crabefi::BootPolicy {
    crabefi::BootPolicy {
        usb_init: if cfg!(feature = "usb-on-demand") {
            crabefi::UsbInit::OnDemand
        } else {
            crabefi::UsbInit::Always
        },
        external_boot: if cfg!(feature = "external-boot-deny") {
            crabefi::ExternalBoot::Deny
        } else if cfg!(feature = "external-boot-menu-only") {
            crabefi::ExternalBoot::MenuOnly
        } else {
            crabefi::ExternalBoot::Allow
        },
        internal_hot_plug_sata: cfg!(feature = "internal-hot-plug-sata"),
    }
}

/// Timer backed by the architecture's monotonic counter.
///
/// On x86_64 this wraps the TSC (calibrated via ACPI PM timer before
/// `init_platform()` is called). On aarch64 this reads the ARM Generic
/// Timer directly. On riscv64 this reads the `rdtime` counter.
pub(crate) struct CorebootTimer {
    pub(crate) freq_hz: u64,
}

impl crabefi::Timer for CorebootTimer {
    fn current_ticks(&self) -> u64 {
        crabefi::time::read_counter()
    }

    fn ticks_per_second(&self) -> u64 {
        self.freq_hz
    }
}

/// Reset handler using architecture-specific reset mechanisms.
pub(crate) struct CorebootReset;

/// Coreboot-specific lifecycle callbacks injected into the generic core.
#[cfg(not(feature = "native-only"))]
pub(crate) struct CorebootHooks;

#[cfg(not(feature = "native-only"))]
impl crabefi::PlatformHooks for CorebootHooks {
    fn on_exit_boot_services(&self) {
        // Invalidate the coreboot framebuffer record to prevent a race between
        // Linux simplefb (coreboot) and efifb (EFI GOP).
        // SAFETY: only this ExitBootServices hook modifies the saved record.
        unsafe {
            framebuffer::invalidate_framebuffer_record();
        }

        // CBMEM console is not runtime mapped; disable it before runtime use.
        cbmem_console::disable();
    }

    fn firmware_settings_available(&self) -> bool {
        true
    }

    fn show_firmware_settings(&self) -> bool {
        crabefi::cfr_menu::show_cfr_menu();
        true
    }

    #[cfg(feature = "ui")]
    fn show_graphical_firmware_settings(&self) -> crabefi::ui::ScreenNav {
        crabefi::cfr_menu::show_graphical_firmware_settings()
    }
}

impl crabefi::ResetHandler for CorebootReset {
    fn reset(&self, reset_type: crabefi::ResetType) -> ! {
        #[cfg(target_arch = "x86_64")]
        {
            // Try keyboard controller reset, then triple fault as fallback.
            let _ = reset_type;
            crabefi::arch::x86_64::reset::keyboard_controller_reset();
            crabefi::time::delay_ms(100);
            crabefi::arch::x86_64::reset::triple_fault()
        }
        #[cfg(target_arch = "aarch64")]
        {
            match reset_type {
                crabefi::ResetType::Shutdown => crabefi::arch::aarch64::reset::system_off(),
                _ => crabefi::arch::aarch64::reset::system_reset(),
            }
        }
        #[cfg(target_arch = "riscv64")]
        {
            match reset_type {
                crabefi::ResetType::Shutdown => crabefi::arch::riscv64::reset::system_off(),
                _ => crabefi::arch::riscv64::reset::system_reset(),
            }
        }
    }
}

pub(crate) fn calibrate_timer(cb_info: &tables::CorebootInfo) {
    // coreboot advertises the TSC rate only when it is constant; using it skips
    // the 50 ms ACPI PM timer calibration window.
    #[cfg(target_arch = "x86_64")]
    let tsc_from_coreboot = cb_info.tsc_freq_khz;
    #[cfg(not(target_arch = "x86_64"))]
    let tsc_from_coreboot: Option<u32> = None;
    if let Some(freq_khz) = tsc_from_coreboot {
        crabefi::time::set_counter_frequency(u64::from(freq_khz) * 1000);
        log::info!("TSC frequency from coreboot: {} kHz", freq_khz);
    } else {
        crabefi::time::init(cb_info.acpi_rsdp);
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn start_timestamps(
    cb_info: &tables::CorebootInfo,
    entry_counter: u64,
) -> Option<crate::timestamps::CorebootTimestampRecorder> {
    cb_info.timestamps.and_then(|table_addr| {
        // Only touch memory coreboot reserved for tables, never RAM the
        // allocator hands out or ranges outside the map.
        let fbpt = cb_info
            .acpi_rsdp
            // SAFETY: coreboot's ACPI tables are identity mapped.
            .and_then(|rsdp| unsafe {
                crate::acpi::find_fbpt(rsdp, |start, length| {
                    crate::boot_memory::in_table_memory(&cb_info.memory_map, start, length)
                })
            });
        let recorder = crate::timestamps::CorebootTimestampRecorder::new(table_addr)?
            .with_fbpt(fbpt, crabefi::time::counter_frequency);
        recorder.record_counter(crabefi::timestamp::TS_CRABEFI_START, entry_counter);
        recorder.record_now(crabefi::timestamp::TS_CRABEFI_TABLES_PARSED);
        Some(recorder)
    })
}
