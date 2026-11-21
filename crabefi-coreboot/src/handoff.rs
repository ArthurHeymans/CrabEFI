//! Assemble the native or EFI configuration and enter the core library.
//! Configuration borrows boot-lifetime storage kept in this non-returning frame.

use crate::platform::{CorebootReset, CorebootTimer, boot_policy};
use crate::{discovery, tables};

#[cfg(feature = "native-only")]
pub(crate) fn boot(
    cb_info: &tables::CorebootInfo,
    memory_map: &[crabefi::MemoryRegion],
    framebuffer: Option<crabefi::FramebufferConfig>,
    timestamp_recorder: Option<&dyn crabefi::TimestampRecorder>,
) -> ! {
    // Create timer backed by the calibrated arch counter.
    let timer = CorebootTimer {
        freq_hz: crabefi::time::counter_frequency(),
    };

    let reset = CorebootReset;
    let mut config =
        crabefi::PlatformConfigBuilder::new_native(memory_map, &timer, &reset, &mut [])
            .boot_policy(boot_policy())
            .build();
    config.timestamp_recorder = timestamp_recorder;
    config.framebuffer = framebuffer;
    config.acpi_rsdp = cb_info.acpi_rsdp;
    config.fdt = discovery::fdt(cb_info);

    crabefi::prepare_native_memory(&mut config);
    discovery::discover_acpi(&mut config);
    crabefi::init_native_platform(config)
}

#[cfg(not(feature = "native-only"))]
pub(crate) fn boot(
    cb_info: &tables::CorebootInfo,
    memory_map: &[crabefi::MemoryRegion],
    framebuffer: Option<crabefi::FramebufferConfig>,
    timestamp_recorder: Option<&dyn crabefi::TimestampRecorder>,
) -> ! {
    use crate::boot_memory::in_table_memory;
    use crate::capsule::CorebootCapsuleBackend;
    use crate::platform::CorebootHooks;
    use crate::runtime::{runtime_image_source, runtime_platform_config};
    use crate::varstore::CorebootVariableStoreLocator;

    // Create timer backed by the calibrated arch counter.
    let timer = CorebootTimer {
        freq_hz: crabefi::time::counter_frequency(),
    };

    let reset = CorebootReset;
    let hooks = CorebootHooks;
    let variable_store_locator = CorebootVariableStoreLocator::new(cb_info);
    let fdt_slice = discovery::fdt(cb_info);
    let firmware_info = cb_info.efi_fw_info.map(|fw_info| crabefi::FirmwareInfo {
        guid: fw_info.guid,
        version: fw_info.version,
        lowest_supported_version: fw_info.lowest_supported_version,
        fw_size: fw_info.fw_size,
    });

    let mut capsule_regions =
        [crabefi::CapsuleRegion { base: 0, size: 0 }; crabefi::handoff::MAX_CAPSULES];
    let mut capsule_count = 0;
    for capsule in cb_info.capsules.iter() {
        if capsule_count >= capsule_regions.len() {
            break;
        }
        capsule_regions[capsule_count] = crabefi::CapsuleRegion {
            base: capsule.base,
            size: capsule.size,
        };
        capsule_count += 1;
    }

    let mut capsule_backend = CorebootCapsuleBackend::new(firmware_info, cb_info.boot_media);

    let mut config = crabefi::PlatformConfig {
        memory_map,
        timer: &timer,
        timestamp_recorder,
        reset: &reset,
        block_devices: &mut [],
        variable_storage: crabefi::VariableStorage::Spi(&variable_store_locator),
        debug_output: None, // Already set up via serial::init_from_config()
        console_input: None,
        peripherals: alloc::vec::Vec::new(),
        framebuffer,
        acpi_rsdp: cb_info.acpi_rsdp,
        smbios: cb_info.smbios,
        fdt: fdt_slice,
        acpi_info: None,
        discover_mmio: cfg!(any(target_arch = "aarch64", target_arch = "riscv64")),
        firmware_info,
        capsule_regions: &capsule_regions[..capsule_count],
        capsule_backend: Some(&mut capsule_backend),
        capsule_on_disk_only: cfg!(feature = "capsule-on-disk-only"),
        // SAFETY: the record lies in coreboot-reserved memory, which persists
        // for the entire boot (checked against the memory map).
        boot_events: cb_info
            .boot_events
            .filter(|_| cfg!(feature = "boot-event-log"))
            .filter(|&(address, size)| {
                address != 0 && in_table_memory(&cb_info.memory_map, address, u64::from(size))
            })
            .map(|(address, size)| unsafe {
                core::slice::from_raw_parts(address as *const u8, size as usize)
            }),
        hooks: Some(&hooks),
        rng: None,
        ecam_regions: &[], // ACPI/FDT discovery is selected by the library below.
        runtime_image: runtime_image_source(),
        runtime: runtime_platform_config(),
        tpm_event_log: Some(crate::measured_boot::event_log(cb_info)),
        boot_policy: boot_policy(),
        heap_pre_initialized: false,
    };

    // Bootstrap the heap for AML and CFR; init_platform reuses it.
    crabefi::efi::allocator::init_from_platform(config.memory_map);
    #[cfg(feature = "payload-mm")]
    crate::payload_mm::reserve_buffer();
    match crabefi::heap::init() {
        Ok(()) | Err(crabefi::heap::HeapInitError::AlreadyInitialized) => {
            config.heap_pre_initialized = true;
        }
        Err(e) => {
            panic!("Failed to initialize heap allocator: {e}");
        }
    }

    #[cfg(not(target_arch = "riscv64"))]
    discovery::discover_acpi(&mut config);
    if let Some(cfr_raw) = cb_info.cfr_raw
        && let Some(cfr) = crabefi::cfr::parse_cfr(cfr_raw)
    {
        log::info!(
            "CFR: {} forms, {} options",
            cfr.forms.len(),
            cfr.total_options()
        );
        crabefi::cfr::store_cfr(cfr);
    }

    crabefi::init_platform(config)
}
