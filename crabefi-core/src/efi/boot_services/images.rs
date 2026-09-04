//! EFI Boot Services image loading and boot handoff.
//!
//! `LoadImage`/`StartImage`/`UnloadImage`/`ExitBootServices` and the
//! TCG deferred-measurement plumbing for boot applications.

use super::super::allocator::{self, MemoryType};
use super::super::image_loader;
use super::super::protocols::loaded_image::{
    LOADED_IMAGE_PROTOCOL_GUID, create_loaded_image_protocol,
};
use super::super::system_table;
use super::super::tables::{LoadedImageEntry, MAX_EVENTS, tables, with_tables_mut};
use super::events::signal_event_group;
use super::events::{
    EVT_SIGNAL_EXIT_BOOT_SERVICES, dynamic_event_id_for_handle, event_handle,
    measure_efi_application_return, measure_efi_application_start,
};
use crate::pe;
use alloc::vec::Vec;
use core::ffi::c_void;
use r_efi::efi::{self, Boolean, Guid, Handle, Status, SystemTable};
use r_efi::protocols::device_path::Protocol as DevicePathProtocol;

/// EFI_EVENT_GROUP_EXIT_BOOT_SERVICES GUID
const EFI_EVENT_GROUP_EXIT_BOOT_SERVICES: Guid = Guid::from_fields(
    0x27ABF055,
    0xB1B8,
    0x4C26,
    0x80,
    0x48,
    &[0x74, 0x8F, 0x37, 0xBA, 0xA2, 0xDF],
);

// ============================================================================
// Image Functions
// ============================================================================
// Device path parsing and file loading helpers are in `super::super::image_loader`.

pub(super) extern "efiapi" fn load_image(
    boot_policy: Boolean,
    parent_image_handle: Handle,
    device_path: *mut DevicePathProtocol,
    source_buffer: *mut c_void,
    source_size: usize,
    image_handle: *mut Handle,
) -> Status {
    log::debug!(
        "BS.LoadImage(boot_policy={:?}, parent={:?}, device_path={:?}, buf={:?}, size={})",
        boot_policy,
        parent_image_handle,
        device_path,
        source_buffer,
        source_size
    );

    // Validate parameters
    if image_handle.is_null() {
        log::error!("BS.LoadImage: image_handle is NULL");
        return Status::INVALID_PARAMETER;
    }

    // Determine the image source: either a caller-provided buffer or loaded from device path.
    enum ImageSource {
        /// Caller-provided buffer — not owned by us, must not be freed
        Buffer {
            data_ptr: *mut c_void,
            data_size: usize,
        },
        /// Loaded from device path — we allocated this buffer and must free it
        DevicePath {
            data_ptr: *mut c_void,
            data_size: usize,
            device_handle: Handle,
        },
    }

    let source = if !source_buffer.is_null() && source_size > 0 {
        ImageSource::Buffer {
            data_ptr: source_buffer,
            data_size: source_size,
        }
    } else if !device_path.is_null() {
        match image_loader::load_image_from_device_path(device_path) {
            Ok((ptr, size, dev_handle)) => ImageSource::DevicePath {
                data_ptr: ptr,
                data_size: size,
                device_handle: dev_handle,
            },
            Err(status) => {
                log::error!(
                    "BS.LoadImage: Failed to load from device path: {:?}",
                    status
                );
                return status;
            }
        }
    } else {
        log::error!("BS.LoadImage: No source buffer and no device path provided");
        return Status::INVALID_PARAMETER;
    };

    let (data_ptr, data_size) = match &source {
        ImageSource::Buffer {
            data_ptr,
            data_size,
        } => (*data_ptr, *data_size),
        ImageSource::DevicePath {
            data_ptr,
            data_size,
            ..
        } => (*data_ptr, *data_size),
    };

    // Create a slice from the source buffer
    let data = unsafe { core::slice::from_raw_parts(data_ptr as *const u8, data_size) };

    // Helper to free the buffer only if we own it (loaded from device path)
    let free_if_owned = |source: &ImageSource| {
        if let ImageSource::DevicePath { data_ptr, .. } = source {
            let _ = allocator::free_pool(*data_ptr as *mut u8);
        }
    };

    // Secure Boot verification (if enabled)
    if super::super::auth::is_secure_boot_enabled() {
        log::debug!("BS.LoadImage: Secure Boot verification required");
        match super::super::auth::verify_pe_image_secure_boot(data) {
            Ok(true) => {
                log::info!("BS.LoadImage: Secure Boot verification passed");
            }
            Ok(false) => {
                log::error!("BS.LoadImage: Secure Boot verification FAILED - image not authorized");
                crate::display_secure_boot_error();
                free_if_owned(&source);
                return Status::SECURITY_VIOLATION;
            }
            Err(e) => {
                log::error!("BS.LoadImage: Secure Boot verification error: {:?}", e);
                crate::display_secure_boot_error();
                free_if_owned(&source);
                return Status::SECURITY_VIOLATION;
            }
        }
    }

    // Load the PE image using our PE loader
    let loaded_image = match pe::load_image(data) {
        Ok(img) => img,
        Err(status) => {
            log::error!("BS.LoadImage: Failed to load PE image: {:?}", status);
            free_if_owned(&source);
            return status;
        }
    };

    log::debug!(
        "BS.LoadImage: PE loaded at {:#x}, entry={:#x}, size={:#x}",
        loaded_image.image_base,
        loaded_image.entry_point,
        loaded_image.image_size
    );

    // Preserve metadata before releasing an owned source buffer.
    let image_subsystem = pe::parse_headers(data)
        .map(|headers| headers.subsystem())
        .unwrap_or(0);

    // TCG measured boot: drivers are measured now; applications are deferred
    // until StartImage after ReadyToBoot, with digests computed before freeing data.
    let deferred_measurement = measure_pe_image_for_tcg(
        data,
        &loaded_image,
        device_path as *const DevicePathProtocol,
    );

    // Free the buffer now that PE is loaded and measured (PE loading makes its own copy).
    free_if_owned(&source);

    // Create a new handle for this image
    let new_handle = match super::create_handle() {
        Some(h) => h,
        None => {
            log::error!("BS.LoadImage: Failed to create handle");
            pe::unload_image(&loaded_image);
            return Status::OUT_OF_RESOURCES;
        }
    };

    // Create LoadedImageProtocol for this image
    // Use the device handle from loading if we loaded from device path,
    // otherwise try to get it from the parent
    let device_handle = match &source {
        ImageSource::DevicePath { device_handle, .. } => *device_handle,
        _ => image_loader::get_device_handle_from_parent(parent_image_handle),
    };

    let system_table = super::super::get_system_table();
    let loaded_image_protocol = create_loaded_image_protocol(
        parent_image_handle,
        system_table,
        device_handle,
        loaded_image.image_base,
        loaded_image.image_size,
    );

    if loaded_image_protocol.is_null() {
        log::error!("BS.LoadImage: Failed to create LoadedImageProtocol");
        if let Some(measurement) = deferred_measurement {
            let _ = allocator::free_pool(measurement.event_data);
        }
        pe::unload_image(&loaded_image);
        return Status::OUT_OF_RESOURCES;
    }

    // Set the device path on the loaded image if provided
    if !device_path.is_null() {
        unsafe {
            super::super::protocols::loaded_image::set_file_path(
                loaded_image_protocol,
                device_path,
            );
        }
    }

    // Install the LoadedImageProtocol on the handle
    let status = super::install_protocol(
        new_handle,
        &LOADED_IMAGE_PROTOCOL_GUID,
        loaded_image_protocol as *mut c_void,
    );

    if status != Status::SUCCESS {
        log::error!(
            "BS.LoadImage: Failed to install LoadedImageProtocol: {:?}",
            status
        );
        if let Some(measurement) = deferred_measurement {
            let _ = allocator::free_pool(measurement.event_data);
        }
        pe::unload_image(&loaded_image);
        return status;
    }

    // Store the loaded image info so StartImage can find it
    let store_result = with_tables_mut(|efi_state| {
        let slot = efi_state
            .loaded_images
            .iter_mut()
            .find(|entry| entry.handle.is_null());

        match slot {
            Some(entry) => {
                entry.handle = new_handle;
                entry.image_base = loaded_image.image_base;
                entry.image_size = loaded_image.image_size;
                entry.entry_point = loaded_image.entry_point;
                entry.alloc_base = loaded_image.alloc_base;
                entry.num_pages = loaded_image.num_pages;
                entry.parent_handle = parent_image_handle;
                entry.subsystem = image_subsystem;
                if let Some(measurement) = deferred_measurement {
                    entry.measurement_pcr = measurement.pcr_index;
                    entry.measurement_event_type = measurement.event_type;
                    entry.measurement_digest_count = measurement.digest_count;
                    entry.measurement_digests = measurement.digests;
                    entry.measurement_event_data = measurement.event_data;
                    entry.measurement_event_data_size = measurement.event_data_size;
                }
                true
            }
            None => false,
        }
    });

    if !store_result {
        log::error!("BS.LoadImage: No space in loaded images table");
        if let Some(measurement) = deferred_measurement {
            let _ = allocator::free_pool(measurement.event_data);
        }
        pe::unload_image(&loaded_image);
        return Status::OUT_OF_RESOURCES;
    }

    // Return the new handle
    unsafe {
        *image_handle = new_handle;
    }

    log::info!(
        "BS.LoadImage: SUCCESS - handle={:?}, base={:#x}, entry={:#x}",
        new_handle,
        loaded_image.image_base,
        loaded_image.entry_point
    );

    Status::SUCCESS
}

pub(super) extern "efiapi" fn start_image(
    image_handle: Handle,
    exit_data_size: *mut usize,
    exit_data: *mut *mut u16,
) -> Status {
    log::debug!("BS.StartImage(handle={:?})", image_handle);

    if image_handle.is_null() {
        log::error!("BS.StartImage: image_handle is NULL");
        return Status::INVALID_PARAMETER;
    }

    // Find the loaded image entry
    let (entry_point, image_base, image_subsystem) = {
        let efi_state = tables();
        match efi_state
            .loaded_images
            .iter()
            .find(|entry| entry.handle == image_handle)
            .map(|entry| (entry.entry_point, entry.image_base, entry.subsystem))
        {
            Some(info) => info,
            None => {
                log::error!(
                    "BS.StartImage: handle {:?} not found in loaded images",
                    image_handle
                );
                return Status::INVALID_PARAMETER;
            }
        }
    };

    log::info!(
        "BS.StartImage: Executing image at {:#x} (base={:#x})",
        entry_point,
        image_base
    );

    // Signal EFI_EVENT_GROUP_READY_TO_BOOT before the first image is started
    // and measure boot-attempt action events without duplicating separators.
    let is_application = image_subsystem == 10;
    measure_efi_application_start(is_application);

    let deferred_measurement = with_tables_mut(|efi_state| {
        efi_state
            .loaded_images
            .iter_mut()
            .find(|entry| entry.handle == image_handle)
            .and_then(|entry| {
                if entry.measurement_event_data.is_null() {
                    return None;
                }
                let measurement = DeferredImageMeasurement {
                    pcr_index: entry.measurement_pcr,
                    event_type: entry.measurement_event_type,
                    digest_count: entry.measurement_digest_count,
                    digests: entry.measurement_digests,
                    event_data: entry.measurement_event_data,
                    event_data_size: entry.measurement_event_data_size,
                };
                entry.measurement_event_data = core::ptr::null_mut();
                entry.measurement_event_data_size = 0;
                entry.measurement_digest_count = 0;
                Some(measurement)
            })
    });

    if let Some(measurement) = deferred_measurement {
        let event_data = unsafe {
            // SAFETY: deferred measurement event data was allocated and filled in
            // LoadImage and remains owned by this loaded-image entry until now.
            core::slice::from_raw_parts(measurement.event_data, measurement.event_data_size)
        };
        if let Err(e) = super::super::tcg::measured_boot::measure_pe_image_digests_all(
            measurement.pcr_index,
            measurement.event_type,
            &measurement.digests[..measurement.digest_count],
            event_data,
        ) {
            log::warn!("Failed to measure PE image: {:?}", e);
        }
        let _ = allocator::free_pool(measurement.event_data);
    }

    // Update table CRC32s one final time before handing off to the image
    // (config tables may have changed since efi::init())
    super::super::system_table::update_crc32();

    // Get the system table
    let system_table = super::super::get_system_table();

    // Define the entry point function type
    type EfiEntryPoint = extern "efiapi" fn(Handle, *mut SystemTable) -> Status;

    // Call the entry point
    let entry: EfiEntryPoint = unsafe { core::mem::transmute(entry_point) };
    let status = entry(image_handle, system_table);

    log::info!("BS.StartImage: Image returned with status: {:?}", status);
    measure_efi_application_return(is_application);

    // Set exit data if provided (we don't support exit data currently)
    if !exit_data_size.is_null() {
        unsafe {
            *exit_data_size = 0;
        }
    }
    if !exit_data.is_null() {
        unsafe {
            *exit_data = core::ptr::null_mut();
        }
    }

    status
}

/// EFI Boot Service: Exit
///
/// UEFI Spec Compliance Note: A fully conformant `Exit()` implementation must
/// perform a non-local return (longjmp) back to the corresponding `StartImage()`
/// call, unwinding the call stack. This requires saving the execution context
/// (registers, stack pointer) in `StartImage()` via setjmp, and restoring it here.
///
/// Current limitation: This implementation simply returns `exit_status` to the
/// caller, which means `Exit()` only works correctly when called directly from
/// the image's entry point (the common case for UEFI bootloaders like shim and
/// GRUB). It will NOT correctly unwind nested image calls or calls from deep
/// within a loaded image's call stack.
///
/// This is acceptable for our boot use case (shim → GRUB → Linux), but would
/// need a proper setjmp/longjmp implementation for full UEFI application support.
pub(super) extern "efiapi" fn exit(
    image_handle: Handle,
    exit_status: Status,
    exit_data_size: usize,
    _exit_data: *mut u16,
) -> Status {
    log::info!(
        "BS.Exit(handle={:?}, status={:?}, data_size={})",
        image_handle,
        exit_status,
        exit_data_size
    );
    exit_status
}

pub(super) extern "efiapi" fn unload_image(image_handle: Handle) -> Status {
    log::debug!("BS.UnloadImage(handle={:?})", image_handle);

    if image_handle.is_null() {
        log::error!("BS.UnloadImage: image_handle is NULL");
        return Status::INVALID_PARAMETER;
    }

    // Find and remove the loaded image entry
    let image_info = with_tables_mut(|efi_state| {
        efi_state
            .loaded_images
            .iter_mut()
            .find(|entry| entry.handle == image_handle)
            .map(|entry| {
                let result = (
                    entry.alloc_base,
                    entry.num_pages,
                    entry.measurement_event_data,
                );
                // Clear the entry
                *entry = LoadedImageEntry::empty();
                result
            })
    });

    match image_info {
        Some((alloc_base, num_pages, measurement_event_data)) => {
            // Free the image memory (using alloc_base, not image_base,
            // since the image may have been aligned within the allocation)
            let status = allocator::free_pages(alloc_base, num_pages);
            if status != Status::SUCCESS {
                log::warn!(
                    "BS.UnloadImage: Failed to free pages at {:#x}: {:?}",
                    alloc_base,
                    status
                );
            }

            if !measurement_event_data.is_null() {
                let _ = allocator::free_pool(measurement_event_data);
            }

            // Remove protocols from the handle
            // Note: In a full implementation, we should uninstall all protocols
            // For now, we just log success
            log::debug!("BS.UnloadImage: SUCCESS");
            Status::SUCCESS
        }
        None => {
            log::warn!(
                "BS.UnloadImage: handle {:?} not found in loaded images",
                image_handle
            );
            // Return success anyway - the handle might have been loaded differently
            Status::SUCCESS
        }
    }
}

pub(super) extern "efiapi" fn exit_boot_services(image_handle: Handle, map_key: usize) -> Status {
    log::info!(
        "BS.ExitBootServices(handle={:?}, map_key={:#x})",
        image_handle,
        map_key
    );

    // Reject a stale key before callbacks, measurements, or any irreversible
    // transition. The allocator repeats this check at the actual commit point
    // in case an EBS callback changes the map.
    let key_status = allocator::validate_map_key(map_key);
    if key_status != Status::SUCCESS {
        return key_status;
    }
    let Some(runtime_image) = crate::efi::runtime_image::installed() else {
        log::error!("ExitBootServices refused: runtime image client is missing");
        return Status::DEVICE_ERROR;
    };

    // TCG measured boot: measure ExitBootServices action into PCR 5.
    super::super::tcg::measured_boot::measure_action_all(5, "Exit Boot Services Invocation");

    // Signal EXIT_BOOT_SERVICES event group BEFORE finalizing the memory map.
    // Windows Boot Manager registers callbacks that must run before we lock
    // the memory map.
    signal_event_group(&EFI_EVENT_GROUP_EXIT_BOOT_SERVICES);

    // Also signal any legacy EVT_SIGNAL_EXIT_BOOT_SERVICES events
    {
        let mut legacy_events: heapless::Vec<usize, MAX_EVENTS> = heapless::Vec::new();
        with_tables_mut(|efi_state| {
            for (i, event) in efi_state.events.iter_mut().enumerate() {
                if event.in_use && event.event_type == EVT_SIGNAL_EXIT_BOOT_SERVICES {
                    event.signaled = true;
                    let _ = legacy_events.push(event_handle(i, event.generation) as usize);
                }
            }
        });
        for handle in &legacy_events {
            let notify_fn = {
                let efi_state = tables();
                dynamic_event_id_for_handle(&efi_state.events, *handle as efi::Event).and_then(
                    |event_id| {
                        let entry = &efi_state.events[event_id];
                        entry.notify_function.map(|f| (f, entry.notify_context))
                    },
                )
            };
            if let Some((func, context)) = notify_fn {
                func(*handle as efi::Event, context);
            }
        }
    }

    // Rebuild the Memory Attributes Table in-place BEFORE locking the allocator.
    // Runtime image and retained-buffer regions are registered after the
    // initial table setup, so the final MAT must be rebuilt from the allocator.
    // A stale MEMATTR table with missing entries causes Windows to crash.
    // We use the in-place variant that overwrites the existing page without
    // calling allocate_pages(), so the map_key stays valid for the caller.
    let prepare_status = system_table::rebuild_memory_attributes_table_in_place();
    if prepare_status != Status::SUCCESS {
        return prepare_status;
    }

    // Event callbacks and MAT rebuilding may have changed the memory map. Do a
    // final key check before any irreversible hardware quiescence.
    let key_status = allocator::validate_map_key(map_key);
    if key_status != Status::SUCCESS {
        return key_status;
    }

    // Stop every firmware-owned DMA engine while BootServices allocations are
    // still typed and cannot yet be reused by the OS. Clearing BME is the final
    // safety net for devices without complete driver shutdown coverage.
    crate::drivers::quiesce_dma_for_os_handoff();

    let status = allocator::exit_boot_services(map_key);

    if status == Status::SUCCESS {
        // TCG measured boot: measure ExitBootServices success into PCR 5.
        super::super::tcg::measured_boot::measure_action_all(
            5,
            "Exit Boot Services Returned with Success",
        );

        log::info!("ExitBootServices SUCCESS - transitioning to OS");
        crate::timestamp::record(crate::timestamp::TS_CRABEFI_EXIT_BOOT_SERVICES);

        // Clean up hardware state for OS handoff.
        // Re-enable keyboard interrupts so Linux's i8042 driver works.
        crate::drivers::keyboard_common::cleanup();

        // Seal only after the allocator accepted the map key, while boot-time
        // diagnostics are still reachable. A failed seal leaves no safe way to
        // return to the OS after allocator EBS, so report it and halt explicitly.
        if let Err(seal_status) = runtime_image.seal() {
            log::error!(
                "FATAL: runtime image seal failed after allocator ExitBootServices: {:?}",
                seal_status
            );
            loop {
                crate::arch::halt();
            }
        }
        log::info!("Runtime image sealed successfully");

        // Let platform glue clean up integration-specific handoff state only
        // after the final fallible step; hooks may disable non-runtime log
        // buffers needed to diagnose a seal failure.
        if let Some(hooks) = crate::handoff::callbacks().hooks {
            hooks.on_exit_boot_services();
        }

        // CRITICAL: Disable logging only after the final fallible runtime-image
        // transition. The OS generally does not map firmware log devices as
        // runtime memory.
        log::set_max_level(log::LevelFilter::Off);

        // Switch from Secure EL1 to Non-Secure EL1 via a RAM trampoline.
        //
        // At Secure EL1, GICv3 routes Non-Secure Group 1 interrupts (LPIs /
        // MSI-X) as FIQ. The Linux kernel only handles IRQ, so NVMe and other
        // MSI-X devices hang forever waiting for completion interrupts.
        //
        // We can't issue the SMC directly from flash because the ERET returns
        // to the instruction after the SMC — which is in Secure flash, not
        // accessible from NS-EL1 on QEMU virt. Instead, we write a small
        // trampoline to RAM that does SMC + RET. The RET returns to the EFI
        // stub (also in RAM), now at NS-EL1 with proper interrupt routing.
        //
        // Uses vendor-specific SMCCC function ID 0xC2000000 handled by
        // fstart's EL3 exception vector. No-op if no EL3 exists.
        #[cfg(target_arch = "aarch64")]
        crate::arch::aarch64::ns_switch::install_ns_trampoline();
    } else {
        super::super::tcg::measured_boot::measure_action_all(
            5,
            "Exit Boot Services Returned with Failure",
        );
        log::warn!("ExitBootServices FAILED: {:?}", status);
    }

    status
}

#[derive(Clone, Copy)]
struct DeferredImageMeasurement {
    pcr_index: u32,
    event_type: u32,
    digest_count: usize,
    digests: [super::super::tcg::types::TaggedDigest; 5],
    event_data: *mut u8,
    event_data_size: usize,
}

pub(crate) fn serialize_tcg_image_load_event(
    loaded_image: &pe::LoadedImage,
    image_link_time_address: u64,
    device_path_ptr: *const DevicePathProtocol,
) -> Vec<u8> {
    let device_path_size = if device_path_ptr.is_null() {
        0
    } else {
        unsafe { super::super::protocols::device_path::device_path_size(device_path_ptr) }
    };

    let mut event = Vec::with_capacity(32 + device_path_size);
    event.extend_from_slice(&loaded_image.image_base.to_le_bytes());
    event.extend_from_slice(&loaded_image.image_size.to_le_bytes());
    event.extend_from_slice(&image_link_time_address.to_le_bytes());
    event.extend_from_slice(&(device_path_size as u64).to_le_bytes());
    if device_path_size != 0 {
        let device_path =
            unsafe { core::slice::from_raw_parts(device_path_ptr as *const u8, device_path_size) };
        event.extend_from_slice(device_path);
    }
    event
}

/// Measure or defer a PE/COFF image for TCG measured boot.
///
/// Driver images are measured immediately. Application image digests and event
/// data are precomputed here so `StartImage()` can log them after ReadyToBoot.
fn measure_pe_image_for_tcg(
    pe_data: &[u8],
    loaded_image: &pe::LoadedImage,
    device_path: *const DevicePathProtocol,
) -> Option<DeferredImageMeasurement> {
    use super::super::tcg::measured_boot::{measure_pe_image_all, precompute_pe_image_digests_all};
    use super::super::tcg::types::*;

    let headers = pe::parse_headers(pe_data).ok()?;
    let subsystem = headers.subsystem();
    let (pcr_index, event_type) = match subsystem {
        10 => (4, EV_EFI_BOOT_SERVICES_APPLICATION),
        11 => (2, EV_EFI_BOOT_SERVICES_DRIVER),
        12 => (2, EV_EFI_RUNTIME_SERVICES_DRIVER),
        _ => (4, EV_EFI_BOOT_SERVICES_APPLICATION),
    };

    let event_data =
        serialize_tcg_image_load_event(loaded_image, headers.preferred_image_base(), device_path);

    if subsystem != 10 {
        if let Err(e) = measure_pe_image_all(pcr_index, event_type, pe_data, &event_data) {
            log::warn!("Failed to measure PE image: {:?}", e);
        }
        return None;
    }

    let (digest_count, digests) = (match precompute_pe_image_digests_all(pe_data) {
        Ok(result) => result,
        Err(e) => {
            log::warn!("Failed to precompute PE image measurement: {:?}", e);
            None
        }
    })?;

    let event_data_size = event_data.len();
    let event_data_ptr =
        match allocator::allocate_pool(MemoryType::BootServicesData, event_data_size) {
            Ok(ptr) => ptr,
            Err(status) => {
                log::warn!(
                    "Failed to allocate deferred PE measurement event data: {:?}",
                    status
                );
                return None;
            }
        };
    unsafe {
        // SAFETY: `event_data_ptr` points to `event_data_size` bytes just
        // allocated above, and `event_data` has exactly that many initialized bytes.
        core::ptr::copy_nonoverlapping(event_data.as_ptr(), event_data_ptr, event_data_size);
    }

    Some(DeferredImageMeasurement {
        pcr_index,
        event_type,
        digest_count,
        digests,
        event_data: event_data_ptr,
        event_data_size,
    })
}
