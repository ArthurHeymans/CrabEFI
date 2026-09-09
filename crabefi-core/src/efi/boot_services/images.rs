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
use super::super::tables::{LoadedImageEntry, MAX_EVENTS, Tables, tables, with_tables_mut};
use super::events::signal_event_group;
use super::events::{
    EVT_SIGNAL_EXIT_BOOT_SERVICES, dynamic_event_id_for_handle, event_handle,
    measure_efi_application_return, measure_efi_application_start,
};
use super::protocol_open_blocks_removal;
use crate::pe;
use alloc::vec::Vec;
use core::ffi::c_void;
use r_efi::efi::{self, Boolean, Guid, Handle, Status};

#[path = "image_execution.rs"]
mod execution;
pub(super) use execution::exit;

static STARTED: crate::cell::Local<Vec<(Handle, bool)>> = crate::cell::Local::new(Vec::new());
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

/// Full device path to the loaded image (distinct from LoadedImage.FilePath).
const LOADED_IMAGE_DEVICE_PATH_GUID: Guid = Guid::from_fields(
    0xbc62157e,
    0x3e33,
    0x4fec,
    0x99,
    0x20,
    &[0x2d, 0x3b, 0x36, 0xd7, 0x50, 0xdf],
);

/// Co-own a copied full path with the LoadedImage allocation, so caller buffers
/// may be freed immediately after LoadImage. One FreePool releases both.
fn own_image_path(
    protocol: *mut r_efi::protocols::loaded_image::Protocol,
    path: *mut DevicePathProtocol,
) -> (
    *mut r_efi::protocols::loaded_image::Protocol,
    *mut DevicePathProtocol,
) {
    if protocol.is_null() || path.is_null() {
        return (protocol, core::ptr::null_mut());
    }
    // SAFETY: LoadImage's caller supplies a valid terminated device path.
    let path_size = unsafe { super::super::protocols::device_path::device_path_size(path) };
    let protocol_size = core::mem::size_of::<r_efi::protocols::loaded_image::Protocol>();
    let allocation = protocol_size
        .checked_add(path_size)
        .and_then(|size| allocator::allocate_pool(MemoryType::BootServicesData, size).ok());
    let result = match allocation {
        Some(allocation) => {
            let owned = allocation.cast::<r_efi::protocols::loaded_image::Protocol>();
            // SAFETY: fresh pool storage fits the protocol and complete byte path;
            // the protocol contains only plain EFI fields, with no Rust ownership.
            unsafe {
                core::ptr::copy_nonoverlapping(protocol, owned, 1);
                let owned_path = allocation.add(protocol_size);
                core::ptr::copy_nonoverlapping(path.cast::<u8>(), owned_path, path_size);
                (owned, owned_path.cast())
            }
        }
        None => (core::ptr::null_mut(), core::ptr::null_mut()),
    };
    let _ = allocator::free_pool(protocol.cast());
    result
}

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
    #[cfg(feature = "secure-boot")]
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
    #[cfg(feature = "tpm")]
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
            #[cfg(feature = "tpm")]
            if let Some(measurement) = deferred_measurement {
                let _ = allocator::free_pool(measurement.event_data);
            }
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

    let (loaded_image_protocol, owned_path) = own_image_path(loaded_image_protocol, device_path);
    if loaded_image_protocol.is_null() {
        log::error!("BS.LoadImage: Failed to create LoadedImageProtocol");
        #[cfg(feature = "tpm")]
        if let Some(measurement) = deferred_measurement {
            let _ = allocator::free_pool(measurement.event_data);
        }
        pe::unload_image(&loaded_image);
        reclaim_image_handle(new_handle);
        return Status::OUT_OF_RESOURCES;
    }

    // Resolve buffer-loaded images against their supplied full path too: the
    // firmware parent itself has no filesystem device to inherit.
    if !owned_path.is_null() {
        let mut remaining = owned_path;
        let mut resolved = core::ptr::null_mut();
        let mut guid = super::super::protocols::simple_file_system::SIMPLE_FILE_SYSTEM_GUID;
        let located =
            super::protocols_db::locate_device_path(&mut guid, &mut remaining, &mut resolved);
        // SAFETY: both paths point within our co-owned allocation; the interface
        // is not yet published and will retain these bytes until UnloadImage.
        unsafe {
            if located == Status::SUCCESS {
                (*loaded_image_protocol).device_handle = resolved;
                (*loaded_image_protocol).file_path = remaining;
            } else {
                (*loaded_image_protocol).file_path = owned_path;
            }
        }
    }

    // Install the LoadedImageProtocol on the handle
    let status = super::install_protocol_internal(
        new_handle,
        &LOADED_IMAGE_PROTOCOL_GUID,
        loaded_image_protocol as *mut c_void,
        false,
    );
    let status = if status == Status::SUCCESS && !owned_path.is_null() {
        super::install_protocol_internal(
            new_handle,
            &LOADED_IMAGE_DEVICE_PATH_GUID,
            owned_path.cast(),
            false,
        )
    } else {
        status
    };

    if status != Status::SUCCESS {
        log::error!(
            "BS.LoadImage: Failed to install LoadedImageProtocol: {:?}",
            status
        );
        #[cfg(feature = "tpm")]
        if let Some(measurement) = deferred_measurement {
            let _ = allocator::free_pool(measurement.event_data);
        }
        pe::unload_image(&loaded_image);
        let _ = allocator::free_pool(loaded_image_protocol.cast());
        reclaim_image_handle(new_handle);
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
                #[cfg(feature = "tpm")]
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
        #[cfg(feature = "tpm")]
        if let Some(measurement) = deferred_measurement {
            let _ = allocator::free_pool(measurement.event_data);
        }
        pe::unload_image(&loaded_image);
        reclaim_image_handle(new_handle);
        let _ = allocator::free_pool(loaded_image_protocol.cast());
        return Status::OUT_OF_RESOURCES;
    }

    for guid in [LOADED_IMAGE_PROTOCOL_GUID, LOADED_IMAGE_DEVICE_PATH_GUID] {
        if guid == LOADED_IMAGE_DEVICE_PATH_GUID && owned_path.is_null() {
            continue;
        }
        let notifications = with_tables_mut(|state| {
            super::protocols_db::protocol_notification_events(state, &guid)
        });
        for event in notifications {
            super::events::signal_event(event);
        }
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

    let mark_status = STARTED.with_mut(|started| {
        if started.iter().any(|(handle, _)| *handle == image_handle) {
            return Status::INVALID_PARAMETER;
        }
        if started.try_reserve(1).is_err() {
            return Status::OUT_OF_RESOURCES;
        }
        // Mark running before ReadyToBoot can reenter UnloadImage.
        started.push((image_handle, true));
        Status::SUCCESS
    });
    if mark_status != Status::SUCCESS {
        return mark_status;
    }

    log::info!(
        "BS.StartImage: Executing image at {:#x} (base={:#x})",
        entry_point,
        image_base
    );

    // Signal EFI_EVENT_GROUP_READY_TO_BOOT before the first image is started
    // and measure boot-attempt action events without duplicating separators.
    let is_application = image_subsystem == 10;
    measure_efi_application_start(is_application);

    #[cfg(feature = "tpm")]
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

    #[cfg(feature = "tpm")]
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

    let mut context = execution::Context::new(image_handle);
    execution::CURRENT.set(core::ptr::addr_of_mut!(context));
    // SAFETY: entry_point is the validated PE entry; context stays at a stable
    // address until the assembly invocation returns, normally or via Exit.
    let returned = unsafe {
        execution::invoke(
            core::ptr::addr_of_mut!(context),
            entry_point as usize,
            image_handle,
            system_table,
        )
    };
    execution::CURRENT.set(context.previous);
    STARTED.with_mut(|started| {
        if let Some((_, running)) = started
            .iter_mut()
            .find(|(handle, _)| *handle == image_handle)
        {
            *running = false;
        }
    });
    let status = if context.exited {
        context.status
    } else {
        returned
    };

    log::info!("BS.StartImage: Image returned with status: {:?}", status);
    measure_efi_application_return(is_application);

    if !exit_data_size.is_null() && !exit_data.is_null() {
        // SAFETY: caller supplies writable output parameters. Ownership of the
        // pool allocation transfers to the StartImage caller, not the image.
        unsafe {
            *exit_data_size = context.size;
            *exit_data = context.data;
        }
    } else if !context.data.is_null() {
        let _ = allocator::free_pool(context.data.cast());
    }

    // Applications, and drivers that failed initialization, do not stay resident.
    if is_application || status.is_error() {
        let _ = release_image(image_handle);
    }
    status
}

/// Prepare Exit without abandoning a Rust frame. The assembly wrapper performs
/// the transfer only after this function has returned and released all borrows.
extern "efiapi" fn prepare_exit(
    image_handle: Handle,
    exit_status: Status,
    exit_data_size: usize,
    exit_data: *mut u16,
) -> usize {
    let current = execution::CURRENT.get();
    if current.is_null() || unsafe { (*current).handle != image_handle } {
        // UEFI also permits Exit on an image that has not been started.
        return if STARTED
            .with_mut(|started| started.iter().any(|(handle, _)| *handle == image_handle))
        {
            Status::INVALID_PARAMETER.as_usize()
        } else {
            // Return success through the assembly wrapper, not as a context.
            let status = release_image(image_handle);
            if status == Status::SUCCESS {
                0
            } else {
                status.as_usize()
            }
        };
    }
    // Exit may only abandon image frames, not an intervening firmware callback.
    if unsafe { (*current).callback_depth } != super::image_callback_depth() {
        return Status::INVALID_PARAMETER.as_usize();
    }
    let (data, size) = if exit_status == Status::SUCCESS || exit_data_size == 0 {
        (core::ptr::null_mut(), 0)
    } else {
        if exit_data.is_null() {
            return Status::INVALID_PARAMETER.as_usize();
        }
        let buffer = match allocator::allocate_pool(MemoryType::BootServicesData, exit_data_size) {
            Ok(buffer) => buffer,
            Err(status) => return status.as_usize(),
        };
        // SAFETY: EFI caller supplies exit_data_size readable bytes; the fresh
        // allocation is disjoint and remains valid after freeing image pages.
        unsafe {
            core::ptr::copy_nonoverlapping(exit_data.cast::<u8>(), buffer, exit_data_size);
        }
        (buffer.cast(), exit_data_size)
    };
    // SAFETY: CURRENT points at the innermost live assembly invocation's context.
    // No references or table borrows remain live across the non-local transfer.
    unsafe {
        (*current).status = exit_status;
        (*current).data = data;
        (*current).size = size;
        (*current).exited = true;
    }
    current as usize
}

/// Remove image-owned protocol records and reclaim the now-empty handle.
/// Interface allocation ownership is handled by the caller, not the database.
fn reclaim_image_handle(image_handle: Handle) {
    with_tables_mut(|state| remove_image_handle_records(state, image_handle));
}

fn remove_image_handle_records(state: &mut Tables, image_handle: Handle) {
    if let Some(index) = state.handles[..state.handle_count]
        .iter()
        .position(|h| h.handle == image_handle)
    {
        state
            .handles
            .copy_within(index + 1..state.handle_count, index);
        state.handle_count -= 1;
        state.handles[state.handle_count] = super::super::tables::HandleEntry::empty();
    }
    state
        .open_protocols
        .retain(|open| open.handle != image_handle);
}

/// Detach an image only when no other agent still has a blocking open on it.
fn detach_loaded_image(
    state: &mut Tables,
    image_handle: Handle,
) -> Result<Option<LoadedImageEntry>, Status> {
    if state.open_protocols.iter().any(|open| {
        (open.handle == image_handle || open.controller_handle == image_handle)
            && open.agent_handle != image_handle
            && protocol_open_blocks_removal(open.attributes)
    }) {
        return Err(Status::ACCESS_DENIED);
    }
    let Some(entry) = state
        .loaded_images
        .iter_mut()
        .find(|entry| entry.handle == image_handle)
    else {
        return Ok(None);
    };
    let image = core::mem::replace(entry, LoadedImageEntry::empty());
    state.open_protocols.retain(|open| {
        open.agent_handle != image_handle
            && open.controller_handle != image_handle
            && open.handle != image_handle
    });
    Ok(Some(image))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efi::tables::OpenProtocolEntry;

    #[test]
    fn pending_start_cannot_be_unloaded_before_context_initialization() {
        let _guard = crate::efi::boot_services::IMAGE_EXECUTION_TEST_LOCK
            .lock()
            .unwrap();
        let image = 0xf000usize as Handle;
        assert!(execution::CURRENT.get().is_null());
        STARTED.with_mut(|started| started.push((image, true)));
        let status = unload_image(image);
        STARTED.with_mut(|started| started.retain(|(handle, _)| *handle != image));
        assert_eq!(status, Status::ACCESS_DENIED);
    }

    #[test]
    fn unload_preserves_images_with_external_blocking_opens() {
        let image = 1usize as Handle;
        let other = 2usize as Handle;
        for attributes in [
            efi::OPEN_PROTOCOL_BY_DRIVER,
            efi::OPEN_PROTOCOL_BY_CHILD_CONTROLLER,
            efi::OPEN_PROTOCOL_EXCLUSIVE,
        ] {
            for (handle, controller) in [(image, other), (other, image)] {
                let mut state = Tables::new();
                state.loaded_images.push(LoadedImageEntry {
                    handle: image,
                    alloc_base: 0x1000,
                    num_pages: 1,
                    ..LoadedImageEntry::empty()
                });
                state.open_protocols.push(OpenProtocolEntry {
                    handle,
                    protocol: LOADED_IMAGE_PROTOCOL_GUID,
                    agent_handle: other,
                    controller_handle: controller,
                    attributes,
                    open_count: 1,
                });
                assert!(matches!(
                    detach_loaded_image(&mut state, image),
                    Err(Status::ACCESS_DENIED)
                ));
                assert_eq!(state.loaded_images[0].handle, image);
                assert_eq!(state.loaded_images[0].alloc_base, 0x1000);
                assert_eq!(state.open_protocols.len(), 1);
            }
        }
    }

    #[test]
    fn image_cleanup_removes_protocols_and_reclaims_handle_slot() {
        use crate::efi::tables::{HandleEntry, ProtocolEntry};

        let image = 1usize as Handle;
        let other = 2usize as Handle;
        for count in [0, 1, 2] {
            let mut state = Tables::new();
            let mut record = HandleEntry {
                handle: image,
                ..HandleEntry::empty()
            };
            record.protocol_count = count;
            for protocol in &mut record.protocols[..count] {
                *protocol = ProtocolEntry {
                    guid: LOADED_IMAGE_PROTOCOL_GUID,
                    interface: 0x1000usize as *mut c_void,
                    generation: 1,
                };
            }
            state.handles.push(record);
            state.handles.push(HandleEntry {
                handle: other,
                ..HandleEntry::empty()
            });
            state.handle_count = 2;
            remove_image_handle_records(&mut state, image);
            assert_eq!(state.handle_count, 1);
            assert_eq!(state.handles[0].handle, other);
            assert!(state.handles[1].handle.is_null());
            assert_eq!(state.handles[1].protocol_count, 0);
        }
    }

    #[test]
    fn unload_releases_image_opens_but_preserves_unrelated_opens() {
        let image = 1usize as Handle;
        let other = 2usize as Handle;
        let mut state = Tables::new();
        state.loaded_images.push(LoadedImageEntry {
            handle: image,
            alloc_base: 0x1000,
            num_pages: 1,
            ..LoadedImageEntry::empty()
        });
        for (handle, agent, controller) in [
            (other, image, other),
            (image, image, other),
            (other, image, image),
            (other, other, other),
        ] {
            state.open_protocols.push(OpenProtocolEntry {
                handle,
                protocol: LOADED_IMAGE_PROTOCOL_GUID,
                agent_handle: agent,
                controller_handle: controller,
                attributes: efi::OPEN_PROTOCOL_BY_DRIVER,
                open_count: 1,
            });
        }
        let detached = detach_loaded_image(&mut state, image).unwrap().unwrap();
        assert_eq!(detached.alloc_base, 0x1000);
        assert!(state.loaded_images[0].handle.is_null());
        assert_eq!(state.open_protocols.len(), 1);
        assert_eq!(state.open_protocols[0].agent_handle, other);
    }
}

pub(super) extern "efiapi" fn unload_image(image_handle: Handle) -> Status {
    // This includes starts pending ReadyToBoot/measurement callbacks, before
    // an initialized assembly context exists.
    if STARTED.with_mut(|started| {
        started
            .iter()
            .any(|(handle, running)| *handle == image_handle && *running)
    }) {
        return Status::ACCESS_DENIED;
    }
    // Active images cannot be freed while their instruction pointer is live.
    let mut current = execution::CURRENT.get();
    while !current.is_null() {
        // SAFETY: contexts form the live, single-hart StartImage invocation stack.
        unsafe {
            if (*current).handle == image_handle {
                return Status::ACCESS_DENIED;
            }
            current = (*current).previous;
        }
    }
    if STARTED.with_mut(|started| started.iter().any(|(handle, _)| *handle == image_handle)) {
        let protocol = super::get_protocol_on_handle(image_handle, &LOADED_IMAGE_PROTOCOL_GUID)
            .cast::<r_efi::protocols::loaded_image::Protocol>();
        if protocol.is_null() {
            return Status::INVALID_PARAMETER;
        }
        // SAFETY: the interface remains installed while its unload callback runs.
        let Some(unload) = (unsafe { (*protocol).unload }) else {
            return Status::UNSUPPORTED;
        };
        let status = super::with_image_callback(|| unload(image_handle));
        if status != Status::SUCCESS {
            return status;
        }
    }
    release_image(image_handle)
}

fn release_image(image_handle: Handle) -> Status {
    if image_handle.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let image = match with_tables_mut(|state| detach_loaded_image(state, image_handle)) {
        Ok(Some(image)) => image,
        Ok(None) => return Status::INVALID_PARAMETER,
        Err(status) => return status,
    };
    let protocol = super::get_protocol_on_handle(image_handle, &LOADED_IMAGE_PROTOCOL_GUID);
    // Remove every interface before freeing code/data: image-installed interfaces
    // can point inside those pages too. Only LoadedImage is allocated by us.
    reclaim_image_handle(image_handle);
    STARTED.with_mut(|started| started.retain(|(handle, _)| *handle != image_handle));
    if !protocol.is_null() {
        let _ = allocator::free_pool(protocol.cast());
    }
    #[cfg(feature = "tpm")]
    if !image.measurement_event_data.is_null() {
        let _ = allocator::free_pool(image.measurement_event_data);
    }
    allocator::free_pages(image.alloc_base, image.num_pages)
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
    #[cfg(feature = "tpm")]
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
                super::with_image_callback(|| func(*handle as efi::Event, context));
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
        #[cfg(feature = "tpm")]
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
        #[cfg(feature = "variable-store")]
        crate::efi::varstore::persistence::detach_backend();
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
        #[cfg(feature = "tpm")]
        super::super::tcg::measured_boot::measure_action_all(
            5,
            "Exit Boot Services Returned with Failure",
        );
        log::warn!("ExitBootServices FAILED: {:?}", status);
    }

    status
}

#[derive(Clone, Copy)]
#[cfg(feature = "tpm")]
struct DeferredImageMeasurement {
    pcr_index: u32,
    event_type: u32,
    digest_count: usize,
    digests: [super::super::tcg::types::TaggedDigest; 5],
    event_data: *mut u8,
    event_data_size: usize,
}

#[cfg(feature = "tpm")]
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
#[cfg(feature = "tpm")]
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
