//! End-to-end protocol database tests, including reentrant notification callbacks.

use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use r_efi::efi::{self, Guid, Handle, Status};

use super::*;
use crate::efi::tables::{LoadedImageEntry, Tables, init_caches, tables, with_tables_mut};

const A: Guid = Guid::from_fields(1, 0, 0, 0, 0, &[0; 6]);
const B: Guid = Guid::from_fields(2, 0, 0, 0, 0, &[0; 6]);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static COMPLETE: AtomicBool = AtomicBool::new(false);

extern "efiapi" fn observe(_event: efi::Event, context: *mut c_void) {
    CALLS.fetch_add(1, Ordering::Relaxed);
    // The caller's output handle is already published when callbacks run.
    let handle = unsafe { *(context as *const Handle) };
    let mut interface = null_mut();
    let status = handle_protocol(handle, &mut { B }, &mut interface);
    COMPLETE.store(status == Status::SUCCESS, Ordering::Relaxed);
    // This open would make rollback fail if callbacks ran inside the transaction.
    assert_eq!(
        open_protocol(
            handle,
            &mut { A },
            &mut interface,
            handle,
            handle,
            efi::OPEN_PROTOCOL_BY_DRIVER
        ),
        Status::SUCCESS
    );
}

fn install(guid: Guid, interface: *mut c_void) -> Handle {
    let mut handle = null_mut();
    assert_eq!(
        install_protocol_interface(&mut handle, &mut { guid }, efi::NATIVE_INTERFACE, interface),
        Status::SUCCESS
    );
    handle
}

fn register(guid: Guid, event: efi::Event) -> *mut c_void {
    let mut registration = null_mut();
    assert_eq!(
        register_protocol_notify(&mut { guid }, event, &mut registration),
        Status::SUCCESS
    );
    registration
}

fn next(registration: *mut c_void) -> Result<Handle, Status> {
    let mut handle = null_mut();
    let mut size = core::mem::size_of::<Handle>();
    let status = locate_handle(
        efi::BY_REGISTER_NOTIFY,
        null_mut(),
        registration,
        &mut size,
        &mut handle,
    );
    if status == Status::SUCCESS {
        Ok(handle)
    } else {
        Err(status)
    }
}

// One test owns the global database throughout: no parallel tests race its cells.
#[test]
fn protocol_transactions_cursors_and_open_lifecycle() {
    let _execution = crate::efi::boot_services::IMAGE_EXECUTION_TEST_LOCK.lock().unwrap();
    with_tables_mut(|state| *state = Tables::new());
    init_caches().unwrap();
    let a = core::ptr::dangling_mut::<u64>().cast::<c_void>();
    let b = core::ptr::dangling_mut::<u32>().cast::<c_void>();
    let mut transaction_handle: Handle = null_mut();
    let mut event = null_mut();
    assert_eq!(
        create_event(
            efi::EVT_NOTIFY_SIGNAL,
            efi::TPL_CALLBACK,
            Some(observe),
            (&raw mut transaction_handle).cast(),
            &mut event
        ),
        Status::SUCCESS
    );
    let registration = register(A, event);

    assert_eq!(
        install_multiple_pairs(&mut transaction_handle, &[(A, a), (A, a)]),
        Status::INVALID_PARAMETER
    );
    assert!(transaction_handle.is_null());
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    assert_eq!(next(registration), Err(Status::NOT_FOUND));
    assert_eq!(
        install_multiple_pairs(&mut transaction_handle, &[(A, a), (B, b)]),
        Status::SUCCESS
    );
    assert_eq!(CALLS.load(Ordering::Relaxed), 1);
    assert!(COMPLETE.load(Ordering::Relaxed));
    assert_eq!(
        reinstall_protocol_interface(transaction_handle, &mut { A }, a, b),
        Status::ACCESS_DENIED
    );
    assert_eq!(get_protocol_on_handle(transaction_handle, &A), a);
    assert_eq!(
        uninstall_multiple_pairs(transaction_handle, &[(A, a), (B, b)]),
        Status::ACCESS_DENIED
    );
    assert_eq!(
        close_protocol(
            transaction_handle,
            &mut { A },
            transaction_handle,
            transaction_handle
        ),
        Status::SUCCESS
    );
    assert_eq!(
        uninstall_multiple_pairs(transaction_handle, &[(A, a), (B, b)]),
        Status::SUCCESS
    );
    assert_eq!(next(registration), Err(Status::NOT_FOUND));
    assert_eq!(close_event(event), Status::SUCCESS);

    // An unsignaled ordinary event lets us explicitly drain registrations.
    assert_eq!(
        create_event(0, 0, None, null_mut(), &mut event),
        Status::SUCCESS
    );
    let first = install(A, a);
    let second = install(A, b);
    let registration = register(A, event);
    let mut interface = null_mut();
    assert_eq!(
        locate_protocol(&mut { A }, registration, &mut interface),
        Status::SUCCESS
    );
    assert_eq!(interface, a); // preexisting instance
    assert_eq!(next(registration), Ok(second)); // shared LocateProtocol/LocateHandle cursor
    assert_eq!(
        locate_protocol(&mut { A }, registration, &mut interface),
        Status::NOT_FOUND
    );
    assert_eq!(
        locate_protocol(&mut { A }, usize::MAX as *mut c_void, &mut interface),
        Status::INVALID_PARAMETER
    );
    assert_eq!(
        locate_protocol(&mut { B }, registration, &mut interface),
        Status::INVALID_PARAMETER
    );

    assert_eq!(
        reinstall_protocol_interface(first, &mut { A }, a, b),
        Status::SUCCESS
    );
    assert_eq!(next(registration), Ok(first));
    assert_eq!(next(registration), Err(Status::NOT_FOUND));
    assert_eq!(remove_protocol(first, &A, Some(b)), Status::SUCCESS);
    assert_eq!(remove_protocol(second, &A, Some(b)), Status::SUCCESS);

    // Both a deleted handle and a surviving handle that lost A must be skipped.
    let deleted = install(A, a);
    let surviving = install(A, a);
    assert_eq!(install_protocol(surviving, &B, b), Status::SUCCESS);
    let live = install(A, b);
    assert_eq!(remove_protocol(deleted, &A, Some(a)), Status::SUCCESS);
    assert_eq!(remove_protocol(surviving, &A, Some(a)), Status::SUCCESS);
    let mut size = 0;
    assert_eq!(
        locate_handle(
            efi::BY_REGISTER_NOTIFY,
            null_mut(),
            registration,
            &mut size,
            null_mut()
        ),
        Status::BUFFER_TOO_SMALL
    );
    assert_eq!(next(registration), Ok(live)); // sizing did not consume
    assert_eq!(next(registration), Err(Status::NOT_FOUND));
    assert_eq!(remove_protocol(live, &A, Some(b)), Status::SUCCESS);
    let handles: alloc::vec::Vec<_> = (0..80).map(|_| install(A, a)).collect();
    for handle in &handles {
        assert_eq!(next(registration), Ok(*handle));
    }
    assert_eq!(next(registration), Err(Status::NOT_FOUND));

    let handle = handles[0];
    let agent = handles[1];
    for attr in [
        efi::OPEN_PROTOCOL_GET_PROTOCOL | efi::OPEN_PROTOCOL_EXCLUSIVE,
        efi::OPEN_PROTOCOL_TEST_PROTOCOL | efi::OPEN_PROTOCOL_EXCLUSIVE,
        efi::OPEN_PROTOCOL_BY_CHILD_CONTROLLER | efi::OPEN_PROTOCOL_EXCLUSIVE,
        0,
    ] {
        assert_eq!(
            open_protocol(handle, &mut { A }, &mut interface, agent, handle, attr),
            Status::INVALID_PARAMETER
        );
    }
    assert_eq!(
        open_protocol(
            handle,
            &mut { A },
            &mut interface,
            agent,
            null_mut(),
            efi::OPEN_PROTOCOL_EXCLUSIVE
        ),
        Status::SUCCESS
    );
    assert_eq!(
        reinstall_protocol_interface(handle, &mut { A }, a, b),
        Status::ACCESS_DENIED
    );
    assert_eq!(
        close_protocol(handle, &mut { A }, agent, null_mut()),
        Status::SUCCESS
    );
    for _ in 0..2 {
        assert_eq!(
            open_protocol(
                handle,
                &mut { A },
                &mut interface,
                agent,
                null_mut(),
                efi::OPEN_PROTOCOL_GET_PROTOCOL
            ),
            Status::SUCCESS
        );
    }
    assert_eq!(tables().open_protocols.len(), 1);
    assert_eq!(tables().open_protocols[0].open_count, 2);
    assert_eq!(
        close_protocol(handle, &mut { A }, agent, null_mut()),
        Status::SUCCESS
    );
    assert!(tables().open_protocols.is_empty());
    assert_eq!(
        open_protocol(
            handle,
            &mut { A },
            &mut interface,
            agent,
            null_mut(),
            efi::OPEN_PROTOCOL_GET_PROTOCOL
        ),
        Status::SUCCESS
    );
    assert_eq!(
        reinstall_protocol_interface(handle, &mut { A }, a, b),
        Status::SUCCESS
    );
    assert!(tables().open_protocols.is_empty());
    assert_eq!(
        open_protocol(
            handle,
            &mut { A },
            &mut interface,
            agent,
            null_mut(),
            efi::OPEN_PROTOCOL_GET_PROTOCOL
        ),
        Status::SUCCESS
    );
    assert_eq!(remove_protocol(handle, &A, Some(b)), Status::SUCCESS);
    assert!(tables().open_protocols.is_empty());

    // Synthetic loaded image: no allocation, so the free attempt safely fails;
    // the observable relationship teardown still exercises real UnloadImage.
    let handle = handles[2];
    with_tables_mut(|state| {
        state.loaded_images[0] = LoadedImageEntry {
            handle: agent,
            ..LoadedImageEntry::empty()
        }
    });
    assert_eq!(
        open_protocol(
            handle,
            &mut { A },
            &mut interface,
            agent,
            handle,
            efi::OPEN_PROTOCOL_BY_DRIVER
        ),
        Status::SUCCESS
    );
    assert_eq!(
        open_protocol(
            handle,
            &mut { A },
            &mut interface,
            agent,
            handle,
            efi::OPEN_PROTOCOL_BY_DRIVER
        ),
        Status::ALREADY_STARTED
    );
    assert_eq!(tables().open_protocols[0].open_count, 1);
    assert_eq!(
        open_protocol(
            agent,
            &mut { A },
            &mut interface,
            handle,
            agent,
            efi::OPEN_PROTOCOL_BY_DRIVER | efi::OPEN_PROTOCOL_EXCLUSIVE
        ),
        Status::SUCCESS
    );
    assert_eq!(
        open_protocol(
            agent,
            &mut { A },
            &mut interface,
            handle,
            agent,
            efi::OPEN_PROTOCOL_BY_DRIVER | efi::OPEN_PROTOCOL_EXCLUSIVE
        ),
        Status::ALREADY_STARTED
    );
    assert_eq!(
        open_protocol(
            agent,
            &mut { A },
            &mut interface,
            handle,
            agent,
            efi::OPEN_PROTOCOL_BY_DRIVER
        ),
        Status::ACCESS_DENIED
    );
    assert_eq!(unload_image(agent), Status::ACCESS_DENIED);
    assert_eq!(tables().loaded_images[0].handle, agent);
    assert_eq!(
        close_protocol(agent, &mut { A }, handle, agent),
        Status::SUCCESS
    );
    assert_eq!(unload_image(agent), Status::SUCCESS);
    assert!(tables().open_protocols.is_empty());
    assert_eq!(remove_protocol(handle, &A, Some(a)), Status::SUCCESS);
    with_tables_mut(|state| *state = Tables::new());
}
