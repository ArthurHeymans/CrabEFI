//! Exercise the variadic ABI and callback visibility using actual firmware services.

use core::ffi::c_void;
use core::ptr::null_mut;
use r_efi::efi::{self, BootServices, Guid, Handle, Status};

const A: Guid = Guid::from_fields(0x6f1e2b45, 0, 0, 0, 0, &[0; 6]);
const B: Guid = Guid::from_fields(0x6f1e2b46, 0, 0, 0, 0, &[0; 6]);

struct Context {
    bs: *mut BootServices,
    handle: Handle,
    agent: Handle,
    calls: usize,
    complete: bool,
}

extern "efiapi" fn observe(_event: efi::Event, context: *mut c_void) {
    // The event is closed before this stack-owned context goes out of scope.
    let context = unsafe { &mut *context.cast::<Context>() };
    context.calls += 1;
    let mut interface = null_mut();
    unsafe {
        context.complete =
            ((*context.bs).handle_protocol)(context.handle, &mut { B }, &mut interface)
                == Status::SUCCESS;
        context.complete &= ((*context.bs).open_protocol)(
            context.handle,
            &mut { A },
            &mut interface,
            context.agent,
            context.handle,
            efi::OPEN_PROTOCOL_BY_DRIVER,
        ) == Status::SUCCESS;
    }
}

pub fn run(bs: *mut BootServices, agent: Handle) -> bool {
    // r-efi exposes the fixed prefix; spell out all arguments to exercise the
    // firmware's variadic trampoline (including arguments on the x64 stack).
    type Install = extern "efiapi" fn(
        *mut Handle,
        *mut Guid,
        *mut c_void,
        *mut Guid,
        *mut c_void,
        *mut Guid,
    ) -> Status;
    type Uninstall = extern "efiapi" fn(
        Handle,
        *mut Guid,
        *mut c_void,
        *mut Guid,
        *mut c_void,
        *mut Guid,
    ) -> Status;
    let install: Install =
        unsafe { core::mem::transmute((*bs).install_multiple_protocol_interfaces) };
    let uninstall: Uninstall =
        unsafe { core::mem::transmute((*bs).uninstall_multiple_protocol_interfaces) };
    let mut context = Context {
        bs,
        handle: null_mut(),
        agent,
        calls: 0,
        complete: false,
    };
    let mut event = null_mut();
    let mut registration = null_mut();
    let mut a = 1u64;
    let mut b = 2u64;
    let ap = (&raw mut a).cast();
    let bp = (&raw mut b).cast();
    unsafe {
        if ((*bs).create_event)(
            efi::EVT_NOTIFY_SIGNAL,
            efi::TPL_CALLBACK,
            Some(observe),
            (&raw mut context).cast(),
            &mut event,
        ) != Status::SUCCESS
        {
            return false;
        }
        if ((*bs).register_protocol_notify)(&mut { A }, event, &mut registration) != Status::SUCCESS
        {
            ((*bs).close_event)(event);
            return false;
        }
    }
    let mut ok = install(
        &mut context.handle,
        &mut { A },
        ap,
        &mut { A },
        ap,
        null_mut(),
    ) == Status::INVALID_PARAMETER;
    ok &= context.handle.is_null() && context.calls == 0;
    ok &= install(
        &mut context.handle,
        &mut { A },
        ap,
        &mut { B },
        bp,
        null_mut(),
    ) == Status::SUCCESS;
    ok &= context.calls == 1 && context.complete;
    unsafe {
        ok &= ((*bs).reinstall_protocol_interface)(context.handle, &mut { A }, ap, bp)
            == Status::ACCESS_DENIED;
        ok &= ((*bs).close_protocol)(context.handle, &mut { A }, agent, context.handle)
            == Status::SUCCESS;
    }
    // Ordinary opens must be visible and closeable, but never pin the interface.
    let mut interface = null_mut();
    unsafe {
        for _ in 0..2 {
            ok &= ((*bs).open_protocol)(
                context.handle,
                &mut { A },
                &mut interface,
                agent,
                null_mut(),
                efi::OPEN_PROTOCOL_GET_PROTOCOL,
            ) == Status::SUCCESS;
        }
        let mut entries = null_mut();
        let mut count = 0;
        let status =
            ((*bs).open_protocol_information)(context.handle, &mut { A }, &mut entries, &mut count);
        ok &= status == Status::SUCCESS && count == 1;
        if status == Status::SUCCESS && count == 1 && !entries.is_null() {
            ok &= (*entries).agent_handle == agent && (*entries).open_count == 2;
            ((*bs).free_pool)(entries.cast());
        }
        ok &= ((*bs).close_protocol)(context.handle, &mut { A }, agent, null_mut())
            == Status::SUCCESS;
        ok &= ((*bs).open_protocol)(
            context.handle,
            &mut { A },
            &mut interface,
            agent,
            null_mut(),
            efi::OPEN_PROTOCOL_EXCLUSIVE,
        ) == Status::SUCCESS;
        ok &= ((*bs).close_protocol)(context.handle, &mut { A }, agent, null_mut())
            == Status::SUCCESS;
        ok &= ((*bs).open_protocol)(
            context.handle,
            &mut { A },
            &mut interface,
            agent,
            null_mut(),
            efi::OPEN_PROTOCOL_GET_PROTOCOL | efi::OPEN_PROTOCOL_EXCLUSIVE,
        ) == Status::INVALID_PARAMETER;
        ok &= ((*bs).open_protocol)(
            context.handle,
            &mut { A },
            &mut interface,
            agent,
            null_mut(),
            efi::OPEN_PROTOCOL_GET_PROTOCOL,
        ) == Status::SUCCESS;
    }
    ok &= uninstall(context.handle, &mut { A }, ap, &mut { B }, bp, null_mut()) == Status::SUCCESS;
    let mut interface = null_mut();
    unsafe {
        ok &=
            ((*bs).locate_protocol)(&mut { A }, registration, &mut interface) == Status::NOT_FOUND;
        ((*bs).close_event)(event);
    }
    ok
}
