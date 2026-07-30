//! SetVirtualAddressMap integration test
//!
//! The application exits boot services, moves code and stack to a 512 GiB
//! virtual alias, calls SetVirtualAddressMap, removes the physical alias, and
//! exercises runtime services. Results are written directly to COM1.

#![no_main]
#![no_std]

use core::arch::{asm, global_asm};
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::panic::PanicInfo;

use r_efi::efi::{
    self, CapsuleHeader, Guid, Handle, MemoryDescriptor, Status, SystemTable, Time,
    TimeCapabilities,
};

const VOFF: u64 = 0x80_0000_0000;
const MAP_BUFFER_SIZE: usize = 128 * 1024;
const EFI_MEMORY_RUNTIME: u64 = 0x8000_0000_0000_0000;
const VARIABLE_ATTRIBUTES: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;
const CAPSULE_FLAGS_PERSIST_ACROSS_RESET: u32 = 0x0001_0000;

#[repr(align(4096))]
struct MapBuffer([u8; MAP_BUFFER_SIZE]);

static mut MAP_BUFFER: MapBuffer = MapBuffer([0; MAP_BUFFER_SIZE]);

#[repr(C)]
struct TransitionContext {
    image_handle: Handle,
    runtime_services_phys: u64,
    map_phys: u64,
    map_size: usize,
    map_key: usize,
    descriptor_size: usize,
    descriptor_version: u32,
    pml4_phys: u64,
}

static mut CONTEXT: MaybeUninit<TransitionContext> = MaybeUninit::uninit();

global_asm!(
    r#"
    .global svam_jump_to_alias
svam_jump_to_alias:
    movabs rax, 0x8000000000
    add rsp, rax
    add rcx, rax
    jmp rcx
"#
);

unsafe extern "efiapi" {
    fn svam_jump_to_alias(target: usize) -> !;
}

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "efiapi" fn efi_main(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    if system_table.is_null() {
        fail("system-table");
    }
    let boot_services = unsafe { (*system_table).boot_services };
    let runtime_services = unsafe { (*system_table).runtime_services };
    if boot_services.is_null() || runtime_services.is_null() {
        fail("service-table");
    }

    let map_phys = unsafe { &raw mut MAP_BUFFER.0 as *mut u8 as u64 };
    let context = unsafe {
        let context_ptr = &raw mut CONTEXT as *mut TransitionContext;
        context_ptr.write(TransitionContext {
            image_handle,
            runtime_services_phys: runtime_services as u64,
            map_phys,
            map_size: MAP_BUFFER_SIZE,
            map_key: 0,
            descriptor_size: 0,
            descriptor_version: 0,
            pml4_phys: read_cr3() & !0xfff,
        });
        &mut *context_ptr
    };

    get_memory_map(boot_services, context);
    let exit_status =
        unsafe { ((*boot_services).exit_boot_services)(context.image_handle, context.map_key) };
    if exit_status != Status::SUCCESS {
        // A final map refresh supports the normal map-key retry contract.
        context.map_size = MAP_BUFFER_SIZE;
        get_memory_map(boot_services, context);
        let retry =
            unsafe { ((*boot_services).exit_boot_services)(context.image_handle, context.map_key) };
        if retry != Status::SUCCESS {
            fail("exit-boot-services");
        }
    }

    serial_line("SVAM_TEST: STAGE alias-map");
    unsafe {
        let pml4 = context.pml4_phys as *mut u64;
        core::ptr::write_volatile(pml4.add(1), core::ptr::read_volatile(pml4));
        reload_cr3(context.pml4_phys);
        serial_line("SVAM_TEST: STAGE alias-ready");
        svam_jump_to_alias(alias_main as *const () as usize);
    }
}

fn get_memory_map(boot_services: *mut efi::BootServices, context: &mut TransitionContext) {
    let status = unsafe {
        ((*boot_services).get_memory_map)(
            &mut context.map_size,
            context.map_phys as *mut MemoryDescriptor,
            &mut context.map_key,
            &mut context.descriptor_size,
            &mut context.descriptor_version,
        )
    };
    if status != Status::SUCCESS || context.descriptor_size < size_of::<MemoryDescriptor>() {
        fail("get-memory-map");
    }
}

extern "efiapi" fn alias_main() -> ! {
    serial_line("SVAM_TEST: STAGE alias-entry");
    let context = unsafe { &mut *(&raw mut CONTEXT as *mut TransitionContext) };
    let map = (context.map_phys + VOFF) as *mut u8;
    let count = context.map_size / context.descriptor_size;

    for index in 0..count {
        let descriptor =
            unsafe { &mut *(map.add(index * context.descriptor_size) as *mut MemoryDescriptor) };
        if descriptor.attribute & EFI_MEMORY_RUNTIME != 0 {
            descriptor.virtual_start = descriptor.physical_start + VOFF;
        } else {
            descriptor.virtual_start = 0;
        }
    }

    serial_line("SVAM_TEST: STAGE virtual-map");
    let runtime_phys = context.runtime_services_phys as *mut efi::RuntimeServices;
    let status = unsafe {
        ((*runtime_phys).set_virtual_address_map)(
            context.map_size,
            context.descriptor_size,
            context.descriptor_version,
            map as *mut MemoryDescriptor,
        )
    };
    if status != Status::SUCCESS {
        fail("set-virtual-address-map");
    }
    serial_line("SVAM_TEST: STAGE svam-complete");

    // Remove the identity map while executing and using the stack through the
    // virtual alias. Any stale physical pointer now faults immediately.
    unsafe {
        let pml4_virtual = (context.pml4_phys + VOFF) as *mut u64;
        core::ptr::write_volatile(pml4_virtual, 0);
        reload_cr3(context.pml4_phys);
    }

    serial_line("SVAM_TEST: STAGE physical-unmapped");
    let runtime = (context.runtime_services_phys + VOFF) as *mut efi::RuntimeServices;
    exercise_runtime_services(runtime);
    serial_line("SVAM_TEST: PASS");

    // Exercise ResetSystem last. QEMU runs with -no-reboot, so the PASS marker
    // remains the harness result even though this call does not return.
    unsafe {
        ((*runtime).reset_system)(efi::RESET_WARM, Status::SUCCESS, 0, core::ptr::null_mut());
    }
    halt()
}

fn exercise_runtime_services(runtime: *mut efi::RuntimeServices) {
    let mut time = Time::default();
    let mut capabilities = TimeCapabilities {
        resolution: 0,
        accuracy: 0,
        sets_to_zero: efi::Boolean::FALSE,
    };
    let status = unsafe { ((*runtime).get_time)(&mut time, &mut capabilities) };
    require(status, "get-time");

    const SETUP_MODE: [u16; 10] = [
        b'S' as u16,
        b'e' as u16,
        b't' as u16,
        b'u' as u16,
        b'p' as u16,
        b'M' as u16,
        b'o' as u16,
        b'd' as u16,
        b'e' as u16,
        0,
    ];
    let mut global_guid = Guid::from_fields(
        0x8be4_df61,
        0x93ca,
        0x11d2,
        0xaa,
        0x0d,
        &[0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
    );
    let mut setup_mode = 0u8;
    let mut setup_size = 1usize;
    require(
        unsafe {
            ((*runtime).get_variable)(
                SETUP_MODE.as_ptr() as *mut u16,
                &mut global_guid,
                core::ptr::null_mut(),
                &mut setup_size,
                &mut setup_mode as *mut u8 as *mut c_void,
            )
        },
        "get-variable",
    );

    let mut name = [0u16; 128];
    let mut guid = Guid::from_fields(0, 0, 0, 0, 0, &[0; 6]);
    let mut enumerated = 0usize;
    loop {
        let mut name_size = size_of_val(&name);
        let status = unsafe {
            ((*runtime).get_next_variable_name)(&mut name_size, name.as_mut_ptr(), &mut guid)
        };
        if status == Status::NOT_FOUND {
            break;
        }
        require(status, "get-next-variable-name");
        enumerated += 1;
        if enumerated > 128 {
            fail("get-next-variable-loop");
        }
    }
    if enumerated < 2 {
        fail("get-next-variable-empty");
    }

    let mut maximum_storage = 0u64;
    let mut remaining_storage = 0u64;
    let mut maximum_variable = 0u64;
    require(
        unsafe {
            ((*runtime).query_variable_info)(
                VARIABLE_ATTRIBUTES,
                &mut maximum_storage,
                &mut remaining_storage,
                &mut maximum_variable,
            )
        },
        "query-variable-info",
    );
    if maximum_storage == 0 || maximum_variable == 0 {
        fail("query-variable-info-values");
    }

    const TEST_NAME: [u16; 13] = [
        b'S' as u16,
        b'v' as u16,
        b'a' as u16,
        b'm' as u16,
        b'T' as u16,
        b'e' as u16,
        b's' as u16,
        b't' as u16,
        b'V' as u16,
        b'a' as u16,
        b'r' as u16,
        0,
        0,
    ];
    let mut test_guid = Guid::from_fields(
        0x7c18_5a6d,
        0xd8a4,
        0x4db1,
        0x91,
        0x28,
        &[0xf2, 0x3c, 0x11, 0xe0, 0x5b, 0x91],
    );
    let payload = [0x43u8, 0x72, 0x61, 0x62];
    require(
        unsafe {
            ((*runtime).set_variable)(
                TEST_NAME.as_ptr() as *mut u16,
                &mut test_guid,
                VARIABLE_ATTRIBUTES,
                payload.len(),
                payload.as_ptr() as *mut c_void,
            )
        },
        "set-variable",
    );

    let mut readback = [0u8; 4];
    let mut readback_size = readback.len();
    require(
        unsafe {
            ((*runtime).get_variable)(
                TEST_NAME.as_ptr() as *mut u16,
                &mut test_guid,
                core::ptr::null_mut(),
                &mut readback_size,
                readback.as_mut_ptr() as *mut c_void,
            )
        },
        "set-variable-readback",
    );
    if readback != payload {
        fail("set-variable-compare");
    }

    require(
        unsafe {
            ((*runtime).set_variable)(
                TEST_NAME.as_ptr() as *mut u16,
                &mut test_guid,
                VARIABLE_ATTRIBUTES,
                0,
                core::ptr::null_mut(),
            )
        },
        "delete-variable",
    );

    let mut capsule = CapsuleHeader {
        capsule_guid: Guid::from_fields(0, 0, 0, 0, 0, &[0; 6]),
        header_size: size_of::<CapsuleHeader>() as u32,
        flags: CAPSULE_FLAGS_PERSIST_ACROSS_RESET,
        capsule_image_size: size_of::<CapsuleHeader>() as u32,
    };
    let mut capsule_ptr = &mut capsule as *mut CapsuleHeader;
    require(
        unsafe {
            ((*runtime).update_capsule)(
                &mut capsule_ptr,
                1,
                &capsule as *const CapsuleHeader as u64,
            )
        },
        "update-capsule",
    );
}

#[inline]
fn read_cr3() -> u64 {
    let value: u64;
    unsafe { asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags)) };
    value
}

#[inline]
unsafe fn reload_cr3(value: u64) {
    unsafe { asm!("mov cr3, {}", in(reg) value, options(nostack, preserves_flags)) };
}

fn require(status: Status, stage: &'static str) {
    if status != Status::SUCCESS {
        fail(stage);
    }
}

fn serial_str(s: &str) {
    for &byte in s.as_bytes() {
        serial_byte(byte);
    }
}

fn serial_line(s: &str) {
    serial_str(s);
    serial_byte(b'\r');
    serial_byte(b'\n');
}

fn serial_byte(byte: u8) {
    unsafe {
        let mut ready: u8;
        loop {
            asm!(
                "in al, dx",
                in("dx") 0x3fdu16,
                out("al") ready,
                options(nomem, nostack, preserves_flags),
            );
            if ready & 0x20 != 0 {
                break;
            }
        }
        asm!(
            "out dx, al",
            in("dx") 0x3f8u16,
            in("al") byte,
            options(nomem, nostack, preserves_flags),
        );
    }
}

fn fail(stage: &'static str) -> ! {
    serial_str("SVAM_TEST: FAIL ");
    serial_line(stage);
    halt()
}

fn halt() -> ! {
    loop {
        unsafe { asm!("cli; hlt", options(nomem, nostack)) };
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    fail("panic")
}
