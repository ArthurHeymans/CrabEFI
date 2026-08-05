//! Pre-EBS structural test for the mandatory separate runtime image.

#![no_std]
#![no_main]
// The UEFI ABI declares efi_main safe while passing firmware-owned raw tables.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::panic::PanicInfo;

use r_efi::efi::{self, Char16, Handle, Status, SystemTable};

static mut MAP: [u8; 64 * 1024] = [0; 64 * 1024];

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system: *mut SystemTable) -> Status {
    if system.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: firmware supplies the initialized System Table for this entry.
    let (boot, runtime) = unsafe { ((*system).boot_services, (*system).runtime_services) };
    if boot.is_null() || runtime.is_null() {
        return Status::NOT_READY;
    }
    let mut map_size = 64 * 1024usize;
    let mut map_key = 0usize;
    let mut descriptor_size = 0usize;
    let mut descriptor_version = 0u32;
    // SAFETY: MAP is exclusively used by this single-threaded test entry.
    let map = core::ptr::addr_of_mut!(MAP).cast::<efi::MemoryDescriptor>();
    let status = unsafe {
        ((*boot).get_memory_map)(
            &mut map_size,
            map,
            &mut map_key,
            &mut descriptor_size,
            &mut descriptor_version,
        )
    };
    if status != Status::SUCCESS || descriptor_size < core::mem::size_of::<efi::MemoryDescriptor>()
    {
        return status;
    }

    let pointers = unsafe {
        let table = &*runtime;
        [
            table.get_time as usize,
            table.set_time as usize,
            table.get_wakeup_time as usize,
            table.set_wakeup_time as usize,
            table.set_virtual_address_map as usize,
            table.convert_pointer as usize,
            table.get_variable as usize,
            table.get_next_variable_name as usize,
            table.set_variable as usize,
            table.get_next_high_mono_count as usize,
            table.reset_system as usize,
            table.update_capsule as usize,
            table.query_capsule_capabilities as usize,
            table.query_variable_info as usize,
        ]
    };
    let count = map_size / descriptor_size;
    if !pointers.into_iter().all(|pointer| {
        in_runtime_descriptor(
            map,
            descriptor_size,
            count,
            pointer,
            efi::RUNTIME_SERVICES_CODE,
        )
    }) || !runtime_properties_and_crcs_valid(system, runtime)
    {
        return Status::COMPROMISED_DATA;
    }
    // SAFETY: system and runtime were checked and remain valid before EBS.
    let data_pointers = unsafe {
        [
            system as usize,
            runtime as usize,
            (*system).firmware_vendor as usize,
            (*system).configuration_table as usize,
        ]
    };
    if !data_pointers.into_iter().all(|pointer| {
        in_runtime_descriptor(
            map,
            descriptor_size,
            count,
            pointer,
            efi::RUNTIME_SERVICES_DATA,
        )
    }) || in_runtime_descriptor(
        map,
        descriptor_size,
        count,
        boot as usize,
        efi::RUNTIME_SERVICES_CODE,
    ) || in_runtime_descriptor(
        map,
        descriptor_size,
        count,
        boot as usize,
        efi::RUNTIME_SERVICES_DATA,
    ) {
        return Status::COMPROMISED_DATA;
    }

    #[cfg(target_arch = "x86_64")]
    if replay_marker_present(runtime) {
        if replayed_runtime_writes(runtime) {
            cleanup_replayed_runtime_writes(runtime);
            serial("RUNTIME DEFERRED VARIABLE REPLAY PASSED\r\n");
            serial("RUNTIME CAPSULE CONSUMPTION PASSED\r\n");
            qemu_debug_exit();
        }
        cleanup_replayed_runtime_writes(runtime);
        serial("RUNTIME TWO BOOT REPLAY FAILED\r\n");
        qemu_debug_exit();
    } else if !set_replay_marker(runtime) {
        return Status::DEVICE_ERROR;
    }

    if !exercise_variables(runtime) {
        return Status::DEVICE_ERROR;
    }
    let mut pointer = runtime.cast::<core::ffi::c_void>();
    let convert_status = unsafe { ((*runtime).convert_pointer)(0, &mut pointer) };
    if convert_status != Status::NOT_STARTED {
        return Status::COMPROMISED_DATA;
    }
    print(system, "RUNTIME IMAGE TEST PASSED\r\n");

    #[cfg(target_arch = "x86_64")]
    {
        let virtual_map_size = make_identity_virtual_map(map, descriptor_size, count);
        let status = unsafe { ((*boot).exit_boot_services)(image, map_key) };
        if status != Status::SUCCESS {
            return status;
        }
        // Inject a validation failure, then retry with the untouched identity
        // plan. Success on the retry proves failed SVAM did not partially
        // relocate image state or consume the one-shot transition.
        let first = unsafe { map.read_unaligned() };
        let mut invalid = first;
        invalid.number_of_pages = 0;
        unsafe { map.write_unaligned(invalid) };
        let rejected = unsafe {
            ((*runtime).set_virtual_address_map)(
                virtual_map_size,
                descriptor_size,
                descriptor_version,
                map,
            )
        };
        unsafe { map.write_unaligned(first) };
        let status = unsafe {
            ((*runtime).set_virtual_address_map)(
                virtual_map_size,
                descriptor_size,
                descriptor_version,
                map,
            )
        };
        if rejected != Status::INVALID_PARAMETER || status != Status::SUCCESS {
            loop {
                core::hint::spin_loop();
            }
        }
        let repeated = unsafe {
            ((*runtime).set_virtual_address_map)(
                virtual_map_size,
                descriptor_size,
                descriptor_version,
                map,
            )
        };
        let mut converted = runtime.cast::<core::ffi::c_void>();
        let convert = unsafe { ((*runtime).convert_pointer)(0, &mut converted) };
        // SAFETY: identity SVAM leaves the image-owned System Table mapped.
        let sealed_tables = unsafe {
            (*system).boot_services.is_null()
                && (*system).con_in.is_null()
                && (*system).con_out.is_null()
                && (*system).std_err.is_null()
                && (*system).hdr.crc32 != 0
                && (*runtime).hdr.crc32 != 0
        };
        if repeated != Status::UNSUPPORTED
            || convert != Status::SUCCESS
            || converted != runtime.cast()
            || !sealed_tables
            || !exercise_variables(runtime)
        {
            loop {
                core::hint::spin_loop();
            }
        }
        if !queue_runtime_writes(runtime) {
            loop {
                core::hint::spin_loop();
            }
        }
        serial("RUNTIME POST SVAM PASSED\r\n");
        serial("RUNTIME FIRST BOOT QUEUED\r\n");
        unsafe {
            ((*runtime).reset_system)(efi::RESET_WARM, Status::SUCCESS, 0, core::ptr::null_mut())
        };
        loop {
            core::hint::spin_loop();
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    Status::SUCCESS
}

#[cfg(target_arch = "x86_64")]
const DEFERRED_TEST_GUID: efi::Guid = efi::Guid::from_fields(
    0xa52c7c11,
    0x61f4,
    0x4eb7,
    0xa2,
    0x19,
    &[0x5a, 0x96, 0xb8, 0x0d, 0xa1, 0x02],
);
#[cfg(target_arch = "x86_64")]
const DEFERRED_ATTRIBUTES: u32 =
    efi::VARIABLE_NON_VOLATILE | efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS;
const CAPSULE_REPORT_GUID: efi::Guid = efi::Guid::from_fields(
    0x39b68c46,
    0xf7fb,
    0x441b,
    0xb6,
    0xec,
    &[0x16, 0xb0, 0xf6, 0x98, 0x21, 0xf3],
);
const ESRT_LAST_ATTEMPT_NAME: [u16; 23] = [
    b'C' as u16,
    b'r' as u16,
    b'a' as u16,
    b'b' as u16,
    b'E' as u16,
    b'f' as u16,
    b'i' as u16,
    b'E' as u16,
    b's' as u16,
    b'r' as u16,
    b't' as u16,
    b'L' as u16,
    b'a' as u16,
    b's' as u16,
    b't' as u16,
    b'A' as u16,
    b't' as u16,
    b't' as u16,
    b'e' as u16,
    b'm' as u16,
    b'p' as u16,
    b't' as u16,
    0,
];
#[cfg(target_arch = "x86_64")]
const REPLAY_MARKER_NAME: [u16; 15] = [
    b'R' as u16,
    b't' as u16,
    b'R' as u16,
    b'e' as u16,
    b'p' as u16,
    b'l' as u16,
    b'a' as u16,
    b'y' as u16,
    b'M' as u16,
    b'a' as u16,
    b'r' as u16,
    b'k' as u16,
    b'e' as u16,
    b'r' as u16,
    0,
];
#[cfg(target_arch = "x86_64")]
const DEFERRED_NAME: [u16; 11] = [
    b'R' as u16,
    b't' as u16,
    b'D' as u16,
    b'e' as u16,
    b'f' as u16,
    b'e' as u16,
    b'r' as u16,
    b'r' as u16,
    b'e' as u16,
    b'd' as u16,
    0,
];
#[cfg(target_arch = "x86_64")]
const CAPSULE_RESULT_NAME: [u16; 12] = [
    b'C' as u16,
    b'a' as u16,
    b'p' as u16,
    b's' as u16,
    b'u' as u16,
    b'l' as u16,
    b'e' as u16,
    b'0' as u16,
    b'0' as u16,
    b'0' as u16,
    b'1' as u16,
    0,
];

#[cfg(target_arch = "x86_64")]
#[repr(C, align(8))]
struct TestCapsule {
    header: efi::CapsuleHeader,
    payload: [u8; 4],
}

#[cfg(target_arch = "x86_64")]
static mut TEST_CAPSULE: TestCapsule = TestCapsule {
    header: efi::CapsuleHeader {
        capsule_guid: efi::Guid::from_fields(
            0x3b8c8162,
            0x188c,
            0x46a4,
            0xae,
            0xc9,
            &[0xbe, 0x43, 0xf1, 0xd6, 0x56, 0x97],
        ),
        header_size: core::mem::size_of::<efi::CapsuleHeader>() as u32,
        flags: 0x0001_0000,
        capsule_image_size: core::mem::size_of::<TestCapsule>() as u32,
    },
    payload: *b"TEST",
};

#[cfg(target_arch = "x86_64")]
static mut TEST_CAPSULE_SG: [u64; 4] = [0; 4];

#[cfg(target_arch = "x86_64")]
fn replay_marker_present(runtime: *mut efi::RuntimeServices) -> bool {
    let mut marker = [0u8; 1];
    get_exact_variable(runtime, REPLAY_MARKER_NAME, DEFERRED_TEST_GUID, &mut marker)
        && marker[0] == 1
}

#[cfg(target_arch = "x86_64")]
fn set_replay_marker(runtime: *mut efi::RuntimeServices) -> bool {
    let mut name = REPLAY_MARKER_NAME;
    let mut guid = DEFERRED_TEST_GUID;
    let mut marker = [1u8];
    unsafe {
        ((*runtime).set_variable)(
            name.as_mut_ptr(),
            &mut guid,
            DEFERRED_ATTRIBUTES,
            marker.len(),
            marker.as_mut_ptr().cast(),
        ) == Status::SUCCESS
    }
}

#[cfg(target_arch = "x86_64")]
fn queue_runtime_writes(runtime: *mut efi::RuntimeServices) -> bool {
    let mut name = DEFERRED_NAME;
    let mut guid = DEFERRED_TEST_GUID;
    let mut value = *b"CrabRT";
    let status = unsafe {
        ((*runtime).set_variable)(
            name.as_mut_ptr(),
            &mut guid,
            DEFERRED_ATTRIBUTES,
            value.len(),
            value.as_mut_ptr().cast(),
        )
    };
    if status != Status::SUCCESS {
        return false;
    }
    let mut output = [0u8; 6];
    if !get_exact_variable(runtime, DEFERRED_NAME, DEFERRED_TEST_GUID, &mut output) {
        serial("RUNTIME DEFERRED IMMEDIATE GET FAILED\r\n");
        return false;
    }
    if output != value {
        serial("RUNTIME DEFERRED IMMEDIATE DATA WRONG: ");
        serial_hex(&output);
        serial("\r\n");
        return false;
    }

    let capsule = core::ptr::addr_of_mut!(TEST_CAPSULE);
    let sg = core::ptr::addr_of_mut!(TEST_CAPSULE_SG).cast::<u64>();
    unsafe {
        sg.write(core::mem::size_of::<TestCapsule>() as u64);
        sg.add(1).write(capsule as u64);
        sg.add(2).write(0);
        sg.add(3).write(0);
    }
    let mut capsule_pointer = capsule.cast::<efi::CapsuleHeader>();
    unsafe { ((*runtime).update_capsule)(&mut capsule_pointer, 1, sg as u64) == Status::SUCCESS }
}

#[cfg(target_arch = "x86_64")]
fn replayed_runtime_writes(runtime: *mut efi::RuntimeServices) -> bool {
    let mut variable = [0u8; 8];
    let mut name = DEFERRED_NAME;
    let mut guid = DEFERRED_TEST_GUID;
    let mut attributes = 0u32;
    let mut size = variable.len();
    let status = unsafe {
        ((*runtime).get_variable)(
            name.as_mut_ptr(),
            &mut guid,
            &mut attributes,
            &mut size,
            variable.as_mut_ptr().cast(),
        )
    };
    if status != Status::SUCCESS
        || size != 6
        || attributes != DEFERRED_ATTRIBUTES
        || variable[..6] != *b"CrabRT"
    {
        if status == Status::NOT_FOUND {
            serial("RUNTIME DEFERRED VALUE NOT FOUND\r\n");
        } else if status == Status::BUFFER_TOO_SMALL {
            serial("RUNTIME DEFERRED VALUE TOO LARGE\r\n");
        } else if status != Status::SUCCESS {
            serial("RUNTIME DEFERRED GET FAILED\r\n");
        } else if size != 6 {
            serial("RUNTIME DEFERRED SIZE WRONG\r\n");
        } else if attributes != DEFERRED_ATTRIBUTES {
            serial("RUNTIME DEFERRED ATTRIBUTES WRONG\r\n");
        } else {
            serial("RUNTIME DEFERRED DATA WRONG: ");
            serial_hex(&variable[..6]);
            serial("\r\n");
        }
        return false;
    }
    let mut capsule_result = [0u8; 44];
    let present = get_exact_variable(
        runtime,
        CAPSULE_RESULT_NAME,
        CAPSULE_REPORT_GUID,
        &mut capsule_result,
    );
    if !present {
        serial("RUNTIME CAPSULE RESULT MISSING\r\n");
    } else if capsule_result[40..44] != 0u32.to_le_bytes() {
        serial("RUNTIME CAPSULE RESULT FAILED\r\n");
    }
    present && capsule_result[40..44] == 0u32.to_le_bytes()
}

#[cfg(target_arch = "x86_64")]
fn get_exact_variable<const N: usize>(
    runtime: *mut efi::RuntimeServices,
    mut name: [u16; N],
    mut guid: efi::Guid,
    output: &mut [u8],
) -> bool {
    let mut size = output.len();
    unsafe {
        ((*runtime).get_variable)(
            name.as_mut_ptr(),
            &mut guid,
            core::ptr::null_mut(),
            &mut size,
            output.as_mut_ptr().cast(),
        ) == Status::SUCCESS
            && size == output.len()
    }
}

#[cfg(target_arch = "x86_64")]
fn cleanup_replayed_runtime_writes(runtime: *mut efi::RuntimeServices) {
    delete_variable(runtime, REPLAY_MARKER_NAME, DEFERRED_TEST_GUID);
    delete_variable(runtime, DEFERRED_NAME, DEFERRED_TEST_GUID);
    delete_variable(runtime, CAPSULE_RESULT_NAME, CAPSULE_REPORT_GUID);
}

#[cfg(target_arch = "x86_64")]
fn delete_variable<const N: usize>(
    runtime: *mut efi::RuntimeServices,
    mut name: [u16; N],
    mut guid: efi::Guid,
) {
    unsafe {
        ((*runtime).set_variable)(name.as_mut_ptr(), &mut guid, 0, 0, core::ptr::null_mut());
    }
}

#[cfg(target_arch = "x86_64")]
fn qemu_debug_exit() -> ! {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0xf4u16,
            in("al") 0x10u8,
            options(nomem, nostack, preserves_flags)
        )
    };
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(target_arch = "x86_64")]
fn make_identity_virtual_map(
    map: *mut efi::MemoryDescriptor,
    stride: usize,
    count: usize,
) -> usize {
    let mut output_count = 0usize;
    for index in 0..count {
        // SAFETY: GetMemoryMap initialized count stride-sized records and
        // output_count never exceeds index, so overlapping compaction is valid.
        let source = unsafe { map.cast::<u8>().add(index * stride) };
        let mut descriptor = unsafe { (source as *const efi::MemoryDescriptor).read_unaligned() };
        if descriptor.attribute & efi::MEMORY_RUNTIME == 0 {
            continue;
        }
        descriptor.virtual_start = descriptor.physical_start;
        let destination = unsafe { map.cast::<u8>().add(output_count * stride) };
        unsafe {
            core::ptr::copy(source, destination, stride);
            (destination as *mut efi::MemoryDescriptor).write_unaligned(descriptor);
        }
        output_count += 1;
    }
    output_count * stride
}

fn runtime_properties_and_crcs_valid(
    system: *mut SystemTable,
    runtime: *mut efi::RuntimeServices,
) -> bool {
    let required = efi::RT_SUPPORTED_GET_VARIABLE
        | efi::RT_SUPPORTED_GET_NEXT_VARIABLE_NAME
        | efi::RT_SUPPORTED_SET_VARIABLE
        | efi::RT_SUPPORTED_SET_VIRTUAL_ADDRESS_MAP
        | efi::RT_SUPPORTED_CONVERT_POINTER
        | efi::RT_SUPPORTED_RESET_SYSTEM
        | efi::RT_SUPPORTED_UPDATE_CAPSULE
        | efi::RT_SUPPORTED_QUERY_CAPSULE_CAPABILITIES
        | efi::RT_SUPPORTED_QUERY_VARIABLE_INFO;
    let properties = unsafe {
        let system = &*system;
        (0..system.number_of_table_entries).find_map(|index| {
            let entry = &*system.configuration_table.add(index);
            (entry.vendor_guid.as_bytes() == efi::RT_PROPERTIES_TABLE_GUID.as_bytes())
                .then_some(entry.vendor_table.cast::<efi::RtPropertiesTable>())
        })
    };
    let Some(properties) = properties else {
        return false;
    };
    unsafe {
        (*properties).version == efi::RT_PROPERTIES_TABLE_VERSION
            && (*properties).length as usize == core::mem::size_of::<efi::RtPropertiesTable>()
            && (*properties).runtime_services_supported & required == required
            && table_crc_valid(system.cast::<efi::TableHeader>())
            && table_crc_valid(runtime.cast::<efi::TableHeader>())
    }
}

unsafe fn table_crc_valid(header: *const efi::TableHeader) -> bool {
    let size = unsafe { (*header).header_size as usize };
    if size < core::mem::size_of::<efi::TableHeader>() {
        return false;
    }
    let expected = unsafe { (*header).crc32 };
    let bytes = header.cast::<u8>();
    let mut crc = u32::MAX;
    for index in 0..size {
        let byte = if (16..20).contains(&index) {
            0
        } else {
            unsafe { bytes.add(index).read() }
        };
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc ^ u32::MAX == expected
}

fn in_runtime_descriptor(
    map: *const efi::MemoryDescriptor,
    stride: usize,
    count: usize,
    pointer: usize,
    memory_type: u32,
) -> bool {
    (0..count).any(|index| {
        // SAFETY: GetMemoryMap initialized count stride-sized records.
        let descriptor = unsafe {
            (map.cast::<u8>().add(index * stride) as *const efi::MemoryDescriptor).read_unaligned()
        };
        let end = descriptor
            .number_of_pages
            .checked_mul(4096)
            .and_then(|size| descriptor.physical_start.checked_add(size));
        descriptor.r#type == memory_type
            && descriptor.attribute & efi::MEMORY_RUNTIME != 0
            && (pointer as u64) >= descriptor.physical_start
            && end.is_some_and(|end| (pointer as u64) < end)
    })
}

fn exercise_variables(runtime: *mut efi::RuntimeServices) -> bool {
    let mut name = [
        b'R' as u16,
        b't' as u16,
        b'I' as u16,
        b's' as u16,
        b'o' as u16,
        0,
    ];
    let mut guid = efi::Guid::from_fields(
        0xa52c7c11,
        0x61f4,
        0x4eb7,
        0xa2,
        0x19,
        &[0x5a, 0x96, 0xb8, 0x0d, 0xa1, 0x01],
    );
    let mut first = [1u8, 2, 3];
    let mut second = [4u8, 5];
    // SAFETY: runtime is the validated table and all buffers live for each call.
    let set = unsafe {
        ((*runtime).set_variable)(
            name.as_mut_ptr(),
            &mut guid,
            efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS,
            first.len(),
            first.as_mut_ptr().cast(),
        )
    };
    if set != Status::SUCCESS {
        return false;
    }
    let append = unsafe {
        ((*runtime).set_variable)(
            name.as_mut_ptr(),
            &mut guid,
            efi::VARIABLE_BOOTSERVICE_ACCESS
                | efi::VARIABLE_RUNTIME_ACCESS
                | efi::VARIABLE_APPEND_WRITE,
            second.len(),
            second.as_mut_ptr().cast(),
        )
    };
    let mut output = [0u8; 8];
    let mut size = output.len();
    let get = unsafe {
        ((*runtime).get_variable)(
            name.as_mut_ptr(),
            &mut guid,
            core::ptr::null_mut(),
            &mut size,
            output.as_mut_ptr().cast(),
        )
    };
    let delete = unsafe {
        ((*runtime).set_variable)(name.as_mut_ptr(), &mut guid, 0, 0, core::ptr::null_mut())
    };
    append == Status::SUCCESS
        && get == Status::SUCCESS
        && size == 5
        && output[..5] == [1, 2, 3, 4, 5]
        && delete == Status::SUCCESS
        && secure_boot_policy_holds(runtime)
        && esrt_last_attempt_is_write_protected(runtime)
}

fn esrt_last_attempt_is_write_protected(runtime: *mut efi::RuntimeServices) -> bool {
    let mut name = ESRT_LAST_ATTEMPT_NAME;
    let mut guid = CAPSULE_REPORT_GUID;
    let mut forged = [0u8; 12];
    unsafe {
        ((*runtime).set_variable)(
            name.as_mut_ptr(),
            &mut guid,
            efi::VARIABLE_NON_VOLATILE
                | efi::VARIABLE_BOOTSERVICE_ACCESS
                | efi::VARIABLE_RUNTIME_ACCESS,
            forged.len(),
            forged.as_mut_ptr().cast(),
        ) == Status::WRITE_PROTECTED
    }
}

fn secure_boot_policy_holds(runtime: *mut efi::RuntimeServices) -> bool {
    let mut value = [1u8];
    let mut secure_boot = [
        b'S' as u16,
        b'e' as u16,
        b'c' as u16,
        b'u' as u16,
        b'r' as u16,
        b'e' as u16,
        b'B' as u16,
        b'o' as u16,
        b'o' as u16,
        b't' as u16,
        0,
    ];
    let mut global = efi::Guid::from_fields(
        0x8be4df61,
        0x93ca,
        0x11d2,
        0xaa,
        0x0d,
        &[0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
    );
    let status = unsafe {
        ((*runtime).set_variable)(
            secure_boot.as_mut_ptr(),
            &mut global,
            efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS,
            value.len(),
            value.as_mut_ptr().cast(),
        )
    };
    if status != Status::WRITE_PROTECTED {
        return false;
    }
    let mut db = [b'd' as u16, b'b' as u16, 0];
    let mut database = efi::Guid::from_fields(
        0xd719b2cb,
        0x3d3a,
        0x4596,
        0xa3,
        0xbc,
        &[0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
    );
    let status = unsafe {
        ((*runtime).set_variable)(
            db.as_mut_ptr(),
            &mut database,
            efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS,
            value.len(),
            value.as_mut_ptr().cast(),
        )
    };
    status == Status::SECURITY_VIOLATION
}

#[cfg(target_arch = "x86_64")]
fn serial_hex(bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        let output = [
            HEX[usize::from(byte >> 4)],
            HEX[usize::from(byte & 0xf)],
            b' ',
        ];
        for byte in output {
            unsafe {
                core::arch::asm!("out dx, al", in("dx") 0x3f8u16, in("al") byte, options(nomem, nostack, preserves_flags))
            };
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn serial(text: &str) {
    for byte in text.bytes() {
        // SAFETY: COM1 is the platform serial port in the x86 integration test.
        unsafe {
            core::arch::asm!("out dx, al", in("dx") 0x3f8u16, in("al") byte, options(nomem, nostack, preserves_flags))
        };
    }
}

fn print(system: *mut SystemTable, text: &str) {
    let mut output = [0u16; 96];
    let mut len = 0usize;
    for byte in text.bytes() {
        if len + 1 >= output.len() {
            break;
        }
        output[len] = u16::from(byte);
        len += 1;
    }
    output[len] = 0;
    // SAFETY: system/con_out are valid before EBS and output is NUL-terminated.
    unsafe {
        ((*(*system).con_out).output_string)((*system).con_out, output.as_mut_ptr() as *mut Char16)
    };
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
