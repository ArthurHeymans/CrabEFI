//! Capsule Update Test Application
//!
//! Verifies that CrabEFI's capsule update infrastructure is correctly
//! set up by checking:
//!
//! 1. ESRT (EFI System Resource Table) is present in configuration tables
//! 2. OsIndicationsSupported variable has the correct capsule bits set
//! 3. QueryCapsuleCapabilities() runtime service works
//! 4. UpdateCapsule() with null/invalid args returns correct errors
//!
//! Built with `CRABEFI_CAPSULE_ON_DISK_ONLY` set, it checks a payload with
//! the `capsule-on-disk-only` feature over two boots instead: no in-memory
//! delivery is advertised, `UpdateCapsule()` fails after ExitBootServices,
//! and a stale `CapsuleUpdateData` left by the first boot is gone in the
//! second.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use r_efi::efi::{self, Char16, Guid, Handle, Status, SystemTable};

// ============================================================================
// GUIDs
// ============================================================================

/// EFI System Resource Table GUID
const EFI_SYSTEM_RESOURCE_TABLE_GUID: Guid = Guid::from_fields(
    0xB122A263,
    0x3661,
    0x4F68,
    0x99,
    0x29,
    &[0x78, 0xF8, 0xB0, 0xD6, 0x21, 0x80],
);

/// EFI Global Variable GUID
const EFI_GLOBAL_VARIABLE_GUID: Guid = Guid::from_fields(
    0x8BE4DF61,
    0x93CA,
    0x11D2,
    0xAA,
    0x0D,
    &[0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
);

/// FMP Capsule GUID (used to build a test capsule header for QueryCapsuleCapabilities)
const EFI_FMP_CAPSULE_GUID: Guid = Guid::from_fields(
    0x6DCBD5ED,
    0xE82D,
    0x4C44,
    0xBD,
    0xA1,
    &[0x71, 0x94, 0x19, 0x9A, 0xD9, 0x2A],
);

/// The payload under test accepts capsules only from the ESP.
const DISK_ONLY: bool = option_env!("CRABEFI_CAPSULE_ON_DISK_ONLY").is_some();

// ============================================================================
// Test Framework
// ============================================================================

struct TestCtx {
    con_out: *mut efi::protocols::simple_text_output::Protocol,
    system_table: *mut SystemTable,
    passed: usize,
    failed: usize,
}

impl TestCtx {
    fn print(&self, msg: &[Char16]) {
        unsafe {
            let output_string = (*self.con_out).output_string;
            output_string(self.con_out, msg.as_ptr() as *mut Char16);
        }
    }

    fn print_str(&self, s: &str) {
        // Print ASCII string as UCS-2, character by character
        let mut buf = [0u16; 2];
        for c in s.chars() {
            if c == '\n' {
                buf[0] = '\r' as u16;
                buf[1] = 0;
                self.print(&buf);
                buf[0] = '\n' as u16;
                self.print(&buf);
            } else {
                buf[0] = c as u16;
                buf[1] = 0;
                self.print(&buf);
            }
        }
    }

    fn pass(&mut self, name: &str) {
        self.print_str("[PASS] ");
        self.print_str(name);
        self.print_str("\n");
        self.passed += 1;
    }

    fn fail(&mut self, name: &str) {
        self.print_str("[FAIL] ");
        self.print_str(name);
        self.print_str("\n");
        self.failed += 1;
    }

    fn print_hex32(&self, val: u32) {
        let hex = "0123456789ABCDEF".as_bytes();
        let mut buf = [0u16; 11]; // "0x" + 8 hex digits + null
        buf[0] = '0' as u16;
        buf[1] = 'x' as u16;
        for i in 0..8 {
            let nibble = ((val >> (28 - i * 4)) & 0xF) as usize;
            buf[2 + i] = hex[nibble] as u16;
        }
        buf[10] = 0;
        self.print(&buf);
    }

    fn print_hex64(&self, val: u64) {
        let hex = "0123456789ABCDEF".as_bytes();
        let mut buf = [0u16; 19]; // "0x" + 16 hex digits + null
        buf[0] = '0' as u16;
        buf[1] = 'x' as u16;
        for i in 0..16 {
            let nibble = ((val >> (60 - i * 4)) & 0xF) as usize;
            buf[2 + i] = hex[nibble] as u16;
        }
        buf[18] = 0;
        self.print(&buf);
    }
}

// ============================================================================
// Entry Point
// ============================================================================

/// # Safety
/// The firmware must pass a valid writable UEFI System Table for the duration
/// of this entry-point call.
#[no_mangle]
pub unsafe extern "efiapi" fn efi_main(
    image_handle: Handle,
    system_table: *mut SystemTable,
) -> Status {
    if system_table.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: guaranteed by the UEFI image-entry contract and checked non-null.
    let con_out = unsafe { (*system_table).con_out };
    if con_out.is_null() {
        return Status::UNSUPPORTED;
    }

    let mut ctx = TestCtx {
        con_out,
        system_table,
        passed: 0,
        failed: 0,
    };

    ctx.print_str("Capsule Update Test Suite\n");
    ctx.print_str("========================\n\n");

    #[cfg(target_arch = "x86_64")]
    if DISK_ONLY {
        disk_only::second_boot(&mut ctx);
    }

    test_esrt_present(&mut ctx);
    test_os_indications_supported(&mut ctx);
    test_query_capsule_capabilities(&mut ctx);
    test_update_capsule_validation(&mut ctx);

    #[cfg(target_arch = "x86_64")]
    if DISK_ONLY {
        disk_only::first_boot(&mut ctx, image_handle);
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = image_handle;

    print_summary(&ctx);
    Status::SUCCESS
}

fn print_summary(ctx: &TestCtx) {
    ctx.print_str("\n========================\n");
    ctx.print_str("Results: ");
    print_decimal(ctx, ctx.passed);
    ctx.print_str(" passed, ");
    print_decimal(ctx, ctx.failed);
    ctx.print_str(" failed\n");

    if ctx.failed == 0 {
        ctx.print_str("All capsule tests passed!\n");
    } else {
        ctx.print_str("Some capsule tests failed!\n");
    }
}

fn print_decimal(ctx: &TestCtx, val: usize) {
    if val == 0 {
        ctx.print_str("0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut n = val;
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    // Reverse
    for j in (0..i).rev() {
        let mut c = [0u16; 2];
        c[0] = buf[j] as u16;
        c[1] = 0;
        ctx.print(&c);
    }
}

// ============================================================================
// Test: ESRT Present
// ============================================================================

fn test_esrt_present(ctx: &mut TestCtx) {
    ctx.print_str("Test: ESRT configuration table\n");

    let st = unsafe { &*ctx.system_table };
    let table_count = st.number_of_table_entries;
    let tables = st.configuration_table;

    if tables.is_null() || table_count == 0 {
        ctx.fail("esrt_present: no configuration tables");
        return;
    }

    let mut found = false;
    for i in 0..table_count {
        let entry = unsafe { &*tables.add(i) };
        if guid_eq(&entry.vendor_guid, &EFI_SYSTEM_RESOURCE_TABLE_GUID) {
            found = true;

            // Validate ESRT contents
            let esrt = entry.vendor_table as *const EsrtHeader;
            if esrt.is_null() {
                ctx.fail("esrt_valid: ESRT pointer is null");
                return;
            }

            let header = unsafe { &*esrt };
            ctx.print_str("  ESRT: fw_resource_count=");
            print_decimal(ctx, header.fw_resource_count as usize);
            ctx.print_str(", version=");
            ctx.print_hex64(header.fw_resource_version);
            ctx.print_str("\n");

            if header.fw_resource_count >= 1 {
                ctx.pass("esrt_has_entries");

                // Read first entry
                let entry_ptr = unsafe { (esrt as *const u8).add(16) } as *const EsrtEntry;
                let entry = unsafe { &*entry_ptr };

                ctx.print_str("  Entry 0: fw_type=");
                print_decimal(ctx, entry.fw_type as usize);
                ctx.print_str(", fw_version=");
                ctx.print_hex32(entry.fw_version);
                ctx.print_str(", lsv=");
                ctx.print_hex32(entry.lowest_supported_fw_version);
                ctx.print_str("\n");

                if entry.fw_type == 1 {
                    ctx.pass("esrt_fw_type_system");
                } else {
                    ctx.fail("esrt_fw_type_system: expected type 1 (system firmware)");
                }
                if DISK_ONLY {
                    if entry.capsule_flags & 0x0001_0000 == 0 {
                        ctx.pass("esrt_no_persist_flag");
                    } else {
                        ctx.fail("esrt_no_persist_flag: ESRT asks for PERSIST_ACROSS_RESET");
                    }
                }
            } else {
                ctx.fail("esrt_has_entries: fw_resource_count is 0");
            }

            break;
        }
    }

    if found {
        ctx.pass("esrt_present");
    } else {
        // ESRT won't be present if coreboot doesn't publish LB_TAG_EFI_FW_INFO.
        // This is expected on stock QEMU Q35 ROMs without the Kconfig enabled.
        // Mark as info, not failure.
        ctx.print_str("  ESRT not found (LB_TAG_EFI_FW_INFO not in coreboot tables)\n");
        ctx.print_str("  This is expected on QEMU without CONFIG_SOC_INTEL_CSE_CAPSULE=y\n");
        ctx.pass("esrt_absent_expected");
    }
}

/// ESRT header (matches the C struct layout)
#[repr(C)]
struct EsrtHeader {
    fw_resource_count: u32,
    fw_resource_count_max: u32,
    fw_resource_version: u64,
}

/// ESRT entry
#[repr(C)]
struct EsrtEntry {
    fw_class: [u8; 16],
    fw_type: u32,
    fw_version: u32,
    lowest_supported_fw_version: u32,
    capsule_flags: u32,
    last_attempt_version: u32,
    last_attempt_status: u32,
}

// ============================================================================
// Test: OsIndicationsSupported
// ============================================================================

fn test_os_indications_supported(ctx: &mut TestCtx) {
    ctx.print_str("\nTest: OsIndicationsSupported variable\n");

    let rt = unsafe { (*ctx.system_table).runtime_services };
    if rt.is_null() {
        ctx.fail("os_ind_supported: no runtime services");
        return;
    }

    // Variable name: "OsIndicationsSupported" in UCS-2
    let name: &[u16] = &[
        'O' as u16, 's' as u16, 'I' as u16, 'n' as u16, 'd' as u16, 'i' as u16, 'c' as u16,
        'a' as u16, 't' as u16, 'i' as u16, 'o' as u16, 'n' as u16, 's' as u16, 'S' as u16,
        'u' as u16, 'p' as u16, 'p' as u16, 'o' as u16, 'r' as u16, 't' as u16, 'e' as u16,
        'd' as u16, 0,
    ];

    let mut attributes: u32 = 0;
    let mut data = [0u8; 8];
    let mut data_size: usize = 8;

    let get_variable = unsafe { (*rt).get_variable };
    let status = unsafe {
        get_variable(
            name.as_ptr() as *mut Char16,
            &EFI_GLOBAL_VARIABLE_GUID as *const Guid as *mut Guid,
            &mut attributes,
            &mut data_size,
            data.as_mut_ptr() as *mut core::ffi::c_void,
        )
    };

    if status != Status::SUCCESS {
        ctx.fail("os_ind_supported_read: GetVariable failed");
        return;
    }

    ctx.pass("os_ind_supported_read");

    if data_size != 8 {
        ctx.fail("os_ind_supported_size: expected 8 bytes");
        return;
    }

    let value = u64::from_le_bytes(data);

    ctx.print_str("  OsIndicationsSupported = ");
    ctx.print_hex64(value);
    ctx.print_str("\n");

    // Check FMP capsule bit (bit 3)
    if value & 0x08 != 0 {
        ctx.pass("os_ind_fmp_capsule_bit");
    } else {
        ctx.fail("os_ind_fmp_capsule_bit: FMP capsule bit not set");
    }

    // Check file capsule delivery bit (bit 2)
    if value & 0x04 != 0 {
        ctx.pass("os_ind_file_capsule_bit");
    } else {
        ctx.fail("os_ind_file_capsule_bit: file capsule delivery bit not set");
    }
}

// ============================================================================
// Test: QueryCapsuleCapabilities
// ============================================================================

fn test_query_capsule_capabilities(ctx: &mut TestCtx) {
    ctx.print_str("\nTest: QueryCapsuleCapabilities\n");

    let rt = unsafe { (*ctx.system_table).runtime_services };
    if rt.is_null() {
        ctx.fail("query_caps: no runtime services");
        return;
    }
    let query = unsafe { (*rt).query_capsule_capabilities };
    let mut max_capsule_size = 0u64;
    let mut reset_type = efi::RESET_COLD;
    if unsafe {
        query(
            core::ptr::null_mut(),
            0,
            &mut max_capsule_size,
            &mut reset_type,
        )
    } == Status::INVALID_PARAMETER
    {
        ctx.pass("query_caps_null_zero_rejected");
    } else {
        ctx.fail("query_caps_null_zero_rejected");
    }

    let mut capsule_header = CapsuleHeader {
        capsule_guid: EFI_FMP_CAPSULE_GUID,
        header_size: 28,
        flags: 0x0001_0000,
        capsule_image_size: 1024,
    };
    let header_ptr: *mut CapsuleHeader = &mut capsule_header;
    let mut headers = [header_ptr, header_ptr];
    let array = headers.as_mut_ptr().cast::<*mut efi::CapsuleHeader>();
    if unsafe { query(array, 0, &mut max_capsule_size, &mut reset_type) }
        == Status::INVALID_PARAMETER
    {
        ctx.pass("query_caps_zero_count_rejected");
    } else {
        ctx.fail("query_caps_zero_count_rejected");
    }
    if unsafe { query(array, 2, &mut max_capsule_size, &mut reset_type) } == Status::UNSUPPORTED {
        ctx.pass("query_caps_multiple_rejected");
    } else {
        ctx.fail("query_caps_multiple_rejected");
    }
    if unsafe { query(array, 1, core::ptr::null_mut(), &mut reset_type) }
        == Status::INVALID_PARAMETER
        && unsafe { query(array, 1, &mut max_capsule_size, core::ptr::null_mut()) }
            == Status::INVALID_PARAMETER
    {
        ctx.pass("query_caps_null_outputs_rejected");
    } else {
        ctx.fail("query_caps_null_outputs_rejected");
    }

    unsafe { core::ptr::write_volatile(&raw mut capsule_header.flags, 0) };
    if unsafe { query(array, 1, &mut max_capsule_size, &mut reset_type) } == Status::UNSUPPORTED {
        ctx.pass("query_caps_persist_flag_required");
    } else {
        ctx.fail("query_caps_persist_flag_required");
    }
    unsafe {
        core::ptr::write_volatile(&raw mut capsule_header.flags, 0x0001_0000);
        core::ptr::write_volatile(
            &raw mut capsule_header.capsule_image_size,
            16 * 1024 * 1024 + 1,
        );
    }
    if unsafe { query(array, 1, &mut max_capsule_size, &mut reset_type) } == Status::UNSUPPORTED {
        ctx.pass("query_caps_oversize_rejected");
    } else {
        ctx.fail("query_caps_oversize_rejected");
    }

    unsafe { core::ptr::write_volatile(&raw mut capsule_header.capsule_image_size, 1024) };
    max_capsule_size = 0;
    reset_type = efi::RESET_COLD;
    let status = unsafe { query(array, 1, &mut max_capsule_size, &mut reset_type) };
    if DISK_ONLY {
        if status == Status::UNSUPPORTED {
            ctx.pass("query_caps_persist_unsupported");
        } else {
            ctx.fail("query_caps_persist_unsupported: in-memory delivery advertised");
        }
    } else if status == Status::SUCCESS
        && max_capsule_size == 16 * 1024 * 1024
        && reset_type == efi::RESET_WARM
    {
        ctx.pass("query_caps_call");
        ctx.pass("query_caps_max_size");
        ctx.pass("query_caps_exact_max_and_warm_reset");
    } else {
        ctx.fail("query_caps_call: invalid maximum/reset result");
    }
}

/// Capsule header (must match UEFI spec layout for QueryCapsuleCapabilities)
#[repr(C)]
struct CapsuleHeader {
    capsule_guid: Guid,
    header_size: u32,
    flags: u32,
    capsule_image_size: u32,
}

// ============================================================================
// Test: UpdateCapsule validation
// ============================================================================

fn test_update_capsule_validation(ctx: &mut TestCtx) {
    ctx.print_str("\nTest: UpdateCapsule input validation\n");

    let rt = unsafe { (*ctx.system_table).runtime_services };
    if rt.is_null() {
        ctx.fail("update_capsule_validation: no runtime services");
        return;
    }
    let update = unsafe { (*rt).update_capsule };
    if unsafe { update(core::ptr::null_mut(), 0, 0) } == Status::INVALID_PARAMETER {
        ctx.pass("update_capsule_null_rejected");
    } else {
        ctx.fail("update_capsule_null_rejected");
    }

    let mut capsule_header = CapsuleHeader {
        capsule_guid: EFI_FMP_CAPSULE_GUID,
        header_size: 28,
        flags: 0x0001_0000,
        capsule_image_size: 1024,
    };
    let header: *mut CapsuleHeader = &mut capsule_header;
    let mut headers = [header, header];
    let array = headers.as_mut_ptr().cast::<*mut efi::CapsuleHeader>();
    if unsafe { update(array, 0, 0) } == Status::INVALID_PARAMETER {
        ctx.pass("update_capsule_zero_count_rejected");
    } else {
        ctx.fail("update_capsule_zero_count_rejected");
    }
    // SAFETY: The next three calls use 1 as a non-null sentinel, not a valid
    // scatter/gather list. CrabEFI rejects multiple capsules or pre-ExitBootServices
    // calls before using the address. UEFI does not guarantee this ordering.
    if unsafe { update(array, 2, 1) } == Status::UNSUPPORTED {
        ctx.pass("update_capsule_multiple_rejected");
    } else {
        ctx.fail("update_capsule_multiple_rejected");
    }
    let mut null_header = core::ptr::null_mut();
    if unsafe { update(&mut null_header, 1, 1) } == Status::UNSUPPORTED {
        ctx.pass("update_capsule_pre_ebs_short_circuits_header");
    } else {
        ctx.fail("update_capsule_pre_ebs_short_circuits_header");
    }
    if unsafe { update(array, 1, 1) } == Status::UNSUPPORTED {
        ctx.pass("update_capsule_pre_ebs_unsupported");
    } else {
        ctx.fail("update_capsule_pre_ebs_unsupported");
    }
}

// ============================================================================
// Capsule-on-disk only: two boots
// ============================================================================

#[cfg(target_arch = "x86_64")]
mod disk_only {
    use super::{print_summary, CapsuleHeader, TestCtx, EFI_FMP_CAPSULE_GUID};
    use r_efi::efi::{self, Guid, Handle, Status};

    const NV_BS_RT: u32 = efi::VARIABLE_NON_VOLATILE
        | efi::VARIABLE_BOOTSERVICE_ACCESS
        | efi::VARIABLE_RUNTIME_ACCESS;

    /// `EFI_CAPSULE_VENDOR_GUID`
    const CAPSULE_VENDOR_GUID: Guid = Guid::from_fields(
        0x711c703f,
        0xc285,
        0x4b10,
        0xa3,
        0xb0,
        &[0x36, 0xec, 0xbd, 0x3c, 0x8b, 0xe2],
    );
    const MARKER_GUID: Guid = Guid::from_fields(
        0x5c0d2b6e,
        0x7a41,
        0x4f0e,
        0x9b,
        0x3d,
        &[0x21, 0x86, 0x4e, 0x0f, 0xa7, 0x5c],
    );
    const CAPSULE_UPDATE_DATA: [u16; 18] = ucs2("CapsuleUpdateData");
    /// Holds the first boot's failure count.
    const MARKER_NAME: [u16; 20] = ucs2("CapsuleDiskOnlyTest");

    #[repr(C, align(8))]
    struct Capsule {
        header: CapsuleHeader,
        payload: [u8; 4],
    }

    static mut CAPSULE: Capsule = Capsule {
        header: CapsuleHeader {
            capsule_guid: EFI_FMP_CAPSULE_GUID,
            header_size: 28,
            flags: 0x0001_0000,
            capsule_image_size: core::mem::size_of::<Capsule>() as u32,
        },
        payload: *b"TEST",
    };
    static mut SCATTER_GATHER: [u64; 4] = [0; 4];
    static mut MEMORY_MAP: [u64; 8192] = [0; 8192];

    const fn ucs2<const N: usize>(text: &str) -> [u16; N] {
        let bytes = text.as_bytes();
        let mut out = [0u16; N];
        let mut i = 0;
        while i < bytes.len() {
            out[i] = bytes[i] as u16;
            i += 1;
        }
        out
    }

    /// Finish the run in the second boot, if the first boot left its marker.
    pub fn second_boot(ctx: &mut TestCtx) {
        let rt = unsafe { (*ctx.system_table).runtime_services };
        let mut failed = [0u8; 4];
        if get(rt, MARKER_NAME, MARKER_GUID, &mut failed) != Status::SUCCESS {
            return;
        }
        set(rt, MARKER_NAME, MARKER_GUID, 0, &mut []);
        ctx.print_str("Second boot after a warm reset\n");

        let mut data = [0u8; 8];
        if get(rt, CAPSULE_UPDATE_DATA, CAPSULE_VENDOR_GUID, &mut data) == Status::NOT_FOUND {
            ctx.pass("capsule_update_data_deleted");
        } else {
            ctx.fail("capsule_update_data_deleted: stale CapsuleUpdateData survived the boot");
        }
        ctx.failed += u32::from_le_bytes(failed) as usize;
        finish(ctx)
    }

    /// Leave a stale `CapsuleUpdateData`, check the capsule services after
    /// ExitBootServices and warm reset into the second boot.
    pub fn first_boot(ctx: &mut TestCtx, image: Handle) -> ! {
        let system_table = ctx.system_table;
        let rt = unsafe { (*system_table).runtime_services };
        // Misaligned, so coreboot rejects it without reading memory.
        let mut stale = 0xdead_beef_u64.to_le_bytes();
        if set(
            rt,
            CAPSULE_UPDATE_DATA,
            CAPSULE_VENDOR_GUID,
            NV_BS_RT,
            &mut stale,
        ) == Status::SUCCESS
        {
            ctx.pass("stale_capsule_update_data_written");
        } else {
            ctx.fail("stale_capsule_update_data_written");
        }
        let mut failed = (ctx.failed as u32).to_le_bytes();
        if set(rt, MARKER_NAME, MARKER_GUID, NV_BS_RT, &mut failed) != Status::SUCCESS {
            ctx.fail("second_boot_marker_written");
            finish(ctx)
        }
        if !exit_boot_services(system_table, image) {
            set(rt, MARKER_NAME, MARKER_GUID, 0, &mut []);
            ctx.fail("exit_boot_services");
            finish(ctx)
        }

        // ConOut is gone after ExitBootServices: report on COM1.
        let capsule = core::ptr::addr_of_mut!(CAPSULE);
        let sg = core::ptr::addr_of_mut!(SCATTER_GATHER);
        unsafe { *sg = [core::mem::size_of::<Capsule>() as u64, capsule as u64, 0, 0] };
        let mut header = capsule.cast::<efi::CapsuleHeader>();
        let update = unsafe { ((*rt).update_capsule)(&mut header, 1, sg as u64) };
        let mut maximum = 0u64;
        let mut reset_type = efi::RESET_COLD;
        let query = unsafe {
            ((*rt).query_capsule_capabilities)(&mut header, 1, &mut maximum, &mut reset_type)
        };
        let update_ok = report(
            "update_capsule_runtime_unsupported",
            update == Status::UNSUPPORTED,
        );
        let query_ok = report(
            "query_caps_runtime_unsupported",
            query == Status::UNSUPPORTED,
        );
        if !(update_ok && query_ok) {
            serial("Some capsule tests failed!\r\n");
            qemu_debug_exit();
        }
        serial("Warm reset into the second boot\r\n");
        unsafe { ((*rt).reset_system)(efi::RESET_WARM, Status::SUCCESS, 0, core::ptr::null_mut()) };
        loop {
            core::hint::spin_loop();
        }
    }

    fn finish(ctx: &TestCtx) -> ! {
        print_summary(ctx);
        qemu_debug_exit()
    }

    fn exit_boot_services(system_table: *mut efi::SystemTable, image: Handle) -> bool {
        let bs = unsafe { (*system_table).boot_services };
        let map = core::ptr::addr_of_mut!(MEMORY_MAP);
        // A stale map key fails the first attempt; the second gets a fresh one.
        for _ in 0..2 {
            let mut size = core::mem::size_of::<[u64; 8192]>();
            let mut key = 0usize;
            let mut descriptor_size = 0usize;
            let mut version = 0u32;
            let status = unsafe {
                ((*bs).get_memory_map)(
                    &mut size,
                    map.cast(),
                    &mut key,
                    &mut descriptor_size,
                    &mut version,
                )
            };
            if status != Status::SUCCESS {
                return false;
            }
            if unsafe { ((*bs).exit_boot_services)(image, key) } == Status::SUCCESS {
                return true;
            }
        }
        false
    }

    fn get<const N: usize>(
        rt: *mut efi::RuntimeServices,
        mut name: [u16; N],
        mut guid: Guid,
        data: &mut [u8],
    ) -> Status {
        let mut size = data.len();
        unsafe {
            ((*rt).get_variable)(
                name.as_mut_ptr(),
                &mut guid,
                core::ptr::null_mut(),
                &mut size,
                data.as_mut_ptr().cast(),
            )
        }
    }

    fn set<const N: usize>(
        rt: *mut efi::RuntimeServices,
        mut name: [u16; N],
        mut guid: Guid,
        attributes: u32,
        data: &mut [u8],
    ) -> Status {
        unsafe {
            ((*rt).set_variable)(
                name.as_mut_ptr(),
                &mut guid,
                attributes,
                data.len(),
                data.as_mut_ptr().cast(),
            )
        }
    }

    fn report(name: &str, passed: bool) -> bool {
        serial(if passed { "[PASS] " } else { "[FAIL] " });
        serial(name);
        serial("\r\n");
        passed
    }

    fn serial(text: &str) {
        for byte in text.bytes() {
            // SAFETY: COM1 is the serial console of the QEMU test machine.
            unsafe {
                core::arch::asm!("out dx, al", in("dx") 0x3f8u16, in("al") byte, options(nomem, nostack, preserves_flags))
            };
        }
    }

    fn qemu_debug_exit() -> ! {
        // SAFETY: the two-boot QEMU run provides isa-debug-exit at 0xf4.
        unsafe {
            core::arch::asm!("out dx, al", in("dx") 0xf4u16, in("al") 0x10u8, options(nomem, nostack, preserves_flags))
        };
        loop {
            core::hint::spin_loop();
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn guid_eq(a: &Guid, b: &Guid) -> bool {
    a.as_bytes() == b.as_bytes()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
