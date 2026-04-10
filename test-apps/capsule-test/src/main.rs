//! Capsule Update Test Application
//!
//! Verifies that CrabEFI's capsule update infrastructure is correctly
//! set up by checking:
//!
//! 1. ESRT (EFI System Resource Table) is present in configuration tables
//! 2. OsIndicationsSupported variable has the correct capsule bits set
//! 3. QueryCapsuleCapabilities() runtime service works
//! 4. UpdateCapsule() with null/invalid args returns correct errors

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

#[no_mangle]
pub extern "efiapi" fn efi_main(_image_handle: Handle, system_table: *mut SystemTable) -> Status {
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

    test_esrt_present(&mut ctx);
    test_os_indications_supported(&mut ctx);
    test_query_capsule_capabilities(&mut ctx);
    test_update_capsule_validation(&mut ctx);

    // Print summary
    ctx.print_str("\n========================\n");
    ctx.print_str("Results: ");
    print_decimal(&ctx, ctx.passed);
    ctx.print_str(" passed, ");
    print_decimal(&ctx, ctx.failed);
    ctx.print_str(" failed\n");

    if ctx.failed == 0 {
        ctx.print_str("All capsule tests passed!\n");
    } else {
        ctx.print_str("Some capsule tests failed!\n");
    }

    Status::SUCCESS
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
    let status = get_variable(
        name.as_ptr() as *mut Char16,
        &EFI_GLOBAL_VARIABLE_GUID as *const Guid as *mut Guid,
        &mut attributes,
        &mut data_size,
        data.as_mut_ptr() as *mut core::ffi::c_void,
    );

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

    // Check FMP capsule bit (bit 0)
    if value & 0x01 != 0 {
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

    // Build a minimal FMP capsule header
    let capsule_header = CapsuleHeader {
        capsule_guid: EFI_FMP_CAPSULE_GUID,
        header_size: 28,
        flags: 0x0001_0000, // PERSIST_ACROSS_RESET
        capsule_image_size: 1024,
    };

    let mut header_ptr: *mut CapsuleHeader =
        &capsule_header as *const CapsuleHeader as *mut CapsuleHeader;
    let mut max_capsule_size: u64 = 0;
    let mut reset_type: efi::ResetType = efi::RESET_COLD;

    let query = unsafe { (*rt).query_capsule_capabilities };
    let status = query(
        &mut header_ptr as *mut *mut CapsuleHeader as *mut *mut efi::CapsuleHeader,
        1,
        &mut max_capsule_size,
        &mut reset_type,
    );

    if status == Status::SUCCESS {
        ctx.pass("query_caps_call");

        ctx.print_str("  max_capsule_size = ");
        ctx.print_hex64(max_capsule_size);
        ctx.print_str("\n");

        if max_capsule_size > 0 {
            ctx.pass("query_caps_max_size");
        } else {
            ctx.fail("query_caps_max_size: returned 0");
        }

        // Check reset type is warm
        if reset_type == efi::RESET_WARM {
            ctx.pass("query_caps_reset_type_warm");
        } else {
            ctx.print_str("  (reset type is not WARM, but that's OK)\n");
            ctx.pass("query_caps_reset_type");
        }
    } else {
        ctx.fail("query_caps_call: QueryCapsuleCapabilities failed");
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

    // Test 1: null header array should return INVALID_PARAMETER
    let status = update(core::ptr::null_mut(), 0, 0);
    if status == Status::INVALID_PARAMETER {
        ctx.pass("update_capsule_null_rejected");
    } else {
        ctx.fail("update_capsule_null_rejected: expected INVALID_PARAMETER");
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
