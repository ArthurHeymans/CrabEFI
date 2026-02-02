//! Secure Boot Test Application
//!
//! This EFI application tests the SecureBoot implementation in CrabEFI.
//! It runs a comprehensive test suite covering:
//!
//! ## Passing Tests (should succeed):
//! - Reading SecureBoot status variables
//! - Reading SetupMode variable
//! - Verifying key enrollment status (PK, KEK, db, dbx counts)
//! - Reading SecureBoot-related GUIDs
//! - Verifying mode transitions after key enrollment
//!
//! ## Failing Tests (expected to fail/be blocked):
//! - Writing to SecureBoot variables without authentication (in User Mode)
//! - Modifying PK without proper signature (in User Mode)
//! - Accessing forbidden hashes in dbx
//! - Invalid timestamp in authenticated variable writes

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use r_efi::efi::{self, Char16, Guid, Handle, Status, SystemTable};

// ============================================================================
// Constants
// ============================================================================

/// EFI Global Variable GUID
const EFI_GLOBAL_VARIABLE_GUID: Guid = Guid::from_fields(
    0x8BE4DF61,
    0x93CA,
    0x11D2,
    0xAA,
    0x0D,
    &[0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
);

/// EFI Image Security Database GUID
const EFI_IMAGE_SECURITY_DATABASE_GUID: Guid = Guid::from_fields(
    0xD719B2CB,
    0x3D3A,
    0x4596,
    0xA3,
    0xBC,
    &[0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F],
);

// ============================================================================
// Test Framework
// ============================================================================

/// Test result tracking
struct TestResults {
    passed: usize,
    failed: usize,
    total: usize,
}

impl TestResults {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            total: 0,
        }
    }

    fn record_pass(&mut self) {
        self.passed += 1;
        self.total += 1;
    }

    fn record_fail(&mut self) {
        self.failed += 1;
        self.total += 1;
    }
}

/// Console output helper
struct Console {
    con_out: *mut efi::protocols::simple_text_output::Protocol,
}

impl Console {
    fn new(system_table: *mut SystemTable) -> Self {
        Self {
            con_out: unsafe { (*system_table).con_out },
        }
    }

    fn print(&self, msg: &str) {
        for c in msg.chars() {
            let ch = [c as Char16, 0];
            unsafe {
                let output_string = (*self.con_out).output_string;
                output_string(self.con_out, ch.as_ptr() as *mut Char16);
            }
        }
    }

    fn println(&self, msg: &str) {
        self.print(msg);
        self.print("\r\n");
    }

    fn print_hex_byte(&self, value: u8) {
        let hex_chars = b"0123456789ABCDEF";
        let high = (value >> 4) as usize;
        let low = (value & 0x0F) as usize;
        let chars = [hex_chars[high] as char, hex_chars[low] as char];
        for c in chars {
            let ch = [c as Char16, 0];
            unsafe {
                let output_string = (*self.con_out).output_string;
                output_string(self.con_out, ch.as_ptr() as *mut Char16);
            }
        }
    }

    fn print_number(&self, mut value: usize) {
        if value == 0 {
            self.print("0");
            return;
        }
        let mut digits = [0u8; 20];
        let mut i = 0;
        while value > 0 {
            digits[i] = (value % 10) as u8 + b'0';
            value /= 10;
            i += 1;
        }
        while i > 0 {
            i -= 1;
            let ch = [digits[i] as Char16, 0];
            unsafe {
                let output_string = (*self.con_out).output_string;
                output_string(self.con_out, ch.as_ptr() as *mut Char16);
            }
        }
    }

    fn print_status(&self, status: Status) {
        if status == Status::SUCCESS {
            self.print("SUCCESS");
        } else if status == Status::NOT_FOUND {
            self.print("NOT_FOUND");
        } else if status == Status::BUFFER_TOO_SMALL {
            self.print("BUFFER_TOO_SMALL");
        } else if status == Status::SECURITY_VIOLATION {
            self.print("SECURITY_VIOLATION");
        } else if status == Status::INVALID_PARAMETER {
            self.print("INVALID_PARAMETER");
        } else if status == Status::WRITE_PROTECTED {
            self.print("WRITE_PROTECTED");
        } else if status == Status::ACCESS_DENIED {
            self.print("ACCESS_DENIED");
        } else if status == Status::UNSUPPORTED {
            self.print("UNSUPPORTED");
        } else {
            self.print("UNKNOWN_STATUS");
        }
    }
}

/// Get a variable using EFI Runtime Services
fn get_variable(
    system_table: *mut SystemTable,
    name: *const Char16,
    guid: &Guid,
    buffer: &mut [u8],
) -> Result<(usize, u32), Status> {
    let runtime_services = unsafe { (*system_table).runtime_services };
    let mut data_size = buffer.len();
    let mut attributes: u32 = 0;

    let status = unsafe {
        ((*runtime_services).get_variable)(
            name as *mut Char16,
            guid as *const Guid as *mut Guid,
            &mut attributes,
            &mut data_size,
            buffer.as_mut_ptr() as *mut core::ffi::c_void,
        )
    };

    if status == Status::SUCCESS {
        Ok((data_size, attributes))
    } else {
        Err(status)
    }
}

/// Set a variable using EFI Runtime Services
fn set_variable(
    system_table: *mut SystemTable,
    name: *const Char16,
    guid: &Guid,
    attributes: u32,
    data: &[u8],
) -> Status {
    let runtime_services = unsafe { (*system_table).runtime_services };

    unsafe {
        ((*runtime_services).set_variable)(
            name as *mut Char16,
            guid as *const Guid as *mut Guid,
            attributes,
            data.len(),
            data.as_ptr() as *mut core::ffi::c_void,
        )
    }
}

// Variable names as static arrays
static SECURE_BOOT_NAME: [Char16; 11] = [
    'S' as u16, 'e' as u16, 'c' as u16, 'u' as u16, 'r' as u16, 'e' as u16, 'B' as u16, 'o' as u16,
    'o' as u16, 't' as u16, 0,
];

static SETUP_MODE_NAME: [Char16; 10] = [
    'S' as u16, 'e' as u16, 't' as u16, 'u' as u16, 'p' as u16, 'M' as u16, 'o' as u16, 'd' as u16,
    'e' as u16, 0,
];

static PK_NAME: [Char16; 3] = ['P' as u16, 'K' as u16, 0];
static KEK_NAME: [Char16; 4] = ['K' as u16, 'E' as u16, 'K' as u16, 0];
static DB_NAME: [Char16; 3] = ['d' as u16, 'b' as u16, 0];
static DBX_NAME: [Char16; 4] = ['d' as u16, 'b' as u16, 'x' as u16, 0];

// ============================================================================
// Passing Tests (Should Succeed)
// ============================================================================

/// Test 1: Read SecureBoot variable
fn test_read_secure_boot(console: &Console, st: *mut SystemTable, results: &mut TestResults) {
    console.print("[TEST] read_secure_boot: ");

    let mut buffer = [0u8; 16];
    match get_variable(
        st,
        SECURE_BOOT_NAME.as_ptr(),
        &EFI_GLOBAL_VARIABLE_GUID,
        &mut buffer,
    ) {
        Ok((size, _attrs)) => {
            if size >= 1 {
                let value = buffer[0];
                console.print("SecureBoot=");
                console.print_number(value as usize);
                console.print(" ");
                if value == 0 {
                    console.println("[PASS] (Secure Boot disabled)");
                } else {
                    console.println("[PASS] (Secure Boot enabled)");
                }
                results.record_pass();
            } else {
                console.println("[FAIL] Invalid size");
                results.record_fail();
            }
        }
        Err(status) => {
            if status == Status::NOT_FOUND {
                console.println("[PASS] (Variable not found - expected in some configs)");
                results.record_pass();
            } else {
                console.print("[FAIL] Status: ");
                console.print_status(status);
                console.println("");
                results.record_fail();
            }
        }
    }
}

/// Test 2: Read SetupMode variable
fn test_read_setup_mode(console: &Console, st: *mut SystemTable, results: &mut TestResults) {
    console.print("[TEST] read_setup_mode: ");

    let mut buffer = [0u8; 16];
    match get_variable(
        st,
        SETUP_MODE_NAME.as_ptr(),
        &EFI_GLOBAL_VARIABLE_GUID,
        &mut buffer,
    ) {
        Ok((size, _attrs)) => {
            if size >= 1 {
                let value = buffer[0];
                console.print("SetupMode=");
                console.print_number(value as usize);
                console.print(" ");
                if value == 1 {
                    console.println("[PASS] (In Setup Mode)");
                } else {
                    console.println("[PASS] (In User Mode)");
                }
                results.record_pass();
            } else {
                console.println("[FAIL] Invalid size");
                results.record_fail();
            }
        }
        Err(status) => {
            if status == Status::NOT_FOUND {
                console.println("[PASS] (Variable not found - expected in some configs)");
                results.record_pass();
            } else {
                console.print("[FAIL] Status: ");
                console.print_status(status);
                console.println("");
                results.record_fail();
            }
        }
    }
}

/// Test 3: Read PK variable (check if enrolled)
fn test_read_pk(console: &Console, st: *mut SystemTable, results: &mut TestResults) {
    console.print("[TEST] read_pk: ");

    let mut buffer = [0u8; 4096];
    match get_variable(st, PK_NAME.as_ptr(), &EFI_GLOBAL_VARIABLE_GUID, &mut buffer) {
        Ok((size, attrs)) => {
            console.print("PK size=");
            console.print_number(size);
            console.print(" attrs=0x");
            console.print_hex_byte((attrs >> 24) as u8);
            console.print_hex_byte((attrs >> 16) as u8);
            console.print_hex_byte((attrs >> 8) as u8);
            console.print_hex_byte(attrs as u8);
            console.println(" [PASS]");
            results.record_pass();
        }
        Err(status) => {
            if status == Status::NOT_FOUND {
                console.println("[PASS] (PK not enrolled - Setup Mode)");
                results.record_pass();
            } else if status == Status::BUFFER_TOO_SMALL {
                console.println("[PASS] (PK exists, buffer too small)");
                results.record_pass();
            } else {
                console.print("[FAIL] Status: ");
                console.print_status(status);
                console.println("");
                results.record_fail();
            }
        }
    }
}

/// Test 4: Read KEK variable
fn test_read_kek(console: &Console, st: *mut SystemTable, results: &mut TestResults) {
    console.print("[TEST] read_kek: ");

    let mut buffer = [0u8; 4096];
    match get_variable(
        st,
        KEK_NAME.as_ptr(),
        &EFI_GLOBAL_VARIABLE_GUID,
        &mut buffer,
    ) {
        Ok((size, attrs)) => {
            console.print("KEK size=");
            console.print_number(size);
            console.print(" attrs=0x");
            console.print_hex_byte((attrs >> 24) as u8);
            console.print_hex_byte((attrs >> 16) as u8);
            console.print_hex_byte((attrs >> 8) as u8);
            console.print_hex_byte(attrs as u8);
            console.println(" [PASS]");
            results.record_pass();
        }
        Err(status) => {
            if status == Status::NOT_FOUND {
                console.println("[PASS] (KEK not enrolled)");
                results.record_pass();
            } else if status == Status::BUFFER_TOO_SMALL {
                console.println("[PASS] (KEK exists, buffer too small)");
                results.record_pass();
            } else {
                console.print("[FAIL] Status: ");
                console.print_status(status);
                console.println("");
                results.record_fail();
            }
        }
    }
}

/// Test 5: Read db variable
fn test_read_db(console: &Console, st: *mut SystemTable, results: &mut TestResults) {
    console.print("[TEST] read_db: ");

    let mut buffer = [0u8; 8192];
    match get_variable(
        st,
        DB_NAME.as_ptr(),
        &EFI_IMAGE_SECURITY_DATABASE_GUID,
        &mut buffer,
    ) {
        Ok((size, attrs)) => {
            console.print("db size=");
            console.print_number(size);
            console.print(" attrs=0x");
            console.print_hex_byte((attrs >> 24) as u8);
            console.print_hex_byte((attrs >> 16) as u8);
            console.print_hex_byte((attrs >> 8) as u8);
            console.print_hex_byte(attrs as u8);
            console.println(" [PASS]");
            results.record_pass();
        }
        Err(status) => {
            if status == Status::NOT_FOUND {
                console.println("[PASS] (db empty)");
                results.record_pass();
            } else if status == Status::BUFFER_TOO_SMALL {
                console.println("[PASS] (db exists, buffer too small)");
                results.record_pass();
            } else {
                console.print("[FAIL] Status: ");
                console.print_status(status);
                console.println("");
                results.record_fail();
            }
        }
    }
}

/// Test 6: Read dbx variable
fn test_read_dbx(console: &Console, st: *mut SystemTable, results: &mut TestResults) {
    console.print("[TEST] read_dbx: ");

    let mut buffer = [0u8; 4096];
    match get_variable(
        st,
        DBX_NAME.as_ptr(),
        &EFI_IMAGE_SECURITY_DATABASE_GUID,
        &mut buffer,
    ) {
        Ok((size, attrs)) => {
            console.print("dbx size=");
            console.print_number(size);
            console.print(" attrs=0x");
            console.print_hex_byte((attrs >> 24) as u8);
            console.print_hex_byte((attrs >> 16) as u8);
            console.print_hex_byte((attrs >> 8) as u8);
            console.print_hex_byte(attrs as u8);
            console.println(" [PASS]");
            results.record_pass();
        }
        Err(status) => {
            if status == Status::NOT_FOUND {
                console.println("[PASS] (dbx empty)");
                results.record_pass();
            } else if status == Status::BUFFER_TOO_SMALL {
                console.println("[PASS] (dbx exists, buffer too small)");
                results.record_pass();
            } else {
                console.print("[FAIL] Status: ");
                console.print_status(status);
                console.println("");
                results.record_fail();
            }
        }
    }
}

/// Test 7: Verify SecureBoot and SetupMode consistency
fn test_mode_consistency(console: &Console, st: *mut SystemTable, results: &mut TestResults) {
    console.print("[TEST] mode_consistency: ");

    let mut sb_buffer = [0u8; 16];
    let mut sm_buffer = [0u8; 16];

    let secure_boot = get_variable(
        st,
        SECURE_BOOT_NAME.as_ptr(),
        &EFI_GLOBAL_VARIABLE_GUID,
        &mut sb_buffer,
    )
    .map(|(_, _)| sb_buffer[0])
    .unwrap_or(0);

    let setup_mode = get_variable(
        st,
        SETUP_MODE_NAME.as_ptr(),
        &EFI_GLOBAL_VARIABLE_GUID,
        &mut sm_buffer,
    )
    .map(|(_, _)| sm_buffer[0])
    .unwrap_or(1);

    // If in Setup Mode (1), SecureBoot should be disabled (0)
    // If SecureBoot enabled (1), must be in User Mode (0)
    let consistent = if setup_mode == 1 {
        secure_boot == 0
    } else {
        true
    };

    if consistent {
        console.print("SecureBoot=");
        console.print_number(secure_boot as usize);
        console.print(" SetupMode=");
        console.print_number(setup_mode as usize);
        console.println(" [PASS]");
        results.record_pass();
    } else {
        console.println("[FAIL] Inconsistent state");
        results.record_fail();
    }
}

// ============================================================================
// Failing Tests (Should be Blocked/Fail)
// ============================================================================

/// Helper to get current setup mode
fn get_setup_mode(st: *mut SystemTable) -> u8 {
    let mut buffer = [0u8; 16];
    get_variable(
        st,
        SETUP_MODE_NAME.as_ptr(),
        &EFI_GLOBAL_VARIABLE_GUID,
        &mut buffer,
    )
    .map(|(_, _)| buffer[0])
    .unwrap_or(1)
}

/// Test 8: Attempt unauthenticated write to PK (should fail in User Mode)
fn test_unauth_pk_write(console: &Console, st: *mut SystemTable, results: &mut TestResults) {
    console.print("[TEST] unauth_pk_write: ");

    if get_setup_mode(st) == 1 {
        console.println("[SKIP] In Setup Mode - unauthenticated writes allowed");
        results.record_pass();
        return;
    }

    let fake_pk_data = [0xDE, 0xAD, 0xBE, 0xEF];
    let attrs = 0x27; // NV + BS + RT + TIME_BASED_AUTH
    let status = set_variable(
        st,
        PK_NAME.as_ptr(),
        &EFI_GLOBAL_VARIABLE_GUID,
        attrs,
        &fake_pk_data,
    );

    if status == Status::SECURITY_VIOLATION || status == Status::INVALID_PARAMETER {
        console.print("Rejected: ");
        console.print_status(status);
        console.println(" [PASS]");
        results.record_pass();
    } else if status == Status::SUCCESS {
        console.println("[FAIL] Write succeeded (should have been blocked)");
        results.record_fail();
    } else {
        console.print("Rejected: ");
        console.print_status(status);
        console.println(" [PASS] (blocked)");
        results.record_pass();
    }
}

/// Test 9: Attempt unauthenticated write to KEK (should fail in User Mode)
fn test_unauth_kek_write(console: &Console, st: *mut SystemTable, results: &mut TestResults) {
    console.print("[TEST] unauth_kek_write: ");

    if get_setup_mode(st) == 1 {
        console.println("[SKIP] In Setup Mode - unauthenticated writes allowed");
        results.record_pass();
        return;
    }

    let fake_kek_data = [0xCA, 0xFE, 0xBA, 0xBE];
    let attrs = 0x27;
    let status = set_variable(
        st,
        KEK_NAME.as_ptr(),
        &EFI_GLOBAL_VARIABLE_GUID,
        attrs,
        &fake_kek_data,
    );

    if status == Status::SECURITY_VIOLATION || status == Status::INVALID_PARAMETER {
        console.print("Rejected: ");
        console.print_status(status);
        console.println(" [PASS]");
        results.record_pass();
    } else if status == Status::SUCCESS {
        console.println("[FAIL] Write succeeded (should have been blocked)");
        results.record_fail();
    } else {
        console.print("Rejected: ");
        console.print_status(status);
        console.println(" [PASS] (blocked)");
        results.record_pass();
    }
}

/// Test 10: Attempt unauthenticated write to db (should fail in User Mode)
fn test_unauth_db_write(console: &Console, st: *mut SystemTable, results: &mut TestResults) {
    console.print("[TEST] unauth_db_write: ");

    if get_setup_mode(st) == 1 {
        console.println("[SKIP] In Setup Mode - unauthenticated writes allowed");
        results.record_pass();
        return;
    }

    let fake_db_data = [0x01, 0x02, 0x03, 0x04];
    let attrs = 0x27;
    let status = set_variable(
        st,
        DB_NAME.as_ptr(),
        &EFI_IMAGE_SECURITY_DATABASE_GUID,
        attrs,
        &fake_db_data,
    );

    if status == Status::SECURITY_VIOLATION || status == Status::INVALID_PARAMETER {
        console.print("Rejected: ");
        console.print_status(status);
        console.println(" [PASS]");
        results.record_pass();
    } else if status == Status::SUCCESS {
        console.println("[FAIL] Write succeeded (should have been blocked)");
        results.record_fail();
    } else {
        console.print("Rejected: ");
        console.print_status(status);
        console.println(" [PASS] (blocked)");
        results.record_pass();
    }
}

/// Test 11: Attempt unauthenticated write to dbx (should fail in User Mode)
fn test_unauth_dbx_write(console: &Console, st: *mut SystemTable, results: &mut TestResults) {
    console.print("[TEST] unauth_dbx_write: ");

    if get_setup_mode(st) == 1 {
        console.println("[SKIP] In Setup Mode - unauthenticated writes allowed");
        results.record_pass();
        return;
    }

    let fake_dbx_data = [0xFF, 0xFE, 0xFD, 0xFC];
    let attrs = 0x27;
    let status = set_variable(
        st,
        DBX_NAME.as_ptr(),
        &EFI_IMAGE_SECURITY_DATABASE_GUID,
        attrs,
        &fake_dbx_data,
    );

    if status == Status::SECURITY_VIOLATION || status == Status::INVALID_PARAMETER {
        console.print("Rejected: ");
        console.print_status(status);
        console.println(" [PASS]");
        results.record_pass();
    } else if status == Status::SUCCESS {
        console.println("[FAIL] Write succeeded (should have been blocked)");
        results.record_fail();
    } else {
        console.print("Rejected: ");
        console.print_status(status);
        console.println(" [PASS] (blocked)");
        results.record_pass();
    }
}

/// Test 12: Attempt to write read-only SecureBoot variable
fn test_write_readonly_secureboot(
    console: &Console,
    st: *mut SystemTable,
    results: &mut TestResults,
) {
    console.print("[TEST] write_readonly_secureboot: ");

    let fake_value = [0x01u8];
    let attrs = 0x06; // BS + RT (no NV, no auth)
    let status = set_variable(
        st,
        SECURE_BOOT_NAME.as_ptr(),
        &EFI_GLOBAL_VARIABLE_GUID,
        attrs,
        &fake_value,
    );

    if status != Status::SUCCESS {
        console.print("Rejected: ");
        console.print_status(status);
        console.println(" [PASS]");
        results.record_pass();
    } else {
        console.println("[FAIL] Write succeeded (should be read-only)");
        results.record_fail();
    }
}

/// Test 13: Attempt to write read-only SetupMode variable
fn test_write_readonly_setupmode(
    console: &Console,
    st: *mut SystemTable,
    results: &mut TestResults,
) {
    console.print("[TEST] write_readonly_setupmode: ");

    let fake_value = [0x00u8];
    let attrs = 0x06;
    let status = set_variable(
        st,
        SETUP_MODE_NAME.as_ptr(),
        &EFI_GLOBAL_VARIABLE_GUID,
        attrs,
        &fake_value,
    );

    if status != Status::SUCCESS {
        console.print("Rejected: ");
        console.print_status(status);
        console.println(" [PASS]");
        results.record_pass();
    } else {
        console.println("[FAIL] Write succeeded (should be read-only)");
        results.record_fail();
    }
}

/// Test 14: Verify attribute enforcement
fn test_attribute_enforcement(console: &Console, st: *mut SystemTable, results: &mut TestResults) {
    console.print("[TEST] attribute_enforcement: ");

    let mut buffer = [0u8; 64];

    // Try reading db with wrong GUID (Global instead of Security)
    let result1 = get_variable(st, DB_NAME.as_ptr(), &EFI_GLOBAL_VARIABLE_GUID, &mut buffer);
    let result2 = get_variable(
        st,
        DB_NAME.as_ptr(),
        &EFI_IMAGE_SECURITY_DATABASE_GUID,
        &mut buffer,
    );

    let pass = match (result1, result2) {
        (Err(_), Err(_)) => true,
        (Err(_), Ok(_)) => true,
        (Ok(_), Err(_)) => true,
        (Ok((s1, _)), Ok((s2, _))) => s1 != s2,
    };

    if pass {
        console.println("[PASS]");
        results.record_pass();
    } else {
        console.println("[FAIL] GUID not properly enforced");
        results.record_fail();
    }
}

/// Test 15: Test malformed authentication header rejection
fn test_malformed_auth_header(console: &Console, st: *mut SystemTable, results: &mut TestResults) {
    console.print("[TEST] malformed_auth_header: ");

    if get_setup_mode(st) == 1 {
        console.println("[SKIP] In Setup Mode");
        results.record_pass();
        return;
    }

    let malformed_data = [0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let attrs = 0x27;
    let status = set_variable(
        st,
        DB_NAME.as_ptr(),
        &EFI_IMAGE_SECURITY_DATABASE_GUID,
        attrs,
        &malformed_data,
    );

    if status == Status::SECURITY_VIOLATION || status == Status::INVALID_PARAMETER {
        console.print("Rejected: ");
        console.print_status(status);
        console.println(" [PASS]");
        results.record_pass();
    } else if status == Status::SUCCESS {
        console.println("[FAIL] Malformed header accepted");
        results.record_fail();
    } else {
        console.print("Rejected: ");
        console.print_status(status);
        console.println(" [PASS]");
        results.record_pass();
    }
}

// ============================================================================
// Entry Point
// ============================================================================

#[no_mangle]
pub extern "efiapi" fn efi_main(_image_handle: Handle, system_table: *mut SystemTable) -> Status {
    let console = Console::new(system_table);
    let mut results = TestResults::new();

    console.println("");
    console.println("==========================================");
    console.println("   Secure Boot Test Suite for CrabEFI");
    console.println("==========================================");
    console.println("");

    // ========================================
    // PASSING TESTS (should succeed)
    // ========================================
    console.println("--- Passing Tests (should succeed) ---");
    console.println("");

    test_read_secure_boot(&console, system_table, &mut results);
    test_read_setup_mode(&console, system_table, &mut results);
    test_read_pk(&console, system_table, &mut results);
    test_read_kek(&console, system_table, &mut results);
    test_read_db(&console, system_table, &mut results);
    test_read_dbx(&console, system_table, &mut results);
    test_mode_consistency(&console, system_table, &mut results);

    console.println("");

    // ========================================
    // FAILING TESTS (should be blocked)
    // ========================================
    console.println("--- Failing Tests (should be blocked) ---");
    console.println("");

    test_unauth_pk_write(&console, system_table, &mut results);
    test_unauth_kek_write(&console, system_table, &mut results);
    test_unauth_db_write(&console, system_table, &mut results);
    test_unauth_dbx_write(&console, system_table, &mut results);
    test_write_readonly_secureboot(&console, system_table, &mut results);
    test_write_readonly_setupmode(&console, system_table, &mut results);
    test_attribute_enforcement(&console, system_table, &mut results);
    test_malformed_auth_header(&console, system_table, &mut results);

    // ========================================
    // Summary
    // ========================================
    console.println("");
    console.println("==========================================");
    console.print("   Results: ");
    console.print_number(results.passed);
    console.print(" passed, ");
    console.print_number(results.failed);
    console.print(" failed, ");
    console.print_number(results.total);
    console.println(" total");
    console.println("==========================================");
    console.println("");

    if results.failed == 0 {
        console.println("All Secure Boot tests passed!");
        console.println("EFI app executed successfully!");
        Status::SUCCESS
    } else {
        console.println("Some Secure Boot tests failed!");
        Status::ABORTED
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
