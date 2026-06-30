//! TCG Protocol test application
//!
//! Tests both EFI_TCG_PROTOCOL (TPM 1.2) and EFI_TCG2_PROTOCOL (TPM 2.0)
//! by querying capabilities, reading the event log, and performing a
//! HashLogExtendEvent operation.
//!
//! Expected output markers (checked by xtask test harness):
//! - "TCG Protocol Test" -- test started
//! - "[PASS] tcg2_locate" -- TCG2 protocol found
//! - "[PASS] tcg2_get_capability" -- GetCapability succeeded, TPM present
//! - "[PASS] tcg2_get_event_log" -- GetEventLog succeeded
//! - "[PASS] tcg2_hash_log_extend" -- HashLogExtendEvent succeeded
//! - "[PASS] tcg2_hardware_tpm" -- hardware TPM/swtpm path is active
//! - "[PASS] tcg2_submit_command" -- SubmitCommand reaches the TPM
//! - "[PASS] tcg1_locate" -- TCG (1.2) protocol found
//! - "All TCG tests passed!" -- all tests passed

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use r_efi::efi::{self, Char16, Guid, Handle, Status, SystemTable};

// ============================================================================
// Protocol GUIDs
// ============================================================================

const TCG2_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x607f766c,
    0x7455,
    0x42be,
    0x93,
    0x0b,
    &[0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f],
);

const TCG_PROTOCOL_GUID: Guid = Guid::from_fields(
    0xf541796d,
    0xa62e,
    0x4954,
    0xa7,
    0x75,
    &[0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd],
);

// ============================================================================
// TCG2 Protocol types
// ============================================================================

#[repr(C)]
struct Tcg2Version {
    major: u8,
    minor: u8,
}

#[repr(C)]
struct Tcg2BootServiceCapability {
    size: u8,
    structure_version: Tcg2Version,
    protocol_version: Tcg2Version,
    hash_algorithm_bitmap: u32,
    supported_event_logs: u32,
    tpm_present_flag: u8,
    max_command_size: u16,
    max_response_size: u16,
    manufacturer_id: u32,
    number_of_pcr_banks: u32,
    active_pcr_banks: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Tcg2EventHeader {
    header_size: u32,
    header_version: u16,
    pcr_index: u32,
    event_type: u32,
}

#[repr(C, packed)]
struct Tcg2Event {
    size: u32,
    header: Tcg2EventHeader,
}

#[repr(C)]
struct Tcg2Protocol {
    get_capability: unsafe extern "efiapi" fn(*mut Self, *mut Tcg2BootServiceCapability) -> Status,
    get_event_log: unsafe extern "efiapi" fn(*mut Self, u32, *mut u64, *mut u64, *mut u8) -> Status,
    hash_log_extend_event:
        unsafe extern "efiapi" fn(*mut Self, u64, u64, u64, *const core::ffi::c_void) -> Status,
    submit_command: unsafe extern "efiapi" fn(*mut Self, u32, *const u8, u32, *mut u8) -> Status,
    get_active_pcr_banks: unsafe extern "efiapi" fn(*mut Self, *mut u32) -> Status,
    set_active_pcr_banks: unsafe extern "efiapi" fn(*mut Self, u32) -> Status,
    get_result_of_set_active_pcr_banks:
        unsafe extern "efiapi" fn(*mut Self, *mut u32, *mut u32) -> Status,
}

// ============================================================================
// Helpers
// ============================================================================

unsafe fn print(con_out: *mut efi::protocols::simple_text_output::Protocol, s: &[u8]) {
    let mut buf = [0u16; 256];
    let len = s.len().min(buf.len() - 1);
    for (i, &b) in s[..len].iter().enumerate() {
        buf[i] = b as u16;
    }
    buf[len] = 0;
    ((*con_out).output_string)(con_out, buf.as_ptr() as *mut Char16);
}

fn be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

// ============================================================================
// Entry point
// ============================================================================

#[no_mangle]
pub extern "efiapi" fn efi_main(_image_handle: Handle, system_table: *mut SystemTable) -> Status {
    let con_out = unsafe { (*system_table).con_out };
    let boot_services = unsafe { (*system_table).boot_services };
    let mut _pass_count: u32 = 0;
    let mut fail_count: u32 = 0;

    unsafe { print(con_out, b"\r\n=== TCG Protocol Test ===\r\n\r\n") };

    // ================================================================
    // TCG2 Protocol (TPM 2.0)
    // ================================================================

    unsafe { print(con_out, b"--- EFI_TCG2_PROTOCOL (TPM 2.0) ---\r\n") };

    let mut tcg2_interface: *mut core::ffi::c_void = core::ptr::null_mut();
    let status = unsafe {
        ((*boot_services).locate_protocol)(
            &TCG2_PROTOCOL_GUID as *const _ as *mut Guid,
            core::ptr::null_mut(),
            &mut tcg2_interface,
        )
    };

    if status != Status::SUCCESS {
        unsafe { print(con_out, b"[FAIL] tcg2_locate: protocol not found\r\n") };
        fail_count += 1;
    } else {
        unsafe { print(con_out, b"[PASS] tcg2_locate: protocol found\r\n") };
        _pass_count += 1;

        let tcg2 = tcg2_interface as *mut Tcg2Protocol;

        // -- GetCapability --
        let mut cap = Tcg2BootServiceCapability {
            size: core::mem::size_of::<Tcg2BootServiceCapability>() as u8,
            structure_version: Tcg2Version { major: 0, minor: 0 },
            protocol_version: Tcg2Version { major: 0, minor: 0 },
            hash_algorithm_bitmap: 0,
            supported_event_logs: 0,
            tpm_present_flag: 0,
            max_command_size: 0,
            max_response_size: 0,
            manufacturer_id: 0,
            number_of_pcr_banks: 0,
            active_pcr_banks: 0,
        };

        let status = unsafe { ((*tcg2).get_capability)(tcg2, &mut cap) };
        if status == Status::SUCCESS && cap.tpm_present_flag != 0 {
            unsafe { print(con_out, b"[PASS] tcg2_get_capability: TPM present\r\n") };
            _pass_count += 1;
        } else {
            unsafe {
                print(
                    con_out,
                    b"[FAIL] tcg2_get_capability: failed or TPM not present\r\n",
                )
            };
            fail_count += 1;
        }

        const SOFTWARE_MANUFACTURER_CRAB: u32 = 0x4352_4142;
        if cap.max_command_size > 0
            && cap.max_response_size > 0
            && cap.manufacturer_id != SOFTWARE_MANUFACTURER_CRAB
        {
            unsafe {
                print(
                    con_out,
                    b"[PASS] tcg2_hardware_tpm: hardware TPM active\r\n",
                )
            };
            _pass_count += 1;
        } else {
            unsafe {
                print(
                    con_out,
                    b"[FAIL] tcg2_hardware_tpm: expected swtpm-backed hardware TPM\r\n",
                )
            };
            fail_count += 1;
        }

        // -- GetEventLog --
        let mut log_loc: u64 = 0;
        let mut log_last: u64 = 0;
        let mut log_trunc: u8 = 0;
        let status = unsafe {
            ((*tcg2).get_event_log)(tcg2, 0x02, &mut log_loc, &mut log_last, &mut log_trunc)
        };
        if status == Status::SUCCESS && log_loc != 0 {
            unsafe { print(con_out, b"[PASS] tcg2_get_event_log: log available\r\n") };
            _pass_count += 1;
        } else {
            unsafe { print(con_out, b"[FAIL] tcg2_get_event_log: failed\r\n") };
            fail_count += 1;
        }

        // -- HashLogExtendEvent --
        let test_data = b"CrabEFI TCG test measurement";
        const EVENT_DATA: &[u8; 16] = b"CrabEFI TCG test";

        #[repr(C)]
        struct TestEvent {
            event: Tcg2Event,
            data: [u8; 16],
        }

        let hdr_size = core::mem::size_of::<Tcg2EventHeader>() as u32;
        let test_event = TestEvent {
            event: Tcg2Event {
                size: (core::mem::size_of::<Tcg2Event>() + 16) as u32,
                header: Tcg2EventHeader {
                    header_size: hdr_size,
                    header_version: 1,
                    pcr_index: 4,
                    event_type: 0x0000_000D, // EV_IPL
                },
            },
            data: *EVENT_DATA,
        };

        let status = unsafe {
            ((*tcg2).hash_log_extend_event)(
                tcg2,
                0,
                test_data.as_ptr() as u64,
                test_data.len() as u64,
                &test_event as *const _ as *const core::ffi::c_void,
            )
        };
        if status == Status::SUCCESS {
            unsafe { print(con_out, b"[PASS] tcg2_hash_log_extend: PCR 4 extended\r\n") };
            _pass_count += 1;
        } else {
            unsafe { print(con_out, b"[FAIL] tcg2_hash_log_extend: failed\r\n") };
            fail_count += 1;
        }

        // -- PCR bank management --
        let mut active_banks: u32 = 0;
        let status = unsafe { ((*tcg2).get_active_pcr_banks)(tcg2, &mut active_banks) };
        if status == Status::SUCCESS && active_banks == cap.active_pcr_banks {
            unsafe {
                print(
                    con_out,
                    b"[PASS] tcg2_get_active_pcr_banks: banks match\r\n",
                )
            };
            _pass_count += 1;
        } else {
            unsafe { print(con_out, b"[FAIL] tcg2_get_active_pcr_banks: mismatch\r\n") };
            fail_count += 1;
        }

        let status = unsafe { ((*tcg2).set_active_pcr_banks)(tcg2, active_banks) };
        if status == Status::SUCCESS {
            unsafe {
                print(
                    con_out,
                    b"[PASS] tcg2_set_active_pcr_banks: current set accepted\r\n",
                )
            };
            _pass_count += 1;
        } else {
            unsafe {
                print(
                    con_out,
                    b"[FAIL] tcg2_set_active_pcr_banks: current set rejected\r\n",
                )
            };
            fail_count += 1;
        }

        let mut operation_present: u32 = 1;
        let mut set_response: u32 = 1;
        let status = unsafe {
            ((*tcg2).get_result_of_set_active_pcr_banks)(
                tcg2,
                &mut operation_present,
                &mut set_response,
            )
        };
        if status == Status::SUCCESS && operation_present == 0 && set_response == 0 {
            unsafe {
                print(
                    con_out,
                    b"[PASS] tcg2_get_result_of_set_active_pcr_banks: no pending op\r\n",
                )
            };
            _pass_count += 1;
        } else {
            unsafe {
                print(
                    con_out,
                    b"[FAIL] tcg2_get_result_of_set_active_pcr_banks: unexpected result\r\n",
                )
            };
            fail_count += 1;
        }

        // -- SubmitCommand --
        // TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, 1)
        let cmd: [u8; 22] = [
            0x80, 0x01, // TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x16, // commandSize
            0x00, 0x00, 0x01, 0x7A, // TPM2_CC_GetCapability
            0x00, 0x00, 0x00, 0x06, // TPM_CAP_TPM_PROPERTIES
            0x00, 0x00, 0x01, 0x05, // TPM_PT_MANUFACTURER
            0x00, 0x00, 0x00, 0x01, // propertyCount
        ];
        let mut resp = [0u8; 64];
        let status = unsafe {
            ((*tcg2).submit_command)(
                tcg2,
                cmd.len() as u32,
                cmd.as_ptr(),
                resp.len() as u32,
                resp.as_mut_ptr(),
            )
        };
        let resp_size = be_u32(&resp, 2) as usize;
        let resp_code = be_u32(&resp, 6);
        let prop = be_u32(&resp, 19);
        let manufacturer = be_u32(&resp, 23);
        if status == Status::SUCCESS
            && resp_size >= 27
            && resp_size <= resp.len()
            && resp_code == 0
            && prop == 0x0000_0105
            && manufacturer == cap.manufacturer_id
        {
            unsafe {
                print(
                    con_out,
                    b"[PASS] tcg2_submit_command: hardware command succeeded\r\n",
                )
            };
            _pass_count += 1;
        } else {
            unsafe {
                print(
                    con_out,
                    b"[FAIL] tcg2_submit_command: hardware command failed\r\n",
                )
            };
            fail_count += 1;
        }
    }

    // ================================================================
    // TCG Protocol (TPM 1.2)
    // ================================================================

    unsafe { print(con_out, b"\r\n--- EFI_TCG_PROTOCOL (TPM 1.2) ---\r\n") };

    let mut tcg_interface: *mut core::ffi::c_void = core::ptr::null_mut();
    let status = unsafe {
        ((*boot_services).locate_protocol)(
            &TCG_PROTOCOL_GUID as *const _ as *mut Guid,
            core::ptr::null_mut(),
            &mut tcg_interface,
        )
    };

    if status != Status::SUCCESS {
        unsafe { print(con_out, b"[FAIL] tcg1_locate: protocol not found\r\n") };
        fail_count += 1;
    } else {
        unsafe { print(con_out, b"[PASS] tcg1_locate: protocol found\r\n") };
        _pass_count += 1;
    }

    // ================================================================
    // Summary
    // ================================================================

    unsafe { print(con_out, b"\r\n--- Results ---\r\n") };

    if fail_count == 0 {
        unsafe { print(con_out, b"All TCG tests passed!\r\n") };
    } else {
        unsafe { print(con_out, b"Some TCG tests failed!\r\n") };
    }

    unsafe { print(con_out, b"\r\n=== TCG Test Complete ===\r\n") };

    if fail_count == 0 {
        Status::SUCCESS
    } else {
        Status::ABORTED
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
