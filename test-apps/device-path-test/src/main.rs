//! Device Path Protocol Test Application
//!
//! Tests CrabEFI's Device Path Utilities, Device Path To Text, Device Path
//! From Text, and Load File 2 protocol implementations.
//!
//! Each test prints [PASS] or [FAIL] markers that the xtask test runner checks.

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;
use r_efi::efi::{self, Boolean, Char16, Guid, Handle, Status, SystemTable};
use r_efi::protocols::{
    device_path, device_path_from_text, device_path_to_text, device_path_utilities, load_file2,
};

static mut BOOT_SERVICES: *mut efi::BootServices = core::ptr::null_mut();
static mut CON_OUT: *mut r_efi::protocols::simple_text_output::Protocol = core::ptr::null_mut();

// ============================================================================
// Output helpers
// ============================================================================

fn print(s: &str) {
    let con_out = unsafe { CON_OUT };
    if con_out.is_null() {
        return;
    }
    // Print in chunks that fit our small buffer
    let mut buf: [Char16; 128] = [0; 128];
    let mut idx = 0;
    for c in s.chars() {
        if c == '\n' {
            if idx >= buf.len() - 3 {
                buf[idx] = 0;
                unsafe { ((*con_out).output_string)(con_out, buf.as_ptr() as *mut Char16) };
                idx = 0;
            }
            buf[idx] = '\r' as Char16;
            idx += 1;
        }
        if idx >= buf.len() - 2 {
            buf[idx] = 0;
            unsafe { ((*con_out).output_string)(con_out, buf.as_ptr() as *mut Char16) };
            idx = 0;
        }
        buf[idx] = c as Char16;
        idx += 1;
    }
    if idx > 0 {
        buf[idx] = 0;
        unsafe { ((*con_out).output_string)(con_out, buf.as_ptr() as *mut Char16) };
    }
}

fn println(s: &str) {
    print(s);
    print("\n");
}

fn print_dec(mut val: usize) {
    let mut buf = [0u8; 20];
    if val == 0 {
        print("0");
        return;
    }
    let mut idx = 20;
    while val > 0 {
        idx -= 1;
        buf[idx] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    let s = unsafe { core::str::from_utf8_unchecked(&buf[idx..20]) };
    print(s);
}

// ============================================================================
// Protocol location helpers
// ============================================================================

fn locate_protocol(guid: &mut Guid) -> *mut c_void {
    let bs = unsafe { BOOT_SERVICES };
    let mut interface: *mut c_void = core::ptr::null_mut();
    let status = unsafe { ((*bs).locate_protocol)(guid, core::ptr::null_mut(), &mut interface) };
    if status != Status::SUCCESS {
        return core::ptr::null_mut();
    }
    interface
}

/// Read node type at offset 0
unsafe fn node_type(node: *const u8) -> u8 {
    unsafe { *node }
}

/// Read node length at offset 2-3
unsafe fn node_len(node: *const u8) -> u16 {
    unsafe { u16::from_le_bytes([*node.add(2), *node.add(3)]) }
}

/// Convert a null-terminated UCS-2 string to ASCII for printing
fn ucs2_to_ascii_print(text: *const Char16) {
    if text.is_null() {
        print("(null)");
        return;
    }
    let mut i = 0;
    loop {
        let ch = unsafe { *(text as *const u16).add(i) };
        if ch == 0 {
            break;
        }
        if ch >= 0x20 && ch < 0x7F {
            let byte = [ch as u8];
            let s = unsafe { core::str::from_utf8_unchecked(&byte) };
            print(s);
        } else {
            print("?");
        }
        i += 1;
        if i > 512 {
            break; // safety limit
        }
    }
}

/// Get UCS-2 string length (in chars, not bytes)
fn ucs2_strlen(text: *const Char16) -> usize {
    if text.is_null() {
        return 0;
    }
    let mut i = 0;
    loop {
        let ch = unsafe { *(text as *const u16).add(i) };
        if ch == 0 {
            return i;
        }
        i += 1;
        if i > 4096 {
            return i;
        }
    }
}

/// Free a pool allocation
fn free_pool(ptr: *mut c_void) {
    if !ptr.is_null() {
        let bs = unsafe { BOOT_SERVICES };
        unsafe { ((*bs).free_pool)(ptr) };
    }
}

// ============================================================================
// Device Path Utilities Tests
// ============================================================================

fn test_device_path_utilities(dpu: &device_path_utilities::Protocol) -> (usize, usize) {
    let mut passed = 0usize;
    let mut failed = 0usize;

    println("--- Device Path Utilities Protocol ---");

    // Test 1: CreateDeviceNode
    {
        let node = (dpu.create_device_node)(0x01, 0x01, 6); // PCI node: type=HW, sub=PCI, len=6
        if !node.is_null() {
            let ntype = unsafe { node_type(node as *const u8) };
            let nlen = unsafe { node_len(node as *const u8) };
            if ntype == 0x01 && nlen == 6 {
                println("[PASS] create_device_node: Created PCI node (type=0x01, len=6)");
                passed += 1;
            } else {
                print("[FAIL] create_device_node: Wrong type/len: ");
                print_dec(ntype as usize);
                print("/");
                print_dec(nlen as usize);
                println("");
                failed += 1;
            }
            free_pool(node as *mut c_void);
        } else {
            println("[FAIL] create_device_node: Returned NULL");
            failed += 1;
        }
    }

    // Test 2: CreateDeviceNode with too-small length should fail
    {
        let node = (dpu.create_device_node)(0x01, 0x01, 2); // len < 4 = invalid
        if node.is_null() {
            println("[PASS] create_device_node_invalid: Rejected length < 4");
            passed += 1;
        } else {
            println("[FAIL] create_device_node_invalid: Should have returned NULL for length < 4");
            free_pool(node as *mut c_void);
            failed += 1;
        }
    }

    // Test 3: GetDevicePathSize on NULL
    {
        let size = (dpu.get_device_path_size)(core::ptr::null());
        if size == 0 {
            println("[PASS] get_size_null: Returns 0 for NULL input");
            passed += 1;
        } else {
            print("[FAIL] get_size_null: Expected 0, got ");
            print_dec(size);
            println("");
            failed += 1;
        }
    }

    // Test 4: Build a device path and check its size
    // Create ACPI node (12 bytes) -> we need a full path with End node
    {
        let acpi = (dpu.create_device_node)(0x02, 0x01, 12); // ACPI node
        if !acpi.is_null() {
            // AppendDeviceNode(NULL, acpi) should create a path: acpi + end(4) = 16 bytes
            let path = (dpu.append_device_node)(core::ptr::null(), acpi);
            if !path.is_null() {
                let size = (dpu.get_device_path_size)(path);
                if size == 16 {
                    // 12 (ACPI) + 4 (End) = 16
                    println("[PASS] get_size: ACPI+End path is 16 bytes");
                    passed += 1;
                } else {
                    print("[FAIL] get_size: Expected 16, got ");
                    print_dec(size);
                    println("");
                    failed += 1;
                }

                // Test 5: DuplicateDevicePath
                let dup = (dpu.duplicate_device_path)(path);
                if !dup.is_null() {
                    let dup_size = (dpu.get_device_path_size)(dup);
                    if dup_size == size {
                        println("[PASS] duplicate: Duplicate has same size");
                        passed += 1;
                    } else {
                        println("[FAIL] duplicate: Size mismatch after duplication");
                        failed += 1;
                    }
                    free_pool(dup as *mut c_void);
                } else {
                    println("[FAIL] duplicate: Returned NULL");
                    failed += 1;
                }

                free_pool(path as *mut c_void);
            } else {
                println("[FAIL] append_device_node_null_path: Returned NULL");
                failed += 1;
            }
            free_pool(acpi as *mut c_void);
        } else {
            println("[FAIL] create_acpi_node: Returned NULL");
            failed += 1;
        }
    }

    // Test 6: AppendDevicePath with two paths
    {
        // Create path1: PCI(dev=1,func=0) + End
        let pci = (dpu.create_device_node)(0x01, 0x01, 6);
        let path1 = (dpu.append_device_node)(core::ptr::null(), pci);
        free_pool(pci as *mut c_void);

        // Create path2: USB(port=1,iface=0) + End
        let usb = (dpu.create_device_node)(0x03, 0x05, 6);
        let path2 = (dpu.append_device_node)(core::ptr::null(), usb);
        free_pool(usb as *mut c_void);

        if !path1.is_null() && !path2.is_null() {
            let combined = (dpu.append_device_path)(path1, path2);
            if !combined.is_null() {
                // Expected: PCI(6) + USB(6) + End(4) = 16
                let size = (dpu.get_device_path_size)(combined);
                if size == 16 {
                    println("[PASS] append_device_path: PCI+USB path is 16 bytes");
                    passed += 1;
                } else {
                    print("[FAIL] append_device_path: Expected 16, got ");
                    print_dec(size);
                    println("");
                    failed += 1;
                }
                free_pool(combined as *mut c_void);
            } else {
                println("[FAIL] append_device_path: Returned NULL");
                failed += 1;
            }
        } else {
            println("[FAIL] append_device_path: Failed to create test paths");
            failed += 1;
        }
        free_pool(path1 as *mut c_void);
        free_pool(path2 as *mut c_void);
    }

    // Test 7: AppendDevicePath with both NULL
    {
        let result = (dpu.append_device_path)(core::ptr::null(), core::ptr::null());
        if !result.is_null() {
            let size = (dpu.get_device_path_size)(result);
            if size == 4 {
                // Just an End node
                println("[PASS] append_both_null: Returns end-only path (4 bytes)");
                passed += 1;
            } else {
                print("[FAIL] append_both_null: Expected 4, got ");
                print_dec(size);
                println("");
                failed += 1;
            }
            free_pool(result as *mut c_void);
        } else {
            println("[FAIL] append_both_null: Returned NULL");
            failed += 1;
        }
    }

    // Test 8: IsDevicePathMultiInstance (single instance)
    {
        let node = (dpu.create_device_node)(0x01, 0x01, 6);
        let path = (dpu.append_device_node)(core::ptr::null(), node);
        free_pool(node as *mut c_void);

        if !path.is_null() {
            let multi = (dpu.is_device_path_multi_instance)(path);
            if multi == Boolean::FALSE {
                println("[PASS] is_multi_instance_single: Single instance returns FALSE");
                passed += 1;
            } else {
                println("[FAIL] is_multi_instance_single: Should return FALSE for single instance");
                failed += 1;
            }
            free_pool(path as *mut c_void);
        }
    }

    // Test 9: AppendDevicePathInstance + IsDevicePathMultiInstance
    {
        let node1 = (dpu.create_device_node)(0x01, 0x01, 6);
        let path1 = (dpu.append_device_node)(core::ptr::null(), node1);
        free_pool(node1 as *mut c_void);

        let node2 = (dpu.create_device_node)(0x03, 0x05, 6);
        let path2 = (dpu.append_device_node)(core::ptr::null(), node2);
        free_pool(node2 as *mut c_void);

        if !path1.is_null() && !path2.is_null() {
            let multi_path = (dpu.append_device_path_instance)(path1, path2);
            if !multi_path.is_null() {
                let is_multi = (dpu.is_device_path_multi_instance)(multi_path);
                if is_multi != Boolean::FALSE {
                    println("[PASS] is_multi_instance_multi: Multi-instance returns TRUE");
                    passed += 1;
                } else {
                    println("[FAIL] is_multi_instance_multi: Should return TRUE");
                    failed += 1;
                }

                // Test 10: GetNextDevicePathInstance
                let mut iter = multi_path as *mut device_path::Protocol;
                let mut inst_size: usize = 0;
                let inst1 = (dpu.get_next_device_path_instance)(&mut iter, &mut inst_size);
                if !inst1.is_null() && inst_size == 10 {
                    // First instance: PCI(6) + End(4) = 10
                    println("[PASS] get_next_instance_1: First instance is 10 bytes");
                    passed += 1;
                    free_pool(inst1 as *mut c_void);
                } else {
                    print("[FAIL] get_next_instance_1: Expected size 10, got ");
                    print_dec(inst_size);
                    println("");
                    failed += 1;
                }

                if !iter.is_null() {
                    let inst2 = (dpu.get_next_device_path_instance)(&mut iter, &mut inst_size);
                    if !inst2.is_null() && inst_size == 10 {
                        println("[PASS] get_next_instance_2: Second instance is 10 bytes");
                        passed += 1;
                    } else {
                        print("[FAIL] get_next_instance_2: Expected size 10, got ");
                        print_dec(inst_size);
                        println("");
                        failed += 1;
                    }
                    if !inst2.is_null() {
                        free_pool(inst2 as *mut c_void);
                    }

                    // After second instance, iter should be NULL
                    if iter.is_null() {
                        println(
                            "[PASS] get_next_instance_end: Iterator is NULL after last instance",
                        );
                        passed += 1;
                    } else {
                        println("[FAIL] get_next_instance_end: Iterator should be NULL after last");
                        failed += 1;
                    }
                } else {
                    println("[FAIL] get_next_instance_iter: Iterator NULL after first instance");
                    failed += 1;
                }

                free_pool(multi_path as *mut c_void);
            } else {
                println("[FAIL] append_instance: Returned NULL");
                failed += 1;
            }
        }
        free_pool(path1 as *mut c_void);
        free_pool(path2 as *mut c_void);
    }

    (passed, failed)
}

// ============================================================================
// Device Path To Text Tests
// ============================================================================

fn test_device_path_to_text(
    dpu: &device_path_utilities::Protocol,
    dpt: &device_path_to_text::Protocol,
) -> (usize, usize) {
    let mut passed = 0usize;
    let mut failed = 0usize;

    println("");
    println("--- Device Path To Text Protocol ---");

    // Test 1: Convert a PCI node to text
    {
        let pci = (dpu.create_device_node)(0x01, 0x01, 6);
        if !pci.is_null() {
            // Set function=0, device=0x1F at offsets 4,5
            unsafe {
                *(pci as *mut u8).add(4) = 0; // function
                *(pci as *mut u8).add(5) = 0x1F; // device
            }
            let text = (dpt.convert_device_node_to_text)(
                pci,
                Boolean::FALSE, // not display_only
                Boolean::FALSE,
            );
            if !text.is_null() {
                // Should be "Pci(0x1F,0x0)"
                let len = ucs2_strlen(text);
                print("[    ] node_to_text_pci: \"");
                ucs2_to_ascii_print(text);
                println("\"");
                if len > 0 {
                    println("[PASS] node_to_text_pci: PCI node converted to text");
                    passed += 1;
                } else {
                    println("[FAIL] node_to_text_pci: Empty text for PCI node");
                    failed += 1;
                }
                free_pool(text as *mut c_void);
            } else {
                println("[FAIL] node_to_text_pci: Returned NULL");
                failed += 1;
            }
            free_pool(pci as *mut c_void);
        }
    }

    // Test 2: Convert a full device path (ACPI/PCI) to text
    {
        // Build ACPI(PNP0A03,0)/PCI(1,0)/End
        let acpi = (dpu.create_device_node)(0x02, 0x01, 12);
        if !acpi.is_null() {
            // HID = 0x0a0341d0 (PNP0A03) at offset 4, UID = 0 at offset 8
            unsafe {
                let hid_bytes = 0x0a0341d0u32.to_le_bytes();
                core::ptr::copy_nonoverlapping(hid_bytes.as_ptr(), (acpi as *mut u8).add(4), 4);
                let uid_bytes = 0u32.to_le_bytes();
                core::ptr::copy_nonoverlapping(uid_bytes.as_ptr(), (acpi as *mut u8).add(8), 4);
            }
            let path = (dpu.append_device_node)(core::ptr::null(), acpi);
            free_pool(acpi as *mut c_void);

            let pci = (dpu.create_device_node)(0x01, 0x01, 6);
            if !pci.is_null() {
                unsafe {
                    *(pci as *mut u8).add(4) = 0; // function
                    *(pci as *mut u8).add(5) = 1; // device
                }
                let full_path = (dpu.append_device_node)(path, pci);
                free_pool(pci as *mut c_void);
                free_pool(path as *mut c_void);

                if !full_path.is_null() {
                    let text = (dpt.convert_device_path_to_text)(
                        full_path,
                        Boolean::FALSE,
                        Boolean::FALSE,
                    );
                    if !text.is_null() {
                        // Should be "PciRoot(0x0)/Pci(0x1,0x0)"
                        print("[    ] path_to_text_pci_root: \"");
                        ucs2_to_ascii_print(text);
                        println("\"");
                        let len = ucs2_strlen(text);
                        if len > 5 {
                            println("[PASS] path_to_text_pci_root: Full path converted to text");
                            passed += 1;
                        } else {
                            println("[FAIL] path_to_text_pci_root: Text too short");
                            failed += 1;
                        }
                        free_pool(text as *mut c_void);
                    } else {
                        println("[FAIL] path_to_text_pci_root: Returned NULL");
                        failed += 1;
                    }
                    free_pool(full_path as *mut c_void);
                }
            } else {
                free_pool(path as *mut c_void);
            }
        }
    }

    // Test 3: Convert NULL should return NULL
    {
        let text = (dpt.convert_device_path_to_text)(
            core::ptr::null_mut(),
            Boolean::FALSE,
            Boolean::FALSE,
        );
        if text.is_null() {
            println("[PASS] path_to_text_null: NULL input returns NULL");
            passed += 1;
        } else {
            println("[FAIL] path_to_text_null: Should return NULL for NULL input");
            free_pool(text as *mut c_void);
            failed += 1;
        }
    }

    (passed, failed)
}

// ============================================================================
// Device Path From Text Tests
// ============================================================================

fn test_device_path_from_text(
    dpu: &device_path_utilities::Protocol,
    dpft: &device_path_from_text::Protocol,
    dpt: &device_path_to_text::Protocol,
) -> (usize, usize) {
    let mut passed = 0usize;
    let mut failed = 0usize;

    println("");
    println("--- Device Path From Text Protocol ---");

    // Test 1: ConvertTextToDeviceNode for PciRoot(0x0)
    {
        let text: [u16; 13] = [
            b'P' as u16,
            b'c' as u16,
            b'i' as u16,
            b'R' as u16,
            b'o' as u16,
            b'o' as u16,
            b't' as u16,
            b'(' as u16,
            b'0' as u16,
            b'x' as u16,
            b'0' as u16,
            b')' as u16,
            0,
        ];
        let node = (dpft.convert_text_to_device_node)(text.as_ptr() as *const Char16);
        if !node.is_null() {
            let ntype = unsafe { node_type(node as *const u8) };
            let nlen = unsafe { node_len(node as *const u8) };
            if ntype == 0x02 && nlen == 12 {
                println("[PASS] text_to_node_pci_root: PciRoot(0x0) parsed as ACPI node");
                passed += 1;
            } else {
                print("[FAIL] text_to_node_pci_root: Wrong type/len: ");
                print_dec(ntype as usize);
                print("/");
                print_dec(nlen as usize);
                println("");
                failed += 1;
            }
            free_pool(node as *mut c_void);
        } else {
            println("[FAIL] text_to_node_pci_root: Returned NULL");
            failed += 1;
        }
    }

    // Test 2: ConvertTextToDevicePath for "PciRoot(0x0)/Pci(0x1,0x0)"
    {
        let text: [u16; 27] = [
            b'P' as u16,
            b'c' as u16,
            b'i' as u16,
            b'R' as u16,
            b'o' as u16,
            b'o' as u16,
            b't' as u16,
            b'(' as u16,
            b'0' as u16,
            b'x' as u16,
            b'0' as u16,
            b')' as u16,
            b'/' as u16,
            b'P' as u16,
            b'c' as u16,
            b'i' as u16,
            b'(' as u16,
            b'0' as u16,
            b'x' as u16,
            b'1' as u16,
            b',' as u16,
            b'0' as u16,
            b'x' as u16,
            b'0' as u16,
            b')' as u16,
            0,
            0, // Extra null for safety
        ];
        let path = (dpft.convert_text_to_device_path)(text.as_ptr() as *const Char16);
        if !path.is_null() {
            let size = (dpu.get_device_path_size)(path);
            // ACPI(12) + PCI(6) + End(4) = 22
            if size == 22 {
                println("[PASS] text_to_path_pci: Path is 22 bytes (ACPI+PCI+End)");
                passed += 1;
            } else {
                print("[FAIL] text_to_path_pci: Expected 22, got ");
                print_dec(size);
                println("");
                failed += 1;
            }

            // Test 3: Round-trip: text->path->text should produce equivalent text
            let text_out = (dpt.convert_device_path_to_text)(path, Boolean::FALSE, Boolean::FALSE);
            if !text_out.is_null() {
                print("[    ] round_trip: \"");
                ucs2_to_ascii_print(text_out);
                println("\"");
                let len = ucs2_strlen(text_out);
                if len > 10 {
                    println("[PASS] round_trip: FromText->ToText round-trip produced text");
                    passed += 1;
                } else {
                    println("[FAIL] round_trip: Round-trip text too short");
                    failed += 1;
                }
                free_pool(text_out as *mut c_void);
            } else {
                println("[FAIL] round_trip: ToText returned NULL");
                failed += 1;
            }

            free_pool(path as *mut c_void);
        } else {
            println("[FAIL] text_to_path_pci: Returned NULL");
            failed += 1;
        }
    }

    // Test 4: ConvertTextToDeviceNode for a file path (unrecognized keyword -> file path node)
    {
        let text: [u16; 14] = [
            b'\\' as u16,
            b'E' as u16,
            b'F' as u16,
            b'I' as u16,
            b'\\' as u16,
            b'B' as u16,
            b'O' as u16,
            b'O' as u16,
            b'T' as u16,
            b'\\' as u16,
            b't' as u16,
            b'.' as u16,
            b'e' as u16,
            0,
        ];
        let node = (dpft.convert_text_to_device_node)(text.as_ptr() as *const Char16);
        if !node.is_null() {
            let ntype = unsafe { node_type(node as *const u8) };
            let nsub = unsafe { *(node as *const u8).add(1) };
            if ntype == 0x04 && nsub == 0x04 {
                // Media type, File Path subtype
                println("[PASS] text_to_node_filepath: File path parsed as Media/FilePath node");
                passed += 1;
            } else {
                print("[FAIL] text_to_node_filepath: Wrong type/sub: ");
                print_dec(ntype as usize);
                print("/");
                print_dec(nsub as usize);
                println("");
                failed += 1;
            }
            free_pool(node as *mut c_void);
        } else {
            println("[FAIL] text_to_node_filepath: Returned NULL");
            failed += 1;
        }
    }

    // Test 5: NULL input returns NULL
    {
        let node = (dpft.convert_text_to_device_node)(core::ptr::null());
        if node.is_null() {
            println("[PASS] text_to_node_null: NULL input returns NULL");
            passed += 1;
        } else {
            println("[FAIL] text_to_node_null: Should return NULL for NULL input");
            free_pool(node as *mut c_void);
            failed += 1;
        }
    }

    (passed, failed)
}

// ============================================================================
// Load File 2 Tests
// ============================================================================

fn test_load_file2() -> (usize, usize) {
    let mut passed = 0usize;
    let mut failed = 0usize;

    println("");
    println("--- Load File 2 Protocol ---");

    // Try to locate LoadFile2 by searching handles
    let bs = unsafe { BOOT_SERVICES };
    let mut guid = load_file2::PROTOCOL_GUID;
    let mut handles: [Handle; 16] = [core::ptr::null_mut(); 16];
    let mut buf_size = core::mem::size_of_val(&handles);

    let status = unsafe {
        ((*bs).locate_handle)(
            efi::BY_PROTOCOL,
            &mut guid,
            core::ptr::null_mut(),
            &mut buf_size,
            handles.as_mut_ptr(),
        )
    };

    if status == Status::SUCCESS && buf_size >= core::mem::size_of::<Handle>() {
        println("[PASS] locate_load_file2: LoadFile2 protocol found");
        passed += 1;

        // Open the protocol
        let mut interface: *mut c_void = core::ptr::null_mut();
        let handle = handles[0];
        let status = unsafe {
            ((*bs).open_protocol)(
                handle,
                &mut guid,
                &mut interface,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0x00000002, // GET_PROTOCOL
            )
        };

        if status == Status::SUCCESS && !interface.is_null() {
            let lf2 = interface as *mut load_file2::Protocol;

            // Test: LoadFile with BootPolicy=TRUE should return UNSUPPORTED
            let mut buf_sz: usize = 0;
            let status = unsafe {
                ((*lf2).load_file)(
                    lf2,
                    core::ptr::null_mut(),
                    Boolean::TRUE,
                    &mut buf_sz,
                    core::ptr::null_mut(),
                )
            };
            if status == Status::UNSUPPORTED {
                println("[PASS] load_file2_boot_policy: BootPolicy=TRUE returns UNSUPPORTED");
                passed += 1;
            } else {
                println("[FAIL] load_file2_boot_policy: Expected UNSUPPORTED for BootPolicy=TRUE");
                failed += 1;
            }

            // Test: LoadFile with BootPolicy=FALSE should return NOT_FOUND (stub)
            let status = unsafe {
                ((*lf2).load_file)(
                    lf2,
                    core::ptr::null_mut(),
                    Boolean::FALSE,
                    &mut buf_sz,
                    core::ptr::null_mut(),
                )
            };
            if status == Status::NOT_FOUND {
                println("[PASS] load_file2_not_found: BootPolicy=FALSE returns NOT_FOUND (stub)");
                passed += 1;
            } else {
                println("[FAIL] load_file2_not_found: Expected NOT_FOUND for stub implementation");
                failed += 1;
            }
        } else {
            println("[FAIL] open_load_file2: Failed to open LoadFile2 protocol");
            failed += 1;
        }
    } else {
        println("[FAIL] locate_load_file2: LoadFile2 protocol not found");
        failed += 1;
    }

    (passed, failed)
}

// ============================================================================
// Entry point
// ============================================================================

#[no_mangle]
pub extern "efiapi" fn efi_main(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    unsafe {
        CON_OUT = (*system_table).con_out;
        BOOT_SERVICES = (*system_table).boot_services;
    }
    let _ = image_handle; // unused

    println("==============================================");
    println("  CrabEFI Device Path Protocol Test Suite");
    println("==============================================");
    println("");

    let mut total_passed = 0usize;
    let mut total_failed = 0usize;

    // Locate Device Path Utilities
    let mut dpu_guid = device_path_utilities::PROTOCOL_GUID;
    let dpu_ptr = locate_protocol(&mut dpu_guid);
    if dpu_ptr.is_null() {
        println("[FAIL] locate_utilities: Device Path Utilities protocol not found");
        total_failed += 1;
    } else {
        println("[PASS] locate_utilities: Device Path Utilities protocol found");
        total_passed += 1;

        let dpu = unsafe { &*(dpu_ptr as *const device_path_utilities::Protocol) };
        let (p, f) = test_device_path_utilities(dpu);
        total_passed += p;
        total_failed += f;

        // Locate Device Path To Text
        let mut dpt_guid = device_path_to_text::PROTOCOL_GUID;
        let dpt_ptr = locate_protocol(&mut dpt_guid);
        if dpt_ptr.is_null() {
            println("[FAIL] locate_to_text: Device Path To Text protocol not found");
            total_failed += 1;
        } else {
            println("[PASS] locate_to_text: Device Path To Text protocol found");
            total_passed += 1;

            let dpt = unsafe { &*(dpt_ptr as *const device_path_to_text::Protocol) };
            let (p, f) = test_device_path_to_text(dpu, dpt);
            total_passed += p;
            total_failed += f;

            // Locate Device Path From Text
            let mut dpft_guid = device_path_from_text::PROTOCOL_GUID;
            let dpft_ptr = locate_protocol(&mut dpft_guid);
            if dpft_ptr.is_null() {
                println("[FAIL] locate_from_text: Device Path From Text protocol not found");
                total_failed += 1;
            } else {
                println("[PASS] locate_from_text: Device Path From Text protocol found");
                total_passed += 1;

                let dpft = unsafe { &*(dpft_ptr as *const device_path_from_text::Protocol) };
                let (p, f) = test_device_path_from_text(dpu, dpft, dpt);
                total_passed += p;
                total_failed += f;
            }
        }
    }

    // LoadFile2 tests (independent of device path protocols)
    let (p, f) = test_load_file2();
    total_passed += p;
    total_failed += f;

    // Summary
    println("");
    println("==============================================");
    print("  Results: ");
    print_dec(total_passed);
    print(" passed, ");
    print_dec(total_failed);
    println(" failed");
    println("==============================================");

    if total_failed == 0 {
        println("All device path tests passed!");
    } else {
        println("Some device path tests FAILED!");
    }

    Status::SUCCESS
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
