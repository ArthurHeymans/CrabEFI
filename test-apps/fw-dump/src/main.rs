//! Firmware Dump EFI Application
//!
//! Dumps UEFI memory map, ACPI tables, and SMBIOS tables to the serial/console
//! in parseable formats for comparing firmware implementations.
//!
//! Output format:
//! - Memory map: human-readable table
//! - ACPI: `acpidump`-compatible hex format (feed to `acpidump -o dump.dat && iasl -d dump.dat`)
//! - SMBIOS: hex dump of the entry point and structure table

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use r_efi::efi::{self, Char16, Guid, Handle, MemoryDescriptor, Status, SystemTable};

// ============================================================================
// Console output helpers
// ============================================================================

struct Console {
    con_out: *mut efi::protocols::simple_text_output::Protocol,
}

impl Console {
    fn new(system_table: *mut SystemTable) -> Self {
        Self {
            con_out: unsafe { (*system_table).con_out },
        }
    }

    fn print_str(&self, s: &str) {
        // Convert ASCII to UCS-2 in small batches
        let mut buf = [0u16; 128];
        for chunk in s.as_bytes().chunks(126) {
            for (i, &b) in chunk.iter().enumerate() {
                buf[i] = b as u16;
            }
            buf[chunk.len()] = 0; // null terminate
            unsafe {
                ((*self.con_out).output_string)(self.con_out, buf.as_ptr() as *mut Char16);
            }
        }
    }

    fn print_hex_u8(&self, v: u8) {
        let hi = v >> 4;
        let lo = v & 0xf;
        let mut buf = [0u16; 3];
        buf[0] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 } as u16;
        buf[1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 } as u16;
        buf[2] = 0;
        unsafe {
            ((*self.con_out).output_string)(self.con_out, buf.as_ptr() as *mut Char16);
        }
    }

    fn print_hex_u16(&self, v: u16) {
        self.print_hex_u8((v >> 8) as u8);
        self.print_hex_u8(v as u8);
    }

    fn print_hex_u32(&self, v: u32) {
        self.print_hex_u16((v >> 16) as u16);
        self.print_hex_u16(v as u16);
    }

    fn print_hex_u64(&self, v: u64) {
        self.print_hex_u32((v >> 32) as u32);
        self.print_hex_u32(v as u32);
    }

    fn print_dec(&self, mut v: u64) {
        if v == 0 {
            self.print_str("0");
            return;
        }
        let mut digits = [0u8; 20];
        let mut n = 0;
        while v > 0 {
            digits[n] = (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        let mut buf = [0u16; 21];
        for i in 0..n {
            buf[i] = (b'0' + digits[n - 1 - i]) as u16;
        }
        buf[n] = 0;
        unsafe {
            ((*self.con_out).output_string)(self.con_out, buf.as_ptr() as *mut Char16);
        }
    }

    fn newline(&self) {
        self.print_str("\r\n");
    }
}

// ============================================================================
// GUID constants
// ============================================================================

const ACPI_20_TABLE_GUID: Guid = Guid::from_fields(
    0x8868e871,
    0xe4f1,
    0x11d3,
    0xbc,
    0x22,
    &[0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
);

const ACPI_TABLE_GUID: Guid = Guid::from_fields(
    0xeb9d2d30,
    0x2d88,
    0x11d3,
    0x9a,
    0x16,
    &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
);

const SMBIOS3_TABLE_GUID: Guid = Guid::from_fields(
    0xf2fd1544,
    0x9794,
    0x4a2c,
    0x99,
    0x2e,
    &[0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94],
);

const SMBIOS_TABLE_GUID: Guid = Guid::from_fields(
    0xeb9d2d31,
    0x2d88,
    0x11d3,
    0x9a,
    0x16,
    &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
);

fn guid_eq(a: &Guid, b: &Guid) -> bool {
    // Compare the raw bytes of the GUIDs
    let a_bytes = unsafe { core::slice::from_raw_parts(a as *const Guid as *const u8, 16) };
    let b_bytes = unsafe { core::slice::from_raw_parts(b as *const Guid as *const u8, 16) };
    a_bytes == b_bytes
}

// ============================================================================
// Memory map dump
// ============================================================================

const MEM_TYPE_NAMES: &[&str] = &[
    "Reserved",      // 0
    "LoaderCode",    // 1
    "LoaderData",    // 2
    "BSCode",        // 3
    "BSData",        // 4
    "RTCode",        // 5
    "RTData",        // 6
    "Conventional",  // 7
    "Unusable",      // 8
    "ACPIReclaim",   // 9
    "ACPINvs",       // 10
    "MMIO",          // 11
    "MMIOPortSpace", // 12
    "PalCode",       // 13
    "Persistent",    // 14
];

fn mem_type_name(t: u32) -> &'static str {
    if (t as usize) < MEM_TYPE_NAMES.len() {
        MEM_TYPE_NAMES[t as usize]
    } else {
        "Unknown"
    }
}

fn dump_memory_map(con: &Console, system_table: *mut SystemTable) {
    con.print_str("======== UEFI MEMORY MAP ========\r\n");

    let bs = unsafe { (*system_table).boot_services };
    if bs.is_null() {
        con.print_str("ERROR: BootServices is NULL\r\n");
        return;
    }

    // First call to get required size
    let mut map_size: usize = 0;
    let mut map_key: usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_ver: u32 = 0;

    let status = unsafe {
        ((*bs).get_memory_map)(
            &mut map_size,
            core::ptr::null_mut(),
            &mut map_key,
            &mut desc_size,
            &mut desc_ver,
        )
    };

    if status != Status::BUFFER_TOO_SMALL {
        con.print_str("ERROR: GetMemoryMap initial call failed\r\n");
        return;
    }

    // Add extra space for the allocation itself
    map_size += 4 * desc_size;

    // Allocate buffer
    let mut buffer: *mut core::ffi::c_void = core::ptr::null_mut();
    let status = unsafe { ((*bs).allocate_pool)(efi::LOADER_DATA, map_size, &mut buffer) };
    if status != Status::SUCCESS || buffer.is_null() {
        con.print_str("ERROR: AllocatePool failed\r\n");
        return;
    }

    // Get the actual memory map
    let status = unsafe {
        ((*bs).get_memory_map)(
            &mut map_size,
            buffer as *mut MemoryDescriptor,
            &mut map_key,
            &mut desc_size,
            &mut desc_ver,
        )
    };
    if status != Status::SUCCESS {
        con.print_str("ERROR: GetMemoryMap failed\r\n");
        unsafe { ((*bs).free_pool)(buffer) };
        return;
    }

    let num_entries = map_size / desc_size;
    con.print_str("DescriptorSize=");
    con.print_dec(desc_size as u64);
    con.print_str(" DescriptorVersion=");
    con.print_dec(desc_ver as u64);
    con.print_str(" Entries=");
    con.print_dec(num_entries as u64);
    con.newline();
    con.print_str(
        "  #  Type            PhysStart        VirtStart        Pages      Attribute\r\n",
    );

    for i in 0..num_entries {
        let entry =
            unsafe { &*((buffer as *const u8).add(i * desc_size) as *const MemoryDescriptor) };

        // Index
        if (i as u64) < 10 {
            con.print_str("  ");
        } else if (i as u64) < 100 {
            con.print_str(" ");
        }
        con.print_dec(i as u64);
        con.print_str("  ");

        // Type name (padded)
        let tname = mem_type_name(entry.r#type);
        con.print_str(tname);
        // Pad to 16 chars
        let pad = if tname.len() < 16 {
            16 - tname.len()
        } else {
            1
        };
        for _ in 0..pad {
            con.print_str(" ");
        }

        // PhysStart
        con.print_hex_u64(entry.physical_start);
        con.print_str(" ");

        // VirtStart
        con.print_hex_u64(entry.virtual_start);
        con.print_str(" ");

        // Pages
        con.print_hex_u64(entry.number_of_pages);
        con.print_str(" ");

        // Attribute
        con.print_hex_u64(entry.attribute);

        con.newline();
    }

    con.print_str("======== END MEMORY MAP ========\r\n");

    unsafe { ((*bs).free_pool)(buffer) };
}

// ============================================================================
// ACPI dump (acpidump-compatible format)
// ============================================================================

/// RSDP structure (ACPI 2.0+)
#[repr(C, packed)]
struct Rsdp {
    signature: [u8; 8], // "RSD PTR "
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

/// ACPI table header
#[repr(C, packed)]
struct AcpiHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

fn dump_acpi_table_hex(con: &Console, addr: u64, len: u32, sig: &[u8; 4]) {
    // Print header line like acpidump: "  DSDT @ 0x00000000DEADBEEF (length 0x1234)"
    // Then hex dump in format:
    //   0000: XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX  ................

    // Signature as string
    let sig_chars: [u8; 4] = *sig;
    for &b in &sig_chars {
        let mut buf = [b as u16, 0];
        if b < 0x20 || b > 0x7e {
            buf[0] = b'.' as u16;
        }
        unsafe {
            ((*con.con_out).output_string)(con.con_out, buf.as_ptr() as *mut Char16);
        }
    }

    con.print_str(" @ 0x");
    con.print_hex_u64(addr);
    con.print_str(" (");
    con.print_dec(len as u64);
    con.print_str(" bytes)\r\n");

    // Hex dump
    let data = unsafe { core::slice::from_raw_parts(addr as *const u8, len as usize) };
    let mut offset: u32 = 0;
    for chunk in data.chunks(16) {
        // Offset
        con.print_hex_u16((offset >> 16) as u16);
        con.print_hex_u16(offset as u16);
        con.print_str(": ");

        // Hex bytes
        for (j, &b) in chunk.iter().enumerate() {
            con.print_hex_u8(b);
            if j < 15 {
                con.print_str(" ");
            }
        }
        // Pad if short line
        for _ in chunk.len()..16 {
            con.print_str("   ");
        }

        con.newline();
        offset += chunk.len() as u32;
    }
    con.newline();
}

fn dump_acpi(con: &Console, system_table: *mut SystemTable) {
    con.print_str("======== ACPI TABLES ========\r\n");

    let num_entries = unsafe { (*system_table).number_of_table_entries };
    let config_table = unsafe { (*system_table).configuration_table };

    if config_table.is_null() {
        con.print_str("ERROR: ConfigurationTable is NULL\r\n");
        return;
    }

    // Find ACPI RSDP (prefer 2.0)
    let mut rsdp_addr: u64 = 0;
    let mut rsdp_ver: u8 = 0;

    for i in 0..num_entries {
        let entry = unsafe { &*config_table.add(i) };
        if guid_eq(&entry.vendor_guid, &ACPI_20_TABLE_GUID) {
            rsdp_addr = entry.vendor_table as u64;
            rsdp_ver = 2;
            break;
        }
        if guid_eq(&entry.vendor_guid, &ACPI_TABLE_GUID) && rsdp_ver == 0 {
            rsdp_addr = entry.vendor_table as u64;
            rsdp_ver = 1;
        }
    }

    if rsdp_addr == 0 {
        con.print_str("No ACPI RSDP found\r\n");
        return;
    }

    con.print_str("RSDP @ 0x");
    con.print_hex_u64(rsdp_addr);
    con.print_str(" (version ");
    con.print_dec(rsdp_ver as u64);
    con.print_str(")\r\n");

    // Dump RSDP itself
    let rsdp = unsafe { &*(rsdp_addr as *const Rsdp) };
    let rsdp_len = if rsdp.revision >= 2 { rsdp.length } else { 20 };
    dump_acpi_table_hex(con, rsdp_addr, rsdp_len, b"RSDP");

    // Get XSDT or RSDT
    let (sdt_addr, is_xsdt) = if rsdp.revision >= 2 && rsdp.xsdt_address != 0 {
        (rsdp.xsdt_address, true)
    } else {
        (rsdp.rsdt_address as u64, false)
    };

    if sdt_addr == 0 {
        con.print_str("No XSDT/RSDT found\r\n");
        return;
    }

    // Read and dump XSDT/RSDT header
    let sdt_hdr = unsafe { &*(sdt_addr as *const AcpiHeader) };
    let sdt_len = sdt_hdr.length;
    let sdt_sig = sdt_hdr.signature;
    dump_acpi_table_hex(con, sdt_addr, sdt_len, &sdt_sig);

    // Parse table pointers from XSDT/RSDT
    let header_size = core::mem::size_of::<AcpiHeader>() as u32;
    let entries_size = sdt_len - header_size;
    let ptr_size: u32 = if is_xsdt { 8 } else { 4 };
    let num_tables = entries_size / ptr_size;

    con.print_str("Found ");
    con.print_dec(num_tables as u64);
    con.print_str(" ACPI tables\r\n");

    for i in 0..num_tables {
        let ptr_offset = (header_size + i * ptr_size) as usize;
        let table_addr: u64 = if is_xsdt {
            unsafe {
                core::ptr::read_unaligned((sdt_addr as *const u8).add(ptr_offset) as *const u64)
            }
        } else {
            unsafe {
                core::ptr::read_unaligned((sdt_addr as *const u8).add(ptr_offset) as *const u32)
                    as u64
            }
        };

        if table_addr == 0 {
            continue;
        }

        let hdr = unsafe { &*(table_addr as *const AcpiHeader) };
        let sig = hdr.signature;
        let len = hdr.length;

        // Sanity check
        if len < 36 || len > 0x100000 {
            con.print_str("  Skipping table with bad length ");
            con.print_hex_u32(len);
            con.newline();
            continue;
        }

        dump_acpi_table_hex(con, table_addr, len, &sig);
    }

    // Also dump DSDT if we find FADT
    for i in 0..num_tables {
        let ptr_offset = (header_size + i * ptr_size) as usize;
        let table_addr: u64 = if is_xsdt {
            unsafe {
                core::ptr::read_unaligned((sdt_addr as *const u8).add(ptr_offset) as *const u64)
            }
        } else {
            unsafe {
                core::ptr::read_unaligned((sdt_addr as *const u8).add(ptr_offset) as *const u32)
                    as u64
            }
        };
        if table_addr == 0 {
            continue;
        }
        let hdr = unsafe { &*(table_addr as *const AcpiHeader) };
        if &hdr.signature == b"FACP" && hdr.length >= 148 {
            // FADT: X_DSDT at offset 140 (8 bytes), DSDT at offset 40 (4 bytes)
            let dsdt_addr = unsafe {
                let x_dsdt =
                    core::ptr::read_unaligned((table_addr as *const u8).add(140) as *const u64);
                if x_dsdt != 0 {
                    x_dsdt
                } else {
                    core::ptr::read_unaligned((table_addr as *const u8).add(40) as *const u32)
                        as u64
                }
            };
            if dsdt_addr != 0 {
                let dsdt_hdr = unsafe { &*(dsdt_addr as *const AcpiHeader) };
                if dsdt_hdr.length >= 36 && dsdt_hdr.length < 0x100000 {
                    dump_acpi_table_hex(con, dsdt_addr, dsdt_hdr.length, &dsdt_hdr.signature);
                }
            }
        }
    }

    con.print_str("======== END ACPI ========\r\n");
}

// ============================================================================
// SMBIOS dump
// ============================================================================

fn dump_smbios(con: &Console, system_table: *mut SystemTable) {
    con.print_str("======== SMBIOS ========\r\n");

    let num_entries = unsafe { (*system_table).number_of_table_entries };
    let config_table = unsafe { (*system_table).configuration_table };

    if config_table.is_null() {
        con.print_str("ERROR: ConfigurationTable is NULL\r\n");
        return;
    }

    // Find SMBIOS (prefer 3.0)
    let mut smbios_addr: u64 = 0;
    let mut smbios_ver: u8 = 0;

    for i in 0..num_entries {
        let entry = unsafe { &*config_table.add(i) };
        if guid_eq(&entry.vendor_guid, &SMBIOS3_TABLE_GUID) {
            smbios_addr = entry.vendor_table as u64;
            smbios_ver = 3;
            break;
        }
        if guid_eq(&entry.vendor_guid, &SMBIOS_TABLE_GUID) && smbios_ver == 0 {
            smbios_addr = entry.vendor_table as u64;
            smbios_ver = 2;
        }
    }

    if smbios_addr == 0 {
        con.print_str("No SMBIOS entry point found\r\n");
        con.print_str("======== END SMBIOS ========\r\n");
        return;
    }

    con.print_str("SMBIOS v");
    con.print_dec(smbios_ver as u64);
    con.print_str(" entry point @ 0x");
    con.print_hex_u64(smbios_addr);
    con.newline();

    if smbios_ver == 3 {
        // SMBIOS 3.0 64-bit entry point (24 bytes minimum)
        // struct { anchor[5], checksum, length, major, minor, docrev, entry_revision,
        //          reserved, max_struct_size(u32), struct_table_address(u64) }
        let ep = unsafe { core::slice::from_raw_parts(smbios_addr as *const u8, 32) };
        con.print_str("Entry Point:\r\n");
        for chunk in ep.chunks(16) {
            for &b in chunk {
                con.print_hex_u8(b);
                con.print_str(" ");
            }
            con.newline();
        }
        // Table address at offset 16 (8 bytes)
        let table_addr =
            unsafe { core::ptr::read_unaligned((smbios_addr as *const u8).add(16) as *const u64) };
        // Max size at offset 12 (4 bytes)
        let max_size =
            unsafe { core::ptr::read_unaligned((smbios_addr as *const u8).add(12) as *const u32) };
        con.print_str("Table @ 0x");
        con.print_hex_u64(table_addr);
        con.print_str(" MaxSize=");
        con.print_dec(max_size as u64);
        con.newline();

        // Dump the structure table (limit to max_size or 8KB)
        let dump_size = if max_size > 8192 { 8192 } else { max_size };
        if table_addr != 0 && dump_size > 0 {
            con.print_str("Structure Table:\r\n");
            let data =
                unsafe { core::slice::from_raw_parts(table_addr as *const u8, dump_size as usize) };
            let mut offset: u32 = 0;
            for chunk in data.chunks(16) {
                con.print_hex_u16((offset >> 16) as u16);
                con.print_hex_u16(offset as u16);
                con.print_str(": ");
                for &b in chunk {
                    con.print_hex_u8(b);
                    con.print_str(" ");
                }
                con.newline();
                offset += chunk.len() as u32;
            }
        }
    } else {
        // SMBIOS 2.x entry point (31 bytes)
        let ep = unsafe { core::slice::from_raw_parts(smbios_addr as *const u8, 31) };
        con.print_str("Entry Point:\r\n");
        for chunk in ep.chunks(16) {
            for &b in chunk {
                con.print_hex_u8(b);
                con.print_str(" ");
            }
            con.newline();
        }
        // Table address at offset 24 (4 bytes)
        let table_addr =
            unsafe { core::ptr::read_unaligned((smbios_addr as *const u8).add(24) as *const u32) }
                as u64;
        // Table length at offset 22 (2 bytes)
        let table_len =
            unsafe { core::ptr::read_unaligned((smbios_addr as *const u8).add(22) as *const u16) };
        con.print_str("Table @ 0x");
        con.print_hex_u64(table_addr);
        con.print_str(" Length=");
        con.print_dec(table_len as u64);
        con.newline();

        let dump_size = if table_len > 8192 { 8192 } else { table_len };
        if table_addr != 0 && dump_size > 0 {
            con.print_str("Structure Table:\r\n");
            let data =
                unsafe { core::slice::from_raw_parts(table_addr as *const u8, dump_size as usize) };
            let mut offset: u32 = 0;
            for chunk in data.chunks(16) {
                con.print_hex_u16((offset >> 16) as u16);
                con.print_hex_u16(offset as u16);
                con.print_str(": ");
                for &b in chunk {
                    con.print_hex_u8(b);
                    con.print_str(" ");
                }
                con.newline();
                offset += chunk.len() as u32;
            }
        }
    }

    con.print_str("======== END SMBIOS ========\r\n");
}

// ============================================================================
// Configuration table dump
// ============================================================================

fn dump_config_tables(con: &Console, system_table: *mut SystemTable) {
    con.print_str("======== CONFIGURATION TABLES ========\r\n");

    let num_entries = unsafe { (*system_table).number_of_table_entries };
    let config_table = unsafe { (*system_table).configuration_table };

    con.print_str("NumberOfTableEntries=");
    con.print_dec(num_entries as u64);
    con.newline();

    if config_table.is_null() {
        con.print_str("ConfigurationTable is NULL\r\n");
    } else {
        for i in 0..num_entries {
            let entry = unsafe { &*config_table.add(i) };
            let g = &entry.vendor_guid;
            let b = unsafe { core::slice::from_raw_parts(g as *const Guid as *const u8, 16) };
            con.print_str("  [");
            con.print_dec(i as u64);
            con.print_str("] GUID=");
            // Print as standard GUID format
            con.print_hex_u32(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            con.print_str("-");
            con.print_hex_u16(u16::from_le_bytes([b[4], b[5]]));
            con.print_str("-");
            con.print_hex_u16(u16::from_le_bytes([b[6], b[7]]));
            con.print_str("-");
            con.print_hex_u8(b[8]);
            con.print_hex_u8(b[9]);
            con.print_str("-");
            for j in 10..16 {
                con.print_hex_u8(b[j]);
            }
            con.print_str(" Addr=0x");
            con.print_hex_u64(entry.vendor_table as u64);

            // Label known GUIDs
            if guid_eq(g, &ACPI_20_TABLE_GUID) {
                con.print_str(" (ACPI 2.0)");
            } else if guid_eq(g, &ACPI_TABLE_GUID) {
                con.print_str(" (ACPI 1.0)");
            } else if guid_eq(g, &SMBIOS3_TABLE_GUID) {
                con.print_str(" (SMBIOS 3.0)");
            } else if guid_eq(g, &SMBIOS_TABLE_GUID) {
                con.print_str(" (SMBIOS 2.x)");
            }

            con.newline();
        }
    }

    con.print_str("======== END CONFIGURATION TABLES ========\r\n");
}

// ============================================================================
// System table info
// ============================================================================

fn dump_system_info(con: &Console, system_table: *mut SystemTable) {
    con.print_str("======== SYSTEM TABLE ========\r\n");

    let st = unsafe { &*system_table };

    con.print_str("Signature=0x");
    con.print_hex_u64(st.hdr.signature);
    con.print_str(" Revision=0x");
    con.print_hex_u32(st.hdr.revision);
    con.newline();

    con.print_str("FirmwareVendor=");
    // Read UCS-2 string
    if !st.firmware_vendor.is_null() {
        let mut p = st.firmware_vendor;
        unsafe {
            while *p != 0 {
                let c = *p as u8;
                if c >= 0x20 && c < 0x7f {
                    let buf = [c as u16, 0];
                    ((*con.con_out).output_string)(con.con_out, buf.as_ptr() as *mut Char16);
                }
                p = p.add(1);
            }
        }
    }
    con.newline();

    con.print_str("FirmwareRevision=0x");
    con.print_hex_u32(st.firmware_revision);
    con.newline();

    con.print_str("BootServices=0x");
    con.print_hex_u64(st.boot_services as u64);
    con.newline();

    con.print_str("RuntimeServices=0x");
    con.print_hex_u64(st.runtime_services as u64);
    con.newline();

    con.print_str("======== END SYSTEM TABLE ========\r\n");
}

// ============================================================================
// Entry point
// ============================================================================

#[no_mangle]
pub extern "efiapi" fn efi_main(_image_handle: Handle, system_table: *mut SystemTable) -> Status {
    let con = Console::new(system_table);

    con.print_str("\r\n");
    con.print_str("==========================================================\r\n");
    con.print_str("  fw-dump: UEFI Firmware Comparison Tool\r\n");
    con.print_str("  Dumps memory map, ACPI, SMBIOS to serial for comparison\r\n");
    con.print_str("==========================================================\r\n");
    con.print_str("\r\n");

    dump_system_info(&con, system_table);
    con.newline();

    dump_config_tables(&con, system_table);
    con.newline();

    dump_memory_map(&con, system_table);
    con.newline();

    dump_acpi(&con, system_table);
    con.newline();

    dump_smbios(&con, system_table);
    con.newline();

    con.print_str("==========================================================\r\n");
    con.print_str("  fw-dump complete. Halting.\r\n");
    con.print_str("==========================================================\r\n");

    // Stall for 10 seconds so serial output can flush
    let bs = unsafe { (*system_table).boot_services };
    if !bs.is_null() {
        unsafe { ((*bs).stall)(10_000_000) }; // 10 seconds in microseconds
    }

    Status::SUCCESS
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
