use super::*;
use acpi::{
    address::{AddressSpace, GenericAddress, MappedGas},
    aml::{Interpreter, namespace::AmlName, object::Object},
    registers::{FixedRegisters, Pm1ControlRegisterBlock, Pm1EventRegisterBlock},
};
use alloc::{boxed::Box, string::ToString, sync::Arc, vec};
use core::str::FromStr;

#[cfg(target_arch = "x86_64")]
#[test]
fn tpm2_lookup_reads_unaligned_xsdt_entry_and_checks_table_length() {
    #[repr(align(8))]
    struct AlignedXsdt([u8; 44]);
    let mut xsdt = AlignedXsdt([0; 44]);
    let mut rsdp = [0u8; 36];
    let mut tpm2 = [0u8; 52];
    rsdp[..8].copy_from_slice(b"RSD PTR ");
    rsdp[15] = 2;
    xsdt.0[..4].copy_from_slice(b"XSDT");
    xsdt.0[4..8].copy_from_slice(&44u32.to_le_bytes());
    tpm2[..4].copy_from_slice(b"TPM2");
    tpm2[4..8].copy_from_slice(&52u32.to_le_bytes());
    tpm2[40..48].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    tpm2[48..52].copy_from_slice(&7u32.to_le_bytes());
    xsdt.0[36..44].copy_from_slice(&(tpm2.as_ptr() as u64).to_le_bytes());
    rsdp[24..32].copy_from_slice(&(xsdt.0.as_ptr() as u64).to_le_bytes());

    // SAFETY: The RSDP and all tables it names are in the local buffers.
    let result = unsafe { find_tpm2_table(rsdp.as_ptr() as u64) }.unwrap();
    assert_eq!(result.control_area, 0x1122_3344_5566_7788);
    assert_eq!(result.start_method, 7);

    tpm2[4..8].copy_from_slice(&51u32.to_le_bytes());
    xsdt.0[36..44].copy_from_slice(&(tpm2.as_ptr() as u64).to_le_bytes());
    rsdp[24..32].copy_from_slice(&(xsdt.0.as_ptr() as u64).to_le_bytes());
    // SAFETY: Same buffers as above, now with a short advertised TPM2 prefix.
    assert!(unsafe { find_tpm2_table(rsdp.as_ptr() as u64) }.is_none());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn tpm2_log_area_update_checks_length_and_checksums_the_full_table() {
    let mut table = [0u8; 80];
    table[..4].copy_from_slice(b"TPM2");
    table[4..8].copy_from_slice(&80u32.to_le_bytes());
    table[76..].copy_from_slice(&[1, 2, 3, 4]);
    assert_eq!(set_tpm2_log_area(&mut table[..75], 1, 2), None);
    let address = 0x1122_3344_5566_7788u64;
    assert_eq!(set_tpm2_log_area(&mut table, 4096, address), Some(()));
    assert_eq!(table[64..68], 4096u32.to_le_bytes());
    assert_eq!(table[68..76], address.to_le_bytes());
    assert_eq!(table[76..], [1, 2, 3, 4]);
    assert_eq!(table.into_iter().fold(0u8, u8::wrapping_add), 0);
}

fn interpreter() -> Interpreter<CrabEfiHandler> {
    let handler = CrabEfiHandler::new();
    let memory = Box::leak(Box::new([0u64; 512]));
    let gas = GenericAddress {
        address_space: AddressSpace::SystemMemory,
        bit_width: 32,
        bit_offset: 0,
        access_size: 3,
        address: memory.as_mut_ptr() as u64,
    };
    // SAFETY: complete, aligned RAM-backed fake register page; no real I/O.
    let event = unsafe { MappedGas::map_gas(gas, &handler) }.unwrap();
    let control = unsafe { MappedGas::map_gas(gas, &handler) }.unwrap();
    // The interpreter API requires Arc; the handler stays on this thread.
    #[allow(clippy::arc_with_non_send_sync)]
    let registers = Arc::new(FixedRegisters {
        pm1_event_registers: Pm1EventRegisterBlock {
            pm1_event_length: 4,
            pm1a: event,
            pm1b: None,
        },
        pm1_control_registers: Pm1ControlRegisterBlock {
            pm1a: control,
            pm1b: None,
        },
    });
    let interpreter = Interpreter::new(handler, 2, registers, None);
    // The checked-in AML is generated from the adjacent, reviewable ASL.
    interpreter
        .load_table(&include_bytes!("../../tests/fixtures/peripherals.aml")[36..])
        .unwrap();
    interpreter
}

fn name(path: &str) -> AmlName {
    AmlName::from_str(path).unwrap()
}

fn touchpad(interpreter: &Interpreter<CrabEfiHandler>) -> Option<peripherals::Connection> {
    let path = name("\\_SB.I2C2.TPAD");
    let ids = peripherals::ids(interpreter, &path);
    peripherals::connection(interpreter, &path, ids)
}

fn resources(interpreter: &Interpreter<CrabEfiHandler>) -> Vec<u8> {
    let crs = interpreter
        .evaluate(name("\\_SB.I2C2.TPAD._CRS"), vec![])
        .unwrap();
    match &*crs {
        Object::Buffer(bytes) => bytes.clone(),
        _ => panic!("_CRS must be a buffer"),
    }
}

#[test]
fn resolves_relative_sources_and_distinguishes_identically_named_controllers() {
    let interpreter = interpreter();
    let device = touchpad(&interpreter).unwrap();
    assert_eq!(device.ids, vec!["ELAN0000".to_string()]);
    assert_eq!(device.bus.path, name("\\_SB.I2C2"));
    assert_eq!((device.bus.base, device.bus.size), (0xfedc4000, 0x1000));
    assert_eq!((device.address, device.speed_hz), (0x15, 400_000));
    let (gpio, line) = device.gpio.unwrap();
    assert_eq!((gpio.base, gpio.size), (0xfed81500, 0x400));
    assert_eq!(
        line,
        peripherals::Line {
            pin: 9,
            active_low: true,
            edge: false
        }
    );
    // A resource source naming no controller is not described.
    let path = name("\\_SB.I2C2.MISS");
    assert!(peripherals::connection(&interpreter, &path, Vec::new()).is_none());
}

#[test]
fn edge_triggered_interrupts_are_described() {
    let interpreter = interpreter();
    let path = name("\\_SB.I2C2.GSC0");
    let ids = peripherals::ids(&interpreter, &path);
    let device = peripherals::connection(&interpreter, &path, ids).unwrap();
    assert_eq!(device.ids, vec!["GOOG0005".to_string()]);
    assert_eq!(device.address, 0x50);
    assert_eq!(
        device.gpio.unwrap().1,
        peripherals::Line {
            pin: 3,
            active_low: true,
            edge: true
        }
    );
}

#[test]
fn hid_devices_carry_their_descriptor_register_from_dsm() {
    let interpreter = interpreter();
    let path = name("\\_SB.I2C2.HIDT");
    let ids = peripherals::ids(&interpreter, &path);
    let device = peripherals::connection(&interpreter, &path, ids).unwrap();
    assert_eq!(
        device.ids,
        vec!["SYNA0001".to_string(), "PNP0C50".to_string()]
    );
    assert_eq!(device.hid_descriptor_register, Some(0x20));
    // Other devices have no HID descriptor.
    assert_eq!(
        touchpad(&interpreter).unwrap().hid_descriptor_register,
        None
    );
}

#[test]
fn absent_disabled_or_powered_down_devices_are_not_described() {
    for method in ["\\DSTP", "\\DSBS", "\\DSGP", "\\SLPB", "\\POFF"] {
        let interpreter = interpreter();
        interpreter.evaluate(name(method), vec![]).unwrap();
        assert!(touchpad(&interpreter).is_none(), "{method}");
    }
}

#[cfg(feature = "ui")]
#[test]
fn a_full_mmio_device_list_does_not_stop_peripheral_discovery() {
    let interpreter = interpreter();
    let mut info = PlatformInfo::new();
    for _ in 0..crabefi::fdt::MAX_DSDT_DEVICES {
        assert!(info.dsdt_devices.push(DsdtDevice::empty()).is_ok());
    }
    let mut connections = Vec::new();
    discover_namespace_devices(&interpreter, &mut info, &mut connections, &mut Vec::new());
    assert!(connections.contains(&touchpad(&interpreter).unwrap()));
}

#[test]
fn supported_mmio_devices_are_described() {
    let interpreter = interpreter();
    let mut mmio = Vec::new();
    discover_namespace_devices(
        &interpreter,
        &mut PlatformInfo::new(),
        &mut Vec::new(),
        &mut mmio,
    );
    let [Peripheral::Mmio(emmc)] = mmio.as_slice() else {
        panic!("expected one MMIO peripheral");
    };
    assert_eq!(emmc.ids, vec!["AMDI0040".to_string()]);
    assert_eq!((emmc.base, emmc.size), (0xfedd5000, 0x1000));
}

#[test]
fn absent_or_powered_down_mmio_devices_are_not_described() {
    for method in ["\\DSTP", "\\SLPB", "\\POFF"] {
        let interpreter = interpreter();
        interpreter.evaluate(name(method), vec![]).unwrap();
        let mut mmio = Vec::new();
        discover_namespace_devices(
            &interpreter,
            &mut PlatformInfo::new(),
            &mut Vec::new(),
            &mut mmio,
        );
        assert!(mmio.is_empty(), "{method}");
    }
}

#[test]
fn connection_parser_rejects_truncation_bad_offsets_and_ambiguous_connections() {
    let interpreter = interpreter();
    let bytes = resources(&interpreter);
    let parsed = connections::parse(&bytes).unwrap();
    assert_eq!(parsed.i2c.unwrap().source, "^^I2C2");
    assert_eq!(parsed.interrupt.unwrap().source, "\\_SB.GPIO");
    for end in 0..bytes.len() {
        assert!(connections::parse(&bytes[..end]).is_err());
    }
    let records = connections::records(&bytes).unwrap();
    let serial_length = records[0].len();
    let mut invalid = bytes.clone();
    invalid[7] = 1; // ten-bit address mode
    assert!(connections::parse(&invalid).is_err());
    let mut invalid = bytes.clone();
    invalid[serial_length + 14..serial_length + 16].fill(0xff); // pin table outside descriptor
    assert!(connections::parse(&invalid).is_err());
    let mut duplicated = bytes[..serial_length].to_vec();
    duplicated.extend_from_slice(&bytes);
    assert!(connections::parse(&duplicated).is_err());
}
