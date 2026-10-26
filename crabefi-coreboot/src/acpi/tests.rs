use super::*;
use acpi::{
    address::{AddressSpace, GenericAddress, MappedGas},
    aml::{Interpreter, namespace::AmlName, object::Object},
    registers::{FixedRegisters, Pm1ControlRegisterBlock, Pm1EventRegisterBlock},
};
use alloc::{boxed::Box, string::ToString, sync::Arc, vec};
use core::str::FromStr;

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
        .load_table(&include_bytes!("../../tests/fixtures/elan.aml")[36..])
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
    let (gpio, pin, active_low) = device.gpio.unwrap();
    assert_eq!(
        (gpio.base, gpio.size, pin, active_low),
        (0xfed81500, 0x400, 9, true)
    );
    // A resource source naming no controller is not described.
    let path = name("\\_SB.I2C2.MISS");
    assert!(peripherals::connection(&interpreter, &path, Vec::new()).is_none());
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
    discover_namespace_devices(&interpreter, &mut info, &mut connections);
    assert_eq!(
        connections,
        touchpad(&interpreter).into_iter().collect::<Vec<_>>()
    );
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
