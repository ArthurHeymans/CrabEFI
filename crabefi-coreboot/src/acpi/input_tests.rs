use super::*;
use acpi::{
    address::{AddressSpace, GenericAddress, MappedGas},
    aml::{Interpreter, namespace::AmlName, object::Object},
    registers::{FixedRegisters, Pm1ControlRegisterBlock, Pm1EventRegisterBlock},
};
use alloc::{boxed::Box, sync::Arc, vec};
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
fn resources(interpreter: &Interpreter<CrabEfiHandler>) -> alloc::vec::Vec<u8> {
    let crs = interpreter
        .evaluate(AmlName::from_str("\\_SB.I2C2.TPAD._CRS").unwrap(), vec![])
        .unwrap();
    match &*crs {
        Object::Buffer(bytes) => bytes.clone(),
        _ => panic!("_CRS must be a buffer"),
    }
}
fn discover(interpreter: &Interpreter<CrabEfiHandler>) -> Option<crate::touchpad::Touchpad> {
    let mut info = PlatformInfo::new();
    let mut touchpad = None;
    discover_namespace_devices(interpreter, &mut info, &mut touchpad);
    touchpad
}

#[test]
fn resolves_relative_sources_and_distinguishes_identically_named_controllers() {
    let interpreter = interpreter();
    let device = discover(&interpreter).unwrap();
    assert_eq!((device.i2c_base, device.i2c_size), (0xfedc4000, 0x1000));
    assert_eq!((device.gpio_base, device.gpio_size), (0xfed81500, 0x400));
    assert_eq!(
        (
            device.address,
            device.speed_hz,
            device.pin,
            device.active_low
        ),
        (0x15, 400_000, 9, true)
    );
    // Connection-only discovery must not depend on free MMIO-device slots.
    let mut info = PlatformInfo::new();
    for _ in 0..crabefi::fdt::MAX_DSDT_DEVICES {
        assert!(info.dsdt_devices.push(DsdtDevice::empty()).is_ok());
    }
    let mut device = None;
    discover_namespace_devices(&interpreter, &mut info, &mut device);
    assert!(device.is_some());
}
#[test]
fn absent_disabled_or_powered_down_devices_are_not_bound() {
    for method in ["\\DSTP", "\\DSBS", "\\DSGP", "\\SLPB", "\\POFF"] {
        let interpreter = interpreter();
        interpreter
            .evaluate(AmlName::from_str(method).unwrap(), vec![])
            .unwrap();
        assert!(discover(&interpreter).is_none(), "{method}");
    }
}
#[test]
fn bounded_connection_parser_rejects_truncation_bad_offsets_and_ambiguous_connections() {
    let interpreter = interpreter();
    let bytes = resources(&interpreter);
    let parsed = input_resources::parse(&bytes).unwrap();
    assert_eq!(parsed.i2c.unwrap().source, "^^I2C2");
    assert_eq!(parsed.interrupt.unwrap().source, "\\_SB.GPIO");
    for end in 0..bytes.len() {
        assert!(input_resources::parse(&bytes[..end]).is_err());
    }
    let records = input_resources::records(&bytes).unwrap();
    let serial_length = records[0].len();
    let mut invalid = bytes.clone();
    invalid[7] = 1; // ten-bit address mode
    assert!(input_resources::parse(&invalid).is_err());
    let mut invalid = bytes.clone();
    invalid[serial_length + 14..serial_length + 16].fill(0xff); // pin table outside descriptor
    assert!(input_resources::parse(&invalid).is_err());
    let mut duplicated = bytes[..serial_length].to_vec();
    duplicated.extend_from_slice(&bytes);
    assert!(input_resources::parse(&duplicated).is_err());
}
