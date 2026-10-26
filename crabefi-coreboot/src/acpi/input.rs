//! Resolve a peripheral's connection resource sources through the AML namespace.
//! Never associate controllers by their four-character basename or scan a bus.
use super::{CrabEfiHandler, input_resources};
use crate::touchpad::Touchpad;
use acpi::aml::{
    Interpreter,
    namespace::AmlName,
    object::{Object, WrappedObject},
    resource::{
        AddressSpaceResourceType, MemoryRangeDescriptor, Resource, resource_descriptor_list,
    },
};
use alloc::vec;
use core::str::FromStr;

fn evaluate(
    interpreter: &Interpreter<CrabEfiHandler>,
    path: &AmlName,
    member: &str,
) -> Result<Option<WrappedObject>, acpi::aml::AmlError> {
    interpreter.evaluate_if_present(AmlName::from_str(member)?.resolve(path)?, vec![])
}
fn present(interpreter: &Interpreter<CrabEfiHandler>, path: &AmlName) -> bool {
    match evaluate(interpreter, path, "_STA") {
        Ok(None) => true,
        Ok(Some(value)) => matches!(&*value, Object::Integer(sta) if sta & 0x0b == 0x0b),
        Err(_) => false,
    }
}
fn powered(interpreter: &Interpreter<CrabEfiHandler>, path: &AmlName) -> bool {
    // Adopt coreboot's initialized D0 hardware; don't power up an unused bus
    // or claim a controller left in D3. Some firmware has no _PSC method.
    let in_d0 = match evaluate(interpreter, path, "_PSC") {
        Ok(None) => true,
        Ok(Some(value)) => matches!(&*value, Object::Integer(0)),
        Err(_) => false,
    };
    if !in_d0 {
        return false;
    }
    match evaluate(interpreter, path, "_PR0") {
        Ok(None) => true,
        Ok(Some(value)) => {
            let Object::Package(resources) = &*value else {
                return false;
            };
            resources.len() <= 16
                && resources.iter().all(|resource| {
                    let Object::NamePath { name, scope } = &**resource else {
                        return false;
                    };
                    let Some(power_path) = resolve(interpreter, scope, name) else {
                        return false;
                    };
                    let is_power_resource = interpreter
                        .namespace
                        .lock()
                        .get(power_path.clone())
                        .is_ok_and(|object| matches!(&*object, Object::PowerResource { .. }));
                    is_power_resource
                        && matches!(evaluate(interpreter, &power_path, "_STA"),
                    Ok(Some(state)) if matches!(&*state, Object::Integer(1)))
                })
        }
        Err(_) => false,
    }
}
fn resolve(
    interpreter: &Interpreter<CrabEfiHandler>,
    peripheral: &AmlName,
    name: &AmlName,
) -> Option<AmlName> {
    let resolved = if name.search_rules_apply() {
        interpreter
            .namespace
            .lock()
            .search_for_level(name, peripheral)
            .ok()?
    } else {
        name.resolve(peripheral).ok()?
    };
    resolved.normalize_absolute().ok()
}
fn controller(
    interpreter: &Interpreter<CrabEfiHandler>,
    path: &AmlName,
    expected_hid: &str,
) -> Option<(u64, u64)> {
    if !present(interpreter, path) || !powered(interpreter, path) {
        return None;
    }
    let hid = evaluate(interpreter, path, "_HID").ok()??;
    let mut encoded = [0; 16];
    let matches = match &*hid {
        Object::String(hid) => hid == expected_hid,
        Object::Integer(value) => {
            let len = super::decode_eisaid_into(*value, &mut encoded);
            &encoded[..len] == expected_hid.as_bytes()
        }
        _ => false,
    };
    if !matches {
        return None;
    }
    let crs = evaluate(interpreter, path, "_CRS").ok()??;
    if let Object::Buffer(bytes) = &*crs {
        input_resources::records(bytes).ok()?;
    } else {
        return None;
    }
    let mut spans = resource_descriptor_list(crs)
        .ok()?
        .into_iter()
        .filter_map(|resource| match resource {
            Resource::MemoryRange(MemoryRangeDescriptor::FixedLocation {
                is_writable: true,
                base_address,
                range_length,
            }) => Some((u64::from(base_address), u64::from(range_length))),
            Resource::AddressSpace(memory)
                if memory.resource_type == AddressSpaceResourceType::MemoryRange
                    && memory.is_minimum_address_fixed
                    && memory.is_maximum_address_fixed
                    && memory.translation_offset == 0 =>
            {
                Some((memory.address_range.0, memory.length))
            }
            _ => None,
        });
    let (base, size) = spans.next()?;
    if spans.next().is_some()
        || base == 0
        || base & 3 != 0
        || size < 0x100
        || base.checked_add(size).is_none()
    {
        return None;
    }
    Some((base, size))
}

pub(super) fn discover(
    interpreter: &Interpreter<CrabEfiHandler>,
    peripheral: &AmlName,
) -> Option<Touchpad> {
    if !present(interpreter, peripheral) || !powered(interpreter, peripheral) {
        return None;
    }
    let crs = evaluate(interpreter, peripheral, "_CRS").ok()??;
    let Object::Buffer(bytes) = &*crs else {
        return None;
    };
    let connections = match input_resources::parse(bytes) {
        Ok(value) => value,
        Err(error) => {
            log::warn!("ACPI touchpad {}: {}", peripheral, error);
            return None;
        }
    };
    let bus = connections.i2c?;
    let interrupt = connections.interrupt?;
    if !matches!(bus.speed_hz, 100_000 | 400_000) {
        return None;
    }
    let i2c = resolve(
        interpreter,
        peripheral,
        &AmlName::from_str(bus.source).ok()?,
    )?;
    let gpio = resolve(
        interpreter,
        peripheral,
        &AmlName::from_str(interrupt.source).ok()?,
    )?;
    let (i2c_base, i2c_size) = controller(interpreter, &i2c, "AMDI0010")?;
    let (gpio_base, gpio_size) = controller(interpreter, &gpio, "AMD0030")?;
    if u64::from(interrupt.pin) * 4 + 4 > gpio_size {
        return None;
    }
    // Independent, disjoint register blocks; never reinterpret the touchpad's
    // address/pin as a CPU interrupt number or as a physical MMIO address.
    if i2c_base < gpio_base + gpio_size && gpio_base < i2c_base + i2c_size {
        return None;
    }
    log::info!(
        "ACPI touchpad {} uses {} at {:#x}, {} pin {}",
        peripheral,
        i2c,
        bus.address,
        gpio,
        interrupt.pin
    );
    Some(Touchpad {
        i2c_base,
        i2c_size,
        address: bus.address,
        speed_hz: bus.speed_hz,
        gpio_base,
        gpio_size,
        pin: interrupt.pin,
        active_low: interrupt.active_low,
    })
}
