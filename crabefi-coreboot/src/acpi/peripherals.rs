//! Describe ACPI I2C devices to CrabEFI's peripheral drivers.
//!
//! A device's `I2cSerialBus` and `GpioInt` resource sources are resolved by
//! namespace path, never by four-character basename. Controllers are taken
//! over as coreboot left them: no clocks, pads or power are changed.
use super::{CrabEfiHandler, connections};
use acpi::aml::{
    Interpreter,
    namespace::AmlName,
    object::{Object, WrappedObject},
    resource::{
        AddressSpaceResourceType, MemoryRangeDescriptor, Resource, resource_descriptor_list,
    },
};
use alloc::{rc::Rc, string::String, vec, vec::Vec};
use core::{cell::RefCell, str::FromStr};
use crabefi::peripheral::{I2cBus, I2cPeripheral, InputLine, Interrupt, Peripheral};
use embedded_hal_bus::i2c::RcDevice;

/// An MMIO controller found through a resource source.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Controller {
    pub path: AmlName,
    pub hid: String,
    pub base: u64,
    pub size: u64,
}

/// An I2C device and the controllers it is wired to, before any hardware
/// access.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Connection {
    pub ids: Vec<String>,
    pub bus: Controller,
    pub address: u8,
    pub speed_hz: u32,
    pub gpio: Option<(Controller, u16, bool)>,
}

/// Take over a firmware-initialized I2C controller.
type AttachI2c = unsafe fn(base: u64, size: u64, speed_hz: u32) -> Option<I2cBus>;
/// Open one input pin of a GPIO controller.
type OpenPin = unsafe fn(base: u64, size: u64, pin: u16) -> Option<InputLine>;

const I2C_CONTROLLERS: &[(&str, AttachI2c)] = &[("AMDI0010", designware)];
const GPIO_CONTROLLERS: &[(&str, OpenPin)] = &[("AMD0030", amd_gpio)];

unsafe fn designware(base: u64, size: u64, speed_hz: u32) -> Option<I2cBus> {
    let (base, size) = (usize::try_from(base).ok()?, usize::try_from(size).ok()?);
    // SAFETY: the caller's identity-mapped, exclusively owned controller.
    match unsafe {
        crabefi_hw::designware::DesignWare::attach(base, size, speed_hz, crabefi::time::Delay)
    } {
        Ok(bus) => Some(I2cBus::new(bus)),
        Err(error) => {
            log::warn!("ACPI: DesignWare I2C at {:#x} unusable: {:?}", base, error);
            None
        }
    }
}

unsafe fn amd_gpio(base: u64, size: u64, pin: u16) -> Option<InputLine> {
    let (base, size) = (usize::try_from(base).ok()?, usize::try_from(size).ok()?);
    // SAFETY: the caller's identity-mapped controller; reads have no effect.
    let pin = unsafe { crabefi_hw::amd_gpio::GpioPin::new(base, size, pin) }.ok()?;
    Some(InputLine::new(pin))
}

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

/// Whether coreboot left the device in D0. Never power up an unused bus or
/// claim a controller left in D3. Some firmware has no `_PSC` method.
fn powered(interpreter: &Interpreter<CrabEfiHandler>, path: &AmlName) -> bool {
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
    scope: &AmlName,
    name: &AmlName,
) -> Option<AmlName> {
    let resolved = if name.search_rules_apply() {
        interpreter
            .namespace
            .lock()
            .search_for_level(name, scope)
            .ok()?
    } else {
        name.resolve(scope).ok()?
    };
    resolved.normalize_absolute().ok()
}

fn id(object: &Object) -> Option<String> {
    match object {
        Object::String(id) => Some(id.clone()),
        Object::Integer(value) => {
            let mut encoded = [0; 16];
            let len = super::decode_eisaid_into(*value, &mut encoded);
            core::str::from_utf8(&encoded[..len]).ok().map(String::from)
        }
        _ => None,
    }
}

/// `_HID` followed by every `_CID`, in order of preference.
pub(super) fn ids(interpreter: &Interpreter<CrabEfiHandler>, path: &AmlName) -> Vec<String> {
    let hid = evaluate(interpreter, path, "_HID").ok().flatten();
    let cid = evaluate(interpreter, path, "_CID").ok().flatten();
    let cids = cid.iter().flat_map(|cid| match &**cid {
        Object::Package(ids) => ids.iter().filter_map(|id_object| id(id_object)).collect(),
        other => id(other).into_iter().collect::<Vec<_>>(),
    });
    hid.iter().filter_map(|hid| id(hid)).chain(cids).collect()
}

/// The single writable MMIO window of a present, powered controller whose
/// `_HID` is one of `supported`.
fn controller(
    interpreter: &Interpreter<CrabEfiHandler>,
    path: AmlName,
    supported: impl Iterator<Item = &'static str>,
) -> Option<Controller> {
    if !present(interpreter, &path) || !powered(interpreter, &path) {
        return None;
    }
    let hid = evaluate(interpreter, &path, "_HID").ok()??;
    let hid = id(&hid).filter(|hid| supported.into_iter().any(|known| known == hid))?;
    let crs = evaluate(interpreter, &path, "_CRS").ok()??;
    // The acpi crate's descriptor parser assumes complete headers.
    let Object::Buffer(bytes) = &*crs else {
        return None;
    };
    connections::records(bytes).ok()?;
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
    if spans.next().is_some() || base == 0 || base & 3 != 0 || base.checked_add(size).is_none() {
        return None;
    }
    Some(Controller {
        path,
        hid,
        base,
        size,
    })
}

/// Resolve an I2C device's connections without touching hardware.
pub(super) fn connection(
    interpreter: &Interpreter<CrabEfiHandler>,
    path: &AmlName,
    ids: Vec<String>,
) -> Option<Connection> {
    if !present(interpreter, path) || !powered(interpreter, path) {
        return None;
    }
    let crs = evaluate(interpreter, path, "_CRS").ok()??;
    let Object::Buffer(bytes) = &*crs else {
        return None;
    };
    let resources = match connections::parse(bytes) {
        Ok(resources) => resources,
        Err(error) => {
            log::warn!("ACPI: {}: {}", path, error);
            return None;
        }
    };
    let i2c = resources.i2c?;
    let bus_path = resolve(interpreter, path, &AmlName::from_str(i2c.source).ok()?)?;
    let Some(bus) = controller(
        interpreter,
        bus_path.clone(),
        I2C_CONTROLLERS.iter().map(|(hid, _)| *hid),
    ) else {
        log::info!("ACPI: {}: unsupported I2C controller {}", path, bus_path);
        return None;
    };
    let gpio = match resources.interrupt {
        None => None,
        Some(interrupt) => {
            let gpio_path = resolve(
                interpreter,
                path,
                &AmlName::from_str(interrupt.source).ok()?,
            )?;
            let Some(gpio) = controller(
                interpreter,
                gpio_path.clone(),
                GPIO_CONTROLLERS.iter().map(|(hid, _)| *hid),
            ) else {
                log::info!("ACPI: {}: unsupported GPIO controller {}", path, gpio_path);
                return None;
            };
            // Independent register blocks; never reinterpret the pin as a
            // CPU interrupt or an MMIO address.
            if bus.base < gpio.base + gpio.size && gpio.base < bus.base + bus.size {
                return None;
            }
            Some((gpio, interrupt.pin, interrupt.active_low))
        }
    };
    Some(Connection {
        ids,
        bus,
        address: i2c.address,
        speed_hz: i2c.speed_hz,
        gpio,
    })
}

/// Take over the controllers of resolved connections. Devices on one
/// controller share it.
///
/// # Safety
/// Controller MMIO is identity mapped and owned by no other CrabEFI driver.
pub(super) unsafe fn adopt(connections: Vec<Connection>) -> Vec<Peripheral> {
    let mut buses: Vec<(AmlName, Option<Rc<RefCell<I2cBus>>>)> = Vec::new();
    connections
        .into_iter()
        .filter_map(|connection| {
            let interrupt = match &connection.gpio {
                None => None,
                Some((gpio, pin, active_low)) => {
                    let open = GPIO_CONTROLLERS.iter().find(|(hid, _)| *hid == gpio.hid)?.1;
                    // SAFETY: the caller's controller contract.
                    let line = unsafe { open(gpio.base, gpio.size, *pin) }?;
                    Some(Interrupt::Level {
                        line,
                        active_low: *active_low,
                    })
                }
            };
            let bus = &connection.bus;
            let shared = match buses.iter().find(|(path, _)| *path == bus.path) {
                Some((_, shared)) => shared.clone(),
                None => {
                    let attach = I2C_CONTROLLERS.iter().find(|(hid, _)| *hid == bus.hid)?.1;
                    // SAFETY: the caller's controller contract; attached once.
                    let shared = unsafe { attach(bus.base, bus.size, connection.speed_hz) }
                        .map(|bus| Rc::new(RefCell::new(bus)));
                    buses.push((bus.path.clone(), shared.clone()));
                    shared
                }
            }?;
            log::info!(
                "ACPI: I2C device {:?} on {} at {:#x}",
                connection.ids,
                bus.path,
                connection.address
            );
            Some(Peripheral::I2c(I2cPeripheral {
                ids: connection.ids,
                bus: I2cBus::new(RcDevice::new(shared)),
                address: connection.address,
                interrupt,
            }))
        })
        .collect()
}
