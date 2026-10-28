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
use alloc::{boxed::Box, rc::Rc, string::String, vec, vec::Vec};
use core::{cell::RefCell, str::FromStr};
use crabefi::peripheral::{
    I2cBus, I2cPeripheral, InputLine, Interrupt, InterruptLatch, Peripheral,
};
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
    pub gpio: Option<(Controller, Line)>,
    pub hid_descriptor_register: Option<u16>,
}

/// A `GpioInt` pin of a GPIO controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Line {
    pub pin: u16,
    pub active_low: bool,
    /// Edge- rather than level-triggered.
    pub edge: bool,
}

/// Take over a firmware-initialized I2C controller.
type AttachI2c = unsafe fn(base: u64, size: u64, speed_hz: u32) -> Option<I2cBus>;
/// Open one input pin of a GPIO controller.
/// Open a `GpioInt` of a GPIO controller as it was configured.
type OpenInterrupt = unsafe fn(base: u64, size: u64, line: &Line) -> Option<Interrupt>;

const I2C_CONTROLLERS: &[(&str, AttachI2c)] = &[("AMDI0010", designware)];
const GPIO_CONTROLLERS: &[(&str, OpenInterrupt)] = &[("AMD0030", amd_gpio)];

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

/// The pad's interrupt status, which coreboot configures the pad to latch.
struct AmdLatch(crabefi_hw::amd_gpio::GpioPin);

impl InterruptLatch for AmdLatch {
    fn take(&mut self) -> bool {
        self.0.take_interrupt_status()
    }
}

unsafe fn amd_gpio(base: u64, size: u64, line: &Line) -> Option<Interrupt> {
    let (base, size) = (usize::try_from(base).ok()?, usize::try_from(size).ok()?);
    // SAFETY: the caller's identity-mapped controller; only the latch of this
    // pad is ever written.
    let pin = unsafe { crabefi_hw::amd_gpio::GpioPin::new(base, size, line.pin) }.ok()?;
    Some(if line.edge {
        Interrupt::Latched(Box::new(AmdLatch(pin)))
    } else {
        Interrupt::Level {
            line: InputLine::new(pin),
            active_low: line.active_low,
        }
    })
}

fn evaluate(
    interpreter: &Interpreter<CrabEfiHandler>,
    path: &AmlName,
    member: &str,
) -> Result<Option<WrappedObject>, acpi::aml::AmlError> {
    interpreter.evaluate_if_present(AmlName::from_str(member)?.resolve(path)?, vec![])
}

pub(super) fn present(interpreter: &Interpreter<CrabEfiHandler>, path: &AmlName) -> bool {
    match evaluate(interpreter, path, "_STA") {
        Ok(None) => true,
        Ok(Some(value)) => matches!(&*value, Object::Integer(sta) if sta & 0x0b == 0x0b),
        Err(_) => false,
    }
}

/// Whether coreboot left the device in D0. Never power up an unused bus or
/// claim a controller left in D3. Some firmware has no `_PSC` method.
pub(super) fn powered(interpreter: &Interpreter<CrabEfiHandler>, path: &AmlName) -> bool {
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
            Some((
                gpio,
                Line {
                    pin: interrupt.pin,
                    active_low: interrupt.active_low,
                    edge: interrupt.edge,
                },
            ))
        }
    };
    let hid_descriptor_register = ids
        .iter()
        .any(|id| matches!(id.as_str(), "PNP0C50" | "ACPI0C50"))
        .then(|| hid_descriptor_register(interpreter, path))
        .flatten();
    Some(Connection {
        ids,
        bus,
        address: i2c.address,
        speed_hz: i2c.speed_hz,
        gpio,
        hid_descriptor_register,
    })
}

/// The HID descriptor register from the HID-over-I2C `_DSM`, function 1.
fn hid_descriptor_register(
    interpreter: &Interpreter<CrabEfiHandler>,
    path: &AmlName,
) -> Option<u16> {
    // 3cdff6f7-4267-4555-ad05-b30a3d8938de in ACPI ToUUID byte order.
    const HID_I2C_DSM: [u8; 16] = [
        0xf7, 0xf6, 0xdf, 0x3c, 0x67, 0x42, 0x55, 0x45, 0xad, 0x05, 0xb3, 0x0a, 0x3d, 0x89, 0x38,
        0xde,
    ];
    let args = vec![
        WrappedObject::new(Object::Buffer(HID_I2C_DSM.to_vec())),
        WrappedObject::new(Object::Integer(1)),
        WrappedObject::new(Object::Integer(1)),
        WrappedObject::new(Object::Package(Vec::new())),
    ];
    let dsm = AmlName::from_str("_DSM").ok()?.resolve(path).ok()?;
    match &*interpreter.evaluate_if_present(dsm, args).ok()?? {
        Object::Integer(register) => u16::try_from(*register).ok(),
        _ => None,
    }
}

struct SharedBus<T> {
    path: AmlName,
    speed_hz: u32,
    bus: Rc<RefCell<T>>,
}

/// Share only successfully adopted controllers at the validated speed. A
/// device-specific attachment failure must not hide other devices on the bus.
fn shared_bus<T>(
    buses: &mut Vec<SharedBus<T>>,
    path: &AmlName,
    speed_hz: u32,
    attach: impl FnOnce() -> Option<T>,
) -> Option<Rc<RefCell<T>>> {
    if let Some(shared) = buses.iter().find(|shared| shared.path == *path) {
        if shared.speed_hz != speed_hz {
            log::warn!(
                "ACPI: I2C device on {} requests {} Hz, adopted bus uses {} Hz",
                path,
                speed_hz,
                shared.speed_hz
            );
            return None;
        }
        return Some(shared.bus.clone());
    }
    let bus = Rc::new(RefCell::new(attach()?));
    buses.push(SharedBus {
        path: path.clone(),
        speed_hz,
        bus: bus.clone(),
    });
    Some(bus)
}

/// Take over the controllers of resolved connections. Devices on one
/// controller share it.
///
/// # Safety
/// Controller MMIO is identity mapped and owned by no other CrabEFI driver.
pub(super) unsafe fn adopt(connections: Vec<Connection>) -> Vec<Peripheral> {
    let mut buses = Vec::new();
    connections
        .into_iter()
        .filter_map(|connection| {
            let interrupt = match &connection.gpio {
                None => None,
                Some((gpio, line)) => {
                    let open = GPIO_CONTROLLERS.iter().find(|(hid, _)| *hid == gpio.hid)?.1;
                    // SAFETY: the caller's controller contract.
                    Some(unsafe { open(gpio.base, gpio.size, line) }?)
                }
            };
            let bus = &connection.bus;
            let shared = shared_bus(&mut buses, &bus.path, connection.speed_hz, || {
                let attach = I2C_CONTROLLERS.iter().find(|(hid, _)| *hid == bus.hid)?.1;
                // SAFETY: the caller's controller contract; adopted once on success.
                unsafe { attach(bus.base, bus.size, connection.speed_hz) }
            })?;
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
                hid_descriptor_register: connection.hid_descriptor_register,
            }))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_buses_validate_each_devices_speed_without_reattaching() {
        let path = AmlName::from_str("\\_SB.I2C2").unwrap();
        let mut buses = Vec::new();
        let first = shared_bus(&mut buses, &path, 400_000, || Some(())).unwrap();
        assert!(shared_bus(&mut buses, &path, 100_000, || panic!("already adopted")).is_none());
        let second = shared_bus(&mut buses, &path, 400_000, || panic!("already adopted")).unwrap();
        assert!(Rc::ptr_eq(&first, &second));
    }

    #[test]
    fn failed_attachment_does_not_hide_a_later_compatible_device() {
        let path = AmlName::from_str("\\_SB.I2C2").unwrap();
        let mut buses = Vec::new();
        assert!(shared_bus(&mut buses, &path, 100_000, || None::<()>).is_none());
        assert!(buses.is_empty());
        assert!(shared_bus(&mut buses, &path, 400_000, || Some(())).is_some());
        assert_eq!(buses.len(), 1);
    }
}
