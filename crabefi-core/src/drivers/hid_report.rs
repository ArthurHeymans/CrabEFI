//! Transport-independent HID keyboard and pointer report decoding.
//!
//! Shared by USB HID and HID-over-I2C. The descriptor, not the transport or
//! vendor identity, defines field locations, report IDs and coordinate ranges.

use super::pointer::PointerReport;
use super::usb::hid_keyboard::KeyboardReport;
use alloc::vec::Vec;
use hidreport::{Field, FieldAttributes, Report, ReportDescriptor, Usage, VariableField};

const GENERIC_DESKTOP: u16 = 0x01;
const MOUSE: u16 = 0x02;
const KEYBOARD: u16 = 0x06;
const X: u16 = 0x30;
const Y: u16 = 0x31;
const WHEEL: u16 = 0x38;
const KEY_CODES: u16 = 0x07;
const BUTTONS: u16 = 0x09;

fn usage(page: u16, id: u16) -> u32 {
    (u32::from(page) << 16) | u32::from(id)
}

fn in_collection(field: &VariableField, collection: u32) -> bool {
    field
        .collections
        .iter()
        .any(|c| c.usages().iter().any(|u| u32::from(u) == collection))
}

fn variables(report: &impl Report, collection: u32) -> impl Iterator<Item = &VariableField> + '_ {
    report.fields().iter().filter_map(move |field| match field {
        Field::Variable(field) if in_collection(field, collection) => Some(field),
        _ => None,
    })
}

fn variable(report: &impl Report, collection: u32, usage: u32) -> Option<VariableField> {
    variables(report, collection)
        .find(|field| u32::from(&field.usage) == usage)
        .cloned()
}

/// Mouse fields of one input report, in relative or absolute mode.
pub(super) struct Mouse {
    pub report_id: Option<u8>,
    pub size: usize,
    x: VariableField,
    y: VariableField,
    wheel: Option<VariableField>,
    buttons: Vec<(u32, VariableField)>,
}

impl Mouse {
    pub fn find(descriptor: &ReportDescriptor) -> Option<Self> {
        let collection = usage(GENERIC_DESKTOP, MOUSE);
        descriptor.input_reports().iter().find_map(|report| {
            let x = variable(report, collection, usage(GENERIC_DESKTOP, X))?;
            let y = variable(report, collection, usage(GENERIC_DESKTOP, Y))?;
            if x.is_relative() != y.is_relative() {
                return None;
            }
            if !x.is_relative()
                && [&x, &y]
                    .iter()
                    .any(|f| i32::from(f.logical_maximum) <= i32::from(f.logical_minimum))
            {
                return None;
            }
            let buttons = variables(report, collection)
                .filter_map(|field| {
                    let Usage {
                        usage_page,
                        usage_id,
                    } = field.usage;
                    let index = u16::from(usage_id);
                    (u16::from(usage_page) == BUTTONS && (1..=3).contains(&index))
                        .then(|| (1 << (index - 1), field.clone()))
                })
                .collect();
            Some(Self {
                report_id: (*report.report_id()).map(u8::from),
                size: report.size_in_bytes(),
                x,
                y,
                wheel: variable(report, collection, usage(GENERIC_DESKTOP, WHEEL)),
                buttons,
            })
        })
    }

    pub fn read(&self, report: &[u8]) -> Option<PointerReport> {
        if !matches(report, self.report_id, self.size) {
            return None;
        }
        let value = |field: &VariableField| field.extract(report).ok().map(i32::from);
        let x = value(&self.x)?;
        let y = value(&self.y)?;
        let absolute = if self.x.is_relative() {
            None
        } else {
            Some((normalize(&self.x, x), normalize(&self.y, y)))
        };
        Some(PointerReport {
            dx: if absolute.is_none() { x } else { 0 },
            dy: if absolute.is_none() { y } else { 0 },
            dz: self.wheel.as_ref().and_then(value).map_or(0, |dz| -dz),
            buttons: self
                .buttons
                .iter()
                .filter(|(_, field)| value(field).is_some_and(|pressed| pressed != 0))
                .fold(0, |buttons, (bit, _)| buttons | bit),
            absolute,
        })
    }
}

/// Normalize a validated absolute field to the full u16 coordinate range.
fn normalize(field: &VariableField, value: i32) -> u16 {
    let minimum = i64::from(i32::from(field.logical_minimum));
    let maximum = i64::from(i32::from(field.logical_maximum));
    let value = i64::from(value).clamp(minimum, maximum);
    ((value - minimum) * i64::from(u16::MAX) / (maximum - minimum)) as u16
}

/// Boot-keyboard-like fields of one input report.
pub(super) struct Keyboard {
    pub report_id: Option<u8>,
    pub size: usize,
    modifiers: Vec<(u8, VariableField)>,
    keys: hidreport::ArrayField,
}

impl Keyboard {
    pub fn find(descriptor: &ReportDescriptor) -> Option<Self> {
        let collection = usage(GENERIC_DESKTOP, KEYBOARD);
        descriptor.input_reports().iter().find_map(|report| {
            let keys = report.fields().iter().find_map(|field| match field {
                Field::Array(field)
                    if field
                        .collections
                        .iter()
                        .any(|c| c.usages().iter().any(|u| u32::from(u) == collection))
                        && field
                            .usages()
                            .first()
                            .is_some_and(|u| u16::from(u.usage_page) == KEY_CODES) =>
                {
                    Some(field.clone())
                }
                _ => None,
            })?;
            let modifiers = variables(report, collection)
                .filter_map(|field| {
                    let id = u16::from(field.usage.usage_id);
                    (u16::from(field.usage.usage_page) == KEY_CODES && (0xe0..=0xe7).contains(&id))
                        .then(|| (1 << (id - 0xe0), field.clone()))
                })
                .collect();
            Some(Self {
                report_id: (*report.report_id()).map(u8::from),
                size: report.size_in_bytes(),
                modifiers,
                keys,
            })
        })
    }

    pub fn read(&self, report: &[u8]) -> Option<KeyboardReport> {
        if !matches(report, self.report_id, self.size) {
            return None;
        }
        let modifiers = self
            .modifiers
            .iter()
            .filter(|(_, field)| field.extract(report).is_ok_and(|v| u32::from(v) != 0))
            .fold(0, |modifiers, (bit, _)| modifiers | bit);
        let mut keys = [0; 6];
        self.keys
            .extract(report)
            .ok()?
            .iter()
            .map(|key| u8::try_from(u32::from(key)).unwrap_or(0))
            .filter(|&key| key > 3)
            .take(keys.len())
            .enumerate()
            .for_each(|(slot, key)| keys[slot] = key);
        Some(KeyboardReport {
            modifiers,
            reserved: 0,
            keys,
        })
    }
}

/// Whether `report` has the expected ID and complete payload.
pub(super) fn matches(report: &[u8], id: Option<u8>, size: usize) -> bool {
    report.len() >= size.max(1) && id.is_none_or(|id| report[0] == id)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    // Insyde 0b1f:03e9: three buttons, two absolute u16 axes (0..32767), wheel.
    pub const ABSOLUTE_MOUSE: &[u8] = &[
        0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x09, 0x01, 0xa1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29,
        0x03, 0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02, 0x95, 0x01, 0x75, 0x05,
        0x81, 0x01, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x16, 0x00, 0x00, 0x26, 0xff, 0x7f, 0x36,
        0x00, 0x00, 0x46, 0xff, 0x7f, 0x66, 0x00, 0x00, 0x75, 0x10, 0x95, 0x02, 0x81, 0x22, 0x05,
        0x01, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7f, 0x35, 0x81, 0x45, 0x7f, 0x75, 0x08, 0x95, 0x01,
        0x81, 0x06, 0xc0, 0xc0,
    ];

    #[test]
    fn absolute_mouse_uses_descriptor_ranges_and_wheel_sign() {
        let descriptor = ReportDescriptor::try_from(ABSOLUTE_MOUSE).unwrap();
        let mouse = Mouse::find(&descriptor).unwrap();
        assert_eq!(mouse.size, 6);
        let report = mouse.read(&[1, 0xff, 0x7f, 0, 0, 0xff]).unwrap();
        assert_eq!(report.absolute, Some((u16::MAX, 0)));
        assert_eq!(
            (report.dx, report.dy, report.dz, report.buttons),
            (0, 0, 1, 1)
        );
        assert!(mouse.read(&[0; 5]).is_none());
        let report = mouse.read(&[0, 0, 0x40, 0, 0x40, 0]).unwrap();
        assert_eq!(report.absolute, Some((32768, 32768)));
    }
}
