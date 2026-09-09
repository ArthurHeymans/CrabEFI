use super::*;
use alloc::vec::Vec;

fn configuration(interfaces: u8, descriptors: &[u8]) -> Vec<u8> {
    let mut bytes = alloc::vec![9, 2, 0, 0, interfaces, 1, 0, 0x80, 50];
    bytes.extend_from_slice(descriptors);
    let length = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&length.to_le_bytes());
    bytes
}

fn hid_interface(number: u8, alternate: u8, protocol: u8) -> [u8; 9] {
    [9, 4, number, alternate, 1, 3, 1, protocol, 0]
}

const INTERRUPT_IN: [u8; 7] = [7, 5, 0x81, 3, 8, 0, 10];

#[test]
fn reads_complete_configuration_with_hid_after_byte_256() {
    for protocol in [1, 2] {
        let mut descriptors = alloc::vec![0; 255];
        descriptors[0] = 255;
        descriptors[1] = 0xff; // Opaque vendor descriptor before the HID interface.
        descriptors.extend_from_slice(&hid_interface(3, 0, protocol));
        descriptors.extend_from_slice(&INTERRUPT_IN);
        let bytes = configuration(1, &descriptors);
        let mut requests = Vec::new();
        let parsed = read_configuration_with(|buffer| {
            requests.push(buffer.len());
            let length = buffer.len().min(bytes.len());
            buffer[..length].copy_from_slice(&bytes[..length]);
            Ok(length)
        })
        .unwrap();
        assert_eq!(requests, [9, bytes.len()]);
        assert_eq!(parsed.num_interfaces, 1);
        assert_eq!(parsed.interfaces[0].interface_number, 3);
        assert_eq!(parsed.interfaces[0].is_hid_keyboard(), protocol == 1);
        assert_eq!(parsed.interfaces[0].is_hid_mouse(), protocol == 2);
        assert_eq!(parsed.interfaces[0].find_interrupt_in().unwrap().number, 1);
    }
}

#[test]
fn inactive_alternate_settings_never_supply_boot_endpoints() {
    let mut descriptors = alloc::vec![9, 4, 3, 0, 0, 0xff, 0, 0, 0];
    for alternate in 1..=12 {
        descriptors.extend_from_slice(&hid_interface(3, alternate, 1));
        descriptors.extend_from_slice(&INTERRUPT_IN);
    }
    let parsed = parse_configuration_checked(&configuration(1, &descriptors)).unwrap();
    assert_eq!(parsed.num_interfaces, 1);
    assert!(!parsed.interfaces[0].is_hid_keyboard());
    assert!(parsed.interfaces[0].find_interrupt_in().is_none());
}

#[test]
fn parser_capacity_limits_reject_instead_of_returning_partial_devices() {
    let mut descriptors = Vec::new();
    for interface in 0..9 {
        descriptors.extend_from_slice(&hid_interface(interface, 0, 1));
        descriptors.extend_from_slice(&INTERRUPT_IN);
    }
    let bytes = configuration(9, &descriptors);
    assert!(matches!(
        parse_configuration_checked(&bytes),
        Err(UsbError::NotSupported)
    ));
    assert_eq!(parse_configuration(&bytes).num_interfaces, 0);

    let mut descriptors = hid_interface(0, 0, 1).to_vec();
    descriptors[4] = 5;
    for endpoint in 1..=5 {
        let mut ep = INTERRUPT_IN;
        ep[2] = 0x80 | endpoint;
        descriptors.extend_from_slice(&ep);
    }
    assert!(matches!(
        parse_configuration_checked(&configuration(1, &descriptors)),
        Err(UsbError::NotSupported)
    ));
}

#[test]
fn superspeed_hid_bursts_and_nonstandard_payloads_are_explicitly_unsupported() {
    for protocol in [1, 2] {
        let mut descriptors = hid_interface(0, 0, protocol).to_vec();
        descriptors.extend_from_slice(&INTERRUPT_IN);
        descriptors.extend_from_slice(&[6, 48, 0, 0, 8, 0]);
        let bytes = configuration(1, &descriptors);
        assert!(parse_configuration_checked(&bytes).is_ok());
        for (field, value) in [(2, 1), (3, 1), (4, 16)] {
            let mut changed = bytes.clone();
            let offset = changed.len() - 6 + field;
            changed[offset] = value;
            assert!(matches!(
                parse_configuration_checked(&changed),
                Err(UsbError::NotSupported)
            ));
        }
    }
}

#[test]
fn interface_count_mismatch_is_tolerated() {
    let mut descriptors = hid_interface(3, 0, 1).to_vec();
    descriptors.extend_from_slice(&INTERRUPT_IN);
    // bNumInterfaces claims two interfaces but only one is present.
    let bytes = configuration(2, &descriptors);
    let parsed = parse_configuration_checked(&bytes).unwrap();
    assert_eq!(parsed.num_interfaces, 1);
    assert_eq!(parsed.interfaces[0].interface_number, 3);
    assert!(parsed.interfaces[0].is_hid_keyboard());

    // bConfigurationValue == 0 would leave the device unconfigured.
    let mut zero_configuration = bytes;
    zero_configuration[5] = 0;
    assert!(matches!(
        parse_configuration_checked(&zero_configuration),
        Err(UsbError::InvalidParameter)
    ));
}

#[test]
fn truncated_and_malformed_configurations_are_rejected() {
    let mut descriptors = hid_interface(0, 0, 1).to_vec();
    descriptors.extend_from_slice(&INTERRUPT_IN);
    let bytes = configuration(1, &descriptors);
    assert!(parse_configuration_checked(&bytes[..bytes.len() - 1]).is_err());
    let mut short_descriptor = bytes.clone();
    short_descriptor[18] = 1;
    assert!(parse_configuration_checked(&short_descriptor).is_err());
    let result = read_configuration_with(|buffer| {
        let count = if buffer.len() == 9 {
            9
        } else {
            buffer.len() - 1
        };
        buffer[..count].copy_from_slice(&bytes[..count]);
        Ok(count)
    });
    assert!(matches!(result, Err(UsbError::InvalidParameter)));

    let mut oversized_header = bytes[..9].to_vec();
    oversized_header[2..4].copy_from_slice(&4097u16.to_le_bytes());
    let result = read_configuration_with(|buffer| {
        assert_eq!(buffer.len(), 9); // Reject before allocating/fetching the body.
        buffer.copy_from_slice(&oversized_header);
        Ok(9)
    });
    assert!(matches!(result, Err(UsbError::NotSupported)));
}
