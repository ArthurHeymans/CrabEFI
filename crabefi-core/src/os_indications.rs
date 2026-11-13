//! One-shot requests in the UEFI global OsIndications variable.

pub(crate) const BOOT_TO_FW_UI: u64 = 1;

/// The text menu is always built, including settings without boot media.
/// A framebuffer needs a ready keyboard, or a pointer with the graphical UI.
/// A bidirectional native serial console supplies both input and output.
/// An output-only platform DebugOutput is not sufficient.
/// The retained journal is also required so OS runtime NV writes can survive
/// reset, not just writes from pre-ExitBootServices tools such as GRUB.
pub(crate) const fn firmware_ui_supported(
    writable_persistence: bool,
    retained_staging_ready: bool,
    framebuffer: bool,
    keyboard: bool,
    graphical_pointer: bool,
    serial_console: bool,
) -> bool {
    writable_persistence
        && retained_staging_ready
        && (serial_console || (framebuffer && (keyboard || graphical_pointer)))
}

/// Return the request with only FW_UI cleared, rejecting malformed values.
fn cleared_request(data: &[u8]) -> Option<[u8; 8]> {
    let value = u64::from_le_bytes(data.try_into().ok()?);
    (value & BOOT_TO_FW_UI != 0).then(|| (value & !BOOT_TO_FW_UI).to_le_bytes())
}

/// Accept setup only when its one-shot clear was successfully persisted.
fn consume_request(data: &[u8], persist_clear: impl FnOnce(&[u8; 8]) -> bool) -> bool {
    cleared_request(data).is_some_and(|cleared| persist_clear(&cleared))
}

/// Whether a well-formed request is pending, without consuming it.
pub(crate) fn firmware_ui_request_pending() -> bool {
    use crate::efi::runtime_image::client::variables;
    use crabefi_efi_types::secure_boot::EFI_GLOBAL_VARIABLE_GUID;

    let guid = r_efi::efi::Guid::from_bytes(&EFI_GLOBAL_VARIABLE_GUID);
    let name: alloc::vec::Vec<u16> = "OsIndications\0".encode_utf16().collect();
    variables::get(&guid, &name)
        .is_some_and(|(attributes, data)| attributes == 7 && cleared_request(&data).is_some())
}

/// Consume only our bit, through the authoritative runtime variable facade,
/// after import is complete. Never enter setup unless the clear was durable:
/// a failed write must not turn every later reset into another setup request.
pub(crate) fn take_firmware_ui_request(available: bool) -> bool {
    if !available {
        return false;
    }
    use crate::efi::runtime_image::client::variables;
    use crabefi_efi_types::secure_boot::EFI_GLOBAL_VARIABLE_GUID;
    use r_efi::efi::{Guid, Status};

    let guid = Guid::from_bytes(&EFI_GLOBAL_VARIABLE_GUID);
    let name: alloc::vec::Vec<u16> = "OsIndications\0".encode_utf16().collect();
    let Some((attributes, data)) = variables::get(&guid, &name) else {
        return false;
    };
    // UEFI defines this as NV | BS | RT. In particular, a volatile request
    // cannot demonstrate the persistent clear required for one-shot handling.
    if attributes != 7 {
        log::warn!(
            "Ignoring OsIndications with invalid attributes: {:#x}",
            attributes
        );
        return false;
    }
    let consumed = consume_request(&data, |cleared| {
        let status = variables::set(&guid, &name, attributes, cleared);
        if status != Status::SUCCESS {
            log::warn!("Failed to consume firmware UI request: {:?}", status);
        }
        status == Status::SUCCESS
    });
    if consumed {
        log::info!("Consumed firmware UI request; OsIndications FW_UI cleared persistently");
    }
    consumed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_requires_runtime_persistence_and_an_interactive_console() {
        for persistent in [false, true] {
            for retained in [false, true] {
                for display in [false, true] {
                    for keyboard in [false, true] {
                        for pointer in [false, true] {
                            for serial in [false, true] {
                                assert_eq!(
                                    firmware_ui_supported(
                                        persistent, retained, display, keyboard, pointer, serial
                                    ),
                                    persistent
                                        && retained
                                        && (serial || (display && (keyboard || pointer)))
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn output_only_setup_does_not_consume_a_request() {
        let available = firmware_ui_supported(true, true, true, false, false, false);
        assert!(!available);
        // No runtime access is needed or allowed when setup has no input.
        assert!(!take_firmware_ui_request(available));
    }

    #[test]
    fn clears_only_fw_ui_and_is_one_shot() {
        for other_bits in [0, 0x0c, 0xffff_ffff_ffff_fffe] {
            let cleared = cleared_request(&(other_bits | BOOT_TO_FW_UI).to_le_bytes()).unwrap();
            assert_eq!(u64::from_le_bytes(cleared), other_bits);
            assert_eq!(cleared_request(&cleared), None);
        }
    }

    #[test]
    fn setup_requires_a_successful_persistent_clear() {
        let requested = 0x0du64.to_le_bytes();
        assert!(!consume_request(&requested, |_| false));
        assert!(consume_request(&requested, |cleared| *cleared == 0x0cu64.to_le_bytes()));
        assert!(!consume_request(&0x0cu64.to_le_bytes(), |_| panic!(
            "no request to write"
        )));
        assert!(!consume_request(&[1; 9], |_| panic!("malformed request")));
    }

    #[test]
    fn absent_or_malformed_request_does_not_enter_setup() {
        assert_eq!(cleared_request(&0x0cu64.to_le_bytes()), None);
        for length in [0, 1, 7, 9, 16] {
            assert_eq!(cleared_request(&[1; 16][..length]), None);
        }
    }
}
