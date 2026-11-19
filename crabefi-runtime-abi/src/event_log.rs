//! Identity of the firmware-owned boot event log variable.

/// CrabEFI settings GUID in EFI byte order.
///
/// Canonical UUID: `9e80634c-cdc7-41d5-a345-4a297f9c7d1a`.
pub const SETTINGS_VARIABLE_GUID: [u8; 16] = [
    0x4c, 0x63, 0x80, 0x9e, 0xc7, 0xcd, 0xd5, 0x41, 0xa3, 0x45, 0x4a, 0x29, 0x7f, 0x9c, 0x7d, 0x1a,
];

/// Boot event log; only firmware writes it, before the first boot option.
pub const EVENT_LOG_VARIABLE_NAME: &[u16] = &[
    b'C' as u16,
    b'r' as u16,
    b'a' as u16,
    b'b' as u16,
    b'E' as u16,
    b'F' as u16,
    b'I' as u16,
    b'E' as u16,
    b'v' as u16,
    b'e' as u16,
    b'n' as u16,
    b't' as u16,
    b'L' as u16,
    b'o' as u16,
    b'g' as u16,
];

/// Return whether a variable is the firmware-owned boot event log.
pub fn is_event_log_variable(guid: &[u8; 16], name: &[u16]) -> bool {
    if guid != &SETTINGS_VARIABLE_GUID {
        return false;
    }
    let name_len = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    name.get(..name_len) == Some(EVENT_LOG_VARIABLE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_log_requires_exact_guid_and_name() {
        let mut terminated = EVENT_LOG_VARIABLE_NAME.to_vec();
        terminated.push(0);
        assert!(is_event_log_variable(
            &SETTINGS_VARIABLE_GUID,
            EVENT_LOG_VARIABLE_NAME
        ));
        assert!(is_event_log_variable(&SETTINGS_VARIABLE_GUID, &terminated));

        let mut other_guid = SETTINGS_VARIABLE_GUID;
        other_guid[0] ^= 1;
        assert!(!is_event_log_variable(&other_guid, EVENT_LOG_VARIABLE_NAME));
        assert!(!is_event_log_variable(
            &SETTINGS_VARIABLE_GUID,
            &EVENT_LOG_VARIABLE_NAME[..14]
        ));
    }
}
