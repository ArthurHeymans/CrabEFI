//! Pure PCI command-register enable policy.

const IO_ENABLE: u16 = 1 << 0;
const MEMORY_ENABLE: u16 = 1 << 1;
const BUS_MASTER_ENABLE: u16 = 1 << 2;

/// Enable only decode modes backed by assigned BARs, plus optional bus mastering.
pub const fn enabled_command(
    original: u16,
    has_io_bar: bool,
    has_memory_bar: bool,
    bus_master: bool,
) -> u16 {
    (original & !(IO_ENABLE | MEMORY_ENABLE | BUS_MASTER_ENABLE))
        | if has_io_bar { IO_ENABLE } else { 0 }
        | if has_memory_bar { MEMORY_ENABLE } else { 0 }
        | if bus_master { BUS_MASTER_ENABLE } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enables_only_assigned_decode_types() {
        assert_eq!(enabled_command(0, false, true, true), 0b110);
        assert_eq!(enabled_command(0, true, false, true), 0b101);
        assert_eq!(enabled_command(0, true, true, true), 0b111);
    }

    #[test]
    fn disables_unsupported_decode_and_preserves_unrelated_bits() {
        let original = 0x457;
        let enabled = enabled_command(original, false, true, false);
        assert_eq!(enabled & 0x7, MEMORY_ENABLE);
        assert_eq!(enabled & !0x7, original & !0x7);
    }
}
