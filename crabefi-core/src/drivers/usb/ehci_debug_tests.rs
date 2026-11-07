use super::*;

#[test]
fn debug_port_uses_the_capability_bar_and_offset() {
    let mut bars = [pci::PciBar::default(); 6];
    bars[2] = pci::PciBar {
        bar_type: pci::BarType::Memory64,
        address: 0x1_0000_0000,
        ..pci::PciBar::default()
    };
    let cap = DEBUG_CAPABILITY::BAR.val(3) + DEBUG_CAPABILITY::OFFSET.val(0xa0);
    assert_eq!(debug_port_address(cap.value, &bars), Some(0x1_0000_00a0));
}

#[test]
fn debug_port_rejects_reserved_bar_numbers_and_io_bars() {
    let mut bars = [pci::PciBar::default(); 6];
    bars[0] = pci::PciBar {
        bar_type: pci::BarType::Io,
        address: 0x1000,
        ..pci::PciBar::default()
    };
    for index in [0, 1, 7] {
        assert_eq!(
            debug_port_address(DEBUG_CAPABILITY::BAR.val(index).value, &bars),
            None
        );
    }
}

#[test]
fn debug_port_rejects_unassigned_bars_and_unaligned_offsets() {
    let mut bars = [pci::PciBar::default(); 6];
    bars[0].bar_type = pci::BarType::Memory32;
    let cap = DEBUG_CAPABILITY::BAR.val(1);
    assert_eq!(debug_port_address(cap.value, &bars), None);
    bars[0].address = 0xfef0_0000;
    assert_eq!(
        debug_port_address((cap + DEBUG_CAPABILITY::OFFSET.val(3)).value, &bars),
        None
    );
}

#[test]
fn debug_port_rejects_address_overflow() {
    let mut bars = [pci::PciBar::default(); 6];
    bars[0] = pci::PciBar {
        bar_type: pci::BarType::Memory64,
        address: u64::MAX - 15,
        ..pci::PciBar::default()
    };
    let cap = DEBUG_CAPABILITY::BAR.val(1) + DEBUG_CAPABILITY::OFFSET.val(0x20);
    assert_eq!(debug_port_address(cap.value, &bars), None);
}
