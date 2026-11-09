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

#[test]
fn debug_port_checks_the_complete_register_against_known_bar_size() {
    let mut bars = [pci::PciBar::default(); 6];
    bars[0] = pci::PciBar {
        bar_type: pci::BarType::Memory32,
        address: 0x1000,
        size: 0x100,
        ..pci::PciBar::default()
    };
    let bar = DEBUG_CAPABILITY::BAR.val(1);
    let last_register = bar + DEBUG_CAPABILITY::OFFSET.val(0xfc);
    assert_eq!(debug_port_address(last_register.value, &bars), Some(0x10fc));
    let outside_bar = bar + DEBUG_CAPABILITY::OFFSET.val(0x100);
    assert_eq!(debug_port_address(outside_bar.value, &bars), None);
    bars[0].size -= 1;
    assert_eq!(debug_port_address(last_register.value, &bars), None);
}

#[test]
fn debug_port_rejects_unaligned_bases_and_32_bit_bar_overflow() {
    let mut bars = [pci::PciBar::default(); 6];
    bars[0] = pci::PciBar {
        bar_type: pci::BarType::Memory32,
        address: 0x1001,
        ..pci::PciBar::default()
    };
    let bar = DEBUG_CAPABILITY::BAR.val(1);
    assert_eq!(debug_port_address(bar.value, &bars), None);
    // An invalid offset must not compensate for an invalid BAR alignment.
    assert_eq!(
        debug_port_address((bar + DEBUG_CAPABILITY::OFFSET.val(3)).value, &bars),
        None
    );
    bars[0].address = u64::from(u32::MAX) - 15;
    let cap = bar + DEBUG_CAPABILITY::OFFSET.val(0x10);
    assert_eq!(debug_port_address(cap.value, &bars), None);
}

#[test]
fn active_debug_port_requires_all_ownership_bits_and_one_snapshot() {
    let mut bars = [pci::PciBar::default(); 6];
    bars[0] = pci::PciBar {
        bar_type: pci::BarType::Memory32,
        address: 0x1000,
        size: 0x100,
        ..pci::PciBar::default()
    };
    let cap = DEBUG_CAPABILITY::BAR.val(1) + DEBUG_CAPABILITY::OFFSET.val(0xa0);
    for owner in [false, true] {
        for enabled in [false, true] {
            for in_use in [false, true] {
                let control = DEBUG_CONTROL::OWNER.val(u32::from(owner))
                    + DEBUG_CONTROL::ENABLED.val(u32::from(enabled))
                    + DEBUG_CONTROL::IN_USE.val(u32::from(in_use));
                let mut reads = 0;
                assert_eq!(
                    debug_port_active(
                        pci::CommandRegister::MEMORY_ENABLE,
                        cap.value,
                        &bars,
                        |address| {
                            assert_eq!(address, 0x10a0);
                            reads += 1;
                            control.value
                        },
                    ),
                    owner && enabled && in_use
                );
                assert_eq!(reads, 1);
            }
        }
    }
    assert!(!debug_port_active(
        pci::CommandRegister::MEMORY_ENABLE,
        cap.value,
        &bars,
        |_| u32::MAX,
    ));
}

#[test]
fn disabled_decode_and_invalid_addresses_do_not_read_mmio() {
    let mut bars = [pci::PciBar::default(); 6];
    bars[0] = pci::PciBar {
        bar_type: pci::BarType::Memory32,
        address: 0x1000,
        size: 0x100,
        ..pci::PciBar::default()
    };
    let cap = DEBUG_CAPABILITY::BAR.val(1);
    assert!(!debug_port_active(
        pci::CommandRegister::empty(),
        cap.value,
        &bars,
        |_| panic!("disabled memory decode must not read MMIO"),
    ));
    let outside_bar = cap + DEBUG_CAPABILITY::OFFSET.val(0x100);
    assert!(!debug_port_active(
        pci::CommandRegister::MEMORY_ENABLE,
        outside_bar.value,
        &bars,
        |_| panic!("invalid debug address must not read MMIO"),
    ));
}
