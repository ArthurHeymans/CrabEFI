use super::*;
use core::cell::Cell;

struct W1cConfig {
    command_status: Cell<u32>,
    writes: Cell<usize>,
}

impl ConfigRegionAccess for W1cConfig {
    unsafe fn read(&self, _address: PciAddress, _offset: u16) -> u32 {
        self.command_status.get()
    }

    unsafe fn write(&self, _address: PciAddress, _offset: u16, value: u32) {
        let prior = self.command_status.get();
        // Actual PCI command/status shape: low RW, upper write-one-to-clear.
        self.command_status
            .set((prior & 0xffff_0000 & !value) | (value & 0xffff));
        self.writes.set(self.writes.get() + 1);
    }
}

impl PciAccess for W1cConfig {
    fn name(&self) -> &'static str {
        "32-bit-only W1C fixture"
    }
    fn max_offset(&self) -> u16 {
        255
    }
    fn contains_address(&self, _address: PciAddress) -> bool {
        true
    }
}

#[test]
fn missing_subword_backend_must_not_clear_neighboring_w1c_status() {
    let address = PciAddress::new(0, 0, 1, 0);
    for width in [1, 2] {
        let fixture = W1cConfig {
            command_status: Cell::new(0xa900_0123),
            writes: Cell::new(0),
        };
        let result = if width == 1 {
            fixture.try_write8(address, 4, 0x67)
        } else {
            fixture.try_write16(address, 4, 0x4567)
        };
        assert_eq!(
            fixture.command_status.get() & 0xffff_0000,
            0xa900_0000,
            "subword fallback cleared adjacent W1C status: {result:?}"
        );
        assert_eq!(result, Err(ConfigAccessError::OutOfRange));
        assert_eq!(fixture.writes.get(), 0);
    }
}

struct EcamRam {
    access: AnyPciAccess,
    memory: core::ptr::NonNull<u8>,
    layout: alloc::alloc::Layout,
}

impl EcamRam {
    fn new() -> Self {
        let layout = alloc::alloc::Layout::from_size_align(1 << 20, 1 << 20).unwrap();
        // A real, aligned CPU allocation backs exactly one ECAM bus. No
        // production physical-address limits or region checks are bypassed.
        let memory = core::ptr::NonNull::new(unsafe { alloc::alloc::alloc_zeroed(layout) })
            .expect("ECAM fixture allocation");
        let region = PciEcamRegion {
            base: memory.as_ptr() as u64,
            segment: 7,
            bus_start: 0x40,
            bus_end: 0x40,
        };
        Self {
            access: AnyPciAccess::Ecam(EcamAccess::new(&[region]).unwrap()),
            memory,
            layout,
        }
    }
}

impl Drop for EcamRam {
    fn drop(&mut self) {
        unsafe { alloc::alloc::dealloc(self.memory.as_ptr(), self.layout) };
    }
}

#[test]
fn ecam_native_subwords_preserve_every_neighboring_lane() {
    let fixture = EcamRam::new();
    let access = &fixture.access;
    let address = PciAddress::new(7, 0x40, 1, 2);
    for lane in 0..4 {
        access.try_write32(address, 0x40, 0xaabb_ccdd).unwrap();
        access.try_write8(address, 0x40 + lane, 0x12).unwrap();
        assert_eq!(access.try_read8(address, 0x40 + lane), Ok(0x12));
        let shift = lane * 8;
        assert_eq!(
            access.try_read32(address, 0x40),
            Ok((0xaabb_ccdd & !(0xff << shift)) | (0x12 << shift))
        );
    }
    for lane in [0, 2] {
        access.try_write32(address, 0x40, 0xaabb_ccdd).unwrap();
        access.try_write16(address, 0x40 + lane, 0x1234).unwrap();
        assert_eq!(access.try_read16(address, 0x40 + lane), Ok(0x1234));
        let shift = lane * 8;
        assert_eq!(
            access.try_read32(address, 0x40),
            Ok((0xaabb_ccdd & !(0xffff << shift)) | (0x1234 << shift))
        );
    }
}

#[test]
fn ecam_subwords_obey_last_byte_alignment_segment_and_bus_bounds() {
    let fixture = EcamRam::new();
    let access = &fixture.access;
    let last = PciAddress::new(7, 0x40, 31, 7);
    access.try_write16(last, 4094, 0x1234).unwrap();
    access.try_write8(last, 4095, 0x99).unwrap();
    assert_eq!(access.try_read16(last, 4094), Ok(0x9934));
    for offset in [1, 4095, 4096, u16::MAX] {
        assert_eq!(
            access.try_write16(last, offset, 0xffff),
            Err(ConfigAccessError::OutOfRange)
        );
        assert_eq!(
            access.try_read16(last, offset),
            Err(ConfigAccessError::OutOfRange)
        );
    }
    for invalid in [
        PciAddress::new(6, 0x40, 31, 7),
        PciAddress::new(7, 0x3f, 31, 7),
        PciAddress::new(7, 0x41, 31, 7),
    ] {
        assert_eq!(
            access.try_write8(invalid, 0, 0xff),
            Err(ConfigAccessError::OutOfRange)
        );
        assert_eq!(
            access.try_read8(invalid, 0),
            Err(ConfigAccessError::OutOfRange)
        );
    }
    assert_eq!(access.try_read16(last, 4094), Ok(0x9934));
    assert_eq!(
        AnyPciAccess::Unavailable.try_write8(last, 0, 1),
        Err(ConfigAccessError::Unavailable)
    );
    assert_eq!(
        AnyPciAccess::Unavailable.try_write16(last, 0, 1),
        Err(ConfigAccessError::Unavailable)
    );
    assert_eq!(
        AnyPciAccess::Unavailable.try_read8(last, 0),
        Err(ConfigAccessError::Unavailable)
    );
    assert_eq!(
        AnyPciAccess::Unavailable.try_read16(last, 0),
        Err(ConfigAccessError::Unavailable)
    );
}
