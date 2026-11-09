//! One test owns the single-hart PCI state and emulates ECAM in aligned RAM.
//! Allocation denial is thread-local, so the test harness remains unaffected.
use std::alloc::{GlobalAlloc, Layout, System, alloc_zeroed, dealloc, handle_alloc_error};
use std::cell::Cell;
use std::ptr::{self, NonNull};

use crabefi::PciEcamRegion;
use crabefi::drivers::pci::{self, PciAddress};

struct FailingAllocator;
thread_local! {
    static ALLOCATIONS_LEFT: Cell<Option<usize>> = const { Cell::new(None) };
}

fn denied() -> bool {
    ALLOCATIONS_LEFT
        .try_with(|left| match left.get() {
            None => false,
            Some(0) => true,
            Some(n) => {
                left.set(Some(n - 1));
                false
            }
        })
        .unwrap_or(false)
}

unsafe impl GlobalAlloc for FailingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if denied() {
            ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if denied() {
            ptr::null_mut()
        } else {
            unsafe { System.alloc_zeroed(layout) }
        }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if denied() {
            ptr::null_mut()
        } else {
            unsafe { System.realloc(pointer, layout, size) }
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: FailingAllocator = FailingAllocator;

fn with_budget<R>(allocations: usize, f: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALLOCATIONS_LEFT.set(None);
        }
    }
    ALLOCATIONS_LEFT.set(Some(allocations));
    let _reset = Reset;
    f()
}

struct FakeEcam {
    memory: NonNull<u8>,
    layout: Layout,
    region: PciEcamRegion,
}

impl FakeEcam {
    fn new(segment: u16, bus_start: u8) -> Self {
        let layout = Layout::from_size_align(3 << 20, 1 << 20).unwrap();
        // SAFETY: the nonzero layout is valid; the allocation is owned until Drop.
        let memory = NonNull::new(unsafe { alloc_zeroed(layout) })
            .unwrap_or_else(|| handle_alloc_error(layout));
        let ecam = Self {
            memory,
            layout,
            region: PciEcamRegion {
                base: memory.as_ptr() as u64,
                segment,
                bus_start,
                bus_end: bus_start + 2,
            },
        };
        // 117 functions per region, including multifunction devices. Bridge
        // headers avoid emulating destructive BAR size probes against RAM.
        // All remaining zero IDs represent absent functions.
        for bus in 0..3 {
            for device in 0..32 {
                let functions = if device == 0 { 8 } else { 1 };
                for function in 0..functions {
                    ecam.write(bus, device, function, 0x00, 0x5678_1234);
                    ecam.write(bus, device, function, 0x04, 0x0000_0007);
                    ecam.write(bus, device, function, 0x08, 0x0604_0000);
                    ecam.write(bus, device, function, 0x0c, 0x0081_0000);
                }
            }
        }
        ecam
    }

    fn register(&self, bus: usize, device: usize, function: usize, offset: usize) -> *mut u32 {
        let index = (bus << 20) | (device << 15) | (function << 12) | offset;
        assert!(bus < 3 && device < 32 && function < 8 && offset < 4096);
        assert_eq!(offset % 4, 0);
        // SAFETY: the checked DWORD lies entirely inside the aligned allocation.
        unsafe { self.memory.as_ptr().add(index).cast() }
    }

    fn write(&self, bus: usize, device: usize, function: usize, offset: usize, value: u32) {
        // SAFETY: register validates alignment and bounds; accesses are serialized.
        unsafe {
            self.register(bus, device, function, offset)
                .write_volatile(value)
        };
    }

    fn assert_bus_mastering_disabled(&self) {
        for bus in 0..3 {
            for device in 0..32 {
                let functions = if device == 0 { 8 } else { 1 };
                for function in 0..functions {
                    // SAFETY: register validates alignment and bounds.
                    let command =
                        unsafe { self.register(bus, device, function, 0x04).read_volatile() };
                    assert_eq!(command, 0x0000_0003, "decode bits must be preserved");
                }
            }
        }
    }
}

impl Drop for FakeEcam {
    fn drop(&mut self) {
        // SAFETY: this is the original allocation and layout. The single test
        // makes no further PCI accesses after its ECAM windows are dropped.
        unsafe { dealloc(self.memory.as_ptr(), self.layout) };
    }
}

#[test]
fn enumeration_is_fallible_and_handoff_needs_no_heap() {
    let first = FakeEcam::new(0, 0);
    let later = FakeEcam::new(7, 64);
    pci::set_ecam_regions(&[first.region, later.region]).unwrap();

    // Initial allocation failure must leave an empty, usable inventory.
    with_budget(0, pci::init);
    assert_eq!(pci::with_devices(|devices| devices.len()), 0);

    // Fail growth in the middle of the first multifunction device.
    with_budget(1, pci::init);
    assert_eq!(pci::with_devices(|devices| devices.len()), 4);
    pci::with_devices(|devices| {
        assert_eq!(devices[3].address, PciAddress::new(0, 0, 0, 3));
    });

    // Fail later growth after crossing into another segment. Earlier devices
    // stay usable, and enumeration does not retry allocation for every root.
    with_budget(5, pci::init);
    assert_eq!(pci::with_devices(|devices| devices.len()), 128);
    pci::with_devices(|devices| {
        assert_eq!(devices[117].address, PciAddress::new(7, 64, 0, 0));
    });

    // Retrying without pressure finds every function, not just the first 64.
    pci::init();
    with_budget(0, || {
        pci::with_devices(|devices| {
            assert_eq!(devices.len(), 234);
            assert_eq!(devices[117].address, PciAddress::new(7, 64, 0, 0));
            assert_eq!(
                devices.last().unwrap().address,
                PciAddress::new(7, 66, 31, 0)
            );
            // Shared inventory borrows must still permit configuration access.
            assert_eq!(pci::read_config16(devices[117].address, 0), 0x1234);
        });
        #[cfg(feature = "spi-flash")]
        assert!(crabefi::drivers::spi::detect_and_init().is_none());
        crabefi::drivers::quiesce_dma_for_os_handoff();
    });
    first.assert_bus_mastering_disabled();
    later.assert_bus_mastering_disabled();
}
