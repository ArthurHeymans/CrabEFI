//! Build-and-link fixture for using CrabEFI as an external Cargo library.

#![no_main]
#![no_std]

use core::panic::PanicInfo;

use crabefi::{
    BlockDevice, DeferredBufferConfig, MemoryRegion, MemoryType, PlatformConfigBuilder,
    ResetHandler, ResetType, RuntimePlatformConfig, RuntimeResetConfig, RuntimeTimeConfig, Timer,
};

// The embedding firmware, rather than crabefi-core, owns this symbol. The
// fixture never runs, so the empty heap intentionally remains uninitialized.
#[global_allocator]
static ALLOCATOR: linked_list_allocator::LockedHeap = linked_list_allocator::LockedHeap::empty();

struct FixtureTimer;

impl Timer for FixtureTimer {
    fn current_ticks(&self) -> u64 {
        0
    }

    fn ticks_per_second(&self) -> u64 {
        1
    }
}

struct FixtureReset;

impl ResetHandler for FixtureReset {
    fn reset(&self, _reset_type: ResetType) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }
}

#[repr(C, align(4096))]
struct DeferredBuffer([u8; 4096]);

#[unsafe(link_section = ".deferred_buffer")]
static mut DEFERRED_BUFFER: DeferredBuffer = DeferredBuffer([0; 4096]);

static TIMER: FixtureTimer = FixtureTimer;
static RESET: FixtureReset = FixtureReset;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let deferred_base = core::ptr::addr_of_mut!(DEFERRED_BUFFER) as u64;
    let memory_map = [
        MemoryRegion {
            base: 0x0100_0000,
            size: 0x0200_0000,
            region_type: MemoryType::Ram,
        },
        MemoryRegion {
            base: deferred_base,
            size: 4096,
            region_type: MemoryType::BootServicesData,
        },
    ];
    let mut block_devices: [&mut dyn BlockDevice; 0] = [];

    crabefi::init_platform(
        PlatformConfigBuilder::new(
            &memory_map,
            &TIMER,
            &RESET,
            &mut block_devices,
            crabefi::BUNDLED_RUNTIME_IMAGE,
            RuntimePlatformConfig {
                time: runtime_time_config(),
                reset: runtime_reset_config(),
                external_ranges: &[],
                deferred_buffer: DeferredBufferConfig {
                    base: deferred_base,
                    size: 4096,
                },
            },
        )
        .build(),
    )
}

const fn runtime_time_config() -> RuntimeTimeConfig {
    RuntimeTimeConfig {
        mechanism: crabefi::time_mechanism::UNSUPPORTED,
        reserved: 0,
        io_or_mmio_base: 0,
    }
}

const fn runtime_reset_config() -> RuntimeResetConfig {
    #[cfg(target_arch = "x86_64")]
    let mechanism = crabefi::reset_mechanism::X86_LEGACY;
    #[cfg(target_arch = "aarch64")]
    let mechanism = crabefi::reset_mechanism::PSCI_SMC;
    #[cfg(target_arch = "riscv64")]
    let mechanism = crabefi::reset_mechanism::SBI_SRST;

    RuntimeResetConfig {
        mechanism,
        reserved: 0,
        #[cfg(target_arch = "x86_64")]
        io_or_mmio_base: 0xcf9,
        #[cfg(not(target_arch = "x86_64"))]
        io_or_mmio_base: 0,
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
