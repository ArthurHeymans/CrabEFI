//! Runtime image and platform mechanisms handed to the EFI core.

pub(crate) fn runtime_image_source() -> crabefi::RuntimeImageSource<'static> {
    #[cfg(feature = "bundled-runtime-image")]
    {
        crabefi::BUNDLED_RUNTIME_IMAGE
    }

    #[cfg(feature = "external-runtime-image")]
    {
        crabefi::RuntimeImageSource {
            bytes: crate::runtime_blob::RUNTIME_IMAGE,
            expected_sha256: crate::runtime_blob::RUNTIME_IMAGE_SHA256,
        }
    }
}

pub(crate) fn runtime_platform_config() -> crabefi::RuntimePlatformConfig<'static> {
    unsafe extern "C" {
        static _deferred_buffer_start: u8;
        static _deferred_buffer_end: u8;
    }

    let deferred_buffer = {
        let start = core::ptr::addr_of!(_deferred_buffer_start) as usize;
        let end = core::ptr::addr_of!(_deferred_buffer_end) as usize;
        let size = end
            .checked_sub(start)
            .expect("deferred-buffer linker symbols are reversed");
        assert!(
            start.is_multiple_of(4096) && size != 0 && size.is_multiple_of(4096),
            "deferred-buffer linker range must be nonzero and page aligned"
        );
        crabefi::DeferredBufferConfig {
            base: start as u64,
            size,
        }
    };

    #[cfg(target_arch = "x86_64")]
    let (time, reset) = (
        crabefi::RuntimeTimeConfig {
            mechanism: crabefi::time_mechanism::X86_CMOS,
            reserved: 0,
            io_or_mmio_base: 0,
        },
        crabefi::RuntimeResetConfig {
            mechanism: crabefi::reset_mechanism::X86_LEGACY,
            reserved: 0,
            io_or_mmio_base: 0xcf9,
        },
    );
    #[cfg(target_arch = "aarch64")]
    let (time, reset) = (
        crabefi::RuntimeTimeConfig {
            mechanism: crabefi::time_mechanism::UNSUPPORTED,
            reserved: 0,
            io_or_mmio_base: 0,
        },
        crabefi::RuntimeResetConfig {
            mechanism: crabefi::reset_mechanism::PSCI_SMC,
            reserved: 0,
            io_or_mmio_base: 0,
        },
    );
    #[cfg(target_arch = "riscv64")]
    let (time, reset) = (
        crabefi::RuntimeTimeConfig {
            mechanism: crabefi::time_mechanism::UNSUPPORTED,
            reserved: 0,
            io_or_mmio_base: 0,
        },
        crabefi::RuntimeResetConfig {
            mechanism: crabefi::reset_mechanism::SBI_SRST,
            reserved: 0,
            io_or_mmio_base: 0,
        },
    );
    #[cfg(feature = "payload-mm")]
    let mm_proxy = crate::payload_mm::runtime_config();
    #[cfg(not(feature = "payload-mm"))]
    let mm_proxy = Default::default();
    crabefi::RuntimePlatformConfig {
        time,
        reset,
        external_ranges: &[],
        deferred_buffer,
        mm_proxy,
    }
}
