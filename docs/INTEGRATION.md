# Library Integration

`crabefi-core` provides the boot-time UEFI implementation. Every integration
must also supply the normalized separate Runtime Services image built from
`crabefi-runtime-image`.

## Mandatory runtime fields

```rust,ignore
let config = crabefi::PlatformConfig {
    memory_map: &regions,
    timer: &boot_timer,
    reset: &boot_reset,
    runtime_image: crabefi::RuntimeImageSource {
        bytes: normalized_runtime_image,
        expected_sha256: runtime_image_sha256,
    },
    runtime: crabefi::RuntimePlatformConfig {
        time: crabefi::RuntimeTimeConfig {
            mechanism: crabefi::time_mechanism::UNSUPPORTED,
            reserved: 0,
            io_or_mmio_base: 0,
        },
        reset: crabefi::RuntimeResetConfig {
            mechanism: crabefi::reset_mechanism::PSCI_SMC,
            reserved: 0,
            io_or_mmio_base: 0,
        },
        external_ranges: &[],
    },
    // block devices, tables, console, TPM, storage locator, ...
};
crabefi::init_platform(config)
```

The digest must be bound by the trusted containing firmware image. A missing,
mismatched, malformed, or wrong-architecture runtime image is a fatal startup
error; there is no monolithic fallback.

## Platform mechanisms

`Timer`, `ResetHandler`, `PlatformHooks`, device traits, and loggers are
boot-only. Runtime time/reset behavior uses integer mechanism records copied
into image state. MMIO time mechanisms additionally require an explicit
retained runtime MMIO range.

External ranges are retained runtime MMIO mappings used only by image-local
architecture mechanisms such as PL031 or Goldfish RTC. Capsule updates and
post-EBS nonvolatile persistence are image-local unsupported stubs; integrations
must not declare a journal or capsule compatibility range.

## Variables

A `VariableStoreLocator` may identify an EDK2-compatible flash region. CrabEFI
imports active records and firmware-created boot values directly into the
runtime image before an EFI application can run. Boot writes use one audited
pre-seal persistence bridge: durable storage
commit occurs before the image-store commit. The bridge is erased at EBS.

The removed `VariableBackend`, `RuntimeRegion`, and `DeferredBufferConfig` APIs
must not be implemented by integrations. Runtime survival is provided only by
the image and explicit ranges.
