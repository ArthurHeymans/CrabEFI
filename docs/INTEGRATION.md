# Library Integration

`crabefi-core` provides the boot-time UEFI implementation. Every integration
must also supply the normalized separate Runtime Services image built from
`crabefi-runtime-image`.

## Cargo-only integration

Enable `crabefi-core`'s `bundled-runtime-image` feature to embed the normalized
image generated from the same CrabEFI source revision:

```toml
[dependencies]
crabefi = {
    package = "crabefi-core",
    git = "https://github.com/ArthurHeymans/CrabEFI.git",
    rev = "<pinned revision>",
    default-features = false,
    features = ["bundled-runtime-image"],
}
```

Then use `crabefi::BUNDLED_RUNTIME_IMAGE` for `PlatformConfig::runtime_image`.
This requires no xtask invocation, environment variables, or separately managed
artifact. Cargo selects the image for the compilation target. Platforms that
authenticate or provision their own image can leave the feature disabled and
construct `RuntimeImageSource` directly.

The bundled image only removes artifact-build plumbing. Runtime mechanism
selection and the warm-reset-retained deferred buffer remain platform-owned
requirements.

## Mandatory runtime fields

```rust,ignore
let config = crabefi::PlatformConfig {
    memory_map: &regions,
    timer: &boot_timer,
    reset: &boot_reset,
    runtime_image: crabefi::BUNDLED_RUNTIME_IMAGE,
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
        deferred_buffer: crabefi::DeferredBufferConfig {
            base: retained_buffer_physical,
            size: retained_buffer_size,
        },
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
into image state. PL031 and Goldfish RTC bases must be fully contained in an
explicit retained runtime MMIO range; port-I/O, PSCI, and SBI mechanisms do not
require an MMIO range.

External ranges are retained MMIO mappings used only by image-local
architecture mechanisms. Each range must have page-aligned physical bounds and
its descriptor must retain `EFI_MEMORY_RUNTIME` plus the declared attributes.

## Retained deferred buffer

`deferred_buffer` is mandatory. Its base and size must be nonzero and page
aligned, the complete range must be reserved as `RuntimeServicesData`, and it
must overlap neither the runtime image nor an external MMIO range. The runtime
image owns the range exclusively; boot code and the OS must not allocate or
reuse it. Both its contents and physical address must survive a warm reset.

After ExitBootServices, runtime nonvolatile variable writes are committed to a
bounded journal in this buffer. `UpdateCapsule()` stages its descriptor there
and requires `PERSIST_ACROSS_RESET`. On the next boot, CrabEFI reserves the
range via a coreboot-compatible capsule-on-disk wrapper around its private
reservation capsule, replays deferred records through the temporary persistence
bridge, processes a staged capsule, and acknowledges records only after durable
completion. The wrapper is transport only: reservation recognition still
requires the nested CrabEFI-private GUID and marker. Capsule and journal
capacity remain bounded by the configured buffer and runtime ABI limits.

## Variables

A `VariableStoreLocator` may identify an EDK2-compatible flash region. CrabEFI
imports active records and firmware-created boot values directly into the
runtime image before an EFI application can run. Boot writes use one audited
pre-seal persistence bridge: durable storage commit occurs before the
image-store commit. The bridge is erased at successful EBS seal.

The old `VariableBackend` and `RuntimeRegion` APIs remain removed.
`DeferredBufferConfig` is their mandatory, narrowly scoped replacement for
warm-reset replay; runtime survival otherwise comes from the separate image and
explicit external ranges.
