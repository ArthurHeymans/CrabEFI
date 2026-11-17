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
selection and the optional warm-reset-retained deferred buffer remain platform-owned.
See [capabilities](capabilities.md) for additive feature selection, exact runtime
capability matching, and the bounded `variable-store` backend.

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
    // block devices, tables, console, optional TPM, variable_storage, ...
};
crabefi::init_platform(config)
```

The digest must be bound by the trusted containing firmware image. A missing,
mismatched, malformed, or wrong-architecture runtime image is a fatal startup
error; there is no monolithic fallback.

## Platform discovery

Platform code can pass discovered ACPI topology through
`PlatformConfig::acpi_info` (or the builder's `.acpi_info(info)`). The core
copies the finalized platform memory map into its direct-Linux handoff and
parses the supplied FDT before EFI initialization. The caller's memory map is
authoritative by default; platforms whose map omits FDT-described MMIO can set
`discover_mmio` (or `.discover_mmio(true)`) on AArch64/RISC-V. Do not enable
that option when the map already describes those windows.

## Platform mechanisms

`Timer`, `ResetHandler`, `PlatformHooks`, device traits, and loggers are
boot-only. Runtime time/reset behavior uses integer mechanism records copied
into image state. PL031 and Goldfish RTC bases must be fully contained in an
explicit retained runtime MMIO range; port-I/O, PSCI, and SBI mechanisms do not
require an MMIO range.

External ranges are retained MMIO mappings used only by image-local
architecture mechanisms. Each range must have page-aligned physical bounds and
its descriptor must retain `EFI_MEMORY_RUNTIME` plus the declared attributes.

## Firmware settings (CFR)

Enable `cfr` (also included in `full`) to use the shared settings menu. After
heap initialization, parse the platform's CFR record with `cfr::parse_cfr` and
publish it with `cfr::store_cfr`. Pass a `PlatformHooks` implementation through
`PlatformConfig::hooks` (or the builder's `.hooks(&hooks)`):

```rust,ignore
impl crabefi::PlatformHooks for Hooks {
    fn firmware_settings_available(&self) -> bool {
        crabefi::cfr::get_cfr().is_some_and(|info| info.total_options() != 0)
    }

    fn show_firmware_settings(&self) -> bool {
        crabefi::cfr_menu::show_cfr_menu();
        true
    }
}
```

With `ui`, also override the graphical hook to preserve sidebar navigation and
route it through the menu's unsaved-changes guard:

```rust,ignore
fn show_graphical_firmware_settings(&self) -> crabefi::ui::ScreenNav {
    crabefi::cfr_menu::show_graphical_firmware_settings()
}
```

The default graphical hook calls `show_firmware_settings()` and returns to Boot,
so existing platform providers remain compatible. A hook may return
`ScreenNav::Reset` to have CrabEFI restart the machine; `ScreenNav` is
`#[non_exhaustive]`, so match it with a wildcard arm. The graphical menu uses `B`,
`S`, and `F` for navigation, `W` for Save, `?` for Help, and `D` for a draft default.
Page Up/Down and Home/End navigate long lists. Changes remain drafts until saved;
Escape cancels dialogs, and failed writes remain editable and retryable. A
partial save commits successful writes only; Discard reverts unsaved drafts, not
already committed values.

Options normally use EFI variables under the CFR GUID. A platform that keeps
some options elsewhere, such as CMOS, can register a static `cfr::OptionStore`
once with `cfr::set_option_store`, after the heap is ready and before showing
the menu. The store must be `Sync`; synchronize mutable state internally. A kept
option that is unset uses its CFR default, not an EFI-variable override. Deleting
a kept option is unsupported; writing its default value is supported.

For reads before heap or EFI initialization (including when booting another
payload), depend only on `crabefi-efi-types` and use
`varstore::read_variable_data_from_region` with the bounded memory-mapped FV
slice, `varstore::COREBOOT_CFR_GUID`, a UTF-16 option name and an output buffer.
Numeric CFR values are little-endian `u32`; strings are NUL-terminated UTF-8.
This reads committed flash records only: a platform must separately handle its
CMOS-kept options and any pending warm-reset deferred journal.

## Retained deferred buffer

Use `DeferredBufferConfig::disabled()` (zero base and size together) to omit
retained staging. Disabled post-EBS NV writes and capsule staging return
`UNSUPPORTED`, while boot-time backend writes, reads, volatile variables and
other runtime services remain available. This is not native runtime persistence.

When enabled, the buffer's base and size must be nonzero and page aligned, the complete range must be reserved as `RuntimeServicesData`, and it
must overlap neither the runtime image nor an external MMIO range. The runtime
image owns the range exclusively; boot code and the OS must not allocate or
reuse it. Both its contents and physical address must survive a warm reset.

After ExitBootServices, runtime nonvolatile variable writes are queued in a
bounded journal in this buffer. Success means warm-reset-retained staging,
not power-loss durability; a RAM CRC does not make volatile memory persistent. `UpdateCapsule()` stages its descriptor there
and requires `PERSIST_ACROSS_RESET`. On the next boot, CrabEFI reserves the
range via a coreboot-compatible capsule-on-disk wrapper around its private
reservation capsule, replays deferred records through the temporary persistence
bridge, processes a staged capsule, and acknowledges records only after durable
completion. The wrapper is transport only: reservation recognition still
requires the nested CrabEFI-private GUID and marker. Capsule and journal
capacity remain bounded by the configured buffer and runtime ABI limits.

## Variables

Enable `variable-store` and pass `VariableStorage::Platform(&mut backend)` (or
`.variable_storage(&mut backend)` on the builder) for an exclusively bounded,
platform-owned region. `StorageBackend` reports exact capacity and program/erase
granularity and offers region-relative read/program/erase, never whole-chip
unlock authority. The optional `spi-flash` capability keeps the standalone
`VariableStoreLocator`/SPI adapter. CrabEFI imports active EDK2 records and
firmware-created boot values directly into the
runtime image before an EFI application can run. Boot writes use one audited
pre-seal persistence bridge: durable storage commit occurs before the
image-store commit. The bridge is erased at successful EBS seal.

The old `VariableBackend` and `RuntimeRegion` APIs remain removed.
`DeferredBufferConfig` is the optional, narrowly scoped contract for
warm-reset replay; runtime survival otherwise comes from the separate image and
explicit external ranges.
