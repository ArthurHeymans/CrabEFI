# Checked-in QEMU firmware fixtures

These compressed images are the base firmware used by the QEMU integration
tests (`xtask/src/rom.rs`). They are test fixtures, not release artifacts.
None of them contains a `fallback/payload`: `xtask` injects the freshly built
CrabEFI payload into a copy of the relevant base image for every run.

| File | Contents | Source revision |
| --- | --- | --- |
| `coreboot-qemu-q35.rom.zst` | coreboot, QEMU x86 Q35 | coreboot `56882b503ac9` (26.06-376), dirty tree |
| `coreboot-qemu-aarch64.rom.zst` | coreboot, QEMU AArch64 virt | coreboot `28b188735fb9` (25.09-1638), dirty tree |
| `coreboot-qemu-sbsa.rom.zst` | coreboot, QEMU SBSA | coreboot `627c1d924372` (25.09-1550), dirty tree |
| `coreboot-qemu-riscv64.rom.zst` | coreboot with OpenSBI, QEMU RISC-V virt | coreboot `e5f6256c49de` (25.12-1116), dirty tree |
| `tfa-sbsa.fd.zst` | TF-A for QEMU SBSA | TF-A `v2.13.0-51-g910914341` |

"Dirty tree" means the images were built with local modifications on top of
the listed upstream revision, so they cannot be rebuilt exactly from public
sources. Each coreboot image embeds its full build configuration and version
information, which is the authoritative record:

```sh
zstd -d firmware/coreboot-qemu-q35.rom.zst -o /tmp/q35.rom
cbfstool /tmp/q35.rom extract -n config -f /tmp/q35.config
cbfstool /tmp/q35.rom extract -n revision -f /tmp/q35.revision
zstd -dc firmware/tfa-sbsa.fd.zst | strings | grep -m1 '(release)'
```

When replacing an image, update this table from the embedded revision data,
and describe the local modifications in the change description.
