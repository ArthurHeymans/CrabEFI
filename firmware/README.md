# Checked-in QEMU firmware fixtures

These compressed images are the base firmware used by the QEMU integration
tests (`xtask/src/rom.rs`). They are test fixtures, not release artifacts.
None of them contains a `fallback/payload`: `xtask` injects the freshly built
CrabEFI payload into a copy of the relevant base image for every run.

| File | Contents | Source revision |
| --- | --- | --- |
| `coreboot-qemu-q35.rom.zst` | coreboot, QEMU x86 Q35, 64-bit payload caller | coreboot `206078d6d990d0b7e51b5d87bc27349cb960ead0` plus `coreboot-x86_64-payload.patch` |
| `coreboot-qemu-aarch64.rom.zst` | coreboot, QEMU AArch64 virt | coreboot `28b188735fb9` (25.09-1638), dirty tree |
| `coreboot-qemu-sbsa.rom.zst` | coreboot, QEMU SBSA | coreboot `627c1d924372` (25.09-1550), dirty tree |
| `coreboot-qemu-riscv64.rom.zst` | coreboot with OpenSBI, QEMU RISC-V virt | coreboot `e5f6256c49de` (25.12-1116), dirty tree |
| `tfa-sbsa.fd.zst` | TF-A for QEMU SBSA | TF-A `v2.13.0-51-g910914341` |

"Dirty tree" means those images were built with local modifications on top of
the listed upstream revision, so they cannot be rebuilt exactly from public
sources. Each coreboot image embeds its full build configuration and version
information. The replacement Q35 image was built from a source archive, so its
embedded Git fields say `Unknown`; its source is the exact commit and patch
listed above, with [`qemu-q35.defconfig`](qemu-q35.defconfig).

```sh
zstd -d firmware/coreboot-qemu-q35.rom.zst -o /tmp/q35.rom
cbfstool /tmp/q35.rom extract -n config -f /tmp/q35.config
cbfstool /tmp/q35.rom extract -n revision -f /tmp/q35.revision
zstd -dc firmware/tfa-sbsa.fd.zst | strings | grep -m1 '(release)'
```

## Rebuilding the 64-bit Q35 caller

CrabEFI has no 32-bit x86 entry. An old base ROM still calls payloads in
protected mode and must not be used for the new ABI. The migration patch adds
`CONFIG_PAYLOAD_X86_64`, which keeps the coreboot call in long mode and passes
the coreboot pointer in RDI. It does not change coreboot's default for other
payloads. See [the entry contract](../docs/X86_ENTRY_ABI.md).

With a coreboot toolchain/development environment:

```sh
git clone https://review.coreboot.org/coreboot.git coreboot-q35
cd coreboot-q35
git checkout 206078d6d990d0b7e51b5d87bc27349cb960ead0
git submodule update --init 3rdparty/vboot 3rdparty/blobs
git apply /path/to/CrabEFI/firmware/coreboot-x86_64-payload.patch
make defconfig KBUILD_DEFCONFIG=/path/to/CrabEFI/firmware/qemu-q35.defconfig
make -j8
# Check that fallback/payload is absent: xtask always injects the fresh ELF.
build/cbfstool build/coreboot.rom print
zstd -f build/coreboot.rom -o /path/to/CrabEFI/firmware/coreboot-qemu-q35.rom.zst
```

The checked-in fixture was built using the coreboot Nix SDK, with
`make -j8 XGCCPATH=` selecting its native toolchain from PATH.

When replacing an image, update the source revision/configuration here and
describe any local modifications in the change description.
