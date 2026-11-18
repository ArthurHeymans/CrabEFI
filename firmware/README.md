# Checked-in QEMU firmware fixtures

These compressed images are the base firmware used by the QEMU integration
tests (`xtask/src/rom.rs`). They are test fixtures, not release artifacts.
None of them contains a `fallback/payload`: `xtask` injects the freshly built
CrabEFI payload into a copy of the relevant base image for every run.

| File | Contents | Source revision |
| --- | --- | --- |
| `coreboot-qemu-q35.rom.zst` | coreboot, QEMU x86 Q35 | coreboot `56882b503ac9` (26.06-376), dirty tree |
| `coreboot-qemu-q35-payload-mm.rom.zst` | coreboot with the payload MM interface, QEMU x86 Q35 | coreboot `85915142b1a9` plus Gerrit topic `payload-mm` up to [88996/19](https://review.coreboot.org/c/coreboot/+/88996/19) and the patches in `coreboot-payload-mm/` |
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

## Payload MM fixture

`coreboot-qemu-q35-payload-mm.rom.zst` is the base for payload MM runs
(`CRABEFI_PAYLOAD_MM=1`; `CRABEFI_Q35_ROM` selects another ROM). coreboot's
payload MM interface is still under review, so the image is built from:

- coreboot `85915142b1a96564145160d28766c3bd3e2ca5a0`;
- the Gerrit chain 89031/19, 79867/24, 79870/24, 89151/15, 79871/25,
  80846/24 and 88996/19 (topic `payload-mm`);
- `coreboot-payload-mm/0001-*.patch`: clear the payload MM area when the SMI
  handler is installed, so a warm reset does not leave the previous image
  registered;
- `coreboot-payload-mm/0002-*.patch`: do not coalesce capsules into reserved
  RAM such as TSEG;
- `coreboot-payload-mm/0003-*.patch`: the defconfig. It differs from the
  plain Q35 fixture in using TSEG SMM (the payload MM area does not fit in
  ASEG), 64-bit coreboot (CrabEFI's MM image needs 64-bit SMM) and a 256 KiB
  SMMSTORE (each half of the MM store holds at least one maximum-size
  variable).

```sh
git checkout 85915142b1a96564145160d28766c3bd3e2ca5a0
git fetch https://review.coreboot.org/coreboot refs/changes/96/88996/19
git checkout FETCH_HEAD
git am /path/to/CrabEFI/firmware/coreboot-payload-mm/*.patch
make defconfig KBUILD_DEFCONFIG=configs/defconfig.crabefi-mm
make
```
