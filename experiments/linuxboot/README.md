# LinuxBoot → kexec → CrabEFI → Windows experiment

**Works in QEMU/KVM with Windows PE and installed Windows 11 Pro.** See
[the installed-Windows results](INSTALLED.md) for setup and repeat cold boots.
The [security follow-up](SECURITY.md) covers TPM 2.0, enforced EFI signature
verification, and TPM-only BitLocker cold boots, including the PCR7/I/O limitations.
This is a disposable x86-64/q35 experiment, not a production platform port. It does not change CrabEFI's core
or resurrect the original firmware's Boot Services.

## What was demonstrated

```text
8-MiB coreboot ROM
  → Linux 7.2.0-rc6 + BusyBox initramfs
  → Linux NVMe driver owns the test disk
  → legacy kexec_load (Multiboot v1)
  → existing CrabEFI coreboot payload + separate Runtime Services image
  → Microsoft's BOOTX64.EFI / Windows loader
  → Windows PE 10.0.26100.6584
  → wpeinit, diskpart, cmd.exe write a success marker
  → clean shutdown
```

The full coreboot chain passed three times (31, 33, and 32 seconds), including
one clean rebuild using the saved build script. A separate
SeaBIOS/direct-Linux test with the small kernel also passed in 33 seconds.
Direct coreboot → CrabEFI → Windows PE passed as a baseline.

Passing means the runner found the ordered Linux/kexec/CrabEFI/EBS milestones,
QEMU exited successfully, and Windows wrote a **fresh**
`CRABEFI_WINDOWS_BOOT_SMOKE_SUCCESS` file to the cloned disk. Merely reaching
`ExitBootServices` or showing the Windows logo is not counted as success.
The runner removes any inherited marker before starting QEMU.

Local evidence from this experiment:

- `.local/linuxboot/full-coreboot/result.json` and `serial.log`
- `.local/linuxboot/repeat-coreboot/result.json` and `serial.log`
- `.local/linuxboot/final-run/result.json` and `serial.log` (scripted rebuild)
- `.local/linuxboot/small-seabios/result.json` and `serial.log`

Windows media came from `Win11_25H2_EnglishInternational_x64.iso`, SHA-256
`baaeb6c90dd51648154b64c40c9e0c14d93a427f611a1bb49c8077fa2ff73364`.
No Microsoft binaries, images, or downloaded media are checked in.

## Design

- `pack.py` retains the original ELF64 payload's load segments inside an ELF32
  container that kexec's Multiboot loader understands. A tiny 32-bit entry
  adapter in `multiboot.S` supplies the coreboot payload's stack argument.
- Guest-only `handoff.c` exports Linux's **firmware** memory map from
  `/sys/firmware/memmap`, preserving reserved/ACPI regions. It obtains the
  original RSDP physical address from Linux's boot log and checks that it lies
  in preserved memory. It does not export Linux virtual pointers or allocations.
- The adapter copies the handoff module into a fixed, reserved 1-MiB arena at
  `0x08000000`. This keeps the handoff/framebuffer record alive even when CrabEFI
  reuses the old Linux and kexec allocations.
- SMBIOS is exported from Linux's DMI sysfs files into the same reserved arena.
  SMBIOS 2/3 entry points are relocated, their checksums rebuilt, and a coreboot
  SMBIOS record is emitted. Enable `CONFIG_DMI=y` and `CONFIG_DMI_SYSFS=y` in the
  first kernel; merely preserving ACPI is not a complete firmware handoff.
- QEMU std-vga is explicitly configured to 1024×768×32 through its VBE ports;
  the resulting framebuffer is passed as a coreboot record for CrabEFI's GOP.
- Linux shuts down its NVMe driver through normal kexec; CrabEFI subsequently
  reinitializes the controller and independently creates a fresh UEFI instance.
- Windows PE's image-2 shell is replaced with a short test command. It runs
  `wpeinit`, assigns its ESP `S:`, writes its Windows version and success marker,
  then shuts down. This is stronger evidence than boot-loader logging.

**Use `kexec -c -l`, not just `kexec -l`.** The packaged kexec-tools 2.0.32
otherwise tries the file-based syscall first and its Multiboot path fails with
`Invalid memory segment` before executing the payload. This experiment uses
legacy `kexec_load`; it does not support a lockdown policy that prohibits it.

## Reproduce

Prerequisites: x86-64 Linux with KVM, QEMU (`11.1.2` tested), Rust configured for
CrabEFI, a user-provided Windows 11 amd64 installation ISO, clean Linux sources,
and coreboot sources with their build SDK/toolchain. Tested sources were Linux
7.2.0-rc6 and the local coreboot q35 tree based on change
`65d90e75cf58` (AMD board additions are unrelated to q35).

Run from the CrabEFI workspace root:

```sh
mkdir -p .local/linuxboot
nix build --impure -f experiments/linuxboot/tools.nix -o .local/linuxboot/tools
export PATH="$PWD/.local/linuxboot/tools/bin:$PATH"
./crabefi build --arch x86-64

bash experiments/linuxboot/prepare-media.sh \
  /path/to/Win11_25H2_EnglishInternational_x64.iso .local/linuxboot/media

# The kernel config is deliberately small and includes NVMe in-kernel.
# Both builds have private output directories. Neither source tree is cleaned.
# In a coreboot build SDK (for example `nix develop --no-write-lock-file
# /path/to/coreboot`), with the experiment tools still on PATH:
bash experiments/linuxboot/build-firmware.sh \
  /path/to/clean-linux /path/to/coreboot .local/linuxboot/firmware

python3 experiments/linuxboot/run.py coreboot \
  --media .local/linuxboot/media/windows.img \
  --rom .local/linuxboot/firmware/linuxboot.rom \
  --output .local/linuxboot/run-coreboot
```

Each run needs a fresh output directory. It creates a writable reflink/copy of
`windows.img`; the input template and original ISO are not modified. It attaches
no host block devices. `result.json`, `serial.log`, and the test disk stay in the
output directory. `--tcg` is available but was not validated in this experiment.

To isolate Linux → kexec from the coreboot ROM:

```sh
python3 experiments/linuxboot/run.py linux \
  --media .local/linuxboot/media/windows.img \
  --kernel .local/linuxboot/firmware/linux/arch/x86/boot/bzImage \
  --initrd .local/linuxboot/firmware/initramfs.cpio.gz \
  --output .local/linuxboot/run-linux
```

For an already-built modular kernel, `build-initramfs.sh` accepts its
kernel-modules root instead of `builtin`, resolves NVMe module dependencies,
and packages them. The matching kernel must provide firmware memmap, ACPI,
`/dev/mem`, DMI sysfs tables, I/O permissions, and legacy kexec. This is **not** a guarantee that
an arbitrary distribution kernel will hand over successfully.

Focused host checks:

```sh
python3 -m unittest discover -s experiments/linuxboot -p 'test_*.py' -v
bash -n experiments/linuxboot/{build-firmware.sh,build-initramfs.sh,prepare-media.sh,init}
```

## Limits and findings

- The original results above cover Windows PE. See [the installed-Windows
  follow-up](INSTALLED.md) for the separate deployment and desktop checks.
  Updates, hibernation, and real hardware remain untested.
- An initial NixOS Linux 7.2.9 kernel booted CrabEFI and Windows' loader but
  stalled after EBS, without the userspace marker (120–180-second timeouts).
  Removing GOP did not resolve it. The small kernel works under both coreboot
  and SeaBIOS; the exact distribution-kernel state causing the stall has **not**
  been isolated. Do not silently substitute a large kernel for this config.
- SeaBIOS normally places this NVMe BAR above CrabEFI's current 64-GiB identity
  map. Linux mode explicitly supplies `opt/org.seabios/pci64=0` through fw_cfg
  to keep BARs low. The tested coreboot path assigns the BAR below 4 GiB itself.
  A general platform port needs proper MMIO mapping, not this test constraint.
- The memory map and RSDP are platform handoff metadata, not authenticated input.
  The fixed-address wrapper, QEMU-specific display setup, and lack of preserved
  TPM event-log handoff are unsuitable as a generic secure firmware interface.
- Secure Boot, TPM/BitLocker, native durable runtime variable writes, and
  firmware updates are not validated. The normal CrabEFI runtime-persistence
  limitations still apply. The warm-reset deferred buffer's durability is not
  established by this experiment.
- No attempt is made to reuse Linux drivers as UEFI callbacks. Only controllers
  CrabEFI can reinitialize are usable after the handover; Linux having a driver
  for a device does not provide CrabEFI with that driver.
