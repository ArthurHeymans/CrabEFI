# Installed Windows follow-up

**Verified in QEMU/KVM:** Windows 11 Pro 25H2, build 26200.6584, boots from
its installed NTFS system partition through coreboot → Linux → kexec → CrabEFI.
It completes setup, logs into an Explorer desktop, writes a fresh marker and
shuts down. The test uses installation image 6 on a disposable 64-GiB NVMe image.
CrabEFI's core payload is unchanged; the Linux handoff now preserves SMBIOS.

## Observed results

- Deployment through the full LinuxBoot chain: **passed**, 277 seconds.
- Direct coreboot → CrabEFI control: **passed**, 368 seconds across two firmware
  boots, including initial setup and an Explorer session on `C:`.
- Original Linux handoff without SMBIOS: **failed** during Sysprep specialize.
  `Windows/Panther/setupact.log` identifies an access violation in
  `RdpSysPrepRestoreOnline` (`tssysprep.dll`), not a failure to enter Windows.
- Linux handoff with SMBIOS: **passed from the freshly applied image**, 844
  seconds across two firmware boots. Windows reported `Professional`, `25H2`,
  `InstallationType=Client`, `SYSTEMDRIVE=C:`, and Explorer in session 1.
  The installation ISO and WinPE disk were absent throughout these boots.
- Installed-system cold boot with the native-command probe: **passed**, 220
  seconds in one firmware boot; Explorer ran in console session 1, and
  `bcdedit` confirmed `winload.efi` with both OS and loader devices on `C:`.
- Repeat cold boot of that completed LinuxBoot-tested system: **passed**, 66
  seconds in one firmware boot, with inherited probe outputs removed first.
- WinPE with the updated SMBIOS handoff: **passed**, 35 seconds.

Main evidence is under `.local/linuxboot/installed/`:

- `deploy/result.json` — DISM and bcdboot results;
- `first-boot/{setupact.log,setuperr.log}` — original missing-SMBIOS failure;
- `direct-control/result.json` — direct-firmware baseline;
- `linuxboot-smbios-setup/result.json` — successful fresh setup through Linux;
- `native-cold/result.json` — successful installed-system cold boot;
- `repeat-cold/result.json` — repeat cold boot with a fresh marker;
- `linuxboot-smbios-cold/boot-01-screen.png` — an installed desktop on the Linux
  path even though that 180-second run's PowerShell marker check timed out.

The fresh-setup result includes CIM and PowerShell process evidence. The saved
probe now uses native `tasklist` and `bcdedit` instead, avoiding PowerShell cold
startup as a desktop-verification dependency. A verification timeout alone must
not be described as proof that Windows failed to boot. Use a generous timeout:
initial setup needed two boots totaling 14 minutes, and even a successful cold
boot took longer than the initial 180-second verification budget.

## Method

1. Boot a private WinPE image through coreboot → Linux → kexec → CrabEFI.
2. Inside that guest, create a GPT ESP/MSR/NTFS layout on its blank disk 0.
3. Apply the original ISO's Windows Pro image using DISM, configure boot files
   with `bcdboot`, and provide an offline specialize/OOBE answer file.
4. Shut down, detach both installation media, and boot **only the installed
   disk** through the same firmware chain. Windows setup may require several
   complete firmware boots; the runner permits these rather than treating
   a reset as proof of success.
5. Require a fresh marker written by the installed OS after an interactive
   desktop has started. Preserve version, environment, process and boot-loader evidence.

This is standard offline image deployment, **not** a test of the interactive
Windows Setup wizard or its TPM/Secure Boot/hardware-requirement checks.
No product key, activation, Microsoft account or network access is used.
No Microsoft binaries are changed or checked in.

**The answer file creates a passwordless local administrator with autologon.**
This is strictly for the disposable VM: the runner supplies `-nic none` and
attaches only regular image files and a read-only installation ISO. Do not use
this answer file on a real machine or connect the resulting VM to a network.
The guest deployment script intentionally partitions disk 0; do not run it
outside the harness's blank-disk/WinPE-media arrangement.

## Reproduce

First build the ROM and WinPE media using [README.md](README.md), then run from
this workspace root with the experiment tools on PATH:

```sh
bash experiments/linuxboot/prepare-installed.sh \
  .local/linuxboot/media/windows.img \
  .local/linuxboot/media/media/sources/boot.wim \
  .local/linuxboot/installed/media

python3 experiments/linuxboot/run-installed.py deploy \
  --installer .local/linuxboot/installed/media/installer.img \
  --iso /path/to/Win11_25H2_EnglishInternational_x64.iso \
  --rom .local/linuxboot/firmware/linuxboot.rom \
  --output .local/linuxboot/installed/deploy --timeout 900

python3 experiments/linuxboot/run-installed.py boot \
  --disk .local/linuxboot/installed/deploy/windows.img \
  --rom .local/linuxboot/firmware/linuxboot.rom \
  --output .local/linuxboot/installed/first-boot --timeout 600

# Cold-boot the completed installation again, on another private copy.
python3 experiments/linuxboot/run-installed.py boot \
  --disk .local/linuxboot/installed/first-boot/windows.img \
  --rom .local/linuxboot/firmware/linuxboot.rom \
  --output .local/linuxboot/installed/repeat-boot --timeout 600
```

Each output directory must be new. Deployment creates its own blank raw image;
boot mode reflinks/copies the source installation. Inputs are never modified.
The original installation ISO is attached only during deployment; subsequent
boots attach neither the ISO nor a WinPE disk.

## Success criterion

The runner checks the ordered Linux/kexec/CrabEFI/EBS milestones on the successful
firmware boot, a clean QEMU exit, and a freshly written
`CRABEFI_INSTALLED_WINDOWS_BOOT_SUCCESS` file on the ESP. The installed probe:

- refuses to run with the WinPE `MiniNT` registry key or an `X:` system drive;
- requires the installed `explorer.exe` and registry `InstallationType=Client`;
- waits for an actual Explorer process in a desktop session;
- records Windows version, edition, system drive, identity and boot-loader properties;
- registers the same check for subsequent logons and disables hibernation;
- writes the marker and requests a full shutdown.

The host additionally requires `SYSTEMDRIVE=C:`, `Client`, and Explorer process
output. Markers inherited from the input image are removed before each run.
A Windows logo, successful image deployment or an EBS log alone is insufficient.
Firmware memory handoff must also include SMBIOS: `CONFIG_DMI=y` and
`CONFIG_DMI_SYSFS=y` enable the first kernel's export; the adapter copies the
entry point and table into reserved memory, relocates pointers and repairs
checksums. Merely forwarding the ACPI RSDP was insufficient for this installation.

Each output contains `result.json`, per-boot serial logs, the writable test disk,
and copies of available deployment/desktop evidence. `--direct` can be used with
a direct CrabEFI ROM to isolate Windows/UEFI issues from the Linux handover.

Secure Boot, TPM/BitLocker, activation, Windows Update, suspend/hibernate,
power-loss-safe runtime persistence, and physical hardware remain separate tests.
