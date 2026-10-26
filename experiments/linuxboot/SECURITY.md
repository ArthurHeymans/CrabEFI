# Windows TPM, Secure Boot and BitLocker follow-up

These are disposable QEMU/KVM feature tests, **not a production trust-chain or
physical-TPM certification**. Windows is the installed Pro 25H2 system from
[INSTALLED.md](INSTALLED.md). There is no NIC, product key or real user data.
The firmware/tool versions for these recorded results are documented in
[README.md](README.md#recorded-result-provenance); they predate the PR rebase.

## Results (2026-10-26)

- Windows detects **TPM 2.0**, provisions/owns it, and reports it ready for storage.
  The device is `swtpm`/libtpms with persistent, private host state, accessed through
  the real MMIO TIS transport and EFI TCG2 protocol—not CrabEFI's software fallback.
- On the SATA control, Windows' **`Confirm-SecureBootUEFI` returns true**, and
  `Get-Tpm` reports `TpmPresent`, `TpmReady`, `TpmEnabled`, `TpmActivated`, and
  `TpmOwned` all true. Evidence: `.local/linuxboot/security/sata-observe/result.json`.
- The unmodified Microsoft Windows boot manager is accepted. The negative EFI
  tests all return **`EFI_SECURITY_VIOLATION` (0x800000000000001a)** before
  `StartImage`: unsigned hello, correctly signed hello with an unenrolled test
  signer, and Microsoft's boot manager with one executable-section byte modified.
  The same unsigned hello executes with Secure Boot disabled.
- **BitLocker works with TPM-only protection.** XTS-AES-128 used-space encryption
  completed at 100%, protection remained `On`, and the only key protector is
  `Tpm`. The raw OS boot-sector OEM field changed from NTFS to `-FVE-FS-`.
  Two subsequent independent cold boots unlocked `C:` without any key entry,
  reached Explorer, and passed all eight security assertions (106 s and 92 s).
  Evidence: `bitlocker-encrypt`, `bitlocker-cold`, `bitlocker-repeat`.
- The NVMe + writable-pflash Windows path encounters CQ timeouts and subsequent
  `QueueFull` errors before EBS, both with keys-only and enforcement-enabled
  fixtures. The successful combined tests use **AHCI/SATA**, with an empty scratch
  NVMe retained only for the first kernel's storage-init check. The Secure-Boot-off
  control also hit AHCI read timeouts: the underlying I/O issue is not proven to
  be NVMe-specific, and no storage fix is claimed.
- Windows reports **PCR7 binding unavailable**, even with Secure Boot enabled.
  Do not describe this as a successful PCR7/modern-standby/device-encryption test.
  The actual BitLocker protector profile is **PCRs 0, 2, 4, 11**.

### Negative BitLocker controls and their limits

- Replacing the software TPM's persistent identity, while retaining an identical
  encrypted disk and flash copy, did **not** reach EBS or the desktop. QEMU exited
  on the guest reset path. This is the expected no-unlock outcome, but a recovery
  UI or a TPM unseal error was not captured; do not call it a verified recovery
  workflow. Evidence: `bitlocker-replaced-tpm`.
- Disabling only `SecureBootEnable` in a private flash/TPM clone did **not** yield
  a usable policy-binding result. It stalled on AHCI reads before EBS. This
  control is **inconclusive**, not proof that BitLocker detected Secure Boot
  changes. Evidence: `bitlocker-sb-off`. Firmware code bytes were checked unchanged.
- The matching original TPM/flash lineage passed another protected cold boot
  after these controls. The original encrypted source remains recoverable in the
  lab. The controls never mutate that disk or its TPM/flash state.

Structured logs are under `.local/linuxboot/security/`: `observe-baseline`,
`sata-observe`, `reject-unsigned`, `reject-untrusted`, `reject-tampered` and the
BitLocker stage directories. A desktop-pass marker alone does not establish
security success; inspect the security probe JSON and its explicit assertions.

## Firmware-variable fixture

The test provisions an EDK2 authenticated-variable FV into the original erased
first MiB of the 8-MiB ROM, then adds an FMAP `SMMSTORE` descriptor for exactly
that region. The helper refuses non-erased/overlapping regions. Firmware code
and the existing CrabEFI payload are unchanged.

`LINUXBOOT_PFLASH=1` opts the handoff into this specific QEMU CFI flash geometry.
CrabEFI's existing bounded SPI/variable-store implementation performs the real
boot-time persistent writes. The QEMU pflash file is reused across cold boots.

Public keys are provisioned offline using virt-firmware's Red Hat test PK/KEK
fixture and Microsoft 2011/2023 KEK and db certificates. **The fixture's dbx is
only its dummy deny-hash entry, not Microsoft's current production revocation
list.** Revoked-but-valid signed loaders are not covered by these tests.

CrabEFI's `SecureBootEnable` preference is in the EFI global namespace with
NV/BS/RT attributes. EDK2's similarly named preference uses another vendor GUID;
setting only that EDK2 variable loaded the keys but left enforcement disabled.
The fixture helper explicitly uses CrabEFI's preference. The standard
`SecureBoot` status remains image-owned/read-only.

## Reproduce

Use the QEMU/KVM prerequisites from [README.md](README.md). From the workspace root:

```sh
mkdir -p .local/linuxboot/security
nix build --impure -f experiments/linuxboot/security-tools.nix \
  -o .local/linuxboot/security-tools
export PATH="$PWD/.local/linuxboot/security-tools/bin:$PATH"

# Install the probes while the source OS is still unencrypted. Inputs are copied.
bash experiments/linuxboot/prepare-security.sh \
  /path/to/completed-windows.img \
  /path/to/winpe/windows.img /path/to/winpe/media/sources/boot.wim \
  /path/to/original-linuxboot.rom .local/linuxboot/security/seed

bash experiments/linuxboot/prepare-security-vars.sh \
  .local/linuxboot/security-tools/share/linuxboot/OVMF_VARS.fd \
  .local/linuxboot/security/vars

# Rebuild only the handoff/initramfs against the already-built first kernel.
bash experiments/linuxboot/build-initramfs.sh \
  target/x86_64-unknown-none/release/crabefi builtin .local/linuxboot/security/fw
cp /path/to/original-linuxboot.rom .local/linuxboot/security/fw/linuxboot.rom
cbfstool .local/linuxboot/security/fw/linuxboot.rom remove -n fallback/payload
cbfstool .local/linuxboot/security/fw/linuxboot.rom add-payload \
  -n fallback/payload -f /path/to/small-linux/bzImage \
  -I .local/linuxboot/security/fw/initramfs.cpio.gz \
  -C 'console=ttyS0,115200 rdinit=/init nokaslr maxcpus=1 panic=-1 LINUXBOOT_PFLASH=1' \
  -c none
python3 experiments/linuxboot/prepare-security-flash.py \
  .local/linuxboot/security/fw/linuxboot.rom \
  .local/linuxboot/security/vars/vars.fd .local/linuxboot/security/flash-template.fd

python3 experiments/linuxboot/run-installed.py boot \
  --disk .local/linuxboot/security/seed/windows.img \
  --rom .local/linuxboot/security/flash-template.fd \
  --flash-state .local/linuxboot/security/state/flash.fd \
  --tpm-state .local/linuxboot/security/state/tpm \
  --storage sata --security-phase observe \
  --output .local/linuxboot/security/observe --timeout 600

python3 experiments/linuxboot/run-installed.py boot \
  --disk .local/linuxboot/security/observe/windows.img \
  --rom .local/linuxboot/security/flash-template.fd \
  --flash-state .local/linuxboot/security/state/flash.fd \
  --tpm-state .local/linuxboot/security/state/tpm \
  --storage sata --security-phase encrypt \
  --output .local/linuxboot/security/encrypt --timeout 1500

python3 experiments/linuxboot/run-installed.py boot \
  --disk .local/linuxboot/security/encrypt/windows.img \
  --rom .local/linuxboot/security/flash-template.fd \
  --flash-state .local/linuxboot/security/state/flash.fd \
  --tpm-state .local/linuxboot/security/state/tpm \
  --storage sata --security-phase verify \
  --output .local/linuxboot/security/verify --timeout 600
```

### EFI enforcement controls

Prepare private copies of the unencrypted seed with just one eligible boot
entry: delete `::/EFI/Microsoft/Boot/bootmgfw.efi` and replace
`::/EFI/BOOT/BOOTX64.EFI` (mtools image offset `@@1048576`). Use these three files:

1. `hello-efi.efi`, built from `test-apps/hello` for `x86_64-unknown-uefi`.
2. The same hello signed with a new unenrolled RSA certificate using `sbsign`.
   Check `sbverify --cert test.crt hello-signed.efi` succeeds independently;
   otherwise this is merely another malformed-signature test.
3. The original Microsoft boot manager with a byte inside `.text`'s raw section
   data XORed with 1. Preserve the PE headers and certificate table.

For each fixture:

```sh
python3 experiments/linuxboot/run-secureboot-negative.py \
  --image /path/to/single-entry-fixture.img \
  --flash .local/linuxboot/security/flash-template.fd \
  --output /path/to/fresh-negative-result
```

The helper checks active User-mode enforcement, explicit security-violation
status, and that neither `StartImage` nor OS handoff occurred. A 30-second halt
following rejection is expected. Separately boot the unsigned fixture with
`SecureBootEnable=0` and require its `Hello from CrabEFI!` entry-point message;
a failure to boot in both configurations is not an enforcement pass.

Never run two VMs against the same flash or TPM state simultaneously. Each run
copies the disk but deliberately reuses those two private state files. Keep
private TPM state inaccessible to other host users. No real TPM is used.

Encryption uses XTS-AES-128, used-space-only, a **TPM-only protector**, and no
recovery password or ESP key file. The lab retains a plaintext source-image
backup and can discard/reset an unusable encrypted test clone. Do not use this
no-recovery arrangement for real data. The probe refuses combined encryption
or verification unless Secure Boot and TPM readiness are true, and refuses to
report success without full encryption and protection enabled.

The expected cold-boot evidence is: fresh desktop marker, `FullyEncrypted`,
100 percent, protection `On`, lock status `Unlocked`, and only a TPM protector.
The ordinary boot check is still required. Initial encryption is not evidence
of a successful TPM unlock on a later cold boot.

## Security boundaries still not established

- This is a **software TPM controlled by the host**, not resistance to a hostile
  host or physical attacks. Windows' reported attestation readiness is not a
  separately verified quote or remote-attestation result.
- Secure Boot enforcement starts at CrabEFI's EFI image-loading boundary. The
  initial coreboot/Linux/initramfs/kexec stages are trusted test firmware, not
  authenticated by this UEFI Secure Boot test. The current first-stage ROM has
  coreboot measured boot disabled; full firmware/kernel measurement and a
  verified handoff of its event log remain necessary for a production design.
- PCR7 binding, current dbx revocations, physical-presence administration,
  authenticated variable-update policy, platform updates, suspend/hibernate,
  power-loss durability and real hardware are not implied by these results.
- Runtime NV writes retain CrabEFI's existing deferred warm-reset semantics;
  these tests do not turn them into native power-loss-safe runtime persistence.
- The passwordless administrator/autologon account and installed privileged
  probe scripts are lab instrumentation. Never network or deploy these images.
