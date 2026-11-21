# Encrypted boot volumes (LUKS2)

With the `luks` feature, CrabEFI boots Linux from an ext2/3/4 volume inside a
LUKS2 partition, such as an encrypted root file system that holds `/boot`.
It unlocks the volume with a passphrase or, with no prompt, with a TPM 2.0
token enrolled by `systemd-cryptenroll`. It then boots a Boot Loader
Specification entry from the volume directly, in UEFI or native-only mode.

`luks` builds on the experimental x86-64 `ext4` feature and inherits its
limits (trusted fixed disks, BLS entries only). It also requires
CrabEFI's own payload entry and heap (`platform-entry` and
`global-allocator`): it relies on their zero-on-free heap and stack scrub
to keep decrypted data and keys from outliving their use. Firmware that
embeds CrabEFI with its own allocator cannot enable it. The coreboot payload's `luks`
feature also enables the TPM in native-only builds.

```sh
./crabefi build --luks                 # UEFI payload
./crabefi build --native-only --luks   # Linux-only payload
```

## What CrabEFI opens

| Supported | Not supported |
| --- | --- |
| LUKS2 with one data segment | LUKS1, detached headers |
| `aes-xts-plain64`, 256- or 512-bit keys | other ciphers, dm-integrity |
| 512 to 4096-byte encryption sectors | reencryption in progress, OPAL |
| PBKDF2 (SHA-256/512), Argon2i, Argon2id keyslots | metadata areas above 256 KiB |
| ext2/3/4 directly inside the volume | LVM, btrfs or other layers inside |
| `systemd-tpm2` tokens with a PCR policy | TPM2 PINs, signed policies (`--tpm2-public-key`), pcrlock |

These are the cryptsetup and systemd defaults. CrabEFI reads both header
copies, verifies their checksums and uses the newer intact one, as
cryptsetup does. It never writes to the disk.

## Unlocking with a passphrase

A volume CrabEFI cannot unlock on its own appears in the boot menu as
**Unlock *label* (*disk*, partition *n*)** under *Encrypted Volumes*. Choose
it, or let the menu timeout choose it, and type the passphrase. The boot
entries inside the volume are listed afterwards. If the timeout started the
unlock and it succeeded, the countdown continues and boots the volume's
default entry. CrabEFI allows three attempts; Escape returns to the menu,
which then waits for a choice.

CrabEFI asks for passphrases only while nothing but firmware code has run
since power-on. Once any EFI image, kernel or payload has started, even one
that returned (a failed `BootOrder` entry, say), that code may have
changed the firmware. The *Unlock* entry then asks you to restart
instead.

The firmware derives keys on one core without SIMD. A keyslot that
cryptsetup benchmarked to two seconds over four threads (the Argon2id
default) takes several times longer at boot. For a faster unlock, add a
keyslot with a cheaper KDF, for example:

```sh
cryptsetup luksAddKey --pbkdf argon2id --pbkdf-memory 262144 --iter-time 1000 /dev/nvme0n1p2
cryptsetup config --key-slot <new slot> --priority prefer /dev/nvme0n1p2
```

CrabEFI tries preferred keyslots first; without `prefer` the original,
slower keyslot may still run first on every boot.

A serial console sends UTF-8, which CrabEFI decodes. A keyboard is read as a
US layout, so characters other than ASCII are best avoided in a passphrase
typed on one. After the third failed attempt, CrabEFI shows why it failed
before returning to the menu.

## Unlocking with the TPM

CrabEFI unseals `systemd-tpm2` tokens while it discovers boot entries, using a
policy session salted to the TPM's storage root key with response
encryption, so the secret does not cross the TPM bus in clear. It needs a
token recorded with the storage root key (systemd 254 or newer) on an ECC
P-256 SRK, which is systemd's choice when the TPM supports it.

### Which PCRs to bind

Before CrabEFI starts any OS code (a kernel or any EFI image) it measures
`EV_SEPARATOR` into PCRs 0–7. In native-only mode CrabEFI measures nothing
else, and in UEFI mode it measures PCR 7's separator at startup with the
Secure Boot state. A token bound to the values these PCRs have *before* the
separators can be unsealed by CrabEFI only. Neither a kernel nor anything
else CrabEFI boots afterwards can unseal it. This includes an entry an
attacker picks from the menu.

- **Native-only mode:** PCRs 0–7 hold what coreboot measured (PCR 0 and 2
  with vboot or measured boot). Compute the values from coreboot's event
  log, without the separators, and pass them explicitly:

  ```sh
  systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0:sha256=<value>+2:sha256=<value> /dev/nvme0n1p2
  ```

- **UEFI mode:** bind PCRs among 0–6, which receive their separators only
  when the first boot option starts. Pre-boot values are again computed from
  the event log. PCR 7 is not suitable: it gets its separator before boot
  entries are discovered, and in UEFI mode CrabEFI opens LUKS2 volumes only
  with Secure Boot off.

A token with no PCRs, or with PCRs only outside 0–7, works too. But then
anything that later runs on the machine can unseal it, as with any such
systemd token. CrabEFI logs a warning for tokens without PCRs.

CrabEFI tries each `systemd-tpm2` token once per boot, before the
separators. A token whose policy does not match is skipped, and if none
unlocks the volume, the passphrase entry is offered.

Bind the PCRs where your firmware chain measures CrabEFI itself (with
coreboot measured boot, the payload is part of PCR 2). Pre-boot values
are unique to CrabEFI only if the measurements tell this payload apart from
another one a person could flash or boot.

The salted session protects the secret from someone *reading* the TPM
bus. Someone who can *drive* the bus, or the TPM, while the PCRs still hold
their pre-boot values can unseal the token. Use a TPM2 PIN in the OS for
that threat; CrabEFI does not support PINs yet.

### What the separators do not do

A separator only takes away the pre-boot PCR state. It does not
authenticate what boots next. In native-only mode CrabEFI measures neither
the kernel nor the initramfs nor the command line. With a TPM token,
anyone at the machine can start the volume's boot entries without a
passphrase. CrabEFI therefore does not allow command-line edits on entries
from a volume the TPM unlocked, so `init=/bin/sh` and the like are
refused. The OS must still protect itself once it runs, by asking for a
login, for example.

LUKS2 without integrity protection does not authenticate the data:
changing the ciphertext changes the plaintext unpredictably, block by block.

### After the firmware

The kernel does not receive the volume key. The initramfs unlocks the root
file system again: through its own TPM token bound to the OS's PCR state, a
key file inside the (encrypted) initramfs, or a passphrase prompt. A key
file in the initramfs is only as safe as the boot path: with a TPM token,
anyone can boot that initramfs. That is safe only while the volume's
kernel, initramfs and command line (which cannot be edited at the menu)
keep the key to themselves.

Before any code other than CrabEFI runs (an EFI image of any type, the
kernel, a payload), CrabEFI ends its trusted phase:

- it measures the separators into each of PCRs 0–7 that has none yet.
  `luks` builds then refuse to start the next stage unless a TPM 2.0
  recorded all eight, whenever the platform has one. That includes a TPM
  the platform described but that failed to come up for CrabEFI, and it
  holds whether or not this boot used a TPM secret: the sealed objects are
  on the disk for anyone to load, and a TPM that failed for the firmware
  may still work for the next stage. A machine with a broken TPM then
  boots no entry until the TPM works or the platform stops describing it.
  A TPM 2.0 counts as present when ACPI lists one (present, even if
  disabled), the platform configures one, or coreboot's log holds
  measurements in a TPM 2.0 bank. A log measured in SHA-1 only counts too,
  unless the platform identifies a TPM 1.2. A working TPM whose active
  banks the inherited log cannot replay still takes the separators in
  every bank; the event log then stays log-only for the OS.
  The menu stays up with its reset action. When the event log is full, the
  PCRs are extended without logging;
- it wipes every volume key, and the unused firmware stack from its bottom
  up to the current stack pointer. In `luks` builds the heap clears every
  block when it is freed, so freed decrypted data does not linger.
  Keyboard queues, repeat state and the USB transfer buffer of the last
  report are cleared after each passphrase entry;
- a kernel or initramfs load that fails or is refused is zeroed before its
  memory is released.

Builds without `luks` keep the TCG ordering: their separators come with the
first application's ReadyToBoot.

Resets and halts from the firmware wipe the same secrets. On a fatal
error (a panic or a CPU exception), CrabEFI only clears the volume keys
and the unused stack, without allocating. If the error interrupts a read
from an unlocked volume, the volume registry is in use and the keys stay
too. A loaded kernel or initramfs, or
the Argon2 work area of an interrupted unlock, may stay in memory until the
next reset.

## Testing

`./crabefi test --app luks-linux` boots a UEFI payload from a LUKS2 volume
after a wrong and then the right passphrase.
`./crabefi test --app luks-tpm-linux` does the same with a UEFI
payload and a token bound to PCRs 2 and 4, which UEFI mode measures only
when the first boot option starts.
`./crabefi test --app native-only-luks-tpm-linux` enrolls two
`systemd-tpm2` tokens into an swtpm state: one bound to a PCR 1 value the
firmware never has, one to PCRs 0 and 7 before the separators. It then
checks that a native-only payload refuses the first and unlocks with the
second. After the separators, the payload (built with the test-only
`luks-test-post-cap` feature) tries the second token again and checks
that the TPM refuses it before Linux starts. The UEFI TPM test checks the
same. All three tests need `cryptsetup` and `mke2fs`. The TPM tests also
need `swtpm`, `systemd-cryptenroll` and the tpm2-tss `swtpm` TCTI. The
volumes are encrypted offline (`cryptsetup reencrypt --encrypt`), so no
test needs root.

`cargo test -p crabefi-core --features luks,tpm --lib luks` unlocks volumes
made by cryptsetup with each KDF and sector size. Set
`CRABEFI_REQUIRE_CRYPTSETUP=1` to fail instead of skipping without
cryptsetup.
