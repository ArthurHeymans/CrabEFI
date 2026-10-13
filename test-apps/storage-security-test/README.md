# Storage protocol test app

The default CI mode validates the advertised Storage Security interface's
invalid-parameter handling and enumerates NVMe, ATA, and SCSI pass-through
devices. Missing hardware is a skip; protocol/open/enumeration errors fail.
Each probe has a 16-handle capacity; exceeding it fails explicitly rather than
claiming complete coverage.

Active security transfers and TCG Discovery0 require capable hardware and an
associated Block I/O protocol exposing the correct media ID. Build that mode
from the repository root with:

```sh
cargo build --release --target x86_64-unknown-uefi \
  --manifest-path test-apps/storage-security-test/Cargo.toml \
  --features hardware-security-probes
```

Copy `test-apps/storage-security-test/target/x86_64-unknown-uefi/release/storage-security-test.efi`
to an ESP and boot it manually. `./crabefi test` rebuilds the default mode.
CI compiles the hardware mode but does not run it against ordinary QEMU drives.

CrabEFI currently creates separate Storage Security and Block I/O handles with
different media IDs. Until their association is corrected, the active mode
reports its missing same-handle Block I/O prerequisite as a failure. It does
not guess a media ID or turn `MEDIA_CHANGED`/device errors into skips.
