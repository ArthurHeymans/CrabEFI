# UEFI conformance priorities

CrabEFI targets bootloader interoperability, not feature parity with EDK2.
Booting an OS and passing a selected SCT sequence are useful evidence, but are
not UEFI certification or proof that every required interface is conformant.
Any compatibility claim must identify the architecture, machine, firmware
profile, SCT version, passing cases, and remaining required-interface gaps.

## Priority order

| Priority | Interfaces / contracts | Why | Validation |
| --- | --- | --- | --- |
| P0 | System/Boot/Runtime table layouts, revisions, CRCs; required protocols and global variables | Establish the minimum platform contract before making a compliance claim | SCT `RequiredElements`, then `PlatformSpecificElements` with an honest machine configuration |
| P1 | Page/pool allocation, memory maps, events/timers/TPL, protocol handles and notifications, image loading/unloading | Every bootloader relies on these; invalid-argument/error paths matter as much as successful boot | Dedicated SCT sequences, independently booted, plus image-exit/protocol-notify integration tests |
| P1 | Block/Disk I/O, FAT file handles, file/directory information, flush/delete, device paths and collation | Load boot files reliably and preserve storage on failure | SCT filesystem/device-path sequences; writable disposable disks, USB/AHCI/NVMe integration tests |
| P1 | Runtime variables, time, virtual address conversion and ExitBootServices | Required for OS ownership and ongoing runtime calls | SCT boot-time runtime tests plus the existing post-EBS/SVAM/two-boot runtime-image test; explicit persistence limits |
| P2 | Advertised HII database/string/configuration protocols | An installed protocol is a contract, even if CrabEFI has no setup application using it | SCT HII sequences; unsupported encoding/configuration paths remain documented gaps, not silently skipped successes |
| P2 | GOP, text/serial input/output, RNG and security-enabled profiles | Feature-dependent but important for interactive boot and authenticated workflows | Separate hardware/feature profiles; SCT automatic cases where usable, dedicated QEMU tests for interactive/destructive paths |
| P3 | Network boot, EBC, external UEFI driver binding, optional pass-through protocols | Not needed for the current native-driver/local-disk boot target | Add only when supported/advertised, or when a required-interface audit shows they cannot legitimately be excluded |

P0 audits and P1 behavior should progress together. A failing mandatory audit is
not made optional just because the current implementation fails it. Conversely,
absence of a genuinely optional feature (for example network boot) is not a
reason to implement the entire EDK2 driver ecosystem.

## CI policy

- Keep explicit, version-pinned sequences, not "run whatever tests happen to
  discover a protocol". The sequence is also the validation manifest.
- Every selected case must have an explicit successful terminal result for each
  dispatched instance, positive assertion passes, zero errors and zero warnings.
  Protocol cases legitimately repeat per handle: require complete sequential
  instance dispatch and the exact result count. Missing/skipped, unsupported,
  extra or truncated results are not passes.
- Preserve serial output, the executed sequence, `Summary.log`, and detailed SCT
  reports on both success and failure. A failing case should be diagnosable from
  the CI artifacts, not require rerunning blindly.
- Split sequences by subsystem so one hang, reset or corrupted test state does
  not hide unrelated coverage. Run gating sequences under QEMU TCG as in CI;
  KVM characterization alone is not enough to promote a case.
- Manual, reset-required and destructive tests need dedicated harnesses. Do not
  run them against real media or count their exclusion as a successful test.
- Record failing implemented/required cases as gaps with a priority and reason.
  Promote them to mandatory CI after fixing them; do not weaken the checker or
  label them "irrelevant" to inflate the coverage number.

SCT cases contain different numbers of assertions and include hardware-specific
features. A percentage of the packaged case inventory is not a percentage of
UEFI specification coverage. Passing protocol-specific functional tests also
must not be presented as passing all of that protocol's conformance cases.

## Selected CI sequences

The pinned package is `edk2-test-stable202509` for x86_64; its local inventory
contains 608 registered cases in 78 modules. The old smoke selected six cases.
The subsystem manifests select **46 distinct cases**, not 46 complete interfaces:

| Manifest in `ci/sct/` | Cases | Scope / limits |
| --- | ---: | --- |
| `boot-memory.seq` | 6 | Memory-map functional/conformance and allocation/free conformance; not exhaustive allocation functional tests |
| `boot-services.seq` | 15 | Miscellaneous services, image start/unload/exit error paths, event creation/close, and two protocol-handler conformance cases |
| `device-path.seq` | 11 | Installed node validation, text-to-path conformance/coverage, utility conformance; not full conversion functionality |
| `block-io.seq` | 3 | Reset, reads, and read error contracts on every discovered Block I/O instance; no raw-block write qualification |
| `filesystem.seq` | 4 | File close (including writable-file use), open and position error contracts; volume-label gaps below remain failures |
| `hii-string.seq` | 6 | String parameter contracts and language enumeration; not complete font/SCSU/configuration support |
| `variables.seq` | 1 | Variable-name enumeration conformance only; no persistence or full variable-service claim |

Each job boots a fresh disposable USB disk under QEMU TCG on Q35. The original
six-case smoke remains a separate check, overlapping the subsystem manifests.
Artifacts contain the executed sequence, serial output, decoded summary,
detailed SCT directories, and `result.json` with the tested ROM SHA256 and CI
revision. Interface instance counts depend on the platform; they are not extra
unique test cases. These gates do not cover other architectures or real boards.

Run a gate locally:

```sh
./crabefi test --app uefi-sct-smoke --disable-kvm --timeout 900 \
  --sct-sequence ci/sct/boot-memory.seq \
  --sct-report-dir target/sct-reports/boot-memory
```

## Characterization findings and next work

Broader local probes selected about 219 cases across ten subsystem groups.
Every broad group failed or exceeded its time budget. Partial passing results
from those runs were **not** promoted as completed green profiles.

| Priority | Observed gap | Next validation / fix |
| --- | --- | --- |
| P0 | Required-elements audit: missing `EFI_DECOMPRESS_PROTOCOL` | Implement the required EFI decompression interface with bounded input/scratch/output handling; rerun the audit |
| P0 | Required-elements audit: runtime-properties mask assertion | Resolve the pinned SCT checker defect described below, without falsely advertising unsupported services |
| P0 | Platform-specific audit fails with the package's default feature assumptions | Establish a spec-backed machine configuration; distinguish genuine conditional requirements from unadvertised optional capabilities |
| P1 | Protocol uninstall/reinstall/install-multiple failures; subsequent clean-environment failures | Isolate protocol database lifecycle and rollback before running the larger group together |
| P1 | Event functional/signal failures and wait timeout; runtime-event registration unsupported | Fix notification/TPL scheduling and investigate isolated waits; retain the runtime-event limitation |
| P1 | `LoadImage_Conf` failures; `ExitBootServices_Conf` timeout | Test image error precedence/cleanup and EBS in separate disposable guests |
| P1 | Allocation and monotonic-counter functional probes timed out | Isolate the expensive cases and determine whether budgets or implementations are at fault |
| P1 | `OpenVolume_Func` and `GetInfo_Conf` fail because volume-label information is unsupported | Implement `EFI_FILE_SYSTEM_VOLUME_LABEL` contracts, including appropriate mutation semantics; do not label these cases irrelevant |
| P1 | Variable get conformance failures and functional warnings; persistence unavailable in the tested default ROM | Fix argument contracts and validate with an actual writable runtime-storage profile, including reset/persistence boundaries |
| P1/P2 | Device-path conversion functional/coverage failures | Complete the semantics of installed conversion protocols; preserve unsupported node/encoding limitations |
| P2 | Broad HII run did not complete | Expand isolated database/string/configuration sequences; installed protocols remain obligations |

The first expansion also corrects null-buffer memory-map validation, event
creation parameter validation, stale-media-ID read precedence, and null HII
package-handle validation. Their selected SCT cases remain mandatory gates.

Failing filesystem and required-element sequences remain reproducible under
`ci/sct/characterization/`; they are **not green CI gates**. Use the same command
above with one of those paths and retain its nonzero result and artifacts.
Full UEFI compliance cannot be claimed while genuine required gaps remain.

### Runtime-properties audit discrepancy

The pinned `EfiCompliantBBTestRequired_uefi.c::CheckRuntimePropertiesTable`
constructs its expected bitmap from non-NULL runtime function pointers. It
therefore expects `0x3FFF`, while the tested firmware reports `0x3DF1`. That
assertion alone does not establish a firmware defect:
[UEFI's runtime-properties contract](https://uefi.org/specs/UEFI/2.11/04_EFI_System_Table.html)
requires callable `EFI_UNSUPPORTED` implementations even for services whose
support bits are clear. Do not null the pointers or set unsupported bits just
to pass the assertion. The required audit still fails independently on missing
decompression, which the
[required-elements table](https://uefi.org/specs/UEFI/2.11/02_Overview.html)
explicitly requires. No checker exception currently converts either failure
into a pass.

## Existing evidence outside SCT

The QEMU jobs exercise boot paths through GRUB/Linux and native test
applications, including the separate runtime-image boundary, SVAM and warm-reset
variable/capsule replay. Host tests cover implementation-specific failure
recovery and security parsing. These complement SCT; they do not replace the
required-interface audit or physical-board qualification.

A local Windows installer PE image (Windows 10.0.26100.6584) reached userspace
and completed `wpeinit` under CrabEFI with KVM and TCG. That is local boot-path
evidence, not installed-Windows qualification or a pass of the optional CI
COM1-based marker check. The installer image lacks a usable COM1 device.

See [platform compatibility](COMPATIBILITY.md) and [capability contracts](capabilities.md)
for unsupported hardware and runtime persistence limits.
