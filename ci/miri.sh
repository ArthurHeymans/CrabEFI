#!/usr/bin/env bash
# Run the crabefi-core host tests under Miri to catch undefined behavior in
# unsafe code: aliasing violations, misaligned or out-of-bounds accesses, and
# use after free. Host tests deliberately leak the RAM they hand the page
# allocator. The FAT filesystem tests take tens of minutes each under Miri, so
# only a short sequence through the published EFI file protocol runs from them.
set -euo pipefail
cd "$(dirname "$0")/.."

export MIRIFLAGS="${MIRIFLAGS:-} -Zmiri-ignore-leaks"
cargo miri test --locked -p crabefi-core --lib -- --skip fs::fat
cargo miri test --locked -p crabefi-core --lib -- --exact \
    fs::fat::tests::efi::protocol_round_trip_under_miri
