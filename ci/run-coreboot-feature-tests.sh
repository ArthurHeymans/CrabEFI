#!/usr/bin/env bash
# Run fast host-side regression tests for coreboot payload features that are
# otherwise only exercised inside firmware/QEMU runs.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

rustc --edition=2024 --test \
    "$ROOT/crabefi-coreboot/src/cbmem_console.rs" \
    -o "$TMPDIR/cbmem_console_tests"
"$TMPDIR/cbmem_console_tests"

rustc --edition=2024 --test \
    "$ROOT/crabefi-coreboot/src/timestamps.rs" \
    -o "$TMPDIR/timestamp_tests"
"$TMPDIR/timestamp_tests"

rustc --edition=2024 --test \
    "$ROOT/crabefi-coreboot/src/memory_map.rs" \
    -o "$TMPDIR/memory_map_tests"
"$TMPDIR/memory_map_tests"

rustc --edition=2024 --test \
    "$ROOT/crabefi-core/src/efi/page_ownership.rs" \
    -o "$TMPDIR/page_ownership_tests"
"$TMPDIR/page_ownership_tests"

rustc --edition=2024 --test \
    "$ROOT/crabefi-core/src/efi/pool_free_list.rs" \
    -o "$TMPDIR/pool_free_list_tests"
"$TMPDIR/pool_free_list_tests"

for test_source in \
    "$ROOT/crabefi-core/src/efi/block_range.rs" \
    "$ROOT/crabefi-core/src/efi/dma_range.rs" \
    "$ROOT/crabefi-core/src/drivers/mmio_bounds.rs" \
    "$ROOT/crabefi-core/src/drivers/nvme/logic.rs" \
    "$ROOT/crabefi-core/src/drivers/ahci/logic.rs" \
    "$ROOT/crabefi-core/src/drivers/sdhci/logic.rs" \
    "$ROOT/crabefi-core/src/drivers/pci/access_rules.rs" \
    "$ROOT/crabefi-core/src/drivers/pci/capability.rs" \
    "$ROOT/crabefi-core/src/drivers/pci/command.rs"
do
    test_name="$(basename "${test_source%.rs}")_tests"
    rustc --edition=2024 --test "$test_source" -o "$TMPDIR/$test_name"
    "$TMPDIR/$test_name"
done

rustc --edition=2021 --test "$ROOT/test-apps/tcg-test/src/tpm.rs" -o "$TMPDIR/tcg_wire_tests"
"$TMPDIR/tcg_wire_tests"

# Check real CFR writes, reads, deletion and error propagation, not source text.
HOST="$(rustc -vV | awk '/^host:/ {print $2}')"
cargo test --locked --manifest-path "$ROOT/Cargo.toml" -p crabefi-core \
    --target "$HOST" --no-default-features --features cfr --test cfr_store
if [[ "$HOST" == x86_64-unknown-linux-gnu ]]; then
    cargo test --locked --manifest-path "$ROOT/Cargo.toml" -p crabefi-core \
        --target "$HOST" --no-default-features \
        --features cfr,variable-store,bundled-runtime-image --test runtime_lifecycle
fi
