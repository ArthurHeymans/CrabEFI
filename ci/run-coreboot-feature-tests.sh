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

python3 - "$ROOT/crabefi-coreboot/src/cfr.rs" <<'PY'
import re
import sys
from pathlib import Path

src = Path(sys.argv[1]).read_text()

write_match = re.search(
    r"pub fn write_option_value\(.*?\n}\n\n/// Delete a CFR option",
    src,
    re.S,
)
assert write_match, "write_option_value block not found"
write_block = write_match.group(0)
assert "variables::set(&COREBOOT_CFR_GUID, &name, attrs, &data)" in write_block, (
    "CFR writes must use the authoritative runtime-image SetVariable facade"
)
assert "status != efi::Status::SUCCESS" in write_block, (
    "CFR writes must propagate runtime-image failures"
)

delete_match = re.search(r"pub fn delete_option_value\(.*?\n}\n\Z", src, re.S)
assert delete_match, "delete_option_value block not found"
delete_block = delete_match.group(0)
assert "variables::delete(&COREBOOT_CFR_GUID, &name)" in delete_block, (
    "CFR deletes must use the authoritative runtime-image facade"
)
assert "matches!(status, efi::Status::SUCCESS | efi::Status::NOT_FOUND)" in delete_block, (
    "CFR deletes must treat an already-absent override as the requested default state"
)
assert 'return Err("Failed to delete CFR variable")' in delete_block, (
    "CFR deletes must still propagate failures other than NOT_FOUND"
)

print("CFR runtime-image variable facade regression checks passed")
PY
