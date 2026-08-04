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
assert "status != efi::Status::SUCCESS" in delete_block, (
    "CFR deletes must propagate runtime-image failures"
)

print("CFR runtime-image variable facade regression checks passed")
PY
