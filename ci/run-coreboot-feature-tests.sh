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
assert "varstore::persist_variable(&COREBOOT_CFR_GUID, &name, attrs, &data)" in write_block, (
    "CFR writes must persist to the backend"
)
assert "varstore::update_variable_in_memory(&COREBOOT_CFR_GUID, &name, attrs, &data);" in write_block, (
    "CFR writes must refresh CrabEFI's in-memory variable cache"
)
assert write_block.index("varstore::persist_variable") < write_block.index("varstore::update_variable_in_memory"), (
    "CFR cache update must happen after successful backend persistence"
)

delete_match = re.search(
    r"pub fn delete_option_value\(.*?\n}\n\nfn delete_option_from_memory",
    src,
    re.S,
)
assert delete_match, "delete_option_value block not found"
delete_block = delete_match.group(0)
assert "varstore::delete_variable(&COREBOOT_CFR_GUID, &name)" in delete_block, (
    "CFR deletes must remove the persisted backend variable"
)
assert "delete_option_from_memory(&name);" in delete_block, (
    "CFR deletes must invalidate CrabEFI's in-memory variable cache"
)
assert delete_block.index("varstore::delete_variable") < delete_block.index("delete_option_from_memory"), (
    "CFR cache invalidation must happen after successful backend delete"
)

memory_delete_match = re.search(r"fn delete_option_from_memory\(.*?\n}\n\Z", src, re.S)
assert memory_delete_match, "delete_option_from_memory helper not found"
memory_delete_block = memory_delete_match.group(0)
assert "var.in_use = false;" in memory_delete_block, "CFR memory delete must mark cache entry unused"
assert "crabefi::efi::utils::ucs2_eq(&var.name, name)" in memory_delete_block, (
    "CFR memory delete must match UCS-2 variable names exactly"
)

print("CFR variable-cache regression checks passed")
PY
