#!/usr/bin/env bash
# Public test PK/KEK/Microsoft db fixture; no production trust or revocation claim.
set -euo pipefail
if [[ $# != 2 ]]; then
    echo "usage: $0 EMPTY_OVMF_VARS OUTPUT_DIRECTORY" >&2
    exit 2
fi
input=$(realpath "$1")
mkdir -p "$2"
out=$(realpath "$2")
[[ ! -e $out/vars.fd ]] || { echo 'Use a fresh output directory' >&2; exit 1; }
virt-fw-vars --input "$input" --enroll-redhat --microsoft-db all --microsoft-kek all --sb \
    --output-json "$out/variables.json"
python3 - "$out/variables.json" "$out/crabefi-variables.json" <<'PY'
import json
import sys
from pathlib import Path
values = json.loads(Path(sys.argv[1]).read_text())
for variable in values['variables']:
    if variable['name'] == 'SecureBootEnable':
        # CrabEFI owns this preference in the global namespace, not EDK2's
        # f0a30bc7 vendor namespace. The standard SecureBoot status stays read-only.
        variable['guid'] = '8be4df61-93ca-11d2-aa0d-00e098032b8c'
        variable['attr'] = 7
Path(sys.argv[2]).write_text(json.dumps(values, indent=2) + '\n')
PY
virt-fw-vars --input "$input" --set-json "$out/crabefi-variables.json" --output "$out/vars.fd"
