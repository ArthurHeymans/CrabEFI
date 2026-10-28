#!/usr/bin/env bash
# Check the entry selected at compile time, not just ELFCLASS64 (both are ELF64).
set -euo pipefail
if [[ $# != 2 || ( $1 != coreboot && $1 != entry64 ) ]]; then
    echo "usage: $0 {coreboot|entry64} payload.elf" >&2
    exit 2
fi
mode=$1
elf=$2
sections=$(readelf -SW "$elf")
notes=$(readelf -n "$elf")
if [[ $mode == coreboot ]]; then
    grep -Eq '\.entry32[[:space:]]' <<< "$sections"
    if grep -Eq '\.entry64[[:space:]]' <<< "$sections" || grep -q 'CrabEFI' <<< "$notes"; then
        echo "coreboot build unexpectedly contains the entry64 ABI" >&2
        exit 1
    fi
else
    grep -Eq '\.entry64[[:space:]]' <<< "$sections"
    if grep -Eq '\.entry32[[:space:]]' <<< "$sections"; then
        echo "entry64 build unexpectedly contains the coreboot entry" >&2
        exit 1
    fi
    grep -q 'CrabEFI' <<< "$notes"
    grep -q 'description data: 01 00 00 00' <<< "$notes"
fi
printf 'PASS: %s entry in %s\n' "$mode" "$elf"
