#!/usr/bin/env bash
# Run each fuzz target for a bounded time, starting from the checked-in seeds.
# Usage: ci/fuzz.sh [seconds-per-target]
set -euo pipefail
cd "$(dirname "$0")/../fuzz"
seconds=${1:-60}

# Target and largest input. Disk images need room for a whole filesystem.
targets=(
    pe:65536
    partitions:65536
    fat:131072
    iso9660:131072
    boot_config:4096
    pkcs7:8192
    device_path:70000
)

# Prebuilt cargo-fuzz binaries default to the target they were built for,
# which may be musl. libFuzzer's sanitizers need the glibc host target.
target=$(rustc -vV | sed -n 's/^host: //p')
cargo fuzz build -O --target "$target"
for entry in "${targets[@]}"; do
    fuzz_target=${entry%%:*}
    max_len=${entry#*:}
    corpus="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/crabefi-fuzz/$fuzz_target"
    mkdir -p "$corpus" "artifacts/$fuzz_target"
    echo "::group::fuzz $fuzz_target"
    cargo fuzz run -O --target "$target" "$fuzz_target" "$corpus" "seeds/$fuzz_target" -- \
        -max_total_time="$seconds" -max_len="$max_len" -rss_limit_mb=4096 \
        -artifact_prefix="artifacts/$fuzz_target/" -print_final_stats=1
    echo "::endgroup::"
done
