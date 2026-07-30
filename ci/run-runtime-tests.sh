#!/usr/bin/env bash
# Run the standalone crabefi-runtime unit tests from outside the repository so
# Cargo does not inherit the firmware-only .cargo/config.toml.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

(cd /tmp && cargo +nightly test --manifest-path "$ROOT/crabefi-runtime/Cargo.toml")
