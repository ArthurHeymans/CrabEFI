#!/usr/bin/env bash
# Run the standalone crabefi-runtime unit tests from outside the repository so
# Cargo does not inherit the firmware-only .cargo/config.toml.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

(cd /tmp && cargo +nightly test --manifest-path "$ROOT/crabefi-runtime/Cargo.toml")

cat >"$TMPDIR/Cargo.toml" <<EOF
[package]
name = "phase-safety-compile-fail"
version = "0.0.0"
edition = "2024"

[dependencies]
crabefi-runtime = { path = "$ROOT/crabefi-runtime" }
EOF
mkdir -p "$TMPDIR/src"

compile_must_fail() {
    local case_name="$1"
    local expected="$2"
    if (cd /tmp && cargo +nightly check --quiet --manifest-path "$TMPDIR/Cargo.toml") \
        >"$TMPDIR/$case_name.stdout" 2>"$TMPDIR/$case_name.stderr"; then
        echo "$case_name unexpectedly compiled" >&2
        exit 1
    fi
    grep -q "$expected" "$TMPDIR/$case_name.stderr" || {
        cat "$TMPDIR/$case_name.stderr" >&2
        echo "$case_name failed for an unexpected reason" >&2
        exit 1
    }
}

cat >"$TMPDIR/src/main.rs" <<'EOF'
use crabefi_runtime::RuntimeState;

fn mutate_retired_backend(state: &mut RuntimeState) {
    state.secure_boot_enabled = true;
}

fn main() {}
EOF
compile_must_fail private-runtime-state "no field.*secure_boot_enabled"

cat >"$TMPDIR/src/main.rs" <<'EOF'
use core::marker::PhantomData;
use crabefi_runtime::BootCtx;

fn main() {
    let _ = BootCtx { _marker: PhantomData };
}
EOF
compile_must_fail private-token-constructor "private"
