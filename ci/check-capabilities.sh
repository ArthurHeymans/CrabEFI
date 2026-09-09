#!/usr/bin/env bash
# Check additive firmware capabilities without workspace feature unification.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
HOST="$(rustc -vV | awk '/^host:/ {print $2}')"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cargo tree --locked -p crabefi-core --target x86_64-unknown-none --no-default-features \
    --features bundled-runtime-image,variable-store --edges normal --prefix none > "$TMP/core-tree"
if grep -E '^(xhci |rflasher-|rsa |x509-cert |cms |der |const-oid |signature |noto-sans-mono-bitmap )' "$TMP/core-tree"; then
    echo 'Unexpected optional capability dependency in the basic core' >&2
    exit 1
fi
cargo tree --locked --manifest-path crabefi-runtime-image/Cargo.toml --target x86_64-unknown-none \
    --no-default-features --edges normal --prefix none > "$TMP/runtime-tree"
if grep -E '^(rsa |crypto-bigint |allocator-api2 |sha2 )' "$TMP/runtime-tree"; then
    echo 'Unexpected authentication dependency in the basic runtime' >&2
    exit 1
fi

cargo tree --locked -p crabefi-core --target x86_64-unknown-none --no-default-features \
    --features capsule-update --edges normal --prefix none > "$TMP/capsule-tree"
if grep -E '^rflasher-' "$TMP/capsule-tree"; then
    echo 'Capsule application must not require SPI discovery' >&2
    exit 1
fi

for target in x86_64-unknown-none aarch64-unknown-none riscv64gc-unknown-none-elf; do
    cargo check --locked -p crabefi-core --target "$target" --release \
        --no-default-features --features bundled-runtime-image,variable-store
    cargo check --locked -p crabefi-core --target "$target" --release \
        --features full,ui,bundled-runtime-image
done
# Exercise independent capabilities, not just the endpoints of the feature set.
for features in tpm secure-boot capsule-update ui; do
    cargo check --locked -p crabefi-core --release --no-default-features --features "$features"
done
cargo test --locked -p crabefi-core --target "$HOST" --no-default-features --doc platform::VariableStorage
for features in '' variable-store full; do
    cargo test --locked -p crabefi-core --target "$HOST" --lib --no-default-features --features "$features"
done
if [[ "$HOST" == x86_64-unknown-linux-gnu ]]; then
    for features in variable-store,bundled-runtime-image full,bundled-runtime-image; do
        cargo test --locked -p crabefi-core --target "$HOST" --features "$features" --test runtime_lifecycle
    done
fi
cargo test --locked --manifest-path crabefi-runtime-abi/Cargo.toml --target "$HOST"
for features in '' full; do
    cargo test --locked --manifest-path crabefi-runtime-image/Cargo.toml --target "$HOST" \
        --no-default-features --features "$features"
done
for features in '' secure-boot; do
    cargo test --locked -p crabefi-runtime-bundle --target "$HOST" \
        --no-default-features --features "$features"
done
