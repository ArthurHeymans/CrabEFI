#!/bin/sh
# Build the payload MM variant of the runtime image (feature "mm"); prints the ELF path.
set -eu
cd "$(dirname "$0")"
TARGET_DIR="$(pwd)/../target/runtime-mm"
CARGO_ENCODED_RUSTFLAGS="$(printf '%s\037' -C relocation-model=pic -C code-model=small -C link-arg=--no-relax -C linker=rust-lld -C link-arg=-pie -Z plt=yes | sed 's/\x1f$//')" \
  cargo build --release --target x86_64-unknown-none --target-dir "$TARGET_DIR" \
  -Z build-std=core,compiler_builtins -Z build-std-features=compiler-builtins-mem \
  --no-default-features --features mm "$@" >&2
echo "$TARGET_DIR/x86_64-unknown-none/release/crabefi-runtime-image"
