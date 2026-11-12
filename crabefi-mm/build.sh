#!/bin/sh
# Build the payload MM image (position-independent, own core build like crabefi-runtime-image).
set -eu
cd "$(dirname "$0")"
LD="$(pwd)/link/x86_64.ld"
CARGO_ENCODED_RUSTFLAGS="$(printf '%s\037' -C code-model=small -C relocation-model=pic -C "link-arg=-T$LD" -C link-arg=-pie -C link-arg=--no-dynamic-linker -C link-arg=-znorelro -C link-arg=--no-relax | sed 's/\x1f$//')" \
  cargo build --release --target x86_64-unknown-none \
  -Z build-std=core,compiler_builtins -Z build-std-features=compiler-builtins-mem "$@"
echo "$(pwd)/target/x86_64-unknown-none/release/crabefi-mm"
