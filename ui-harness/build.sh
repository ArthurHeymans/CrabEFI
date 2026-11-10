#!/usr/bin/env bash
# Build the browser demo into target/ui-harness-site: static files, no bundler.
set -euo pipefail
cd "$(dirname "$0")/.."

# The CLI must be the wasm-bindgen release that Cargo.lock resolved.
version=$(sed -n '/^name = "wasm-bindgen"$/{n;s/^version = "\(.*\)"$/\1/p}' ui-harness/Cargo.lock)
if [[ "${1:-}" == --wasm-bindgen-version ]]; then
    echo "$version"
    exit
fi
bindgen="${WASM_BINDGEN:-wasm-bindgen}"
if [[ "$("$bindgen" --version 2>/dev/null)" != "wasm-bindgen $version" ]]; then
    echo "Needs wasm-bindgen-cli $version: cargo install wasm-bindgen-cli --version $version --locked" >&2
    exit 1
fi

cargo build --locked --manifest-path ui-harness/Cargo.toml \
    --target-dir target/ui-harness --target wasm32-unknown-unknown --release
out=target/ui-harness-site
rm -rf "$out"
mkdir -p "$out"
"$bindgen" target/ui-harness/wasm32-unknown-unknown/release/crabefi_ui_harness.wasm \
    --target web --no-typescript --out-dir "$out/pkg"
cp ui-harness/web/* "$out/"
# The footer names the commit the page was built from.
revision=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
sed -i "s/@REVISION@/$revision/" "$out/index.html"
echo "Static site: $PWD/$out/"
