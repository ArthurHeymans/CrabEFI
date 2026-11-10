# UI testing

The setup UI otherwise runs only in QEMU or on hardware. `ui-harness` runs the
same screens from `crabefi-ui` against a simulated backend (boot entries, CFR
settings and Secure Boot state), so UI changes can be checked in seconds
without booting firmware. It covers UI behaviour and pixels only: drivers,
variable persistence, signature verification and booting still need QEMU or
hardware.

## Tests

```sh
cargo test --locked -p crabefi-ui --features screens,secure-boot,cfr
cargo test --locked --manifest-path ui-harness/Cargo.toml
```

`ui-harness/tests/` drives `Playground`: inject keys, pointer and virtual
time, then assert on its state JSON or pixels.

## Screenshots

```sh
cargo run --manifest-path ui-harness/Cargo.toml --example shot -- \
    --scenario cfr --steps "BackTab ArrowDown Enter ArrowRight" /tmp/cfr.png
```

This saves the screen and prints the final UI state as JSON. Scenarios:
`normal`, `cfr`, `many`, `empty`, `countdown`, `secure`, `write-error` and
`no-settings`. Steps are key names (`Enter`, `Escape`, `Tab`, `BackTab`,
`ArrowDown`, `PageUp`, `F8`, `F10`, single characters), `click:X,Y`,
`pointer:X,Y`, `scroll:N` and `wait:MS`. `--size WxH` picks the framebuffer.

## Browser demo

The same harness compiles to WebAssembly. The `master` build is published at
https://arthurheymans.github.io/CrabEFI/. To run it locally:

```sh
rustup target add wasm32-unknown-unknown
bash ui-harness/build.sh    # names the wasm-bindgen-cli version it needs
python3 -m http.server 8080 --bind 127.0.0.1 --directory target/ui-harness-site
```

The page is a demo, not a second test target. `ui-harness/web/app.js` only
forwards DOM input, advances the clock and paints the framebuffer; fixtures,
key names and everything the UI does stay in Rust and are tested natively.
One Playwright smoke test covers what is left: loading, pixel conversion,
key forwarding and scaled pointer coordinates.

```sh
cd ui-harness && npm ci && npx playwright install --only-shell chromium && npm test
```
