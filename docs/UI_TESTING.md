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
