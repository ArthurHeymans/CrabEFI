//! Linker selection for the Cargo-only CrabEFI library-consumer fixture.

fn main() {
    let target = std::env::var("TARGET").expect("TARGET");
    let architecture = if target.starts_with("x86_64") {
        "x86_64"
    } else if target.starts_with("aarch64") {
        "aarch64"
    } else if target.starts_with("riscv64") {
        "riscv64"
    } else {
        panic!("unsupported fixture target: {target}");
    };
    let script = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"))
        .join("link")
        .join(format!("{architecture}.ld"));
    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rustc-link-arg=-T{}", script.display());
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rustc-link-arg=--build-id=none");
}
