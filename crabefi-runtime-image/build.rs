//! Select the architecture-specific runtime image linker script.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("-linux-") {
        return;
    }
    let script = if target.starts_with("x86_64") {
        "link/x86_64.ld"
    } else if target.starts_with("aarch64") {
        "link/aarch64.ld"
    } else if target.starts_with("riscv64") {
        "link/riscv64.ld"
    } else {
        panic!("unsupported runtime image target: {target}");
    };
    println!("cargo:rerun-if-changed={script}");
    println!("cargo:rustc-link-arg=-T{script}");
    println!("cargo:rustc-link-arg=-nostdlib");
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=defs");
    println!("cargo:rustc-link-arg=--no-undefined");
    println!("cargo:rustc-link-arg=--build-id=none");
    println!("cargo:rustc-link-arg=--emit-relocs");
}
