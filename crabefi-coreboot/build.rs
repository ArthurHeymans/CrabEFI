//! Build script for the coreboot payload binary.
//!
//! Handles linker script selection and the aarch64 PAYLOAD_BASE symbol.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    // Point to linker scripts in the workspace root (they stay there for now)
    let workspace_root = std::path::Path::new(&manifest_dir).parent().unwrap();

    if target.starts_with("x86_64") {
        let ld = workspace_root.join("x86_64-coreboot.ld");
        println!("cargo:rerun-if-changed={}", ld.display());
        println!("cargo:rustc-link-arg=-T{}", ld.display());
        println!("cargo:rustc-link-arg=-no-pie");
    } else if target.starts_with("aarch64") {
        let ld = workspace_root.join("aarch64-coreboot.ld");
        println!("cargo:rerun-if-changed={}", ld.display());
        println!("cargo:rustc-link-arg=-T{}", ld.display());
        println!("cargo:rustc-link-arg=-no-pie");

        // Allow overriding the aarch64 payload base address at build time.
        // Default is for QEMU SBSA (DRAM starts at 0x100_0000_0000).
        // For QEMU virt (aarch64), set PAYLOAD_BASE=0x62000000.
        println!("cargo:rerun-if-env-changed=PAYLOAD_BASE");
        let payload_base =
            std::env::var("PAYLOAD_BASE").unwrap_or_else(|_| "0x10022000000".to_string());
        println!("cargo:rustc-link-arg=--defsym");
        println!("cargo:rustc-link-arg=PAYLOAD_BASE={payload_base}");
    } else if target.starts_with("riscv64") {
        let ld = workspace_root.join("riscv64-coreboot.ld");
        println!("cargo:rerun-if-changed={}", ld.display());
        println!("cargo:rustc-link-arg=-T{}", ld.display());
        println!("cargo:rustc-link-arg=-no-pie");

        // Allow overriding the riscv64 payload base address at build time.
        // Default is for QEMU virt (DRAM at 0x80000000, payload at +16MB).
        println!("cargo:rerun-if-env-changed=PAYLOAD_BASE");
        let payload_base =
            std::env::var("PAYLOAD_BASE").unwrap_or_else(|_| "0x81000000".to_string());
        println!("cargo:rustc-link-arg=--defsym");
        println!("cargo:rustc-link-arg=PAYLOAD_BASE={payload_base}");
    }
}
