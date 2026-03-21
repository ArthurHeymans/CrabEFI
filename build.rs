//! Build script for CrabEFI

fn main() {
    // Tell Cargo to rerun this build script if either linker script changes
    println!("cargo:rerun-if-changed=x86_64-coreboot.ld");
    println!("cargo:rerun-if-changed=aarch64-coreboot.ld");

    // Allow overriding the aarch64 payload base address at build time.
    // Default is for QEMU SBSA (DRAM starts at 0x100_0000_0000).
    // For QEMU virt (aarch64), set PAYLOAD_BASE=0x62000000.
    println!("cargo:rerun-if-env-changed=PAYLOAD_BASE");
    let payload_base =
        std::env::var("PAYLOAD_BASE").unwrap_or_else(|_| "0x10022000000".to_string());
    println!("cargo:rustc-link-arg=--defsym");
    println!("cargo:rustc-link-arg=PAYLOAD_BASE={payload_base}");
}
