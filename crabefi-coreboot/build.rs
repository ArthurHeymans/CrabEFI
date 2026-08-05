//! Build script for the coreboot payload binary.
//!
//! Handles linker script selection, runtime-image embedding, and payload symbols.

use crabefi_runtime_abi::{ValidatedImage, architecture};
use sha2::{Digest, Sha256};

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    let runtime_architecture = if target.starts_with("x86_64") {
        architecture::X86_64
    } else if target.starts_with("aarch64") {
        architecture::AARCH64
    } else if target.starts_with("riscv64") {
        architecture::RISCV64
    } else {
        panic!("unsupported coreboot payload target: {target}");
    };
    let bundled_runtime = std::env::var_os("CARGO_FEATURE_BUNDLED_RUNTIME_IMAGE").is_some();
    let external_runtime = std::env::var_os("CARGO_FEATURE_EXTERNAL_RUNTIME_IMAGE").is_some();
    match (bundled_runtime, external_runtime) {
        (true, false) => {}
        (false, true) => embed_runtime_image(runtime_architecture),
        (true, true) => {
            panic!("bundled-runtime-image and external-runtime-image are mutually exclusive")
        }
        (false, false) => panic!("select either bundled-runtime-image or external-runtime-image"),
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = std::path::Path::new(&manifest_dir);

    if target.starts_with("x86_64") {
        let ld = manifest_path.join("x86_64-coreboot.ld");
        println!("cargo:rerun-if-changed={}", ld.display());

        // Define the symbol before the linker script evaluates its PROVIDE fallback.
        println!("cargo:rerun-if-env-changed=PAYLOAD_BASE");
        let payload_base = std::env::var("PAYLOAD_BASE").unwrap_or_else(|_| "0x100000".to_string());
        println!("cargo:rustc-link-arg=--defsym=__payload_base={payload_base}");
        println!("cargo:rustc-link-arg=-T{}", ld.display());
        println!("cargo:rustc-link-arg=-no-pie");
    } else if target.starts_with("aarch64") {
        let ld = manifest_path.join("aarch64-coreboot.ld");
        println!("cargo:rerun-if-changed={}", ld.display());
        println!("cargo:rustc-link-arg=-T{}", ld.display());
        println!("cargo:rustc-link-arg=-no-pie");

        // Allow overriding the aarch64 payload base address at build time.
        // Default is for QEMU SBSA (DRAM starts at 0x100_0000_0000).
        // For QEMU virt (aarch64), set PAYLOAD_BASE=0x62000000.
        println!("cargo:rerun-if-env-changed=PAYLOAD_BASE");
        let payload_base =
            std::env::var("PAYLOAD_BASE").unwrap_or_else(|_| "0x10022000000".to_string());
        println!("cargo:rustc-link-arg=--defsym=PAYLOAD_BASE={payload_base}");
    } else if target.starts_with("riscv64") {
        let ld = manifest_path.join("riscv64-coreboot.ld");
        println!("cargo:rerun-if-changed={}", ld.display());
        println!("cargo:rustc-link-arg=-T{}", ld.display());
        println!("cargo:rustc-link-arg=-no-pie");

        // Allow overriding the riscv64 payload base address at build time.
        // Default is for QEMU virt (DRAM at 0x80000000, payload at +16MB).
        println!("cargo:rerun-if-env-changed=PAYLOAD_BASE");
        let payload_base =
            std::env::var("PAYLOAD_BASE").unwrap_or_else(|_| "0x81000000".to_string());
        println!("cargo:rustc-link-arg=--defsym=PAYLOAD_BASE={payload_base}");
    }
}

fn embed_runtime_image(expected_architecture: u16) {
    println!("cargo:rerun-if-env-changed=RUNTIME_IMAGE_PATH");
    println!("cargo:rerun-if-env-changed=RUNTIME_IMAGE_SHA256");
    let source = std::env::var("RUNTIME_IMAGE_PATH")
        .expect("RUNTIME_IMAGE_PATH is mandatory; build through ./crabefi build");
    println!("cargo:rerun-if-changed={source}");
    let bytes = std::fs::read(&source).expect("read normalized runtime image");
    ValidatedImage::parse(&bytes, expected_architecture)
        .expect("runtime image failed checked format/architecture validation");
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let expected =
        std::env::var("RUNTIME_IMAGE_SHA256").expect("RUNTIME_IMAGE_SHA256 is mandatory");
    let actual = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        expected, actual,
        "runtime image digest does not match xtask output"
    );

    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out.join("runtime.img"), bytes).expect("copy runtime image to OUT_DIR");
    let digest_source = format!("pub const RUNTIME_IMAGE_SHA256: [u8; 32] = {digest:?};\n");
    std::fs::write(out.join("runtime_digest.rs"), digest_source)
        .expect("write runtime image digest source");
}
