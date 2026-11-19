//! Build script for the coreboot payload binary.
//!
//! Handles linker script selection, runtime-image embedding, and payload symbols.

use crabefi_runtime_abi::{ValidatedImage, architecture};
use sha2::{Digest, Sha256};

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if std::env::var_os("CARGO_FEATURE_ENTRY64").is_some() && !target.starts_with("x86_64") {
        panic!("the entry64 feature is only supported on x86-64");
    }
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
    let native_only = std::env::var_os("CARGO_FEATURE_NATIVE_ONLY").is_some();
    match (bundled_runtime, external_runtime, native_only) {
        (true, false, false) => {}
        (false, true, false) => embed_runtime_image(runtime_architecture),
        (false, false, true) => {
            assert!(target.starts_with("x86_64"), "native-only requires x86-64");
            for (env, feature) in [
                ("SECURE_BOOT_ENFORCED", "secure-boot-enforced"),
                ("PAYLOAD_MM", "payload-mm"),
                ("CAPSULE_ON_DISK_ONLY", "capsule-on-disk-only"),
                ("BOOT_EVENT_LOG", "boot-event-log"),
                ("EXTERNAL_BOOT_SETTING", "external-boot-setting"),
                (
                    "REPLAY_TEST_RESET_AFTER_PERSIST",
                    "replay-test-reset-after-persist",
                ),
                (
                    "PAYLOAD_MM_TEST_LOSE_READY_TO_BOOT",
                    "payload-mm-test-lose-ready-to-boot",
                ),
                ("UI", "ui"),
            ] {
                assert!(
                    std::env::var_os(format!("CARGO_FEATURE_{env}")).is_none(),
                    "native-only is incompatible with {feature}"
                );
            }
        }
        _ => panic!(
            "select exactly one of bundled-runtime-image, external-runtime-image, or native-only (use --no-default-features to replace bundled-runtime-image)"
        ),
    }
    if !native_only {
        embed_capsule_trust_store();
        if std::env::var_os("CARGO_FEATURE_PAYLOAD_MM").is_some() {
            embed_payload_mm_image();
        }
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = std::path::Path::new(&manifest_dir);

    if target.starts_with("x86_64") {
        let ld = manifest_path.join("x86_64-coreboot.ld");
        println!("cargo:rerun-if-changed={}", ld.display());

        // Define the symbol before the linker script evaluates its PROVIDE fallback.
        println!("cargo:rerun-if-env-changed=PAYLOAD_BASE");
        let payload_base = std::env::var("PAYLOAD_BASE").unwrap_or_else(|_| "0x100000".to_string());
        println!("cargo:rustc-link-arg-bin=crabefi=--defsym=__payload_base={payload_base}");
        println!("cargo:rustc-link-arg-bin=crabefi=-T{}", ld.display());
        println!("cargo:rustc-link-arg-bin=crabefi=-no-pie");
    } else if target.starts_with("aarch64") {
        let ld = manifest_path.join("aarch64-coreboot.ld");
        println!("cargo:rerun-if-changed={}", ld.display());
        println!("cargo:rustc-link-arg-bin=crabefi=-T{}", ld.display());
        println!("cargo:rustc-link-arg-bin=crabefi=-no-pie");

        // Allow overriding the aarch64 payload base address at build time.
        // Default is for QEMU SBSA (DRAM starts at 0x100_0000_0000).
        // For QEMU virt (aarch64), set PAYLOAD_BASE=0x62000000.
        println!("cargo:rerun-if-env-changed=PAYLOAD_BASE");
        let payload_base =
            std::env::var("PAYLOAD_BASE").unwrap_or_else(|_| "0x10022000000".to_string());
        println!("cargo:rustc-link-arg-bin=crabefi=--defsym=PAYLOAD_BASE={payload_base}");
    } else if target.starts_with("riscv64") {
        let ld = manifest_path.join("riscv64-coreboot.ld");
        println!("cargo:rerun-if-changed={}", ld.display());
        println!("cargo:rustc-link-arg-bin=crabefi=-T{}", ld.display());
        println!("cargo:rustc-link-arg-bin=crabefi=-no-pie");

        // Allow overriding the riscv64 payload base address at build time.
        // Default is for QEMU virt (DRAM at 0x80000000, payload at +16MB).
        println!("cargo:rerun-if-env-changed=PAYLOAD_BASE");
        let payload_base =
            std::env::var("PAYLOAD_BASE").unwrap_or_else(|_| "0x81000000".to_string());
        println!("cargo:rustc-link-arg-bin=crabefi=--defsym=PAYLOAD_BASE={payload_base}");
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

/// Embed the capsule signing roots listed in CRABEFI_CAPSULE_TRUST_CERTS
/// (`:`-separated DER certificate files). Without it every capsule is refused.
///
/// The bytes read here are copied into OUT_DIR and embedded from there, and
/// the build reruns when the listed path, the file it resolves to or the
/// directory holding it changes. Retargeting a symlink to another certificate
/// therefore rebuilds with the new root rather than keeping the retired one.
fn embed_capsule_trust_store() {
    println!("cargo:rerun-if-env-changed=CRABEFI_CAPSULE_TRUST_CERTS");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let mut source = String::from("pub static CAPSULE_TRUST_STORE: &[&[u8]] = &[\n");
    for (index, path) in std::env::var("CRABEFI_CAPSULE_TRUST_CERTS")
        .unwrap_or_default()
        .split(':')
        .filter(|path| !path.is_empty())
        .enumerate()
    {
        let path = std::path::Path::new(path);
        let resolved = std::fs::canonicalize(path).expect("read capsule trust certificate");
        let der = std::fs::read(&resolved).expect("read capsule trust certificate");
        assert!(
            der.first() == Some(&0x30),
            "{} is not a DER certificate",
            path.display()
        );
        println!("cargo:rerun-if-changed={}", path.display());
        println!("cargo:rerun-if-changed={}", resolved.display());
        if let Some(directory) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            println!("cargo:rerun-if-changed={}", directory.display());
        }
        let copy = out.join(format!("capsule_trust_{index}.der"));
        std::fs::write(&copy, &der).expect("copy capsule trust certificate");
        source.push_str(&format!(
            "    include_bytes!({:?}),\n",
            copy.display().to_string()
        ));
    }
    source.push_str("];\n");
    std::fs::write(out.join("capsule_trust.rs"), source).expect("write capsule trust store");
}

/// Flatten the payload MM ELF (crabefi-mm/build.sh) into `payload_mm.img`:
/// "CRABMMI\0", u32 file size, u32 memory size, u32 entry, u32 relocation count,
/// u32 R_X86_64_RELATIVE offsets (addends already stored in place), image bytes.
fn embed_payload_mm_image() {
    println!("cargo:rerun-if-env-changed=CRABEFI_MM_ELF");
    let source = std::env::var("CRABEFI_MM_ELF")
        .expect("the payload-mm feature needs CRABEFI_MM_ELF (crabefi-mm/build.sh prints it)");
    println!("cargo:rerun-if-changed={source}");
    let elf = std::fs::read(&source).expect("read payload MM ELF");
    let u16_at = |o: usize| u16::from_le_bytes(elf[o..o + 2].try_into().unwrap());
    let u32_at = |o: usize| u32::from_le_bytes(elf[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(elf[o..o + 8].try_into().unwrap());
    assert!(
        elf.starts_with(b"\x7fELF\x02\x01") && u16_at(18) == 62,
        "not an x86-64 ELF64"
    );
    let entry = u64_at(24);
    let (phoff, phentsize, phnum) = (
        u64_at(32) as usize,
        u16_at(54) as usize,
        u16_at(56) as usize,
    );
    let (shoff, shentsize, shnum) = (
        u64_at(40) as usize,
        u16_at(58) as usize,
        u16_at(60) as usize,
    );

    let loads: Vec<usize> = (0..phnum)
        .map(|i| phoff + i * phentsize)
        .filter(|&ph| u32_at(ph) == 1)
        .collect();
    assert_eq!(
        loads.len(),
        1,
        "payload MM image must have exactly one PT_LOAD"
    );
    let ph = loads[0];
    let (offset, vaddr, filesz, memsz) = (
        u64_at(ph + 8) as usize,
        u64_at(ph + 16),
        u64_at(ph + 32) as usize,
        u64_at(ph + 40),
    );
    assert_eq!(vaddr, 0, "payload MM image must be linked at 0");
    let mut image = elf[offset..offset + filesz].to_vec();

    let shstrtab = shoff + u16_at(62) as usize * shentsize;
    let names = u64_at(shstrtab + 24) as usize;
    let mut relocations = Vec::new();
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let name_at = names + u32_at(sh) as usize;
        let name_end = name_at + elf[name_at..].iter().position(|&b| b == 0).unwrap();
        // --emit-relocs also keeps link-time .rela.* sections; only .rela.dyn applies at load.
        if u32_at(sh + 4) != 4 || &elf[name_at..name_end] != b".rela.dyn" {
            continue;
        }
        let (rel_off, rel_size) = (u64_at(sh + 24) as usize, u64_at(sh + 32) as usize);
        for r in (rel_off..rel_off + rel_size).step_by(24) {
            let (r_offset, r_info, addend) = (u64_at(r) as usize, u64_at(r + 8), u64_at(r + 16));
            assert_eq!(
                r_info & 0xffff_ffff,
                8,
                "only R_X86_64_RELATIVE is supported"
            );
            assert!(
                r_offset + 8 <= image.len(),
                "relocation outside the file image"
            );
            image[r_offset..r_offset + 8].copy_from_slice(&addend.to_le_bytes());
            relocations.push(r_offset as u32);
        }
    }

    let mut blob = b"CRABMMI\0".to_vec();
    for value in [
        filesz as u32,
        memsz as u32,
        entry as u32,
        relocations.len() as u32,
    ] {
        blob.extend_from_slice(&value.to_le_bytes());
    }
    for r in &relocations {
        blob.extend_from_slice(&r.to_le_bytes());
    }
    blob.extend_from_slice(&image);
    let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("payload_mm.img");
    std::fs::write(out, blob).expect("write payload MM blob");
}
