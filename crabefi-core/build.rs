//! Build script for CrabEFI core library
//!
//! Records the build's `SOURCE_DATE_EPOCH` (0 when unset) for the timestamps
//! the firmware puts on key databases it writes itself, the build identifier
//! measured as the S-CRTM version, and embeds the build's Secure Boot key set
//! (see [`embed_secure_boot_keys`]). Linker scripts and PAYLOAD_BASE are
//! handled by crabefi-coreboot/build.rs.

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let epoch = env::var("SOURCE_DATE_EPOCH").map_or(0, |value| {
        value
            .trim()
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("SOURCE_DATE_EPOCH is not a Unix timestamp: {value:?}"))
    });
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    fs::write(
        out_dir.join("source_date_epoch.rs"),
        format!("pub(crate) const SOURCE_DATE_EPOCH: u64 = {epoch};\n"),
    )
    .expect("write source_date_epoch.rs");

    // CRABEFI_BUILD_ID (set by the build), else the crate version.
    println!("cargo:rerun-if-env-changed=CRABEFI_BUILD_ID");
    let build_id = env::var("CRABEFI_BUILD_ID")
        .ok()
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| {
            env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION is set by cargo")
        });
    println!("cargo:rustc-env=CRABEFI_SCRTM_VERSION={build_id}");

    embed_secure_boot_keys(&out_dir);
}

/// DER certificates named by `var` (':'-separated paths).
fn certificates(var: &str) -> Vec<String> {
    println!("cargo:rerun-if-env-changed={var}");
    env::var(var)
        .unwrap_or_default()
        .split(':')
        .filter(|path| !path.is_empty())
        .map(|path| {
            let path = fs::canonicalize(path).unwrap_or_else(|_| panic!("{var}: {path} not found"));
            let der = fs::read(&path).expect("read certificate");
            assert!(
                der.first() == Some(&0x30),
                "{var}: {} is not DER",
                path.display()
            );
            println!("cargo:rerun-if-changed={}", path.display());
            format!("include_bytes!({:?})", path.display().to_string())
        })
        .collect()
}

/// Secure Boot keys enrolled on a store without keys: `CRABEFI_SB_PK` replaces
/// the placeholder PK; `CRABEFI_SB_KEK`/`CRABEFI_SB_DB` (platform owner) and
/// `CRABEFI_SB_MS_KEK`/`CRABEFI_SB_MS_DB` (Microsoft, e.g. the 2023 CAs) are
/// enrolled in addition to the Microsoft 2011 defaults.
fn embed_secure_boot_keys(out_dir: &std::path::Path) {
    let pk = certificates("CRABEFI_SB_PK");
    assert!(pk.len() <= 1, "CRABEFI_SB_PK takes one certificate");
    let list = |var| format!("&[{}]", certificates(var).join(", "));
    let source = format!(
        "pub(crate) static SB_PK: Option<&[u8]> = {};\n\
         pub(crate) static SB_KEK: &[&[u8]] = {};\n\
         pub(crate) static SB_DB: &[&[u8]] = {};\n\
         pub(crate) static SB_MS_KEK: &[&[u8]] = {};\n\
         pub(crate) static SB_MS_DB: &[&[u8]] = {};\n",
        pk.first()
            .map_or_else(|| "None".to_string(), |cert| format!("Some({cert})")),
        list("CRABEFI_SB_KEK"),
        list("CRABEFI_SB_DB"),
        list("CRABEFI_SB_MS_KEK"),
        list("CRABEFI_SB_MS_DB"),
    );
    fs::write(out_dir.join("secure_boot_keys.rs"), source).expect("write secure_boot_keys.rs");
}
