//! Build script for CrabEFI core library
//!
//! Records the build's `SOURCE_DATE_EPOCH` (0 when unset) for the timestamps
//! the firmware puts on key databases it writes itself, and the build
//! identifier measured as the S-CRTM version. Linker scripts and
//! PAYLOAD_BASE are handled by crabefi-coreboot/build.rs.

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
}
