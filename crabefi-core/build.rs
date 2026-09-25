//! Build script for CrabEFI core library
//!
//! Records the build's `SOURCE_DATE_EPOCH` (0 when unset) for the timestamps
//! the firmware puts on key databases it writes itself. Linker scripts and
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
}
