//! Build script for CrabEFI core library
//!
//! Records the build's `SOURCE_DATE_EPOCH` (0 when unset) for the timestamps
//! the firmware puts on key databases it writes itself, and the build
//! identifier measured as the S-CRTM version. Linker scripts and
//! PAYLOAD_BASE are handled by crabefi-coreboot/build.rs.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

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

    // CRABEFI_BUILD_ID, else `git describe`, else the crate version.
    println!("cargo:rerun-if-env-changed=CRABEFI_BUILD_ID");
    let build_id = env::var("CRABEFI_BUILD_ID")
        .ok()
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty())
        .or_else(git_describe)
        .unwrap_or_else(|| {
            env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION is set by cargo")
        });
    println!("cargo:rustc-env=CRABEFI_SCRTM_VERSION={build_id}");
}

/// `git describe --always --dirty` of the CrabEFI checkout this crate is in.
fn git_describe() -> Option<String> {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR")?);
    let git = |args: &[&str]| -> Option<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&manifest_dir)
            .args(args)
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    // Not a repository that merely contains a vendored copy of this crate.
    let top_level = git(&["rev-parse", "--show-toplevel"])?;
    if fs::canonicalize(top_level).ok()? != fs::canonicalize(manifest_dir.parent()?).ok()? {
        return None;
    }
    let describe = git(&["describe", "--always", "--dirty"])?;
    // Describe again after a commit or checkout; a missing path would rerun
    // this script on every build.
    let branch = git(&["symbolic-ref", "-q", "HEAD"]);
    for name in ["HEAD", "packed-refs"].into_iter().chain(branch.as_deref()) {
        if let Some(path) = git(&["rev-parse", "--path-format=absolute", "--git-path", name])
            && Path::new(&path).exists()
        {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    Some(describe)
}
