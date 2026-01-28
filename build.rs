//! Build script for CrabEFI

fn main() {
    // Tell Cargo to rerun this build script if the linker script changes
    println!("cargo:rerun-if-changed=x86_64-coreboot.ld");
}
