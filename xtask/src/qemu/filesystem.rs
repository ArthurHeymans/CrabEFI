//! Fail-closed checks for the disposable directory/mutation test disk.
use anyhow::{Context, Result, ensure};
use std::path::Path;
use std::process::Command;

const MUTATION: &str = "[PASS] filesystem_mutation:";
const READ_ONLY: &str = "[PASS] filesystem_read_only:";
const REQUIRED: [&str; 6] = [
    "Directory Enumeration Test",
    "[PASS] OpenVolume succeeded",
    "[PASS] long_filename:",
    "[PASS] long_filename_suffix:",
    "[PASS] short_filename:",
    "Directory enumeration test PASSED!",
];

pub(super) fn validate(output: &str, writable: bool) -> Result<()> {
    ensure!(
        !output.contains("[FAIL]") && !output.contains("test FAILED!"),
        "filesystem test reported a failure"
    );
    for marker in REQUIRED {
        ensure!(output.contains(marker), "filesystem test missing {marker}");
    }
    let (expected, unexpected) = if writable {
        (MUTATION, READ_ONLY)
    } else {
        (READ_ONLY, MUTATION)
    };
    ensure!(
        output.matches(expected).count() == 1 && !output.contains(unexpected),
        "filesystem test did not exercise the expected media protection"
    );
    Ok(())
}

/// Read the sentinel back with an independent FAT implementation after QEMU
/// exits. Guest-side readback alone could have observed only cached writes.
pub(super) fn verify_persisted_write(disk_path: &Path) -> Result<()> {
    let output = Command::new("mtype")
        .args([
            "-i",
            &crate::disk::mtools_esp_image(disk_path),
            "::/CRABWRITE.BIN",
        ])
        .output()
        .context("failed to read mutation sentinel with mtools")?;
    ensure!(
        output.status.success(),
        "mutation sentinel missing: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Vec<_> = std::iter::repeat_n(0xa5, 600)
        .chain(std::iter::repeat_n(0, 424))
        .chain(std::iter::repeat_n(0x5a, 400))
        .collect();
    ensure!(
        output.stdout == expected,
        "persisted mutation payload or zero-filled gap is incorrect"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completed(marker: &str) -> String {
        format!("{}\n{marker} exercised\n", REQUIRED.join("\n"))
    }

    #[test]
    fn requires_mutation_on_usb_and_protection_on_read_only_backends() {
        let writable = completed(MUTATION);
        let read_only = completed(READ_ONLY);
        validate(&writable, true).unwrap();
        validate(&read_only, false).unwrap();
        assert!(validate(&read_only, true).is_err());
        assert!(validate(&writable, false).is_err());
        for bad in [
            writable.replace(MUTATION, ""),
            writable.replace("Directory enumeration test PASSED!", ""),
            format!("{writable}\n{MUTATION}"),
            format!("{writable}\n[FAIL] close failed"),
            format!("{writable}\n{READ_ONLY}"),
        ] {
            assert!(validate(&bad, true).is_err(), "accepted {bad}");
        }
    }
}
