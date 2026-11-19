//! Exercise recovery to a native FAT boot without publishing EFI to Linux.
use super::*;
use std::io::Write;
use std::time::{Duration, Instant};

const RECOVERY_MENU: &str = "Showing boot menu (autoboot timeout: 0s)";

pub(super) fn run(config: &QemuConfig, disk: &Path) -> Result<()> {
    let log = tempfile::NamedTempFile::new()?;
    let mut cmd = build_qemu_command_x86_64(
        config,
        disk,
        &config.coreboot_rom,
        CaptureScenario::BootSmoke,
    )?;
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(log.reopen()?)
        .stderr(Stdio::inherit())
        .spawn()
        .context("start QEMU for native FAT test")?;

    let result = (|| -> Result<()> {
        let start = Instant::now();
        let timeout = Duration::from_secs(config.timeout_secs.unwrap_or(60));
        let mut sent_selection = false;
        loop {
            let output = fs::read(log.path())?;
            let text = String::from_utf8_lossy(&output);
            anyhow::ensure!(
                !text.contains("EFI System Table at:")
                    && !text.contains("Hello from CrabEFI!")
                    && !text.contains("Dispatching to UEFI boot path"),
                "native payload initialized EFI or ran the fallback application"
            );
            if text
                .lines()
                .any(|line| line.trim() == crate::disk::NATIVE_FAT_SUCCESS)
            {
                anyhow::ensure!(sent_selection, "Linux booted without a manual selection");
                return Ok(());
            }
            if !sent_selection && text.contains(RECOVERY_MENU) {
                anyhow::ensure!(text.contains("Direct Linux boot: Broken native BLS default"));
                anyhow::ensure!(text.contains("Direct Linux boot failed"));
                anyhow::ensure!(text.matches("Found 2 boot entries").count() == 2);
                // The two native entries are BLS first and GRUB second. The
                // serial keyboard can select the second entry and press Enter.
                let input = child.stdin.as_mut().context("missing QEMU stdin")?;
                input.write_all(b"2\r")?;
                input.flush()?;
                sent_selection = true;
            }
            anyhow::ensure!(
                child.try_wait()?.is_none(),
                "QEMU exited before Linux confirmed native boot"
            );
            anyhow::ensure!(start.elapsed() < timeout, "native FAT test timed out");
            std::thread::sleep(Duration::from_millis(50));
        }
    })();
    cleanup_child(&mut child);
    if result.is_err() {
        let output = fs::read(log.path())?;
        eprintln!("{}", String::from_utf8_lossy(&output));
    }
    result?;
    println!(
        "[PASS] native_fat: Recovered from a failed BLS boot and ran Linux with ACPI but no EFI"
    );
    Ok(())
}
