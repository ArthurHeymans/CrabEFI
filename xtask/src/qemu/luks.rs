//! Boot Linux from ext inside LUKS2: by passphrase in a UEFI payload, and
//! by a systemd-tpm2 token in a native-only payload.
use super::*;
use crate::LuksTest;
use std::io::Write;
use std::time::{Duration, Instant};

const PROMPT: &str = "LUKS2: waiting for a passphrase";
const WRONG_KEY: &str = "LUKS2: no keyslot opens with this passphrase";
const TPM_UNLOCKED: &str = "unlocked with the TPM";
const SEPARATORS: &str = "Pre-OS separators measured";
const WIPED: &str = "LUKS2: wiping 1 volume key(s)";
const REFUSED_AFTER_CAP: &str = "LUKS2 test: the TPM refuses the token after the separators";

pub(super) fn run(config: &QemuConfig, disk: &Path, app: &str) -> Result<()> {
    let test = crate::luks_linux_test(app).context("not a LUKS test")?;
    let log = tempfile::NamedTempFile::new()?;
    let mut cmd = build_qemu_command_x86_64(
        config,
        disk,
        &config.coreboot_rom,
        CaptureScenario::BootSmoke,
    )?;
    let _swtpm = if config.enable_tpm {
        let (swtpm, args) = spawn_swtpm(config.tpm_state.as_deref())?;
        cmd.args(args);
        Some(swtpm)
    } else {
        None
    };
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(log.reopen()?)
        .stderr(Stdio::inherit())
        .spawn()
        .context("start QEMU for the LUKS2 test")?;

    let result = (|| -> Result<(String, usize)> {
        let start = Instant::now();
        let timeout = Duration::from_secs(config.timeout_secs.unwrap_or(120));
        let mut answered = 0;
        loop {
            let output = fs::read(log.path())?;
            let text = String::from_utf8_lossy(&output).into_owned();
            if text
                .lines()
                .any(|line| line.trim() == crate::disk::EXT_BOOT_SUCCESS)
            {
                return Ok((text, answered));
            }
            let prompts = text.matches(PROMPT).count();
            if matches!(test, LuksTest::Tpm { .. }) {
                anyhow::ensure!(prompts == 0, "the TPM token did not unlock the volume");
            } else if prompts > answered {
                // First a wrong passphrase, then the right one.
                let input = child.stdin.as_mut().context("missing QEMU stdin")?;
                if answered == 0 {
                    input.write_all(b"not the passphrase\r")?;
                } else {
                    anyhow::ensure!(text.contains(WRONG_KEY), "wrong passphrase not reported");
                    input.write_all(crate::disk::LUKS_PASSPHRASE.as_bytes())?;
                    input.write_all(b"\r")?;
                }
                input.flush()?;
                answered += 1;
                anyhow::ensure!(answered <= 2, "the passphrase was not accepted");
            }
            anyhow::ensure!(
                child.try_wait()?.is_none(),
                "QEMU exited before Linux ran from the LUKS2 volume"
            );
            anyhow::ensure!(start.elapsed() < timeout, "LUKS2 test timed out");
            std::thread::sleep(Duration::from_millis(50));
        }
    })();
    cleanup_child(&mut child);
    let (text, answered) = match result {
        Ok(found) => found,
        Err(err) => {
            eprintln!("{}", String::from_utf8_lossy(&fs::read(log.path())?));
            return Err(err);
        }
    };

    for line in text
        .lines()
        .filter(|line| line.contains("LUKS2") || line.contains(SEPARATORS))
    {
        println!("{}", line.trim());
    }
    let position = |needle: &str| {
        text.find(needle)
            .with_context(|| format!("'{needle}' not in the firmware log"))
    };
    // Keys must be gone, and with a TPM the PCRs capped, before Linux runs.
    let linux = position("Booting Linux via direct 64-bit entry")?;
    anyhow::ensure!(position(WIPED)? < linux, "volume key wiped after handoff");
    match test {
        LuksTest::Passphrase => {
            anyhow::ensure!(
                text.contains("EFI System Table at:"),
                "expected a UEFI payload"
            );
            // Proof of the rejection: the firmware reported the wrong
            // passphrase and asked again before the right one opened it.
            anyhow::ensure!(
                answered == 2 && text.contains(WRONG_KEY),
                "the wrong passphrase was not rejected before the right one"
            );
            println!("[PASS] luks_passphrase: Rejected a wrong passphrase, then booted Linux");
        }
        LuksTest::Tpm { native } => {
            anyhow::ensure!(
                text.contains("Native-only boot: UEFI services are disabled") == native,
                "expected a {} payload",
                if native { "native-only" } else { "UEFI" }
            );
            // Token 0 is bound to a PCR 1 value the firmware never has.
            anyhow::ensure!(
                text.contains("LUKS2 token 0: TPM unseal failed"),
                "the token with the wrong PCR policy was not refused"
            );
            // UEFI measured PCR 7's separator at startup; the cap is the
            // first separator after the unlock.
            let unlocked = position(TPM_UNLOCKED)?;
            let separators = text[unlocked..]
                .find(SEPARATORS)
                .map(|offset| unlocked + offset)
                .context("no separators after the TPM unlock")?;
            anyhow::ensure!(
                unlocked < separators && separators < linux,
                "PCRs were not capped between the TPM unlock and Linux"
            );
            // The postcondition itself: the real TPM no longer unseals it.
            anyhow::ensure!(
                separators < position(REFUSED_AFTER_CAP)?,
                "the TPM was not checked to refuse the token after the separators"
            );
            println!(
                "[PASS] luks_tpm: The PCR-bound token unlocked the volume; PCRs capped before Linux"
            );
        }
    }
    println!("[PASS] luks_userspace: Linux ran the initramfs from the encrypted volume");
    Ok(())
}
