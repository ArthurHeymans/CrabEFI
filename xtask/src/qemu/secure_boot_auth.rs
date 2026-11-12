//! Multi-boot Secure Boot test: authenticated variables, key hierarchy and
//! image verification on file-backed persistent SMMSTORE. Each stage is a
//! separate QEMU process, so persistence is checked across cold boots.
use super::*;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_STAGES: usize = 3;

/// Erase SMMSTORE and seed `SecureBootEnable=1` without keys: the state the
/// setup UI leaves after "clear keys" and "enable Secure Boot". A blank store
/// would instead auto-enroll the built-in default keys and leave Setup Mode.
fn seed_setup_mode(flash: &Path) -> Result<()> {
    const FV_HEADER: usize = 72;
    const VS_HEADER: usize = 28;
    const AUTH_RECORD_HEADER: usize = 60;
    // gEfiSystemNvDataFvGuid and gEfiAuthenticatedVariableGuid, little-endian.
    const NV_DATA_FV_GUID: [u8; 16] = [
        0x8d, 0x2b, 0xf1, 0xff, 0x96, 0x76, 0x8b, 0x4c, 0xa9, 0x85, 0x27, 0x47, 0x07, 0x5b, 0x4f,
        0x50,
    ];
    const AUTH_VARIABLE_GUID: [u8; 16] = [
        0x78, 0x2c, 0xf3, 0xaa, 0x7b, 0x94, 0x9a, 0x43, 0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77,
        0x92,
    ];
    const GLOBAL_VARIABLE_GUID: [u8; 16] = [
        0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b,
        0x8c,
    ];

    let mut bytes = fs::read(flash)?;
    let (offset, size) = fmap_smmstore(&bytes)?
        .smmstore
        .context("test flash has no SMMSTORE")?;
    let region = bytes
        .get_mut(offset..offset + size)
        .context("SMMSTORE outside flash")?;
    region.fill(0xff);

    let fv = &mut region[..FV_HEADER];
    fv[..0x10].fill(0);
    fv[0x10..0x20].copy_from_slice(&NV_DATA_FV_GUID);
    fv[0x20..0x28].copy_from_slice(&(size as u64).to_le_bytes());
    fv[0x28..0x2c].copy_from_slice(b"_FVH");
    fv[0x2c..0x30].copy_from_slice(&0x0004_feffu32.to_le_bytes());
    fv[0x30..0x32].copy_from_slice(&(FV_HEADER as u16).to_le_bytes());
    fv[0x32..0x38].fill(0);
    fv[0x37] = 2;
    fv[0x38..0x3c].copy_from_slice(&1u32.to_le_bytes());
    fv[0x3c..0x40].copy_from_slice(&(size as u32).to_le_bytes());
    fv[0x40..0x48].fill(0);
    let sum = fv.as_chunks::<2>().0.iter().fold(0u16, |sum, word| {
        sum.wrapping_add(u16::from_le_bytes(*word))
    });
    fv[0x32..0x34].copy_from_slice(&0u16.wrapping_sub(sum).to_le_bytes());

    let vs = &mut region[FV_HEADER..FV_HEADER + VS_HEADER];
    vs[..16].copy_from_slice(&AUTH_VARIABLE_GUID);
    vs[16..20].copy_from_slice(&((size - FV_HEADER - VS_HEADER) as u32).to_le_bytes());
    vs[20] = 0x5a; // formatted
    vs[21] = 0xfe; // healthy
    vs[22..].fill(0);

    let name: Vec<u8> = "SecureBootEnable\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut record = vec![0u8; AUTH_RECORD_HEADER];
    record[..2].copy_from_slice(&0x55aau16.to_le_bytes());
    record[2] = 0x3f; // VAR_ADDED
    record[4..8].copy_from_slice(&0x7u32.to_le_bytes()); // NV | BS | RT
    record[0x24..0x28].copy_from_slice(&(name.len() as u32).to_le_bytes());
    record[0x28..0x2c].copy_from_slice(&1u32.to_le_bytes());
    record[0x2c..0x3c].copy_from_slice(&GLOBAL_VARIABLE_GUID);
    record.extend_from_slice(&name);
    record.push(1);
    let start = FV_HEADER + VS_HEADER;
    region[start..start + record.len()].copy_from_slice(&record);
    fs::write(flash, bytes)?;
    Ok(())
}

/// Boot once with persistent flash and return the serial log when QEMU exits,
/// or right after `kill_at` appears on serial, killing QEMU like a power cut.
fn boot(
    config: &QemuConfig,
    flash: &Path,
    disk: &Path,
    report: &Path,
    label: &str,
    kill_at: Option<&str>,
) -> Result<String> {
    let serial = report.join(format!("{label}.serial.log"));
    let stderr = fs::File::create(report.join(format!("{label}.stderr.log")))?;
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args([
        "-machine",
        "q35",
        "-m",
        "2G",
        "-display",
        "none",
        "-no-reboot",
    ]);
    cmd.args([
        "-drive",
        &format!("if=pflash,format=raw,file={}", flash.display()),
    ]);
    cmd.args(["-serial", &format!("file:{}", serial.display())]);
    if !config.disable_kvm && is_kvm_available() {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        cmd.args(["-cpu", "max"]);
    }
    add_storage_args_x86_64(&mut cmd, config, disk, false);
    for arg in &config.extra_devices {
        cmd.arg(arg);
    }
    fs::write(
        report.join(format!("{label}.command.txt")),
        format!("{cmd:?}\n"),
    )?;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(config.timeout_secs.unwrap_or(120));
    while child.try_wait()?.is_none() {
        if kill_at
            .is_some_and(|marker| fs::read_to_string(&serial).is_ok_and(|log| log.contains(marker)))
        {
            cleanup_child(&mut child);
            break;
        }
        if Instant::now() >= deadline {
            cleanup_child(&mut child);
            bail!("{label} timed out; see {}", serial.display());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(fs::read_to_string(&serial).unwrap_or_default())
}

/// Select the plan stage of the next boot through `\\sbtest\\stage.txt`.
fn set_stage(disk: &Path, stage: usize) -> Result<()> {
    let file = tempfile::NamedTempFile::new()?;
    fs::write(file.path(), stage.to_string())?;
    let status = Command::new("mcopy")
        .args(["-o", "-i", &crate::disk::mtools_esp_image(disk)])
        .arg(file.path())
        .arg("::/sbtest/stage.txt")
        .status()?;
    if !status.success() {
        bail!("mcopy stage.txt failed");
    }
    Ok(())
}

/// Kill QEMU after `writes` completed NV writes, then check on the next boot
/// that the keys are unchanged and the written variable is old or new.
fn power_loss_trial(
    config: &QemuConfig,
    flash: &Path,
    disk: &Path,
    report: &Path,
    writes: usize,
) -> Result<bool> {
    set_stage(disk, 4)?;
    let marker = format!("SBAUTH WRITE {writes}\r");
    let label = format!("power-loss-{writes}");
    let stress = boot(config, flash, disk, report, &label, Some(&marker))?;
    set_stage(disk, 5)?;
    let check = boot(config, flash, disk, report, &format!("{label}-check"), None)?;
    let logs = [stress, check];
    let keys = state(&logs, "s4-start").is_some_and(|keys| state(&logs, "s5-check") == Some(keys));
    let checks = logs[1]
        .lines()
        .filter(|line| line.starts_with("SBAUTH PASS ") || line.starts_with("SBAUTH FAIL "))
        .collect::<Vec<_>>();
    let ok = keys
        && logs[1].contains("SBAUTH COMPLETE")
        && !checks.is_empty()
        && checks.iter().all(|line| line.starts_with("SBAUTH PASS "));
    println!(
        "[{}] power-loss-after-write-{writes}: keys {}, {}",
        if ok { "PASS" } else { "FAIL" },
        if keys { "unchanged" } else { "CHANGED" },
        checks.join("; ")
    );
    Ok(ok)
}

/// `SBSTATE <label> ...` digest line printed by the app.
fn state(logs: &[String], label: &str) -> Option<String> {
    let prefix = format!("SBSTATE {label} ");
    logs.iter()
        .flat_map(|log| log.lines())
        .find_map(|line| line.trim_end().strip_prefix(&prefix).map(str::to_owned))
}

pub(super) fn run(config: &QemuConfig, disk: &Path) -> Result<()> {
    if !matches!(config.arch, Arch::X86_64) {
        bail!("secure-boot-auth-test currently requires x86-64 QEMU");
    }
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let report: PathBuf = crate::project_root().join(format!("target/sb-auth-reports/{stamp}"));
    fs::create_dir_all(&report)?;
    println!("Secure Boot auth test logs: {}", report.display());

    let flash = prepare_runtime_test_flash(Path::new(&config.coreboot_rom))?;
    seed_setup_mode(flash.path())?;
    let mut logs = Vec::new();
    for stage in 1..=MAX_STAGES {
        println!("Booting stage {stage}...");
        let log = boot(
            config,
            flash.path(),
            disk,
            &report,
            &format!("stage{stage}"),
            None,
        )?;
        let ended = log.contains(&format!("SBAUTH STAGE {stage} END"));
        let complete = log.contains("SBAUTH COMPLETE");
        logs.push(log);
        if !ended {
            bail!(
                "stage {stage} did not finish; see {}",
                report.join(format!("stage{stage}.serial.log")).display()
            );
        }
        if complete {
            break;
        }
    }

    let (mut passed, mut failed) = (0, 0);
    for line in logs.iter().flat_map(|log| log.lines()) {
        let line = line.trim_end();
        if let Some(rest) = line.strip_prefix("SBAUTH PASS ") {
            println!("[PASS] {rest}");
            passed += 1;
        } else if let Some(rest) = line.strip_prefix("SBAUTH FAIL ") {
            println!("[FAIL] {rest}");
            failed += 1;
        } else if let Some(rest) = line.strip_prefix("SBAUTH SKIP ") {
            println!("[SKIP] {rest}");
        }
    }
    if !logs
        .last()
        .is_some_and(|log| log.contains("SBAUTH COMPLETE"))
    {
        println!("[FAIL] complete: the plan did not reach its end");
        failed += 1;
    }
    for (before, after) in [("s1-end", "s2-start"), ("s2-end", "s3-start")] {
        let (old, new) = (state(&logs, before), state(&logs, after));
        if old.is_some() && old == new {
            println!("[PASS] persist-{after}: PK/KEK/db/dbx identical across reset");
            passed += 1;
        } else {
            println!("[FAIL] persist-{after}: {before} {old:?} != {after} {new:?}");
            failed += 1;
        }
    }

    // Opt-in: CrabEFI does not claim power-fail-safe SMMSTORE updates yet.
    let trials = std::env::var("CRABEFI_SB_POWER_LOSS_TRIALS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let baseline = fs::read(flash.path())?;
    for trial in 1..=trials {
        // Each cut starts from the post-stage-3 flash. 2 KiB records fill the
        // 64 KiB store within ~30 writes, so this crosses a compaction.
        fs::write(flash.path(), &baseline)?;
        let writes = 1 + (trial - 1) * 3;
        if power_loss_trial(config, flash.path(), disk, &report, writes)? {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    println!("\n=== Summary ===\nPassed: {passed}\nFailed: {failed}");
    if failed > 0 {
        bail!(
            "{failed} Secure Boot check(s) failed; logs in {}",
            report.display()
        );
    }
    Ok(())
}
