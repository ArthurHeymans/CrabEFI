//! Boot event log: the guest app checks every boot and resets; all boots run
//! in one QEMU process so CMOS (coreboot's CMOS_POST banks) survives.
use super::*;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MARKERS: &[&str] = &[
    "BEVT BOOT SERVICES WRITE REFUSED PASSED",
    "BEVT GROWTH PASSED",
    "BEVT WRAP PASSED",
    "BEVT OS WRITE REFUSED PASSED",
    "BEVT TEST PASSED",
];

pub(super) fn run(config: &QemuConfig, disk: &Path) -> Result<()> {
    if !matches!(config.arch, Arch::X86_64) {
        bail!("boot-events-test currently requires x86-64 QEMU");
    }
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let report = crate::project_root().join(format!("target/boot-events-reports/{stamp}"));
    fs::create_dir_all(&report)?;
    let serial = report.join("serial.log");
    println!("Boot events log: {}", serial.display());

    let flash = prepare_runtime_test_flash(Path::new(&config.coreboot_rom))?;
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(["-machine", "q35", "-m", "2G", "-display", "none"]);
    add_x86_boot_args(
        &mut cmd,
        flash.path().to_str().context("flash path is not UTF-8")?,
        CaptureScenario::BootEventLog,
    );
    cmd.args(["-serial", &format!("file:{}", serial.display())]);
    add_storage_args_x86_64(&mut cmd, config, disk, true);
    if !config.disable_kvm && is_kvm_available() {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        cmd.args(["-cpu", "max"]);
    }
    let stderr = fs::File::create(report.join("stderr.log"))?;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()?;
    // The timeout applies to each of the 33 boots.
    let timeout = Duration::from_secs(config.timeout_secs.unwrap_or(60));
    let boots = |log: &str| log.matches("BEVT BOOT phase=").count();
    let (mut seen, mut deadline) = (0, Instant::now() + timeout);
    while child.try_wait()?.is_none() {
        let now = boots(&String::from_utf8_lossy(
            &fs::read(&serial).unwrap_or_default(),
        ));
        if now != seen {
            (seen, deadline) = (now, Instant::now() + timeout);
        } else if Instant::now() >= deadline {
            cleanup_child(&mut child);
            bail!("boot-events-test timed out; see {}", serial.display());
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    let log = String::from_utf8_lossy(&fs::read(&serial)?).into_owned();
    let boots = boots(&log);
    println!("{boots} boots");
    for line in log
        .lines()
        .filter(|line| line.contains("BEVT ") && !line.contains("BEVT BOOT phase="))
    {
        println!("  {}", line.trim());
    }
    if let Some(line) = log.lines().find(|line| line.contains("BEVT TEST FAILED")) {
        bail!("{}", line.trim());
    }
    for marker in MARKERS {
        if !log.contains(marker) {
            bail!("missing {marker:?}; see {}", serial.display());
        }
    }
    if !log.contains("BEVT COREBOOT HANDOFF PASSED") {
        println!("[SKIP] coreboot handoff: the ROM has no CMOS_POST at 0x70 / ELOG_BOOT_EVENTS");
    }
    println!("[PASS] boot event log");
    Ok(())
}
