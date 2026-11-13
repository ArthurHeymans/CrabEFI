//! On-demand USB and the external boot policy: cold boots with an NVMe and a
//! USB disk that share one persistent variable store.
use super::*;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The external (USB) disk created next to the internal (NVMe) one.
pub(crate) fn usb_disk_path(disk: &Path) -> PathBuf {
    disk.with_extension("usb.img")
}

/// Boot once until the guest resets or exits (-no-reboot) and return its serial log.
fn boot(
    config: &QemuConfig,
    flash: &Path,
    disk: &Path,
    report: &Path,
    label: &str,
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
    cmd.args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);
    if !config.disable_kvm && is_kvm_available() {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        cmd.args(["-cpu", "max"]);
    }
    let usb = usb_disk_path(disk);
    cmd.args([
        "-drive",
        &format!(
            "file={},if=none,id=nvme0,format=raw,snapshot=on",
            disk.display()
        ),
    ]);
    cmd.args(["-device", "nvme,serial=deadbeef,drive=nvme0"]);
    cmd.args(["-device", "qemu-xhci,id=xhci"]);
    cmd.args([
        "-drive",
        &format!(
            "file={},if=none,id=usbdisk,format=raw,snapshot=on",
            usb.display()
        ),
    ]);
    cmd.args(["-device", "usb-storage,drive=usbdisk,bus=xhci.0"]);
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
        if Instant::now() >= deadline {
            cleanup_child(&mut child);
            bail!("{label} timed out; see {}", serial.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(fs::read_to_string(&serial).unwrap_or_default())
}

fn expect(log: &str, label: &str, present: &[&str], absent: &[&str]) -> Result<()> {
    if let Some(line) = log.lines().find(|line| line.contains("BPOL TEST FAILED")) {
        bail!("{label}: {}", line.trim());
    }
    for marker in present {
        if !log.contains(marker) {
            bail!("{label}: missing {marker:?}");
        }
    }
    for marker in absent {
        if log.contains(marker) {
            bail!("{label}: unexpected {marker:?}");
        }
    }
    println!("[PASS] {label}");
    Ok(())
}

pub(super) fn run(config: &QemuConfig, disk: &Path) -> Result<()> {
    if !matches!(config.arch, Arch::X86_64) {
        bail!("boot-policy-test currently requires x86-64 QEMU");
    }
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let report = crate::project_root().join(format!("target/boot-policy-reports/{stamp}"));
    fs::create_dir_all(&report)?;
    println!("Boot policy logs: {}", report.display());
    let flash = prepare_runtime_test_flash(Path::new(&config.coreboot_rom))?;
    let boot = |label: &str| boot(config, flash.path(), disk, &report, label);

    // No BootOrder: the removable-media path needs USB first.
    // The default Error log level hides firmware markers until phase 0
    // raises it; the menu itself shows the USB disk.
    let log = boot("fallback")?;
    expect(
        &log,
        "removable-media fallback initializes USB",
        &["Boot Entry (xHCI USB)", "BPOL FALLBACK PASSED"],
        &[],
    )?;

    let log = boot("internal")?;
    expect(
        &log,
        "BootOrder from NVMe without USB",
        &["USB: initialization deferred", "BPOL INTERNAL PASSED"],
        &["USB: initializing on demand", "binding USB driver"],
    )?;

    let log = boot("usb-fallback")?;
    expect(
        &log,
        "failed internal BootOrder falls back to USB",
        &[
            "USB: initializing on demand (no BootOrder option started)",
            "=== BootOrder: retrying on USB ===",
            "BPOL USB FALLBACK PASSED",
        ],
        &[],
    )?;

    let log = boot("deny")?;
    expect(
        &log,
        "Deny refuses the USB boot option and hides USB",
        &[
            "external boot Deny",
            "Boot policy: not retrying BootOrder on USB",
            "is external; hiding it",
            "Found 1 boot entries",
            "BPOL DENY PASSED",
        ],
        &["=== BootOrder: retrying on USB ==="],
    )?;

    let log = boot("menu-only")?;
    expect(
        &log,
        "MenuOnly refuses the USB boot option, lists USB, and is not writable by the OS",
        &[
            "external boot MenuOnly",
            "Boot policy: not retrying BootOrder on USB",
            "Found 2 boot entries",
            "BPOL MENU ONLY PASSED",
            "BPOL TEST PASSED",
        ],
        &["=== BootOrder: retrying on USB ==="],
    )?;
    Ok(())
}
