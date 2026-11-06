//! Reset-based firmware-UI regression, using the runtime test's real SMMSTORE.
use super::*;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const REQUEST: &str = "Consumed firmware UI request; OsIndications FW_UI cleared persistently";
const MENU: &str = "Showing firmware UI: boot menu (autoboot timeout: 0s)";

struct Vm {
    child: Child,
    serial: PathBuf,
    monitor: PathBuf,
    deadline: Instant,
}
impl Drop for Vm {
    fn drop(&mut self) {
        cleanup_child(&mut self.child);
        let _ = fs::remove_file(&self.monitor);
    }
}
impl Vm {
    fn output(&self) -> String {
        fs::read_to_string(&self.serial).unwrap_or_default()
    }
    fn wait_for(&mut self, marker: &str) -> Result<String> {
        self.wait_for_n(marker, 1)
    }
    fn wait_for_n(&mut self, marker: &str, count: usize) -> Result<String> {
        loop {
            let text = self.output();
            if text.contains("FWUI TEST FAILED") {
                bail!("EFI app failed; see {}", self.serial.display());
            }
            if text.matches(marker).count() >= count {
                return Ok(text);
            }
            if self.child.try_wait()?.is_some() {
                bail!(
                    "QEMU exited before {marker:?}; see {}",
                    self.serial.display()
                );
            }
            if Instant::now() >= self.deadline {
                bail!(
                    "timed out waiting for {marker:?}; see {}",
                    self.serial.display()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn key(&self, key: &str) -> Result<()> {
        let mut monitor = UnixStream::connect(&self.monitor)?;
        monitor.write_all(format!("sendkey {key}\n").as_bytes())?;
        Ok(())
    }
    fn stays_in_setup(&mut self, request_number: usize) -> Result<()> {
        let text = self.wait_for_n(MENU, request_number)?;
        let after_reset = text
            .split(REQUEST)
            .nth(request_number)
            .context("setup reached without consuming request")?;
        if after_reset.contains("=== BootNext:") || after_reset.contains("=== BootOrder:") {
            bail!("setup attempted automatic boot");
        }
        // Timeout is 2s in the EFI app; also exceed the ordinary default of 5s.
        let until = Instant::now() + Duration::from_secs(8);
        while Instant::now() < until {
            let output = self.output();
            let text = output
                .split(REQUEST)
                .nth(request_number)
                .unwrap_or_default();
            if self.child.try_wait()?.is_some()
                || text.contains("=== BootNext:")
                || text.contains("=== BootOrder:")
                || text.contains("FWUI MANUAL BOOT")
                || text.contains("FWUI TEST FAILED")
                || text.contains("Menu returned:")
            {
                bail!(
                    "setup exited/autobooted without input; see {}",
                    self.serial.display()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        println!("[PASS] setup stayed interactive for 8s without autoboot");
        Ok(())
    }
    fn wait_exit(&mut self) -> Result<()> {
        while self.child.try_wait()?.is_none() {
            if Instant::now() >= self.deadline {
                bail!("QEMU did not exit; see {}", self.serial.display());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }
}

fn start(
    config: &QemuConfig,
    flash: &Path,
    disk: Option<&Path>,
    report: &Path,
    label: &str,
    stop_on_reset: bool,
) -> Result<Vm> {
    let serial = report.join(format!("{label}.serial.log"));
    let stderr = fs::File::create(report.join(format!("{label}.stderr.log")))?;
    // Short socket path, independent of the report path/checkout length.
    let monitor = flash.with_extension("monitor.sock");
    let _ = fs::remove_file(&monitor);
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(["-machine", "q35", "-m", "2G", "-display", "none"]);
    cmd.args([
        "-drive",
        &format!("if=pflash,format=raw,file={}", flash.display()),
    ]);
    cmd.args(["-serial", &format!("file:{}", serial.display())]);
    cmd.args([
        "-monitor",
        &format!("unix:{},server=on,wait=off", monitor.display()),
    ]);
    cmd.args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);
    if stop_on_reset {
        cmd.arg("-no-reboot");
    }
    if !config.disable_kvm && is_kvm_available() {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        cmd.args(["-cpu", "max"]);
    }
    if let Some(disk) = disk {
        add_storage_args_x86_64(&mut cmd, config, disk, false);
    }
    for arg in &config.extra_devices {
        cmd.arg(arg);
    }
    fs::write(
        report.join(format!("{label}.command.txt")),
        format!("{cmd:?}\n"),
    )?;
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()?;
    Ok(Vm {
        child,
        serial,
        monitor,
        deadline: Instant::now() + Duration::from_secs(config.timeout_secs.unwrap_or(120)),
    })
}

pub(super) fn run(config: &QemuConfig, disk: &Path) -> Result<()> {
    if !matches!(config.arch, Arch::X86_64) {
        bail!("fwui-test currently requires x86-64 QEMU");
    }
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let report = crate::project_root().join(format!("target/fwui-reports/{stamp}"));
    fs::create_dir_all(&report)?;
    println!("Firmware UI regression logs: {}", report.display());

    let flash = prepare_runtime_test_flash(Path::new(&config.coreboot_rom))?;
    let mut vm = start(
        config,
        flash.path(),
        Some(disk),
        &report,
        "with-media",
        false,
    )?;
    vm.stays_in_setup(1)?;
    vm.key("ret")?;
    vm.wait_for("FWUI RUNTIME REQUEST WRITTEN; RESETTING")?;
    vm.stays_in_setup(2)?;
    vm.key("ret")?;
    vm.wait_for("FWUI TEST PASSED")?;
    vm.wait_exit()?;
    let text = vm.output();
    for marker in [
        "FWUI SUPPORTED PASSED",
        "FWUI REQUEST WRITTEN; RESETTING",
        "FWUI MANUAL BOOT: REQUEST CLEARED AND BOOTNEXT PRESERVED",
        "FWUI NORMAL BOOTNEXT PASSED",
        "FWUI NORMAL BOOTORDER PASSED",
        "FWUI RUNTIME MANUAL BOOT: REQUEST CLEARED",
        "FWUI RUNTIME SUBSEQUENT BOOT PASSED",
    ] {
        if !text.contains(marker) {
            bail!("missing {marker}");
        }
        println!("[PASS] {marker}");
    }
    if text.matches(REQUEST).count() != 2 {
        bail!("request was not one-shot");
    }
    drop(vm);

    // New erased store: run the same request writer, then unplug all storage
    // between QEMU processes. Flash writes are file-backed, not snapshots.
    let flash = prepare_runtime_test_flash(Path::new(&config.coreboot_rom))?;
    let mut writer = start(
        config,
        flash.path(),
        Some(disk),
        &report,
        "no-media-writer",
        true,
    )?;
    writer.wait_for("FWUI REQUEST WRITTEN; RESETTING")?;
    writer.wait_exit()?;
    drop(writer);
    let mut setup = start(config, flash.path(), None, &report, "no-media-setup", true)?;
    setup.stays_in_setup(1)?;
    setup.key("ret")?; // An empty menu must not return even on Enter.
    std::thread::sleep(Duration::from_secs(1));
    if setup.child.try_wait()?.is_some() || setup.output().contains("Menu returned:") {
        bail!("empty setup menu exited on Enter");
    }
    // The fixture has no framebuffer: verify the text menu's setup access,
    // not just that an empty loop remains alive.
    if setup.output().contains("CrabEFI Boot Menu") {
        let menus = setup.output().matches("CrabEFI Boot Menu").count();
        setup.key("f")?;
        setup.wait_for("Firmware Settings")?;
        setup.key("esc")?;
        setup.wait_for_n("CrabEFI Boot Menu", menus + 1)?;
        println!("[PASS] firmware settings accessible without boot media");
    }
    setup.key("r")?;
    setup.wait_exit()?;
    drop(setup);
    let mut normal = start(config, flash.path(), None, &report, "no-media-normal", true)?;
    let text = normal.wait_for("No bootable media found!")?;
    if text.contains(REQUEST) || text.contains(MENU) {
        bail!("no-media request was not cleared persistently");
    }
    println!(
        "[PASS] no-media setup, empty-menu Enter, persistent clear, and normal subsequent reboot"
    );
    Ok(())
}
