//! QMP-driven USB hotplug integration test.

use super::{CaptureScenario, QemuConfig, add_x86_boot_args, cleanup_child};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const CONTROLLERS: [&str; 4] = ["qemu-xhci", "usb-ehci", "piix3-usb-uhci", "pci-ohci"];

enum Topology {
    Standalone(&'static str),
    Companions { cold: bool },
}

impl Topology {
    fn name(&self) -> &'static str {
        match self {
            Self::Standalone(model) => model,
            Self::Companions { cold: false } => "ich9-ehci-companions-hot",
            Self::Companions { cold: true } => "ich9-ehci-companions-cold",
        }
    }

    fn add_args(&self, qemu: &mut Command) {
        match self {
            Self::Standalone(model) => {
                qemu.args(["-device", &format!("{model},id=hotusb")]);
            }
            Self::Companions { cold } => {
                qemu.args(["-device", "ich9-usb-ehci1,id=hotusb,addr=1d.7"]);
                for index in 0..3 {
                    let mut device = format!(
                        "ich9-usb-uhci{},masterbus=hotusb.0,firstport={},addr=1d.{index}",
                        index + 1,
                        index * 2
                    );
                    if index == 0 {
                        device.push_str(",multifunction=on");
                    }
                    qemu.args(["-device", &device]);
                }
                if *cold {
                    qemu.args(["-device", "usb-storage,bus=hotusb.0,port=1,drive=hotdisk"]);
                    qemu.args(["-device", "usb-hub,bus=hotusb.0,port=2"]);
                    qemu.args(["-device", "usb-kbd,bus=hotusb.0,port=2.1"]);
                }
            }
        }
    }
}

fn test_qemu(config: &QemuConfig) -> Command {
    let mut qemu = Command::new("qemu-system-x86_64");
    // No PS/2 input: the app can receive keys only from USB.
    qemu.args(["-machine", "q35,usb=off,i8042=off", "-m", "2G"]);
    if !config.disable_kvm && super::is_kvm_available() {
        qemu.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        qemu.args(["-cpu", "max"]);
    }
    qemu.args(["-display", "none", "-monitor", "none"]);
    qemu.stdin(Stdio::null()).stdout(Stdio::null());
    qemu
}

fn boot_order(
    config: &QemuConfig,
    disk: &Path,
    topology: &Topology,
    behind_hub: bool,
    timeout: Duration,
) -> Result<()> {
    let temp = tempfile::tempdir()?;
    let flash = super::prepare_runtime_test_flash(Path::new(&config.coreboot_rom))?;
    let build = |serial: &Path| -> Command {
        let mut qemu = test_qemu(config);
        qemu.args([
            "-no-reboot",
            "-drive",
            &format!("if=pflash,format=raw,file={}", flash.path().display()),
        ]);
        qemu.args(["-serial", &format!("file:{}", serial.display())]);
        qemu.args([
            "-drive",
            &format!(
                "if=none,format=raw,file={},snapshot=on,id=internal",
                disk.display()
            ),
        ]);
        qemu.args(["-device", "nvme,serial=cold-order,drive=internal"]);
        qemu
    };
    let seed_log = temp.path().join("seed.log");
    let mut seed = build(&seed_log).spawn()?;
    let deadline = Instant::now() + timeout;
    while seed.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            cleanup_child(&mut seed);
            bail!(
                "cold BootOrder seed did not reset: {}",
                fs::read_to_string(&seed_log).unwrap_or_default()
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
    let seed = fs::read_to_string(seed_log)?;
    if !seed.contains("USB BOOT ORDER: seed installed") {
        bail!("failed to seed BootOrder: {seed}");
    }

    let serial = temp.path().join("cold.log");
    let usb = super::boot_policy::usb_disk_path(disk);
    let mut qemu = build(&serial);
    qemu.args([
        "-drive",
        &format!(
            "if=none,format=raw,file={},snapshot=on,id=hotdisk",
            usb.display()
        ),
    ]);
    topology.add_args(&mut qemu);
    let port = if behind_hub || matches!(topology, Topology::Companions { .. }) {
        // QEMU mass storage supports high and full speed. Put it behind
        // a full-speed hub so EHCI hands that root port to UHCI, or to test
        // cold boot behind a hub on xHCI.
        qemu.args(["-device", "usb-hub,bus=hotusb.0,port=2"]);
        "2.1"
    } else {
        "1"
    };
    qemu.args([
        "-device",
        &format!("usb-storage,bus=hotusb.0,port={port},drive=hotdisk"),
    ]);
    let mut cold = qemu.spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        let log = fs::read_to_string(&serial).unwrap_or_default();
        if log.contains("USB BOOT ORDER: NVMe fallback reached")
            || log.contains("BootOrder: trying Boot0001")
        {
            cleanup_child(&mut cold);
            bail!("cold USB lost BootOrder priority: {log}");
        }
        let companion = matches!(topology, Topology::Companions { .. });
        if log.contains("BootOrder: trying Boot0000")
            && log.contains("USB HOTPLUG: waiting for keyboard")
            && (!companion
                || (log.contains("releasing to companion")
                    && log.contains("USB: attached storage on controller 0")))
        {
            cleanup_child(&mut cold);
            return Ok(());
        }
        if let Err(error) = check_alive(&mut cold, deadline, "USB Boot0000 before NVMe fallback") {
            cleanup_child(&mut cold);
            bail!("{error:#}: {log}");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub(crate) fn run(config: &QemuConfig, disk: &Path) -> Result<()> {
    let timeout = Duration::from_secs(config.timeout_secs.unwrap_or(60));
    let mut failed = Vec::new();
    for topology in CONTROLLERS.into_iter().map(Topology::Standalone).chain([
        Topology::Companions { cold: false },
        Topology::Companions { cold: true },
    ]) {
        let model = topology.name();
        println!("USB hotplug: {model}");
        let temp = tempfile::tempdir()?;
        let serial = temp.path().join("serial.log");
        let stderr = temp.path().join("qemu.log");
        let socket = temp.path().join("qmp.sock");
        let mut qemu = test_qemu(config);
        add_x86_boot_args(&mut qemu, &config.coreboot_rom, CaptureScenario::BootSmoke);
        qemu.args(["-serial", &format!("file:{}", serial.display())]);
        qemu.args([
            "-qmp",
            &format!("unix:{},server=on,wait=off", socket.display()),
        ]);
        qemu.args(["-blockdev", &json!({ "driver": "raw", "node-name": "hotdisk", "file": { "driver": "file", "filename": disk } }).to_string()]);
        topology.add_args(&mut qemu);
        qemu.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&stderr)?);
        let mut child = qemu.spawn().context("starting QEMU for USB hotplug")?;
        let result =
            Scenario::new(&mut child, &serial, &socket, timeout).and_then(|mut scenario| {
                match topology {
                    Topology::Standalone(model) => scenario.exercise(model),
                    Topology::Companions { cold } => scenario.exercise_companions(cold),
                }
            });
        cleanup_child(&mut child);
        match result {
            Ok(()) => println!("[PASS] USB hotplug {model}"),
            Err(error) => {
                let log = fs::read_to_string(&serial).unwrap_or_default();
                eprintln!("[FAIL] {model}: {error:#}");
                failed.push(model);
                for line in log
                    .lines()
                    .rev()
                    .take(35)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                {
                    eprintln!("{line}");
                }
                eprintln!("{}", fs::read_to_string(&stderr).unwrap_or_default());
            }
        }
    }
    for (topology, behind_hub, label) in [
        (Topology::Standalone("qemu-xhci"), false, "qemu-xhci"),
        (Topology::Standalone("qemu-xhci"), true, "qemu-xhci-hub"),
        (Topology::Standalone("usb-ehci"), false, "usb-ehci"),
        (
            Topology::Companions { cold: false },
            true,
            "ich9-uhci-full-speed",
        ),
    ] {
        match boot_order(config, disk, &topology, behind_hub, timeout) {
            Ok(()) => println!("[PASS] USB cold BootOrder {label}"),
            Err(error) => {
                eprintln!("[FAIL] USB cold BootOrder {label}: {error:#}");
                failed.push(label);
            }
        }
    }
    if !failed.is_empty() {
        bail!("USB hotplug failed for {}", failed.join(", "));
    }
    Ok(())
}

struct Scenario<'a> {
    qmp: Qmp,
    child: &'a mut Child,
    serial: &'a Path,
    cursor: usize,
    deadline: Instant,
}

impl<'a> Scenario<'a> {
    fn new(
        child: &'a mut Child,
        serial: &'a Path,
        socket: &Path,
        timeout: Duration,
    ) -> Result<Self> {
        let deadline = Instant::now() + timeout;
        let stream = loop {
            if let Ok(stream) = UnixStream::connect(socket) {
                break stream;
            }
            check_alive(child, deadline, "QMP socket")?;
            thread::sleep(Duration::from_millis(10));
        };
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut qmp = Qmp {
            stream: BufReader::new(stream),
            deleted: Vec::new(),
        };
        if qmp.read()?.get("QMP").is_none() {
            bail!("missing QMP greeting");
        }
        qmp.command("qmp_capabilities", json!({}))?;
        Ok(Self {
            qmp,
            child,
            serial,
            cursor: 0,
            deadline,
        })
    }

    fn marker(&mut self, marker: &str) -> Result<()> {
        self.marker_groups(&[&[marker]])
    }

    // Each group describes causal order, but separate groups may interleave.
    fn marker_groups(&mut self, groups: &[&[&str]]) -> Result<()> {
        loop {
            if let Ok(log) = fs::read(self.serial)
                && let Some(end) = marker_groups_end(&log, self.cursor, groups)
            {
                self.cursor = end;
                return Ok(());
            }
            check_alive(self.child, self.deadline, &format!("{groups:?}"))?;
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn exercise(&mut self, model: &str) -> Result<()> {
        self.marker("Found 0 boot entries")?;
        self.add("usb-kbd", "keyboard", "1", None)?;
        self.marker("USB: attached keyboard")?;
        self.add("usb-mouse", "mouse", "2", None)?;
        self.marker("USB: attached mouse")?;
        // UHCI only exposes two root ports. Free one while leaving the USB
        // keyboard present for the menu selection.
        self.qmp.delete("mouse")?;
        self.add("usb-storage", "disk", "2", Some("hotdisk"))?;
        self.marker("Found 1 boot entries")?;
        self.qmp.delete("disk")?;
        self.marker("Found 0 boot entries")?;
        // QEMU's usb-hub is full-speed; standalone usb-ehci cannot
        // attach it without a companion. Exercise this topology elsewhere.
        if model != "usb-ehci" {
            self.add("usb-hub", "hub", "2", None)?;
            if model == "qemu-xhci" {
                // The USB2 hub descriptor is shorter than our EP0 request.
                self.marker("xHCI: EP0 short IN:")?;
            }
            self.marker("USB hub ")?;
            self.add("usb-kbd", "hub-keyboard", "2.2", None)?;
            self.marker("USB: attached keyboard")?;
            self.add("usb-storage", "hub-disk", "2.1", Some("hotdisk"))?;
            self.marker("Found 1 boot entries")?;
            // QEMU recursively removes the child qdev with the hub. Leave
            // the storage attached here to exercise firmware tree teardown.
            self.qmp.delete("hub")?;
            self.marker("Found 0 boot entries")?;
        }
        self.add("usb-storage", "boot-disk", "2", Some("hotdisk"))?;
        self.marker("Found 1 boot entries")?;
        // Storage-induced refreshes must still allow unattended autoboot.
        self.marker("Showing boot menu")?;
        self.marker("USB HOTPLUG: waiting for keyboard")?;
        self.qmp.delete("keyboard")?;
        self.add("usb-kbd", "app-keyboard", "1", None)?;
        self.marker("USB: attached keyboard")?;
        self.qmp.key("h")?;
        self.marker("USB HOTPLUG: received h")?;
        self.marker("USB HOTPLUG: polling ReadKeyStroke")?;
        self.qmp.delete("app-keyboard")?;
        self.add("usb-kbd", "poll-keyboard", "1", None)?;
        self.marker("USB: attached keyboard")?;
        self.qmp.key("p")?;
        self.marker("USB HOTPLUG: received p by direct poll")?;
        self.marker("EFI app executed successfully!")
    }

    fn exercise_companions(&mut self, cold: bool) -> Result<()> {
        // USB controller indices follow the fixture's PCI function order:
        // the UHCI companions are 1d.0–2, and EHCI is 1d.7.
        let storage = "USB: attached storage on controller 3";
        let app = "USB HOTPLUG: waiting for keyboard";
        let handoff_then_keyboard = [
            "EHCI: Port 1 has full-speed device, releasing to companion",
            "USB: attached keyboard on controller 0",
        ];
        if cold {
            self.marker_groups(&[&[storage, app], &handoff_then_keyboard])
        } else {
            self.marker("Found 0 boot entries")?;
            self.add("usb-storage", "ehci-disk", "1", Some("hotdisk"))?;
            self.marker(storage)?;
            self.add("usb-hub", "companion-hub", "2", None)?;
            self.add("usb-kbd", "companion-keyboard", "2.1", None)?;
            self.marker_groups(&[&[app], &handoff_then_keyboard])
        }
    }

    fn add(&mut self, driver: &str, id: &str, port: &str, drive: Option<&str>) -> Result<()> {
        let mut args = json!({ "driver": driver, "id": id, "bus": "hotusb.0", "port": port });
        if let Some(drive) = drive {
            args["drive"] = json!(drive);
        }
        self.qmp.command("device_add", args)
    }
}

fn marker_groups_end(log: &[u8], start: usize, groups: &[&[&str]]) -> Option<usize> {
    let mut end = start;
    for group in groups {
        let mut cursor = start;
        for marker in *group {
            let offset = log
                .get(cursor..)?
                .windows(marker.len())
                .position(|bytes| bytes == marker.as_bytes())?;
            cursor += offset + marker.len();
        }
        end = end.max(cursor);
    }
    Some(end)
}

#[cfg(test)]
#[test]
fn companion_markers_accept_interleaving_but_not_reversed_dependencies() {
    let groups: &[&[&str]] = &[&["disk", "app"], &["handoff", "keyboard"]];
    for log in [
        "disk handoff keyboard app",
        "handoff disk app keyboard",
        "handoff keyboard disk app",
    ] {
        assert_eq!(
            marker_groups_end(log.as_bytes(), 0, groups),
            Some(log.len())
        );
    }
    assert_eq!(
        marker_groups_end(b"disk app keyboard handoff", 0, groups),
        None
    );
    assert_eq!(marker_groups_end(b"handoff disk app", 0, groups), None);
    assert_eq!(
        marker_groups_end(b"handoff keyboard disk app", 1, groups),
        None
    );
}

fn check_alive(child: &mut Child, deadline: Instant, marker: &str) -> Result<()> {
    if let Some(status) = child.try_wait()? {
        bail!("QEMU exited with {status} while waiting for {marker:?}");
    }
    if Instant::now() >= deadline {
        bail!("timed out waiting for {marker:?}");
    }
    Ok(())
}

struct Qmp {
    stream: BufReader<UnixStream>,
    deleted: Vec<String>,
}

impl Qmp {
    fn read(&mut self) -> Result<Value> {
        let mut line = String::new();
        if self.stream.read_line(&mut line)? == 0 {
            bail!("QMP socket closed");
        }
        let message: Value = serde_json::from_str(&line)?;
        if message["event"] == "DEVICE_DELETED"
            && let Some(id) = message["data"]["device"].as_str()
        {
            self.deleted.push(id.to_owned());
        }
        Ok(message)
    }

    fn command(&mut self, command: &str, arguments: Value) -> Result<()> {
        writeln!(
            self.stream.get_mut(),
            "{}",
            json!({ "execute": command, "arguments": arguments })
        )?;
        loop {
            let reply = self.read().with_context(|| format!("QMP {command}"))?;
            if let Some(error) = reply.get("error") {
                bail!("QMP {command}: {error}");
            }
            if reply.get("return").is_some() {
                return Ok(());
            }
        }
    }

    fn delete(&mut self, id: &str) -> Result<()> {
        self.command("device_del", json!({ "id": id }))?;
        loop {
            if let Some(index) = self.deleted.iter().position(|deleted| deleted == id) {
                self.deleted.swap_remove(index);
                return Ok(());
            }
            self.read()
                .with_context(|| format!("waiting for QMP DEVICE_DELETED for {id}"))?;
        }
    }

    fn key(&mut self, key: &str) -> Result<()> {
        self.command(
            "send-key",
            json!({ "keys": [{ "type": "qcode", "data": key }], "hold-time": 250 }),
        )
    }
}
