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
        let mut qemu = Command::new("qemu-system-x86_64");
        // Ensure that the app can only get keyboard input from the hotplugged
        // USB device rather than the usual QEMU PS/2 keyboard.
        qemu.args(["-machine", "q35,usb=off,i8042=off", "-m", "2G"]);
        if !config.disable_kvm && super::is_kvm_available() {
            qemu.args(["-enable-kvm", "-cpu", "host"]);
        } else {
            qemu.args(["-cpu", "max"]);
        }
        add_x86_boot_args(&mut qemu, &config.coreboot_rom, CaptureScenario::BootSmoke);
        qemu.args(["-display", "none", "-monitor", "none"]);
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
        loop {
            if let Ok(log) = fs::read(self.serial)
                && let Some(offset) = log.get(self.cursor..).and_then(|log| {
                    log.windows(marker.len())
                        .position(|window| window == marker.as_bytes())
                })
            {
                self.cursor += offset + marker.len();
                return Ok(());
            }
            check_alive(self.child, self.deadline, marker)?;
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
        if !cold {
            self.marker("Found 0 boot entries")?;
            self.add("usb-storage", "ehci-disk", "1", Some("hotdisk"))?;
        }
        // USB controller indices follow the fixture's PCI function order:
        // the UHCI companions are 1d.0–2, and EHCI is 1d.7.
        self.marker("USB: attached storage on controller 3")?;
        if !cold {
            self.add("usb-hub", "companion-hub", "2", None)?;
            self.add("usb-kbd", "companion-keyboard", "2.1", None)?;
        }
        self.marker("EHCI: Port 1 has full-speed device, releasing to companion")?;
        self.marker("USB: attached keyboard on controller 0")?;
        self.marker("USB HOTPLUG: waiting for keyboard")
    }

    fn add(&mut self, driver: &str, id: &str, port: &str, drive: Option<&str>) -> Result<()> {
        let mut args = json!({ "driver": driver, "id": id, "bus": "hotusb.0", "port": port });
        if let Some(drive) = drive {
            args["drive"] = json!(drive);
        }
        self.qmp.command("device_add", args)
    }
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
