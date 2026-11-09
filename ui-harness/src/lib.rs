//! Deterministic test host for the same UI that firmware links.
//!
//! All simulation is here, not in the shared UI. No device, flash, signing
//! key, filesystem or network access is performed.

use crabefi_ui::{
    Backend, BootCategory, BootEntry, BootEntryKind, BootMenu, DiskEntry, FirmwarePage,
    FramebufferConfig, KeyCounts, KeyPress, Outcome, PayloadFormat, Screen, SecurityAction,
    SecurityState, Surface, UiState,
};
mod cfr_fixture;

use crabefi_ui::cfr::{CfrValue, LevelFilter};
use crabefi_ui::screens::layout::{Metrics, TextSize};
use serde::Serialize;
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll, Waker},
};
type Task = Pin<Box<dyn Future<Output = Outcome>>>;

struct Simulation {
    now_ms: u64,
    pointer: (i32, i32),
    input: VecDeque<KeyPress>,
    security: SecurityState,
    fail_writes: bool,
    state: UiState,
    actions: VecDeque<String>,
    dialog: Option<String>,
    command_line: Option<String>,
    cfr_enabled: bool,
    settings_saved: BTreeMap<String, CfrValue>,
    configured_log_level: LevelFilter,
    firmware: Option<serde_json::Value>,
    text_size: TextSize,
}

impl Simulation {
    fn log(&mut self, action: impl Into<String>) {
        if self.actions.len() == 32 {
            self.actions.pop_front();
        }
        self.actions.push_back(action.into());
    }
}

#[derive(Clone)]
struct SimBackend(Rc<RefCell<Simulation>>, bool);

impl Backend for SimBackend {
    fn poll_pointer(&mut self) -> (i32, i32) {
        self.0.borrow().pointer
    }
    fn read_key(&mut self) -> Option<KeyPress> {
        self.0.borrow_mut().input.pop_front()
    }
    fn now_ms(&self) -> u64 {
        self.0.borrow().now_ms
    }
    fn poll_frame(&mut self, _: &mut Context<'_>) -> Poll<()> {
        self.1 = !self.1;
        if self.1 {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
    fn firmware_page(&mut self) -> Option<FirmwarePage> {
        self.0
            .borrow()
            .cfr_enabled
            .then(|| FirmwarePage::Cfr(Rc::new(cfr_fixture::Fixture::new(self.0.clone()))))
    }
    fn observe_firmware(&mut self, state: &crabefi_ui::settings::FirmwareObservation<'_>) {
        let snapshot = cfr_fixture::observe(state);
        self.0.borrow_mut().firmware = Some(snapshot);
    }
    fn security_state(&self) -> SecurityState {
        self.0.borrow().security
    }

    fn security_action(&mut self, action: SecurityAction) -> (&'static str, bool) {
        let mut sim = self.0.borrow_mut();
        if sim.fail_writes {
            sim.log(format!("{action:?}: simulated persistence failure"));
            return ("Simulated variable write failure", false);
        }
        let result = match action {
            SecurityAction::Toggle => {
                sim.security.requested = !sim.security.requested;
                sim.security.enforcing = sim.security.requested && !sim.security.setup_mode;
                if sim.security.enforcing {
                    ("Secure Boot enabled", true)
                } else if sim.security.requested {
                    ("Secure Boot enabled; awaiting PK enrollment", true)
                } else {
                    ("Secure Boot disabled", true)
                }
            }
            SecurityAction::EnrollDefaults if !sim.security.setup_mode => {
                ("Keys already enrolled", false)
            }
            SecurityAction::EnrollDefaults => {
                sim.security.keys = KeyCounts {
                    pk: 1,
                    kek: 1,
                    db: 2,
                    dbx: 0,
                };
                sim.security.has_stored_keys = true;
                sim.security.setup_mode = false;
                sim.security.enforcing = sim.security.requested;
                ("Default keys enrolled", true)
            }
            SecurityAction::ClearKeys => {
                sim.security.keys = KeyCounts::default();
                sim.security.has_stored_keys = false;
                sim.security.setup_mode = true;
                sim.security.enforcing = false;
                ("All keys cleared", true)
            }
            // ESP imports use the host's prepare/commit boundary, not these actions.
            SecurityAction::EnrollCustomPk | SecurityAction::ImportDbx => {
                ("Not implemented", false)
            }
        };
        sim.log(format!("{action:?}: {}", result.0));
        result
    }

    fn text_size(&self) -> TextSize {
        self.0.borrow().text_size
    }
    fn set_text_size(&mut self, size: TextSize) {
        self.0.borrow_mut().text_size = size;
    }
    fn observe(&mut self, state: UiState) {
        self.0.borrow_mut().state = state;
    }
    fn observe_dialog(&mut self, title: Option<&str>) {
        self.0.borrow_mut().dialog = title.map(String::from);
    }
    fn enrolled_keys(&self) -> Vec<crabefi_ui::screens::dialog::ReviewSection> {
        use crabefi_ui::screens::dialog::{LineKind, ReviewSection};
        self.0
            .borrow()
            .security
            .keys
            .as_array()
            .into_iter()
            .zip(["PK", "KEK", "db", "dbx"])
            .map(|(count, label)| {
                ReviewSection::labelled(label).line(
                    LineKind::Note,
                    &format!("{count} simulated entries; no real certificates or signing keys"),
                )
            })
            .collect()
    }
}

fn boot_menu(scenario: &str) -> BootMenu<DiskEntry> {
    let mut menu = BootMenu::new();
    if scenario == "empty" {
        return menu;
    }
    let count = if scenario == "many" { 16 } else { 4 };
    let fixtures = [
        (
            "Fedora Linux",
            "EFI\\fedora\\shimx64.efi",
            BootCategory::Uefi,
        ),
        ("Linux (BLS)", "/vmlinuz-linux", BootCategory::Bls),
        (
            "USB recovery (GRUB)",
            "/boot/grub/grub.cfg",
            BootCategory::Grub,
        ),
        (
            "Coreboot payload",
            "/payloads/memtest.elf",
            BootCategory::Payload,
        ),
    ];
    for index in 0..count {
        let (name, path, category) = fixtures[index % fixtures.len()];
        let name = if index >= 4 {
            format!("{name} {}", index + 1)
        } else {
            name.into()
        };
        let kind = match category {
            BootCategory::Uefi => BootEntryKind::Uefi,
            BootCategory::Bls => BootEntryKind::BlsLinux {
                linux_path: path.try_into().unwrap(),
                initrd_paths: Default::default(),
                cmdline: "root=LABEL=demo quiet".try_into().unwrap(),
            },
            BootCategory::Grub => BootEntryKind::GrubLinux {
                linux_path: "/vmlinuz-recovery".try_into().unwrap(),
                initrd_paths: Default::default(),
                cmdline: "root=LABEL=recovery".try_into().unwrap(),
            },
            BootCategory::Payload => BootEntryKind::Payload {
                path: path.try_into().unwrap(),
                format: PayloadFormat::Elf,
            },
        };
        menu.add_entry(DiskEntry {
            entry: BootEntry::new(&name, path, 1, kind, category),
            disk: index % 3,
            disk_name: if index % 3 == 2 {
                "USB 1".into()
            } else {
                format!("NVMe {}", index % 3)
            },
        });
    }
    if scenario == "countdown" {
        menu.timeout_seconds = 5;
    }
    menu
}

/// A host-owned framebuffer, UI future and simulated firmware services.
/// Dropping/replacing the future always happens before its framebuffer is freed.
pub struct Playground {
    task: Option<Task>,
    pixels: Box<[u32]>,
    sim: Rc<RefCell<Simulation>>,
    width: u32,
    height: u32,
    scenario: String,
    outcome: Option<Outcome>,
    frames: u64,
}

#[derive(Serialize)]
struct NavigationTarget {
    label: &'static str,
    rect: (i32, i32, u32, u32),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot<'a> {
    scenario: &'a str,
    width: u32,
    height: u32,
    frames: u64,
    now_ms: u64,
    screen: &'static str,
    selected: Option<usize>,
    scroll_offset: usize,
    countdown: u32,
    outcome: Option<String>,
    requested: bool,
    setup_mode: bool,
    enforcing: bool,
    keys: [usize; 4],
    fail_writes: bool,
    actions: &'a VecDeque<String>,
    dialog: &'a Option<String>,
    command_line: &'a Option<String>,
    navigation: Vec<NavigationTarget>,
    text_size: &'static str,
    firmware: &'a Option<serde_json::Value>,
    saved_settings: serde_json::Value,
    configured_log_level: &'static str,
}

impl Playground {
    pub fn new(width: u32, height: u32, scenario: &str) -> Result<Playground, String> {
        if !(640..=1920).contains(&width) || !(400..=1080).contains(&height) {
            return Err("Resolution must be between 640x400 and 1920x1080".into());
        }
        if ![
            "normal",
            "cfr",
            "no-settings",
            "many",
            "empty",
            "countdown",
            "secure",
            "write-error",
        ]
        .contains(&scenario)
        {
            return Err(format!("Unknown scenario: {scenario}"));
        }
        let secure = scenario == "secure";
        let sim = Rc::new(RefCell::new(Simulation {
            now_ms: 0,
            pointer: (-1, -1),
            input: if scenario == "cfr" {
                VecDeque::from([KeyPress::Char('f')])
            } else {
                VecDeque::new()
            },
            security: SecurityState {
                requested: secure,
                setup_mode: !secure,
                enforcing: secure,
                keys: if secure {
                    KeyCounts {
                        pk: 1,
                        kek: 1,
                        db: 2,
                        dbx: 1,
                    }
                } else {
                    KeyCounts::default()
                },
                has_stored_keys: secure,
                keys_incomplete: false,
            },
            fail_writes: scenario == "write-error",
            state: UiState {
                screen: Screen::Boot,
                selected: None,
                scroll_offset: 0,
                countdown: 0,
            },
            actions: VecDeque::new(),
            dialog: None,
            command_line: None,
            cfr_enabled: scenario != "no-settings",
            settings_saved: BTreeMap::new(),
            configured_log_level: crabefi_ui::cfr::DEFAULT_LEVEL,
            firmware: None,
            text_size: TextSize::Auto,
        }));
        let mut host = Self {
            task: None,
            pixels: vec![0; (width * height) as usize].into_boxed_slice(),
            sim,
            width,
            height,
            scenario: scenario.into(),
            outcome: None,
            frames: 0,
        };
        host.start_ui();
        host.advance(0);
        Ok(host)
    }

    /// Inject or repair persistence errors without discarding the active draft.
    pub fn set_write_failures(&mut self, enabled: bool) {
        self.sim.borrow_mut().fail_writes = enabled;
    }

    /// Move a pointer in framebuffer coordinates. (-1, -1) hides it.
    pub fn pointer(&mut self, x: i32, y: i32) {
        self.sim.borrow_mut().pointer = (
            x.clamp(-1, self.width as i32 - 1),
            y.clamp(-1, self.height as i32 - 1),
        );
    }

    pub fn key(&mut self, key: &str) -> Result<(), String> {
        let event = match key {
            "ArrowUp" => KeyPress::Up,
            "ArrowDown" => KeyPress::Down,
            "ArrowLeft" => KeyPress::Left,
            "ArrowRight" => KeyPress::Right,
            "Enter" => KeyPress::Enter,
            "Escape" => KeyPress::Escape,
            "Tab" => KeyPress::Tab,
            "BackTab" | "Shift+Tab" => KeyPress::BackTab,
            "Home" => KeyPress::Home,
            "End" => KeyPress::End,
            "PageUp" => KeyPress::PageUp,
            "PageDown" => KeyPress::PageDown,
            "Backspace" => KeyPress::Char('\x08'),
            "Delete" => KeyPress::Delete,
            "F8" => KeyPress::F8,
            "F10" => KeyPress::F10,
            _ => {
                let mut chars = key.chars();
                let c = chars.next().ok_or("Empty key")?;
                if chars.next().is_some() {
                    return Err(format!("Unsupported key: {key}"));
                }
                KeyPress::Char(c)
            }
        };
        self.enqueue(event)
    }

    pub fn click(&mut self, x: u32, y: u32) -> Result<(), String> {
        if x >= self.width || y >= self.height {
            return Err("Click outside framebuffer".into());
        }
        self.pointer(x as i32, y as i32);
        self.enqueue(KeyPress::MouseClick { x, y })
    }

    pub fn scroll(&mut self, delta: i32) -> Result<(), String> {
        if delta != 0 {
            self.enqueue(KeyPress::MouseScroll(delta))?;
        }
        Ok(())
    }

    /// Advance virtual time and poll exactly one UI frame. Never sleeps.
    pub fn advance(&mut self, delta_ms: u32) {
        {
            let mut sim = self.sim.borrow_mut();
            sim.now_ms = sim.now_ms.saturating_add(delta_ms as u64);
        }
        self.frames += 1;
        let outcome = self.task.as_mut().and_then(|task| {
            match task.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(outcome) => Some(outcome),
                Poll::Pending => None,
            }
        });
        if let Some(outcome) = outcome {
            self.task = None;
            self.outcome = Some(outcome);
            self.sim.borrow_mut().log(format!("{outcome:?}"));
            if outcome == Outcome::Reset {
                self.sim.borrow_mut().input.clear();
                self.start_ui();
                // A new future's first poll paints without consuming time.
                self.advance(0);
            }
        }
    }

    /// Copy RGBA8 pixels, for screenshots and pixel tests.
    pub fn rgba(&self) -> Vec<u8> {
        self.pixels
            .iter()
            .flat_map(|pixel| [(pixel >> 16) as u8, (pixel >> 8) as u8, *pixel as u8, 255])
            .collect()
    }

    pub fn state_json(&self) -> String {
        // Geometry only: tab rectangles and metrics, never painted.
        let geometry = Surface::new(
            self.framebuffer_config(),
            SimBackend(self.sim.clone(), false),
        );
        let sim = self.sim.borrow();
        serde_json::to_string(&Snapshot {
            scenario: &self.scenario,
            width: self.width,
            height: self.height,
            frames: self.frames,
            now_ms: sim.now_ms,
            screen: match sim.state.screen {
                Screen::Boot => "boot",
                Screen::Security => "security",
                Screen::Firmware => "firmware",
                Screen::NoMedia => "no-media",
            },
            selected: sim.state.selected,
            scroll_offset: sim.state.scroll_offset,
            countdown: sim.state.countdown,
            outcome: self.outcome.map(|o| match o {
                Outcome::Boot(index) => format!("boot:{index}"),
                Outcome::Reset => "reset".into(),
                Outcome::Exit => "exit".into(),
            }),
            requested: sim.security.requested,
            setup_mode: sim.security.setup_mode,
            enforcing: sim.security.enforcing,
            keys: sim.security.keys.as_array(),
            fail_writes: sim.fail_writes,
            actions: &sim.actions,
            firmware: &sim.firmware,
            saved_settings: sim
                .settings_saved
                .iter()
                .map(|(name, value)| (name.clone(), cfr_fixture::value_json(value)))
                .collect::<serde_json::Map<_, _>>()
                .into(),
            configured_log_level: crabefi_ui::cfr::level_name(sim.configured_log_level),
            dialog: &sim.dialog,
            command_line: &sim.command_line,
            navigation: crabefi_ui::screens::kit::tab_rects(
                &geometry,
                &["Boot", "Security", "Firmware"],
            )
            .into_iter()
            .zip(["Boot", "Security", "Firmware"])
            .map(|(rect, label)| NavigationTarget { label, rect })
            .collect(),
            text_size: if Metrics::for_fb(&geometry).large {
                "large"
            } else {
                "compact"
            },
        })
        .unwrap()
    }

    fn enqueue(&mut self, event: KeyPress) -> Result<(), String> {
        let mut sim = self.sim.borrow_mut();
        if sim.input.len() >= 128 {
            return Err("Input queue full; advance a frame".into());
        }
        if self.task.is_none() {
            return Err("UI session ended; reset to continue".into());
        }
        sim.input.push_back(event);
        Ok(())
    }

    fn framebuffer_config(&self) -> FramebufferConfig {
        FramebufferConfig {
            physical_address: 0, // geometry only; the running surface gets a writable pointer
            width: self.width,
            height: self.height,
            stride: self.width,
            bits_per_pixel: 32,
            red_mask_pos: 16,
            red_mask_size: 8,
            green_mask_pos: 8,
            green_mask_size: 8,
            blue_mask_pos: 0,
            blue_mask_size: 8,
        }
    }

    fn start_ui(&mut self) {
        // Like firmware, a restart forgets the F8 text size.
        self.task = None;
        self.sim.borrow_mut().text_size = TextSize::Auto;
        let mut fb = self.framebuffer_config();
        fb.physical_address = self.pixels.as_mut_ptr() as u64;
        let backend = SimBackend(self.sim.clone(), false);
        let simulation = self.sim.clone();
        let mut menu = boot_menu(&self.scenario);
        self.task = Some(Box::pin(async move {
            let surface = Surface::new(fb, backend);
            // A restart keeps the physical pointer; that is not new motion.
            surface.set_pointer(simulation.borrow().pointer);
            let outcome = crabefi_ui::screens::show_graphical_menu(&surface, &mut menu).await;
            if let Outcome::Boot(index) = outcome {
                // Like firmware, boot the clone carrying any one-shot edit.
                simulation.borrow_mut().command_line = menu
                    .entry_for_boot(index)
                    .as_ref()
                    .and_then(|entry| entry.get_cmdline())
                    .map(|cmdline| String::from(cmdline.as_str()));
            }
            outcome
        }));
    }
}
