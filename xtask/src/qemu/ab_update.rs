//! A/B firmware updates on payload MM: signed capsule-on-disk into the
//! inactive slot, unconfirmed trial boots and the rollback, an OS
//! confirmation, and a capsule that reaches outside the slots. Every boot is a
//! separate QEMU process on one persistent flash and ESP; ab-update-test
//! reports the trial and ESRT state and acts on marker files placed here.
use super::*;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Synthetic slot regions of the `ab-test-slots` payload, in the blank lower
/// half of the payload MM fixture ROM.
const SLOT_A: (&str, usize) = ("AB_TEST_A", 0x10_0000);
const SLOT_B: (&str, usize) = ("AB_TEST_B", 0x20_0000);
const SLOT_SIZE: usize = 0x10_0000;
/// Byte 0 == 0x01 selects slot B.
const SELECTOR: usize = 0x30_0000;
const SELECTOR_SIZE: usize = 0x1000;
/// An FMAP region outside both slots that RMAP validation approves. The
/// capsule carries its current bytes, so a wrong write would not change it.
const OUTSIDE_REGION: &str = "FMAP";

const FW_CLASS: [u8; 16] = guid(
    0x0011_2233,
    0x4455,
    0x6677,
    [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
);
const FMP_CAPSULE_ID: [u8; 16] = guid(
    0x6dcb_d5ed,
    0xe82d,
    0x4c44,
    [0xbd, 0xa1, 0x71, 0x94, 0x19, 0x9a, 0xd9, 0x2a],
);
const CERT_TYPE_PKCS7: [u8; 16] = guid(
    0x4aaf_d29d,
    0x68df,
    0x49ee,
    [0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7],
);
const CAPSULE_FLAGS_PERSIST_ACROSS_RESET: u32 = 0x0001_0000;
const CURRENT_VERSION: u32 = 0x0001_0000;
const V1: u32 = 0x0001_0001;
const V2: u32 = 0x0001_0002;
const V3: u32 = 0x0001_0003;
/// Unconfirmed boots of a new slot before the firmware rolls back.
const MAX_TRIALS: usize = 3;

const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5],
        d4[6], d4[7],
    ]
}

/// Test-only capsule signer; its certificate is the payload's trust root.
fn signer_dir() -> PathBuf {
    crate::project_root().join("target/ab-update-test/signer")
}

fn openssl(args: &[&str], what: &str) -> Result<()> {
    let output = Command::new("openssl")
        .args(args)
        .output()
        .context("failed to run openssl (install the openssl CLI)")?;
    if !output.status.success() {
        bail!(
            "openssl {what} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Create the test signing key once and make its certificate the capsule
/// trust root of the payload built next (CRABEFI_CAPSULE_TRUST_CERTS).
/// The key is kept so repeated runs do not rebuild the payload.
pub(crate) fn prepare_trust_root() -> Result<()> {
    if std::env::var_os("CRABEFI_PAYLOAD_MM").is_none() {
        bail!(
            "ab-update-test needs CRABEFI_PAYLOAD_MM=1 (A/B slots are written through payload MM)"
        );
    }
    let dir = signer_dir();
    let (key, cert, der) = (
        dir.join("key.pem"),
        dir.join("cert.pem"),
        dir.join("cert.der"),
    );
    if !(key.exists() && cert.exists() && der.exists()) {
        fs::create_dir_all(&dir)?;
        openssl(
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-days",
                "3650",
                "-subj",
                "/CN=CrabEFI A-B update test capsule signer",
                "-keyout",
                &key.to_string_lossy(),
                "-out",
                &cert.to_string_lossy(),
            ],
            "req (capsule signer)",
        )?;
        openssl(
            &[
                "x509",
                "-in",
                &cert.to_string_lossy(),
                "-outform",
                "DER",
                "-out",
                &der.to_string_lossy(),
            ],
            "x509 -outform DER",
        )?;
    }
    let mut roots = der.to_string_lossy().into_owned();
    if let Ok(existing) = std::env::var("CRABEFI_CAPSULE_TRUST_CERTS")
        && !existing.is_empty()
        && !existing.split(':').any(|path| Path::new(path) == der)
    {
        roots = format!("{existing}:{roots}");
    }
    // SAFETY: xtask is single-threaded here, before the payload build.
    unsafe { std::env::set_var("CRABEFI_CAPSULE_TRUST_CERTS", roots) };
    Ok(())
}

/// Recognisable contents of one region in the capsule of `version`: 16-byte
/// records of an ASCII tag and the offset within the region.
fn region_data(version: u32, slot: &str, size: usize) -> Vec<u8> {
    let tag = format!("v{:x}{}", version & 0xff, &slot[slot.len() - 1..]);
    let mut tag = format!("ABUP{tag:<4}").into_bytes();
    tag.truncate(8);
    (0..size / 16)
        .flat_map(|record| {
            tag.iter()
                .copied()
                .chain((record as u64 * 16).to_le_bytes())
        })
        .collect()
}

/// A signed FMP capsule for `version` whose image covers `regions` in order,
/// followed by the RMAP manifest naming them.
fn build_capsule(version: u32, regions: &[(&str, Vec<u8>)], work: &Path) -> Result<Vec<u8>> {
    let manifest: String = regions
        .iter()
        .map(|(name, _)| format!("{name}\n"))
        .collect();
    // EDK2 FMP payload header "MSS1", then the image the firmware writes.
    let mut signed = Vec::new();
    signed.extend_from_slice(b"MSS1");
    signed.extend_from_slice(&16u32.to_le_bytes());
    signed.extend_from_slice(&version.to_le_bytes());
    signed.extend_from_slice(&CURRENT_VERSION.to_le_bytes());
    for (_, data) in regions {
        signed.extend_from_slice(data);
    }
    signed.extend_from_slice(manifest.as_bytes());
    signed.extend_from_slice(&(manifest.len() as u32).to_le_bytes());

    // UEFI 23.1: the signature covers the payload followed by MonotonicCount.
    let monotonic_count = u64::from(version);
    let to_sign = work.join(format!("{version:08x}.tbs"));
    let signature = work.join(format!("{version:08x}.p7"));
    let mut message = signed.clone();
    message.extend_from_slice(&monotonic_count.to_le_bytes());
    fs::write(&to_sign, message)?;
    let dir = signer_dir();
    openssl(
        &[
            "cms",
            "-sign",
            "-binary",
            "-noattr",
            "-md",
            "sha256",
            "-outform",
            "DER",
            "-signer",
            &dir.join("cert.pem").to_string_lossy(),
            "-inkey",
            &dir.join("key.pem").to_string_lossy(),
            "-in",
            &to_sign.to_string_lossy(),
            "-out",
            &signature.to_string_lossy(),
        ],
        "cms -sign (capsule)",
    )?;
    let pkcs7 = fs::read(&signature)?;

    // EFI_FIRMWARE_IMAGE_AUTHENTICATION: MonotonicCount, WIN_CERTIFICATE_UEFI_GUID.
    let mut update_image = Vec::new();
    update_image.extend_from_slice(&monotonic_count.to_le_bytes());
    update_image.extend_from_slice(&(24 + pkcs7.len() as u32).to_le_bytes());
    update_image.extend_from_slice(&0x0200u16.to_le_bytes()); // WIN_CERT_REVISION_2_0
    update_image.extend_from_slice(&0x0ef1u16.to_le_bytes()); // WIN_CERT_TYPE_EFI_GUID
    update_image.extend_from_slice(&CERT_TYPE_PKCS7);
    update_image.extend_from_slice(&pkcs7);
    update_image.extend_from_slice(&signed);

    // EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER version 2.
    let mut item = Vec::new();
    item.extend_from_slice(&2u32.to_le_bytes());
    item.extend_from_slice(&FW_CLASS);
    item.extend_from_slice(&[1, 0, 0, 0]); // UpdateImageIndex, reserved
    item.extend_from_slice(&(update_image.len() as u32).to_le_bytes());
    item.extend_from_slice(&0u32.to_le_bytes()); // UpdateVendorCodeSize
    item.extend_from_slice(&0u64.to_le_bytes()); // UpdateHardwareInstance
    item.extend_from_slice(&update_image);

    // EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER with one payload item.
    let mut fmp = Vec::new();
    fmp.extend_from_slice(&1u32.to_le_bytes());
    fmp.extend_from_slice(&0u16.to_le_bytes());
    fmp.extend_from_slice(&1u16.to_le_bytes());
    fmp.extend_from_slice(&16u64.to_le_bytes());
    fmp.extend_from_slice(&item);

    const HEADER_SIZE: u32 = 28;
    let mut capsule = Vec::new();
    capsule.extend_from_slice(&FMP_CAPSULE_ID);
    capsule.extend_from_slice(&HEADER_SIZE.to_le_bytes());
    capsule.extend_from_slice(&CAPSULE_FLAGS_PERSIST_ACROSS_RESET.to_le_bytes());
    capsule.extend_from_slice(&(HEADER_SIZE + fmp.len() as u32).to_le_bytes());
    capsule.extend_from_slice(&fmp);
    fs::write(work.join(format!("{version:08x}.cap")), &capsule)?;
    Ok(capsule)
}

/// Offset and size of FMAP area `name` in a flash image.
fn fmap_area(bytes: &[u8], name: &str) -> Result<(usize, usize)> {
    let fmap = fmap_smmstore(bytes)?;
    (0..usize::from(fmap.count))
        .find_map(|index| {
            let entry = fmap.areas + index * FMAP_AREA_SIZE;
            let area = bytes.get(entry..entry + FMAP_AREA_SIZE)?;
            let field = &area[8..40];
            let len = field.iter().position(|byte| *byte == 0).unwrap_or(32);
            (&field[..len] == name.as_bytes()).then(|| {
                (
                    u32::from_le_bytes(area[..4].try_into().unwrap()) as usize,
                    u32::from_le_bytes(area[4..8].try_into().unwrap()) as usize,
                )
            })
        })
        .with_context(|| format!("test flash has no FMAP area {name}"))
}

/// The ESP of the test disk, changed between boots.
struct Esp {
    image: String,
}

impl Esp {
    fn put(&self, data: &[u8], dest: &str) -> Result<()> {
        let file = tempfile::NamedTempFile::new()?;
        fs::write(file.path(), data)?;
        let status = Command::new("mcopy")
            .args(["-o", "-i", &self.image])
            .arg(file.path())
            .arg(format!("::{dest}"))
            .status()
            .context("failed to run mcopy")?;
        if !status.success() {
            bail!("mcopy {dest} failed");
        }
        Ok(())
    }

    fn remove(&self, dest: &str) -> Result<()> {
        let status = Command::new("mdel")
            .args(["-i", &self.image])
            .arg(format!("::{dest}"))
            .status()
            .context("failed to run mdel")?;
        if !status.success() {
            bail!("mdel {dest} failed");
        }
        Ok(())
    }
}

const DELIVER: &str = "/AB/DELIVER";
const CONFIRM: &str = "/AB/CONFIRM";

fn capsule_path(version: u32) -> String {
    format!("/EFI/UpdateCapsule/AB{:X}.CAP", version & 0xff)
}

/// Boot once until the guest resets or exits (-no-reboot); return its serial log.
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
    // Like AMD ROM Armor 3, only SMM may write the flash.
    cmd.args(["-global", "driver=cfi.pflash01,property=secure,value=on"]);
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
    cmd.args([
        "-drive",
        &format!("file={},if=none,id=nvme0,format=raw", disk.display()),
    ]);
    cmd.args(["-device", "nvme,serial=deadbeef,drive=nvme0"]);
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
            println!("[FAIL] {label}: timed out");
            bail!("{label} timed out; see {}", serial.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let log = fs::read_to_string(&serial).unwrap_or_default();
    if let Some(line) = log.lines().find(|line| line.contains("ABTEST FAILED")) {
        println!("[FAIL] {label}: {}", line.trim());
        bail!("{label}: {}", line.trim());
    }
    Ok(log)
}

/// What one boot must and must not show.
#[derive(Default)]
struct Expect<'a> {
    /// The app ran (`ABTEST DONE`) or the firmware reset before it.
    app: bool,
    /// The slot the selector picks; any slot the firmware logs must match.
    running: Option<&'a str>,
    /// Whether `CrabEFIFirmwareTrialPending` exists.
    trial: Option<bool>,
    /// ESRT LastAttemptVersion and whether LastAttemptStatus is success.
    esrt: Option<(u32, bool)>,
    present: &'a [&'a str],
    absent: &'a [&'a str],
}

fn esrt(log: &str) -> Option<(u32, u32)> {
    let line = log.lines().find(|line| line.starts_with("ABTEST ESRT "))?;
    let field = |key: &str| {
        line.split_whitespace()
            .find_map(|word| word.strip_prefix(key))
    };
    let version = u32::from_str_radix(field("version=")?.trim_start_matches("0x"), 16).ok()?;
    let status = field("status=")?.parse().ok()?;
    Some((version, status))
}

/// Check one boot's log; `flash` is read for the selector, which no boot that
/// reaches the app changes.
fn check_boot(log: &str, label: &str, what: &str, expect: &Expect, flash: &Path) -> Result<()> {
    let mut problems = Vec::new();
    let done = log.contains("ABTEST DONE");
    if expect.app != done {
        problems.push(if done {
            "the app ran; expected a firmware reset before it".to_owned()
        } else {
            "the app did not run (no ABTEST DONE)".to_owned()
        });
    }
    // The firmware only logs the slots when it needs them (trials, capsules);
    // the selector decides which slot runs.
    if let Some(slot) = expect.running {
        let selector = fs::read(flash)?[SELECTOR];
        if (selector == 0x01) != (slot == SLOT_B.0) {
            problems.push(format!(
                "selector byte {selector:#04x}, expected {slot} to run"
            ));
        }
        let marker = format!("A/B slots: running '{slot}'");
        if let Some(line) = log
            .lines()
            .find(|line| line.contains("A/B slots: running '") && !line.contains(&marker))
        {
            problems.push(format!("expected {marker:?}, got {:?}", line.trim()));
        }
    }
    if let Some(pending) = expect.trial {
        let marker = if pending {
            "ABTEST TRIAL pending"
        } else {
            "ABTEST TRIAL none"
        };
        if !log.contains(marker) {
            problems.push(format!("missing {marker:?}"));
        }
    }
    if let Some((version, success)) = expect.esrt {
        match esrt(log) {
            Some((found, status)) if found == version && (status == 0) == success => {}
            found => problems.push(format!(
                "ESRT last attempt {found:x?}, expected version {version:#x} with {} status",
                if success { "success" } else { "a failure" }
            )),
        }
    }
    for marker in expect.present {
        if !log.contains(marker) {
            problems.push(format!("missing {marker:?}"));
        }
    }
    for marker in expect.absent {
        if log.contains(marker) {
            problems.push(format!("unexpected {marker:?}"));
        }
    }
    if problems.is_empty() {
        println!("[PASS] {label}: {what}");
        return Ok(());
    }
    for problem in &problems {
        println!("[FAIL] {label}: {problem}");
    }
    bail!("{label}: {what} failed: {}", problems.join("; "));
}

/// Check the slot regions and selector in the flash file.
fn check_flash(flash: &Path, label: &str, b: &[u8], selected_b: bool) -> Result<()> {
    let bytes = fs::read(flash)?;
    let mut problems = Vec::new();
    if bytes[SLOT_A.1..SLOT_A.1 + SLOT_SIZE]
        .iter()
        .any(|byte| *byte != 0xff)
    {
        problems.push(format!(
            "{} (running during every update) was written",
            SLOT_A.0
        ));
    }
    if bytes[SLOT_B.1..SLOT_B.1 + SLOT_SIZE] != *b {
        problems.push(format!("{} does not hold the expected image", SLOT_B.0));
    }
    if (bytes[SELECTOR] == 0x01) != selected_b {
        problems.push(format!(
            "selector byte {:#04x}, expected slot {}",
            bytes[SELECTOR],
            if selected_b { "B" } else { "A" }
        ));
    }
    if problems.is_empty() {
        println!(
            "[PASS] {label}: flash holds A blank, B as expected, selector on {}",
            if selected_b { "B" } else { "A" }
        );
        return Ok(());
    }
    for problem in &problems {
        println!("[FAIL] {label}: {problem}");
    }
    bail!("{label}: flash check failed: {}", problems.join("; "));
}

pub(super) fn run(config: &QemuConfig, disk: &Path) -> Result<()> {
    if !matches!(config.arch, Arch::X86_64) {
        bail!("ab-update-test currently requires x86-64 QEMU");
    }
    if std::env::var_os("CRABEFI_PAYLOAD_MM").is_none() {
        bail!("ab-update-test needs CRABEFI_PAYLOAD_MM=1");
    }
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let report = crate::project_root().join(format!("target/ab-update-reports/{stamp}"));
    fs::create_dir_all(&report)?;
    println!("A/B update test logs: {}", report.display());

    let flash = prepare_runtime_test_flash(Path::new(&config.coreboot_rom))?;
    let rom = fs::read(flash.path())?;
    if rom.len() < SELECTOR + SELECTOR_SIZE
        || rom[SLOT_A.1..SELECTOR + SELECTOR_SIZE]
            .iter()
            .any(|byte| *byte != 0xff)
    {
        bail!("the test ROM's A/B slot range is not blank; use the 8 MiB payload MM fixture");
    }
    let (fmap_offset, fmap_size) = fmap_area(&rom, OUTSIDE_REGION)?;
    if (SLOT_A.1..SELECTOR + SELECTOR_SIZE).contains(&fmap_offset) {
        bail!("FMAP area {OUTSIDE_REGION} overlaps the test slots");
    }
    let outside = rom[fmap_offset..fmap_offset + fmap_size].to_vec();

    let slots = |version| {
        [
            (SLOT_A.0, region_data(version, SLOT_A.0, SLOT_SIZE)),
            (SLOT_B.0, region_data(version, SLOT_B.0, SLOT_SIZE)),
        ]
    };
    let v1_regions = slots(V1);
    let b1 = v1_regions[1].1.clone();
    let v1 = build_capsule(V1, &v1_regions, &report)?;
    let v2_regions = slots(V2);
    let b2 = v2_regions[1].1.clone();
    let v2 = build_capsule(V2, &v2_regions, &report)?;
    let [a3, b3] = slots(V3);
    let v3 = build_capsule(V3, &[a3, b3, (OUTSIDE_REGION, outside)], &report)?;

    let esp = Esp {
        image: crate::disk::mtools_esp_image(disk),
    };
    crate::disk::create_mtools_dir(&esp.image, "::/AB")?;
    crate::disk::create_mtools_dir(&esp.image, "::/EFI/UpdateCapsule")?;
    let boot = |label: &str| boot(config, flash.path(), disk, &report, label);
    let check = |log: &str, label: &str, what: &str, expect: &Expect| {
        check_boot(log, label, what, expect, flash.path())
    };

    // The default log level hides the firmware's slot and trial messages
    // until the app raises it.
    let log = boot("setup")?;
    check(
        &log,
        "setup",
        "the app raised the log level",
        &Expect {
            app: true,
            ..Default::default()
        },
    )?;

    // a. Slot A runs; deliver v1, which carries images for both slots.
    esp.put(&v1, &capsule_path(V1))?;
    esp.put(b"1\n", DELIVER)?;
    let log = boot("deliver-v1")?;
    check(
        &log,
        "deliver-v1",
        "slot A runs without a trial; capsule delivery requested",
        &Expect {
            app: true,
            running: Some(SLOT_A.0),
            trial: Some(false),
            present: &["ABTEST DELIVER"],
            ..Default::default()
        },
    )?;
    esp.remove(DELIVER)?;

    let log = boot("apply-v1")?;
    check(
        &log,
        "apply-v1",
        "v1 written to slot B only, then reset",
        &Expect {
            present: &[
                "Capsule applied successfully",
                "Keeping region 'AB_TEST_A'",
                "to region 'AB_TEST_B'",
            ],
            absent: &["to region 'AB_TEST_A'"],
            ..Default::default()
        },
    )?;
    esp.remove(&capsule_path(V1))?;
    check_flash(flash.path(), "apply-v1", &b1, true)?;

    // b. Never confirmed: trial boots of slot B, then the rollback.
    let mut trials = 0;
    let (label, log) = loop {
        let label = format!("trial-v1-{}", trials + 1);
        let log = boot(&label)?;
        if log.contains("rolling back") || trials >= MAX_TRIALS {
            break (label, log);
        }
        trials += 1;
        let marker = format!("Trial boot {trials} of {MAX_TRIALS} of firmware ");
        check(
            &log,
            &label,
            "unconfirmed trial boot of v1 in slot B",
            &Expect {
                app: true,
                running: Some(SLOT_B.0),
                trial: Some(true),
                esrt: Some((V1, true)),
                present: &[&marker, "in slot 'AB_TEST_B'"],
                ..Default::default()
            },
        )?;
    };
    if trials != MAX_TRIALS {
        println!("[FAIL] {label}: rollback after {trials} trial boots, expected {MAX_TRIALS}");
        bail!("rollback after {trials} trial boots");
    }
    check(
        &log,
        &label,
        "unconfirmed v1 requests the rollback boot and resets",
        &Expect {
            present: &["not confirmed after", "rolling back"],
            ..Default::default()
        },
    )?;
    let log = boot("rollback")?;
    check(
        &log,
        "rollback",
        "the capsule-update boot activates slot A again and resets",
        &Expect {
            present: &["slot 'AB_TEST_A' boots again"],
            absent: &["Processing ESP capsule"],
            ..Default::default()
        },
    )?;
    check_flash(flash.path(), "rollback", &b1, false)?;

    // c. Slot A again; deliver v2 and confirm its first trial boot.
    esp.put(&v2, &capsule_path(V2))?;
    esp.put(b"1\n", DELIVER)?;
    let log = boot("rolled-back")?;
    check(
        &log,
        "rolled-back",
        "slot A runs, no trial, ESRT reports v1 failed; deliver v2",
        &Expect {
            app: true,
            running: Some(SLOT_A.0),
            trial: Some(false),
            esrt: Some((V1, false)),
            present: &["ABTEST DELIVER"],
            ..Default::default()
        },
    )?;
    esp.remove(DELIVER)?;

    let log = boot("apply-v2")?;
    check(
        &log,
        "apply-v2",
        "v2 written to slot B only, then reset",
        &Expect {
            present: &[
                "Capsule applied successfully",
                "Keeping region 'AB_TEST_A'",
                "to region 'AB_TEST_B'",
            ],
            absent: &["to region 'AB_TEST_A'"],
            ..Default::default()
        },
    )?;
    esp.remove(&capsule_path(V2))?;
    check_flash(flash.path(), "apply-v2", &b2, true)?;

    esp.put(b"1\n", CONFIRM)?;
    let log = boot("trial-v2")?;
    let marker = format!("Trial boot 1 of {MAX_TRIALS} of firmware ");
    check(
        &log,
        "trial-v2",
        "first trial boot of v2 in slot B; the OS confirms it",
        &Expect {
            app: true,
            running: Some(SLOT_B.0),
            trial: Some(true),
            esrt: Some((V2, true)),
            present: &[&marker, "in slot 'AB_TEST_B'", "ABTEST CONFIRM"],
            ..Default::default()
        },
    )?;
    esp.remove(CONFIRM)?;

    // d. v3 also names a region outside the slots.
    esp.put(&v3, &capsule_path(V3))?;
    esp.put(b"1\n", DELIVER)?;
    let log = boot("confirmed")?;
    check(
        &log,
        "confirmed",
        "v2 confirmed in slot B, trial over; deliver v3",
        &Expect {
            app: true,
            running: Some(SLOT_B.0),
            trial: Some(false),
            esrt: Some((V2, true)),
            present: &["in slot 'AB_TEST_B' confirmed", "ABTEST DELIVER"],
            absent: &["Trial boot", "rolling back"],
        },
    )?;
    esp.remove(DELIVER)?;

    let rejection = format!("RMAP region '{OUTSIDE_REGION}' is not inside one firmware slot");
    let log = boot("reject-v3")?;
    check(
        &log,
        "reject-v3",
        "v3 rejected without a write or reset; slot B keeps running",
        &Expect {
            app: true,
            running: Some(SLOT_B.0),
            trial: Some(false),
            esrt: Some((V3, false)),
            present: &["Processing ESP capsule", &rejection],
            absent: &["Capsule applied successfully", "bytes to region '"],
        },
    )?;
    esp.remove(&capsule_path(V3))?;

    let log = boot("after-reject")?;
    check(
        &log,
        "after-reject",
        "no capsule processing or reset loop after the rejection",
        &Expect {
            app: true,
            running: Some(SLOT_B.0),
            trial: Some(false),
            esrt: Some((V3, false)),
            absent: &["Processing ESP capsule", "Trial boot"],
            ..Default::default()
        },
    )?;

    // e. Slot A was running during both updates and was never written.
    check_flash(flash.path(), "final", &b2, true)?;
    println!("\nA/B update test passed; logs in {}", report.display());
    Ok(())
}
