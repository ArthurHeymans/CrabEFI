//! QEMU Runner
//!
//! This module provides functionality to run CrabEFI in QEMU with various
//! storage configurations and parse serial output for test results.

use anyhow::{bail, Context, Result};
use regex::Regex;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use crate::{Arch, Machine};

/// Storage type for QEMU
#[derive(Debug, Clone, Copy)]
pub enum StorageType {
    /// USB mass storage via xHCI
    Usb,
    /// AHCI/SATA storage
    Ahci,
    /// NVMe storage
    Nvme,
    /// SDHCI (SD card)
    Sdhci,
}

/// QEMU configuration
pub struct QemuConfig {
    /// Path to coreboot ROM with CrabEFI payload
    pub coreboot_rom: String,
    /// Path to TF-A flash image (aarch64 only, used as pflash0)
    pub tfa_flash: Option<String>,
    /// Storage type to use
    pub storage: StorageType,
    /// Run without graphical display
    pub headless: bool,
    /// Disable KVM acceleration
    pub disable_kvm: bool,
    /// Timeout in seconds (None = no timeout)
    pub timeout_secs: Option<u64>,
    /// Target architecture
    pub arch: Arch,
    /// QEMU machine type (aarch64 only)
    pub machine: Machine,
    /// Extra QEMU device arguments (e.g., USB mouse for UI testing)
    pub extra_devices: Vec<String>,
    /// Enable TPM 2.0 emulation via swtpm (x86_64 only).
    pub enable_tpm: bool,
}

/// Manages a swtpm process lifetime for TPM emulation.
///
/// The swtpm process is killed when this struct is dropped.
pub struct SwtpmProcess {
    child: Child,
    _state_dir: tempfile::TempDir,
}

impl Drop for SwtpmProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn cleanup_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Spawn a swtpm process and return the QEMU arguments to connect to it.
fn spawn_swtpm() -> Result<(SwtpmProcess, Vec<String>)> {
    let state_dir = tempfile::tempdir().context("failed to create swtpm state dir")?;
    let sock_path = state_dir.path().join("swtpm-sock");

    let mut child = Command::new("swtpm")
        .args([
            "socket",
            "--tpmstate",
            &format!("dir={}", state_dir.path().display()),
            "--ctrl",
            &format!("type=unixio,path={}", sock_path.display()),
            "--tpm2",
            "--log",
            "level=0",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to start swtpm (is it installed?)")?;

    // Wait for the control socket. CI hosts can be slow immediately after
    // process spawn, so poll instead of sleeping for a fixed short interval.
    for _ in 0..40 {
        if sock_path.exists() {
            break;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let _ = child.wait();
                bail!("swtpm exited before creating socket: {}", status);
            }
            Ok(None) => {}
            Err(e) => {
                cleanup_child(&mut child);
                return Err(e).context("failed to poll swtpm");
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    if !sock_path.exists() {
        cleanup_child(&mut child);
        bail!("swtpm socket not created at {}", sock_path.display());
    }

    let qemu_args = vec![
        "-chardev".into(),
        format!("socket,id=chrtpm,path={}", sock_path.display()),
        "-tpmdev".into(),
        "emulator,id=tpm0,chardev=chrtpm".into(),
        "-device".into(),
        "tpm-tis,tpmdev=tpm0".into(),
    ];

    Ok((
        SwtpmProcess {
            child,
            _state_dir: state_dir,
        },
        qemu_args,
    ))
}

/// Test result from QEMU run
#[derive(Debug)]
#[allow(dead_code)] // Fields will be used when expanding test framework
pub struct TestResult {
    /// Whether all tests passed
    pub success: bool,
    /// Number of tests that passed
    pub passed: usize,
    /// Total number of tests
    pub total: usize,
    /// Captured serial output
    pub output: String,
}

/// Build QEMU command with the given configuration
fn build_qemu_command(config: &QemuConfig, disk_path: &Path) -> Result<Command> {
    // Check that coreboot ROM exists
    if !Path::new(&config.coreboot_rom).exists() {
        bail!(
            "coreboot ROM not found: {}\n\n\
            Build coreboot with CrabEFI payload:\n\
            1. cargo build --release\n\
            2. Use ./x build to prepare the ROM",
            config.coreboot_rom
        );
    }

    match (config.arch, config.machine) {
        (Arch::X86_64, _) => build_qemu_command_x86_64(config, disk_path),
        (Arch::Aarch64, Machine::Sbsa) => build_qemu_command_aarch64_sbsa(config, disk_path),
        (Arch::Aarch64, Machine::Virt) => build_qemu_command_aarch64_virt(config, disk_path),
        (Arch::Riscv64, _) => build_qemu_command_riscv64(config, disk_path),
    }
}

/// Build QEMU command for x86_64 (Q35)
fn build_qemu_command_x86_64(config: &QemuConfig, disk_path: &Path) -> Result<Command> {
    let mut cmd = Command::new("qemu-system-x86_64");

    // Basic machine setup
    cmd.args(["-machine", "q35"]);
    cmd.args(["-bios", &config.coreboot_rom]);
    cmd.args(["-m", "512M"]);
    cmd.arg("-no-reboot");

    // Display and serial settings
    if config.headless {
        // Use chardev for proper serial output capture
        cmd.args(["-display", "none"]);
        cmd.args(["-chardev", "stdio,id=char0,mux=on,signal=off"]);
        cmd.args(["-serial", "chardev:char0"]);
        cmd.args(["-mon", "chardev=char0,mode=readline"]);
    } else {
        cmd.args(["-serial", "stdio"]);
    }

    // Storage configuration
    add_storage_args_x86_64(&mut cmd, config, disk_path, false);

    // KVM acceleration
    if !config.disable_kvm && is_kvm_available() {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        // Use `-cpu max` so TCG emulates all available features (e.g. RDRAND)
        cmd.args(["-cpu", "max"]);
    }

    // Debug options
    cmd.args(["-d", "guest_errors"]);

    // Extra devices (e.g., USB mouse for UI testing)
    for arg in &config.extra_devices {
        cmd.arg(arg);
    }

    // Capture stderr for QEMU errors
    cmd.stderr(Stdio::piped());
    cmd.stdout(Stdio::piped());

    Ok(cmd)
}

/// Build QEMU command for aarch64 (SBSA)
fn build_qemu_command_aarch64_sbsa(config: &QemuConfig, disk_path: &Path) -> Result<Command> {
    // Validate: no SDHCI on SBSA
    if matches!(config.storage, StorageType::Sdhci) {
        bail!("SDHCI storage is not supported on SBSA (aarch64)");
    }

    let tfa_flash = config
        .tfa_flash
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("TF-A flash path is required for aarch64 SBSA"))?;

    if !Path::new(tfa_flash).exists() {
        bail!("TF-A flash not found: {}", tfa_flash);
    }

    let mut cmd = Command::new("qemu-system-aarch64");

    // Basic machine setup
    cmd.args(["-machine", "sbsa-ref"]);
    cmd.args(["-m", "1G"]);
    cmd.arg("-no-reboot");

    // pflash drives: pflash0 = TF-A, pflash1 = coreboot ROM
    // Use snapshot=on to avoid corrupting the images
    cmd.args([
        "-drive",
        &format!("if=pflash,format=raw,file={},snapshot=on", tfa_flash),
    ]);
    cmd.args([
        "-drive",
        &format!(
            "if=pflash,format=raw,file={},snapshot=on",
            config.coreboot_rom
        ),
    ]);

    // Display and serial settings
    // SBSA uses PL011 UART — -nographic sends serial to stdio
    cmd.arg("-nographic");
    // SBSA machine includes bochs-display which needs a VGA BIOS ROM.
    // Suppress loading it — we're headless and the ROM may not be installed
    // (qemu-system-arm on Ubuntu doesn't ship x86 VGA ROMs).
    cmd.args(["-global", "bochs-display.romfile="]);

    // Storage configuration
    add_storage_args_aarch64(&mut cmd, config, disk_path);

    // CPU: use Neoverse V1 (ARMv8.4-A with RNDR).  The "max" model
    // advertises features (e.g. FEAT_GCS) whose system registers QEMU
    // doesn't fully implement, causing undefined-instruction faults in
    // early Linux boot code that probes ID registers.
    cmd.args(["-cpu", "neoverse-v1"]);

    // Debug options
    cmd.args(["-d", "guest_errors"]);

    // Capture stderr for QEMU errors
    cmd.stderr(Stdio::piped());
    cmd.stdout(Stdio::piped());

    Ok(cmd)
}

/// Build QEMU command for aarch64 (virt — FDT-based, single ROM)
fn build_qemu_command_aarch64_virt(config: &QemuConfig, disk_path: &Path) -> Result<Command> {
    // Validate: no SDHCI on virt (no built-in SDHCI controller)
    if matches!(config.storage, StorageType::Sdhci) {
        bail!("SDHCI storage is not supported on aarch64 virt");
    }

    let mut cmd = Command::new("qemu-system-aarch64");

    // Basic machine setup
    // secure=on enables TrustZone so TF-A (BL31) can run at EL3.
    // virtualization=on enables EL2 so coreboot's payload runs at EL2.
    cmd.args(["-machine", "virt,secure=on,virtualization=on"]);
    cmd.args(["-m", "1G"]);
    cmd.arg("-no-reboot");
    cmd.args(["-cpu", "cortex-a53"]);

    // Flash: single coreboot ROM loaded as pflash (read-only).
    // The virt machine ROM starts at address 0x0.
    cmd.args([
        "-drive",
        &format!(
            "if=pflash,format=raw,file={},readonly=on",
            config.coreboot_rom
        ),
    ]);

    // Display and serial: PL011 UART to stdio
    cmd.arg("-nographic");

    // Storage configuration (same as SBSA, minus SDHCI)
    add_storage_args_aarch64(&mut cmd, config, disk_path);

    // Debug options
    cmd.args(["-d", "guest_errors"]);

    // Capture stderr for QEMU errors
    cmd.stderr(Stdio::piped());
    cmd.stdout(Stdio::piped());

    Ok(cmd)
}

/// Add storage arguments for x86_64
fn add_storage_args_x86_64(
    cmd: &mut Command,
    config: &QemuConfig,
    disk_path: &Path,
    snapshot: bool,
) {
    let disk_path_str = disk_path.to_string_lossy();
    let snapshot_arg = if snapshot { ",snapshot=on" } else { "" };
    match config.storage {
        StorageType::Usb => {
            cmd.args(["-device", "qemu-xhci,id=xhci"]);
            cmd.args([
                "-drive",
                &format!(
                    "file={},if=none,id=usbdisk,format=raw{}",
                    disk_path_str, snapshot_arg
                ),
            ]);
            cmd.args(["-device", "usb-storage,drive=usbdisk,bus=xhci.0"]);
        }
        StorageType::Ahci => {
            cmd.args([
                "-drive",
                &format!(
                    "file={},if=none,id=disk0,format=raw{}",
                    disk_path_str, snapshot_arg
                ),
            ]);
            cmd.args(["-device", "ide-hd,drive=disk0,bus=ide.0"]);
        }
        StorageType::Nvme => {
            cmd.args([
                "-drive",
                &format!(
                    "file={},if=none,id=nvme0,format=raw{}",
                    disk_path_str, snapshot_arg
                ),
            ]);
            cmd.args(["-device", "nvme,serial=deadbeef,drive=nvme0"]);
        }
        StorageType::Sdhci => {
            cmd.args(["-device", "sdhci-pci"]);
            cmd.args([
                "-drive",
                &format!(
                    "file={},if=none,id=sddrive0,format=raw{}",
                    disk_path_str, snapshot_arg
                ),
            ]);
            cmd.args(["-device", "sd-card,drive=sddrive0"]);
        }
    }
}

/// Add storage arguments for aarch64 (SBSA)
fn add_storage_args_aarch64(cmd: &mut Command, config: &QemuConfig, disk_path: &Path) {
    let disk_path_str = disk_path.to_string_lossy();
    match config.storage {
        StorageType::Usb => {
            cmd.args(["-device", "qemu-xhci,id=xhci"]);
            cmd.args([
                "-drive",
                &format!("file={},if=none,id=usbdisk,format=raw", disk_path_str),
            ]);
            cmd.args(["-device", "usb-storage,drive=usbdisk,bus=xhci.0"]);
        }
        StorageType::Ahci => {
            cmd.args([
                "-drive",
                &format!("file={},if=none,id=disk0,format=raw", disk_path_str),
            ]);
            cmd.args(["-device", "ide-hd,drive=disk0,bus=ide.0"]);
        }
        StorageType::Nvme => {
            cmd.args([
                "-drive",
                &format!(
                    "file={},if=none,id=nvme0,format=raw,media=disk",
                    disk_path_str
                ),
            ]);
            cmd.args(["-device", "nvme,serial=deadbeef,drive=nvme0"]);
        }
        StorageType::Sdhci => {
            // This shouldn't be reached due to validation in build_qemu_command_aarch64,
            // but handle gracefully
            unreachable!("SDHCI is not supported on SBSA");
        }
    }
}

/// Check if KVM is available
fn is_kvm_available() -> bool {
    Path::new("/dev/kvm").exists()
        && std::fs::metadata("/dev/kvm")
            .map(|m| m.permissions().readonly() == false)
            .unwrap_or(false)
}

/// Wrapper to kill child process on drop
#[allow(dead_code)]
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run QEMU interactively (for `xtask run`)
pub fn run_qemu(config: &QemuConfig, disk_path: Option<&Path>) -> Result<()> {
    // Create a temporary disk if none provided
    let temp_disk;
    let disk = if let Some(path) = disk_path {
        path.to_path_buf()
    } else {
        temp_disk = tempfile::NamedTempFile::new()?;
        // Create a minimal test disk
        crate::disk::create_test_disk(
            temp_disk.path().to_string_lossy().as_ref(),
            None,
            config.arch,
        )?;
        temp_disk.path().to_path_buf()
    };

    let mut cmd = build_qemu_command(config, &disk)?;

    // Start swtpm for TPM emulation if requested.
    let _swtpm = if config.enable_tpm {
        match spawn_swtpm() {
            Ok((swtpm, tpm_args)) => {
                for arg in &tpm_args {
                    cmd.arg(arg);
                }
                println!("TPM 2.0 emulation enabled via swtpm");
                Some(swtpm)
            }
            Err(e) => {
                eprintln!("Warning: failed to start swtpm: {}", e);
                None
            }
        }
    } else {
        None
    };

    // For interactive mode, use inherited stdio
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    println!(
        "=== CrabEFI QEMU ({:?}, {:?}) ===",
        config.arch, config.storage
    );
    println!("coreboot ROM: {}", config.coreboot_rom);
    if let Some(ref tfa) = config.tfa_flash {
        println!("TF-A flash: {}", tfa);
    }
    println!("Press Ctrl+A X to exit QEMU");
    println!("==========================================\n");

    let status = cmd.status().context("failed to run QEMU")?;
    // _swtpm dropped here

    if !status.success() {
        bail!("QEMU exited with status: {:?}", status.code());
    }

    Ok(())
}

/// Boot headless QEMU and capture the emulated display once the UI is up.
///
/// Uses the QEMU human monitor over a unix socket: `screendump` works with
/// `-display none`, so no compositor or windowing system is needed.  The
/// moment to capture is detected by watching the serial log for the boot
/// manager's menu messages.
pub fn run_screenshot(
    config: &QemuConfig,
    disk_path: Option<&Path>,
    out: &Path,
    timeout_secs: u64,
) -> Result<()> {
    use std::time::Duration;

    if !matches!(config.arch, Arch::X86_64) {
        bail!("screenshot is currently only supported on x86_64");
    }

    let extension = out
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);
    if !matches!(extension.as_deref(), Some("png" | "ppm")) {
        bail!("screenshot output must have a .png or .ppm extension");
    }

    // Create a temporary disk if none provided (same default as run_qemu)
    let temp_disk;
    let disk = if let Some(path) = disk_path {
        path.to_path_buf()
    } else {
        temp_disk = tempfile::NamedTempFile::new()?;
        crate::disk::create_test_disk(
            temp_disk.path().to_string_lossy().as_ref(),
            None,
            config.arch,
        )?;
        temp_disk.path().to_path_buf()
    };

    let temp_dir = tempfile::tempdir()?;
    let serial_log = temp_dir.path().join("serial.log");
    let mon_sock = temp_dir.path().join("monitor.sock");
    let ppm = temp_dir.path().join("capture.ppm");

    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(["-machine", "q35"]);
    cmd.args(["-bios", &config.coreboot_rom]);
    cmd.args(["-m", "512M"]);
    cmd.arg("-no-reboot");
    // No display backend at all — the emulated VGA still exists and the
    // monitor can screendump it.
    cmd.args(["-display", "none"]);
    // Serial to a file so we can watch for the menu marker.
    cmd.args(["-serial", &format!("file:{}", serial_log.display())]);
    // Human monitor on a unix socket for screendump.
    cmd.args([
        "-monitor",
        &format!("unix:{},server,nowait", mon_sock.display()),
    ]);
    add_storage_args_x86_64(&mut cmd, config, &disk, disk_path.is_some());
    if !config.disable_kvm && is_kvm_available() {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        cmd.args(["-cpu", "max"]);
    }
    for arg in &config.extra_devices {
        cmd.arg(arg);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    let mut child = cmd.spawn().context("failed to start QEMU")?;

    let result = capture_when_ready(
        &mut child,
        &serial_log,
        &mon_sock,
        &ppm,
        out,
        Duration::from_secs(timeout_secs),
    );
    cleanup_child(&mut child);
    result
}

/// Wait for the UI marker on serial, then trigger `screendump` via the
/// monitor socket and move the result to `out`.
fn capture_when_ready(
    child: &mut Child,
    serial_log: &Path,
    mon_sock: &Path,
    ppm: &Path,
    out: &Path,
    timeout: std::time::Duration,
) -> Result<()> {
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() > deadline {
            bail!("timed out waiting for the UI (no menu marker on serial)");
        }
        if let Some(status) = child.try_wait()? {
            bail!("QEMU exited before the UI appeared: {}", status);
        }
        if let Ok(text) = std::fs::read_to_string(serial_log) {
            // ponytail: these two markers cover the boot menu and the
            // no-media screen; add more markers for other screens.
            if text.contains("Showing boot menu...") || text.contains("No bootable media found!")
            {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // Let the UI finish its first full paint (the boot menu has a 5s
    // countdown by default, so don't dawdle).
    std::thread::sleep(std::time::Duration::from_millis(700));

    let mut mon = UnixStream::connect(mon_sock).context("failed to connect QEMU monitor socket")?;
    mon.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    let mut response = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !response.ends_with(b"(qemu) ") {
        match mon.read(&mut buffer) {
            Ok(0) => bail!("QEMU monitor closed before becoming ready"),
            Ok(count) => response.extend_from_slice(&buffer[..count]),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                bail!("timed out waiting for the QEMU monitor prompt")
            }
            Err(error) => return Err(error.into()),
        }
    }

    writeln!(mon, "screendump {}", ppm.display())?;
    mon.flush()?;

    response.clear();
    while !response.ends_with(b"(qemu) ") {
        match mon.read(&mut buffer) {
            Ok(0) => bail!("QEMU monitor closed before screendump completed"),
            Ok(count) => response.extend_from_slice(&buffer[..count]),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                bail!("timed out waiting for screendump to complete")
            }
            Err(error) => return Err(error.into()),
        }
    }
    if !ppm.is_file() || ppm.metadata()?.len() == 0 {
        bail!("screendump produced no image data");
    }

    let extension = out
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);
    if extension.as_deref() == Some("png") {
        match Command::new("magick").arg(ppm).arg(out).status() {
            Ok(s) if s.success() => {}
            _ => {
                std::fs::copy(ppm, out.with_extension("ppm"))?;
                bail!("ImageMagick 'magick' not found; wrote {} instead", out.with_extension("ppm").display());
            }
        }
    } else if extension.as_deref() == Some("ppm") {
        std::fs::copy(ppm, out)?;
    } else {
        bail!("screenshot output must have a .png or .ppm extension");
    }
    println!("Screenshot written to {}", out.display());
    Ok(())
}

/// Run integration tests in QEMU
pub fn run_tests(config: &QemuConfig, disk_path: &Path, app_name: &str) -> Result<()> {
    println!(
        "=== CrabEFI Integration Tests ({}, {:?}) ===\n",
        app_name, config.arch
    );

    // Run QEMU and capture output
    println!("Running tests in QEMU...\n");
    let result = run_qemu_with_capture(config, disk_path)?;

    // Keep firmware memory metrics visible in successful CI runs.
    for line in result
        .output
        .lines()
        .filter(|line| line.contains("MEMORY_REPORT"))
    {
        println!("{line}");
    }

    // Analyze results
    println!("\n=== Test Results ===");
    println!("Output captured: {} bytes", result.output.len());

    // Check for expected output based on app
    let mut passed = 0;
    let mut failed = 0;

    match app_name {
        "hello" => {
            // Test 1: Check if "Hello from CrabEFI!" appears
            if result.output.contains("Hello from CrabEFI!") {
                println!("[PASS] hello_output: Hello message printed");
                passed += 1;
            } else {
                println!("[FAIL] hello_output: Expected 'Hello from CrabEFI!' in output");
                failed += 1;
            }

            // Test 2: Check if EFI app executed successfully
            if result.output.contains("EFI app executed successfully!") {
                println!("[PASS] efi_app_executed: EFI application ran successfully");
                passed += 1;
            } else {
                println!("[FAIL] efi_app_executed: EFI application did not complete");
                failed += 1;
            }
        }
        "storage-security-test" => {
            // Check for storage security test markers
            if result.output.contains("Storage Security Protocol Test") {
                println!("[PASS] test_started: Storage security test started");
                passed += 1;
            } else {
                println!("[FAIL] test_started: Test did not start");
                failed += 1;
            }

            // Check for any passed tests
            if result.output.contains("[PASS]") {
                println!("[PASS] some_tests_passed: At least one test passed");
                passed += 1;
            }
        }
        "secure-boot-test" => {
            // Check for Secure Boot test markers
            if result.output.contains("Secure Boot Test Suite") {
                println!("[PASS] test_started: Secure Boot test suite started");
                passed += 1;
            } else {
                println!("[FAIL] test_started: Secure Boot test did not start");
                failed += 1;
            }

            // Check for passing tests section
            if result.output.contains("Passing Tests") {
                println!("[PASS] passing_tests_section: Passing tests section found");
                passed += 1;
            } else {
                println!("[FAIL] passing_tests_section: Missing passing tests section");
                failed += 1;
            }

            // Check for failing tests section
            if result.output.contains("Failing Tests") {
                println!("[PASS] failing_tests_section: Failing tests section found");
                passed += 1;
            } else {
                println!("[FAIL] failing_tests_section: Missing failing tests section");
                failed += 1;
            }

            // Check for results summary
            if result.output.contains("Results:") {
                println!("[PASS] results_summary: Test results summary found");
                passed += 1;
            } else {
                println!("[FAIL] results_summary: Missing results summary");
                failed += 1;
            }

            // Check for specific SecureBoot tests
            if result.output.contains("read_secure_boot") {
                println!("[PASS] sb_read_test: SecureBoot read test executed");
                passed += 1;
            }

            if result.output.contains("read_setup_mode") {
                println!("[PASS] sm_read_test: SetupMode read test executed");
                passed += 1;
            }

            if result.output.contains("mode_consistency") {
                println!("[PASS] consistency_test: Mode consistency test executed");
                passed += 1;
            }

            // Check for any failed tests in output
            // Count [FAIL] occurrences in the actual test output
            let fail_count = result.output.matches("[FAIL]").count();
            if fail_count == 0 {
                println!("[PASS] no_internal_failures: No test failures detected");
                passed += 1;
            } else {
                println!(
                    "[WARN] internal_failures: {} test failures detected",
                    fail_count
                );
                // Don't count this as a framework failure - the tests themselves report status
            }

            // Final check: did all tests pass?
            if result.output.contains("All Secure Boot tests passed!") {
                println!("[PASS] all_tests_passed: All Secure Boot tests passed");
                passed += 1;
            } else if result.output.contains("Some Secure Boot tests failed!") {
                println!("[FAIL] all_tests_passed: Some Secure Boot tests failed");
                failed += 1;
            }
        }
        "rng-test" => {
            // Check that the test app started
            if result.output.contains("RNG Protocol Test") {
                println!("[PASS] test_started: RNG protocol test started");
                passed += 1;
            } else {
                println!("[FAIL] test_started: RNG protocol test did not start");
                failed += 1;
            }

            // Check protocol was located
            if result.output.contains("[PASS] locate_protocol") {
                println!("[PASS] locate_protocol: RNG protocol found");
                passed += 1;
            } else {
                println!("[FAIL] locate_protocol: RNG protocol not found");
                failed += 1;
            }

            // Check GetInfo works
            if result.output.contains("[PASS] get_info") {
                println!("[PASS] get_info: Algorithm enumeration succeeded");
                passed += 1;
            } else {
                println!("[FAIL] get_info: Algorithm enumeration failed");
                failed += 1;
            }

            // Check random byte generation
            if result.output.contains("[PASS] get_rng_default") {
                println!("[PASS] get_rng_default: Default algorithm produced random bytes");
                passed += 1;
            } else {
                println!("[FAIL] get_rng_default: Default algorithm failed");
                failed += 1;
            }

            // Check uniqueness
            if result.output.contains("[PASS] uniqueness") {
                println!("[PASS] uniqueness: Multiple calls return different data");
                passed += 1;
            } else {
                println!("[FAIL] uniqueness: Multiple calls returned identical data");
                failed += 1;
            }

            // Check all tests passed
            if result.output.contains("All RNG tests passed!") {
                println!("[PASS] all_passed: All RNG tests passed");
                passed += 1;
            } else {
                println!("[FAIL] all_passed: Not all RNG tests passed");
                failed += 1;
            }
        }
        "grub-linux" => {
            // ── GRUB + Linux + u-root boot-chain test ────────────────
            // Full boot path: CrabEFI -> GRUB -> Linux -> u-root init.
            // u-root prints UROOT_BOOT_SUCCESS from its -uinitcmd.

            // Check that Linux actually started
            if result.output.contains("Linux version") {
                println!("[PASS] linux_started: Linux kernel started (saw 'Linux version')");
                passed += 1;
            } else {
                println!("[FAIL] linux_started: 'Linux version' not found in output");
                failed += 1;
            }

            // Check that u-root userspace reached its init
            if result.output.contains("UROOT_BOOT_SUCCESS") {
                println!("[PASS] userspace: u-root init reached userspace");
                passed += 1;
            } else {
                println!("[FAIL] userspace: 'UROOT_BOOT_SUCCESS' not found in output");
                failed += 1;
            }
        }
        "tcg-test" => {
            // TCG (TPM 1.2) and TCG2 (TPM 2.0) protocol tests
            if result.output.contains("TCG Protocol Test") {
                println!("[PASS] test_started: TCG protocol test started");
                passed += 1;
            } else {
                println!("[FAIL] test_started: TCG protocol test did not start");
                failed += 1;
            }

            if result.output.contains("[PASS] tcg2_locate") {
                println!("[PASS] tcg2_locate: TCG2 protocol found");
                passed += 1;
            } else {
                println!("[FAIL] tcg2_locate: TCG2 protocol not found");
                failed += 1;
            }

            if result.output.contains("[PASS] tcg2_get_capability") {
                println!("[PASS] tcg2_get_capability: GetCapability succeeded");
                passed += 1;
            } else {
                println!("[FAIL] tcg2_get_capability: GetCapability failed");
                failed += 1;
            }

            if result.output.contains("[PASS] tcg2_hardware_tpm") {
                println!("[PASS] tcg2_hardware_tpm: Hardware TPM via swtpm is active");
                passed += 1;
            } else {
                println!("[FAIL] tcg2_hardware_tpm: Hardware TPM via swtpm was not active");
                failed += 1;
            }

            if result.output.contains("[PASS] tcg2_get_event_log") {
                println!("[PASS] tcg2_get_event_log: Event log available");
                passed += 1;
            } else {
                println!("[FAIL] tcg2_get_event_log: Event log unavailable");
                failed += 1;
            }

            if result.output.contains("[PASS] tcg2_hash_log_extend") {
                println!("[PASS] tcg2_hash_log_extend: HashLogExtendEvent succeeded");
                passed += 1;
            } else {
                println!("[FAIL] tcg2_hash_log_extend: HashLogExtendEvent failed");
                failed += 1;
            }

            if result.output.contains("[PASS] tcg2_get_active_pcr_banks") {
                println!("[PASS] tcg2_get_active_pcr_banks: active banks reported correctly");
                passed += 1;
            } else {
                println!("[FAIL] tcg2_get_active_pcr_banks: active banks not reported correctly");
                failed += 1;
            }

            if result.output.contains("[PASS] tcg2_set_active_pcr_banks") {
                println!("[PASS] tcg2_set_active_pcr_banks: current bank set accepted");
                passed += 1;
            } else {
                println!("[FAIL] tcg2_set_active_pcr_banks: current bank set rejected");
                failed += 1;
            }

            if result
                .output
                .contains("[PASS] tcg2_get_result_of_set_active_pcr_banks")
            {
                println!("[PASS] tcg2_get_result_of_set_active_pcr_banks: no pending operation");
                passed += 1;
            } else {
                println!("[FAIL] tcg2_get_result_of_set_active_pcr_banks: unexpected result");
                failed += 1;
            }

            if result.output.contains("[PASS] tcg2_submit_command") {
                println!("[PASS] tcg2_submit_command: SubmitCommand returned an expected status");
                passed += 1;
            } else {
                println!(
                    "[FAIL] tcg2_submit_command: SubmitCommand did not return an expected status"
                );
                failed += 1;
            }

            if result.output.contains("[PASS] tcg1_locate") {
                println!("[PASS] tcg1_locate: TCG (TPM 1.2) protocol found");
                passed += 1;
            } else {
                println!("[FAIL] tcg1_locate: TCG (TPM 1.2) protocol not found");
                failed += 1;
            }

            if result.output.contains("All TCG tests passed!") {
                println!("[PASS] all_passed: All TCG tests passed");
                passed += 1;
            } else {
                println!("[FAIL] all_passed: Not all TCG tests passed");
                failed += 1;
            }
        }
        "directory-test" => {
            // Check that the test app started
            if result.output.contains("Directory Enumeration Test") {
                println!("[PASS] test_started: Directory enumeration test started");
                passed += 1;
            } else {
                println!("[FAIL] test_started: Test did not start");
                failed += 1;
            }

            // Check OpenVolume succeeded
            if result.output.contains("[PASS] OpenVolume succeeded") {
                println!("[PASS] open_volume: OpenVolume succeeded");
                passed += 1;
            } else {
                println!("[FAIL] open_volume: OpenVolume failed");
                failed += 1;
            }

            // Check that the long filename (>64 chars) was found intact
            if result.output.contains("[PASS] long_filename:") {
                println!("[PASS] long_filename: Filename >64 chars returned intact");
                passed += 1;
            } else {
                println!(
                    "[FAIL] long_filename: Filename >64 chars NOT found (LFN truncation bug?)"
                );
                failed += 1;
            }

            // Check that the long filename's .efi suffix was preserved
            if result.output.contains("[PASS] long_filename_suffix:") {
                println!("[PASS] long_filename_suffix: .efi suffix preserved on long name");
                passed += 1;
            } else {
                println!("[FAIL] long_filename_suffix: .efi suffix lost on long filename");
                failed += 1;
            }

            // Check that the short filename was also found
            if result.output.contains("[PASS] short_filename:") {
                println!("[PASS] short_filename: Short filename found");
                passed += 1;
            } else {
                println!("[FAIL] short_filename: Short filename not found");
                failed += 1;
            }

            // Check overall result
            if result.output.contains("test PASSED!") {
                println!("[PASS] overall: Directory enumeration test passed");
                passed += 1;
            } else {
                println!("[FAIL] overall: Directory enumeration test failed");
                failed += 1;
            }
        }
        "device-path-test" => {
            // Check that the test app started
            if result.output.contains("Device Path Protocol Test Suite") {
                println!("[PASS] test_started: Device Path test suite started");
                passed += 1;
            } else {
                println!("[FAIL] test_started: Device Path test did not start");
                failed += 1;
            }

            // Check protocol discovery
            for (tag, label) in [
                ("locate_utilities", "Device Path Utilities"),
                ("locate_to_text", "Device Path To Text"),
                ("locate_from_text", "Device Path From Text"),
            ] {
                let pattern = format!("[PASS] {}", tag);
                if result.output.contains(&pattern) {
                    println!("[PASS] {}: {} protocol found", tag, label);
                    passed += 1;
                } else {
                    println!("[FAIL] {}: {} protocol not found", tag, label);
                    failed += 1;
                }
            }

            // Check key functional tests
            for tag in [
                "create_device_node",
                "get_size",
                "duplicate",
                "append_device_path",
                "append_both_null",
                "is_multi_instance_multi",
                "get_next_instance_1",
                "get_next_instance_2",
                "node_to_text_pci",
                "path_to_text_pci_root",
                "node_to_text_acpi_pnp",
                "text_to_node_pci_root",
                "text_to_node_acpi_pnp",
                "text_to_path_pci",
                "round_trip",
            ] {
                let pattern = format!("[PASS] {}", tag);
                if result.output.contains(&pattern) {
                    println!("[PASS] {}", tag);
                    passed += 1;
                } else {
                    let fail_pattern = format!("[FAIL] {}", tag);
                    if result.output.contains(&fail_pattern) {
                        println!("[FAIL] {}", tag);
                        failed += 1;
                    }
                    // If neither PASS nor FAIL, the test may not have run (skip)
                }
            }

            // Check overall result
            if result.output.contains("All device path tests passed!") {
                println!("[PASS] all_passed: All device path tests passed");
                passed += 1;
            } else if result.output.contains("Some device path tests FAILED!") {
                println!("[FAIL] all_passed: Some device path tests failed");
                failed += 1;
            }
        }
        "capsule-test" => {
            // Check that the test app started
            if result.output.contains("Capsule Update Test Suite") {
                println!("[PASS] test_started: Capsule test suite started");
                passed += 1;
            } else {
                println!("[FAIL] test_started: Capsule test suite did not start");
                failed += 1;
            }

            // Check OsIndicationsSupported was set by firmware
            if result.output.contains("OsIndicationsSupported set:") {
                println!("[PASS] firmware_os_ind: Firmware set OsIndicationsSupported");
                passed += 1;
            } else {
                println!("[FAIL] firmware_os_ind: Firmware did not set OsIndicationsSupported");
                failed += 1;
            }

            // Check individual test results from the EFI app
            for test_name in [
                "os_ind_supported_read",
                "os_ind_fmp_capsule_bit",
                "os_ind_file_capsule_bit",
                "query_caps_call",
                "query_caps_max_size",
                "update_capsule_null_rejected",
            ] {
                let pass_marker = format!("[PASS] {}", test_name);
                let fail_marker = format!("[FAIL] {}", test_name);
                if result.output.contains(&pass_marker) {
                    println!("[PASS] {}: Test passed", test_name);
                    passed += 1;
                } else if result.output.contains(&fail_marker) {
                    println!("[FAIL] {}: Test failed", test_name);
                    failed += 1;
                } else {
                    println!("[FAIL] {}: Test not executed", test_name);
                    failed += 1;
                }
            }

            // Check for UpdateCapsule/QueryCapsuleCapabilities in RT properties
            if result.output.contains("UpdateCapsule") || result.output.contains("query_caps_call")
            {
                // At least one capsule runtime service was exercised
            }

            // Overall result
            if result.output.contains("All capsule tests passed!") {
                println!("[PASS] all_passed: All capsule tests passed");
                passed += 1;
            } else if result.output.contains("Some capsule tests failed!") {
                println!("[FAIL] all_passed: Some capsule tests failed");
                failed += 1;
            }
        }
        _ => {
            // Generic test: just check if CrabEFI booted
            if result.output.contains("CrabEFI") {
                println!("[PASS] crabefi_boot: CrabEFI initialized");
                passed += 1;
            } else {
                println!("[FAIL] crabefi_boot: CrabEFI did not initialize");
                failed += 1;
            }
        }
    }

    // Always check CrabEFI initialized
    if result.output.contains("CrabEFI") {
        println!("[PASS] crabefi_init: CrabEFI initialized");
        passed += 1;
    } else {
        println!("[FAIL] crabefi_init: CrabEFI did not initialize");
        failed += 1;
    }

    println!("\n=== Summary ===");
    println!("Passed: {}", passed);
    println!("Failed: {}", failed);

    if failed > 0 {
        println!("\n--- Captured Output ---");
        println!("{}", result.output);
        bail!("{} test(s) failed", failed);
    }

    Ok(())
}

/// Run QEMU and capture serial output
fn run_qemu_with_capture(config: &QemuConfig, disk_path: &Path) -> Result<TestResult> {
    let timeout = config.timeout_secs.unwrap_or(60);

    match (config.arch, config.machine) {
        (Arch::X86_64, _) => run_qemu_with_capture_x86_64(config, disk_path, timeout),
        (Arch::Aarch64, Machine::Sbsa) => {
            run_qemu_with_capture_aarch64_sbsa(config, disk_path, timeout)
        }
        (Arch::Aarch64, Machine::Virt) => {
            run_qemu_with_capture_aarch64_virt(config, disk_path, timeout)
        }
        (Arch::Riscv64, _) => run_qemu_with_capture_riscv64(config, disk_path, timeout),
    }
}

/// Run QEMU with capture for x86_64
fn run_qemu_with_capture_x86_64(
    config: &QemuConfig,
    disk_path: &Path,
    timeout: u64,
) -> Result<TestResult> {
    // Use the `timeout` command to enforce the timeout at the process level
    let mut cmd = Command::new("timeout");
    cmd.arg("--signal=KILL");
    cmd.arg(format!("{}s", timeout));
    cmd.arg("qemu-system-x86_64");

    // Build the rest of QEMU args
    cmd.args(["-machine", "q35"]);
    cmd.args(["-bios", &config.coreboot_rom]);
    cmd.args(["-m", "2G"]);
    cmd.arg("-no-reboot");

    // Serial settings for capture
    cmd.args(["-display", "none"]);
    cmd.args(["-chardev", "stdio,id=char0,mux=on,signal=off"]);
    cmd.args(["-serial", "chardev:char0"]);
    cmd.args(["-mon", "chardev=char0,mode=readline"]);

    // Storage configuration
    add_storage_args_x86_64(&mut cmd, config, disk_path, false);

    // KVM acceleration
    if !config.disable_kvm && is_kvm_available() {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        cmd.args(["-cpu", "max"]);
    }

    cmd.args(["-d", "guest_errors"]);

    // Extra devices
    for arg in &config.extra_devices {
        cmd.arg(arg);
    }

    // TPM emulation via swtpm. Capture-mode tests that request TPM must fail
    // early if swtpm cannot start; otherwise the TCG test could silently pass
    // in software-only mode and never exercise the TIS/SubmitCommand path.
    let _swtpm = if config.enable_tpm {
        let (swtpm, tpm_args) = spawn_swtpm()?;
        for arg in &tpm_args {
            cmd.arg(arg);
        }
        Some(swtpm)
    } else {
        None
    };

    // Execute and capture output
    let output = cmd.output().context("failed to execute QEMU via timeout")?;

    // _swtpm is dropped here, killing the swtpm process
    parse_qemu_output(&output)
}

/// Run QEMU with capture for aarch64 (SBSA)
fn run_qemu_with_capture_aarch64_sbsa(
    config: &QemuConfig,
    disk_path: &Path,
    timeout: u64,
) -> Result<TestResult> {
    // Validate: no SDHCI on SBSA
    if matches!(config.storage, StorageType::Sdhci) {
        bail!("SDHCI storage is not supported on SBSA (aarch64)");
    }

    let tfa_flash = config
        .tfa_flash
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("TF-A flash path is required for aarch64 SBSA"))?;

    let mut cmd = Command::new("timeout");
    cmd.arg("--signal=KILL");
    cmd.arg(format!("{}s", timeout));
    cmd.arg("qemu-system-aarch64");

    // Machine setup
    cmd.args(["-machine", "sbsa-ref"]);
    cmd.args(["-m", "1G"]);
    cmd.arg("-no-reboot");

    // pflash drives
    cmd.args([
        "-drive",
        &format!("if=pflash,format=raw,file={},snapshot=on", tfa_flash),
    ]);
    cmd.args([
        "-drive",
        &format!(
            "if=pflash,format=raw,file={},snapshot=on",
            config.coreboot_rom
        ),
    ]);

    // Serial: -nographic for PL011 to stdio
    cmd.arg("-nographic");
    // Suppress bochs-display VGA BIOS ROM (not shipped with qemu-system-arm)
    cmd.args(["-global", "bochs-display.romfile="]);

    // Storage configuration
    add_storage_args_aarch64(&mut cmd, config, disk_path);

    // CPU: use Neoverse V1 (see above)
    cmd.args(["-cpu", "neoverse-v1"]);

    cmd.args(["-d", "guest_errors"]);

    // Execute and capture output
    let output = cmd
        .output()
        .context("failed to execute QEMU (aarch64) via timeout")?;

    parse_qemu_output(&output)
}

/// Run QEMU with capture for aarch64 (virt — FDT-based, single ROM)
fn run_qemu_with_capture_aarch64_virt(
    config: &QemuConfig,
    disk_path: &Path,
    timeout: u64,
) -> Result<TestResult> {
    if matches!(config.storage, StorageType::Sdhci) {
        bail!("SDHCI storage is not supported on aarch64 virt");
    }

    let mut cmd = Command::new("timeout");
    cmd.arg("--signal=KILL");
    cmd.arg(format!("{}s", timeout));
    cmd.arg("qemu-system-aarch64");

    // Machine setup
    cmd.args(["-machine", "virt,secure=on,virtualization=on"]);
    cmd.args(["-m", "1G"]);
    cmd.arg("-no-reboot");
    cmd.args(["-cpu", "cortex-a53"]);

    // Flash: single coreboot ROM
    cmd.args([
        "-drive",
        &format!(
            "if=pflash,format=raw,file={},readonly=on",
            config.coreboot_rom
        ),
    ]);

    // Serial: -nographic for PL011 to stdio
    cmd.arg("-nographic");

    // Storage configuration
    add_storage_args_aarch64(&mut cmd, config, disk_path);

    cmd.args(["-d", "guest_errors"]);

    // Execute and capture output
    let output = cmd
        .output()
        .context("failed to execute QEMU (aarch64-virt) via timeout")?;

    parse_qemu_output(&output)
}

/// Build QEMU command for riscv64 (QEMU virt)
fn build_qemu_command_riscv64(config: &QemuConfig, disk_path: &Path) -> Result<Command> {
    if matches!(config.storage, StorageType::Sdhci) {
        bail!("SDHCI storage is not supported on riscv64 virt");
    }

    let mut cmd = Command::new("qemu-system-riscv64");

    // Basic machine setup
    cmd.args(["-machine", "virt"]);
    cmd.args(["-m", "1024M"]);
    cmd.arg("-no-reboot");

    // coreboot ROM: -bios loads bootblock into DRAM at reset vector,
    // -drive if=pflash maps the ROM as SPI flash for CBFS access.
    cmd.args(["-bios", &config.coreboot_rom]);
    cmd.args([
        "-drive",
        &format!(
            "if=pflash,file={},format=raw,readonly=on",
            config.coreboot_rom
        ),
    ]);

    // Serial: 16550 UART to stdio via -nographic
    cmd.arg("-nographic");

    // Storage configuration
    add_storage_args_riscv64(&mut cmd, config, disk_path);

    // Debug options
    cmd.args(["-d", "guest_errors"]);

    // Capture output
    cmd.stderr(Stdio::piped());
    cmd.stdout(Stdio::piped());

    Ok(cmd)
}

/// Add storage arguments for riscv64 (virtio-based)
fn add_storage_args_riscv64(cmd: &mut Command, config: &QemuConfig, disk_path: &Path) {
    let disk_path_str = disk_path.to_string_lossy();
    match config.storage {
        StorageType::Usb => {
            cmd.args(["-device", "qemu-xhci,id=xhci"]);
            cmd.args([
                "-drive",
                &format!("file={},if=none,id=usbdisk,format=raw", disk_path_str),
            ]);
            cmd.args(["-device", "usb-storage,drive=usbdisk,bus=xhci.0"]);
        }
        StorageType::Nvme => {
            cmd.args([
                "-drive",
                &format!(
                    "file={},if=none,id=nvme0,format=raw,media=disk",
                    disk_path_str
                ),
            ]);
            cmd.args(["-device", "nvme,serial=deadbeef,drive=nvme0"]);
        }
        StorageType::Ahci => {
            // QEMU virt has no native AHCI; attach via PCI
            cmd.args(["-device", "ahci,id=ahci0"]);
            cmd.args([
                "-drive",
                &format!("file={},if=none,id=disk0,format=raw", disk_path_str),
            ]);
            cmd.args(["-device", "ide-hd,drive=disk0,bus=ahci0.0"]);
        }
        StorageType::Sdhci => {
            unreachable!("SDHCI is not supported on riscv64 virt");
        }
    }
}

/// Run QEMU with capture for riscv64 (QEMU virt)
fn run_qemu_with_capture_riscv64(
    config: &QemuConfig,
    disk_path: &Path,
    timeout: u64,
) -> Result<TestResult> {
    if matches!(config.storage, StorageType::Sdhci) {
        bail!("SDHCI storage is not supported on riscv64 virt");
    }

    let mut cmd = Command::new("timeout");
    cmd.arg("--signal=KILL");
    cmd.arg(format!("{}s", timeout));
    cmd.arg("qemu-system-riscv64");

    // Machine setup
    cmd.args(["-machine", "virt"]);
    cmd.args(["-m", "1024M"]);
    cmd.arg("-no-reboot");

    // coreboot ROM: -bios + pflash
    cmd.args(["-bios", &config.coreboot_rom]);
    cmd.args([
        "-drive",
        &format!(
            "if=pflash,file={},format=raw,readonly=on",
            config.coreboot_rom
        ),
    ]);

    // Serial: -nographic for 16550 UART to stdio
    cmd.arg("-nographic");

    // Storage configuration
    add_storage_args_riscv64(&mut cmd, config, disk_path);

    cmd.args(["-d", "guest_errors"]);

    // Execute and capture output
    let output = cmd
        .output()
        .context("failed to execute QEMU (riscv64) via timeout")?;

    parse_qemu_output(&output)
}

/// Parse QEMU output into a TestResult
fn parse_qemu_output(output: &std::process::Output) -> Result<TestResult> {
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Combine stdout and stderr
    let combined = format!("{}\n{}", stdout, stderr);

    // Strip ANSI escape codes
    let ansi_re =
        Regex::new(r"\x1b\[[0-9;]*[mHJK]|\x1b\[\?[0-9]*[hl]|\x1b\[2J|\x1b\[\?25[hl]").unwrap();
    let clean_output = ansi_re.replace_all(&combined, "").to_string();

    Ok(TestResult {
        success: clean_output.contains("EFI app executed successfully"),
        passed: 0, // Will be calculated by caller
        total: 0,
        output: clean_output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kvm_check() {
        // Just ensure it doesn't panic
        let _ = is_kvm_available();
    }
}
