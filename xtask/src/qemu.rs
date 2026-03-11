//! QEMU Runner
//!
//! This module provides functionality to run CrabEFI in QEMU with various
//! storage configurations and parse serial output for test results.

use anyhow::{bail, Context, Result};
use regex::Regex;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use crate::Arch;

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

    match config.arch {
        Arch::X86_64 => build_qemu_command_x86_64(config, disk_path),
        Arch::Aarch64 => build_qemu_command_aarch64(config, disk_path),
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
    add_storage_args_x86_64(&mut cmd, config, disk_path);

    // KVM acceleration
    if !config.disable_kvm && is_kvm_available() {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        // Use `-cpu max` so TCG emulates all available features (e.g. RDRAND)
        cmd.args(["-cpu", "max"]);
    }

    // Debug options
    cmd.args(["-d", "guest_errors"]);

    // Capture stderr for QEMU errors
    cmd.stderr(Stdio::piped());
    cmd.stdout(Stdio::piped());

    Ok(cmd)
}

/// Build QEMU command for aarch64 (SBSA)
fn build_qemu_command_aarch64(config: &QemuConfig, disk_path: &Path) -> Result<Command> {
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

    // CPU: always use TCG for cross-arch (no KVM on non-native)
    cmd.args(["-cpu", "max"]);

    // Debug options
    cmd.args(["-d", "guest_errors"]);

    // Capture stderr for QEMU errors
    cmd.stderr(Stdio::piped());
    cmd.stdout(Stdio::piped());

    Ok(cmd)
}

/// Add storage arguments for x86_64
fn add_storage_args_x86_64(cmd: &mut Command, config: &QemuConfig, disk_path: &Path) {
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
                &format!("file={},if=none,id=nvme0,format=raw", disk_path_str),
            ]);
            cmd.args(["-device", "nvme,serial=deadbeef,drive=nvme0"]);
        }
        StorageType::Sdhci => {
            cmd.args(["-device", "sdhci-pci"]);
            cmd.args([
                "-drive",
                &format!("file={},if=none,id=sddrive0,format=raw", disk_path_str),
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

    if !status.success() {
        bail!("QEMU exited with status: {:?}", status.code());
    }

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

    match config.arch {
        Arch::X86_64 => run_qemu_with_capture_x86_64(config, disk_path, timeout),
        Arch::Aarch64 => run_qemu_with_capture_aarch64(config, disk_path, timeout),
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
    add_storage_args_x86_64(&mut cmd, config, disk_path);

    // KVM acceleration
    if !config.disable_kvm && is_kvm_available() {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        cmd.args(["-cpu", "max"]);
    }

    cmd.args(["-d", "guest_errors"]);

    // Execute and capture output
    let output = cmd.output().context("failed to execute QEMU via timeout")?;

    parse_qemu_output(&output)
}

/// Run QEMU with capture for aarch64 (SBSA)
fn run_qemu_with_capture_aarch64(
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

    // CPU: always TCG for cross-arch
    cmd.args(["-cpu", "max"]);

    cmd.args(["-d", "guest_errors"]);

    // Execute and capture output
    let output = cmd
        .output()
        .context("failed to execute QEMU (aarch64) via timeout")?;

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
