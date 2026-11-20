//! CrabEFI Build and Test Automation
//!
//! This xtask provides commands for building, testing, and running CrabEFI.
//! Similar to cargo-xtask pattern used by uefi-rs and other OS projects.
//!
//! # Usage
//!
//! ```bash
//! ./crabefi build                    # Build CrabEFI
//! ./crabefi run                      # Run in QEMU with USB storage  
//! ./crabefi run --ahci               # Run in QEMU with AHCI storage
//! ./crabefi run --nvme               # Run in QEMU with NVMe storage
//! ./crabefi run --app hello          # Run with specific test app
//! ./crabefi test                     # Run integration tests in QEMU
//! ./crabefi build-test-app hello     # Build a test EFI application
//! ./crabefi list-test-apps           # List available test apps
//! ```

mod disk;
mod qemu;
mod rom;
mod runtime;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Global project directory, set via --project-dir or derived from CARGO_MANIFEST_DIR
static PROJECT_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Get the project root directory
fn project_root() -> &'static Path {
    PROJECT_DIR.get().expect("PROJECT_DIR not initialized")
}

/// The Rust toolchain pinned by the workspace `rust-toolchain.toml`
/// (e.g. `"nightly-2026-10-08"`). Subprocesses that run outside the project tree —
/// where rustup cannot discover the file — pass it explicitly as
/// `+<channel>` so every firmware build uses the same compiler.
fn pinned_toolchain() -> Result<String> {
    let path = project_root().join("rust-toolchain.toml");
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("read pinned toolchain from {}", path.display()))?;
    contents
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "channel").then(|| value.trim().trim_matches('"').to_owned())
        })
        .filter(|channel| !channel.is_empty())
        .with_context(|| format!("no channel pinned in {}", path.display()))
}

/// Target architecture for CrabEFI
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Arch {
    X86_64,
    Aarch64,
    Riscv64,
}

impl Arch {
    /// Short directory/file-name component for this architecture.
    pub fn dir_name(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
            Arch::Riscv64 => "riscv64",
        }
    }
}

/// QEMU machine type for aarch64
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Machine {
    /// QEMU SBSA reference platform (requires TF-A pflash, DRAM at 1TB)
    Sbsa,
    /// QEMU virt machine (FDT-based, DRAM at 1GB)
    Virt,
}

#[derive(Parser)]
#[command(name = "crabefi", bin_name = "crabefi")]
#[command(about = "CrabEFI build and test automation")]
struct Cli {
    /// Path to the CrabEFI project directory (set automatically by ./crabefi wrapper)
    #[arg(long, global = true, hide = true)]
    project_dir: Option<PathBuf>,

    /// Target architecture
    #[arg(long, global = true, value_enum, default_value_t = Arch::X86_64)]
    arch: Arch,

    /// QEMU machine type (aarch64 only; ignored for x86_64)
    #[arg(long, global = true, value_enum, default_value_t = Machine::Sbsa)]
    machine: Machine,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build CrabEFI
    Build {
        /// Build in release mode (default, required for firmware)
        #[arg(long, default_value_t = true)]
        release: bool,

        /// Enable graphical UI with mouse support
        #[arg(long)]
        ui: bool,

        /// Build the 64-bit x86 entry for u-root/LinuxBoot (not coreboot)
        #[arg(long)]
        entry64: bool,

        /// Boot Linux directly without UEFI (x86-64 only)
        #[arg(long, conflicts_with = "ui")]
        native_only: bool,

        /// Enable experimental BLS boot from ext2/3/4 (x86-64 only)
        #[arg(long)]
        ext4: bool,
    },

    /// Build and audit a linked runtime without replacing its checked-in bundle
    AuditRuntime {
        #[arg(long)]
        secure_boot: bool,
    },

    /// Regenerate the checked-in Cargo runtime bundle for one architecture
    BundleRuntime {
        /// Include UEFI authenticated variables and Secure Boot policy.
        #[arg(long)]
        secure_boot: bool,
    },

    /// Verify all checked-in runtime image/digest pairs and their target profiles
    CheckRuntimeBundle {
        /// Also rebuild all six images and check freshness against current sources.
        #[arg(long)]
        rebuild: bool,
    },

    /// Run CrabEFI in QEMU
    Run {
        /// Path to coreboot ROM (default: ~/src/coreboot/build/coreboot.rom)
        #[arg(long)]
        coreboot_rom: Option<String>,

        /// Use AHCI/SATA storage instead of USB
        #[arg(long)]
        ahci: bool,

        /// Use NVMe storage instead of USB
        #[arg(long)]
        nvme: bool,

        /// Use SDHCI (SD card) storage instead of USB
        #[arg(long)]
        sdhci: bool,

        /// Run without graphical display (serial only)
        #[arg(long)]
        headless: bool,

        /// Disable KVM acceleration
        #[arg(long)]
        disable_kvm: bool,

        /// Test app to run (e.g., hello, storage-security-test)
        #[arg(long)]
        app: Option<String>,

        /// Path to existing disk image to use
        #[arg(long)]
        disk: Option<String>,

        /// Enable the x86-64 runtime test's two-boot replay on an existing disk
        #[arg(long, requires = "disk")]
        runtime_replay: bool,

        /// Boot Linux directly without UEFI (x86-64 only)
        #[arg(long, requires = "disk", conflicts_with_all = ["coreboot_rom", "app", "runtime_replay", "ui"])]
        native_only: bool,

        /// Enable experimental BLS boot from ext2/3/4 (x86-64 only)
        #[arg(long, conflicts_with = "coreboot_rom")]
        ext4: bool,

        /// Enable graphical UI with mouse support
        #[arg(long)]
        ui: bool,
    },

    /// Run integration tests in QEMU
    Test {
        /// Path to coreboot ROM
        #[arg(long)]
        coreboot_rom: Option<String>,

        /// Test app to run (default: hello)
        ///
        /// Use "grub-linux" for the GRUB + Linux boot-chain test.
        /// Use "ext4-linux" (also "ext2-linux" or "ext3-linux") for native Linux boot.
        /// Use "native-only-linux" or "native-only-fat-linux" to test without UEFI.
        /// Use "uefi-sct-smoke" for the UEFI SCT smoke subset.
        /// Use "windows-boot-smoke" for a Windows Boot Manager smoke test.
        #[arg(long, default_value = "hello")]
        app: String,

        /// Use AHCI storage
        #[arg(long)]
        ahci: bool,

        /// Use NVMe storage
        #[arg(long)]
        nvme: bool,

        /// Use SDHCI (SD card) storage
        #[arg(long)]
        sdhci: bool,

        /// Disable KVM acceleration
        #[arg(long)]
        disable_kvm: bool,

        /// Timeout in seconds (default: 60)
        #[arg(long, default_value_t = 60)]
        timeout: u64,

        /// Enable graphical UI with mouse support
        #[arg(long)]
        ui: bool,

        /// Directory containing pre-built Linux boot assets (default: boot-assets/<arch>).
        #[arg(long)]
        boot_assets_dir: Option<PathBuf>,

        /// Directory containing pre-built UEFI SCT assets.
        /// Required when --app uefi-sct-smoke is used unless sct-assets/<arch> exists.
        #[arg(long)]
        sct_assets_dir: Option<PathBuf>,

        /// SCT sequence to run instead of ci/sct/smoke.seq.
        #[arg(long, requires = "sct_report_dir")]
        sct_sequence: Option<PathBuf>,

        /// Directory for SCT serial output, summary, and detailed reports.
        #[arg(long)]
        sct_report_dir: Option<PathBuf>,

        /// Raw Windows/WinPE disk image for --app windows-boot-smoke.
        /// Defaults to windows-assets/<arch>/windows-smoke.img.
        #[arg(long)]
        windows_disk: Option<PathBuf>,

        /// Windows/WinPE boot media directory for --app windows-boot-smoke.
        /// Defaults to windows-assets/<arch>/media if present.
        #[arg(long)]
        windows_media_dir: Option<PathBuf>,

        /// Serial output marker that indicates a successful Windows smoke boot.
        /// May be passed multiple times; any matching marker passes the test.
        #[arg(long = "windows-success-marker")]
        windows_success_markers: Vec<String>,
    },

    /// Take a screenshot of the graphical UI in headless QEMU
    ///
    /// Builds CrabEFI with --ui, boots it with `-display none`, and captures
    /// the emulated display via the QEMU monitor's screendump command.
    Screenshot {
        /// Output image path (.ppm, or .png if ImageMagick is installed)
        #[arg(long, default_value = "screenshot.ppm")]
        out: String,

        /// Test app to place on the boot disk (gives the menu real entries,
        /// e.g. --app hello). Without it the no-media screen is captured.
        #[arg(long, conflicts_with = "disk")]
        app: Option<String>,

        /// Path to an existing disk image to boot from
        #[arg(long, conflicts_with = "app")]
        disk: Option<String>,

        /// Seconds to wait for the UI before giving up
        #[arg(long, default_value_t = 90)]
        timeout_s: u64,

        /// Disable KVM acceleration
        #[arg(long)]
        disable_kvm: bool,
    },

    /// Build a test EFI application
    BuildTestApp {
        /// Name of the test app (hello, storage-security-test)
        name: String,
    },

    /// List available test applications
    ListTestApps,

    /// Create a test disk image
    CreateDisk {
        /// Output path for the disk image
        #[arg(long, default_value = "test-disk.img")]
        output: String,

        /// Path to EFI application to install as BOOTX64.EFI
        #[arg(long)]
        efi_app: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize project directory
    let project_dir = cli.project_dir.unwrap_or_else(|| {
        // Fall back to deriving from CARGO_MANIFEST_DIR (works when built in-tree)
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf()
    });
    PROJECT_DIR
        .set(project_dir)
        .expect("PROJECT_DIR already initialized");

    let arch = cli.arch;
    let machine = cli.machine;

    match cli.command {
        Commands::Build {
            release,
            ui,
            entry64,
            ext4,
            native_only,
        } => cmd_build_payload(
            release,
            ui,
            arch,
            machine,
            entry64,
            boot_features(native_only, ext4),
        ),
        Commands::AuditRuntime { secure_boot } => {
            runtime::build_with_capabilities(arch, secure_boot).map(|_| ())
        }
        Commands::BundleRuntime { secure_boot } => runtime::bundle(arch, secure_boot),
        Commands::CheckRuntimeBundle { rebuild } => runtime::check_bundle(rebuild),
        Commands::Run {
            coreboot_rom,
            ahci,
            nvme,
            sdhci,
            headless,
            disable_kvm,
            app,
            disk,
            runtime_replay,
            ui,
            ext4,
            native_only,
        } => cmd_run(
            coreboot_rom,
            ahci,
            nvme,
            sdhci,
            headless,
            disable_kvm,
            app,
            disk,
            runtime_replay,
            ui,
            arch,
            machine,
            boot_features(native_only, ext4),
        ),
        Commands::Test {
            coreboot_rom,
            app,
            ahci,
            nvme,
            sdhci,
            disable_kvm,
            timeout,
            ui,
            boot_assets_dir,
            sct_assets_dir,
            sct_sequence,
            sct_report_dir,
            windows_disk,
            windows_media_dir,
            windows_success_markers,
        } => cmd_test(
            coreboot_rom,
            &app,
            ahci,
            nvme,
            sdhci,
            disable_kvm,
            timeout,
            ui,
            arch,
            machine,
            boot_assets_dir,
            sct_assets_dir,
            sct_sequence,
            sct_report_dir,
            windows_disk,
            windows_media_dir,
            windows_success_markers,
        ),
        Commands::Screenshot {
            out,
            app,
            disk,
            timeout_s,
            disable_kvm,
        } => cmd_screenshot(&out, app, disk, timeout_s, disable_kvm, arch, machine),
        Commands::BuildTestApp { name } => cmd_build_test_app(&name, arch),
        Commands::ListTestApps => cmd_list_test_apps(),
        Commands::CreateDisk { output, efi_app } => {
            cmd_create_disk(&output, efi_app.as_deref(), arch)
        }
    }
}

// Native coreboot run/test/screenshot commands always use the default entry.
fn boot_features(native_only: bool, ext4: bool) -> &'static [&'static str] {
    match (native_only, ext4) {
        (false, false) => &[],
        (false, true) => &["ext4"],
        (true, false) => &["native-only"],
        (true, true) => &["native-only", "ext4"],
    }
}

fn cmd_build(release: bool, ui: bool, arch: Arch, machine: Machine) -> Result<()> {
    cmd_build_payload(release, ui, arch, machine, false, &[])
}

fn ext_linux_filesystem(app: &str) -> Option<&'static str> {
    match app {
        "ext2-linux" => Some("ext2"),
        "ext3-linux" => Some("ext3"),
        "ext4-linux" | "native-only-linux" => Some("ext4"),
        _ => None,
    }
}

/// Payload Cargo features a test app needs beyond the default build.
fn test_payload_features(app: &str) -> Vec<&'static str> {
    let mut features = match app {
        "ab-update-test" => vec!["ab-test-slots"],
        "boot-policy-test" => vec!["usb-on-demand"],
        "fwui-test" => vec!["external-boot-setting"],
        "mm-seal-test" => vec!["payload-mm-test-lose-ready-to-boot"],
        "runtime-replay-interrupt-test" => vec!["replay-test-reset-after-persist"],
        "boot-events-test" => vec!["boot-event-log"],
        "native-only-linux" => vec!["native-only", "ext4"],
        "native-only-fat-linux" => vec!["native-only"],
        app if ext_linux_filesystem(app).is_some() => vec!["ext4"],
        _ => Vec::new(),
    };
    if capsule_on_disk_only() {
        features.push("capsule-on-disk-only");
    }
    features
}

/// CRABEFI_CAPSULE_ON_DISK_ONLY=1: test a payload that accepts capsules only
/// from the ESP; capsule-test, built with the same variable, then checks it.
pub(crate) fn capsule_on_disk_only() -> bool {
    std::env::var_os("CRABEFI_CAPSULE_ON_DISK_ONLY").is_some()
}

/// Target directory of a payload build; variants never overwrite the default.
fn payload_target_dir(entry64: bool, features: &[&str]) -> String {
    let mut variants = Vec::new();
    if entry64 {
        variants.push("entry64");
    }
    variants.extend_from_slice(features);
    if variants.is_empty() {
        "target".to_string()
    } else {
        format!("target/{}", variants.join("+"))
    }
}

fn cmd_build_payload(
    release: bool,
    ui: bool,
    arch: Arch,
    machine: Machine,
    entry64: bool,
    extra_features: &[&str],
) -> Result<()> {
    if entry64 && arch != Arch::X86_64 {
        bail!("--entry64 is only supported on x86-64");
    }
    let native_only = extra_features.contains(&"native-only");
    if native_only && arch != Arch::X86_64 {
        bail!("--native-only is only supported on x86-64");
    }
    if native_only && std::env::var_os("CRABEFI_PAYLOAD_MM").is_some() {
        bail!("--native-only is incompatible with CRABEFI_PAYLOAD_MM");
    }
    if extra_features.contains(&"ext4") && arch != Arch::X86_64 {
        bail!("--ext4 is only supported on x86-64");
    }
    let label = match (arch, machine) {
        (Arch::X86_64, _) => "x86_64".to_string(),
        (Arch::Aarch64, Machine::Sbsa) => "aarch64/sbsa".to_string(),
        (Arch::Aarch64, Machine::Virt) => "aarch64/virt".to_string(),
        (Arch::Riscv64, _) => "riscv64".to_string(),
    };
    println!("Building CrabEFI ({})...", label);

    let project_root = project_root();
    let runtime = if native_only {
        None
    } else {
        println!("Building and auditing separate Runtime Services image...");
        Some(runtime::build(arch)?)
    };

    let mut cmd = std::process::Command::new("cargo");
    let toolchain = format!("+{}", pinned_toolchain()?);
    cmd.args([
        toolchain.as_str(),
        "-Z",
        "build-std=core,compiler_builtins,alloc",
        "-Z",
        "build-std-features=compiler-builtins-mem",
        "build",
    ]);
    // Build the coreboot payload binary (the binary target lives in the
    // crabefi-coreboot workspace member, not in the root library crate).
    cmd.arg("-p").arg("crabefi-coreboot");
    cmd.arg("--no-default-features");
    if release {
        cmd.arg("--release");
    }
    // CRABEFI_DEBUG_ASSERTIONS=1: keep the payload's debug assertions, such as
    // the check that no firmware borrow is live across a foreign call, in a
    // release build. Only the payload: the runtime image must stay panic-free.
    if std::env::var_os("CRABEFI_DEBUG_ASSERTIONS").is_some() {
        cmd.args(["--config", "profile.release.debug-assertions=true"]);
    }
    let mut features = extra_features.to_vec();
    if !native_only {
        features.push("external-runtime-image");
    }
    if ui {
        features.push("ui");
    }
    if entry64 {
        features.push("entry64");
    }
    // Do not overwrite the default coreboot payload with an incompatible
    // entry or feature set: regular run/test commands must still find it.
    let target_dir = payload_target_dir(entry64, extra_features);
    if target_dir != "target" {
        cmd.arg("--target-dir").arg(&target_dir);
    }
    // CRABEFI_PAYLOAD_MM=1: also build the runtime image as payload MM and load it into coreboot's
    // payload MM SMRAM (needs a coreboot base ROM with PAYLOAD_MM_INTERFACE,
    // see CRABEFI_Q35_ROM).
    if std::env::var_os("CRABEFI_PAYLOAD_MM").is_some() && matches!(arch, Arch::X86_64) {
        let output =
            std::process::Command::new(project_root.join("crabefi-runtime-image/mm-build.sh"))
                .stderr(std::process::Stdio::inherit())
                .output()
                .context("Failed to run crabefi-runtime-image/mm-build.sh")?;
        if !output.status.success() {
            bail!("payload MM runtime image build failed");
        }
        let elf = String::from_utf8_lossy(&output.stdout)
            .lines()
            .last()
            .unwrap_or_default()
            .to_string();
        runtime::audit_mm_image(Path::new(&elf))?;
        cmd.env("CRABEFI_MM_ELF", elf);
        features.push("payload-mm");
    }
    cmd.arg("--features").arg(features.join(","));

    let target_triple = match arch {
        Arch::X86_64 => "x86_64-unknown-none",
        Arch::Aarch64 => "aarch64-unknown-none",
        Arch::Riscv64 => "riscv64gc-unknown-none-elf",
    };
    cmd.arg("--target").arg(target_triple);
    if let Some(runtime) = runtime {
        cmd.env("RUNTIME_IMAGE_PATH", &runtime.image);
        cmd.env(
            "RUNTIME_IMAGE_SHA256",
            runtime.digest.map(|byte| format!("{byte:02x}")).concat(),
        );
    }

    // Architecture-specific: set PAYLOAD_BASE for the linker script.
    match arch {
        Arch::Aarch64 => {
            let payload_base = match machine {
                Machine::Sbsa => "0x10022000000",
                Machine::Virt => "0x62000000",
            };
            cmd.env("PAYLOAD_BASE", payload_base);
        }
        Arch::Riscv64 => {
            // QEMU virt: DRAM at 0x80000000, payload at 0x81000000 (16MB in)
            cmd.env("PAYLOAD_BASE", "0x81000000");
        }
        _ => {}
    }

    // Key-database timestamps are floored at the build's source date; derive
    // it from the checked-out commit unless the caller already set one.
    if std::env::var_os("SOURCE_DATE_EPOCH").is_none()
        && let Some(epoch) = commit_epoch(project_root)
    {
        cmd.env("SOURCE_DATE_EPOCH", epoch);
    }

    cmd.current_dir(project_root);
    // Remove RUSTUP_TOOLCHAIN to let CrabEFI use its own rust-toolchain.toml
    cmd.env_remove("RUSTUP_TOOLCHAIN");

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Build failed");
    }

    let mode = if release { "release" } else { "debug" };
    println!("Built: {target_dir}/{target_triple}/{mode}/crabefi");
    Ok(())
}

/// Committer date of `HEAD` as Unix seconds, if the tree is a git checkout.
fn commit_epoch(project_root: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["log", "-1", "--format=%ct"])
        .current_dir(project_root)
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let epoch = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    epoch.parse::<u64>().is_ok().then_some(epoch)
}

#[allow(clippy::too_many_arguments)]
fn cmd_run(
    coreboot_rom: Option<String>,
    ahci: bool,
    nvme: bool,
    sdhci: bool,
    headless: bool,
    disable_kvm: bool,
    app: Option<String>,
    disk: Option<String>,
    runtime_replay: bool,
    ui: bool,
    arch: Arch,
    machine: Machine,
    extra_features: &[&str],
) -> Result<()> {
    if runtime_replay && arch != Arch::X86_64 {
        bail!("--runtime-replay is only supported on x86-64");
    }
    let storage = if ahci {
        qemu::StorageType::Ahci
    } else if nvme {
        qemu::StorageType::Nvme
    } else if sdhci {
        qemu::StorageType::Sdhci
    } else {
        qemu::StorageType::Usb
    };

    // Create temp dir for ROM and disk (needs to live for duration of QEMU run)
    let temp_dir = tempfile::tempdir()?;

    // Prepare the ROM
    let firmware = if let Some(rom) = coreboot_rom {
        rom::PreparedFirmware {
            coreboot_rom: PathBuf::from(rom),
            tfa_flash: None,
        }
    } else {
        // Build CrabEFI first
        cmd_build_payload(true, ui, arch, machine, false, extra_features)?;

        // Prepare ROM with CrabEFI payload
        let crabefi_elf = rom::get_crabefi_elf_in(&payload_target_dir(false, extra_features), arch);
        rom::prepare_rom(&crabefi_elf, temp_dir.path(), arch, machine)?
    };

    let mut config = qemu::QemuConfig {
        coreboot_rom: firmware.coreboot_rom.to_string_lossy().to_string(),
        tfa_flash: firmware.tfa_flash.map(|p| p.to_string_lossy().to_string()),
        storage,
        headless,
        disable_kvm,
        timeout_secs: None,
        arch,
        machine,
        extra_devices: Vec::new(),
        enable_tpm: app.as_deref() == Some("tcg-test") && matches!(arch, Arch::X86_64),
    };

    // Add USB keyboard for UI testing.
    // NOTE: We do NOT add -device usb-mouse because QEMU routes ALL window
    // mouse events to the USB mouse exclusively, starving the PS/2 mouse.
    // The PS/2 mouse (built into Q35's i8042) receives window mouse events
    // by default when no USB pointing device is present.
    if ui {
        config.extra_devices.push("-device".to_string());
        config.extra_devices.push("usb-kbd,bus=xhci.0".to_string());
    }

    // If a disk is specified, use it directly
    if let Some(disk_path) = disk {
        return qemu::run_qemu(&config, Some(Path::new(&disk_path)), runtime_replay);
    }

    // If an app is specified, build it and create a disk with it
    if let Some(app_name) = app {
        // Build the app
        println!("Building test app: {}", app_name);
        cmd_build_test_app(&app_name, arch)?;

        // Find the EFI file
        let efi_path = find_test_app_efi(&app_name, arch)?;

        // Create a temporary disk with this app
        let disk_path = temp_dir.path().join("test.img");
        disk::create_test_disk(disk_path.to_string_lossy().as_ref(), Some(&efi_path), arch)?;

        return qemu::run_qemu(&config, Some(&disk_path), false);
    }

    // Otherwise just run with a minimal disk
    qemu::run_qemu(&config, None, false)
}

fn cmd_screenshot(
    out: &str,
    app: Option<String>,
    disk: Option<String>,
    timeout_s: u64,
    disable_kvm: bool,
    arch: Arch,
    machine: Machine,
) -> Result<()> {
    // Screenshot always wants the UI build
    cmd_build(true, true, arch, machine)?;

    let temp_dir = tempfile::tempdir()?;
    let crabefi_elf = rom::get_crabefi_elf(arch);
    let firmware = rom::prepare_rom(&crabefi_elf, temp_dir.path(), arch, machine)?;

    let config = qemu::QemuConfig {
        coreboot_rom: firmware.coreboot_rom.to_string_lossy().to_string(),
        tfa_flash: firmware.tfa_flash.map(|p| p.to_string_lossy().to_string()),
        storage: qemu::StorageType::Usb,
        headless: true,
        disable_kvm,
        timeout_secs: Some(timeout_s),
        arch,
        machine,
        extra_devices: vec!["-device".to_string(), "usb-kbd,bus=xhci.0".to_string()],
        enable_tpm: false,
    };

    if let Some(disk_path) = disk {
        return qemu::run_screenshot(
            &config,
            Some(Path::new(&disk_path)),
            Path::new(out),
            timeout_s,
        );
    }

    if let Some(app_name) = app {
        println!("Building test app: {}", app_name);
        cmd_build_test_app(&app_name, arch)?;
        let efi_path = find_test_app_efi(&app_name, arch)?;
        let disk_path = temp_dir.path().join("test.img");
        disk::create_test_disk(disk_path.to_string_lossy().as_ref(), Some(&efi_path), arch)?;
        return qemu::run_screenshot(&config, Some(&disk_path), Path::new(out), timeout_s);
    }

    qemu::run_screenshot(&config, None, Path::new(out), timeout_s)
}

fn windows_source_media_dir(
    disk: Option<&Path>,
    media: Option<&Path>,
    default_assets: &Path,
) -> Option<PathBuf> {
    media.map(resolve_project_path).or_else(|| {
        if disk.is_some() {
            return None;
        }
        let path = default_assets.join("media");
        path.exists().then_some(path)
    })
}

#[allow(clippy::too_many_arguments)]
fn cmd_test(
    coreboot_rom: Option<String>,
    app: &str,
    ahci: bool,
    nvme: bool,
    sdhci: bool,
    disable_kvm: bool,
    timeout: u64,
    ui: bool,
    arch: Arch,
    machine: Machine,
    boot_assets_dir: Option<PathBuf>,
    sct_assets_dir: Option<PathBuf>,
    sct_sequence: Option<PathBuf>,
    sct_report_dir: Option<PathBuf>,
    windows_disk: Option<PathBuf>,
    windows_media_dir: Option<PathBuf>,
    windows_success_markers: Vec<String>,
) -> Result<()> {
    // Payload MM persists runtime writes at once; there is no journal
    // replay to interrupt. Refuse before building or booting anything.
    if app == "runtime-replay-interrupt-test" && std::env::var_os("CRABEFI_PAYLOAD_MM").is_some() {
        bail!("runtime-replay-interrupt-test needs the retained journal, not payload MM");
    }
    let native_fat = app == "native-only-fat-linux";
    if (app == "native-only-linux" || native_fat) && ui {
        bail!("{app} uses the text menu; omit --ui");
    }
    let ext_filesystem = ext_linux_filesystem(app);
    if native_fat && arch != Arch::X86_64 {
        bail!("{app} needs x86-64");
    }
    if ext_filesystem.is_some() && (arch != Arch::X86_64 || sdhci) {
        bail!("{app} needs x86-64 with AHCI or NVMe storage");
    }
    let storage = if ahci || (ext_filesystem.is_some() && !nvme) {
        qemu::StorageType::Ahci
    } else if nvme {
        qemu::StorageType::Nvme
    } else if sdhci {
        qemu::StorageType::Sdhci
    } else {
        qemu::StorageType::Usb
    };

    if app != "uefi-sct-smoke" && (sct_sequence.is_some() || sct_report_dir.is_some()) {
        bail!("SCT sequence/report options require --app uefi-sct-smoke");
    }
    let sequence = sct_sequence
        .as_deref()
        .map(resolve_project_path)
        .map(fs::read_to_string)
        .transpose()?
        .unwrap_or_else(|| qemu::sct::SMOKE_SEQUENCE.to_owned());
    let sequence = qemu::sct::Sequence::parse(&sequence)?;
    let sct_report_dir = sct_report_dir
        .as_deref()
        .map(resolve_project_path)
        .unwrap_or_else(|| project_root().join("target/sct-reports/smoke"));

    // Create temp dir for ROM and disk
    let temp_dir = tempfile::tempdir()?;

    // The payload must trust the test capsule signer.
    if app == "ab-update-test" {
        qemu::ab_update::prepare_trust_root()?;
    }

    // Prepare the ROM
    let firmware = if let Some(rom) = coreboot_rom {
        rom::PreparedFirmware {
            coreboot_rom: PathBuf::from(rom),
            tfa_flash: None,
        }
    } else {
        // Build CrabEFI first
        let features = test_payload_features(app);
        cmd_build_payload(true, ui, arch, machine, false, &features)?;

        // Prepare ROM with CrabEFI payload
        let crabefi_elf = rom::get_crabefi_elf_in(&payload_target_dir(false, &features), arch);
        rom::prepare_rom(&crabefi_elf, temp_dir.path(), arch, machine)?
    };

    let config = qemu::QemuConfig {
        coreboot_rom: firmware.coreboot_rom.to_string_lossy().to_string(),
        tfa_flash: firmware.tfa_flash.map(|p| p.to_string_lossy().to_string()),
        storage,
        headless: true,
        disable_kvm,
        timeout_secs: Some(timeout),
        arch,
        machine,
        extra_devices: Vec::new(),
        // Enable TPM emulation for TCG test app.
        enable_tpm: app == "tcg-test" && matches!(arch, Arch::X86_64),
    };

    let disk_path = temp_dir.path().join("test.img");

    let boot_assets = || {
        boot_assets_dir
            .as_deref()
            .map(resolve_project_path)
            .unwrap_or_else(|| project_root().join("boot-assets").join(arch.dir_name()))
    };
    if native_fat {
        let assets_dir = boot_assets();
        let kernel = assets_dir.join("vmlinuz");
        require_boot_assets(arch, &assets_dir, &[("vmlinuz", &kernel)])?;
        cmd_build_test_app("hello", arch)?;
        let efi_app = find_test_app_efi("hello", arch)?;
        disk::create_native_fat_disk(&disk_path, &efi_app, &kernel)?;
    } else if let Some(filesystem) = ext_filesystem {
        let assets_dir = boot_assets();
        let kernel = assets_dir.join("vmlinuz");
        let initramfs = assets_dir.join("initramfs.cpio");
        require_boot_assets(
            arch,
            &assets_dir,
            &[("vmlinuz", &kernel), ("initramfs.cpio", &initramfs)],
        )?;
        disk::create_ext_linux_disk(&disk_path, &kernel, &initramfs, filesystem)?;
    } else if app == "grub-linux" {
        let assets_dir = boot_assets();

        let grub_efi_name = match arch {
            Arch::X86_64 => "grubx64.efi",
            Arch::Aarch64 => "grubaa64.efi",
            Arch::Riscv64 => "grubriscv64.efi",
        };
        let grub_efi = assets_dir.join(grub_efi_name);
        let kernel = assets_dir.join("vmlinuz");
        let initramfs = assets_dir.join("initramfs.cpio");
        let grub_cfg = assets_dir.join("grub.cfg");

        require_boot_assets(
            arch,
            &assets_dir,
            &[
                (grub_efi_name, &grub_efi),
                ("vmlinuz", &kernel),
                ("initramfs.cpio", &initramfs),
                ("grub.cfg", &grub_cfg),
            ],
        )?;

        disk::create_grub_linux_disk(
            disk_path.to_string_lossy().as_ref(),
            grub_efi.to_string_lossy().as_ref(),
            kernel.to_string_lossy().as_ref(),
            initramfs.to_string_lossy().as_ref(),
            grub_cfg.to_string_lossy().as_ref(),
            arch,
        )?;
    } else if app == "uefi-sct-smoke" {
        if arch != Arch::X86_64 {
            bail!("UEFI SCT smoke is currently wired for x86_64 only");
        }

        let assets_dir = sct_assets_dir
            .as_deref()
            .map(resolve_project_path)
            .unwrap_or_else(|| project_root().join("sct-assets").join(arch.dir_name()));
        let shell_efi = assets_dir.join("shellx64.efi");
        let sct_dir = assets_dir.join("SctPackageX64").join("X64");

        for (label, path) in [
            ("shellx64.efi", &shell_efi),
            ("SctPackageX64/X64", &sct_dir),
        ] {
            if !path.exists() {
                bail!(
                    "SCT asset not found: {} (looked in {})\n\
                     Run ci/build-sct-assets.sh --arch x86_64 to build assets, \
                     or pass --sct-assets-dir",
                    label,
                    assets_dir.display(),
                );
            }
        }

        disk::create_uefi_sct_smoke_disk(
            disk_path.to_string_lossy().as_ref(),
            shell_efi.to_string_lossy().as_ref(),
            &sct_dir,
            arch,
            &sequence.text,
        )?;
    } else if app == "windows-boot-smoke" {
        if arch != Arch::X86_64 {
            bail!("Windows boot smoke is currently wired for x86_64 only");
        }

        let default_assets_dir = project_root().join("windows-assets").join(arch.dir_name());
        let source_media_dir = windows_source_media_dir(
            windows_disk.as_deref(),
            windows_media_dir.as_deref(),
            &default_assets_dir,
        );
        let source_disk = windows_disk
            .as_deref()
            .map(resolve_project_path)
            .unwrap_or_else(|| default_assets_dir.join("windows-smoke.img"));

        if let Some(media_dir) = source_media_dir {
            disk::create_windows_media_disk(
                disk_path.to_string_lossy().as_ref(),
                &media_dir,
                arch,
            )?;
        } else if source_disk.exists() {
            println!("Copying Windows smoke disk: {}", source_disk.display());
            fs::copy(&source_disk, &disk_path).with_context(|| {
                format!(
                    "failed to copy Windows smoke disk {} to {}",
                    source_disk.display(),
                    disk_path.display()
                )
            })?;
        } else {
            bail!(
                "Windows smoke assets not found.\n\
                 Provide --windows-media-dir, provide --windows-disk, \
                 or place assets at windows-assets/{}/media or windows-assets/{}/windows-smoke.img",
                arch.dir_name(),
                arch.dir_name(),
            );
        }
    } else {
        // ── Normal UEFI test app ─────────────────────────────────────
        // mm-seal-test boots hello on a payload whose MM never closes the
        // firmware phase: hello must never run.
        let efi_app = match app {
            "mm-seal-test" => "hello",
            // runtime-image-test on a payload that resets in the middle of
            // replaying its journal.
            "runtime-replay-interrupt-test" => "runtime-image-test",
            app => app,
        };
        println!("Building test app: {}", efi_app);
        cmd_build_test_app(efi_app, arch)?;

        let efi_path = find_test_app_efi(efi_app, arch)?;

        if app == "directory-test" {
            disk::create_directory_test_disk(
                disk_path.to_string_lossy().as_ref(),
                &efi_path,
                arch,
            )?;
        } else if app == "boot-policy-test" {
            disk::create_boot_policy_disks(
                &disk_path,
                &qemu::boot_policy::usb_disk_path(&disk_path),
                &efi_path,
                arch,
            )?;
        } else if app == "secure-boot-auth-test" {
            disk::create_secure_boot_auth_disk(
                disk_path.to_string_lossy().as_ref(),
                &efi_path,
                &project_root().join("test-apps/secure-boot-auth-test/fixtures"),
                arch,
            )?;
        } else {
            disk::create_test_disk(disk_path.to_string_lossy().as_ref(), Some(&efi_path), arch)?;
        }
    }

    // Run tests
    if app == "uefi-sct-smoke" {
        qemu::run_uefi_sct_smoke_tests(&config, &disk_path, &sequence, &sct_report_dir)
    } else if app == "windows-boot-smoke" {
        let markers = if windows_success_markers.is_empty() {
            vec!["CRABEFI_WINDOWS_BOOT_SMOKE_SUCCESS".to_string()]
        } else {
            windows_success_markers
        };
        qemu::run_windows_boot_smoke_test(&config, &disk_path, &markers)
    } else {
        qemu::run_tests(&config, &disk_path, app)
    }
}

fn require_boot_assets(arch: Arch, dir: &Path, assets: &[(&str, &Path)]) -> Result<()> {
    for (label, path) in assets {
        if !path.is_file() {
            bail!(
                "Boot asset not found: {label} (looked in {})\n\
                 Run ci/build-boot-assets.sh --arch {} to build them, or pass --boot-assets-dir",
                dir.display(),
                arch.dir_name(),
            );
        }
    }
    Ok(())
}

fn resolve_project_path(path: &Path) -> PathBuf {
    if path.is_relative() {
        project_root().join(path)
    } else {
        path.to_path_buf()
    }
}

fn cmd_build_test_app(name: &str, arch: Arch) -> Result<()> {
    let app_dir = project_root().join("test-apps").join(name);

    if !app_dir.exists() {
        anyhow::bail!(
            "Test app not found: {}\nUse './x list-test-apps' to see available apps",
            app_dir.display()
        );
    }

    println!("Building test app: {} ({:?})", name, arch);

    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("build").arg("--release");

    match arch {
        Arch::X86_64 => {}
        Arch::Aarch64 => {
            cmd.arg("--target").arg("aarch64-unknown-uefi");
        }
        Arch::Riscv64 => {
            // No riscv64gc-unknown-uefi target in Rust — build as ELF, convert later.
            cmd.arg("--target").arg("riscv64gc-unknown-none-elf");
            // Use a linker script that sets ENTRY(efi_main) so the PE entry
            // point survives the ELF-to-PE/COFF objcopy conversion.
            let lds = project_root().join("test-apps/riscv64-uefi.lds");
            cmd.env("RUSTFLAGS", format!("-C link-arg=-T{}", lds.display()));
        }
    }

    cmd.current_dir(&app_dir)
        // Let the test app inherit the workspace rust-toolchain.toml pin.
        .env_remove("RUSTUP_TOOLCHAIN");

    let status = cmd.status()?;

    if !status.success() {
        anyhow::bail!("Build failed");
    }

    // RISC-V: convert ELF to PE/COFF since there is no riscv64gc-unknown-uefi target.
    // Uses riscv64 cross-binutils objcopy (riscv64-unknown-linux-gnu-objcopy or
    // riscv64-linux-gnu-objcopy from binutils-riscv64-linux-gnu on Ubuntu).
    if matches!(arch, Arch::Riscv64) {
        let elf_dir = app_dir.join("target/riscv64gc-unknown-none-elf/release");
        convert_elf_to_pe(&elf_dir)?;
    }

    let efi_path = find_test_app_efi(name, arch)?;
    println!("Built: {}", efi_path);
    Ok(())
}

fn cmd_list_test_apps() -> Result<()> {
    let test_apps_dir = project_root().join("test-apps");

    println!("Available test applications:");
    println!();

    for entry in std::fs::read_dir(&test_apps_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().unwrap().to_string_lossy();
            // Check if it has a Cargo.toml
            if path.join("Cargo.toml").exists() {
                println!("  {}", name);
            }
        }
    }

    println!();
    println!("Build with: ./x build-test-app <name>");
    println!("Run with:   ./x run --app <name>");
    println!("Test with:  ./x test --app <name>");

    Ok(())
}

fn cmd_create_disk(output: &str, efi_app: Option<&str>, arch: Arch) -> Result<()> {
    disk::create_test_disk(output, efi_app, arch)
}

/// Find the .efi file for a test app
/// Convert RISC-V ELF binaries to PE/COFF (.efi) using cross-binutils objcopy.
///
/// Rust has no `riscv64gc-unknown-uefi` target, so test apps are built as ELF
/// and post-processed into PE/COFF.  The objcopy binary is found by searching
/// for common names: `riscv64-unknown-linux-gnu-objcopy` (Nix) and
/// `riscv64-linux-gnu-objcopy` (Ubuntu binutils-riscv64-linux-gnu).
/// Convert all RISC-V ELF binaries in a release directory to PE/COFF (.efi).
///
/// Rust has no `riscv64gc-unknown-uefi` target, so test apps are built as ELF
/// and post-processed into PE/COFF.  The objcopy binary is found by searching
/// for common names: `riscv64-unknown-linux-gnu-objcopy` (Nix) and
/// `riscv64-linux-gnu-objcopy` (Ubuntu binutils-riscv64-linux-gnu).
fn convert_elf_to_pe(elf_dir: &Path) -> Result<()> {
    // Find the riscv64 objcopy
    let objcopy = [
        "riscv64-unknown-linux-gnu-objcopy",
        "riscv64-linux-gnu-objcopy",
    ]
    .iter()
    .find_map(|name| {
        std::process::Command::new("which")
            .arg(name)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|_| name.to_string())
    })
    .ok_or_else(|| {
        anyhow::anyhow!(
            "riscv64 objcopy not found. Install:\n  \
                 NixOS: nix-shell -p pkgsCross.riscv64.buildPackages.binutils\n  \
                 Ubuntu: sudo apt-get install binutils-riscv64-linux-gnu"
        )
    })?;

    // Find ELF executables (no extension, executable, not .d/.efi/directories)
    for entry in std::fs::read_dir(elf_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // Skip files with extensions (.d, .efi, etc.)
        if path.extension().is_some() {
            continue;
        }
        // Skip directories and dep-info
        let name = path.file_name().unwrap().to_string_lossy();
        if name.starts_with('.')
            || name == "build"
            || name == "deps"
            || name == "examples"
            || name == "incremental"
        {
            continue;
        }

        // Check it's actually an ELF
        let mut magic = [0u8; 4];
        if let Ok(mut f) = std::fs::File::open(&path) {
            use std::io::Read;
            if f.read_exact(&mut magic).is_err() || &magic != b"\x7fELF" {
                continue;
            }
        }

        let efi_path = path.with_extension("efi");
        println!(
            "Converting ELF to PE/COFF: {} -> {}",
            path.display(),
            efi_path.display()
        );
        let status = std::process::Command::new(&objcopy)
            .arg("--output-target=pei-riscv64-little")
            .arg("--subsystem=10") // IMAGE_SUBSYSTEM_EFI_APPLICATION
            .arg(&path)
            .arg(&efi_path)
            .status()
            .with_context(|| format!("Failed to run {}", objcopy))?;

        if !status.success() {
            bail!("ELF to PE/COFF conversion failed for {}", path.display());
        }
        println!("Created PE/COFF: {}", efi_path.display());
    }

    Ok(())
}

fn find_test_app_efi(name: &str, arch: Arch) -> Result<String> {
    let app_dir = project_root().join("test-apps").join(name);
    let target_triple = match arch {
        Arch::X86_64 => "x86_64-unknown-uefi",
        Arch::Aarch64 => "aarch64-unknown-uefi",
        // riscv64: ELF built to this target, then converted to .efi
        Arch::Riscv64 => "riscv64gc-unknown-none-elf",
    };
    let target_dir = app_dir.join(format!("target/{}/release", target_triple));

    if !target_dir.exists() {
        anyhow::bail!("Test app not built. Run: ./x build-test-app {}", name);
    }

    // Find .efi files
    for entry in std::fs::read_dir(&target_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "efi") {
            return Ok(path.to_string_lossy().to_string());
        }
    }

    anyhow::bail!("No .efi file found in {}", target_dir.display())
}

#[cfg(test)]
mod entry_tests {
    use super::*;

    #[test]
    fn runtime_replay_requires_an_explicit_run_disk() {
        assert!(Cli::try_parse_from(["crabefi", "run", "--runtime-replay"]).is_err());
        assert!(Cli::try_parse_from(["crabefi", "test", "--runtime-replay"]).is_err());
        for (disk, args, expected) in [
            ("runtime-image-test.img", &[][..], false),
            ("test.img", &["--runtime-replay"][..], true),
        ] {
            let cli = Cli::try_parse_from(
                ["crabefi", "run", "--disk", disk]
                    .into_iter()
                    .chain(args.iter().copied()),
            )
            .unwrap();
            assert!(
                matches!(cli.command, Commands::Run { runtime_replay, .. } if runtime_replay == expected)
            );
        }
    }

    #[test]
    fn entry64_is_opt_in() {
        for (args, want) in [
            (&["crabefi", "build"][..], false),
            (&["crabefi", "build", "--entry64"][..], true),
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            let Commands::Build { entry64, .. } = cli.command else {
                panic!("expected build command");
            };
            assert_eq!(entry64, want);
        }
    }

    #[test]
    fn native_coreboot_commands_do_not_accept_entry64() {
        for command in ["run", "test"] {
            assert!(Cli::try_parse_from(["crabefi", command, "--entry64"]).is_err());
        }
    }

    #[test]
    fn entry64_rejects_other_architectures_before_building() {
        for arch in [Arch::Aarch64, Arch::Riscv64] {
            let err = cmd_build_payload(true, false, arch, Machine::Sbsa, true, &[]).unwrap_err();
            assert!(
                err.to_string()
                    .contains("--entry64 is only supported on x86-64")
            );
        }
    }
}

#[cfg(test)]
mod windows_tests {
    use super::*;

    #[test]
    fn explicit_disk_precedes_default_media_but_not_explicit_media() {
        let assets = tempfile::tempdir().unwrap();
        let media = assets.path().join("media");
        fs::create_dir(&media).unwrap();
        let disk = Path::new("custom.img");
        assert_eq!(
            windows_source_media_dir(None, None, assets.path()),
            Some(media)
        );
        assert_eq!(
            windows_source_media_dir(Some(disk), None, assets.path()),
            None
        );
        let explicit_media = assets.path().join("custom-media");
        assert_eq!(
            windows_source_media_dir(Some(disk), Some(&explicit_media), assets.path()),
            Some(explicit_media)
        );
    }
}
