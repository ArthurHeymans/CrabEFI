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

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Global project directory, set via --project-dir or derived from CARGO_MANIFEST_DIR
static PROJECT_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Get the project root directory
fn project_root() -> &'static Path {
    PROJECT_DIR.get().expect("PROJECT_DIR not initialized")
}

/// Target architecture for CrabEFI
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Arch {
    X86_64,
    Aarch64,
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

        /// Directory containing pre-built boot assets (vmlinuz, grubx64.efi, grub.cfg).
        /// Required when --app grub-linux is used.
        #[arg(long)]
        boot_assets_dir: Option<PathBuf>,
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
        Commands::Build { release, ui } => cmd_build(release, ui, arch, machine),
        Commands::Run {
            coreboot_rom,
            ahci,
            nvme,
            sdhci,
            headless,
            disable_kvm,
            app,
            disk,
            ui,
        } => cmd_run(
            coreboot_rom,
            ahci,
            nvme,
            sdhci,
            headless,
            disable_kvm,
            app,
            disk,
            ui,
            arch,
            machine,
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
        ),
        Commands::BuildTestApp { name } => cmd_build_test_app(&name, arch),
        Commands::ListTestApps => cmd_list_test_apps(),
        Commands::CreateDisk { output, efi_app } => {
            cmd_create_disk(&output, efi_app.as_deref(), arch)
        }
    }
}

fn cmd_build(release: bool, ui: bool, arch: Arch, machine: Machine) -> Result<()> {
    let label = match (arch, machine) {
        (Arch::X86_64, _) => "x86_64".to_string(),
        (Arch::Aarch64, Machine::Sbsa) => "aarch64/sbsa".to_string(),
        (Arch::Aarch64, Machine::Virt) => "aarch64/virt".to_string(),
    };
    println!("Building CrabEFI ({})...", label);

    let project_root = project_root();

    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("build");
    // Build the coreboot payload binary (the binary target lives in the
    // crabefi-coreboot workspace member, not in the root library crate).
    cmd.arg("-p").arg("crabefi-coreboot");
    if release {
        cmd.arg("--release");
    }
    if ui {
        cmd.arg("--features").arg("ui");
    }

    let target_triple = match arch {
        Arch::X86_64 => "x86_64-unknown-none",
        Arch::Aarch64 => "aarch64-unknown-none",
    };
    cmd.arg("--target").arg(target_triple);

    // aarch64-specific: set PAYLOAD_BASE for the linker script.
    // SBSA: DRAM at 1TB, payload above ramstage.
    // Virt: DRAM at 1GB, payload above ramstage.
    if matches!(arch, Arch::Aarch64) {
        let payload_base = match machine {
            Machine::Sbsa => "0x10022000000",
            Machine::Virt => "0x62000000",
        };
        cmd.env("PAYLOAD_BASE", payload_base);
    }

    cmd.current_dir(project_root);
    // Remove RUSTUP_TOOLCHAIN to let CrabEFI use its own rust-toolchain.toml
    cmd.env_remove("RUSTUP_TOOLCHAIN");

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Build failed");
    }

    let mode = if release { "release" } else { "debug" };
    println!("Built: target/{}/{}/crabefi", target_triple, mode);
    Ok(())
}

fn cmd_run(
    coreboot_rom: Option<String>,
    ahci: bool,
    nvme: bool,
    sdhci: bool,
    headless: bool,
    disable_kvm: bool,
    app: Option<String>,
    disk: Option<String>,
    ui: bool,
    arch: Arch,
    machine: Machine,
) -> Result<()> {
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
        cmd_build(true, ui, arch, machine)?;

        // Prepare ROM with CrabEFI payload
        let crabefi_elf = rom::get_crabefi_elf(arch);
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
        return qemu::run_qemu(&config, Some(Path::new(&disk_path)));
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

        return qemu::run_qemu(&config, Some(&disk_path));
    }

    // Otherwise just run with a minimal disk
    qemu::run_qemu(&config, None)
}

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
) -> Result<()> {
    let storage = if ahci {
        qemu::StorageType::Ahci
    } else if nvme {
        qemu::StorageType::Nvme
    } else if sdhci {
        qemu::StorageType::Sdhci
    } else {
        qemu::StorageType::Usb
    };

    // Create temp dir for ROM and disk
    let temp_dir = tempfile::tempdir()?;

    // Prepare the ROM
    let firmware = if let Some(rom) = coreboot_rom {
        rom::PreparedFirmware {
            coreboot_rom: PathBuf::from(rom),
            tfa_flash: None,
        }
    } else {
        // Build CrabEFI first
        cmd_build(true, ui, arch, machine)?;

        // Prepare ROM with CrabEFI payload
        let crabefi_elf = rom::get_crabefi_elf(arch);
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
    };

    let disk_path = temp_dir.path().join("test.img");

    if app == "grub-linux" {
        // ── GRUB + Linux boot-chain test ─────────────────────────────
        // Instead of building a UEFI test app, we create a disk with
        // GRUB as the boot application and a Linux kernel.
        let assets_dir = boot_assets_dir
            .as_deref()
            .map(|p| {
                if p.is_relative() {
                    // Resolve relative paths against the project root,
                    // since the crabefi wrapper cd's into xtask/ before
                    // running us.
                    project_root().join(p)
                } else {
                    p.to_path_buf()
                }
            })
            .unwrap_or_else(|| project_root().join("boot-assets"));

        let grub_efi = assets_dir.join("grubx64.efi");
        let kernel = assets_dir.join("vmlinuz");
        let grub_cfg = assets_dir.join("grub.cfg");

        for (label, path) in [
            ("grubx64.efi", &grub_efi),
            ("vmlinuz", &kernel),
            ("grub.cfg", &grub_cfg),
        ] {
            if !path.exists() {
                anyhow::bail!(
                    "Boot asset not found: {} (looked in {})\n\
                     Run ci/build-boot-assets.sh to build them, \
                     or pass --boot-assets-dir",
                    label,
                    assets_dir.display()
                );
            }
        }

        disk::create_grub_linux_disk(
            disk_path.to_string_lossy().as_ref(),
            grub_efi.to_string_lossy().as_ref(),
            kernel.to_string_lossy().as_ref(),
            grub_cfg.to_string_lossy().as_ref(),
            arch,
        )?;
    } else {
        // ── Normal UEFI test app ─────────────────────────────────────
        println!("Building test app: {}", app);
        cmd_build_test_app(app, arch)?;

        let efi_path = find_test_app_efi(app, arch)?;

        if app == "directory-test" {
            disk::create_directory_test_disk(
                disk_path.to_string_lossy().as_ref(),
                &efi_path,
                arch,
            )?;
        } else {
            disk::create_test_disk(disk_path.to_string_lossy().as_ref(), Some(&efi_path), arch)?;
        }
    }

    // Run tests
    qemu::run_tests(&config, &disk_path, app)
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
    }

    cmd.current_dir(&app_dir)
        // Remove RUSTUP_TOOLCHAIN to let the test app use its own rust-toolchain.toml
        .env_remove("RUSTUP_TOOLCHAIN");

    let status = cmd.status()?;

    if !status.success() {
        anyhow::bail!("Build failed");
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
fn find_test_app_efi(name: &str, arch: Arch) -> Result<String> {
    let app_dir = project_root().join("test-apps").join(name);
    let target_triple = match arch {
        Arch::X86_64 => "x86_64-unknown-uefi",
        Arch::Aarch64 => "aarch64-unknown-uefi",
    };
    let target_dir = app_dir.join(format!("target/{}/release", target_triple));

    if !target_dir.exists() {
        anyhow::bail!("Test app not built. Run: ./x build-test-app {}", name);
    }

    // Find .efi files
    for entry in std::fs::read_dir(&target_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "efi") {
            return Ok(path.to_string_lossy().to_string());
        }
    }

    anyhow::bail!("No .efi file found in {}", target_dir.display())
}
