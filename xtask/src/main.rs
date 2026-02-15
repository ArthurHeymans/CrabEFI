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

#[derive(Parser)]
#[command(name = "crabefi", bin_name = "crabefi")]
#[command(about = "CrabEFI build and test automation")]
struct Cli {
    /// Path to the CrabEFI project directory (set automatically by ./crabefi wrapper)
    #[arg(long, global = true, hide = true)]
    project_dir: Option<PathBuf>,

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
    },

    /// Run integration tests in QEMU
    Test {
        /// Path to coreboot ROM
        #[arg(long)]
        coreboot_rom: Option<String>,

        /// Test app to run (default: hello)
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

    match cli.command {
        Commands::Build { release } => cmd_build(release),
        Commands::Run {
            coreboot_rom,
            ahci,
            nvme,
            sdhci,
            headless,
            disable_kvm,
            app,
            disk,
        } => cmd_run(
            coreboot_rom,
            ahci,
            nvme,
            sdhci,
            headless,
            disable_kvm,
            app,
            disk,
        ),
        Commands::Test {
            coreboot_rom,
            app,
            ahci,
            nvme,
            sdhci,
            disable_kvm,
            timeout,
        } => cmd_test(coreboot_rom, &app, ahci, nvme, sdhci, disable_kvm, timeout),
        Commands::BuildTestApp { name } => cmd_build_test_app(&name),
        Commands::ListTestApps => cmd_list_test_apps(),
        Commands::CreateDisk { output, efi_app } => cmd_create_disk(&output, efi_app.as_deref()),
    }
}

fn cmd_build(release: bool) -> Result<()> {
    println!("Building CrabEFI...");

    let project_root = project_root();

    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("build");
    if release {
        cmd.arg("--release");
    }
    cmd.current_dir(project_root);
    // Remove RUSTUP_TOOLCHAIN to let CrabEFI use its own rust-toolchain.toml
    cmd.env_remove("RUSTUP_TOOLCHAIN");

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Build failed");
    }

    let mode = if release { "release" } else { "debug" };
    println!("Built: target/x86_64-unknown-none/{}/crabefi", mode);
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
    let rom_path = if let Some(rom) = coreboot_rom {
        rom
    } else {
        // Build CrabEFI first
        cmd_build(true)?;

        // Prepare ROM with CrabEFI payload
        let crabefi_elf = rom::get_crabefi_elf();
        let prepared_rom = rom::prepare_rom(&crabefi_elf, temp_dir.path())?;
        prepared_rom.to_string_lossy().to_string()
    };

    let config = qemu::QemuConfig {
        coreboot_rom: rom_path,
        storage,
        headless,
        disable_kvm,
        timeout_secs: None,
    };

    // If a disk is specified, use it directly
    if let Some(disk_path) = disk {
        return qemu::run_qemu(&config, Some(Path::new(&disk_path)));
    }

    // If an app is specified, build it and create a disk with it
    if let Some(app_name) = app {
        // Build the app
        println!("Building test app: {}", app_name);
        cmd_build_test_app(&app_name)?;

        // Find the EFI file
        let efi_path = find_test_app_efi(&app_name)?;

        // Create a temporary disk with this app
        let disk_path = temp_dir.path().join("test.img");
        disk::create_test_disk(disk_path.to_string_lossy().as_ref(), Some(&efi_path))?;

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
    let rom_path = if let Some(rom) = coreboot_rom {
        rom
    } else {
        // Build CrabEFI first
        cmd_build(true)?;

        // Prepare ROM with CrabEFI payload
        let crabefi_elf = rom::get_crabefi_elf();
        let prepared_rom = rom::prepare_rom(&crabefi_elf, temp_dir.path())?;
        prepared_rom.to_string_lossy().to_string()
    };

    let config = qemu::QemuConfig {
        coreboot_rom: rom_path,
        storage,
        headless: true,
        disable_kvm,
        timeout_secs: Some(timeout),
    };

    // Build the test app
    println!("Building test app: {}", app);
    cmd_build_test_app(app)?;

    // Find the EFI file
    let efi_path = find_test_app_efi(app)?;

    // Create test disk (directory-test needs LFN files on disk)
    let disk_path = temp_dir.path().join("test.img");
    if app == "directory-test" {
        disk::create_directory_test_disk(disk_path.to_string_lossy().as_ref(), &efi_path)?;
    } else {
        disk::create_test_disk(disk_path.to_string_lossy().as_ref(), Some(&efi_path))?;
    }

    // Run tests
    qemu::run_tests(&config, &disk_path, app)
}

fn cmd_build_test_app(name: &str) -> Result<()> {
    let app_dir = project_root().join("test-apps").join(name);

    if !app_dir.exists() {
        anyhow::bail!(
            "Test app not found: {}\nUse './x list-test-apps' to see available apps",
            app_dir.display()
        );
    }

    println!("Building test app: {}", name);

    let status = std::process::Command::new("cargo")
        .arg("build")
        .arg("--release")
        .current_dir(&app_dir)
        // Remove RUSTUP_TOOLCHAIN to let the test app use its own rust-toolchain.toml
        .env_remove("RUSTUP_TOOLCHAIN")
        .status()?;

    if !status.success() {
        anyhow::bail!("Build failed");
    }

    let efi_path = find_test_app_efi(name)?;
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

fn cmd_create_disk(output: &str, efi_app: Option<&str>) -> Result<()> {
    disk::create_test_disk(output, efi_app)
}

/// Find the .efi file for a test app
fn find_test_app_efi(name: &str) -> Result<String> {
    let app_dir = project_root().join("test-apps").join(name);
    let target_dir = app_dir.join("target/x86_64-unknown-uefi/release");

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
