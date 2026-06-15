//! Logging infrastructure for CrabEFI
//!
//! This module provides logging via the `log` crate, outputting to the
//! serial port and optionally the framebuffer.
//!
//! Log lines are prefixed with microseconds since boot. Before timer
//! calibration, the platform's initial frequency estimate is used.
//!
//! Framebuffer logging is disabled by default as it is very slow.
//! Enable with the `fb-log` feature flag.

use crate::time::read_counter;
use log::{Level, LevelFilter, Metadata, Record};
use r_efi::efi::Guid;

/// Default log level when no persistent CrabEFI log-level variable exists.
pub const DEFAULT_LEVEL: LevelFilter = LevelFilter::Debug;

/// Log levels shown in the CrabEFI settings menu.
pub const LEVEL_CHOICES: [LevelFilter; 6] = [
    LevelFilter::Off,
    LevelFilter::Error,
    LevelFilter::Warn,
    LevelFilter::Info,
    LevelFilter::Debug,
    LevelFilter::Trace,
];

/// CrabEFI settings variable GUID.
///
/// {9e80634c-cdc7-41d5-a345-4a297f9c7d1a}
pub const CRABEFI_SETTINGS_GUID: Guid = Guid::from_fields(
    0x9e80634c,
    0xcdc7,
    0x41d5,
    0xa3,
    0x45,
    &[0x4a, 0x29, 0x7f, 0x9c, 0x7d, 0x1a],
);

/// UEFI variable name used to persist CrabEFI's maximum log level.
pub const LOG_LEVEL_VARIABLE_NAME: &[u16] = &[
    b'C' as u16,
    b'r' as u16,
    b'a' as u16,
    b'b' as u16,
    b'E' as u16,
    b'F' as u16,
    b'I' as u16,
    b'L' as u16,
    b'o' as u16,
    b'g' as u16,
    b'L' as u16,
    b'e' as u16,
    b'v' as u16,
    b'e' as u16,
    b'l' as u16,
    0,
];

const LOG_LEVEL_VARIABLE_ATTRS: u32 = crate::efi::auth::attributes::NON_VOLATILE
    | crate::efi::auth::attributes::BOOTSERVICE_ACCESS
    | crate::efi::auth::attributes::RUNTIME_ACCESS;

/// Get microseconds elapsed since boot.
///
/// Uses raw-pointer read (see *Log-Path Contract* in [`crate::state`]) to
/// avoid creating a `&DriverState` reference that would alias with a live
/// `&mut` from `with_*_mut()` closures.
pub fn get_us_since_boot() -> u64 {
    let current = read_counter();
    // SAFETY: single-threaded firmware; field is written once at init,
    // only read afterwards. Raw pointer avoids aliasing with &mut held
    // by with_*_mut() closures that may log.
    let boot = unsafe { (*crate::state::drivers_mut_ptr()).timing.boot_counter };
    let delta = current.saturating_sub(boot);
    let freq = crate::time::counter_frequency().max(1);
    ((delta as u128 * 1_000_000) / freq as u128) as u64
}

/// Combined serial + framebuffer logger
struct CombinedLogger;

impl log::Log for CombinedLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            // Level strings for serial (with ANSI colors)
            let level_str_serial = match record.level() {
                Level::Error => "\x1b[31mERROR\x1b[0m",
                Level::Warn => "\x1b[33mWARN\x1b[0m ",
                Level::Info => "\x1b[32mINFO\x1b[0m ",
                Level::Debug => "\x1b[34mDEBUG\x1b[0m",
                Level::Trace => "\x1b[35mTRACE\x1b[0m",
            };

            // Get timestamp (microseconds since boot)
            let ts = get_us_since_boot();

            // Output to serial with timestamp
            crate::serial_println!("[{:>10}] [{}] {}", ts, level_str_serial, record.args());

            // Output to framebuffer (if feature enabled)
            #[cfg(feature = "fb-log")]
            crate::fb_log::log_to_framebuffer(record.level(), ts, record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: CombinedLogger = CombinedLogger;

/// Initialize the logging subsystem.
///
/// Safe to call multiple times — the second call is a no-op. This allows
/// the coreboot payload to initialize logging early (for debug output
/// during coreboot table parsing) and then call [`crate::init_platform()`]
/// which calls `init()` again internally.
pub fn init() {
    // Only set the boot counter and register the logger on the first call.
    // log::set_logger() returns Err if a logger is already registered.
    if log::set_logger(&LOGGER).is_ok() {
        // Record the boot counter for relative timestamps.
        // SAFETY: single-threaded init; raw pointer avoids re-entrancy
        // issues with the state lock.
        unsafe {
            (*crate::state::drivers_mut_ptr()).timing.boot_counter = read_counter();
        }
        log::set_max_level(DEFAULT_LEVEL);
    }
}

/// Set the framebuffer for logging output
///
/// Call this after parsing coreboot tables to enable framebuffer logging.
/// Clears the screen to remove any stale content from bootloader.
///
/// This function is only effective with the `fb-log` feature.
#[cfg(feature = "fb-log")]
pub fn set_framebuffer(fb: crate::platform::FramebufferConfig) {
    crate::fb_log::set_framebuffer(fb);
}

/// Stub for when fb-log feature is disabled
#[cfg(not(feature = "fb-log"))]
pub fn set_framebuffer(_fb: crate::platform::FramebufferConfig) {
    // Framebuffer logging disabled at compile time
}

/// Set the maximum log level
pub fn set_level(level: LevelFilter) {
    log::set_max_level(level);
}

/// Return the display name for a log level.
pub fn level_name(level: LevelFilter) -> &'static str {
    match level {
        LevelFilter::Off => "Off",
        LevelFilter::Error => "Error",
        LevelFilter::Warn => "Warn",
        LevelFilter::Info => "Info",
        LevelFilter::Debug => "Debug",
        LevelFilter::Trace => "Trace",
    }
}

/// Return the menu index for a log level.
pub fn level_index(level: LevelFilter) -> usize {
    LEVEL_CHOICES.iter().position(|&l| l == level).unwrap_or(4)
}

/// Parse a persisted log-level variable payload.
pub fn level_from_data(data: &[u8]) -> Option<LevelFilter> {
    match data.first().copied() {
        Some(0) => Some(LevelFilter::Off),
        Some(1) => Some(LevelFilter::Error),
        Some(2) => Some(LevelFilter::Warn),
        Some(3) => Some(LevelFilter::Info),
        Some(4) => Some(LevelFilter::Debug),
        Some(5) => Some(LevelFilter::Trace),
        _ => None,
    }
}

fn level_to_data(level: LevelFilter) -> [u8; 1] {
    [match level {
        LevelFilter::Off => 0,
        LevelFilter::Error => 1,
        LevelFilter::Warn => 2,
        LevelFilter::Info => 3,
        LevelFilter::Debug => 4,
        LevelFilter::Trace => 5,
    }]
}

/// Check whether a variable name/GUID pair is the CrabEFI log-level variable.
pub fn is_log_level_variable(guid: &Guid, name: &[u16]) -> bool {
    *guid == CRABEFI_SETTINGS_GUID && crate::efi::utils::ucs2_eq(name, LOG_LEVEL_VARIABLE_NAME)
}

/// Read the configured log level from the in-memory EFI variable cache.
pub fn configured_level() -> LevelFilter {
    read_persisted_level().unwrap_or_else(log::max_level)
}

/// Apply the persisted log level from the in-memory EFI variable cache.
pub fn apply_persisted_level() {
    if let Some(level) = read_persisted_level() {
        set_level(level);
        log::info!("CrabEFI log level set to {}", level_name(level));
    }
}

/// Apply the persisted log level from an EDK2-compatible variable-store region.
///
/// This is a read-only, allocation-free early-boot helper. Platforms that can
/// already see an EDK2 variable store as a byte slice may use it before the
/// full variable backend is initialized. Platform-specific discovery remains in
/// the platform crate; this helper only understands the generic EDK2 variable
/// store format.
pub fn apply_from_edk2_varstore_region(region: &[u8]) -> bool {
    let mut data = [0u8; 1];
    let Some(data_len) = crate::efi::varstore::edk2::read_variable_data_from_region(
        region,
        CRABEFI_SETTINGS_GUID.as_bytes(),
        LOG_LEVEL_VARIABLE_NAME,
        &mut data,
    ) else {
        return false;
    };

    if let Some(level) = level_from_data(&data[..data_len]) {
        set_level(level);
        true
    } else {
        false
    }
}

/// Apply a just-written log-level variable payload.
pub fn apply_variable_write(data: &[u8]) {
    if crate::state::is_exit_boot_services_called() {
        return;
    }

    if let Some(level) = level_from_data(data) {
        set_level(level);
    }
}

/// Apply deletion of the log-level variable by reverting to the default level.
pub fn apply_variable_delete() {
    if crate::state::is_exit_boot_services_called() {
        return;
    }

    set_level(DEFAULT_LEVEL);
}

/// Persist and apply a new CrabEFI log level.
pub fn set_configured_level(level: LevelFilter) -> Result<(), crate::efi::varstore::VarStoreError> {
    let data = level_to_data(level);

    crate::efi::varstore::persist_variable(
        &CRABEFI_SETTINGS_GUID,
        LOG_LEVEL_VARIABLE_NAME,
        LOG_LEVEL_VARIABLE_ATTRS,
        &data,
    )?;

    crate::efi::varstore::update_variable_in_memory(
        &CRABEFI_SETTINGS_GUID,
        LOG_LEVEL_VARIABLE_NAME,
        LOG_LEVEL_VARIABLE_ATTRS,
        &data,
    );
    set_level(level);

    Ok(())
}

fn read_persisted_level() -> Option<LevelFilter> {
    crate::state::efi()
        .variables
        .iter()
        .find(|var| var.in_use && is_log_level_variable(&var.vendor_guid, &var.name))
        .and_then(|var| level_from_data(&var.data[..var.data_size]))
}
