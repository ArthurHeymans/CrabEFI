//! Logging infrastructure for CrabEFI
//!
//! This module provides logging via the `log` crate, outputting to the
//! serial port and optionally the framebuffer.
//!
//! Framebuffer logging is disabled by default as it is very slow.
//! Enable with the `fb-log` feature flag.

use crate::time::read_counter;
use log::{Level, LevelFilter, Metadata, Record};

/// Get relative counter ticks since boot (in thousands for readability)
///
/// Uses raw-pointer read (see *Log-Path Contract* in [`crate::state`]) to
/// avoid creating a `&DriverState` reference that would alias with a live
/// `&mut` from `with_*_mut()` closures.
pub fn get_timestamp_k() -> u64 {
    let current = read_counter();
    // SAFETY: single-threaded firmware; field is written once at init,
    // only read afterwards.  Raw pointer avoids aliasing with &mut held
    // by with_*_mut() closures that may log.
    let boot = unsafe { (*crate::state::drivers_mut_ptr()).timing.boot_counter };
    // Return delta in thousands (k-ticks) to keep numbers manageable
    current.saturating_sub(boot) / 1000
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

            // Get timestamp (k-ticks since boot)
            let ts = get_timestamp_k();

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
        log::set_max_level(LevelFilter::Debug);
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
