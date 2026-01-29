//! Logging infrastructure for CrabEFI
//!
//! This module provides logging via the `log` crate, outputting to the
//! serial port, the coreboot CBMEM console, and optionally the framebuffer.
//!
//! Framebuffer logging is disabled by default as it is very slow.
//! Enable with the `fb-log` feature flag.

use crate::arch::x86_64::rdtsc;
use crate::coreboot::cbmem_console;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};
use log::{Level, LevelFilter, Metadata, Record};

/// Initial TSC value at boot (set during init)
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

/// Get relative TSC ticks since boot (in thousands for readability)
pub fn get_timestamp_k() -> u64 {
    let current = rdtsc();
    let boot = BOOT_TSC.load(Ordering::Relaxed);
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

            // Level strings without ANSI colors (for CBMEM console)
            let level_str_plain = match record.level() {
                Level::Error => "ERROR",
                Level::Warn => "WARN ",
                Level::Info => "INFO ",
                Level::Debug => "DEBUG",
                Level::Trace => "TRACE",
            };

            // Get timestamp (k-ticks since boot)
            let ts = get_timestamp_k();

            // Output to serial with timestamp
            crate::serial_println!("[{:>10}] [{}] {}", ts, level_str_serial, record.args());

            // Output to CBMEM console (if available)
            if cbmem_console::is_available() {
                let mut writer = cbmem_console::CbmemConsoleWriter;
                let _ = writeln!(
                    writer,
                    "[{:>10}] [{}] {}",
                    ts,
                    level_str_plain,
                    record.args()
                );
            }

            // Output to framebuffer (if feature enabled)
            #[cfg(feature = "fb-log")]
            crate::fb_log::log_to_framebuffer(record.level(), ts, record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: CombinedLogger = CombinedLogger;

/// Initialize the logging subsystem
pub fn init() {
    // Record the boot TSC for relative timestamps
    BOOT_TSC.store(rdtsc(), Ordering::Relaxed);

    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Debug))
        .expect("Failed to set logger");
}

/// Set the framebuffer for logging output
///
/// Call this after parsing coreboot tables to enable framebuffer logging.
/// Clears the screen to remove any stale content from bootloader.
///
/// This function is only effective with the `fb-log` feature.
#[cfg(feature = "fb-log")]
pub fn set_framebuffer(fb: crate::coreboot::FramebufferInfo) {
    crate::fb_log::set_framebuffer(fb);
}

/// Stub for when fb-log feature is disabled
#[cfg(not(feature = "fb-log"))]
pub fn set_framebuffer(_fb: crate::coreboot::FramebufferInfo) {
    // Framebuffer logging disabled at compile time
}

/// Set the maximum log level
pub fn set_level(level: LevelFilter) {
    log::set_max_level(level);
}
