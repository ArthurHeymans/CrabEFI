//! Logging infrastructure for CrabEFI
//!
//! This module provides logging via the `log` crate, outputting to the serial port.

use log::{Level, LevelFilter, Metadata, Record};

/// Serial logger implementation
struct SerialLogger;

impl log::Log for SerialLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level_str = match record.level() {
                Level::Error => "\x1b[31mERROR\x1b[0m",
                Level::Warn => "\x1b[33mWARN\x1b[0m ",
                Level::Info => "\x1b[32mINFO\x1b[0m ",
                Level::Debug => "\x1b[34mDEBUG\x1b[0m",
                Level::Trace => "\x1b[35mTRACE\x1b[0m",
            };

            // Format: [LEVEL] target: message
            crate::serial_println!("[{}] {}: {}", level_str, record.target(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: SerialLogger = SerialLogger;

/// Initialize the logging subsystem
pub fn init() {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Debug))
        .expect("Failed to set logger");
}

/// Set the maximum log level
pub fn set_level(level: LevelFilter) {
    log::set_max_level(level);
}
