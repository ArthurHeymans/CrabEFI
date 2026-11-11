//! CrabEFI log-level choices shared by the firmware logger and settings UI.
pub use log::LevelFilter;

/// Default log level when no persistent CrabEFI log-level variable exists.
/// Debug lines are slow on a 115200 baud console (about 6.5 ms each); the
/// `default-log-level-error` feature starts at Error instead.
pub const DEFAULT_LEVEL: LevelFilter = if cfg!(feature = "default-log-level-error") {
    LevelFilter::Error
} else {
    LevelFilter::Debug
};

/// Log levels shown in the CrabEFI settings menu.
pub const LEVEL_CHOICES: [LevelFilter; 6] = [
    LevelFilter::Off,
    LevelFilter::Error,
    LevelFilter::Warn,
    LevelFilter::Info,
    LevelFilter::Debug,
    LevelFilter::Trace,
];

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
    LEVEL_CHOICES
        .iter()
        .position(|choice| *choice == level)
        .unwrap_or(4)
}
