//! Minimal GRUB Configuration Parser
//!
//! This module provides a minimal parser for GRUB configuration files,
//! extracting boot entries without full GRUB scripting support.
//!
//! # Supported Directives
//!
//! - `menuentry "title" { ... }` - Boot entry definition
//! - `linux` / `linuxefi` - Kernel path and options
//! - `initrd` / `initrdefi` - Initrd path
//! - `blscfg` - Load BLS entries (triggers BLS discovery)
//!
//! # Unsupported Features
//!
//! - Variable substitution (`$root`, `${prefix}`, etc.)
//! - Conditional statements (`if`, `else`, etc.)
//! - Functions and sourcing
//! - Submenus

use crate::fs::fat::FatFilesystem;
use heapless::{String, Vec};

/// Maximum number of GRUB entries we can parse
const MAX_GRUB_ENTRIES: usize = 16;

/// Maximum size of grub.cfg we'll read
const MAX_CONFIG_SIZE: usize = 32768;

/// Common non-EFI paths to check for grub.cfg
const GRUB_TOPLEVEL_PATHS: &[&str] = &[
    "boot\\grub\\grub.cfg",
    "grub\\grub.cfg",
    "grub2\\grub.cfg",
    "boot\\grub2\\grub.cfg",
];

/// A parsed GRUB menu entry
#[derive(Debug, Clone)]
pub struct GrubEntry {
    /// Menu title
    pub title: String<64>,
    /// Path to Linux kernel
    pub linux: String<128>,
    /// Path to initrd
    pub initrd: String<128>,
    /// Kernel command line options
    pub options: String<512>,
    /// Entry class (for styling, ignored)
    pub class: String<32>,
}

impl Default for GrubEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl GrubEntry {
    /// Create a new empty GRUB entry
    pub const fn new() -> Self {
        Self {
            title: String::new(),
            linux: String::new(),
            initrd: String::new(),
            options: String::new(),
            class: String::new(),
        }
    }

    /// Check if this entry is valid (has required fields)
    pub fn is_valid(&self) -> bool {
        !self.title.is_empty() && !self.linux.is_empty()
    }
}

/// Result of GRUB config parsing
#[derive(Debug)]
pub struct GrubConfig {
    /// Parsed menu entries
    pub entries: Vec<GrubEntry, MAX_GRUB_ENTRIES>,
    /// Default entry index
    pub default_entry: usize,
    /// Timeout in seconds
    pub timeout: Option<u32>,
    /// Whether blscfg directive was found
    pub has_blscfg: bool,
}

impl Default for GrubConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl GrubConfig {
    /// Create a new empty GRUB config
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            default_entry: 0,
            timeout: None,
            has_blscfg: false,
        }
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Error during GRUB config parsing
#[derive(Debug)]
pub enum GrubError {
    /// Config file not found
    ConfigNotFound,
    /// Failed to read file
    ReadError,
    /// Parse error
    ParseError,
    /// No valid entries found
    NoEntries,
}

/// Parse GRUB configuration from a FAT filesystem
///
/// Searches common paths for grub.cfg and parses the first one found.
/// For EFI subdirectories, dynamically lists `EFI\*` and checks each
/// for grub.cfg rather than probing hardcoded distro names.
///
/// # Arguments
///
/// * `fs` - FAT filesystem to search
pub fn parse_config(fs: &mut FatFilesystem<'_>) -> Result<GrubConfig, GrubError> {
    // Try common top-level paths first
    for path in GRUB_TOPLEVEL_PATHS {
        if let Ok(size) = fs.file_size(path)
            && size > 0
            && size <= MAX_CONFIG_SIZE as u32
        {
            log::debug!("Found grub.cfg at {}", path);
            return parse_config_file(fs, path);
        }
    }

    // Dynamically scan EFI subdirectories for grub.cfg
    // This avoids probing hardcoded distro names one-by-one
    if let Ok(subdirs) = fs.list_subdirectories("EFI") {
        for subdir in subdirs.iter() {
            // Skip BOOT directory (that's for the UEFI bootloader, not GRUB config)
            if subdir.as_str().eq_ignore_ascii_case("BOOT") {
                continue;
            }
            let mut path = heapless::String::<128>::new();
            if core::fmt::write(&mut path, format_args!("EFI\\{}\\grub.cfg", subdir)).is_err() {
                continue;
            }
            if let Ok(size) = fs.file_size(&path)
                && size > 0
                && size <= MAX_CONFIG_SIZE as u32
            {
                log::debug!("Found grub.cfg at {}", path);
                return parse_config_file(fs, &path);
            }
        }
    }

    Err(GrubError::ConfigNotFound)
}

/// Parse a specific grub.cfg file
fn parse_config_file(fs: &mut FatFilesystem<'_>, path: &str) -> Result<GrubConfig, GrubError> {
    // Read the config file
    let mut buf = [0u8; MAX_CONFIG_SIZE];
    let bytes_read = fs
        .read_file_all(path, &mut buf)
        .map_err(|_| GrubError::ReadError)?;

    // Parse as UTF-8
    let content = core::str::from_utf8(&buf[..bytes_read]).map_err(|_| GrubError::ParseError)?;

    // Parse the content
    parse_grub_content(content)
}

/// Parse GRUB configuration content
fn parse_grub_content(content: &str) -> Result<GrubConfig, GrubError> {
    let mut config = GrubConfig::new();
    let mut current_entry: Option<GrubEntry> = None;
    let mut in_menuentry = false;
    let mut brace_depth = 0;

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Track brace depth
        let open_braces = line.matches('{').count();
        let close_braces = line.matches('}').count();

        // Check for blscfg directive
        if line == "blscfg" || line.starts_with("blscfg ") {
            config.has_blscfg = true;
            log::debug!("Found blscfg directive");
            continue;
        }

        // Parse timeout
        if line.starts_with("set timeout=") || line.starts_with("timeout=") {
            if let Some(value) = line.split('=').nth(1) {
                let value = value.trim().trim_matches('"');
                if let Ok(secs) = value.parse::<u32>() {
                    config.timeout = Some(secs);
                }
            }
            continue;
        }

        // Parse default entry
        if line.starts_with("set default=") || line.starts_with("default=") {
            if let Some(value) = line.split('=').nth(1) {
                let value = value.trim().trim_matches('"');
                if let Ok(idx) = value.parse::<usize>() {
                    config.default_entry = idx;
                }
            }
            continue;
        }

        // Parse menuentry start
        if line.starts_with("menuentry ")
            && let Some(title) = parse_menuentry_title(line)
        {
            let mut entry = GrubEntry::new();
            let _ = entry.title.push_str(title);

            // Extract class if present
            if let Some(class) = parse_menuentry_class(line) {
                let _ = entry.class.push_str(class);
            }

            current_entry = Some(entry);
            in_menuentry = true;
        }

        // Update brace depth
        brace_depth += open_braces;
        brace_depth = brace_depth.saturating_sub(close_braces);

        // Check for menuentry end
        if in_menuentry && brace_depth == 0 && close_braces > 0 {
            if let Some(entry) = current_entry.take()
                && entry.is_valid()
            {
                log::debug!("Parsed GRUB entry: {}", entry.title);
                let _ = config.entries.push(entry);
            }
            in_menuentry = false;
        }

        // Parse content inside menuentry
        if in_menuentry && let Some(ref mut entry) = current_entry {
            parse_menuentry_line(line, entry);
        }
    }

    if config.is_empty() && !config.has_blscfg {
        Err(GrubError::NoEntries)
    } else {
        log::info!("Parsed {} GRUB entries", config.len());
        Ok(config)
    }
}

/// Parse the title from a menuentry line
///
/// Handles formats like:
/// - `menuentry "Title" {`
/// - `menuentry 'Title' {`
/// - `menuentry "Title" --class linux {`
fn parse_menuentry_title(line: &str) -> Option<&str> {
    // Find the start of the title (after menuentry)
    let after_menuentry = line.strip_prefix("menuentry")?;
    let trimmed = after_menuentry.trim_start();

    // Find quoted string
    let (quote_char, start) = if trimmed.starts_with('"') {
        ('"', 1)
    } else if trimmed.starts_with('\'') {
        ('\'', 1)
    } else {
        return None;
    };

    // Find the closing quote
    let rest = &trimmed[start..];
    let end = rest.find(quote_char)?;

    Some(&rest[..end])
}

/// Parse the class from a menuentry line
fn parse_menuentry_class(line: &str) -> Option<&str> {
    // Look for --class argument
    let class_start = line.find("--class ")?;
    let after_class = &line[class_start + 8..];

    // Class ends at space or brace
    let end = after_class
        .find(|c: char| c.is_whitespace() || c == '{' || c == '-')
        .unwrap_or(after_class.len());

    Some(&after_class[..end])
}

/// Parse a line inside a menuentry block
fn parse_menuentry_line(line: &str, entry: &mut GrubEntry) {
    // Parse linux/linuxefi directive
    if line.starts_with("linux ") || line.starts_with("linuxefi ") {
        let rest = if let Some(stripped) = line.strip_prefix("linux ") {
            stripped
        } else {
            &line[9..]
        };

        let parts: Vec<&str, 2> = rest.splitn(2, char::is_whitespace).collect();
        if let Some(path) = parts.first() {
            entry.linux.clear();
            let normalized = normalize_grub_path(path);
            let _ = entry.linux.push_str(&normalized);
        }
        if let Some(opts) = parts.get(1) {
            entry.options.clear();
            let _ = entry.options.push_str(opts.trim());
        }
    }
    // Parse initrd/initrdefi directive
    else if line.starts_with("initrd ") || line.starts_with("initrdefi ") {
        let rest = if let Some(stripped) = line.strip_prefix("initrd ") {
            stripped
        } else {
            &line[10..]
        };

        entry.initrd.clear();
        let normalized = normalize_grub_path(rest.trim());
        let _ = entry.initrd.push_str(&normalized);
    }
}

/// Normalize a GRUB path to a clean path
///
/// GRUB uses forward slashes and often includes:
/// - Device references like `($drive1)`, `(hd0,gpt1)`, etc.
/// - Variable references like `$root`, `${prefix}`
/// - Double slashes `//` (NixOS uses this)
///
/// We strip device references and clean up the path.
///
/// Examples:
/// - `($drive1)//kernels/vmlinuz` → `kernels/vmlinuz`
/// - `/boot/vmlinuz` → `boot/vmlinuz`
/// - `(hd0,gpt2)/vmlinuz` → `vmlinuz`
fn normalize_grub_path(path: &str) -> String<128> {
    let mut result: String<128> = String::new();

    let mut path = path;

    // Strip GRUB device reference like ($drive1), (hd0,gpt1), etc.
    if path.starts_with('(')
        && let Some(end) = path.find(')')
    {
        path = &path[end + 1..];
    }

    // Strip leading slashes (including double slashes like //)
    let path = path.trim_start_matches('/');

    // Copy the rest, preserving the path structure
    for c in path.chars() {
        // Skip any remaining problematic characters
        if c == '$' {
            // Skip variable references - find the end of the variable
            // This is a simplification; real GRUB variables are more complex
            continue;
        }
        let _ = result.push(c);
    }

    result
}

/// Check if a filesystem has a GRUB configuration
pub fn has_grub_config(fs: &mut FatFilesystem<'_>) -> bool {
    // Check top-level paths
    if GRUB_TOPLEVEL_PATHS
        .iter()
        .any(|path| fs.file_size(path).is_ok())
    {
        return true;
    }
    // Dynamically check EFI subdirectories
    if let Ok(subdirs) = fs.list_subdirectories("EFI") {
        for subdir in subdirs.iter() {
            if subdir.as_str().eq_ignore_ascii_case("BOOT") {
                continue;
            }
            let mut path = heapless::String::<128>::new();
            if core::fmt::write(&mut path, format_args!("EFI\\{}\\grub.cfg", subdir)).is_err() {
                continue;
            }
            if fs.file_size(&path).is_ok() {
                return true;
            }
        }
    }
    false
}
