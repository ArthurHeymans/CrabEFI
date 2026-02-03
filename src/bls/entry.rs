//! BLS Entry Parser
//!
//! Parses individual Boot Loader Specification Type #1 entry files.
//! These are text files in `/loader/entries/*.conf` format.
//!
//! Reference: https://uapi-group.org/specifications/specs/boot_loader_specification/

use heapless::String;

/// Maximum length for various BLS entry fields
const MAX_TITLE_LEN: usize = 64;
const MAX_VERSION_LEN: usize = 32;
const MAX_PATH_LEN: usize = 128;
const MAX_OPTIONS_LEN: usize = 512;
const MAX_MACHINE_ID_LEN: usize = 33; // 32 hex chars + null
const MAX_SORT_KEY_LEN: usize = 32;

/// A parsed BLS Type #1 entry
#[derive(Debug, Clone)]
pub struct BlsEntry {
    /// Display title for the menu
    pub title: String<MAX_TITLE_LEN>,
    /// Kernel version string
    pub version: String<MAX_VERSION_LEN>,
    /// Path to the Linux kernel (relative to ESP root)
    pub linux: String<MAX_PATH_LEN>,
    /// Path to the initrd (relative to ESP root)
    pub initrd: String<MAX_PATH_LEN>,
    /// Kernel command line options
    pub options: String<MAX_OPTIONS_LEN>,
    /// Machine ID (for sorting)
    pub machine_id: String<MAX_MACHINE_ID_LEN>,
    /// Sort key (for ordering entries)
    pub sort_key: String<MAX_SORT_KEY_LEN>,
    /// Device tree path (optional, mainly for ARM)
    pub devicetree: String<MAX_PATH_LEN>,
    /// Architecture (x64, ia32, arm, etc.)
    pub architecture: String<8>,
}

impl Default for BlsEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl BlsEntry {
    /// Create a new empty BLS entry
    pub const fn new() -> Self {
        Self {
            title: String::new(),
            version: String::new(),
            linux: String::new(),
            initrd: String::new(),
            options: String::new(),
            machine_id: String::new(),
            sort_key: String::new(),
            devicetree: String::new(),
            architecture: String::new(),
        }
    }

    /// Check if this entry is valid (has required fields)
    pub fn is_valid(&self) -> bool {
        // At minimum, we need a title and linux path
        !self.title.is_empty() && !self.linux.is_empty()
    }

    /// Get a display title, using version as fallback
    pub fn display_title(&self) -> &str {
        if !self.title.is_empty() {
            &self.title
        } else if !self.version.is_empty() {
            &self.version
        } else {
            "Unknown"
        }
    }

    /// Parse a BLS entry from text content
    ///
    /// # Arguments
    ///
    /// * `content` - The text content of the .conf file
    ///
    /// # Returns
    ///
    /// A parsed `BlsEntry` if successful
    pub fn parse(content: &str) -> Result<Self, BlsParseError> {
        let mut entry = BlsEntry::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse key-value pairs
            if let Some((key, value)) = split_key_value(line) {
                match key {
                    "title" => {
                        entry.title.clear();
                        let _ = entry.title.push_str(value);
                    }
                    "version" => {
                        entry.version.clear();
                        let _ = entry.version.push_str(value);
                    }
                    "linux" => {
                        entry.linux.clear();
                        let _ = entry.linux.push_str(normalize_path(value));
                    }
                    "initrd" => {
                        // initrd can have multiple values, but we only take the first
                        if entry.initrd.is_empty() {
                            let _ = entry.initrd.push_str(normalize_path(value));
                        }
                    }
                    "options" => {
                        entry.options.clear();
                        let _ = entry.options.push_str(value);
                    }
                    "machine-id" => {
                        entry.machine_id.clear();
                        let _ = entry.machine_id.push_str(value);
                    }
                    "sort-key" => {
                        entry.sort_key.clear();
                        let _ = entry.sort_key.push_str(value);
                    }
                    "devicetree" => {
                        entry.devicetree.clear();
                        let _ = entry.devicetree.push_str(normalize_path(value));
                    }
                    "architecture" => {
                        entry.architecture.clear();
                        let _ = entry.architecture.push_str(value);
                    }
                    _ => {
                        // Unknown key - ignore
                        log::trace!("Unknown BLS key: {}", key);
                    }
                }
            }
        }

        if entry.is_valid() {
            Ok(entry)
        } else {
            Err(BlsParseError::MissingRequired)
        }
    }
}

/// Error parsing a BLS entry
#[derive(Debug)]
pub enum BlsParseError {
    /// Missing required fields (title or linux)
    MissingRequired,
    /// Invalid format
    InvalidFormat,
}

/// Split a line into key and value
///
/// BLS uses whitespace to separate key from value.
/// Example: "title    Fedora 40"
fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.splitn(2, |c: char| c.is_whitespace());
    let key = parts.next()?.trim();
    let value = parts.next()?.trim();

    if key.is_empty() || value.is_empty() {
        None
    } else {
        Some((key, value))
    }
}

/// Normalize a path from BLS format to our internal format
///
/// BLS uses forward slashes and paths relative to the boot partition root.
/// We convert to backslashes for FAT filesystem compatibility.
fn normalize_path(path: &str) -> &str {
    // Remove leading slash if present
    path.trim_start_matches('/')
}

/// Convert a normalized BLS path to FAT path format
///
/// # Arguments
///
/// * `bls_path` - Path from BLS entry (e.g., "vmlinuz-6.8.0")
/// * `output` - Buffer to write the FAT path
pub fn to_fat_path(bls_path: &str, output: &mut String<MAX_PATH_LEN>) {
    output.clear();
    for c in bls_path.chars() {
        if c == '/' {
            let _ = output.push('\\');
        } else {
            let _ = output.push(c);
        }
    }
}

/// BLS loader.conf settings
#[derive(Debug, Clone)]
pub struct LoaderConf {
    /// Default entry pattern (filename without .conf extension)
    pub default: String<64>,
    /// Timeout in seconds (0 = no timeout, empty = no timeout)
    pub timeout: Option<u32>,
    /// Console mode (keep, text, auto, max, etc.)
    pub console_mode: String<16>,
    /// Editor enabled (true/false/auto)
    pub editor: bool,
    /// Auto-entries generation
    pub auto_entries: bool,
    /// Auto-firmware reboot entries
    pub auto_firmware: bool,
}

impl Default for LoaderConf {
    fn default() -> Self {
        Self::new()
    }
}

impl LoaderConf {
    /// Create a new loader.conf with defaults
    pub const fn new() -> Self {
        Self {
            default: String::new(),
            timeout: None,
            console_mode: String::new(),
            editor: true,
            auto_entries: true,
            auto_firmware: true,
        }
    }

    /// Parse loader.conf content
    ///
    /// # Arguments
    ///
    /// * `content` - The text content of loader.conf
    pub fn parse(content: &str) -> Self {
        let mut conf = LoaderConf::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = split_key_value(line) {
                match key {
                    "default" => {
                        conf.default.clear();
                        // Remove .conf extension if present
                        let value = value.trim_end_matches(".conf");
                        let _ = conf.default.push_str(value);
                    }
                    "timeout" => {
                        if value == "menu-force" || value == "menu-hidden" {
                            conf.timeout = None;
                        } else if let Ok(secs) = value.parse::<u32>() {
                            conf.timeout = Some(secs);
                        }
                    }
                    "console-mode" => {
                        conf.console_mode.clear();
                        let _ = conf.console_mode.push_str(value);
                    }
                    "editor" => {
                        conf.editor = value == "yes" || value == "true" || value == "1";
                    }
                    "auto-entries" => {
                        conf.auto_entries = value == "yes" || value == "true" || value == "1";
                    }
                    "auto-firmware" => {
                        conf.auto_firmware = value == "yes" || value == "true" || value == "1";
                    }
                    _ => {
                        log::trace!("Unknown loader.conf key: {}", key);
                    }
                }
            }
        }

        conf
    }
}
