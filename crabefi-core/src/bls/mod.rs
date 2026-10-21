//! Boot Loader Specification Support
//!
//! This module implements Type #1 (text-based) entries from the Boot Loader
//! Specification. It discovers and parses boot entries from `/loader/entries/`.
//!
//! Reference: https://uapi-group.org/specifications/specs/boot_loader_specification/
//!
//! # Directory Structure
//!
//! ```text
//! /loader/
//!     loader.conf          # Optional global configuration
//!     entries/
//!         *.conf           # Individual boot entry files
//!     entries.srel         # Optional conformance marker
//! ```
//!
//! # Entry Format Example
//!
//! ```ini
//! title        Fedora 40
//! version      6.8.0-300.fc40.x86_64
//! linux        /vmlinuz-6.8.0-300.fc40.x86_64
//! initrd       /initramfs-6.8.0-300.fc40.x86_64.img
//! options      root=UUID=... quiet
//! ```

pub mod entry;

pub use entry::{BlsEntry, BlsParseError, LoaderConf};

use crate::fs::fat::FatFilesystem;
use heapless::{String, Vec};

/// Maximum number of BLS entries we can discover
const MAX_BLS_ENTRIES: usize = 16;

/// Maximum size of a .conf file we'll read
const MAX_CONF_SIZE: usize = 4096;

/// Path to BLS entries directory
const ENTRIES_DIR: &str = "loader\\entries";

/// Path to loader.conf
const LOADER_CONF_PATH: &str = "loader\\loader.conf";

/// Error during BLS discovery
#[derive(Debug)]
pub enum BlsError {
    /// Failed to read filesystem
    FsError,
    /// Directory not found
    DirectoryNotFound,
    /// No valid entries found
    NoEntries,
}

/// Discovered BLS entries with optional loader configuration
#[derive(Debug)]
pub struct BlsDiscovery {
    /// Parsed boot entries
    pub entries: Vec<BlsEntry, MAX_BLS_ENTRIES>,
    /// Loader configuration (if loader.conf exists)
    pub loader_conf: Option<LoaderConf>,
}

impl BlsDiscovery {
    /// Create a new empty discovery result
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            loader_conf: None,
        }
    }

    /// Get the number of discovered entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if no entries were found
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `loader.conf`'s `default` names `entry`: a glob over the
    /// entry IDs, matched case-insensitively as in systemd-boot. False
    /// without a default and for the `@saved` style special values.
    pub fn is_default(&self, entry: &BlsEntry) -> bool {
        self.loader_conf.as_ref().is_some_and(|conf| {
            let pattern = conf.default.as_str();
            !pattern.is_empty()
                && !pattern.starts_with('@')
                && glob_match(pattern.as_bytes(), entry.id.as_bytes())
        })
    }

    /// Get the timeout from loader.conf (or None)
    pub fn timeout(&self) -> Option<u32> {
        self.loader_conf.as_ref().and_then(|c| c.timeout)
    }
}

impl Default for BlsDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

/// Discover BLS entries on a FAT filesystem
///
/// This function scans `/loader/entries/` for .conf files and parses them.
///
/// # Arguments
///
/// * `fs` - FAT filesystem to scan
///
/// # Returns
///
/// `BlsDiscovery` containing all valid entries found
pub fn discover_entries(fs: &mut FatFilesystem<'_>) -> Result<BlsDiscovery, BlsError> {
    let mut discovery = BlsDiscovery::new();

    // Try to read loader.conf
    if let Ok(size) = fs.file_size(LOADER_CONF_PATH)
        && size > 0
        && size <= MAX_CONF_SIZE as u32
    {
        let mut buf = [0u8; MAX_CONF_SIZE];
        if let Ok(bytes_read) = fs.read_file_all(LOADER_CONF_PATH, &mut buf)
            && let Ok(content) = core::str::from_utf8(&buf[..bytes_read])
        {
            discovery.loader_conf = Some(LoaderConf::parse(content));
            log::debug!("Parsed loader.conf: {:?}", discovery.loader_conf);
        }
    }

    // List .conf files in the entries directory using directory enumeration
    // This is much faster than probing hardcoded filenames one-by-one
    if let Ok(conf_files) = fs.list_directory_files(ENTRIES_DIR, ".conf") {
        log::debug!("Found {} .conf files in {}", conf_files.len(), ENTRIES_DIR);
        for filename in conf_files.iter() {
            let mut path: String<280> = String::new();
            let _ = core::fmt::write(&mut path, format_args!("{}\\{}", ENTRIES_DIR, filename));
            if let Some(entry) = try_load_entry(fs, path.as_str()) {
                let _ = discovery.entries.push(entry);
            }
        }
    }

    // Sort entries: by sort-key ascending, then by version descending (newer first)
    discovery.entries.as_mut_slice().sort_by(|a, b| {
        if !a.sort_key.is_empty() || !b.sort_key.is_empty() {
            a.sort_key.cmp(&b.sort_key)
        } else {
            b.version.cmp(&a.version)
        }
    });

    if discovery.is_empty() {
        log::debug!("No BLS entries found");
        Err(BlsError::NoEntries)
    } else {
        log::info!("Found {} BLS entries", discovery.len());
        Ok(discovery)
    }
}

/// Try to load and parse a single BLS entry file
fn try_load_entry(fs: &mut FatFilesystem<'_>, path: &str) -> Option<BlsEntry> {
    // Check if file exists and get size
    let size = fs.file_size(path).ok()?;

    if size == 0 || size > MAX_CONF_SIZE as u32 {
        return None;
    }

    // Read file content
    let mut buf = [0u8; MAX_CONF_SIZE];
    let bytes_read = fs.read_file_all(path, &mut buf).ok()?;

    // Parse as UTF-8
    let content = core::str::from_utf8(&buf[..bytes_read]).ok()?;

    // Parse the entry
    match BlsEntry::parse(content) {
        Ok(mut entry) => {
            let name = path.rsplit('\\').next().unwrap_or(path);
            let _ = entry
                .id
                .push_str(name.strip_suffix(".conf").unwrap_or(name));
            log::debug!("Loaded BLS entry: {} ({})", entry.display_title(), path);
            Some(entry)
        }
        Err(e) => {
            log::warn!("Failed to parse BLS entry {}: {:?}", path, e);
            None
        }
    }
}

/// Match `text` against a glob `pattern` with `*` (any run) and `?` (any
/// byte), ignoring ASCII case, as systemd-boot matches entry IDs. Iterative,
/// backtracking only to the last `*`: at most `pattern.len() * text.len()`
/// steps.
fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    // The last `*` and the text position it currently covers up to.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == b'?' || c.eq_ignore_ascii_case(&text[t]) => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((star_p, star_t)) => {
                    star = Some((star_p, star_t + 1));
                    p = star_p + 1;
                    t = star_t + 1;
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// Check if a filesystem has BLS entries
///
/// Quick check: verifies the loader.conf or entries directory exists.
///
/// # Arguments
///
/// * `fs` - FAT filesystem to check
pub fn has_bls_entries(fs: &mut FatFilesystem<'_>) -> bool {
    // Check if loader.conf or the entries directory exists
    fs.file_size(LOADER_CONF_PATH).is_ok() || fs.find_file(ENTRIES_DIR).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discovery(default: &str, ids: &[&str]) -> BlsDiscovery {
        let mut discovery = BlsDiscovery::new();
        let mut conf = LoaderConf::new();
        let _ = conf.default.push_str(default);
        discovery.loader_conf = Some(conf);
        for id in ids {
            let mut entry = BlsEntry::new();
            let _ = entry.id.push_str(id);
            let _ = discovery.entries.push(entry);
        }
        discovery
    }

    #[test]
    fn the_default_names_an_entry_id() {
        let ids = ["02-archiso-speech-linux", "01-archiso-linux"];
        let default = |pattern| {
            let discovery = discovery(pattern, &ids);
            discovery
                .entries
                .iter()
                .find(|e| discovery.is_default(e))
                .map(|e| e.id.clone())
        };
        assert_eq!(
            default("01-archiso-linux").as_deref(),
            Some("01-archiso-linux")
        );
        assert_eq!(
            default("*speech*").as_deref(),
            Some("02-archiso-speech-linux")
        );
        assert_eq!(
            default("0?-archiso-linux").as_deref(),
            Some("01-archiso-linux")
        );
        assert_eq!(default("01-ARCHISO-*").as_deref(), Some("01-archiso-linux"));
        assert_eq!(default("archiso"), None);
        assert_eq!(default("@saved"), None);
        assert_eq!(default(""), None);
    }

    #[test]
    fn glob_work_is_bounded() {
        assert!(glob_match(b"*a*b", b"xaxxb"));
        assert!(glob_match(b"**", b""));
        assert!(!glob_match(b"a*", b"b"));
        let pattern = [b"*a".repeat(30).as_slice(), b"*b"].concat();
        assert!(!glob_match(&pattern, &[b'a'; 120]));
    }
}
