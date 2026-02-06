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

    /// Get the default entry index based on loader.conf
    ///
    /// Returns the index of the default entry, or 0 if no default is set
    /// or the default entry is not found.
    pub fn default_entry_index(&self) -> usize {
        if let Some(ref conf) = self.loader_conf
            && !conf.default.is_empty()
        {
            // Try to find entry matching the default pattern
            // The default can be a wildcard like "fedora-*" or exact like "fedora-40"
            for (i, entry) in self.entries.iter().enumerate() {
                // Simple matching: check if entry title/version contains the pattern
                if entry.title.contains(conf.default.as_str())
                    || entry.version.contains(conf.default.as_str())
                {
                    return i;
                }
            }
        }
        0
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
            let mut path: String<64> = String::new();
            let _ = core::fmt::write(&mut path, format_args!("{}\\{}", ENTRIES_DIR, filename));
            if let Some(entry) = try_load_entry(fs, path.as_str()) {
                let _ = discovery.entries.push(entry);
            }
        }
    }

    // Sort entries - convert to slice, sort, and copy back
    // heapless Vec doesn't have sort_by, so we do a simple insertion sort
    let len = discovery.entries.len();
    for i in 1..len {
        let mut j = i;
        while j > 0 {
            let should_swap = {
                let a = &discovery.entries[j - 1];
                let b = &discovery.entries[j];
                // First by sort-key, then by version (descending - newer first)
                if !a.sort_key.is_empty() || !b.sort_key.is_empty() {
                    a.sort_key > b.sort_key
                } else {
                    a.version < b.version
                }
            };
            if should_swap {
                discovery.entries.swap(j - 1, j);
                j -= 1;
            } else {
                break;
            }
        }
    }

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
        Ok(entry) => {
            log::debug!("Loaded BLS entry: {} ({})", entry.display_title(), path);
            Some(entry)
        }
        Err(e) => {
            log::warn!("Failed to parse BLS entry {}: {:?}", path, e);
            None
        }
    }
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
    fs.file_size(LOADER_CONF_PATH).is_ok()
        || fs.find_file(ENTRIES_DIR).is_ok()
}
