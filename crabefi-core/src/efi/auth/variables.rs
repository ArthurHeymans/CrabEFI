//! Secure Boot Variable Management
//!
//! This module handles the Secure Boot key databases and provides
//! functions for managing authenticated variables.

use alloc::vec::Vec;

use crabefi_efi_types::{
    authentication::{EfiSignatureList, EfiTime, SignatureIterator, SignatureListIterator},
    constant_time_eq,
    secure_boot::{EFI_CERT_SHA256_GUID, EFI_CERT_X509_GUID},
};

use super::AuthError;

// ============================================================================
// Secure Boot Key Database
// ============================================================================

/// Maximum size for a single key database
const MAX_KEY_DB_SIZE: usize = 64 * 1024; // 64 KB

/// Secure Boot key database entry
#[derive(Clone)]
pub struct KeyDatabaseEntry {
    /// Certificate type GUID (as raw bytes)
    pub cert_type: [u8; 16],
    /// Certificate/signature data
    pub data: Vec<u8>,
    /// Owner GUID (as raw bytes)
    pub owner: [u8; 16],
}

/// Secure Boot key database
pub struct KeyDatabase {
    /// Database entries
    entries: Vec<KeyDatabaseEntry>,
    /// Last modification timestamp
    timestamp: EfiTime,
}

impl KeyDatabase {
    /// Create a new empty key database
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            timestamp: EfiTime::zero(),
        }
    }

    /// Check if the database is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Get the last modification timestamp
    pub fn timestamp(&self) -> &EfiTime {
        &self.timestamp
    }

    /// Update the timestamp
    pub fn set_timestamp(&mut self, timestamp: EfiTime) {
        self.timestamp = timestamp;
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Add an entry to the database
    pub fn add_entry(&mut self, entry: KeyDatabaseEntry) -> Result<(), AuthError> {
        // Check size limit
        let current_size: usize = self.entries.iter().map(|e| e.data.len()).sum();
        if current_size + entry.data.len() > MAX_KEY_DB_SIZE {
            return Err(AuthError::BufferTooSmall);
        }

        self.entries.push(entry);
        Ok(())
    }

    /// Parse and load entries from a signature list blob
    pub fn load_from_signature_lists(&mut self, data: &[u8]) -> Result<(), AuthError> {
        for (list, list_data) in SignatureListIterator::new(data) {
            for (owner, sig_data) in SignatureIterator::new(list, list_data) {
                let entry = KeyDatabaseEntry {
                    cert_type: list.signature_type,
                    data: sig_data.to_vec(),
                    owner,
                };
                self.add_entry(entry)?;
            }
        }
        Ok(())
    }

    /// Serialize the database to signature list format
    pub fn to_signature_lists(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Group entries by certificate type
        let x509_guid = EFI_CERT_X509_GUID;
        let sha256_guid = EFI_CERT_SHA256_GUID;

        let mut x509_entries: Vec<&KeyDatabaseEntry> = Vec::new();
        let mut sha256_entries: Vec<&KeyDatabaseEntry> = Vec::new();
        let mut other_entries: Vec<&KeyDatabaseEntry> = Vec::new();

        for entry in &self.entries {
            if entry.cert_type == x509_guid {
                x509_entries.push(entry);
            } else if entry.cert_type == sha256_guid {
                sha256_entries.push(entry);
            } else {
                other_entries.push(entry);
            }
        }

        // Serialize X.509 certificates (variable size, one list per cert)
        for entry in x509_entries {
            let sig_size = (16 + entry.data.len()) as u32; // Owner GUID + data
            let list_size = (EfiSignatureList::HEADER_SIZE + sig_size as usize) as u32;

            // Write EFI_SIGNATURE_LIST header
            result.extend_from_slice(&entry.cert_type);
            result.extend_from_slice(&list_size.to_le_bytes());
            result.extend_from_slice(&0u32.to_le_bytes()); // signature_header_size
            result.extend_from_slice(&sig_size.to_le_bytes());

            // Write EFI_SIGNATURE_DATA
            result.extend_from_slice(&entry.owner);
            result.extend_from_slice(&entry.data);
        }

        // Serialize SHA-256 hashes (fixed size, can be in one list)
        if !sha256_entries.is_empty() {
            let sig_size = 16 + 32; // Owner GUID + SHA-256 hash
            let list_size = EfiSignatureList::HEADER_SIZE + sha256_entries.len() * sig_size;

            // Write EFI_SIGNATURE_LIST header
            result.extend_from_slice(&sha256_guid);
            result.extend_from_slice(&(list_size as u32).to_le_bytes());
            result.extend_from_slice(&0u32.to_le_bytes()); // signature_header_size
            result.extend_from_slice(&(sig_size as u32).to_le_bytes());

            // Write signatures
            for entry in sha256_entries {
                result.extend_from_slice(&entry.owner);
                // Ensure exactly 32 bytes for SHA-256
                if entry.data.len() >= 32 {
                    result.extend_from_slice(&entry.data[..32]);
                } else {
                    result.extend_from_slice(&entry.data);
                    result.resize(result.len() + 32 - entry.data.len(), 0);
                }
            }
        }

        // Serialize other certificate types
        for entry in other_entries {
            let sig_size = (16 + entry.data.len()) as u32;
            let list_size = (EfiSignatureList::HEADER_SIZE + sig_size as usize) as u32;

            result.extend_from_slice(&entry.cert_type);
            result.extend_from_slice(&list_size.to_le_bytes());
            result.extend_from_slice(&0u32.to_le_bytes());
            result.extend_from_slice(&sig_size.to_le_bytes());
            result.extend_from_slice(&entry.owner);
            result.extend_from_slice(&entry.data);
        }

        result
    }

    /// Find an X.509 certificate in the database
    pub fn find_x509_certificate(&self, cert_data: &[u8]) -> Option<&KeyDatabaseEntry> {
        let x509_guid = EFI_CERT_X509_GUID;
        self.entries
            .iter()
            .find(|e| e.cert_type == x509_guid && e.data == cert_data)
    }

    /// Check if a SHA-256 hash is in the database
    ///
    /// Uses constant-time comparison to prevent timing side-channel attacks
    /// that could leak information about which hashes are in the database.
    pub fn contains_sha256_hash(&self, hash: &[u8; 32]) -> bool {
        let sha256_guid = EFI_CERT_SHA256_GUID;
        self.entries.iter().any(|e| {
            e.cert_type == sha256_guid
                && e.data.len() >= 32
                && constant_time_eq(&e.data[..32], hash)
        })
    }

    /// Get all X.509 certificates in the database
    pub fn x509_certificates(&self) -> impl Iterator<Item = &[u8]> {
        let x509_guid = EFI_CERT_X509_GUID;
        self.entries
            .iter()
            .filter(move |e| e.cert_type == x509_guid)
            .map(|e| e.data.as_slice())
    }
}

impl Default for KeyDatabase {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Secure Boot State Management
// ============================================================================

use spin::Mutex;

/// Global Platform Key (PK) database
static PK_DATABASE: Mutex<KeyDatabase> = Mutex::new(KeyDatabase::new());

/// Global Key Exchange Key (KEK) database  
static KEK_DATABASE: Mutex<KeyDatabase> = Mutex::new(KeyDatabase::new());

/// Global allowed signature database (db)
static DB_DATABASE: Mutex<KeyDatabase> = Mutex::new(KeyDatabase::new());

/// Global forbidden signature database (dbx)
static DBX_DATABASE: Mutex<KeyDatabase> = Mutex::new(KeyDatabase::new());

/// Get a reference to the PK database
pub fn pk_database() -> spin::MutexGuard<'static, KeyDatabase> {
    PK_DATABASE.lock()
}

/// Get a reference to the KEK database
pub fn kek_database() -> spin::MutexGuard<'static, KeyDatabase> {
    KEK_DATABASE.lock()
}

/// Get a reference to the db database
pub fn db_database() -> spin::MutexGuard<'static, KeyDatabase> {
    DB_DATABASE.lock()
}

/// Get a reference to the dbx database
pub fn dbx_database() -> spin::MutexGuard<'static, KeyDatabase> {
    DBX_DATABASE.lock()
}
