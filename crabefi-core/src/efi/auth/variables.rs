//! Secure Boot Variable Management
//!
//! This module handles the Secure Boot key databases and provides
//! functions for managing authenticated variables.

use super::crypto::constant_time_eq;
use super::guid_to_bytes;
use super::structures::{EfiTime, SignatureIterator, SignatureListIterator};
use super::{AuthError, EFI_CERT_SHA256_GUID, EFI_CERT_X509_GUID};
use alloc::vec::Vec;
use r_efi::efi::Guid;
use zerocopy::FromBytes;

// ============================================================================
// Secure Boot Variable Names
// ============================================================================

/// Platform Key variable name (UCS-2)
pub const PK_NAME: &[u16] = &[0x50, 0x4B, 0x00]; // "PK\0"

/// Key Exchange Key variable name (UCS-2)
pub const KEK_NAME: &[u16] = &[0x4B, 0x45, 0x4B, 0x00]; // "KEK\0"

/// Signature database variable name (UCS-2)
pub const DB_NAME: &[u16] = &[0x64, 0x62, 0x00]; // "db\0"

/// Forbidden signature database variable name (UCS-2)
pub const DBX_NAME: &[u16] = &[0x64, 0x62, 0x78, 0x00]; // "dbx\0"

/// SetupMode variable name (UCS-2)
pub const SETUP_MODE_NAME: &[u16] = &[0x53, 0x65, 0x74, 0x75, 0x70, 0x4D, 0x6F, 0x64, 0x65, 0x00]; // "SetupMode\0"

/// SecureBoot variable name (UCS-2)
pub const SECURE_BOOT_NAME: &[u16] = &[
    0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x42, 0x6F, 0x6F, 0x74, 0x00,
]; // "SecureBoot\0"

/// SecureBootEnable variable name (UCS-2)
/// This is a non-volatile variable that stores the user's preference for enabling Secure Boot.
/// Unlike SecureBoot (which is a read-only status variable), this persists across resets.
pub const SECURE_BOOT_ENABLE_NAME: &[u16] = &[
    0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x42, 0x6F, 0x6F, 0x74, 0x45, 0x6E, 0x61, 0x62, 0x6C, 0x65,
    0x00,
]; // "SecureBootEnable\0"

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

    /// Clear all entries while retaining boot-time allocation capacity.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Retire all allocator-backed storage before the boot heap is unmapped.
    pub fn retire(&mut self) {
        self.entries = Vec::new();
        self.timestamp = EfiTime::zero();
    }

    /// Add an entry to the database
    pub fn add_entry(&mut self, entry: KeyDatabaseEntry) -> Result<(), AuthError> {
        // Check size and allocation limits before mutating the database. Runtime
        // authentication uses this same path with the bounded runtime arena.
        let current_size: usize = self.entries.iter().map(|e| e.data.len()).sum();
        let required = current_size
            .checked_add(entry.data.len())
            .ok_or(AuthError::BufferTooSmall)?;
        if required > MAX_KEY_DB_SIZE {
            return Err(AuthError::BufferTooSmall);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| AuthError::BufferTooSmall)?;
        self.entries.push(entry);
        Ok(())
    }

    /// Parse and load entries from a signature list blob
    pub fn load_from_signature_lists(&mut self, data: &[u8]) -> Result<(), AuthError> {
        let mut consumed = 0usize;
        let mut entry_count = 0usize;
        for (list, list_data) in SignatureListIterator::new(data) {
            let first = list.first_signature_offset();
            let signature_size = list.signature_size as usize;
            let signature_bytes = list_data
                .len()
                .checked_sub(first)
                .ok_or(AuthError::InvalidHeader)?;
            if signature_size < super::structures::EfiSignatureData::HEADER_SIZE
                || signature_bytes == 0
                || !signature_bytes.is_multiple_of(signature_size)
            {
                return Err(AuthError::InvalidHeader);
            }

            for (owner, sig_data) in SignatureIterator::new(list, list_data) {
                let mut entry_data = Vec::new();
                entry_data
                    .try_reserve(sig_data.len())
                    .map_err(|_| AuthError::BufferTooSmall)?;
                entry_data.extend_from_slice(sig_data);
                let entry = KeyDatabaseEntry {
                    cert_type: list.signature_type,
                    data: entry_data,
                    owner,
                };
                self.add_entry(entry)?;
                entry_count += 1;
            }
            consumed = consumed
                .checked_add(list_data.len())
                .ok_or(AuthError::InvalidHeader)?;
        }
        if consumed != data.len() || (!data.is_empty() && entry_count == 0) {
            return Err(AuthError::InvalidHeader);
        }
        Ok(())
    }

    /// Total certificate bytes held by this database.
    pub fn payload_bytes(&self) -> usize {
        self.entries.iter().map(|entry| entry.data.len()).sum()
    }

    /// Serialize the database to signature list format
    pub fn to_signature_lists(&self) -> Vec<u8> {
        use super::structures::EfiSignatureList;

        let mut result = Vec::new();

        // Group entries by certificate type
        let x509_guid = guid_to_bytes(&EFI_CERT_X509_GUID);
        let sha256_guid = guid_to_bytes(&EFI_CERT_SHA256_GUID);

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
        let x509_guid = guid_to_bytes(&EFI_CERT_X509_GUID);
        self.entries
            .iter()
            .find(|e| e.cert_type == x509_guid && e.data == cert_data)
    }

    /// Check if a SHA-256 hash is in the database
    ///
    /// Uses constant-time comparison to prevent timing side-channel attacks
    /// that could leak information about which hashes are in the database.
    pub fn contains_sha256_hash(&self, hash: &[u8; 32]) -> bool {
        let sha256_guid = guid_to_bytes(&EFI_CERT_SHA256_GUID);
        self.entries.iter().any(|e| {
            e.cert_type == sha256_guid
                && e.data.len() >= 32
                && constant_time_eq(&e.data[..32], hash)
        })
    }

    /// Get all X.509 certificates in the database
    pub fn x509_certificates(&self) -> impl Iterator<Item = &[u8]> {
        let x509_guid = guid_to_bytes(&EFI_CERT_X509_GUID);
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

/// Authentication databases owned only for the duration of one runtime call.
///
/// The entries are allocated from the bounded runtime workspace and are never
/// stored in a static. In particular, dropping this value cannot replace a
/// boot-heap `Vec` after ExitBootServices.
pub struct RuntimeAuthDatabases {
    pub pk: KeyDatabase,
    pub kek: KeyDatabase,
    pub db: KeyDatabase,
    pub dbx: KeyDatabase,
}

impl RuntimeAuthDatabases {
    fn new() -> Self {
        Self {
            pk: KeyDatabase::new(),
            kek: KeyDatabase::new(),
            db: KeyDatabase::new(),
            dbx: KeyDatabase::new(),
        }
    }

    fn load(
        database: &mut KeyDatabase,
        runtime: &crate::runtime_state::RuntimeState,
        guid: &Guid,
        name: &[u16],
    ) -> Result<(), AuthError> {
        if let Some((_, payload)) = runtime.get(guid, name) {
            database.load_from_signature_lists(payload)?;
        }
        if let Some(timestamp) = runtime.auth_timestamp(guid, name)
            && let Ok(timestamp) = EfiTime::read_from_bytes(&timestamp)
        {
            database.set_timestamp(timestamp);
        }
        Ok(())
    }

    /// Build all four databases from pointer-free runtime storage.
    pub fn from_runtime_state(
        runtime: &crate::runtime_state::RuntimeState,
    ) -> Result<Self, AuthError> {
        let mut databases = Self::new();
        Self::load(
            &mut databases.pk,
            runtime,
            &super::EFI_GLOBAL_VARIABLE_GUID,
            PK_NAME,
        )?;
        Self::load(
            &mut databases.kek,
            runtime,
            &super::EFI_GLOBAL_VARIABLE_GUID,
            KEK_NAME,
        )?;
        Self::load(
            &mut databases.db,
            runtime,
            &super::EFI_IMAGE_SECURITY_DATABASE_GUID,
            DB_NAME,
        )?;
        Self::load(
            &mut databases.dbx,
            runtime,
            &super::EFI_IMAGE_SECURITY_DATABASE_GUID,
            DBX_NAME,
        )?;
        Ok(databases)
    }

    /// Conservative upper bound for crypto/parser scratch space. This is
    /// checked before entering dependency APIs that do not expose fallible
    /// allocation, so arena exhaustion becomes EFI_OUT_OF_RESOURCES.
    pub fn runtime_preflight_size(
        &self,
        variable: SecureBootVariable,
        raw_size: usize,
        signed_size: usize,
    ) -> Option<usize> {
        let database_size = match variable {
            SecureBootVariable::PK => self.pk.payload_bytes(),
            SecureBootVariable::KEK | SecureBootVariable::Db | SecureBootVariable::Dbx => self
                .kek
                .payload_bytes()
                .checked_add(self.pk.payload_bytes())?,
        };
        raw_size
            .checked_mul(2)?
            .checked_add(signed_size.checked_mul(2)?)?
            .checked_add(database_size.checked_mul(2)?)?
            .checked_add(64 * 1024)
    }
}

/// Validate a complete EFI signature database without retaining allocations.
pub fn validate_signature_database(data: &[u8]) -> Result<(), AuthError> {
    let mut database = KeyDatabase::new();
    database.load_from_signature_lists(data)
}

/// Rebuild operation-local authentication databases from runtime state.
pub fn prepare_runtime_databases() -> Result<RuntimeAuthDatabases, AuthError> {
    crate::runtime_state::with(RuntimeAuthDatabases::from_runtime_state)
}

/// Copy a boot-time replay timestamp before its allocator-backed database is
/// retired for the runtime transition.
pub fn database_timestamp(var_type: SecureBootVariable) -> EfiTime {
    match var_type {
        SecureBootVariable::PK => *PK_DATABASE.lock().timestamp(),
        SecureBootVariable::KEK => *KEK_DATABASE.lock().timestamp(),
        SecureBootVariable::Db => *DB_DATABASE.lock().timestamp(),
        SecureBootVariable::Dbx => *DBX_DATABASE.lock().timestamp(),
    }
}

/// Drop boot-heap database entries while physical boot memory is still mapped.
/// The static databases remain empty and are never touched by runtime calls.
pub fn retire_boot_databases() {
    PK_DATABASE.lock().retire();
    KEK_DATABASE.lock().retire();
    DB_DATABASE.lock().retire();
    DBX_DATABASE.lock().retire();
}

/// Identify which key database a variable belongs to
pub fn identify_key_database(name: &[u16], guid: &Guid) -> Option<SecureBootVariable> {
    use super::{EFI_GLOBAL_VARIABLE_GUID, EFI_IMAGE_SECURITY_DATABASE_GUID};

    use crate::efi::utils::ucs2_eq;

    if *guid == EFI_GLOBAL_VARIABLE_GUID {
        if ucs2_eq(name, PK_NAME) {
            return Some(SecureBootVariable::PK);
        }
        if ucs2_eq(name, KEK_NAME) {
            return Some(SecureBootVariable::KEK);
        }
    } else if *guid == EFI_IMAGE_SECURITY_DATABASE_GUID {
        if ucs2_eq(name, DB_NAME) {
            return Some(SecureBootVariable::Db);
        }
        if ucs2_eq(name, DBX_NAME) {
            return Some(SecureBootVariable::Dbx);
        }
    }
    None
}

/// Secure Boot variable type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootVariable {
    /// Platform Key
    PK,
    /// Key Exchange Key
    KEK,
    /// Allowed signature database
    Db,
    /// Forbidden signature database
    Dbx,
}

impl SecureBootVariable {
    /// Get the GUID for this variable
    pub fn guid(&self) -> Guid {
        use super::{EFI_GLOBAL_VARIABLE_GUID, EFI_IMAGE_SECURITY_DATABASE_GUID};
        match self {
            SecureBootVariable::PK | SecureBootVariable::KEK => EFI_GLOBAL_VARIABLE_GUID,
            SecureBootVariable::Db | SecureBootVariable::Dbx => EFI_IMAGE_SECURITY_DATABASE_GUID,
        }
    }

    /// Get which key database should authorize modifications to this variable
    pub fn authorizing_database(&self) -> SecureBootVariable {
        match self {
            // PK is self-signed (or authorized in setup mode)
            SecureBootVariable::PK => SecureBootVariable::PK,
            // KEK is authorized by PK
            SecureBootVariable::KEK => SecureBootVariable::PK,
            // db and dbx are authorized by KEK (or PK)
            SecureBootVariable::Db | SecureBootVariable::Dbx => SecureBootVariable::KEK,
        }
    }
}

// name_matches consolidated into crate::efi::utils::ucs2_eq
