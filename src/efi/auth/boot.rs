//! Secure Boot Boot-Time Initialization
//!
//! This module handles initialization of Secure Boot state at boot time:
//!
//! 1. Load Secure Boot keys from persisted UEFI variables (PK, KEK, db, dbx)
//! 2. Check enrollment status and optionally enroll default keys
//! 3. Create/update SecureBoot and SetupMode status variables
//! 4. Persist newly enrolled keys to SMMSTORE
//!
//! # Boot Flow
//!
//! ```text
//! init_persistence() loads variables from SMMSTORE
//!         |
//!         v
//! init_secure_boot() is called:
//!   1. Load PK/KEK/db/dbx from in-memory variable cache
//!   2. If PK exists -> enter User Mode
//!   3. Create SecureBoot/SetupMode variables
//!   4. Optionally enroll default keys if none exist
//! ```

use super::enrollment::{self, EnrollmentStatus};
use super::variables::{
    db_database, dbx_database, kek_database, pk_database, SecureBootVariable, DBX_NAME, DB_NAME,
    KEK_NAME, PK_NAME, SECURE_BOOT_NAME, SETUP_MODE_NAME,
};
use super::{
    enter_setup_mode, enter_user_mode, is_setup_mode, AuthError, EFI_GLOBAL_VARIABLE_GUID,
    EFI_IMAGE_SECURITY_DATABASE_GUID,
};
use crate::efi::varstore::{
    get_variable_timestamp, persist_variable_with_timestamp, VarStoreError,
};
use crate::state::{self, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN};
use alloc::vec::Vec;

/// Variable attributes for read-only status variables
const STATUS_VAR_ATTRS: u32 =
    super::attributes::BOOTSERVICE_ACCESS | super::attributes::RUNTIME_ACCESS;

/// Variable attributes for Secure Boot key variables
const SECURE_BOOT_KEY_ATTRS: u32 = super::attributes::NON_VOLATILE
    | super::attributes::BOOTSERVICE_ACCESS
    | super::attributes::RUNTIME_ACCESS
    | super::attributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

/// Secure Boot initialization configuration
#[derive(Debug, Clone)]
pub struct SecureBootConfig {
    /// Whether to automatically enroll default Microsoft keys if none exist
    pub auto_enroll_defaults: bool,
    /// Whether to enable Secure Boot after enrollment
    pub enable_secure_boot: bool,
}

impl Default for SecureBootConfig {
    fn default() -> Self {
        Self {
            auto_enroll_defaults: true,
            enable_secure_boot: false, // Don't enable by default, let user decide
        }
    }
}

/// Initialize Secure Boot state at boot time
///
/// This should be called after `init_persistence()` has loaded variables from SMMSTORE.
///
/// # Returns
///
/// Returns the enrollment status after initialization.
pub fn init_secure_boot(config: &SecureBootConfig) -> Result<EnrollmentStatus, AuthError> {
    log::info!("Initializing Secure Boot...");

    // Step 1: Load Secure Boot keys from persisted variables
    let keys_loaded = load_keys_from_variables();
    log::info!(
        "Loaded Secure Boot keys: PK={}, KEK={}, db={}, dbx={}",
        keys_loaded.pk_count,
        keys_loaded.kek_count,
        keys_loaded.db_count,
        keys_loaded.dbx_count
    );

    // Step 2: Determine mode based on PK enrollment
    if keys_loaded.pk_enrolled {
        enter_user_mode();
        log::info!("Secure Boot: Entered User Mode (PK enrolled)");
    } else {
        enter_setup_mode();
        log::info!("Secure Boot: In Setup Mode (no PK enrolled)");

        // Step 3: Optionally enroll default keys
        if config.auto_enroll_defaults {
            log::info!("Auto-enrolling Microsoft default keys...");
            match enroll_and_persist_default_keys() {
                Ok(()) => {
                    log::info!("Default keys enrolled and persisted successfully");
                }
                Err(e) => {
                    log::warn!("Failed to enroll default keys: {:?}", e);
                    // Continue without keys - system stays in Setup Mode
                }
            }
        }
    }

    // Step 4: Create/update status variables
    create_status_variables()?;

    // Step 5: Enable Secure Boot if configured
    if config.enable_secure_boot && !is_setup_mode() {
        super::enable_secure_boot();
    }

    // Return final enrollment status
    Ok(enrollment::get_enrollment_status())
}

/// Initialize Secure Boot with default configuration
pub fn init_secure_boot_default() -> Result<EnrollmentStatus, AuthError> {
    init_secure_boot(&SecureBootConfig::default())
}

/// Load Secure Boot keys from in-memory UEFI variables
///
/// This reads the PK, KEK, db, and dbx variables from the variable cache
/// (which were loaded from SMMSTORE by init_persistence) and populates
/// the in-memory key databases. Also restores timestamps for proper
/// monotonic timestamp validation on future authenticated variable updates.
fn load_keys_from_variables() -> EnrollmentStatus {
    use super::structures::EfiTime;

    // Load PK
    if let Some(data) = get_variable_data(&EFI_GLOBAL_VARIABLE_GUID, PK_NAME) {
        if !data.is_empty() {
            let mut pk = pk_database();
            if let Err(e) = pk.load_from_signature_lists(&data) {
                log::warn!("Failed to parse PK variable: {:?}", e);
            } else {
                log::debug!("Loaded {} PK entries", pk.len());
                // Restore timestamp from stored variable for monotonic validation
                if let Some(ts) = get_variable_timestamp(&EFI_GLOBAL_VARIABLE_GUID, PK_NAME) {
                    pk.set_timestamp(EfiTime::from_serialized(&ts));
                    log::debug!(
                        "Restored PK timestamp: {}-{:02}-{:02}",
                        ts.year,
                        ts.month,
                        ts.day
                    );
                }
            }
        }
    }

    // Load KEK
    if let Some(data) = get_variable_data(&EFI_GLOBAL_VARIABLE_GUID, KEK_NAME) {
        if !data.is_empty() {
            let mut kek = kek_database();
            if let Err(e) = kek.load_from_signature_lists(&data) {
                log::warn!("Failed to parse KEK variable: {:?}", e);
            } else {
                log::debug!("Loaded {} KEK entries", kek.len());
                // Restore timestamp
                if let Some(ts) = get_variable_timestamp(&EFI_GLOBAL_VARIABLE_GUID, KEK_NAME) {
                    kek.set_timestamp(EfiTime::from_serialized(&ts));
                    log::debug!(
                        "Restored KEK timestamp: {}-{:02}-{:02}",
                        ts.year,
                        ts.month,
                        ts.day
                    );
                }
            }
        }
    }

    // Load db
    if let Some(data) = get_variable_data(&EFI_IMAGE_SECURITY_DATABASE_GUID, DB_NAME) {
        if !data.is_empty() {
            let mut db = db_database();
            if let Err(e) = db.load_from_signature_lists(&data) {
                log::warn!("Failed to parse db variable: {:?}", e);
            } else {
                log::debug!("Loaded {} db entries", db.len());
                // Restore timestamp
                if let Some(ts) = get_variable_timestamp(&EFI_IMAGE_SECURITY_DATABASE_GUID, DB_NAME)
                {
                    db.set_timestamp(EfiTime::from_serialized(&ts));
                    log::debug!(
                        "Restored db timestamp: {}-{:02}-{:02}",
                        ts.year,
                        ts.month,
                        ts.day
                    );
                }
            }
        }
    }

    // Load dbx
    if let Some(data) = get_variable_data(&EFI_IMAGE_SECURITY_DATABASE_GUID, DBX_NAME) {
        if !data.is_empty() {
            let mut dbx = dbx_database();
            if let Err(e) = dbx.load_from_signature_lists(&data) {
                log::warn!("Failed to parse dbx variable: {:?}", e);
            } else {
                log::debug!("Loaded {} dbx entries", dbx.len());
                // Restore timestamp
                if let Some(ts) =
                    get_variable_timestamp(&EFI_IMAGE_SECURITY_DATABASE_GUID, DBX_NAME)
                {
                    dbx.set_timestamp(EfiTime::from_serialized(&ts));
                    log::debug!(
                        "Restored dbx timestamp: {}-{:02}-{:02}",
                        ts.year,
                        ts.month,
                        ts.day
                    );
                }
            }
        }
    }

    enrollment::get_enrollment_status()
}

/// Get variable data from the in-memory variable cache
fn get_variable_data(guid: &r_efi::efi::Guid, name: &[u16]) -> Option<Vec<u8>> {
    let mut result: Option<Vec<u8>> = None;

    state::with_efi_mut(|efi| {
        for var in &efi.variables {
            if !var.in_use {
                continue;
            }

            // Compare GUID
            if var.vendor_guid != *guid {
                continue;
            }

            // Compare name
            if !name_matches(&var.name, name) {
                continue;
            }

            // Found the variable - copy data
            let data = var.data[..var.data_size].to_vec();
            result = Some(data);
            break;
        }
    });

    result
}

/// Check if stored name matches the expected name
fn name_matches(stored: &[u16], expected: &[u16]) -> bool {
    // Get effective lengths (up to null terminator)
    let stored_len = stored.iter().position(|&c| c == 0).unwrap_or(stored.len());
    let expected_len = expected
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(expected.len());

    if stored_len != expected_len {
        return false;
    }

    stored[..stored_len] == expected[..expected_len]
}

/// Enroll default keys and persist them to SMMSTORE
fn enroll_and_persist_default_keys() -> Result<(), AuthError> {
    // First, enroll keys in memory
    enrollment::enroll_default_keys()?;

    // Then persist each key database to SMMSTORE
    persist_key_databases()?;

    Ok(())
}

/// Persist all key databases to SMMSTORE as UEFI variables
///
/// This persists each key database along with its timestamp for proper
/// monotonic timestamp validation on future authenticated variable updates.
pub fn persist_key_databases() -> Result<(), AuthError> {
    // Persist PK
    {
        let pk = pk_database();
        if !pk.is_empty() {
            let data = pk.to_signature_lists();
            let timestamp = pk.timestamp().clone();
            if !data.is_empty() {
                persist_key_variable(SecureBootVariable::PK, &data, &timestamp)?;
                log::debug!("Persisted PK ({} bytes)", data.len());
            }
        }
    }

    // Persist KEK
    {
        let kek = kek_database();
        if !kek.is_empty() {
            let data = kek.to_signature_lists();
            let timestamp = kek.timestamp().clone();
            if !data.is_empty() {
                persist_key_variable(SecureBootVariable::KEK, &data, &timestamp)?;
                log::debug!("Persisted KEK ({} bytes)", data.len());
            }
        }
    }

    // Persist db
    {
        let db = db_database();
        if !db.is_empty() {
            let data = db.to_signature_lists();
            let timestamp = db.timestamp().clone();
            if !data.is_empty() {
                persist_key_variable(SecureBootVariable::Db, &data, &timestamp)?;
                log::debug!("Persisted db ({} bytes)", data.len());
            }
        }
    }

    // Persist dbx
    {
        let dbx = dbx_database();
        if !dbx.is_empty() {
            let data = dbx.to_signature_lists();
            let timestamp = dbx.timestamp().clone();
            if !data.is_empty() {
                persist_key_variable(SecureBootVariable::Dbx, &data, &timestamp)?;
                log::debug!("Persisted dbx ({} bytes)", data.len());
            }
        }
    }

    log::info!("Secure Boot key databases persisted to SMMSTORE");
    Ok(())
}

/// Persist a single key variable to SMMSTORE with its timestamp
///
/// The timestamp is preserved for proper monotonic timestamp validation
/// on future authenticated variable updates.
fn persist_key_variable(
    var_type: SecureBootVariable,
    data: &[u8],
    timestamp: &super::structures::EfiTime,
) -> Result<(), AuthError> {
    let (guid, name) = match var_type {
        SecureBootVariable::PK => (EFI_GLOBAL_VARIABLE_GUID, PK_NAME),
        SecureBootVariable::KEK => (EFI_GLOBAL_VARIABLE_GUID, KEK_NAME),
        SecureBootVariable::Db => (EFI_IMAGE_SECURITY_DATABASE_GUID, DB_NAME),
        SecureBootVariable::Dbx => (EFI_IMAGE_SECURITY_DATABASE_GUID, DBX_NAME),
    };

    // Convert EfiTime to SerializedTime for varstore
    let serialized_ts = timestamp.to_serialized();

    // Persist to SMMSTORE with timestamp
    persist_variable_with_timestamp(&guid, name, SECURE_BOOT_KEY_ATTRS, data, serialized_ts)
        .map_err(|e| {
            log::error!("Failed to persist {:?}: {:?}", var_type, e);
            match e {
                VarStoreError::StoreFull => AuthError::BufferTooSmall,
                _ => AuthError::CryptoError,
            }
        })?;

    // Also update in-memory variable cache
    update_variable_in_memory(&guid, name, SECURE_BOOT_KEY_ATTRS, data);

    Ok(())
}

/// Update a variable in the in-memory cache
fn update_variable_in_memory(guid: &r_efi::efi::Guid, name: &[u16], attributes: u32, data: &[u8]) {
    state::with_efi_mut(|efi| {
        // Find existing or free slot
        let existing_idx = efi.variables.iter().position(|var| {
            var.in_use && var.vendor_guid == *guid && name_matches(&var.name, name)
        });

        let idx = match existing_idx {
            Some(i) => i,
            None => match efi.variables.iter().position(|var| !var.in_use) {
                Some(i) => i,
                None => {
                    log::warn!("No free variable slots for status variable");
                    return;
                }
            },
        };

        // Copy name
        let name_len = name.len().min(MAX_VARIABLE_NAME_LEN);
        efi.variables[idx].name[..name_len].copy_from_slice(&name[..name_len]);
        if name_len < MAX_VARIABLE_NAME_LEN {
            efi.variables[idx].name[name_len..].fill(0);
        }

        // Copy data
        let data_len = data.len().min(MAX_VARIABLE_DATA_SIZE);
        efi.variables[idx].data[..data_len].copy_from_slice(&data[..data_len]);

        efi.variables[idx].vendor_guid = *guid;
        efi.variables[idx].attributes = attributes;
        efi.variables[idx].data_size = data_len;
        efi.variables[idx].in_use = true;
    });
}

/// Create or update the SecureBoot and SetupMode status variables
fn create_status_variables() -> Result<(), AuthError> {
    // SetupMode: 1 if in Setup Mode, 0 if in User Mode
    let setup_mode_value: u8 = if is_setup_mode() { 1 } else { 0 };
    update_variable_in_memory(
        &EFI_GLOBAL_VARIABLE_GUID,
        SETUP_MODE_NAME,
        STATUS_VAR_ATTRS,
        &[setup_mode_value],
    );
    log::debug!("SetupMode variable set to {}", setup_mode_value);

    // SecureBoot: 1 if Secure Boot is enabled, 0 otherwise
    let secure_boot_value: u8 = if super::is_secure_boot_enabled() {
        1
    } else {
        0
    };
    update_variable_in_memory(
        &EFI_GLOBAL_VARIABLE_GUID,
        SECURE_BOOT_NAME,
        STATUS_VAR_ATTRS,
        &[secure_boot_value],
    );
    log::debug!("SecureBoot variable set to {}", secure_boot_value);

    Ok(())
}

/// Update status variables after a mode change
///
/// Call this after enter_user_mode() or enter_setup_mode() to keep
/// the status variables in sync.
pub fn update_status_variables() -> Result<(), AuthError> {
    create_status_variables()
}

/// Check if Secure Boot keys are enrolled
///
/// Returns true if at least PK is enrolled (system is in User Mode).
pub fn is_enrolled() -> bool {
    !pk_database().is_empty()
}

/// Get a summary of enrolled keys
pub fn get_enrollment_summary() -> (usize, usize, usize, usize) {
    let pk_count = pk_database().len();
    let kek_count = kek_database().len();
    let db_count = db_database().len();
    let dbx_count = dbx_database().len();
    (pk_count, kek_count, db_count, dbx_count)
}

/// Clear all Secure Boot keys and return to Setup Mode
///
/// This is a dangerous operation that clears all enrolled keys.
/// After clearing, the system returns to Setup Mode and Secure Boot
/// is disabled.
pub fn clear_all_keys() -> Result<(), AuthError> {
    log::warn!("Clearing all Secure Boot keys!");

    // Clear in-memory databases
    {
        let mut pk = pk_database();
        pk.clear();
    }
    {
        let mut kek = kek_database();
        kek.clear();
    }
    {
        let mut db = db_database();
        db.clear();
    }
    {
        let mut dbx = dbx_database();
        dbx.clear();
    }

    // Enter Setup Mode
    enter_setup_mode();

    // Delete persisted variables from SMMSTORE
    // Note: We persist empty data which effectively deletes the variable
    // Use zero timestamp since we're clearing everything
    let zero_ts = super::structures::EfiTime::zero();
    let _ = persist_key_variable(SecureBootVariable::PK, &[], &zero_ts);
    let _ = persist_key_variable(SecureBootVariable::KEK, &[], &zero_ts);
    let _ = persist_key_variable(SecureBootVariable::Db, &[], &zero_ts);
    let _ = persist_key_variable(SecureBootVariable::Dbx, &[], &zero_ts);

    // Update status variables
    update_status_variables()?;

    log::info!("All Secure Boot keys cleared - system in Setup Mode");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_matches() {
        let name1 = [0x50, 0x4B, 0x00]; // "PK\0"
        let name2 = [0x50, 0x4B, 0x00, 0x00, 0x00]; // "PK\0" with padding

        assert!(name_matches(&name1, &name1));
        assert!(name_matches(&name2, &name1));
        assert!(name_matches(&name1, &name2));
    }
}
