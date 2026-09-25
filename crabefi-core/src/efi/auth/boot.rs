//! Secure Boot Boot-Time Initialization
//!
//! This module handles initialization of Secure Boot state at boot time:
//!
//! 1. Load Secure Boot keys from persisted UEFI variables (PK, KEK, db, dbx)
//! 2. Check enrollment status and optionally enroll default keys
//! 3. Create/update SecureBoot and SetupMode status variables
//! 4. Persist newly enrolled keys to persistent variable storage
//!
//! # Boot Flow
//!
//! ```text
//! variable persistence initialization loads variables from storage
//!         |
//!         v
//! init_secure_boot() is called:
//!   1. Load PK/KEK/db/dbx from the authoritative runtime image store
//!   2. If PK exists -> enter User Mode
//!   3. Create SecureBoot/SetupMode variables
//!   4. Optionally enroll default keys if none exist
//! ```

use alloc::vec::Vec;

use crabefi_efi_types::{
    authentication::EfiTime,
    secure_boot::{
        DB_NAME, DBX_NAME, EFI_CERT_TYPE_PKCS7_GUID, EFI_GLOBAL_VARIABLE_GUID,
        EFI_IMAGE_SECURITY_DATABASE_GUID, KEK_NAME, PK_NAME, SECURE_BOOT_ENABLE_NAME,
        SecureBootVariable,
    },
};
use crabefi_pkcs7::time::DateTime;
use crabefi_runtime_abi::VariableTimestamp;
use r_efi::efi::Guid;

use super::enrollment::{self, EnrollmentStatus};
use super::variables::{KeyDatabase, db_database, dbx_database, kek_database, pk_database};
use super::{AuthError, enter_setup_mode, enter_user_mode, is_setup_mode};
use crate::efi::varstore::get_variable_timestamp;

/// Variable attributes for Secure Boot key variables
const SECURE_BOOT_KEY_ATTRS: u32 = super::attributes::NON_VOLATILE
    | super::attributes::BOOTSERVICE_ACCESS
    | super::attributes::RUNTIME_ACCESS
    | super::attributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

struct DatabaseSnapshot {
    initialized: bool,
    data: Option<Vec<u8>>,
}

impl DatabaseSnapshot {
    const fn new() -> Self {
        Self {
            initialized: false,
            data: None,
        }
    }

    fn matches(&self, data: Option<&[u8]>) -> bool {
        self.initialized && self.data.as_deref() == data
    }
}

static KEY_DATABASE_SNAPSHOTS: spin::Mutex<[DatabaseSnapshot; 4]> =
    spin::Mutex::new([const { DatabaseSnapshot::new() }; 4]);

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
/// This should be called after variable persistence has loaded variables from storage.
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

    // Step 5: Load and apply SecureBootEnable preference from persistent storage
    // This is the user's saved preference from previous boot
    if !is_setup_mode() {
        if config.enable_secure_boot && !load_secure_boot_enable_preference() {
            super::enable_secure_boot();
        }
        if super::is_secure_boot_enabled() {
            log::info!("Secure Boot: Enabled (from persisted preference)");
        }
    }

    // Return final enrollment status
    Ok(enrollment::get_enrollment_status())
}

/// Load the SecureBootEnable preference from persistent storage.
///
/// Returns true if Secure Boot was previously enabled by the user.
/// Called during boot initialization and by
/// `handle_secure_boot_variable_update()` when PK is enrolled at runtime.
pub fn load_secure_boot_enable_preference() -> bool {
    if let Some(data) = get_variable_data(
        &Guid::from_bytes(&EFI_GLOBAL_VARIABLE_GUID),
        SECURE_BOOT_ENABLE_NAME,
    ) && !data.is_empty()
        && data[0] == 1
    {
        log::debug!("Loaded SecureBootEnable preference: enabled");
        return true;
    }
    log::debug!("SecureBootEnable preference not set or disabled");
    false
}

/// Initialize Secure Boot with default configuration
pub fn init_secure_boot_default() -> Result<EnrollmentStatus, AuthError> {
    init_secure_boot(&SecureBootConfig::default())
}

/// Load Secure Boot keys from image-owned UEFI variables.
///
/// This reads the PK, KEK, db, and dbx values imported from SMMSTORE into the
/// authoritative runtime image store and populates disposable boot-only key
/// databases. It also restores timestamps for proper
/// monotonic timestamp validation on future authenticated variable updates.
fn load_keys_from_variables() -> EnrollmentStatus {
    for variable in [
        SecureBootVariable::PK,
        SecureBootVariable::Kek,
        SecureBootVariable::Db,
        SecureBootVariable::Dbx,
    ] {
        refresh_key_database(variable, true, true);
    }
    enrollment::get_enrollment_status()
}

fn key_database(variable: SecureBootVariable) -> spin::MutexGuard<'static, KeyDatabase> {
    match variable {
        SecureBootVariable::PK => pk_database(),
        SecureBootVariable::Kek => kek_database(),
        SecureBootVariable::Db => db_database(),
        SecureBootVariable::Dbx => dbx_database(),
    }
}

fn refresh_key_database(
    variable: SecureBootVariable,
    restore_persistent_timestamp: bool,
    force: bool,
) {
    let guid = Guid::from_bytes(variable.guid());
    let data = get_variable_data(&guid, variable.name());
    if !force && KEY_DATABASE_SNAPSHOTS.lock()[variable.index()].matches(data.as_deref()) {
        return;
    }

    let mut database = key_database(variable);
    database.clear();
    if let Some(value) = data.as_deref()
        && !value.is_empty()
    {
        if let Err(error) = database.load_from_signature_lists(value) {
            log::warn!("Failed to parse {:?} variable: {:?}", variable, error);
        } else {
            log::debug!("Loaded {} {:?} entries", database.len(), variable);
            if restore_persistent_timestamp
                && let Some(timestamp) = get_variable_timestamp(&guid, variable.name())
            {
                database.set_timestamp(efi_time_from_timestamp(timestamp));
                log::debug!(
                    "Restored {:?} timestamp: {}-{:02}-{:02}",
                    variable,
                    timestamp.year,
                    timestamp.month,
                    timestamp.day
                );
            }
        }
    }
    drop(database);

    let mut snapshots = KEY_DATABASE_SNAPSHOTS.lock();
    snapshots[variable.index()] = DatabaseSnapshot {
        initialized: true,
        data,
    };
}

/// Refresh boot-only Authenticode key caches from authoritative runtime-store
/// snapshots. Unchanged values are not reparsed, and this verification-only
/// path deliberately avoids persistent-store timestamp walks.
pub(crate) fn refresh_key_databases() {
    refresh_key_databases_with_force(false);
}

fn force_refresh_key_databases() {
    refresh_key_databases_with_force(true);
}

fn refresh_key_databases_with_force(force: bool) {
    for variable in [
        SecureBootVariable::PK,
        SecureBootVariable::Kek,
        SecureBootVariable::Db,
        SecureBootVariable::Dbx,
    ] {
        refresh_key_database(variable, false, force);
    }
}

/// Get variable data from the authoritative runtime image store.
fn get_variable_data(guid: &Guid, name: &[u16]) -> Option<Vec<u8>> {
    crate::efi::runtime_image::client::variables::get(guid, name).map(|(_, data)| data)
}

fn efi_time_from_timestamp(timestamp: VariableTimestamp) -> EfiTime {
    EfiTime {
        year: timestamp.year,
        month: timestamp.month,
        day: timestamp.day,
        hour: timestamp.hour,
        minute: timestamp.minute,
        second: timestamp.second,
        pad1: timestamp.pad1,
        nanosecond: timestamp.nanosecond,
        timezone: timestamp.timezone,
        daylight: timestamp.daylight,
        pad2: timestamp.pad2,
    }
}

// name_matches consolidated into crate::efi::utils::ucs2_eq

/// Enroll the default keys through the authoritative variable-store path.
///
/// Enrollment is only allowed in Setup Mode. Existing boot-only caches are
/// discarded first so retrying after a partial failed enrollment cannot append
/// duplicate certificates.
pub fn enroll_and_persist_default_keys() -> Result<(), AuthError> {
    if !is_setup_mode() {
        return Err(AuthError::AccessDenied);
    }

    for variable in [
        SecureBootVariable::PK,
        SecureBootVariable::Kek,
        SecureBootVariable::Db,
        SecureBootVariable::Dbx,
    ] {
        key_database(variable).clear();
    }

    if let Err(error) = enrollment::enroll_default_keys().and_then(|()| persist_key_databases()) {
        // Persistence may have committed only a prefix of the databases. Make
        // the runtime store authoritative again before returning to the UI.
        force_refresh_key_databases();
        return Err(error);
    }

    force_refresh_key_databases();
    Ok(())
}

/// Persist all key databases to SMMSTORE as UEFI variables
///
/// This persists each key database along with its timestamp for proper
/// monotonic timestamp validation on future authenticated variable updates.
pub fn persist_key_databases() -> Result<(), AuthError> {
    // Persist KEK, db, and dbx while the image remains in Setup Mode. PK is
    // deliberately enrolled last because that standard SetVariable call
    // transitions the image into User Mode.
    // Persist KEK
    {
        let kek = kek_database();
        if !kek.is_empty() {
            let data = kek.to_signature_lists();
            if !data.is_empty() {
                persist_key_variable(SecureBootVariable::Kek, &data)?;
                log::debug!("Persisted KEK ({} bytes)", data.len());
            }
        }
    }

    // Persist db
    {
        let db = db_database();
        if !db.is_empty() {
            let data = db.to_signature_lists();
            if !data.is_empty() {
                persist_key_variable(SecureBootVariable::Db, &data)?;
                log::debug!("Persisted db ({} bytes)", data.len());
            }
        }
    }

    // Persist dbx
    {
        let dbx = dbx_database();
        if !dbx.is_empty() {
            let data = dbx.to_signature_lists();
            if !data.is_empty() {
                persist_key_variable(SecureBootVariable::Dbx, &data)?;
                log::debug!("Persisted dbx ({} bytes)", data.len());
            }
        }
    }

    // Persist PK last: its commit enters User Mode.
    {
        let pk = pk_database();
        if !pk.is_empty() {
            let data = pk.to_signature_lists();
            if !data.is_empty() {
                persist_key_variable(SecureBootVariable::PK, &data)?;
                log::debug!("Persisted PK ({} bytes)", data.len());
            }
        }
    }

    // Keep snapshots synchronized with the authoritative runtime variables.
    force_refresh_key_databases();
    log::info!("Secure Boot key databases persisted to SMMSTORE");
    Ok(())
}

include!(concat!(env!("OUT_DIR"), "/source_date_epoch.rs"));

/// 2025-01-01T00:00:00Z: floor for builds without a usable `SOURCE_DATE_EPOCH`.
const FIRMWARE_TIMESTAMP_FLOOR: i64 = 1_735_689_600;

/// Latest timestamp this boot issued for each key database, in Unix seconds.
static ISSUED_TIMESTAMPS: spin::Mutex<[i64; 4]> = spin::Mutex::new([i64::MIN; 4]);

/// Timestamp for a key-database write made by the firmware itself.
///
/// Authenticated writes must be strictly newer than the last accepted one,
/// including deletions. The firmware has no trustworthy clock, so it uses one
/// second after the latest known timestamp for the variable, but never less
/// than the date CrabEFI was built from. That keeps default-key enrollment,
/// clearing and re-enrollment working without an RTC, and a wrong RTC can no
/// longer push timestamps into the future.
fn next_firmware_timestamp(variable: SecureBootVariable, guid: &Guid, name: &[u16]) -> EfiTime {
    let persisted = get_variable_timestamp(guid, name)
        .map(|timestamp| utc_seconds(&efi_time_from_timestamp(timestamp)));
    let mut issued = ISSUED_TIMESTAMPS.lock();
    let previous = persisted
        .into_iter()
        .fold(issued[variable.index()], i64::max);
    let next = next_timestamp_after(previous);
    issued[variable.index()] = next;
    efi_time_from_unix(next)
}

/// One second after `previous`, but at least the build date.
fn next_timestamp_after(previous: i64) -> i64 {
    let build_date = i64::try_from(SOURCE_DATE_EPOCH).unwrap_or(i64::MAX);
    previous
        .saturating_add(1)
        .max(build_date)
        .max(FIRMWARE_TIMESTAMP_FLOOR)
}

const EFI_UNSPECIFIED_TIMEZONE: i16 = 0x7FF;

/// Unix seconds of an EFI timestamp, honouring its timezone offset.
fn utc_seconds(time: &EfiTime) -> i64 {
    let local = DateTime {
        year: time.year,
        month: time.month,
        day: time.day,
        hour: time.hour,
        minute: time.minute,
        second: time.second,
    }
    .unix_timestamp();
    match time.timezone {
        EFI_UNSPECIFIED_TIMEZONE => local,
        // Same convention as `EfiTime::is_after`, which enforces ordering.
        timezone => local - i64::from(timezone) * 60,
    }
}

/// UTC `EfiTime` for Unix seconds (civil-from-days, Howard Hinnant).
fn efi_time_from_unix(seconds: i64) -> EfiTime {
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = era * 400 + year_of_era + i64::from(month <= 2);
    EfiTime {
        year: year as u16,
        month: month as u8,
        day: day as u8,
        hour: (second_of_day / 3_600) as u8,
        minute: (second_of_day / 60 % 60) as u8,
        second: (second_of_day % 60) as u8,
        timezone: EFI_UNSPECIFIED_TIMEZONE,
        ..EfiTime::zero()
    }
}

/// Persist a single key variable to SMMSTORE
///
/// The write carries [`next_firmware_timestamp`], so it passes the same
/// monotonic timestamp check as any other authenticated update.
fn persist_key_variable(var_type: SecureBootVariable, data: &[u8]) -> Result<(), AuthError> {
    let (guid, name) = match var_type {
        SecureBootVariable::PK => (Guid::from_bytes(&EFI_GLOBAL_VARIABLE_GUID), PK_NAME),
        SecureBootVariable::Kek => (Guid::from_bytes(&EFI_GLOBAL_VARIABLE_GUID), KEK_NAME),
        SecureBootVariable::Db => (Guid::from_bytes(&EFI_IMAGE_SECURITY_DATABASE_GUID), DB_NAME),
        SecureBootVariable::Dbx => (
            Guid::from_bytes(&EFI_IMAGE_SECURITY_DATABASE_GUID),
            DBX_NAME,
        ),
    };

    use zerocopy::IntoBytes;

    let timestamp = next_firmware_timestamp(var_type, &guid, name);
    let mut envelope = Vec::new();
    envelope
        .try_reserve_exact(40usize.saturating_add(data.len()))
        .map_err(|_| AuthError::BufferTooSmall)?;
    envelope.extend_from_slice(timestamp.as_bytes());
    envelope.extend_from_slice(&24u32.to_le_bytes());
    envelope.extend_from_slice(&super::WIN_CERT_REVISION.to_le_bytes());
    envelope.extend_from_slice(&super::WIN_CERT_TYPE_EFI_GUID.to_le_bytes());
    envelope.extend_from_slice(&EFI_CERT_TYPE_PKCS7_GUID);
    envelope.extend_from_slice(data);

    let status = crate::efi::runtime_image::client::variables::set(
        &guid,
        name,
        SECURE_BOOT_KEY_ATTRS,
        &envelope,
    );
    if status == r_efi::efi::Status::SUCCESS
        || (data.is_empty() && status == r_efi::efi::Status::NOT_FOUND)
    {
        // Clear-all is idempotent in Setup Mode; preserve ordinary public
        // SetVariable semantics while accepting an already-absent key here.
        Ok(())
    } else if status == r_efi::efi::Status::OUT_OF_RESOURCES {
        Err(AuthError::BufferTooSmall)
    } else {
        log::error!(
            "SetVariable rejected {:?} enrollment: {:?}",
            var_type,
            status
        );
        Err(AuthError::CryptoError)
    }
}

/// Create or update the SecureBoot and SetupMode status variables
fn create_status_variables() -> Result<(), AuthError> {
    // SetupMode and SecureBoot are synthesized read-only by the runtime image.
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
    log::warn!("Clearing all Secure Boot keys by physical-presence setup action!");

    // Public SetVariable correctly rejects an unsigned PK deletion in User
    // Mode, even when signature verification has been disabled. Firmware setup
    // is the physical-presence authority, so remove PK through the privileged
    // pre-boot persistence/import path first. This transitions the live policy
    // into Setup Mode; the remaining databases can then use ordinary unsigned
    // SetVariable deletes.
    if !is_setup_mode() {
        let guid = Guid::from_bytes(&EFI_GLOBAL_VARIABLE_GUID);
        if crate::efi::varstore::persistence::persist_firmware_variable(
            &guid,
            PK_NAME,
            SECURE_BOOT_KEY_ATTRS,
            &[],
        )
        .is_err()
        {
            force_refresh_key_databases();
            return Err(AuthError::CryptoError);
        }
        force_refresh_key_databases();
        if !is_setup_mode() {
            return Err(AuthError::AccessDenied);
        }
    }

    for variable in [
        SecureBootVariable::Dbx,
        SecureBootVariable::Db,
        SecureBootVariable::Kek,
    ] {
        if let Err(error) = persist_key_variable(variable, &[]) {
            // A preceding delete may already have changed live image policy.
            // Always reconcile disposable boot caches before reporting failure.
            force_refresh_key_databases();
            return Err(error);
        }
    }

    // An already-absent variable is an idempotent delete, but stale boot-only
    // caches must still be discarded.
    force_refresh_key_databases();
    update_status_variables()?;
    log::info!("All Secure Boot keys cleared - system in Setup Mode");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DatabaseSnapshot, EFI_UNSPECIFIED_TIMEZONE, FIRMWARE_TIMESTAMP_FLOOR, SOURCE_DATE_EPOCH,
        efi_time_from_unix, next_timestamp_after, utc_seconds,
    };
    use crate::efi::utils::ucs2_eq;
    use alloc::vec;
    use crabefi_efi_types::authentication::EfiTime;

    #[test]
    fn test_ucs2_eq() {
        let name1 = [0x50, 0x4B, 0x00]; // "PK\0"
        let name2 = [0x50, 0x4B, 0x00, 0x00, 0x00]; // "PK\0" with padding

        assert!(ucs2_eq(&name1, &name1));
        assert!(ucs2_eq(&name2, &name1));
        assert!(ucs2_eq(&name1, &name2));
    }

    #[test]
    fn database_snapshot_detects_authoritative_content_changes() {
        let mut snapshot = DatabaseSnapshot::new();
        assert!(!snapshot.matches(None));
        snapshot.initialized = true;
        assert!(snapshot.matches(None));
        snapshot.data = Some(vec![1, 2, 3]);
        assert!(snapshot.matches(Some(&[1, 2, 3])));
        assert!(!snapshot.matches(Some(&[1, 2, 4])));
        assert!(!snapshot.matches(None));
    }

    fn date(time: &EfiTime) -> (u16, u8, u8, u8, u8, u8) {
        (
            time.year,
            time.month,
            time.day,
            time.hour,
            time.minute,
            time.second,
        )
    }

    #[test]
    fn efi_time_from_unix_matches_known_dates() {
        for (seconds, expected) in [
            (0, (1970, 1, 1, 0, 0, 0)),
            (951_782_400, (2000, 2, 29, 0, 0, 0)),
            (1_790_368_857, (2026, 9, 25, 20, 40, 57)),
            (253_402_300_799, (9999, 12, 31, 23, 59, 59)),
        ] {
            let time = efi_time_from_unix(seconds);
            assert_eq!(date(&time), expected);
            assert!(time.is_valid());
            assert_eq!(utc_seconds(&time), seconds);
        }
    }

    #[test]
    fn firmware_timestamps_start_at_the_build_date() {
        let build_date = i64::try_from(SOURCE_DATE_EPOCH)
            .unwrap()
            .max(FIRMWARE_TIMESTAMP_FLOOR);
        assert_eq!(next_timestamp_after(i64::MIN), build_date);
        assert_eq!(next_timestamp_after(0), build_date);
        assert_eq!(next_timestamp_after(build_date), build_date + 1);
    }

    #[test]
    fn firmware_timestamps_follow_any_previous_timezone() {
        for timezone in [-1440, -60, 0, 60, 1440, EFI_UNSPECIFIED_TIMEZONE] {
            let previous = EfiTime {
                timezone,
                nanosecond: 999_999_999,
                ..efi_time_from_unix(4_102_444_800) // 2100-01-01
            };
            let next = efi_time_from_unix(next_timestamp_after(utc_seconds(&previous)));
            assert!(next.is_valid());
            assert!(next.is_after(&previous), "timezone {timezone}");
        }
    }
}
