//! Boot device policy: when USB comes up and which media may boot.
//!
//! The platform selects both settings through [`crate::PlatformConfig`].
//! The NV+BS-only `CrabEFIExternalBoot` variable can tighten, never loosen,
//! the platform's external-media setting; the OS cannot write it after
//! ExitBootServices.

use crate::cell::LocalCell;
use crate::drivers::storage::{self, StorageDevice, StorageId};

/// When CrabEFI brings up USB host controllers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UsbInit {
    /// Before boot dispatch, like every other controller.
    #[default]
    Always,
    /// Only when no internal boot option starts, or for the boot menu.
    OnDemand,
}

/// Whether external media (USB and removable devices) may boot.
///
/// Ordered from least to most restrictive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExternalBoot {
    /// Boot external media like internal storage.
    #[default]
    Allow,
    /// Automatic boot (BootNext, BootOrder, menu timeout) uses internal
    /// storage only; a user may still select external media in the menu.
    MenuOnly,
    /// Never boot external media.
    Deny,
}

/// Boot device policy selected by the platform.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BootPolicy {
    pub usb_init: UsbInit,
    pub external_boot: ExternalBoot,
    /// Treat SATA ports the controller reports as hot-plug capable as
    /// internal. Hot-plug ports are usually drive bays and count as external
    /// media, but some desktop boards mark every connector hot-plug capable;
    /// such boards set this so the external-boot policy does not hide their
    /// system disk. eSATA ports and removable media stay external.
    pub internal_hot_plug_sata: bool,
}

static POLICY: LocalCell<BootPolicy> = LocalCell::new(BootPolicy {
    usb_init: UsbInit::Always,
    external_boot: ExternalBoot::Allow,
    internal_hot_plug_sata: false,
});

/// The platform's external-boot setting, before `CrabEFIExternalBoot`.
static PLATFORM_EXTERNAL_BOOT: LocalCell<ExternalBoot> = LocalCell::new(ExternalBoot::Allow);

/// Name of the variable that can tighten [`BootPolicy::external_boot`].
pub const EXTERNAL_BOOT_VARIABLE_NAME: &str = "CrabEFIExternalBoot";

/// NV+BS: settable before ExitBootServices only.
const EXTERNAL_BOOT_VARIABLE_ATTRS: u32 =
    crate::efi::auth::attributes::NON_VOLATILE | crate::efi::auth::attributes::BOOTSERVICE_ACCESS;

pub(crate) fn configure(policy: BootPolicy) {
    PLATFORM_EXTERNAL_BOOT.set(policy.external_boot);
    POLICY.set(policy);
}

pub(crate) fn get() -> BootPolicy {
    POLICY.get()
}

/// Decode the tightening variable; anything but NV+BS and one known byte is ignored.
fn parse_external_boot(attributes: u32, data: &[u8]) -> Option<ExternalBoot> {
    if attributes != EXTERNAL_BOOT_VARIABLE_ATTRS {
        return None;
    }
    match data {
        [0] => Some(ExternalBoot::Allow),
        [1] => Some(ExternalBoot::MenuOnly),
        [2] => Some(ExternalBoot::Deny),
        _ => None,
    }
}

/// The platform setting tightened by the variable, never loosened. The
/// variable exists only to tighten, so a malformed one fails closed to
/// [`ExternalBoot::Deny`]; the setup menu rewrites it.
fn tightened(platform: ExternalBoot, attributes: u32, data: &[u8]) -> ExternalBoot {
    platform.max(parse_external_boot(attributes, data).unwrap_or(ExternalBoot::Deny))
}

fn variable_name() -> alloc::vec::Vec<u16> {
    EXTERNAL_BOOT_VARIABLE_NAME
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect()
}

/// Apply `CrabEFIExternalBoot` once the variable store is authoritative.
pub(crate) fn apply_variable() {
    use crate::efi::runtime_image::client::variables;

    let mut policy = get();
    if let Some((attributes, data)) =
        variables::get(&crate::logger::CRABEFI_SETTINGS_GUID, &variable_name())
    {
        if parse_external_boot(attributes, &data).is_none() {
            log::error!(
                "Malformed {}: denying external boot",
                EXTERNAL_BOOT_VARIABLE_NAME
            );
        }
        policy.external_boot = tightened(policy.external_boot, attributes, &data);
    }
    POLICY.set(policy);
    log::info!(
        "Boot policy: USB {:?}, external boot {:?}",
        policy.usb_init,
        policy.external_boot
    );
}

/// The setup menu's floor and current value, as variable bytes: the
/// platform setting and the effective policy.
pub(crate) fn external_boot_setting() -> (u8, u8) {
    (
        PLATFORM_EXTERNAL_BOOT.get() as u8,
        get().external_boot as u8,
    )
}

/// Persist a setup-menu choice and apply it to this boot. Only a byte
/// [`parse_external_boot`] accepts is written, with its attributes.
pub(crate) fn set_external_boot(byte: u8) -> Result<(), r_efi::efi::Status> {
    use crate::efi::runtime_image::client::variables;

    let data = [byte];
    let value = parse_external_boot(EXTERNAL_BOOT_VARIABLE_ATTRS, &data)
        .ok_or(r_efi::efi::Status::INVALID_PARAMETER)?;
    // A variable with other attributes (say one the OS created at runtime)
    // denies external boot as malformed, and SetVariable refuses to change
    // its attributes: replace it.
    if let Some((attributes, _)) =
        variables::get(&crate::logger::CRABEFI_SETTINGS_GUID, &variable_name())
        && attributes != EXTERNAL_BOOT_VARIABLE_ATTRS
    {
        let status = variables::delete(&crate::logger::CRABEFI_SETTINGS_GUID, &variable_name());
        if status != r_efi::efi::Status::SUCCESS {
            return Err(status);
        }
    }
    let status = variables::set(
        &crate::logger::CRABEFI_SETTINGS_GUID,
        &variable_name(),
        EXTERNAL_BOOT_VARIABLE_ATTRS,
        &data,
    );
    if status != r_efi::efi::Status::SUCCESS {
        return Err(status);
    }
    let mut policy = get();
    policy.external_boot = PLATFORM_EXTERNAL_BOOT.get().max(value);
    POLICY.set(policy);
    Ok(())
}

/// USB, removable media and SATA devices on external or hot-plug capable
/// ports count as external ([`StorageDevice::external`]).
pub(crate) fn device_is_external(device: &StorageDevice) -> bool {
    device.external
}

/// Like [`device_is_external`]; a device that is gone counts as external.
pub(crate) fn storage_is_external(id: StorageId) -> bool {
    storage::is_external(id).unwrap_or(true)
}

const fn automatic_allowed(policy: ExternalBoot, external: bool) -> bool {
    !external || matches!(policy, ExternalBoot::Allow)
}

const fn menu_allowed(policy: ExternalBoot, external: bool) -> bool {
    !external || !matches!(policy, ExternalBoot::Deny)
}

/// May BootNext, BootOrder or a menu timeout start an image from `device`?
pub(crate) fn automatic_boot_allowed(device: &StorageDevice) -> bool {
    let allowed = automatic_allowed(get().external_boot, device_is_external(device));
    if !allowed {
        log::info!(
            "Boot policy: {} is external; not booting it automatically",
            device.label
        );
    }
    allowed
}

/// May the boot menu offer `device`?
pub(crate) fn menu_boot_allowed(device: &StorageDevice) -> bool {
    let allowed = menu_allowed(get().external_boot, device_is_external(device));
    if !allowed {
        log::info!("Boot policy: {} is external; hiding it", device.label);
    }
    allowed
}

/// May the menu start the entry on `id` now? `automatic` when its countdown
/// chose the entry rather than the user.
pub(crate) fn dispatch_allowed(id: StorageId, automatic: bool) -> bool {
    let policy = get().external_boot;
    let external = storage_is_external(id);
    if automatic {
        automatic_allowed(policy, external)
    } else {
        menu_allowed(policy, external)
    }
}

/// May automatic boot use external media at all?
pub(crate) fn automatic_external_allowed() -> bool {
    automatic_allowed(get().external_boot, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NV_BS: u32 = EXTERNAL_BOOT_VARIABLE_ATTRS;

    #[test]
    fn variable_requires_boot_service_only_attributes_and_one_known_byte() {
        assert_eq!(parse_external_boot(NV_BS, &[0]), Some(ExternalBoot::Allow));
        assert_eq!(
            parse_external_boot(NV_BS, &[1]),
            Some(ExternalBoot::MenuOnly)
        );
        assert_eq!(parse_external_boot(NV_BS, &[2]), Some(ExternalBoot::Deny));
        // Runtime-accessible copies could come from the OS.
        assert_eq!(parse_external_boot(NV_BS | 4, &[2]), None);
        assert_eq!(parse_external_boot(NV_BS, &[3]), None);
        assert_eq!(parse_external_boot(NV_BS, &[2, 0]), None);
        assert_eq!(parse_external_boot(NV_BS, &[]), None);
    }

    #[test]
    fn variable_only_tightens() {
        use ExternalBoot::*;
        assert_eq!(tightened(Allow, NV_BS, &[2]), Deny);
        assert_eq!(tightened(Allow, NV_BS, &[1]), MenuOnly);
        assert_eq!(tightened(MenuOnly, NV_BS, &[0]), MenuOnly);
        assert_eq!(tightened(Deny, NV_BS, &[0]), Deny);
        assert_eq!(tightened(Deny, NV_BS, &[1]), Deny);
    }

    #[test]
    fn malformed_variable_denies_external_boot() {
        use ExternalBoot::*;
        for platform in [Allow, MenuOnly, Deny] {
            assert_eq!(tightened(platform, NV_BS | 4, &[0]), Deny);
            assert_eq!(tightened(platform, NV_BS, &[3]), Deny);
            assert_eq!(tightened(platform, NV_BS, &[0, 0]), Deny);
            assert_eq!(tightened(platform, NV_BS, &[]), Deny);
        }
    }

    #[test]
    fn setting_bytes_are_the_variable_encoding() {
        use ExternalBoot::*;
        for value in [Allow, MenuOnly, Deny] {
            assert_eq!(parse_external_boot(NV_BS, &[value as u8]), Some(value));
        }
    }

    #[test]
    fn the_runtime_image_reserves_this_variable() {
        use crabefi_runtime_abi::settings::{EXTERNAL_BOOT_NAME, SETTINGS_GUID};
        assert_eq!(
            &SETTINGS_GUID,
            crate::logger::CRABEFI_SETTINGS_GUID.as_bytes()
        );
        let name = variable_name();
        assert_eq!(&name[..name.len() - 1], EXTERNAL_BOOT_NAME);
    }

    #[test]
    fn policy_matrix() {
        use ExternalBoot::*;
        for policy in [Allow, MenuOnly, Deny] {
            assert!(automatic_allowed(policy, false));
            assert!(menu_allowed(policy, false));
        }
        assert!(automatic_allowed(Allow, true));
        assert!(!automatic_allowed(MenuOnly, true));
        assert!(!automatic_allowed(Deny, true));
        assert!(menu_allowed(Allow, true));
        assert!(menu_allowed(MenuOnly, true));
        assert!(!menu_allowed(Deny, true));
    }
}
