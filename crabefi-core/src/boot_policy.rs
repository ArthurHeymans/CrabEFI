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
}

static POLICY: LocalCell<BootPolicy> = LocalCell::new(BootPolicy {
    usb_init: UsbInit::Always,
    external_boot: ExternalBoot::Allow,
});

/// Name of the variable that can tighten [`BootPolicy::external_boot`].
pub const EXTERNAL_BOOT_VARIABLE_NAME: &str = "CrabEFIExternalBoot";

/// NV+BS: settable before ExitBootServices only.
const EXTERNAL_BOOT_VARIABLE_ATTRS: u32 =
    crate::efi::auth::attributes::NON_VOLATILE | crate::efi::auth::attributes::BOOTSERVICE_ACCESS;

pub(crate) fn configure(policy: BootPolicy) {
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

/// The platform setting tightened by a well-formed variable, never loosened.
fn tightened(platform: ExternalBoot, attributes: u32, data: &[u8]) -> Option<ExternalBoot> {
    parse_external_boot(attributes, data).map(|value| platform.max(value))
}

/// Apply `CrabEFIExternalBoot` once the variable store is authoritative.
pub(crate) fn apply_variable() {
    use crate::efi::runtime_image::client::variables;

    let name: alloc::vec::Vec<u16> = EXTERNAL_BOOT_VARIABLE_NAME
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();
    let mut policy = get();
    if let Some((attributes, data)) = variables::get(&crate::logger::CRABEFI_SETTINGS_GUID, &name) {
        match tightened(policy.external_boot, attributes, &data) {
            Some(value) => policy.external_boot = value,
            None => log::warn!("Ignoring malformed {}", EXTERNAL_BOOT_VARIABLE_NAME),
        }
    }
    configure(policy);
    log::info!(
        "Boot policy: USB {:?}, external boot {:?}",
        policy.usb_init,
        policy.external_boot
    );
}

/// USB and removable media count as external.
pub(crate) fn is_external(id: StorageId, removable: bool) -> bool {
    matches!(id, StorageId::Usb { .. }) || removable
}

pub(crate) fn device_is_external(device: &StorageDevice) -> bool {
    is_external(device.id, device.info.removable)
}

pub(crate) fn storage_is_external(id: StorageId) -> bool {
    is_external(
        id,
        storage::with_disk(id, |disk| disk.info().removable).unwrap_or(true),
    )
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
        assert_eq!(tightened(Allow, NV_BS, &[2]), Some(Deny));
        assert_eq!(tightened(Allow, NV_BS, &[1]), Some(MenuOnly));
        assert_eq!(tightened(MenuOnly, NV_BS, &[0]), Some(MenuOnly));
        assert_eq!(tightened(Deny, NV_BS, &[0]), Some(Deny));
        assert_eq!(tightened(Deny, NV_BS, &[1]), Some(Deny));
        assert_eq!(tightened(Allow, NV_BS | 4, &[2]), None);
    }

    #[test]
    fn usb_and_removable_media_are_external() {
        let usb = StorageId::Usb {
            controller_id: 0,
            device_addr: 1,
        };
        let nvme = StorageId::Nvme {
            controller_id: 0,
            nsid: 1,
        };
        let sd = StorageId::Sdhci { controller_id: 0 };
        assert!(is_external(usb, false));
        assert!(!is_external(nvme, false));
        assert!(is_external(sd, true));
        assert!(!is_external(sd, false));
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
