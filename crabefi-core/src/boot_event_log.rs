//! Boot event log: one record per boot in a firmware-owned UEFI variable.
//!
//! `CrabEFIEventLog` under the CrabEFI settings GUID (NV|BS|RT) holds a
//! coreboot event log (ELOG, coreboot `commonlib/bsd/elog.h`): an 8-byte
//! header (`"ELOG"`, version 1, header size 8, two 0xff bytes), the events,
//! then 0xff. An event is type, length, BCD year/month/day/hour/minute/second,
//! data and a checksum byte that makes the event sum to zero.
//!
//! Every boot appends `ELOG_TYPE_BOOT` (0x17, little-endian `u32` boot
//! counter, time of this boot) and then the events the platform firmware
//! handed over for this boot (coreboot: CBMEM `ELGB`). The oldest boots are
//! dropped beyond [`MAX_BOOTS`] boots or [`MAX_LOG_SIZE`] bytes. Only firmware
//! writes the log, before the first boot option; SetVariable refuses it.

use alloc::vec::Vec;

use crabefi_runtime_abi::event_log::{EVENT_LOG_VARIABLE_NAME, SETTINGS_VARIABLE_GUID};
use r_efi::efi;

const SIGNATURE: [u8; 4] = *b"ELOG";
const VERSION: u8 = 1;
const HEADER_SIZE: usize = 8;
const EVENT_HEADER_SIZE: usize = 8;
const MAX_EVENT_SIZE: usize = 0x7f;
const TYPE_BOOT: u8 = 0x17;
const TYPE_EOL: u8 = 0xff;

/// Boots kept in the log.
pub const MAX_BOOTS: usize = 32;
/// Size limit of the variable.
pub const MAX_LOG_SIZE: usize = 2048;
/// Platform events kept for one boot.
pub const MAX_BOOT_EVENTS_SIZE: usize = 512;

const ATTRIBUTES: u32 =
    efi::VARIABLE_NON_VOLATILE | efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS;

/// Length of the valid event at the start of `bytes`.
fn event_len(bytes: &[u8]) -> Option<usize> {
    let (&kind, rest) = bytes.split_first()?;
    let len = usize::from(*rest.first()?);
    if kind == TYPE_EOL || len <= EVENT_HEADER_SIZE || len > MAX_EVENT_SIZE || len > bytes.len() {
        return None;
    }
    let sum = bytes[..len]
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    (sum == 0).then_some(len)
}

/// Offsets of the events in `events`, which holds only valid events.
fn offsets(events: &[u8]) -> impl Iterator<Item = usize> + '_ {
    let mut offset = 0;
    core::iter::from_fn(move || {
        let len = event_len(&events[offset..])?;
        offset += len;
        Some(offset - len)
    })
}

/// The valid events of an ELOG image, up to the first end marker or damage.
fn events(log: &[u8]) -> &[u8] {
    let header_ok = log.len() >= HEADER_SIZE
        && log[..4] == SIGNATURE
        && log[4] == VERSION
        && usize::from(log[5]) == HEADER_SIZE;
    if !header_ok {
        return &[];
    }
    let body = &log[HEADER_SIZE..];
    let end = offsets(body).last().map_or(0, |offset| {
        offset + event_len(&body[offset..]).unwrap_or_default()
    });
    &body[..end]
}

/// The platform's events for this boot (an ELOG image), without boot markers,
/// cut at an event boundary to [`MAX_BOOT_EVENTS_SIZE`] bytes.
pub fn platform_events(log: &[u8]) -> Vec<u8> {
    let events = events(log);
    let mut kept = Vec::new();
    for offset in offsets(events) {
        let event = &events[offset..offset + usize::from(events[offset + 1])];
        if event[0] == TYPE_BOOT {
            continue;
        }
        if kept.len() + event.len() > MAX_BOOT_EVENTS_SIZE {
            break;
        }
        kept.extend_from_slice(event);
    }
    kept
}

fn bcd(value: u16) -> u8 {
    let value = (value % 100) as u8;
    ((value / 10) << 4) | (value % 10)
}

fn boot_event(count: u32, time: &efi::Time) -> [u8; EVENT_HEADER_SIZE + 5] {
    let mut event = [0u8; EVENT_HEADER_SIZE + 5];
    event[0] = TYPE_BOOT;
    event[1] = event.len() as u8;
    // A zero date means "time unknown", as in coreboot.
    if time.month != 0 {
        event[2] = bcd(time.year);
        event[3] = bcd(time.month.into());
        event[4] = bcd(time.day.into());
        event[5] = bcd(time.hour.into());
        event[6] = bcd(time.minute.into());
        event[7] = bcd(time.second.into());
    }
    event[8..12].copy_from_slice(&count.to_le_bytes());
    let sum = event.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    event[12] = sum.wrapping_neg();
    event
}

/// Append a boot to `old` (the current log, empty or damaged starts a new
/// one). `platform` holds valid events, see [`platform_events`]. Returns the
/// new log and the number of this boot.
pub fn append(old: &[u8], platform: &[u8], time: &efi::Time) -> (Vec<u8>, u32) {
    let old = events(old);
    let boots: Vec<usize> = offsets(old)
        .filter(|&offset| old[offset] == TYPE_BOOT)
        .collect();
    let count = boots
        .last()
        .and_then(|&offset| old.get(offset + EVENT_HEADER_SIZE..offset + EVENT_HEADER_SIZE + 4))
        .and_then(|bytes| bytes.try_into().ok())
        .map_or(1, |bytes| u32::from_le_bytes(bytes).wrapping_add(1));
    let boot = boot_event(count, time);
    let platform = &platform[..platform.len().min(MAX_BOOT_EVENTS_SIZE)];

    // Drop the oldest boots until this one fits.
    let mut first = 0;
    while boots.len() - first + 1 > MAX_BOOTS
        || HEADER_SIZE + old.len() - boots.get(first).copied().unwrap_or(old.len())
            + boot.len()
            + platform.len()
            + 1
            > MAX_LOG_SIZE
    {
        first += 1;
    }
    let kept = &old[boots.get(first).copied().unwrap_or(old.len())..];

    let mut log = Vec::with_capacity(HEADER_SIZE + kept.len() + boot.len() + platform.len() + 1);
    log.extend_from_slice(&SIGNATURE);
    log.extend_from_slice(&[VERSION, HEADER_SIZE as u8, TYPE_EOL, TYPE_EOL]);
    log.extend_from_slice(kept);
    log.extend_from_slice(&boot);
    log.extend_from_slice(platform);
    log.push(TYPE_EOL);
    (log, count)
}

/// Time of this boot from the Runtime Services clock; zero when unavailable.
fn now() -> efi::Time {
    let mut time = efi::Time {
        year: 0,
        month: 0,
        day: 0,
        hour: 0,
        minute: 0,
        second: 0,
        pad1: 0,
        nanosecond: 0,
        timezone: 0,
        daylight: 0,
        pad2: 0,
    };
    let runtime = crate::efi::runtime_image::client::get_runtime_services();
    if runtime.is_null() {
        return time;
    }
    // SAFETY: runtime points to the validated runtime image table; `time` is
    // a live boot-owned buffer.
    let status = crate::efi::boot_services::with_image_callback(|| unsafe {
        ((*runtime).get_time)(&mut time, core::ptr::null_mut())
    });
    if status != efi::Status::SUCCESS {
        time.month = 0;
    }
    time
}

/// Append this boot to the log. Call once per boot, while the variable store
/// takes firmware writes (before the boot manager runs).
pub fn record_boot() {
    use crate::efi::runtime_image::client::variables;

    let guid = efi::Guid::from_bytes(&SETTINGS_VARIABLE_GUID);
    let old = variables::get(&guid, EVENT_LOG_VARIABLE_NAME)
        .map(|(_, data)| data)
        .unwrap_or_default();
    let platform = crate::handoff::get().boot_events.clone();
    let (log, count) = append(&old, &platform, &now());
    // Never compact the store for the log: see persist_firmware_variable_if_room.
    match crate::efi::varstore::persistence::persist_firmware_variable_if_room(
        &guid,
        EVENT_LOG_VARIABLE_NAME,
        ATTRIBUTES,
        &log,
    ) {
        Ok(()) => log::info!(
            "Boot event log: boot {} with {} bytes of platform events ({} bytes)",
            count,
            platform.len(),
            log.len()
        ),
        Err(error) => log::warn!("Boot event log not written: {:?}", error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time() -> efi::Time {
        efi::Time {
            year: 2026,
            month: 11,
            day: 13,
            hour: 21,
            minute: 7,
            second: 59,
            pad1: 0,
            nanosecond: 0,
            timezone: 0,
            daylight: 0,
            pad2: 0,
        }
    }

    fn event(kind: u8, data: &[u8]) -> Vec<u8> {
        let mut event = alloc::vec![kind, (EVENT_HEADER_SIZE + data.len() + 1) as u8];
        event.extend_from_slice(&[0x26, 0x11, 0x13, 0x21, 0x07, 0x58]);
        event.extend_from_slice(data);
        let sum = event.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        event.push(sum.wrapping_neg());
        event
    }

    fn image(events: &[Vec<u8>]) -> Vec<u8> {
        let mut log = alloc::vec![b'E', b'L', b'O', b'G', 1, 8, 0xff, 0xff];
        for event in events {
            log.extend_from_slice(event);
        }
        log.push(TYPE_EOL);
        log
    }

    fn boots(log: &[u8]) -> Vec<u32> {
        let events = events(log);
        offsets(events)
            .filter(|&offset| events[offset] == TYPE_BOOT)
            .map(|offset| u32::from_le_bytes(events[offset + 8..offset + 12].try_into().unwrap()))
            .collect()
    }

    #[test]
    fn guid_is_the_settings_guid() {
        assert_eq!(
            crate::logger::CRABEFI_SETTINGS_GUID.as_bytes(),
            &SETTINGS_VARIABLE_GUID
        );
    }

    #[test]
    fn first_boot_starts_a_valid_log() {
        let reset = event(0x9a, &[]);
        let platform = platform_events(&image(&[reset.clone()]));
        assert_eq!(platform, reset);

        let (log, count) = append(&[], &platform, &time());
        assert_eq!(count, 1);
        assert_eq!(&log[..8], b"ELOG\x01\x08\xff\xff");
        assert_eq!(*log.last().unwrap(), TYPE_EOL);
        // Boot event: type, length, BCD time, counter, checksum.
        assert_eq!(
            &log[8..20],
            &[
                TYPE_BOOT, 13, 0x26, 0x11, 0x13, 0x21, 0x07, 0x59, 1, 0, 0, 0
            ]
        );
        assert_eq!(event_len(&log[8..]), Some(13));
        assert_eq!(&log[21..21 + reset.len()], &reset[..]);
        assert_eq!(events(&log).len(), log.len() - 9);
    }

    #[test]
    fn boots_count_up_and_the_oldest_are_dropped() {
        let mut log = Vec::new();
        for boot in 1..=MAX_BOOTS as u32 + 3 {
            let (next, count) = append(&log, &[], &time());
            assert_eq!(count, boot);
            log = next;
        }
        let kept = boots(&log);
        assert_eq!(kept.len(), MAX_BOOTS);
        assert_eq!(kept[0], 4);
        assert_eq!(*kept.last().unwrap(), MAX_BOOTS as u32 + 3);
    }

    #[test]
    fn size_limit_drops_whole_boots() {
        let big = event(0xb1, &[0x55; MAX_EVENT_SIZE - EVENT_HEADER_SIZE - 1]);
        let platform = platform_events(&image(&[big.clone(), big.clone(), big.clone()]));
        assert_eq!(platform.len(), 3 * MAX_EVENT_SIZE);
        let mut log = Vec::new();
        for _ in 0..10 {
            log = append(&log, &platform, &time()).0;
            assert!(log.len() <= MAX_LOG_SIZE);
        }
        let kept = boots(&log);
        assert_eq!(*kept.last().unwrap(), 10);
        assert_eq!(kept.len(), (MAX_LOG_SIZE - 9) / (13 + platform.len()));
        // Every kept boot still has all its events.
        assert_eq!(events(&log).len(), kept.len() * (13 + platform.len()));
    }

    #[test]
    fn platform_events_are_bounded_and_boot_markers_dropped() {
        let big = event(0xb1, &[0x55; MAX_EVENT_SIZE - EVENT_HEADER_SIZE - 1]);
        let mut many = alloc::vec![event(TYPE_BOOT, &[9, 0, 0, 0])];
        many.extend(core::iter::repeat_n(big, 8));
        let platform = platform_events(&image(&many));
        assert_eq!(platform.len(), 4 * MAX_EVENT_SIZE);
        assert!(platform.len() <= MAX_BOOT_EVENTS_SIZE);
        assert_eq!(platform[0], 0xb1);
    }

    #[test]
    fn damage_ends_the_events() {
        let mut bad = event(0x9a, &[]);
        bad[8] ^= 1;
        let good = event(0x99, &[]);
        assert_eq!(
            platform_events(&image(&[good.clone(), bad, good.clone()])),
            good
        );
        assert!(platform_events(b"ELOG\x02\x08\xff\xff").is_empty());

        // A damaged log restarts at boot 1.
        let (log, count) = append(b"garbage", &[], &time());
        assert_eq!(count, 1);
        assert_eq!(boots(&log), [1]);
    }

    #[test]
    fn counter_continues_after_the_last_boot() {
        let old = image(&[event(TYPE_BOOT, &[0xfe, 0xff, 0xff, 0xff])]);
        let (log, count) = append(&old, &[], &time());
        assert_eq!(count, u32::MAX);
        let (_, count) = append(&log, &[], &time());
        assert_eq!(count, 0);
    }
}
