//! Coreboot timestamp table support.
//!
//! Coreboot stores boot timestamps in a CBMEM table and exposes its address via
//! `CB_TAG_TIMESTAMPS`. Payloads may append their own entries so `cbmem -t`
//! shows a combined firmware-to-payload timeline.
//!
//! The table layout matches coreboot's serialized timestamp table:
//!
//! ```text
//! +0x00: base_time     u64
//! +0x08: max_entries   u16
//! +0x0a: tick_freq_mhz u16
//! +0x0c: num_entries   u32
//! +0x10: entries[]     { u32 entry_id, i64 entry_stamp }
//! ```
//!
//! Entry stamps are relative to `base_time`.

/// Coreboot timestamp table header.
#[repr(C, packed)]
struct TimestampTable {
    base_time: u64,
    max_entries: u16,
    tick_freq_mhz: u16,
    num_entries: u32,
}

/// Coreboot timestamp table entry.
#[repr(C, packed)]
struct TimestampEntry {
    entry_id: u32,
    entry_stamp: i64,
}

/// Recorder that appends CrabEFI milestones to coreboot's timestamp table.
#[derive(Clone, Copy)]
pub(crate) struct CorebootTimestampRecorder {
    table_addr: u64,
}

impl CorebootTimestampRecorder {
    /// Create a recorder from a coreboot timestamp table address.
    pub(crate) fn new(table_addr: u64) -> Option<Self> {
        if table_addr == 0 {
            return None;
        }

        // SAFETY: The address comes from coreboot's CB_TAG_TIMESTAMPS record.
        // We only perform unaligned reads from the fixed-size table header and
        // validate the entry capacity before accepting the table.
        let (max_entries, num_entries) = unsafe {
            let table = table_addr as *const TimestampTable;
            let max_entries = core::ptr::addr_of!((*table).max_entries).read_unaligned();
            let num_entries = core::ptr::addr_of!((*table).num_entries).read_unaligned();
            (max_entries, num_entries)
        };

        if !(16..=1024).contains(&max_entries) || num_entries > max_entries as u32 {
            #[cfg(not(test))]
            log::warn!(
                "Ignoring suspicious coreboot timestamp table at {:#x}: entries={}/{}",
                table_addr,
                num_entries,
                max_entries
            );
            #[cfg(test)]
            let _ = (num_entries, max_entries);
            return None;
        }

        Some(Self { table_addr })
    }

    /// Append a milestone using the current architecture counter.
    #[cfg(not(test))]
    pub(crate) fn record_now(&self, id: u32) {
        self.record_counter(id, crabefi::time::read_counter());
    }

    /// Append a milestone using an explicit architecture counter value.
    pub(crate) fn record_counter(&self, id: u32, counter: u64) {
        // SAFETY: `table_addr` was accepted by `new()`. CrabEFI is
        // single-threaded during boot, so the non-atomic num_entries update
        // cannot race with another CrabEFI writer.
        unsafe {
            let table = self.table_addr as *mut TimestampTable;

            let max_entries = core::ptr::addr_of!((*table).max_entries).read_unaligned();
            let num_ptr = core::ptr::addr_of_mut!((*table).num_entries);
            let num_entries = num_ptr.read_unaligned();

            if num_entries >= max_entries as u32 {
                #[cfg(not(test))]
                log::warn!(
                    "Coreboot timestamp table full ({}/{}), dropping id={}",
                    num_entries,
                    max_entries,
                    id
                );
                #[cfg(test)]
                let _ = (num_entries, max_entries, id);
                return;
            }

            let base_time = core::ptr::addr_of!((*table).base_time).read_unaligned();
            let entry_stamp = counter.wrapping_sub(base_time) as i64;
            let entries_base = (table as *mut u8).add(core::mem::size_of::<TimestampTable>())
                as *mut TimestampEntry;
            let entry = entries_base.add(num_entries as usize);

            core::ptr::addr_of_mut!((*entry).entry_id).write_unaligned(id);
            core::ptr::addr_of_mut!((*entry).entry_stamp).write_unaligned(entry_stamp);
            num_ptr.write_unaligned(num_entries + 1);
        }
    }
}

#[cfg(not(test))]
impl crabefi::TimestampRecorder for CorebootTimestampRecorder {
    fn record(&self, id: u32) {
        self.record_now(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    const ENTRIES: usize = 16;

    fn timestamp_storage(base_time: u64, max_entries: u16, num_entries: u32) -> Vec<u8> {
        let mut storage = std::vec![
            0;
            core::mem::size_of::<TimestampTable>()
                + ENTRIES * core::mem::size_of::<TimestampEntry>()
        ];
        let table = storage.as_mut_ptr() as *mut TimestampTable;
        // SAFETY: `storage` is large enough for the packed table header.
        unsafe {
            core::ptr::addr_of_mut!((*table).base_time).write_unaligned(base_time);
            core::ptr::addr_of_mut!((*table).max_entries).write_unaligned(max_entries);
            core::ptr::addr_of_mut!((*table).tick_freq_mhz).write_unaligned(1000);
            core::ptr::addr_of_mut!((*table).num_entries).write_unaligned(num_entries);
        }
        storage
    }

    fn entry(storage: &[u8], index: usize) -> (u32, i64) {
        let entries_base = unsafe {
            storage.as_ptr().add(core::mem::size_of::<TimestampTable>()) as *const TimestampEntry
        };
        let entry = unsafe { entries_base.add(index) };
        // SAFETY: Tests only read entries within the allocated storage.
        unsafe {
            (
                core::ptr::addr_of!((*entry).entry_id).read_unaligned(),
                core::ptr::addr_of!((*entry).entry_stamp).read_unaligned(),
            )
        }
    }

    fn num_entries(storage: &[u8]) -> u32 {
        let table = storage.as_ptr() as *const TimestampTable;
        // SAFETY: `storage` begins with a packed timestamp table header.
        unsafe { core::ptr::addr_of!((*table).num_entries).read_unaligned() }
    }

    #[test]
    fn rejects_null_and_suspicious_tables() {
        assert!(CorebootTimestampRecorder::new(0).is_none());

        let mut too_small = timestamp_storage(0, 15, 0);
        assert!(CorebootTimestampRecorder::new(too_small.as_mut_ptr() as u64).is_none());

        let mut inconsistent = timestamp_storage(0, 16, 17);
        assert!(CorebootTimestampRecorder::new(inconsistent.as_mut_ptr() as u64).is_none());
    }

    #[test]
    fn appends_entries_relative_to_base_time() {
        let mut storage = timestamp_storage(1_000_000, ENTRIES as u16, 2);
        let recorder = CorebootTimestampRecorder::new(storage.as_mut_ptr() as u64).unwrap();

        recorder.record_counter(1500, 1_000_123);

        assert_eq!(num_entries(&storage), 3);
        assert_eq!(entry(&storage, 2), (1500, 123));
    }

    #[test]
    fn full_table_drops_new_entries() {
        let mut storage = timestamp_storage(42, ENTRIES as u16, ENTRIES as u32);
        let recorder = CorebootTimestampRecorder::new(storage.as_mut_ptr() as u64).unwrap();

        recorder.record_counter(1501, 1000);

        assert_eq!(num_entries(&storage), ENTRIES as u32);
        assert_eq!(entry(&storage, ENTRIES - 1), (0, 0));
    }

    #[test]
    fn counter_before_base_wraps_like_coreboot_stamps() {
        let mut storage = timestamp_storage(10, ENTRIES as u16, 0);
        let recorder = CorebootTimestampRecorder::new(storage.as_mut_ptr() as u64).unwrap();

        recorder.record_counter(1502, 8);

        assert_eq!(entry(&storage, 0), (1502, -2));
    }
}
