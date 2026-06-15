//! Boot timestamp recording abstraction.
//!
//! The core library records boot-stage milestones via [`record`]. Platforms
//! provide the backend by passing a [`crate::TimestampRecorder`] in
//! [`crate::PlatformConfig`]. Without a recorder, all calls are no-ops.
//!
//! CrabEFI uses timestamp IDs 1500–1599. Coreboot reserves IDs 1000+ for
//! payloads, and the same IDs are useful for any platform that wants stable
//! CrabEFI milestone identifiers.

/// CrabEFI payload entry point reached.
pub const TS_CRABEFI_START: u32 = 1500;
/// Platform tables parsed.
pub const TS_CRABEFI_TABLES_PARSED: u32 = 1501;
/// Timing subsystem calibrated.
pub const TS_CRABEFI_COUNTER_CALIBRATED: u32 = 1502;
/// EFI environment initialized.
pub const TS_CRABEFI_EFI_INIT: u32 = 1503;
/// PCI bus enumeration complete.
pub const TS_CRABEFI_PCI_INIT: u32 = 1504;
/// Variable store and Secure Boot initialization complete.
pub const TS_CRABEFI_VARSTORE_INIT: u32 = 1505;
/// Storage controller initialization started.
pub const TS_CRABEFI_STORAGE_INIT_START: u32 = 1506;
/// Storage controllers ready.
pub const TS_CRABEFI_STORAGE_INIT_DONE: u32 = 1507;
/// `ExitBootServices` succeeded; handing off to the OS.
pub const TS_CRABEFI_EXIT_BOOT_SERVICES: u32 = 1508;

/// Record a boot milestone with the current platform timestamp.
///
/// This is a no-op when the platform did not provide a timestamp recorder.
pub fn record(id: u32) {
    if let Some(recorder) = crate::state::drivers().platform.timestamp_recorder {
        recorder.record(id);
    }
}
