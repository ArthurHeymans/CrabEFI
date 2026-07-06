//! TCG (Trusted Computing Group) measured boot infrastructure.
//!
//! This module provides the core TCG types, event log management, and software
//! PCR bank implementation used by the `EFI_TCG_PROTOCOL` (TPM 1.2) and
//! `EFI_TCG2_PROTOCOL` (TPM 2.0) protocol implementations.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────┐
//! │  EFI Applications (shim, GRUB, systemd-boot)   │
//! │  Call: HashLogExtendEvent, GetCapability, ...   │
//! └────────────────┬───────────────────────────────┘
//!                  │
//! ┌────────────────▼───────────────────────────────┐
//! │  EFI Protocol Layer (protocols/tcg.rs, tcg2.rs) │
//! │  Function pointers matching UEFI ABI            │
//! └────────────────┬───────────────────────────────┘
//!                  │
//! ┌────────────────▼───────────────────────────────┐
//! │  TCG Core (this module)                         │
//! │  ┌──────────────┐  ┌──────────┐  ┌──────────┐ │
//! │  │  Event Log    │  │ PCR Banks │  │  Types   │ │
//! │  │  (trait-based │  │ (SHA-256  │  │  (GUIDs, │ │
//! │  │   abstraction)│  │  + SHA-1) │  │  structs)│ │
//! │  └──────────────┘  └──────────┘  └──────────┘ │
//! └────────────────────────────────────────────────┘
//! ```
//!
//! # Event Log Abstraction
//!
//! The [`EventLog`](event_log::EventLog) trait abstracts over the two
//! standard log formats:
//!
//! - **SHA1-only** (TPM 1.2): `TCG_PCClientPCREvent` entries with a fixed
//!   20-byte SHA-1 digest per event.
//! - **Crypto-agile** (TPM 2.0): `TCG_PCR_EVENT2` entries with algorithm-tagged
//!   digests. CrabEFI currently manages SHA-256 plus optional SHA-1 banks.
//!
//! Both formats can be initialized from existing data, enabling CrabEFI
//! to append to a coreboot-provided TPM event log in CBMEM.
//!
//! # Portability
//!
//! This module keeps event-log management and software PCR mirrors separate
//! from TPM transport. Attestable measured boot requires the built-in TIS MMIO
//! driver for x86/coreboot and QEMU+swtpm, or a platform-provided TPM 2.0
//! driver through [`crate::platform::Tpm2Device`]. Without a TPM backend,
//! CrabEFI may expose existing logs for discovery, but it does not present
//! software-only PCR state as hardware-backed evidence.

pub mod event_log;
pub mod measured_boot;
pub mod pcr;
pub mod tpm_tis;
pub mod types;

pub use event_log::{CryptoAgileEventLog, EventLog, EventLogFormat, Sha1EventLog};
pub use pcr::PcrBanks;
pub use tpm_tis::TpmTis;
pub use types::*;
