//! Request protocol between ring 0 (boot code and the runtime image proxy)
//! and the runtime image's payload MM build, through a buffer in normal RAM.

/// Request header at the start of the communication buffer. The name area
/// follows at [`NAME_OFFSET`], the data area at [`DATA_OFFSET`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Request {
    pub magic: u64,
    pub version: u32,
    pub command: u32,
    /// EFI status; [`STATUS_PENDING`] until MM answers.
    pub status: u64,
    pub guid: [u8; 16],
    pub attributes: u32,
    /// Bytes in the name area, including the terminator (in and out).
    pub name_size: u32,
    /// Bytes in the data area (in: capacity or payload, out: actual/required).
    pub data_size: u64,
    pub maximum_storage: u64,
    pub remaining_storage: u64,
    pub maximum_variable: u64,
    /// Flash offset for the firmware commands.
    pub offset: u64,
}

pub const COMM_MAGIC: u64 = 0x0056_4d4d_4241_5243; // "CRABMMV\0"
pub const COMM_VERSION: u32 = 2;
pub const NAME_OFFSET: u64 = 0x100;
pub const NAME_CAPACITY: usize = 0x200;
pub const DATA_OFFSET: u64 = NAME_OFFSET + NAME_CAPACITY as u64;
pub const STATUS_PENDING: u64 = u64::MAX;

pub mod command {
    /// Reply `attributes`: 1 when MM writes the flash through coreboot's
    /// flash services, 0 when it drives the flash itself.
    pub const PING: u32 = 1;
    pub const GET_VARIABLE: u32 = 2;
    pub const GET_NEXT_VARIABLE_NAME: u32 = 3;
    pub const SET_VARIABLE: u32 = 4;
    pub const QUERY_VARIABLE_INFO: u32 = 5;
    /// No more firmware-only operations (before the first boot option runs).
    pub const READY_TO_BOOT: u32 = 6;
    /// Only runtime-accessible variables from now on.
    pub const EXIT_BOOT_SERVICES: u32 = 7;

    // Firmware-only commands: rejected once READY_TO_BOOT or EXIT_BOOT_SERVICES
    // was seen, i.e. before any boot option or other third-party code ran.

    /// Physical-presence setup action: `attributes` names the bridge
    /// authorization (`bridge_operation::AUTHORIZE_SETUP_*`), `data_size` is 1
    /// to open and 0 to close it.
    pub const SETUP_AUTHORIZE: u32 = 8;
    /// Erase `data_size` bytes at flash `offset` (outside the variable store).
    pub const FIRMWARE_ERASE: u32 = 9;
    /// Program the data area to flash `offset` (outside the variable store).
    pub const FIRMWARE_WRITE: u32 = 10;
    /// SetVariable without the protected-variable check, for firmware status
    /// variables such as ESRT last-attempt and capsule results. Never for
    /// Secure Boot key databases.
    pub const SET_FIRMWARE_VARIABLE: u32 = 11;
}
