//! Request protocol between the ring-0 runtime image (proxy) and its payload
//! MM build (variable authority in SMM), through a buffer in normal RAM.

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
}

pub const COMM_MAGIC: u64 = 0x0056_4d4d_4241_5243; // "CRABMMV\0"
pub const COMM_VERSION: u32 = 2;
pub const NAME_OFFSET: u64 = 0x100;
pub const NAME_CAPACITY: usize = 0x200;
pub const DATA_OFFSET: u64 = NAME_OFFSET + NAME_CAPACITY as u64;
pub const STATUS_PENDING: u64 = u64::MAX;

pub mod command {
    pub const PING: u32 = 1;
    pub const GET_VARIABLE: u32 = 2;
    pub const GET_NEXT_VARIABLE_NAME: u32 = 3;
    pub const SET_VARIABLE: u32 = 4;
    pub const QUERY_VARIABLE_INFO: u32 = 5;
    /// No more firmware-only operations (before the first boot option runs).
    pub const READY_TO_BOOT: u32 = 6;
    /// Only runtime-accessible variables from now on.
    pub const EXIT_BOOT_SERVICES: u32 = 7;
}
