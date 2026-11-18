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
/// Largest data payload MM accepts in one request, whatever the buffer size.
pub const DATA_MAX: usize = 48 * 1024;
pub const STATUS_PENDING: u64 = u64::MAX;

pub mod command {
    /// Reply `attributes`: bit 0 when MM writes the flash through coreboot's
    /// flash services (else it drives the flash itself), bit 1 when those
    /// services also cover firmware in this boot (capsule update).
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

/// Smallest variable store region (coreboot's SMMSTORE) the MM build serves.
/// It keeps two halves, each whole 4 KiB erase blocks large enough for the
/// EDK2 store headers and one record of the largest variable.
pub const MIN_STORE_SIZE: u64 = {
    const STORE_HEADERS: usize = 0x48 + 0x1c;
    const LARGEST_RECORD: usize =
        60 + (crate::MAX_VARIABLE_NAME_LEN + 1) * 2 + crate::MAX_VARIABLE_DATA_SIZE + 4;
    2 * ((STORE_HEADERS + LARGEST_RECORD).div_ceil(4096) * 4096) as u64
};

/// `status` of a request that is filled in or given up: MM skips it.
pub const STATUS_IDLE: u64 = u64::MAX - 1;
/// Byte offset of [`Request::status`] in the buffer.
pub const STATUS_OFFSET: u64 = core::mem::offset_of!(Request, status) as u64;
/// Encoded size of [`Request`].
pub const REQUEST_SIZE: usize = core::mem::size_of::<Request>();
const _: () = assert!(REQUEST_SIZE == 88 && STATUS_OFFSET == 16);

/// SMIs raised for one request before it is given up. Hardware can deliver
/// an SMI late or lose it.
pub const SMI_ATTEMPTS: u32 = 3;
/// Status polls after each SMI; [`Transport::pause`] waits about 10 µs, so
/// this is about 50 ms.
pub const POLLS_PER_SMI: u32 = 5_000;

impl Request {
    /// The little-endian layout MM reads from the buffer.
    pub fn to_bytes(&self) -> [u8; REQUEST_SIZE] {
        let mut out = [0u8; REQUEST_SIZE];
        let mut at = 0;
        let mut put = |bytes: &[u8]| {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };
        put(&self.magic.to_le_bytes());
        put(&self.version.to_le_bytes());
        put(&self.command.to_le_bytes());
        put(&self.status.to_le_bytes());
        put(&self.guid);
        put(&self.attributes.to_le_bytes());
        put(&self.name_size.to_le_bytes());
        put(&self.data_size.to_le_bytes());
        put(&self.maximum_storage.to_le_bytes());
        put(&self.remaining_storage.to_le_bytes());
        put(&self.maximum_variable.to_le_bytes());
        put(&self.offset.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8; REQUEST_SIZE]) -> Self {
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap_or([0; 4]));
        let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]));
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&bytes[24..40]);
        Self {
            magic: u64_at(0),
            version: u32_at(8),
            command: u32_at(12),
            status: u64_at(16),
            guid,
            attributes: u32_at(40),
            name_size: u32_at(44),
            data_size: u64_at(48),
            maximum_storage: u64_at(56),
            remaining_storage: u64_at(64),
            maximum_variable: u64_at(72),
            offset: u64_at(80),
        }
    }
}

/// The ring-0 side's access to the buffer shared with MM. Implementations
/// do the volatile accesses; [`exchange`] owns the protocol.
pub trait Transport {
    /// Copy `bytes` to `offset` in the buffer.
    fn write(&mut self, offset: u64, bytes: &[u8]);
    /// Copy from `offset` in the buffer.
    fn read(&mut self, offset: u64, bytes: &mut [u8]);
    /// Atomically, with respect to SMIs, replace a `current` status with
    /// `new`; return the status found.
    fn compare_exchange_status(&mut self, current: u64, new: u64) -> u64;
    /// Store `status`.
    fn write_status(&mut self, status: u64);
    /// Raise the software SMI that makes MM look at the buffer.
    fn raise_smi(&mut self);
    /// Wait about 10 µs between status polls.
    fn pause(&mut self);
}

/// Result of [`exchange`].
#[derive(Clone, Copy)]
pub enum Outcome {
    /// MM answered; `reply` holds its status and output fields.
    Answered {
        reply: Request,
        /// SMIs raised (1 when the first one was handled).
        smis: u32,
        /// Polls after the last SMI before the answer showed up.
        polls: u32,
    },
    /// MM never answered. The request was withdrawn, so a late SMI cannot
    /// run it with the next request's name or data.
    Lost,
}

/// One request/reply round trip.
///
/// The request is only marked [`STATUS_PENDING`] once its name, data and
/// header are in place, and a request MM did not answer is withdrawn before
/// returning. MM therefore only ever runs a complete request that a caller is
/// still waiting for. Callers check the name and data sizes against the
/// buffer.
pub fn exchange(
    transport: &mut dyn Transport,
    request: Request,
    name: &[u16],
    data: &[u8],
) -> Outcome {
    // A request left pending by an earlier caller must not run with what
    // follows.
    transport.write_status(STATUS_IDLE);
    let mut name_bytes = [0u8; NAME_CAPACITY];
    for (bytes, unit) in name_bytes.as_chunks_mut::<2>().0.iter_mut().zip(name) {
        bytes.copy_from_slice(&unit.to_le_bytes());
    }
    transport.write(
        NAME_OFFSET,
        &name_bytes[..(name.len() * 2).min(NAME_CAPACITY)],
    );
    transport.write(DATA_OFFSET, data);
    let header = Request {
        magic: COMM_MAGIC,
        version: COMM_VERSION,
        status: STATUS_IDLE,
        ..request
    };
    transport.write(0, &header.to_bytes());
    transport.write_status(STATUS_PENDING);
    for smis in 1..=SMI_ATTEMPTS {
        transport.raise_smi();
        for polls in 0..=POLLS_PER_SMI {
            let mut status = [0u8; 8];
            transport.read(STATUS_OFFSET, &mut status);
            if u64::from_le_bytes(status) != STATUS_PENDING {
                let mut reply = [0u8; REQUEST_SIZE];
                transport.read(0, &mut reply);
                return Outcome::Answered {
                    reply: Request::from_bytes(&reply),
                    smis,
                    polls,
                };
            }
            transport.pause();
        }
    }
    // An SMI may still arrive between the last poll and here: withdraw the
    // request only if MM has not answered it meanwhile.
    if transport.compare_exchange_status(STATUS_PENDING, STATUS_IDLE) != STATUS_PENDING {
        let mut reply = [0u8; REQUEST_SIZE];
        transport.read(0, &mut reply);
        return Outcome::Answered {
            reply: Request::from_bytes(&reply),
            smis: SMI_ATTEMPTS,
            polls: POLLS_PER_SMI,
        };
    }
    Outcome::Lost
}

/// The communication buffer in RAM, accessed with volatile operations,
/// minus the SMI and the wait that only the caller knows how to do.
pub struct SharedBuffer<'a> {
    base: u64,
    size: u64,
    raise_smi: &'a mut dyn FnMut(),
    pause: &'a mut dyn FnMut(),
}

impl<'a> SharedBuffer<'a> {
    /// # Safety
    /// `base..base + size` must be the communication buffer, mapped,
    /// 8-byte aligned and shared only with MM while the value lives.
    #[allow(unsafe_code)]
    pub unsafe fn new(
        base: u64,
        size: u64,
        raise_smi: &'a mut dyn FnMut(),
        pause: &'a mut dyn FnMut(),
    ) -> Self {
        Self {
            base,
            size,
            raise_smi,
            pause,
        }
    }

    fn address(&self, offset: u64, len: usize) -> Option<u64> {
        let end = offset.checked_add(len as u64)?;
        (end <= self.size).then(|| self.base + offset)
    }

    fn status(&self) -> *mut u64 {
        (self.base + STATUS_OFFSET) as *mut u64
    }
}

#[allow(unsafe_code)]
impl Transport for SharedBuffer<'_> {
    fn write(&mut self, offset: u64, bytes: &[u8]) {
        let Some(address) = self.address(offset, bytes.len()) else {
            return;
        };
        for (i, &byte) in bytes.iter().enumerate() {
            // SAFETY: inside the buffer `new` was given.
            unsafe { core::ptr::write_volatile((address + i as u64) as *mut u8, byte) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    fn read(&mut self, offset: u64, bytes: &mut [u8]) {
        let Some(address) = self.address(offset, bytes.len()) else {
            bytes.fill(0);
            return;
        };
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        for (i, byte) in bytes.iter_mut().enumerate() {
            // SAFETY: inside the buffer `new` was given.
            *byte = unsafe { core::ptr::read_volatile((address + i as u64) as *const u8) };
        }
    }

    fn compare_exchange_status(&mut self, current: u64, new: u64) -> u64 {
        // SAFETY: the status word is 8-byte aligned inside the buffer, and a
        // locked compare-exchange is one instruction, so no SMI splits it.
        let status = unsafe { core::sync::atomic::AtomicU64::from_ptr(self.status()) };
        match status.compare_exchange(
            current,
            new,
            core::sync::atomic::Ordering::SeqCst,
            core::sync::atomic::Ordering::SeqCst,
        ) {
            Ok(found) | Err(found) => found,
        }
    }

    fn write_status(&mut self, status: u64) {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: the aligned status word inside the buffer.
        unsafe { core::ptr::write_volatile(self.status(), status) };
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    fn raise_smi(&mut self) {
        (self.raise_smi)();
    }

    fn pause(&mut self) {
        (self.pause)();
    }
}
