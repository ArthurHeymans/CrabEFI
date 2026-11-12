//! Flash access from SMM.
//!
//! Preferred: the flash services coreboot publishes in the payload MM shared
//! page (variable store region only), which work on any platform coreboot's
//! SMM can write, e.g. AMD ROM Armor 3 through the PSP. Fallback: QEMU's
//! `cfi.pflash01` command set; with `secure=on` QEMU accepts flash writes
//! only from SMM.

use core::ptr::{read_volatile, write_volatile};

const CFI_READ_ARRAY: u8 = 0xff;
const CFI_WRITE_BYTE: u8 = 0x10;
const CFI_ERASE_SETUP: u8 = 0x20;
const CFI_ERASE_CONFIRM: u8 = 0xd0;

pub const ERASE_BLOCK: u64 = 4096;

/// coreboot `struct payload_mm_flash_services`.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ServicesTable {
    header_magic: u64,
    size: u16,
    revision: u8,
    reserved: u8,
    reserved2: u32,
    region_size: u64,
    read: u64,
    write: u64,
    erase: u64,
}

const SERVICES_OFFSET: u64 = 3072;
const SERVICES_MAGIC: u64 = 0x5346_4d4d_444c_505f; // "_PLDMMFS"

type ReadFn = unsafe extern "sysv64" fn(u64, *mut u8, u64) -> u32;
type WriteFn = unsafe extern "sysv64" fn(u64, *const u8, u64) -> u32;
type EraseFn = unsafe extern "sysv64" fn(u64, u64) -> u32;

/// coreboot's flash services for the variable store region.
#[derive(Clone, Copy)]
struct Services {
    /// Flash offset of the region the services address.
    region: u64,
    region_size: u64,
    read: ReadFn,
    write: WriteFn,
    erase: EraseFn,
}

#[derive(Clone, Copy)]
pub struct Flash {
    base: u64,
    size: u64,
    services: Option<Services>,
}

impl Flash {
    pub const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            services: None,
        }
    }

    /// Flash mapped at `base`, written with QEMU pflash commands.
    pub const fn new(base: u64, size: u64) -> Self {
        Self {
            base,
            size,
            services: None,
        }
    }

    /// Use coreboot's flash services when its shared page offers them for the
    /// region at flash offset `region` (the variable store).
    pub fn with_coreboot_services(mut self, shared_page: u64, region: u64) -> Self {
        // SAFETY: the shared page is MM-mapped SMRAM coreboot filled before calling us.
        let table = unsafe {
            core::ptr::read_unaligned((shared_page + SERVICES_OFFSET) as *const ServicesTable)
        };
        if table.header_magic == SERVICES_MAGIC
            && table.size as usize >= core::mem::size_of::<ServicesTable>()
            && table.read != 0
            && table.write != 0
            && table.erase != 0
        {
            // SAFETY: coreboot published these as functions of its SMM handler.
            self.services = Some(unsafe {
                Services {
                    region,
                    region_size: table.region_size,
                    read: core::mem::transmute::<u64, ReadFn>(table.read),
                    write: core::mem::transmute::<u64, WriteFn>(table.write),
                    erase: core::mem::transmute::<u64, EraseFn>(table.erase),
                }
            });
        }
        self
    }

    pub fn uses_coreboot_services(&self) -> bool {
        self.services.is_some()
    }

    /// Region-relative offset of `offset..offset+len` when coreboot serves it.
    fn service_range(&self, offset: u64, len: u64) -> Option<(Services, u64)> {
        let services = self.services?;
        let relative = offset.checked_sub(services.region)?;
        (relative.checked_add(len)? <= services.region_size).then_some((services, relative))
    }

    fn in_range(&self, offset: u64, len: u64) -> bool {
        offset.checked_add(len).is_some_and(|end| end <= self.size)
    }

    fn ptr(&self, offset: u64) -> *mut u8 {
        (self.base + offset) as *mut u8
    }

    pub fn read(&self, offset: u64, buf: &mut [u8]) -> bool {
        if !self.in_range(offset, buf.len() as u64) {
            return false;
        }
        if self.services.is_some() {
            let Some((services, relative)) = self.service_range(offset, buf.len() as u64) else {
                return false;
            };
            // SAFETY: coreboot SMM function; the buffer is MM-owned.
            return buf.is_empty()
                || unsafe { (services.read)(relative, buf.as_mut_ptr(), buf.len() as u64) } == 0;
        }
        for (i, byte) in buf.iter_mut().enumerate() {
            // SAFETY: inside the memory-mapped flash window checked above.
            *byte = unsafe { read_volatile(self.ptr(offset + i as u64)) };
        }
        true
    }

    /// Erase whole blocks.
    pub fn erase(&self, offset: u64, len: u64) -> bool {
        if !self.in_range(offset, len) || offset % ERASE_BLOCK != 0 || len % ERASE_BLOCK != 0 {
            return false;
        }
        if self.services.is_some() {
            let Some((services, relative)) = self.service_range(offset, len) else {
                return false; // Firmware regions are not offered through the services yet.
            };
            // SAFETY: coreboot SMM function.
            return unsafe { (services.erase)(relative, len) } == 0;
        }
        let mut block = offset;
        while block < offset + len {
            // SAFETY: flash command cycles inside the checked window.
            unsafe {
                write_volatile(self.ptr(block), CFI_ERASE_SETUP);
                write_volatile(self.ptr(block), CFI_ERASE_CONFIRM);
            }
            block += ERASE_BLOCK;
        }
        // SAFETY: as above.
        unsafe { write_volatile(self.ptr(offset), CFI_READ_ARRAY) };
        (0..len).all(|i| {
            // SAFETY: as above.
            unsafe { read_volatile(self.ptr(offset + i)) == 0xff }
        })
    }

    /// Program bytes into erased flash and verify them exactly.
    pub fn program(&self, offset: u64, data: &[u8]) -> bool {
        if self.services.is_some() {
            return self.service_write(offset, data)
                && self.verify(offset, data, |now, byte| now == byte);
        }
        self.program_raw(offset, data)
            && data.iter().enumerate().all(|(i, &byte)| {
                // SAFETY: inside the window checked by program_raw.
                unsafe { read_volatile(self.ptr(offset + i as u64)) == byte }
            })
    }

    fn service_write(&self, offset: u64, data: &[u8]) -> bool {
        let Some((services, relative)) = self.service_range(offset, data.len() as u64) else {
            return false;
        };
        // SAFETY: coreboot SMM function; the data is MM-owned.
        data.is_empty()
            || unsafe { (services.write)(relative, data.as_ptr(), data.len() as u64) } == 0
    }

    /// Read back through the same path that wrote and compare byte by byte.
    fn verify(&self, offset: u64, data: &[u8], ok: fn(u8, u8) -> bool) -> bool {
        let mut chunk = [0u8; 64];
        let mut done = 0;
        while done < data.len() {
            let n = (data.len() - done).min(chunk.len());
            if !self.read(offset + done as u64, &mut chunk[..n])
                || !chunk[..n]
                    .iter()
                    .zip(&data[done..done + n])
                    .all(|(&now, &byte)| ok(now, byte))
            {
                return false;
            }
            done += n;
        }
        true
    }

    /// Clear bits in one already programmed byte (EDK2 record state). NOR
    /// flash ANDs the new value in; QEMU stores it as is. Both leave no bit set
    /// that `value` clears.
    pub fn program_bits(&self, offset: u64, value: u8) -> bool {
        if self.services.is_some() {
            return self.service_write(offset, &[value])
                && self.verify(offset, &[value], |now, value| now & !value == 0);
        }
        self.program_raw(offset, &[value]) && {
            // SAFETY: inside the window checked by program_raw.
            let now = unsafe { read_volatile(self.ptr(offset)) };
            now & !value == 0
        }
    }

    fn program_raw(&self, offset: u64, data: &[u8]) -> bool {
        if !self.in_range(offset, data.len() as u64) {
            return false;
        }
        for (i, &byte) in data.iter().enumerate() {
            let target = self.ptr(offset + i as u64);
            // SAFETY: flash command cycles inside the checked window.
            unsafe {
                write_volatile(target, CFI_WRITE_BYTE);
                write_volatile(target, byte);
            }
        }
        if !data.is_empty() {
            // SAFETY: as above.
            unsafe { write_volatile(self.ptr(offset), CFI_READ_ARRAY) };
        }
        true
    }
}
