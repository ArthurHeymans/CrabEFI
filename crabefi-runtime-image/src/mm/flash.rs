//! Flash access from SMM.
//!
//! Only QEMU's `cfi.pflash01` command set for now. With `secure=on` QEMU accepts
//! flash writes only from SMM, like AMD ROM Armor 3 does on hardware; the ROM
//! Armor PSP mailbox path comes later.

use core::ptr::{read_volatile, write_volatile};

const CFI_READ_ARRAY: u8 = 0xff;
const CFI_WRITE_BYTE: u8 = 0x10;
const CFI_ERASE_SETUP: u8 = 0x20;
const CFI_ERASE_CONFIRM: u8 = 0xd0;

pub const ERASE_BLOCK: u64 = 4096;

#[derive(Clone, Copy)]
pub struct Flash {
    base: u64,
    size: u64,
}

impl Flash {
    pub const fn empty() -> Self {
        Self { base: 0, size: 0 }
    }

    pub const fn new(base: u64, size: u64) -> Self {
        Self { base, size }
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
        self.program_raw(offset, data)
            && data.iter().enumerate().all(|(i, &byte)| {
                // SAFETY: inside the window checked by program_raw.
                unsafe { read_volatile(self.ptr(offset + i as u64)) == byte }
            })
    }

    /// Clear bits in one already programmed byte (EDK2 record state). NOR
    /// flash ANDs the new value in; QEMU stores it as is. Both leave no bit set
    /// that `value` clears.
    pub fn program_bits(&self, offset: u64, value: u8) -> bool {
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
