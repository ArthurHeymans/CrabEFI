//! Page-backed EFI pool free-list primitives.
//!
//! This module has no crate dependencies so its split, coalesce, reuse, and
//! double-free metadata behavior can be tested directly with `rustc --test`.

use core::ptr;

pub const POOL_ALLOCATED_MAGIC: u64 = 0x504F4F4C_48445200; // "POOLHDR\0"
pub const POOL_FREE_MAGIC: u64 = 0x504F4F4C_46524545; // "POOLFREE"
pub const POOL_ALIGNMENT: usize = 16;

#[repr(C, align(16))]
pub struct PoolHeader {
    pub magic: u64,
    pub block_size: u64,
    pub memory_type: u32,
    pub reserved: u32,
    pub padding: u64,
}

#[repr(C, align(16))]
struct FreePoolBlock {
    magic: u64,
    block_size: u64,
    next: *mut FreePoolBlock,
    memory_type: u32,
    reserved: u32,
}

/// Round a request up to the pool's alignment.
///
/// Lives here with [`POOL_ALIGNMENT`] so the free list and its callers cannot
/// disagree about block granularity.
pub fn align_pool_size(size: usize) -> Option<usize> {
    size.checked_add(POOL_ALIGNMENT - 1)
        .map(|size| size & !(POOL_ALIGNMENT - 1))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolListError {
    InvalidMagic,
    BlockSizeOverflow,
}

pub struct PoolState {
    free_head: *mut FreePoolBlock,
}

// Safety: callers serialize PoolState access and its pointers refer to owned
// page-backed pool chunks.
unsafe impl Send for PoolState {}

impl PoolState {
    pub const fn new() -> Self {
        Self {
            free_head: ptr::null_mut(),
        }
    }

    pub fn disable(&mut self) {
        self.free_head = ptr::null_mut();
    }

    /// Take a block of at least `size` bytes.
    ///
    /// `size` is rounded up to [`POOL_ALIGNMENT`] here rather than trusted from
    /// the caller, so a split can never hand out a misaligned remainder.
    pub fn take(
        &mut self,
        memory_type: u32,
        size: usize,
    ) -> Result<Option<(*mut u8, usize)>, PoolListError> {
        let Some(size) = align_pool_size(size) else {
            return Ok(None);
        };
        let mut previous: *mut FreePoolBlock = ptr::null_mut();
        let mut current = self.free_head;
        while !current.is_null() {
            // Safety: every node was written by insert and access is serialized.
            let block = unsafe { &mut *current };
            if block.magic != POOL_FREE_MAGIC {
                self.truncate_after(previous);
                return Err(PoolListError::InvalidMagic);
            }
            let block_size = match usize::try_from(block.block_size) {
                Ok(block_size) => block_size,
                Err(_) => {
                    self.truncate_after(previous);
                    return Err(PoolListError::BlockSizeOverflow);
                }
            };
            if block.memory_type == memory_type && block_size >= size {
                let remaining = block_size - size;
                let allocated_size = if remaining >= size_of::<FreePoolBlock>() {
                    // Safety: size is aligned and lies within this free block.
                    let replacement =
                        unsafe { (current as *mut u8).add(size).cast::<FreePoolBlock>() };
                    // Safety: replacement covers the unused tail of the block.
                    unsafe {
                        replacement.write(FreePoolBlock {
                            magic: POOL_FREE_MAGIC,
                            block_size: remaining as u64,
                            next: block.next,
                            memory_type: block.memory_type,
                            reserved: 0,
                        });
                    }
                    if previous.is_null() {
                        self.free_head = replacement;
                    } else {
                        // Safety: previous is another valid list node.
                        unsafe { (*previous).next = replacement };
                    }
                    size
                } else {
                    if previous.is_null() {
                        self.free_head = block.next;
                    } else {
                        // Safety: previous is another valid list node.
                        unsafe { (*previous).next = block.next };
                    }
                    block_size
                };
                return Ok(Some((current.cast(), allocated_size)));
            }
            previous = current;
            current = block.next;
        }
        Ok(None)
    }

    fn truncate_after(&mut self, previous: *mut FreePoolBlock) {
        if previous.is_null() {
            self.free_head = ptr::null_mut();
        } else {
            // Safety: previous is a validated list node and access is serialized.
            unsafe { (*previous).next = ptr::null_mut() };
        }
    }

    /// Insert an owned range into the address-sorted free list.
    ///
    /// Adjacent blocks of the same memory type are coalesced, including blocks
    /// from separate page chunks. Chunks are never returned to the page
    /// allocator, so crossing a chunk boundary is safe.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own `[address, address + size)`. The range
    /// must be writable, 16-byte aligned, and remain allocated to `memory_type`.
    pub unsafe fn insert(&mut self, address: *mut u8, size: usize, memory_type: u32) {
        let block = address.cast::<FreePoolBlock>();
        let mut previous: *mut FreePoolBlock = ptr::null_mut();
        let mut current = self.free_head;
        while !current.is_null() && (current as usize) < address as usize {
            previous = current;
            // Safety: current is a valid node and access is serialized.
            current = unsafe { (*current).next };
        }
        // Re-inserting a node that is already listed would give it a `next`
        // pointing at itself, which neither coalesce arm can clear and every
        // later traversal would spin on. Leak the block instead of hanging.
        if current == block {
            return;
        }
        // Safety: the caller owns this aligned range.
        unsafe {
            block.write(FreePoolBlock {
                magic: POOL_FREE_MAGIC,
                block_size: size as u64,
                next: current,
                memory_type,
                reserved: 0,
            });
        }
        if previous.is_null() {
            self.free_head = block;
        } else {
            // Safety: previous is a valid list node.
            unsafe { (*previous).next = block };
        }

        // Safety: block and current are valid nodes under serialized access.
        if let Some(current_block) = unsafe { current.as_mut() } {
            // Safety: block was initialized above.
            let block_ref = unsafe { &mut *block };
            if block_ref.memory_type == current_block.memory_type
                && address as usize + block_ref.block_size as usize == current as usize
            {
                block_ref.block_size += current_block.block_size;
                block_ref.next = current_block.next;
            }
        }
        // Safety: previous and block are valid nodes under serialized access.
        if let Some(previous_block) = unsafe { previous.as_mut() } {
            // Safety: block was initialized above and remains in the list.
            let block_ref = unsafe { &mut *block };
            if previous_block.memory_type == block_ref.memory_type
                && previous as usize + previous_block.block_size as usize == block as usize
            {
                previous_block.block_size += block_ref.block_size;
                previous_block.next = block_ref.next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(16))]
    struct Aligned<const N: usize>([u8; N]);

    #[test]
    fn split_free_and_reuse_coalesces_the_original_block() {
        let mut storage = Aligned([0; 1024]);
        let base = storage.0.as_mut_ptr();
        let mut state = PoolState::new();
        unsafe { state.insert(base, 1024, 4) };

        let (allocated, allocated_size) = state.take(4, 128).unwrap().unwrap();
        assert_eq!(allocated, base);
        assert_eq!(allocated_size, 128);
        assert_eq!(allocated as usize % POOL_ALIGNMENT, 0);

        unsafe { state.insert(allocated, allocated_size, 4) };
        let (whole, whole_size) = state.take(4, 1024).unwrap().unwrap();
        assert_eq!(whole, base);
        assert_eq!(whole_size, 1024);
    }

    #[test]
    fn adjacent_blocks_coalesce_regardless_of_insertion_order() {
        let mut storage = Aligned([0; 1024]);
        let base = storage.0.as_mut_ptr();
        let mut state = PoolState::new();
        unsafe {
            state.insert(base.add(512), 512, 4);
            state.insert(base, 512, 4);
        }
        assert_eq!(state.take(4, 1024).unwrap().unwrap(), (base, 1024));
    }

    #[test]
    fn reinserting_a_listed_block_cannot_create_a_self_loop() {
        let mut storage = Aligned([0; 256]);
        let base = storage.0.as_mut_ptr();
        let mut state = PoolState::new();
        unsafe {
            state.insert(base, 256, 4);
            // A caller-contract violation; it must leak, never hang.
            state.insert(base, 256, 4);
        }
        assert_eq!(state.take(4, 256).unwrap().unwrap(), (base, 256));
        assert!(state.take(4, 16).unwrap().is_none());
    }

    #[test]
    fn take_rounds_requests_up_to_the_pool_alignment() {
        let mut storage = Aligned([0; 256]);
        let base = storage.0.as_mut_ptr();
        let mut state = PoolState::new();
        unsafe { state.insert(base, 256, 4) };

        // An unaligned request must not leave a misaligned remainder behind.
        let (allocated, allocated_size) = state.take(4, 1).unwrap().unwrap();
        assert_eq!(allocated, base);
        assert_eq!(allocated_size, POOL_ALIGNMENT);
        let (next, _) = state.take(4, 1).unwrap().unwrap();
        assert_eq!(next as usize % POOL_ALIGNMENT, 0);
        assert_eq!(align_pool_size(usize::MAX), None);
    }

    #[test]
    fn free_metadata_has_an_explicit_distinct_magic() {
        let mut storage = Aligned([0; 128]);
        let base = storage.0.as_mut_ptr();
        let mut state = PoolState::new();
        unsafe { state.insert(base, 128, 4) };
        let header = unsafe { &*base.cast::<PoolHeader>() };
        assert_eq!(header.magic, POOL_FREE_MAGIC);
        assert_ne!(header.magic, POOL_ALLOCATED_MAGIC);
    }

    #[test]
    fn disable_drops_all_free_blocks() {
        let mut storage = Aligned([0; 128]);
        let mut state = PoolState::new();
        unsafe { state.insert(storage.0.as_mut_ptr(), 128, 4) };
        state.disable();
        assert!(state.take(4, 64).unwrap().is_none());
    }

    #[test]
    fn corrupt_node_truncates_the_untrusted_tail() {
        let mut storage = Aligned([0; 256]);
        let base = storage.0.as_mut_ptr();
        let mut state = PoolState::new();
        unsafe { state.insert(base, 256, 4) };
        unsafe { (*base.cast::<PoolHeader>()).magic = POOL_ALLOCATED_MAGIC };

        assert_eq!(state.take(4, 64), Err(PoolListError::InvalidMagic));
        assert!(state.take(4, 64).unwrap().is_none());
    }
}
