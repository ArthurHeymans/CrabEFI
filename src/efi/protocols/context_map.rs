//! Generic protocol-to-context mapping
//!
//! Provides a fixed-capacity map from EFI protocol instance pointers to
//! associated context data. This eliminates duplicated infrastructure across
//! block_io, disk_io, storage_security, nvme_pass_thru, ata_pass_thru, and
//! scsi_pass_thru modules.
//!
//! Uses `spin::Mutex` for safe interior mutability, avoiding `static mut`.

use spin::Mutex;

/// Inner storage for the protocol-to-context map.
struct Inner<Ctx, Proto, const N: usize> {
    contexts: [Option<Ctx>; N],
    proto_ptrs: [Option<*mut Proto>; N],
}

// Safety: Inner contains raw pointers (both in proto_ptrs and potentially in Ctx
// fields like Handle). These are only accessed from UEFI protocol callbacks
// which run single-threaded in the firmware.
unsafe impl<Ctx, Proto, const N: usize> Send for Inner<Ctx, Proto, N> {}

impl<Ctx: Copy, Proto, const N: usize> Inner<Ctx, Proto, N> {
    const fn new() -> Self {
        Self {
            contexts: [const { None }; N],
            proto_ptrs: [const { None }; N],
        }
    }

    fn find_index(&self, protocol: *mut Proto) -> Option<usize> {
        self.proto_ptrs
            .iter()
            .position(|p| p.is_some_and(|ptr| ptr == protocol))
    }
}

/// A fixed-capacity map from protocol pointers to context structs.
///
/// Each protocol module stores one of these as a `static` (not `static mut`)
/// to associate per-instance context data with opaque EFI protocol pointers.
///
/// # Type Parameters
/// * `Ctx` - The context data type (must be `Copy`; all contexts are small scalar structs)
/// * `Proto` - The protocol struct type (e.g., `BlockIoProtocol`)
/// * `N` - Maximum number of instances
pub struct ProtocolContextMap<Ctx: Copy, Proto, const N: usize> {
    inner: Mutex<Inner<Ctx, Proto, N>>,
}

impl<Ctx: Copy, Proto, const N: usize> Default for ProtocolContextMap<Ctx, Proto, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Ctx: Copy, Proto, const N: usize> ProtocolContextMap<Ctx, Proto, N> {
    /// Create an empty map.
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::new()),
        }
    }

    /// Find the slot index for a given protocol pointer.
    pub fn find_index(&self, protocol: *mut Proto) -> Option<usize> {
        self.inner.lock().find_index(protocol)
    }

    /// Look up the context for a protocol pointer, returning a copy.
    pub fn get(&self, protocol: *mut Proto) -> Option<Ctx> {
        let inner = self.inner.lock();
        let idx = inner.find_index(protocol)?;
        inner.contexts[idx]
    }

    /// Look up the context at a given index, returning a copy.
    pub fn get_by_index(&self, idx: usize) -> Option<Ctx> {
        let inner = self.inner.lock();
        *inner.contexts.get(idx)?
    }

    /// Find a free slot, returning its index.
    pub fn find_free_slot(&self) -> Option<usize> {
        self.inner
            .lock()
            .contexts
            .iter()
            .position(|slot| slot.is_none())
    }

    /// Store a context and its associated protocol pointer at the given index.
    ///
    /// # Panics
    /// Panics if `idx >= N`.
    pub fn store(&self, idx: usize, ctx: Ctx, protocol: *mut Proto) {
        let mut inner = self.inner.lock();
        inner.contexts[idx] = Some(ctx);
        inner.proto_ptrs[idx] = Some(protocol);
    }

    /// Remove the context and protocol pointer at the given index.
    ///
    /// Returns the context if present.
    #[allow(dead_code)]
    pub fn remove(&self, idx: usize) -> Option<Ctx> {
        if idx < N {
            let mut inner = self.inner.lock();
            inner.proto_ptrs[idx] = None;
            inner.contexts[idx].take()
        } else {
            None
        }
    }
}
