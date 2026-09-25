//! Per-protocol context storage without a fixed instance limit.

use crate::cell::Local;
use crate::efi::utils::allocate_protocol_with_log;

#[repr(C)]
struct Instance<Proto, Ctx> {
    // EFI receives a pointer to this first field.
    protocol: Proto,
    ctx: Ctx,
    next: *mut Self,
}

/// Firmware-lifetime instances of one protocol type.
///
/// The linked list lets callbacks validate an untrusted `this` pointer by
/// address before dereferencing it. Published instances stay live throughout
/// boot; an instance whose publication fails must be passed to [`remove`]
/// so retries cannot leak pool allocations.
pub struct Registry<Proto, Ctx> {
    head: Local<*mut Instance<Proto, Ctx>>,
}

impl<Proto, Ctx: Copy> Registry<Proto, Ctx> {
    pub const fn new() -> Self {
        Self {
            head: Local::new(core::ptr::null_mut()),
        }
    }

    pub fn allocate(&self, name: &str, ctx: Ctx, init: impl FnOnce(&mut Proto)) -> *mut Proto {
        let ptr = allocate_protocol_with_log::<Instance<Proto, Ctx>>(name, |instance| {
            init(&mut instance.protocol);
            instance.ctx = ctx;
        });
        if ptr.is_null() {
            return core::ptr::null_mut();
        }
        self.register(ptr);
        ptr.cast()
    }

    fn register(&self, ptr: *mut Instance<Proto, Ctx>) {
        let mut head = self.head.borrow_mut();
        // SAFETY: `ptr` identifies an initialized allocation that remains live
        // for the firmware lifetime. Only registration changes list links.
        unsafe { (*ptr).next = *head };
        *head = ptr;
    }

    pub fn get(&self, protocol: *mut Proto) -> Option<Ctx> {
        let mut cursor = *self.head.borrow();
        while !cursor.is_null() {
            // Compare addresses first: `protocol` may not point to valid memory.
            if cursor.cast::<Proto>() == protocol {
                // SAFETY: the registered allocation stays live throughout boot,
                // and its context is initialized before registration.
                return Some(unsafe { (*cursor).ctx });
            }
            // SAFETY: every link is either null or an initialized allocation
            // registered with this registry and never freed while linked.
            cursor = unsafe { (*cursor).next };
        }
        None
    }

    /// Unregister `protocol` and return its allocation to the pool.
    ///
    /// Call this when publishing an instance fails (for example a rejected
    /// `InstallProtocol`) so repeated attempts cannot exhaust the
    /// firmware's boot-time heap. Returns whether a registered instance
    /// was removed.
    pub fn remove(&self, protocol: *mut Proto) -> bool {
        let mut head = self.head.borrow_mut();
        let mut prev: *mut Instance<Proto, Ctx> = core::ptr::null_mut();
        let mut cursor = *head;
        while !cursor.is_null() {
            // SAFETY: every link is either null or a registered allocation
            // that stays live until unlinked and freed below.
            let next = unsafe { (*cursor).next };
            if cursor.cast::<Proto>() == protocol {
                if prev.is_null() {
                    *head = next;
                } else {
                    // SAFETY: `prev` is a live registered allocation.
                    unsafe {
                        (*prev).next = next;
                    }
                }
                drop(head);
                // SAFETY: `cursor` was allocated by `allocate` via
                // `allocate_pool`, has just been unlinked, and is never
                // touched again after this call.
                let _ = crate::efi::allocator::free_pool(cursor.cast::<u8>());
                return true;
            }
            prev = cursor;
            cursor = next;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_have_no_fixed_limit_and_unknown_pointers_are_rejected() {
        let registry = Registry::<u32, u32>::new();
        let mut instances: [Instance<u32, u32>; 24] = core::array::from_fn(|i| Instance {
            protocol: i as u32,
            ctx: (i + 100) as u32,
            next: core::ptr::null_mut(),
        });
        for instance in &mut instances {
            registry.register(instance);
        }
        for (i, instance) in instances.iter_mut().enumerate() {
            assert_eq!(registry.get(&mut instance.protocol), Some((i + 100) as u32));
        }
        let mut foreign = 0;
        assert_eq!(registry.get(&mut foreign), None);
        assert_eq!(registry.get(core::ptr::null_mut()), None);
        assert_eq!(registry.get(1usize as *mut u32), None);
    }
}
