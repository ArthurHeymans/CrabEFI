//! Controller registry growth beyond the old fixed per-driver capacity.

use super::{ControllerRegistry, RegisterError};
use crate::efi::allocator::{self, HOST_TEST_PAGES, with_host_pages};
use r_efi::efi::Status;

/// Stand-in controller: big enough to span pages like the real ones.
struct Controller {
    id: usize,
    _state: [u8; 5000],
}

#[test]
fn registry_keeps_every_controller() {
    // The Tyan S8030 has six NVMe drives; the old registries held four.
    const CONTROLLERS: usize = 10;
    let mut registry = ControllerRegistry::<Controller>::new("test");
    with_host_pages(|| {
        for id in 0..CONTROLLERS {
            let controller = Controller {
                id,
                _state: [0; 5000],
            };
            assert_eq!(registry.register(controller, |_| unreachable!()), Ok(()));
        }

        assert_eq!(registry.count(), CONTROLLERS);
        for id in 0..CONTROLLERS {
            assert_eq!(registry.with_mut(id, |c| c.id), Some(id));
        }
        assert_eq!(registry.with_mut(CONTROLLERS, |c| c.id), None);
        let mut seen = 0;
        registry.for_each_mut(|c| {
            assert_eq!(c.id, seen);
            seen += 1;
        });
        assert_eq!(seen, CONTROLLERS);

        // The production registry keeps its controllers for the boot lifetime;
        // return this stand-in registry's pages to the shared test allocator.
        let pages = core::mem::size_of::<Controller>().div_ceil(allocator::PAGE_SIZE_USIZE);
        for super::ControllerPtr(ptr) in registry.controllers.get_mut().drain(..) {
            // SAFETY: these pointers still uniquely own the initialized controllers.
            unsafe { ptr.as_ptr().drop_in_place() };
            assert_eq!(
                allocator::free_pages(ptr.as_ptr() as u64, pages as u64),
                Status::SUCCESS
            );
        }
    });
}

#[test]
fn registry_reports_a_full_heap() {
    let registry = ControllerRegistry::<Controller>::new("test");
    let mut discarded = None;
    let (result, _) = crate::test_allocator::with_budget(0, || {
        registry.register(
            Controller {
                id: 42,
                _state: [0; 5000],
            },
            |controller| {
                assert_eq!(registry.count(), 0); // Cleanup must run unlocked.
                discarded = Some(controller.id);
            },
        )
    });
    assert_eq!(result, Err(RegisterError::OutOfHeap));
    assert_eq!(discarded, Some(42));
}

#[test]
fn registry_returns_the_controller_when_pages_are_exhausted() {
    with_host_pages(|| {
        let all_pages = crate::efi::allocate_pages(HOST_TEST_PAGES).unwrap();
        let registry = ControllerRegistry::<Controller>::new("test");
        let mut discarded = None;
        let result = registry.register(
            Controller {
                id: 42,
                _state: [0; 5000],
            },
            |controller| {
                assert_eq!(registry.count(), 0);
                discarded = Some(controller.id);
            },
        );
        crate::efi::free_pages(all_pages, HOST_TEST_PAGES);
        assert_eq!(result, Err(RegisterError::OutOfPages));
        assert_eq!(discarded, Some(42));
        assert_eq!(registry.count(), 0);
    });
}
