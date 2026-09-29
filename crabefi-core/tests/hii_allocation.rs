//! Exercise the public HII callbacks with real host allocator failures.
//! One test owns the single-hart database; allocation denial is thread-local.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ptr;

use crabefi::efi::protocols::hii::{database_protocol, string_protocol};
use r_efi::{
    efi::Status,
    hii,
    protocols::{hii_database, hii_string},
};

struct FailingAllocator;
thread_local! {
    static ALLOCATIONS_LEFT: Cell<Option<usize>> = const { Cell::new(None) };
}

fn denied() -> bool {
    ALLOCATIONS_LEFT
        .try_with(|left| match left.get() {
            None => false,
            Some(0) => true,
            Some(n) => {
                left.set(Some(n - 1));
                false
            }
        })
        .unwrap_or(false)
}

unsafe impl GlobalAlloc for FailingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if denied() {
            ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if denied() {
            ptr::null_mut()
        } else {
            unsafe { System.alloc_zeroed(layout) }
        }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if denied() {
            ptr::null_mut()
        } else {
            unsafe { System.realloc(pointer, layout, size) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: FailingAllocator = FailingAllocator;

fn with_budget<R>(allocations: usize, f: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALLOCATIONS_LEFT.set(None);
        }
    }
    ALLOCATIONS_LEFT.set(Some(allocations));
    let _reset = Reset;
    f()
}

fn package() -> Vec<u8> {
    let languages = b"en-US;en;EN-us\0";
    let offset = 46 + languages.len();
    let mut strings = vec![0; 46];
    strings[3] = hii::PACKAGE_STRINGS;
    strings[4..8].copy_from_slice(&(offset as u32).to_le_bytes());
    strings[8..12].copy_from_slice(&(offset as u32).to_le_bytes());
    strings.extend_from_slice(languages);
    strings.extend_from_slice(&[
        0x10, b'A', 0, // SCSU id 1
        0x14, 0x4c, 0x75, 0, 0, // UCS-2 id 2: U+754C
        0,
    ]);
    let length = strings.len() as u32;
    strings[..3].copy_from_slice(&length.to_le_bytes()[..3]);
    let mut list = vec![0; 20];
    list.extend_from_slice(&strings);
    list.extend_from_slice(&[4, 0, 0, hii::PACKAGE_END]);
    let length = list.len() as u32;
    list[16..20].copy_from_slice(&length.to_le_bytes());
    list
}

#[test]
fn hii_mutations_fail_cleanly_and_getters_need_no_heap() {
    // All protocol pointers and input/output buffers remain valid for each call.
    unsafe {
        let db = &*database_protocol().cast::<hii_database::Protocol>();
        let strings = &*string_protocol().cast::<hii_string::Protocol>();
        let bytes = package();
        let sentinel = ptr::dangling_mut::<u8>().cast();
        let mut handle = sentinel;
        // Package bytes and the database's package vector are both fallible.
        for budget in 0..2 {
            let status = with_budget(budget, || {
                (db.new_package_list)(db, bytes.as_ptr().cast(), ptr::null_mut(), &mut handle)
            });
            assert_eq!(status, Status::OUT_OF_RESOURCES);
            assert_eq!(handle, sentinel);
        }
        assert_eq!(
            (db.new_package_list)(db, bytes.as_ptr().cast(), ptr::null_mut(), &mut handle),
            Status::SUCCESS
        );

        let language = c"en-US".as_ptr().cast();
        let mut value = [b'X' as u16, 0];
        let mut id = u16::MAX;
        // Language, UTF-16 payload and dynamic-string vector reservations.
        for budget in 0..3 {
            let status = with_budget(budget, || {
                (strings.new_string)(
                    strings,
                    handle,
                    &mut id,
                    language,
                    ptr::null(),
                    value.as_mut_ptr(),
                    ptr::null(),
                )
            });
            assert_eq!(status, Status::OUT_OF_RESOURCES);
            assert_eq!(id, u16::MAX);
        }
        assert_eq!(
            (strings.new_string)(
                strings,
                handle,
                &mut id,
                language,
                ptr::null(),
                value.as_mut_ptr(),
                ptr::null()
            ),
            Status::SUCCESS
        );
        assert_eq!(id, 3); // Failed calls neither consume an ID nor publish a string.

        value[0] = b'Y' as u16;
        let status = with_budget(0, || {
            (strings.set_string)(
                strings,
                handle,
                id,
                language,
                value.as_mut_ptr(),
                ptr::null(),
            )
        });
        assert_eq!(status, Status::OUT_OF_RESOURCES);
        // Adding a translation of a compiled ID must also leave no partial update.
        for budget in 0..2 {
            let status = with_budget(budget, || {
                (strings.set_string)(
                    strings,
                    handle,
                    1,
                    language,
                    value.as_mut_ptr(),
                    ptr::null(),
                )
            });
            assert_eq!(status, Status::OUT_OF_RESOURCES);
        }

        for (id, expected) in [(1, b'A' as u16), (2, 0x754c), (3, b'X' as u16)] {
            let mut size = 0;
            let status = with_budget(0, || {
                (strings.get_string)(
                    strings,
                    language,
                    handle,
                    id,
                    ptr::null_mut(),
                    &mut size,
                    ptr::null_mut(),
                )
            });
            assert_eq!(status, Status::BUFFER_TOO_SMALL);
            assert_eq!(size, 4);
            let mut output = [0xa5a5; 3];
            size = 2;
            let status = with_budget(0, || {
                (strings.get_string)(
                    strings,
                    language,
                    handle,
                    id,
                    output.as_mut_ptr(),
                    &mut size,
                    ptr::null_mut(),
                )
            });
            assert_eq!(status, Status::BUFFER_TOO_SMALL);
            assert_eq!(output, [0xa5a5; 3]);
            let status = with_budget(0, || {
                (strings.get_string)(
                    strings,
                    language,
                    handle,
                    id,
                    output.as_mut_ptr(),
                    &mut size,
                    ptr::null_mut(),
                )
            });
            assert_eq!(status, Status::SUCCESS);
            assert_eq!(output, [expected, 0, 0xa5a5]);
        }

        let mut size = 0;
        let status = with_budget(0, || {
            (strings.get_languages)(strings, handle, ptr::null_mut(), &mut size)
        });
        assert_eq!(status, Status::BUFFER_TOO_SMALL);
        assert_eq!(size, b"en-US;en\0".len());
        let mut output = [0xa5; 32];
        let status = with_budget(0, || {
            (strings.get_languages)(strings, handle, output.as_mut_ptr(), &mut size)
        });
        assert_eq!(status, Status::SUCCESS);
        assert_eq!(&output[..size], b"en-US;en\0");
        assert_eq!(output[size], 0xa5);
        size = 0;
        let status = with_budget(0, || {
            (strings.get_secondary_languages)(strings, handle, language, ptr::null_mut(), &mut size)
        });
        assert_eq!(status, Status::BUFFER_TOO_SMALL);
        let status = with_budget(0, || {
            (strings.get_secondary_languages)(
                strings,
                handle,
                language,
                output.as_mut_ptr(),
                &mut size,
            )
        });
        assert_eq!(status, Status::SUCCESS);
        assert_eq!(&output[..size], b"en;EN-us\0");
        assert_eq!((db.remove_package_list)(db, handle), Status::SUCCESS);
    }
}
