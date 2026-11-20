use r_efi::efi::Status;

/// One caller-initiated attempt. Never retry on behalf of the OS: it needs a
/// fresh GetMemoryMap after an event callback has changed the allocator key.
#[inline]
pub(super) fn attempt<T>(
    key: usize,
    validate: impl Fn(usize) -> Status,
    prepare: impl FnOnce() -> Result<T, Status>,
    quiesce: impl FnOnce(),
    commit: impl FnOnce(usize) -> Status,
    finish: impl FnOnce(T),
) -> Status {
    let status = validate(key);
    if status != Status::SUCCESS {
        return status;
    }
    let prepared = match prepare() {
        Ok(prepared) => prepared,
        Err(status) => return status,
    };
    // Events and MAT preparation ran with Boot Services live. Reject their
    // stale key before stopping DMA, not merely inside allocator commit.
    let status = validate(key);
    if status != Status::SUCCESS {
        return status;
    }
    quiesce();
    let status = commit(key);
    if status == Status::SUCCESS {
        finish(prepared);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    // Model only the external effects. The sequence is the same function the
    // firmware entry point calls; the allocator decides key validity.
    fn retry_scenario(
        stale: usize,
        get_key: impl Fn() -> usize,
        validate: impl Fn(usize) -> Status,
        change_map: impl Fn(),
    ) {
        let initial = get_key();
        let mut quiesced = false;
        let result = attempt(
            initial,
            &validate,
            || Ok(()),
            || quiesced = true,
            |_| Status::DEVICE_ERROR,
            |()| panic!("failed commit reached finish"),
        );
        assert_eq!(result, Status::DEVICE_ERROR);
        assert!(quiesced);

        let prepares = Cell::new(0);
        let quiesces = Cell::new(0);
        let commits = Cell::new(0);
        let seals = Cell::new(0);
        let run = |provided| {
            attempt(
                provided,
                |k| {
                    if commits.get() == 0 {
                        validate(k)
                    } else {
                        Status::INVALID_PARAMETER
                    }
                },
                || {
                    if prepares.get() == 0 {
                        change_map();
                    }
                    prepares.set(prepares.get() + 1);
                    Ok(())
                },
                || quiesces.set(quiesces.get() + 1),
                |k| {
                    assert_eq!(validate(k), Status::SUCCESS);
                    assert_eq!(quiesces.get(), 1);
                    commits.set(commits.get() + 1);
                    Status::SUCCESS
                },
                |()| {
                    assert_eq!(commits.get(), 1);
                    seals.set(seals.get() + 1);
                },
            )
        };
        let counts = || (prepares.get(), quiesces.get(), commits.get(), seals.get());
        assert_eq!(run(stale), Status::INVALID_PARAMETER);
        assert_eq!(counts(), (0, 0, 0, 0));
        assert_eq!(run(initial), Status::INVALID_PARAMETER);
        assert_eq!(counts(), (1, 0, 0, 0));
        let refreshed = get_key();
        assert_ne!(refreshed, initial);
        assert_eq!(run(refreshed), Status::SUCCESS);
        assert_eq!(counts(), (2, 1, 1, 1));
        assert_eq!(run(refreshed), Status::INVALID_PARAMETER);
        assert_eq!(counts(), (2, 1, 1, 1));
    }

    #[test]
    fn callback_invalidates_key_and_refreshed_key_retries_once() {
        use crate::efi::allocator::{AllocateType, MemoryAllocator, MemoryDescriptor, MemoryType};
        use core::cell::RefCell;

        let allocator = RefCell::new(MemoryAllocator::new());
        const RAM: u64 = 0x10_0000;
        allocator
            .borrow_mut()
            .force_add_region(RAM, 1, MemoryType::ConventionalMemory)
            .unwrap();
        retry_scenario(
            0,
            || {
                let mut map = [MemoryDescriptor::default()];
                let mut size = core::mem::size_of_val(&map);
                let (mut key, mut stride, mut version) = (0, 0, 0);
                assert_eq!(
                    allocator.borrow().get_memory_map(
                        &mut size,
                        Some(&mut map),
                        &mut key,
                        &mut stride,
                        &mut version
                    ),
                    Status::SUCCESS
                );
                key
            },
            |key| allocator.borrow().validate_map_key(key),
            || {
                let mut address = RAM;
                assert_eq!(
                    allocator.borrow_mut().allocate_pages(
                        AllocateType::AllocateAddress,
                        MemoryType::LoaderData,
                        1,
                        &mut address
                    ),
                    Status::SUCCESS
                );
            },
        );
    }
}
