use r_efi::efi::Status;

/// One caller-initiated ExitBootServices attempt. Never retry on behalf of the
/// OS: it needs a fresh GetMemoryMap after a `BEFORE_EXIT_BOOT_SERVICES`
/// callback has changed the allocator key.
///
/// Order:
/// 1. Validate `key` before running any callbacks.
/// 2. Run `prepare` (`BEFORE_EXIT_BOOT_SERVICES` + MAT rebuild).
/// 3. Re-validate `key` before the point of no return.
/// 4. Notify `EXIT_BOOT_SERVICES` events, quiesce DMA, commit the allocator,
///    and run `finish`.
#[allow(clippy::too_many_arguments)]
#[inline]
pub(super) fn attempt<T>(
    key: usize,
    validate: impl Fn(usize) -> Status,
    prepare: impl FnOnce() -> Result<T, Status>,
    on_failure: impl FnOnce(Status),
    notify_exit: impl FnOnce(),
    quiesce: impl FnOnce(),
    commit: impl FnOnce(usize),
    finish: impl FnOnce(T),
) -> Status {
    let status = validate(key);
    if status != Status::SUCCESS {
        return status;
    }
    let prepared = match prepare() {
        Ok(prepared) => prepared,
        Err(status) => {
            on_failure(status);
            return status;
        }
    };
    // BEFORE_EXIT_BOOT_SERVICES callbacks and MAT preparation ran with Boot
    // Services live. Reject a stale key before notifying EXIT_BOOT_SERVICES,
    // stopping DMA, or committing the allocator.
    let status = validate(key);
    if status != Status::SUCCESS {
        on_failure(status);
        return status;
    }
    notify_exit();
    quiesce();
    commit(key);
    finish(prepared);
    Status::SUCCESS
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
        let prepares = Cell::new(0);
        let failures = Cell::new(0);
        let exit_notifies = Cell::new(0);
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
                |_| failures.set(failures.get() + 1),
                || {
                    assert_eq!(quiesces.get(), 0);
                    assert_eq!(commits.get(), 0);
                    exit_notifies.set(exit_notifies.get() + 1);
                },
                || {
                    assert_eq!(exit_notifies.get(), 1);
                    quiesces.set(quiesces.get() + 1);
                },
                |k| {
                    assert_eq!(validate(k), Status::SUCCESS);
                    assert_eq!(quiesces.get(), 1);
                    commits.set(commits.get() + 1);
                },
                |()| {
                    assert_eq!(commits.get(), 1);
                    seals.set(seals.get() + 1);
                },
            )
        };
        let counts = || {
            (
                prepares.get(),
                failures.get(),
                exit_notifies.get(),
                quiesces.get(),
                commits.get(),
                seals.get(),
            )
        };
        // Stale key on entry: nothing runs.
        assert_eq!(run(stale), Status::INVALID_PARAMETER);
        assert_eq!(counts(), (0, 0, 0, 0, 0, 0));
        // Valid key, but BEFORE_EXIT callback mutates the map: fails before
        // EXIT_BOOT_SERVICES notification, DMA quiescence, or commit.
        assert_eq!(run(initial), Status::INVALID_PARAMETER);
        assert_eq!(counts(), (1, 1, 0, 0, 0, 0));
        // Caller refreshes GetMemoryMap and retries: succeeds once.
        let refreshed = get_key();
        assert_ne!(refreshed, initial);
        assert_eq!(run(refreshed), Status::SUCCESS);
        assert_eq!(counts(), (2, 1, 1, 1, 1, 1));
        // Any subsequent call fails immediately without running callbacks.
        assert_eq!(run(refreshed), Status::INVALID_PARAMETER);
        assert_eq!(counts(), (2, 1, 1, 1, 1, 1));
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
