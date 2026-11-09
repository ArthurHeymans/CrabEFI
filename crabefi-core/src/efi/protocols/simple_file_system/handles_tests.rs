use super::*;

#[test]
fn reservations_grow_past_32_without_moving_protocol_addresses() {
    let mut pool = FilePool::new();
    let mut pointers = Vec::new();
    for _ in 0..96 {
        let index = pool
            .reserve()
            .expect("available boot memory must permit more than 32 slots");
        pointers.push((index, &raw mut pool.handles[index.0].protocol));
        for (index, pointer) in &pointers {
            assert_eq!(
                *pointer,
                &raw const pool.handles[index.0].protocol as *mut _
            );
        }
    }
}

#[test]
fn released_reservations_are_reused_without_growth_or_stale_cursors() {
    let mut pool = FilePool::new();
    let indices: Vec<_> = (0..65).map(|_| pool.reserve().unwrap()).collect();
    let slots = pool.handles.len();
    let pointer = &raw mut pool.handles[indices[0].0].protocol;
    pool.set_position(indices[0], 123);
    pool.release(indices[0]);
    for _ in 0..1000 {
        let index = pool.reserve().unwrap();
        assert_eq!(index.0, indices[0].0);
        assert_eq!(pool.handles[index.0].position, 0);
        assert_eq!(pool.handles[index.0].open_mode, 0);
        assert_eq!(pointer, &raw mut pool.handles[index.0].protocol);
        assert_eq!(pool.handles.len(), slots);
        pool.release(index);
    }
}

#[test]
fn reset_releases_reservations_but_keeps_protocol_storage_alive() {
    let mut pool = FilePool::new();
    for _ in 0..65 {
        pool.reserve().unwrap();
    }
    let pointer = &raw mut pool.handles[0].protocol;
    let slots = pool.handles.len();
    pool.reset();
    assert!(pool.handles.iter().all(|handle| !handle.in_use));
    assert!(pool.nodes.iter().all(|node| node.references == 0));
    let index = pool.reserve().unwrap();
    assert_eq!(index.0, 0);
    assert_eq!(pointer, &raw mut pool.handles[0].protocol);
    assert_eq!(pool.handles.len(), slots);
    // The representation stays initialized and allocated until pool teardown.
    assert_eq!(unsafe { (*pointer).revision }, efi_file::REVISION);
}

#[test]
fn denied_growth_preserves_existing_storage_and_can_reuse_a_freed_slot() {
    let mut pool = FilePool::new();
    pool.budget = 0;
    assert!(matches!(pool.reserve(), Err(Status::OUT_OF_RESOURCES)));
    assert!(pool.nodes.is_empty());
    assert_eq!(pool.handles.len(), 0);
    pool.budget = SLOTS_PER_SLAB * SLOT_COST;
    let indices: Vec<_> = (0..SLOTS_PER_SLAB)
        .map(|_| pool.reserve().unwrap())
        .collect();
    let pointer = &raw mut pool.handles[0].protocol;
    assert!(matches!(pool.reserve(), Err(Status::OUT_OF_RESOURCES)));
    assert_eq!(pool.handles.len(), SLOTS_PER_SLAB);
    assert_eq!(pool.nodes.len(), SLOTS_PER_SLAB);
    assert_eq!(pointer, &raw mut pool.handles[0].protocol);
    assert!(pool.handles.iter().all(|handle| handle.in_use));
    pool.release(indices[0]);
    assert_eq!(pool.reserve().unwrap().0, 0);
}

#[test]
fn payload_budget_bounds_growth_without_imposing_a_fixed_32_slot_limit() {
    let mut pool = FilePool::new();
    let slots = (POOL_BUDGET / SLOT_COST / SLOTS_PER_SLAB) * SLOTS_PER_SLAB;
    assert!(slots > 32);
    for _ in 0..slots {
        pool.reserve().unwrap();
    }
    assert!(matches!(pool.reserve(), Err(Status::OUT_OF_RESOURCES)));
    assert_eq!(pool.handles.len(), slots);
    assert!(slots * SLOT_COST <= POOL_BUDGET);
    assert!((slots + SLOTS_PER_SLAB) * SLOT_COST > POOL_BUDGET);
}
