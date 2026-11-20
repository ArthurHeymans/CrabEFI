use super::*;

#[test]
fn reservations_grow_past_32_without_moving_protocol_addresses() {
    let mut pool = FilePool::new();
    let mut pointers = Vec::new();
    for _ in 0..96 {
        let index = pool
            .reserve()
            .expect("available boot memory must permit more than 32 slots");
        pointers.push((index, pool.handles.protocol(index.0)));
        for (index, pointer) in &pointers {
            assert_eq!(*pointer, pool.handles.protocol(index.0));
        }
    }
}

/// Under Miri this checks that published protocol pointers stay valid for
/// reads after handle bookkeeping changes and the pool grows new slabs.
#[test]
fn published_protocols_stay_readable_across_mutation_and_growth() {
    let mut pool = FilePool::new();
    let first = pool.reserve().unwrap();
    let pointer = pool.handles.protocol(first.0);
    pool.set_position(first, 7);
    for _ in 0..40 {
        let index = pool.reserve().unwrap();
        pool.set_position(index, 9);
    }
    pool.set_position(first, 11);
    // SAFETY: the protocol slab is never freed or moved while the pool lives.
    let (revision, close) = unsafe { ((*pointer).revision, (*pointer).close) };
    assert_eq!(revision, efi_file::REVISION);
    core::hint::black_box(close);
}

#[test]
fn released_reservations_are_reused_without_growth_or_stale_cursors() {
    let mut pool = FilePool::new();
    let indices: Vec<_> = (0..65).map(|_| pool.reserve().unwrap()).collect();
    let slots = pool.handles.len();
    let pointer = pool.handles.protocol(indices[0].0);
    pool.set_position(indices[0], 123);
    pool.release(indices[0]);
    for _ in 0..1000 {
        let index = pool.reserve().unwrap();
        assert_eq!(index.0, indices[0].0);
        assert_eq!(pool.handles[index.0].position, 0);
        assert_eq!(pool.handles[index.0].open_mode, 0);
        assert_eq!(pointer, pool.handles.protocol(index.0));
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
    let pointer = pool.handles.protocol(0);
    let slots = pool.handles.len();
    pool.reset();
    assert!(pool.handles.iter().all(|handle| !handle.in_use));
    assert!(pool.nodes.iter().all(|node| node.references == 0));
    let index = pool.reserve().unwrap();
    assert_eq!(index.0, 0);
    assert_eq!(pointer, pool.handles.protocol(0));
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
    let pointer = pool.handles.protocol(0);
    assert!(matches!(pool.reserve(), Err(Status::OUT_OF_RESOURCES)));
    assert_eq!(pool.handles.len(), SLOTS_PER_SLAB);
    assert_eq!(pool.nodes.len(), SLOTS_PER_SLAB);
    assert_eq!(pointer, pool.handles.protocol(0));
    assert!(pool.handles.iter().all(|handle| handle.in_use));
    pool.release(indices[0]);
    assert_eq!(pool.reserve().unwrap().0, 0);
}

#[test]
fn allocator_failures_do_not_publish_partial_slabs_or_consume_reservations() {
    use crate::test_allocator::with_budget;

    // Growing reserves the handle slab, the protocol slab, both outer
    // vectors and the node vector.
    const GROWTH_ALLOCATIONS: usize = 5;
    {
        // Exactly that many: a new allocation site must join the sweep below.
        let mut pool = FilePool::new();
        let (result, attempts) = with_budget(GROWTH_ALLOCATIONS, || pool.reserve());
        assert!(result.is_ok());
        assert_eq!(attempts, GROWTH_ALLOCATIONS);
    }
    for occupied in [0, SLOTS_PER_SLAB] {
        // Fail each growth allocation in turn. Each case starts fresh so
        // retained capacity cannot skip a failure.
        for allowed in 0..GROWTH_ALLOCATIONS {
            let mut pool = FilePool::new();
            let pointers: Vec<_> = (0..occupied)
                .map(|position| {
                    let index = pool.reserve().unwrap();
                    pool.set_position(index, position as u64 + 1);
                    pool.handles.protocol(index.0)
                })
                .collect();
            let (result, attempts) = with_budget(allowed, || pool.reserve());
            assert!(matches!(result, Err(Status::OUT_OF_RESOURCES)));
            assert_eq!(attempts, allowed + 1);
            assert_eq!(pool.handles.len(), occupied);
            assert_eq!(pool.nodes.len(), occupied);
            assert_eq!(pool.handles.slabs.len() * SLOTS_PER_SLAB, occupied);
            assert_eq!(pool.handles.protocols.len() * SLOTS_PER_SLAB, occupied);
            for (index, pointer) in pointers.into_iter().enumerate() {
                assert_eq!(pointer, pool.handles.protocol(index));
                assert!(pool.handles[index].in_use);
                assert_eq!(pool.handles[index].position, index as u64 + 1);
            }
            if occupied != 0 {
                pool.release(HandleId(0));
                let (result, attempts) = with_budget(0, || pool.reserve());
                assert_eq!(result.unwrap().0, 0);
                assert_eq!(attempts, 0, "reuse must not require an allocation");
            }
            // Retry must start at the first new slot, not skip a reservation
            // consumed by a failed grow, even if it retained vector capacity.
            assert_eq!(pool.reserve().unwrap().0, occupied);
            assert_eq!(pool.handles.len(), occupied + SLOTS_PER_SLAB);
        }
    }
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
