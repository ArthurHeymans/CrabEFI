//! Random operation sequences against a page-level oracle.
//!
//! The Kani harnesses in `src/proofs.rs` (`descriptor_and_owner_splits_agree`,
//! `owner_split_keeps_every_page_owned_once`, `exact_cover_requires_an_exact_tiling`)
//! prove range-splitting and exact-cover arithmetic over 64-bit ranges.
//! These property tests exercise full [`MemoryMap`] operations at table sizes
//! where capacity failures are frequent, comparing every page
//! in a 64-page window before and after each step.

use crabefi_memmap::{
    AllocateType, MemoryDescriptor, MemoryMap, MemoryRegion, MemoryType, PAGE_SIZE, PageAllocation,
    RegionType, attributes,
};
use proptest::prelude::*;
use r_efi::efi::Status;

const BASE: u64 = 0x10_0000_0000;
const WINDOW: u64 = 64;

#[derive(Clone, Copy, Debug)]
enum Op {
    Address {
        ty: u8,
        page: u64,
        pages: u64,
    },
    Any {
        ty: u8,
        pages: u64,
    },
    Below {
        ty: u8,
        pages: u64,
        max_page: u64,
    },
    /// Free part of the `owner`-th live record (modulo the count), or a random
    /// range when there is none.
    FreeOwned {
        owner: usize,
        skip: u64,
        pages: u64,
    },
    Free {
        page: u64,
        pages: u64,
    },
    PeImage {
        pages: u64,
        code: (u64, u64),
        second_code: Option<(u64, u64)>,
        runtime: bool,
    },
    FreePe {
        owner: usize,
    },
    RuntimeImage {
        pages: u64,
        code: u64,
    },
}

const TYPES: [MemoryType; 7] = [
    MemoryType::LoaderCode,
    MemoryType::LoaderData,
    MemoryType::BootServicesCode,
    MemoryType::BootServicesData,
    MemoryType::RuntimeServicesCode,
    MemoryType::RuntimeServicesData,
    // Rejected by allocation.
    MemoryType::ConventionalMemory,
];

fn op() -> impl Strategy<Value = Op> {
    let ty = 0u8..TYPES.len() as u8;
    let page = 0..WINDOW + 2;
    let pages = 1..9u64;
    prop_oneof![
        (ty.clone(), page.clone(), pages.clone()).prop_map(|(ty, page, pages)| Op::Address {
            ty,
            page,
            pages
        }),
        (ty.clone(), pages.clone()).prop_map(|(ty, pages)| Op::Any { ty, pages }),
        (ty.clone(), pages.clone(), page.clone()).prop_map(|(ty, pages, max_page)| Op::Below {
            ty,
            pages,
            max_page
        }),
        (any::<usize>(), 0..4u64, pages.clone()).prop_map(|(owner, skip, pages)| Op::FreeOwned {
            owner,
            skip,
            pages
        }),
        (page, pages.clone()).prop_map(|(page, pages)| Op::Free { page, pages }),
        (
            2..10u64,
            (0..10u64, 1..4u64),
            proptest::option::of((0..10u64, 1..4u64)),
            any::<bool>()
        )
            .prop_map(|(pages, code, second_code, runtime)| Op::PeImage {
                pages,
                code,
                second_code,
                runtime
            }),
        any::<usize>().prop_map(|owner| Op::FreePe { owner }),
        (1..8u64, 1..8u64).prop_map(|(pages, code)| Op::RuntimeImage { pages, code }),
    ]
}

/// Platform regions inside the window: RAM with occasional reserved holes.
fn regions() -> impl Strategy<Value = Vec<MemoryRegion>> {
    proptest::collection::vec((1..24u64, 0..3u8, 0..2u64), 1..6).prop_map(|parts| {
        let mut page = 0;
        let mut regions = Vec::new();
        for (pages, kind, gap) in parts {
            page += gap;
            if page + pages > WINDOW {
                break;
            }
            regions.push(MemoryRegion {
                base: BASE + page * PAGE_SIZE,
                size: pages * PAGE_SIZE,
                region_type: if kind == 0 {
                    RegionType::Reserved
                } else {
                    RegionType::Ram
                },
            });
            page += pages;
        }
        regions
    })
}

type Page = Option<(u32, u64)>;

fn pages<const E: usize, const O: usize>(map: &MemoryMap<E, O>) -> Vec<Page> {
    (0..WINDOW + 2)
        .map(|page| {
            let address = BASE + page * PAGE_SIZE;
            map.descriptors()
                .iter()
                .find(|d| d.physical_start <= address && address < d.end())
                .map(|d| (d.memory_type, d.attribute))
        })
        .collect()
}

fn owner_at<const E: usize, const O: usize>(
    map: &MemoryMap<E, O>,
    page: u64,
) -> Option<(MemoryType, u64)> {
    let address = BASE + page * PAGE_SIZE;
    map.allocations()
        .iter()
        .find(|o| o.range.start_bytes() <= address && address < o.range.end_bytes())
        .map(|o| (o.memory_type, o.restore_attribute))
}

struct Snapshot {
    descriptors: Vec<MemoryDescriptor>,
    allocations: Vec<PageAllocation>,
    map_key: usize,
}

impl Snapshot {
    fn of<const E: usize, const O: usize>(map: &MemoryMap<E, O>) -> Self {
        Self {
            descriptors: map.descriptors().to_vec(),
            allocations: map.allocations().to_vec(),
            map_key: map.map_key(),
        }
    }

    fn map_key(&self) -> usize {
        self.map_key
    }

    fn owner_at(&self, page: u64) -> Option<(MemoryType, u64)> {
        let address = BASE + page * PAGE_SIZE;
        self.allocations
            .iter()
            .find(|o| o.range.start_bytes() <= address && address < o.range.end_bytes())
            .map(|o| (o.memory_type, o.restore_attribute))
    }
}

fn same_state<const E: usize, const O: usize>(a: &Snapshot, b: &MemoryMap<E, O>) -> bool {
    a.descriptors.as_slice() == b.descriptors()
        && a.allocations.as_slice() == b.allocations()
        && a.map_key == b.map_key()
}

fn conventional(page: Page) -> bool {
    page.is_some_and(|(ty, _)| ty == MemoryType::ConventionalMemory as u32)
}

/// GetMemoryMap returns merged descriptors that describe the same pages.
fn check_exported<const E: usize, const O: usize>(map: &MemoryMap<E, O>) {
    let mut buffer = vec![MemoryDescriptor::default(); E];
    let mut size = core::mem::size_of_val(buffer.as_slice());
    let (mut key, mut stride, mut version) = (0, 0, 0);
    assert_eq!(
        map.get_memory_map(
            &mut size,
            Some(&mut buffer),
            &mut key,
            &mut stride,
            &mut version
        ),
        Status::SUCCESS
    );
    assert_eq!(key, map.map_key());
    let exported = &buffer[..size / stride];
    let strip = attributes::EFI_MEMORY_RO | attributes::EFI_MEMORY_XP | attributes::EFI_MEMORY_RP;
    for pair in exported.windows(2) {
        assert!(
            pair[0].end() <= pair[1].physical_start,
            "exported map unsorted"
        );
        assert!(
            pair[0].end() != pair[1].physical_start
                || pair[0].memory_type != pair[1].memory_type
                || pair[0].attribute != pair[1].attribute,
            "exported map left mergeable neighbours"
        );
    }
    for page in 0..WINDOW + 2 {
        let address = BASE + page * PAGE_SIZE;
        let internal = map
            .descriptors()
            .iter()
            .find(|d| d.physical_start <= address && address < d.end())
            .map(|d| (d.memory_type, d.attribute & !strip));
        let external = exported
            .iter()
            .find(|d| d.physical_start <= address && address < d.end())
            .map(|d| (d.memory_type, d.attribute));
        assert_eq!(internal, external, "page {page}");
    }
}

fn run<const E: usize, const O: usize>(
    regions: &[MemoryRegion],
    ops: &[Op],
    insert_individually: bool,
) {
    let mut map = MemoryMap::<E, O>::new();
    if insert_individually {
        for region in regions {
            let mem_type = match region.region_type {
                RegionType::Ram => MemoryType::ConventionalMemory,
                _ => MemoryType::ReservedMemoryType,
            };
            let _ = map.force_add_region(region.base, region.size / PAGE_SIZE, mem_type);
        }
    } else {
        map.init_from_platform(regions);
    }
    map.check_well_formed().unwrap();
    for &op in ops {
        let before = Snapshot::of(&map);
        let old = pages(&map);
        // (first page, page count, resulting type) when the op claims or
        // releases exactly one contiguous range.
        let (status, effect): (Status, Option<(u64, u64, MemoryType)>) = match op {
            Op::Address { ty, page, pages } => {
                let ty = TYPES[ty as usize];
                let mut address = BASE + page * PAGE_SIZE;
                let status =
                    map.allocate_pages(AllocateType::AllocateAddress, ty, pages, &mut address);
                (status, Some((page, pages, ty)))
            }
            Op::Any { ty, pages } | Op::Below { ty, pages, .. } => {
                let ty = TYPES[ty as usize];
                let (kind, mut address, limit) = match op {
                    Op::Below { max_page, .. } => {
                        let limit = BASE + max_page * PAGE_SIZE - 1;
                        (AllocateType::AllocateMaxAddress, limit, limit)
                    }
                    _ => (AllocateType::AllocateAnyPages, 0, u64::MAX),
                };
                let status = map.allocate_pages(kind, ty, pages, &mut address);
                if status == Status::SUCCESS {
                    assert!(address + pages * PAGE_SIZE - 1 <= limit);
                    let first = (address - BASE) / PAGE_SIZE;
                    assert!(
                        (first..first + pages).all(|p| conventional(old[p as usize])),
                        "search took non-free pages"
                    );
                    (status, Some((first, pages, ty)))
                } else {
                    (status, None)
                }
            }
            Op::FreeOwned { owner, skip, pages } => {
                let (address, count) = match map.allocations() {
                    [] => (BASE, pages),
                    owners => {
                        let o = owners[owner % owners.len()];
                        let total = o.range.pages().get();
                        let skip = skip.min(total - 1);
                        (
                            o.range.start_bytes() + skip * PAGE_SIZE,
                            pages.min(total - skip),
                        )
                    }
                };
                let status = map.free_pages(address, count);
                let first = (address - BASE) / PAGE_SIZE;
                (status, Some((first, count, MemoryType::ConventionalMemory)))
            }
            Op::Free { page, pages } => (
                map.free_pages(BASE + page * PAGE_SIZE, pages),
                Some((page, pages, MemoryType::ConventionalMemory)),
            ),
            Op::PeImage {
                pages,
                code,
                second_code,
                runtime,
            } => {
                let mut base = 0;
                let status = map.allocate_pages(
                    AllocateType::AllocateAnyPages,
                    MemoryType::LoaderCode,
                    pages,
                    &mut base,
                );
                let mut effect = None;
                if status == Status::SUCCESS {
                    let first = (base - BASE) / PAGE_SIZE;
                    let mut ranges: Vec<_> = core::iter::once(code)
                        .chain(second_code)
                        .map(|(start, len)| start..start + len)
                        .collect();
                    ranges.sort_by_key(|r| r.start);
                    let (code_ty, data_ty) = if runtime {
                        (
                            MemoryType::RuntimeServicesCode,
                            MemoryType::RuntimeServicesData,
                        )
                    } else {
                        (MemoryType::BootServicesCode, MemoryType::BootServicesData)
                    };
                    let staged = Snapshot::of(&map);
                    match map.retype_pe_image(base, pages, code_ty, data_ty, &ranges) {
                        Ok(()) => {
                            map.check_well_formed().unwrap();
                            let retyped = crate::pages(&map);
                            for page in 0..pages {
                                let expected = if ranges.iter().any(|r| r.contains(&page)) {
                                    code_ty
                                } else {
                                    data_ty
                                };
                                let index = (first + page) as usize;
                                assert_eq!(retyped[index].map(|(t, _)| t), Some(expected as u32));
                                assert_eq!(
                                    owner_at(&map, first + page).map(|(t, _)| t),
                                    Some(expected)
                                );
                            }
                            let loaded = Snapshot::of(&map);
                            match map.free_pe_image(base, pages) {
                                Status::SUCCESS => {
                                    assert_eq!(crate::pages(&map), old, "PE image round trip");
                                }
                                Status::OUT_OF_RESOURCES => {
                                    assert!(
                                        E - loaded.descriptors.len() < 2,
                                        "unexpected PE unload failure"
                                    );
                                    assert!(
                                        same_state(&loaded, &map),
                                        "rejected PE unload changed the map"
                                    );
                                    for (p, page) in old.iter().enumerate() {
                                        if !(first..first + pages).contains(&(p as u64)) {
                                            assert_eq!(
                                                retyped[p], *page,
                                                "PE load changed page {p}"
                                            );
                                            assert_eq!(
                                                owner_at(&map, p as u64),
                                                before.owner_at(p as u64)
                                            );
                                        }
                                    }
                                }
                                status => panic!("unexpected PE unload status: {status:?}"),
                            }
                        }
                        Err(_) => {
                            assert!(same_state(&staged, &map), "failed PE retype");
                            effect = Some((first, pages, MemoryType::LoaderCode));
                        }
                    }
                }
                (status, effect)
            }
            Op::FreePe { owner } => match map.allocations() {
                [] => (Status::NOT_FOUND, None),
                owners => {
                    let o = owners[owner % owners.len()];
                    let first = (o.range.start_bytes() - BASE) / PAGE_SIZE;
                    let pages = o.range.pages().get();
                    let status = map.free_pe_image(o.range.start_bytes(), pages);
                    (status, Some((first, pages, MemoryType::ConventionalMemory)))
                }
            },
            Op::RuntimeImage { pages, code } => {
                let status = match map.allocate_runtime_image_layout(pages, code) {
                    Ok(base) => {
                        let first = (base - BASE) / PAGE_SIZE;
                        let new = crate::pages(&map);
                        for p in first..first + pages {
                            let (ty, attribute) = new[p as usize].unwrap();
                            let code_page = p < first + code;
                            assert_eq!(
                                ty,
                                if code_page {
                                    MemoryType::RuntimeServicesCode
                                } else {
                                    MemoryType::RuntimeServicesData
                                } as u32
                            );
                            assert_ne!(attribute & attributes::EFI_MEMORY_RUNTIME, 0);
                            assert_eq!(attribute & attributes::EFI_MEMORY_XP != 0, !code_page);
                            // The image is permanent: no public record owns it.
                            assert_eq!(owner_at(&map, p), None);
                        }
                        for (p, page) in old.iter().enumerate() {
                            if !(first..first + pages).contains(&(p as u64)) {
                                assert_eq!(new[p], *page, "runtime image changed page {p}");
                            }
                        }
                        Status::SUCCESS
                    }
                    Err(status) => status,
                };
                (status, None)
            }
        };

        map.check_well_formed()
            .unwrap_or_else(|error| panic!("{op:?} broke the map: {error}"));
        check_exported(&map);
        if status != Status::SUCCESS {
            assert!(same_state(&before, &map), "failed {op:?} changed the map");
            continue;
        }
        assert!(map.map_key() > before.map_key());
        let new = pages(&map);
        // Address space is neither created nor destroyed.
        for (page, (a, b)) in old.iter().zip(&new).enumerate() {
            assert_eq!(a.is_some(), b.is_some(), "{op:?} page {page}");
        }
        let Some((first, count, ty)) = effect else {
            continue;
        };
        for page in 0..WINDOW + 2 {
            let inside = (first..first + count).contains(&page);
            if !inside {
                assert_eq!(old[page as usize], new[page as usize], "{op:?} page {page}");
                assert_eq!(
                    before.owner_at(page),
                    owner_at(&map, page),
                    "{op:?} page {page}"
                );
            } else if ty == MemoryType::ConventionalMemory {
                let (_, restore) = before.owner_at(page).expect("freed an unowned page");
                assert_eq!(new[page as usize], Some((ty as u32, restore)));
                assert_eq!(owner_at(&map, page), None);
            } else {
                assert_eq!(new[page as usize].map(|(t, _)| t), Some(ty as u32));
                assert_eq!(owner_at(&map, page).map(|(t, _)| t), Some(ty));
            }
        }
    }

    // ExitBootServices hands firmware memory to the OS and nothing else.
    let before = Snapshot::of(&map);
    let old = pages(&map);
    assert_eq!(
        map.exit_boot_services(map.map_key().wrapping_add(1)),
        Status::INVALID_PARAMETER
    );
    assert!(same_state(&before, &map));
    assert_eq!(map.exit_boot_services(map.map_key()), Status::SUCCESS);
    map.check_well_formed().unwrap();
    for (a, b) in old.iter().zip(pages(&map)) {
        let firmware = a.is_some_and(|(ty, _)| {
            ty == MemoryType::BootServicesCode as u32 || ty == MemoryType::BootServicesData as u32
        });
        if firmware {
            assert_eq!(
                b,
                a.map(|(_, attribute)| (MemoryType::ConventionalMemory as u32, attribute))
            );
        } else {
            assert_eq!(*a, b);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Tables so small that splits often fail outright.
    #[test]
    fn small_tables(
        regions in regions(),
        ops in proptest::collection::vec(op(), 1..48),
        insert_individually in any::<bool>(),
    ) {
        run::<6, 4>(&regions, &ops, insert_individually);
    }

    #[test]
    fn medium_tables(regions in regions(), ops in proptest::collection::vec(op(), 1..64)) {
        run::<12, 10>(&regions, &ops, false);
    }

    #[test]
    fn roomy_tables(regions in regions(), ops in proptest::collection::vec(op(), 1..96)) {
        run::<64, 64>(&regions, &ops, false);
    }
}
