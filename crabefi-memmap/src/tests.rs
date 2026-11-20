use super::*;

const MAX_MEMORY_ENTRIES: usize = 64;
type MemoryAllocator = MemoryMap<MAX_MEMORY_ENTRIES, 64>;

#[test]
fn memory_map_null_buffer_distinguishes_query_from_invalid_output() {
    let allocator = allocator_with_ram();
    let (mut size, mut key, mut descriptor_size, mut version) = (0, 0, 0, 0);
    assert_eq!(
        allocator.get_memory_map(
            &mut size,
            None,
            &mut key,
            &mut descriptor_size,
            &mut version
        ),
        efi::Status::BUFFER_TOO_SMALL
    );
    let required = size;
    assert_eq!(required, core::mem::size_of::<MemoryDescriptor>());
    for supplied in [1, required - 1] {
        size = supplied;
        assert_eq!(
            allocator.get_memory_map(
                &mut size,
                None,
                &mut key,
                &mut descriptor_size,
                &mut version
            ),
            efi::Status::BUFFER_TOO_SMALL
        );
        assert_eq!(size, required);
    }
    assert_eq!(
        allocator.get_memory_map(
            &mut size,
            None,
            &mut key,
            &mut descriptor_size,
            &mut version
        ),
        efi::Status::INVALID_PARAMETER
    );
    assert_eq!(size, required);
    let mut map = [memory_descriptor(MemoryType::ConventionalMemory, 0, 0, 0)];
    assert_eq!(
        allocator.get_memory_map(
            &mut size,
            Some(&mut map),
            &mut key,
            &mut descriptor_size,
            &mut version
        ),
        efi::Status::SUCCESS
    );
    assert_eq!(map[0].physical_start, 0x10_0000);
}

fn allocator_with_ram() -> MemoryAllocator {
    let mut allocator = MemoryAllocator::new();
    allocator
        .entries
        .push(memory_descriptor(
            MemoryType::ConventionalMemory,
            0x10_0000,
            32,
            attributes::EFI_MEMORY_RAM_CAPS,
        ))
        .unwrap();
    allocator
}

#[test]
fn acpi_marking_retypes_verified_platform_reserved_memory() {
    let mut allocator = allocator_with_ram();
    let reserved_start = 0x20_0000;
    allocator
        .entries
        .push(memory_descriptor(
            MemoryType::ReservedMemoryType,
            reserved_start,
            4,
            attributes::EFI_MEMORY_RAM_CAPS,
        ))
        .unwrap();

    allocator.mark_as_acpi_reclaim(reserved_start, 4).unwrap();
    allocator.mark_as_acpi_reclaim(0x10_0000, 4).unwrap();

    assert_eq!(
        allocator
            .entries
            .iter()
            .find(|entry| entry.physical_start == reserved_start)
            .and_then(MemoryDescriptorExt::get_memory_type),
        Some(MemoryType::AcpiReclaimMemory)
    );
    assert_eq!(
        allocator
            .entries
            .iter()
            .find(|entry| entry.physical_start == 0x10_0000)
            .and_then(MemoryDescriptorExt::get_memory_type),
        Some(MemoryType::AcpiReclaimMemory)
    );
}

#[test]
fn public_allocate_address_cannot_subclaim_runtime_image_data() {
    let mut allocator = allocator_with_ram();
    let mut base = 0;
    assert_eq!(
        allocator.allocate_pages(
            AllocateType::AllocateAnyPages,
            MemoryType::RuntimeServicesData,
            4,
            &mut base,
        ),
        efi::Status::SUCCESS
    );
    let mut claim = base;
    assert_eq!(
        allocator.allocate_pages(
            AllocateType::AllocateAddress,
            MemoryType::RuntimeServicesCode,
            1,
            &mut claim,
        ),
        efi::Status::NOT_FOUND
    );
}

#[test]
fn private_runtime_layout_split_preserves_runtime_attributes() {
    let mut allocator = allocator_with_ram();
    let mut base = 0;
    assert_eq!(
        allocator.allocate_pages(
            AllocateType::AllocateAnyPages,
            MemoryType::RuntimeServicesData,
            4,
            &mut base,
        ),
        efi::Status::SUCCESS
    );
    let image = PageRange::from_bytes(base, 4).unwrap();
    let code = PageRange::from_bytes(base, 1).unwrap();
    allocator.retype_runtime_image_code(image, code).unwrap();
    let code_descriptor = allocator
        .entries
        .iter()
        .find(|entry| entry.physical_start == base)
        .unwrap();
    assert_eq!(
        code_descriptor.get_memory_type(),
        Some(MemoryType::RuntimeServicesCode)
    );
    assert_ne!(
        code_descriptor.attribute & attributes::EFI_MEMORY_RUNTIME,
        0
    );
    assert_eq!(code_descriptor.attribute & attributes::EFI_MEMORY_XP, 0);
    let data_descriptor = allocator
        .entries
        .iter()
        .find(|entry| entry.physical_start == base + PAGE_SIZE)
        .unwrap();
    assert_eq!(
        data_descriptor.get_memory_type(),
        Some(MemoryType::RuntimeServicesData)
    );
    assert_ne!(data_descriptor.attribute & attributes::EFI_MEMORY_XP, 0);
    assert_eq!(allocator.free_pages(base, 1), efi::Status::NOT_FOUND);
    assert_eq!(
        allocator.free_pages(base + PAGE_SIZE, 3),
        efi::Status::NOT_FOUND
    );
    assert_eq!(
        allocator
            .entries
            .iter()
            .find(|entry| entry.physical_start == base)
            .and_then(MemoryDescriptorExt::get_memory_type),
        Some(MemoryType::RuntimeServicesCode)
    );
}

#[test]
fn pe_driver_layout_is_retained_and_can_be_freed_as_one_image() {
    for (code_type, data_type) in [
        (
            MemoryType::RuntimeServicesCode,
            MemoryType::RuntimeServicesData,
        ),
        (MemoryType::BootServicesCode, MemoryType::BootServicesData),
    ] {
        let mut allocator = allocator_with_ram();
        let mut base = 0;
        assert_eq!(
            allocator.allocate_pages(
                AllocateType::AllocateAnyPages,
                MemoryType::LoaderCode,
                8,
                &mut base
            ),
            efi::Status::SUCCESS
        );
        allocator
            .retype_pe_image(base, 8, code_type, data_type, &[1..3, 5..6])
            .unwrap();
        for page in 0..8 {
            let address = base + page * PAGE_SIZE;
            let expected = if (1..3).contains(&page) || page == 5 {
                code_type
            } else {
                data_type
            };
            let descriptor = allocator
                .entries
                .iter()
                .find(|entry| {
                    entry
                        .page_range()
                        .unwrap()
                        .contains(PageRange::from_bytes(address, 1).unwrap())
                })
                .unwrap();
            assert_eq!(descriptor.get_memory_type(), Some(expected));
            if code_type == MemoryType::RuntimeServicesCode {
                assert_ne!(descriptor.attribute & attributes::EFI_MEMORY_RUNTIME, 0);
                assert_eq!(
                    descriptor.attribute & attributes::EFI_MEMORY_XP != 0,
                    expected == data_type
                );
            }
        }
        assert_eq!(allocator.free_pages(base, 8), efi::Status::NOT_FOUND);
        assert_eq!(allocator.free_pe_image(base, 8), efi::Status::SUCCESS);
        assert!(allocator.allocations.is_empty());
        assert!(allocator.entries.iter().all(|entry| entry.get_memory_type()
            == Some(MemoryType::ConventionalMemory)
            && entry.attribute == attributes::EFI_MEMORY_RAM_CAPS));
        assert_eq!(
            allocator.allocate_pages(
                AllocateType::AllocateAnyPages,
                MemoryType::LoaderCode,
                8,
                &mut base
            ),
            efi::Status::SUCCESS
        );
        allocator
            .retype_pe_image(base, 8, code_type, data_type, &[1..3, 5..6])
            .unwrap();
        assert_eq!(
            allocator.exit_boot_services(allocator.map_key()),
            efi::Status::SUCCESS
        );
        let image = PageRange::from_bytes(base, 8).unwrap();
        for descriptor in allocator
            .entries
            .iter()
            .filter(|entry| entry.page_range().unwrap().overlaps(image))
        {
            if code_type == MemoryType::RuntimeServicesCode {
                assert!(matches!(
                    descriptor.get_memory_type(),
                    Some(MemoryType::RuntimeServicesCode | MemoryType::RuntimeServicesData)
                ));
                assert_ne!(descriptor.attribute & attributes::EFI_MEMORY_RUNTIME, 0);
            } else {
                assert_eq!(
                    descriptor.get_memory_type(),
                    Some(MemoryType::ConventionalMemory)
                );
            }
        }
    }
}

#[test]
fn invalid_pe_layout_leaves_staging_allocation_owned() {
    let mut allocator = allocator_with_ram();
    let mut base = 0;
    assert_eq!(
        allocator.allocate_pages(
            AllocateType::AllocateAnyPages,
            MemoryType::LoaderCode,
            8,
            &mut base
        ),
        efi::Status::SUCCESS
    );
    let key = allocator.map_key();
    for code in [
        &[1..3, 2..4][..],
        core::slice::from_ref(&(7..9)),
        core::slice::from_ref(&(4..4)),
    ] {
        assert_eq!(
            allocator.retype_pe_image(
                base,
                8,
                MemoryType::RuntimeServicesCode,
                MemoryType::RuntimeServicesData,
                code
            ),
            Err(efi::Status::INVALID_PARAMETER)
        );
        assert_eq!(allocator.map_key(), key);
    }
    while allocator.entries.len() < MAX_MEMORY_ENTRIES {
        let address = 0x1000_0000 + allocator.entries.len() as u64 * 2 * PAGE_SIZE;
        allocator
            .entries
            .push(memory_descriptor(
                MemoryType::ReservedMemoryType,
                address,
                1,
                0,
            ))
            .unwrap();
    }
    assert_eq!(
        allocator.retype_pe_image(
            base,
            8,
            MemoryType::RuntimeServicesCode,
            MemoryType::RuntimeServicesData,
            &[1..3, 5..6]
        ),
        Err(efi::Status::OUT_OF_RESOURCES)
    );
    assert_eq!(allocator.map_key(), key);
    assert_eq!(allocator.free_pages(base, 8), efi::Status::SUCCESS);
}

#[test]
fn invalid_exit_map_key_leaves_boot_services_active() {
    let mut allocator = allocator_with_ram();
    let current = allocator.map_key();
    assert_eq!(
        allocator.exit_boot_services(current.wrapping_add(1)),
        efi::Status::INVALID_PARAMETER
    );
    assert!(!allocator.boot_services_exited);
    assert_eq!(allocator.exit_boot_services(current), efi::Status::SUCCESS);
    assert!(allocator.boot_services_exited);
}

#[test]
fn loader_subclaims_remain_supported() {
    let mut allocator = allocator_with_ram();
    let mut base = 0;
    assert_eq!(
        allocator.allocate_pages(
            AllocateType::AllocateAnyPages,
            MemoryType::LoaderData,
            4,
            &mut base,
        ),
        efi::Status::SUCCESS
    );
    let mut claim = base;
    assert_eq!(
        allocator.allocate_pages(
            AllocateType::AllocateAddress,
            MemoryType::LoaderCode,
            1,
            &mut claim,
        ),
        efi::Status::SUCCESS
    );
}
