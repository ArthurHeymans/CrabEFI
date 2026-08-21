//! Validate-then-commit SetVirtualAddressMap implementation.

use crabefi_runtime_abi::{
    MAX_EXTERNAL_RANGES, MAX_RELOCATIONS, MAX_SECTIONS, RuntimeTimeConfig, relocation_kind,
    section_flags, time_mechanism,
};

use crate::{efi, state};

const MAX_DESCRIPTORS: usize = 256;
const PAGE_SIZE: u64 = 4096;
// Every format-valid relocation can target transition-sensitive storage, so
// the no-allocation commit tail must cover the ABI's complete relocation bound.
const MAX_TAIL_RELOCATIONS: usize = MAX_RELOCATIONS;

#[derive(Clone, Copy)]
struct Mapping {
    physical: u64,
    virtual_address: u64,
    byte_len: u64,
    memory_type: u32,
    attributes: u64,
}

impl Mapping {
    const fn empty() -> Self {
        Self {
            physical: 0,
            virtual_address: 0,
            byte_len: 0,
            memory_type: 0,
            attributes: 0,
        }
    }

    fn physical_end(self) -> Option<u64> {
        self.physical.checked_add(self.byte_len)
    }

    fn virtual_end(self) -> Option<u64> {
        self.virtual_address.checked_add(self.byte_len)
    }
}

#[derive(Clone, Copy)]
struct SlotPatch {
    address: u64,
    value: u64,
}

impl SlotPatch {
    const fn empty() -> Self {
        Self {
            address: 0,
            value: 0,
        }
    }
}

pub fn set_virtual_address_map(
    memory_map_size: usize,
    descriptor_size: usize,
    descriptor_version: u32,
    virtual_map: *mut efi::MemoryDescriptor,
) -> efi::Status {
    if virtual_map.is_null()
        || descriptor_version != efi::MEMORY_DESCRIPTOR_VERSION
        || descriptor_size < core::mem::size_of::<efi::MemoryDescriptor>()
        || memory_map_size == 0
        || !memory_map_size.is_multiple_of(descriptor_size)
    {
        return efi::Status::INVALID_PARAMETER;
    }
    let descriptor_count = memory_map_size / descriptor_size;
    if descriptor_count == 0 || descriptor_count > MAX_DESCRIPTORS {
        return efi::Status::INVALID_PARAMETER;
    }
    let state_pointer = match state::begin_virtual_transition() {
        Ok(pointer) => pointer,
        Err(status) => return status,
    };
    // SAFETY: begin_virtual_transition owns the global lease. The physical
    // state pointer is snapshotted once and is used through the whole commit.
    let runtime = unsafe { &mut *state_pointer };

    let result = validate_descriptor_stream(virtual_map.cast(), descriptor_size, descriptor_count)
        .and_then(|()| {
            let section_mappings = resolve_sections(
                runtime,
                virtual_map.cast(),
                descriptor_size,
                descriptor_count,
            )?;
            let range_mappings = resolve_ranges(
                runtime,
                virtual_map.cast(),
                descriptor_size,
                descriptor_count,
            )?;
            let deferred_mapping = resolve_deferred_buffer(
                runtime,
                virtual_map.cast(),
                descriptor_size,
                descriptor_count,
            )?;
            validate_and_commit(
                state_pointer,
                runtime,
                &section_mappings,
                &range_mappings,
                deferred_mapping,
            )
        });
    if let Err(status) = result {
        state::abort_virtual_transition();
        return status;
    }
    efi::Status::SUCCESS
}

fn validate_descriptor_stream(
    map: *const u8,
    stride: usize,
    count: usize,
) -> Result<(), efi::Status> {
    (0..count).try_for_each(|index| {
        let descriptor = read_descriptor(map, stride, index)?;
        let byte_len = descriptor
            .number_of_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        if descriptor.physical_start == 0
            || byte_len == 0
            || !descriptor.physical_start.is_multiple_of(PAGE_SIZE)
            || (descriptor.virtual_start != 0
                && (!descriptor.virtual_start.is_multiple_of(PAGE_SIZE)
                    || descriptor.virtual_start.checked_add(byte_len).is_none()
                    || !canonical_virtual(descriptor.virtual_start)
                    || !canonical_virtual(descriptor.virtual_start + byte_len - 1)))
        {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        // x86 Linux includes BootServicesCode/Data descriptors in the map it
        // passes to SetVirtualAddressMap as a compatibility mapping for buggy
        // firmware. They are not runtime-owned mappings and are ignored below.
        // Descriptors used for CrabEFI state are still required to carry
        // EFI_MEMORY_RUNTIME by the individual resolvers.
        let linux_boot_services_mapping = cfg!(target_arch = "x86_64")
            && matches!(
                descriptor.r#type,
                efi::BOOT_SERVICES_CODE | efi::BOOT_SERVICES_DATA
            );
        if descriptor.attribute & efi::MEMORY_RUNTIME == 0 && !linux_boot_services_mapping {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        let current = mapping(descriptor)?;
        (0..index).try_for_each(|previous_index| {
            let previous = mapping(read_descriptor(map, stride, previous_index)?)?;
            if overlaps(
                current.physical,
                current
                    .physical_end()
                    .ok_or(efi::Status::INVALID_PARAMETER)?,
                previous.physical,
                previous
                    .physical_end()
                    .ok_or(efi::Status::INVALID_PARAMETER)?,
            ) || (current.virtual_address != 0
                && previous.virtual_address != 0
                && overlaps(
                    current.virtual_address,
                    current
                        .virtual_end()
                        .ok_or(efi::Status::INVALID_PARAMETER)?,
                    previous.virtual_address,
                    previous
                        .virtual_end()
                        .ok_or(efi::Status::INVALID_PARAMETER)?,
                ))
            {
                Err(efi::Status::INVALID_PARAMETER)
            } else {
                Ok(())
            }
        })
    })
}

fn resolve_sections(
    runtime: &state::RuntimeState,
    map: *const u8,
    stride: usize,
    count: usize,
) -> Result<[Mapping; MAX_SECTIONS], efi::Status> {
    let mut resolved = [Mapping::empty(); MAX_SECTIONS];
    for (index, section) in runtime
        .sections
        .iter()
        .take(runtime.section_count)
        .enumerate()
    {
        let expected_type = if section.flags & section_flags::EXECUTE != 0 {
            efi::RUNTIME_SERVICES_CODE
        } else {
            efi::RUNTIME_SERVICES_DATA
        };
        let section_end = section
            .physical_base
            .checked_add(u64::from(section.byte_len))
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        *resolved
            .get_mut(index)
            .ok_or(efi::Status::INVALID_PARAMETER)? = (0..count)
            .try_fold(None, |found, descriptor_index| {
                let candidate = mapping(read_descriptor(map, stride, descriptor_index)?)?;
                if candidate.memory_type != expected_type
                    || candidate.attributes & efi::MEMORY_RUNTIME == 0
                    || candidate.virtual_address == 0
                    || candidate.physical > section.physical_base
                    || !candidate
                        .physical_end()
                        .is_some_and(|end| end >= section_end)
                {
                    return Ok(found);
                }
                if found.is_some() {
                    return Err(efi::Status::INVALID_PARAMETER);
                }
                Ok(Some(candidate))
            })?
            .ok_or(efi::Status::NOT_FOUND)?;
    }
    Ok(resolved)
}

fn resolve_ranges(
    runtime: &state::RuntimeState,
    map: *const u8,
    stride: usize,
    count: usize,
) -> Result<[Mapping; MAX_EXTERNAL_RANGES], efi::Status> {
    let mut resolved = [Mapping::empty(); MAX_EXTERNAL_RANGES];
    for (index, range) in runtime.ranges.iter().take(runtime.range_count).enumerate() {
        let range_end = range
            .physical_base
            .checked_add(range.byte_len)
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        let expected_type = efi::MEMORY_MAPPED_IO;
        *resolved
            .get_mut(index)
            .ok_or(efi::Status::INVALID_PARAMETER)? = (0..count)
            .try_fold(None, |found, descriptor_index| {
                let candidate = mapping(read_descriptor(map, stride, descriptor_index)?)?;
                if candidate.memory_type != expected_type
                    || candidate.virtual_address == 0
                    || candidate.attributes & range.attributes != range.attributes
                    || candidate.physical > range.physical_base
                    || !candidate.physical_end().is_some_and(|end| end >= range_end)
                {
                    return Ok(found);
                }
                if found.is_some() {
                    return Err(efi::Status::INVALID_PARAMETER);
                }
                Ok(Some(candidate))
            })?
            .ok_or(efi::Status::NOT_FOUND)?;
    }
    Ok(resolved)
}

fn resolve_deferred_buffer(
    runtime: &state::RuntimeState,
    map: *const u8,
    stride: usize,
    count: usize,
) -> Result<Mapping, efi::Status> {
    let end = runtime
        .deferred_buffer_physical
        .checked_add(runtime.deferred_buffer_size as u64)
        .ok_or(efi::Status::INVALID_PARAMETER)?;
    (0..count)
        .try_fold(None, |found, index| {
            let candidate = mapping(read_descriptor(map, stride, index)?)?;
            if candidate.memory_type != efi::RUNTIME_SERVICES_DATA
                || candidate.attributes & efi::MEMORY_RUNTIME == 0
                || candidate.virtual_address == 0
                || candidate.physical > runtime.deferred_buffer_physical
                || !candidate.physical_end().is_some_and(|value| value >= end)
            {
                return Ok(found);
            }
            if found.is_some() {
                return Err(efi::Status::INVALID_PARAMETER);
            }
            Ok(Some(candidate))
        })?
        .ok_or(efi::Status::NOT_FOUND)
}

fn virtual_time_config(
    runtime: &state::RuntimeState,
    range_virtual_bases: &[u64; MAX_EXTERNAL_RANGES],
) -> Result<RuntimeTimeConfig, efi::Status> {
    let width = match runtime.time.mechanism {
        time_mechanism::PL031 => 4,
        time_mechanism::GOLDFISH_RTC => 8,
        _ => return Ok(runtime.time),
    };
    let physical_end = runtime
        .time
        .io_or_mmio_base
        .checked_add(width)
        .ok_or(efi::Status::INVALID_PARAMETER)?;
    let (index, range) = runtime
        .ranges
        .iter()
        .take(runtime.range_count)
        .enumerate()
        .find(|(_, range)| {
            range.physical_base <= runtime.time.io_or_mmio_base
                && range
                    .physical_base
                    .checked_add(range.byte_len)
                    .is_some_and(|end| physical_end <= end)
        })
        .ok_or(efi::Status::NOT_FOUND)?;
    let offset = runtime
        .time
        .io_or_mmio_base
        .checked_sub(range.physical_base)
        .ok_or(efi::Status::INVALID_PARAMETER)?;
    let mut config = runtime.time;
    config.io_or_mmio_base = range_virtual_bases
        .get(index)
        .and_then(|base| base.checked_add(offset))
        .ok_or(efi::Status::INVALID_PARAMETER)?;
    Ok(config)
}

fn validate_and_commit(
    state_pointer: *mut state::RuntimeState,
    runtime: &mut state::RuntimeState,
    section_mappings: &[Mapping; MAX_SECTIONS],
    range_mappings: &[Mapping; MAX_EXTERNAL_RANGES],
    deferred_mapping: Mapping,
) -> Result<(), efi::Status> {
    let mut section_virtual_bases = [0u64; MAX_SECTIONS];
    for ((section, mapping), virtual_base) in runtime
        .sections
        .iter()
        .take(runtime.section_count)
        .zip(section_mappings.iter())
        .zip(section_virtual_bases.iter_mut())
    {
        let offset = section
            .physical_base
            .checked_sub(mapping.physical)
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        *virtual_base = mapping
            .virtual_address
            .checked_add(offset)
            .ok_or(efi::Status::INVALID_PARAMETER)?;
    }
    let mut range_virtual_bases = [0u64; MAX_EXTERNAL_RANGES];
    for ((range, mapping), virtual_base) in runtime
        .ranges
        .iter()
        .take(runtime.range_count)
        .zip(range_mappings.iter())
        .zip(range_virtual_bases.iter_mut())
    {
        let offset = range
            .physical_base
            .checked_sub(mapping.physical)
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        *virtual_base = mapping
            .virtual_address
            .checked_add(offset)
            .ok_or(efi::Status::INVALID_PARAMETER)?;
    }

    let virtual_time = virtual_time_config(runtime, &range_virtual_bases)?;

    let deferred_offset = runtime
        .deferred_buffer_physical
        .checked_sub(deferred_mapping.physical)
        .ok_or(efi::Status::INVALID_PARAMETER)?;
    let deferred_virtual = deferred_mapping
        .virtual_address
        .checked_add(deferred_offset)
        .ok_or(efi::Status::INVALID_PARAMETER)?;

    let runtime_table_start = core::ptr::addr_of!(runtime.tables.runtime) as u64;
    let runtime_table_end = runtime_table_start
        .checked_add(runtime.tables.runtime.hdr.header_size.into())
        .ok_or(efi::Status::INVALID_PARAMETER)?;
    let state_address = runtime as *mut state::RuntimeState as u64;
    let transition_tail_addresses = state::transition_tail_addresses();
    let store_address = core::ptr::addr_of!(state::RUNTIME_VARIABLE_STORE) as u64;
    let mut tail = [SlotPatch::empty(); MAX_TAIL_RELOCATIONS];
    let mut tail_count = 0usize;

    // Validation pass: no writes.
    for relocation in runtime.relocations.iter().take(runtime.relocation_count) {
        let patch_section = runtime
            .sections
            .get(usize::from(relocation.patch_section))
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        let target_section = runtime
            .sections
            .get(usize::from(relocation.target_section))
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        let patch_relative = relocation
            .patch_offset
            .checked_sub(patch_section.image_offset)
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        if patch_relative
            .checked_add(8)
            .is_none_or(|end| end > patch_section.byte_len)
            || !patch_relative.is_multiple_of(8)
        {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        let target_relative = relocation
            .target_offset
            .checked_sub(target_section.image_offset)
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        if target_relative >= target_section.byte_len
            || relocation.kind != relocation_kind::ABSOLUTE64
        {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        let patch_address = patch_section
            .physical_base
            .checked_add(u64::from(patch_relative))
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        let virtual_target = section_virtual_bases
            .get(usize::from(relocation.target_section))
            .and_then(|base| base.checked_add(u64::from(target_relative)))
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        let physical_target = target_section
            .physical_base
            .checked_add(u64::from(target_relative))
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        let tail_required = target_section.flags & section_flags::EXECUTE != 0
            || physical_target == state_address
            || physical_target == store_address
            || transition_tail_addresses.contains(&physical_target);
        // `commit_matching` skips every patch address inside the Runtime
        // Services table, so a table-resident slot that is not classified for
        // the tail would never be patched and would silently keep its stale
        // physical value after the virtual transition. Reject it instead.
        if patch_address >= runtime_table_start
            && patch_address < runtime_table_end
            && !tail_required
        {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        if tail_required {
            if tail_count >= tail.len() {
                return Err(efi::Status::OUT_OF_RESOURCES);
            }
            *tail
                .get_mut(tail_count)
                .ok_or(efi::Status::OUT_OF_RESOURCES)? = SlotPatch {
                address: patch_address,
                value: virtual_target,
            };
            tail_count += 1;
        }
    }

    // Infallible commit begins. First publish resolved bases in image state.
    for (section, virtual_base) in runtime
        .sections
        .iter_mut()
        .take(runtime.section_count)
        .zip(section_virtual_bases.iter())
    {
        section.virtual_base = *virtual_base;
    }
    for (range, virtual_base) in runtime
        .ranges
        .iter_mut()
        .take(runtime.range_count)
        .zip(range_virtual_bases.iter())
    {
        range.virtual_base = *virtual_base;
    }
    runtime.time = virtual_time;
    runtime.deferred_buffer_virtual = deferred_virtual;

    let sections = runtime.sections;
    let section_count = runtime.section_count;
    runtime.tables.convert_internal_pointers(|physical| {
        sections.iter().take(section_count).find_map(|section| {
            let offset = physical.checked_sub(section.physical_base)?;
            (offset < u64::from(section.byte_len))
                .then(|| section.virtual_base.checked_add(offset))?
        })
    });

    // Code and GOT slots are deferred until this function has released the
    // physical transition lock. Their table bytes still contribute their final
    // virtual values to the Runtime Services CRC.
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    runtime.tables.recompute_crcs();
    runtime.tables.recompute_runtime_crc_with(|address, byte| {
        tail.iter()
            .take(tail_count)
            .find_map(|slot| {
                let offset = address.checked_sub(slot.address)?;
                slot.value.to_le_bytes().get(offset as usize).copied()
            })
            .unwrap_or(byte)
    });

    // Patch every non-tail slot while physical aliases are executable.
    commit_matching(runtime, &section_virtual_bases, |address| {
        !(address >= runtime_table_start && address < runtime_table_end)
            && !tail
                .iter()
                .take(tail_count)
                .any(|slot| slot.address == address)
    });

    // No image state or transition atomic is accessed after this release.
    state::publish_virtual_and_unlock();
    runtime_image_commit_tail_and_return(state_pointer, tail.as_ptr(), tail_count);
    Ok(())
}

fn commit_matching(
    runtime: &state::RuntimeState,
    virtual_bases: &[u64; MAX_SECTIONS],
    predicate: impl Fn(u64) -> bool,
) {
    for relocation in runtime.relocations.iter().take(runtime.relocation_count) {
        let patch_index = usize::from(relocation.patch_section);
        let target_index = usize::from(relocation.target_section);
        // SAFETY: the preceding validation pass checked both section indices,
        // relocation offsets, and both address additions before commit began.
        let (patch_section, target_section, target_base) = unsafe {
            (
                *runtime.sections.get_unchecked(patch_index),
                *runtime.sections.get_unchecked(target_index),
                *virtual_bases.get_unchecked(target_index),
            )
        };
        let patch_relative = relocation
            .patch_offset
            .wrapping_sub(patch_section.image_offset);
        let target_relative = relocation
            .target_offset
            .wrapping_sub(target_section.image_offset);
        let patch_address = patch_section
            .physical_base
            .wrapping_add(u64::from(patch_relative));
        if !predicate(patch_address) {
            continue;
        }
        let value = target_base.wrapping_add(u64::from(target_relative));
        // SAFETY: the loader exposed these firmware addresses and validation
        // proved this complete aligned-width destination before commit.
        unsafe { write_slot_at_address(patch_address, value) };
    }
}

#[inline(always)]
unsafe fn write_slot_at_address(address: u64, value: u64) {
    // The destination can be in any validated runtime-image section; it is not
    // derived from RuntimeState's allocation. Reconstitute the loader-exposed
    // firmware address with explicit exposed provenance instead.
    let slot = core::ptr::with_exposed_provenance_mut::<u64>(address as usize);
    // SAFETY: callers validated the complete width inside a writable relocation
    // slot whose address provenance was exposed by the boot loader.
    unsafe { slot.write_unaligned(value) };
}

#[unsafe(no_mangle)]
#[inline(never)]
fn runtime_image_commit_tail_and_return(
    _state_pointer: *mut state::RuntimeState,
    tail: *const SlotPatch,
    count: usize,
) {
    let mut index = 0;
    while index < count {
        // SAFETY: the fixed stack tail array has `count` initialized entries.
        let slot = unsafe { tail.add(index).read() };
        // SAFETY: validation established this image-local slot and the caller
        // invokes this only while physical aliases remain valid.
        unsafe { write_slot_at_address(slot.address, slot.value) };
        index += 1;
    }
}

fn read_descriptor(
    map: *const u8,
    stride: usize,
    index: usize,
) -> Result<efi::MemoryDescriptor, efi::Status> {
    let offset = index
        .checked_mul(stride)
        .ok_or(efi::Status::INVALID_PARAMETER)?;
    // SAFETY: the UEFI caller supplied map_size bytes and top-level validation
    // proved exact divisibility and a bounded index.
    Ok(unsafe {
        map.add(offset)
            .cast::<efi::MemoryDescriptor>()
            .read_unaligned()
    })
}

fn mapping(descriptor: efi::MemoryDescriptor) -> Result<Mapping, efi::Status> {
    Ok(Mapping {
        physical: descriptor.physical_start,
        virtual_address: descriptor.virtual_start,
        byte_len: descriptor
            .number_of_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(efi::Status::INVALID_PARAMETER)?,
        memory_type: descriptor.r#type,
        attributes: descriptor.attribute,
    })
}

fn overlaps(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

fn canonical_virtual(address: u64) -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let high = address >> 48;
        high == 0 || high == 0xffff
    }
    #[cfg(target_arch = "riscv64")]
    {
        let satp: u64;
        // SAFETY: reading SATP is side-effect free in supervisor mode.
        unsafe { core::arch::asm!("csrr {}, satp", out(reg) satp, options(nomem, nostack)) };
        let bit = match satp >> 60 {
            8 => 38,
            9 => 47,
            10 => 56,
            _ => return true,
        };
        let sign = (address >> bit) & 1;
        let high = address >> (bit + 1);
        if sign == 0 {
            high == 0
        } else {
            high == (u64::MAX >> (bit + 1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn accepts_linux_boot_services_compatibility_mapping() {
        let descriptors = [efi::MemoryDescriptor {
            r#type: efi::BOOT_SERVICES_DATA,
            physical_start: 0x20_0000,
            virtual_start: 0xffff_fffe_ffe0_0000,
            number_of_pages: 4,
            attribute: efi::MEMORY_WB,
        }];
        assert_eq!(
            validate_descriptor_stream(
                descriptors.as_ptr().cast(),
                core::mem::size_of::<efi::MemoryDescriptor>(),
                descriptors.len(),
            ),
            Ok(())
        );
    }

    #[test]
    fn runtime_section_requires_runtime_attribute() {
        let mut runtime = state::RuntimeState::new();
        runtime.section_count = 1;
        runtime.sections[0] = state::SectionRecord {
            physical_base: 0x40_0000,
            virtual_base: 0,
            image_offset: 0,
            byte_len: PAGE_SIZE as u32,
            flags: section_flags::EXECUTE,
        };
        let descriptors = [efi::MemoryDescriptor {
            r#type: efi::RUNTIME_SERVICES_CODE,
            physical_start: 0x40_0000,
            virtual_start: 0xffff_fffe_ffc0_0000,
            number_of_pages: 1,
            attribute: efi::MEMORY_WB,
        }];
        assert!(matches!(
            resolve_sections(
                &runtime,
                descriptors.as_ptr().cast(),
                core::mem::size_of::<efi::MemoryDescriptor>(),
                descriptors.len(),
            ),
            Err(efi::Status::NOT_FOUND)
        ));
    }

    #[test]
    fn converts_mmio_time_base_to_matching_virtual_range() {
        let mut runtime = state::RuntimeState::new();
        runtime.time = RuntimeTimeConfig {
            mechanism: time_mechanism::PL031,
            reserved: 0,
            io_or_mmio_base: 0x20_0120,
        };
        runtime.range_count = 1;
        runtime.ranges[0] = state::RangeRecord {
            physical_base: 0x20_0000,
            virtual_base: 0,
            byte_len: 0x1000,
            attributes: efi::MEMORY_RUNTIME,
        };
        let mut virtual_bases = [0; MAX_EXTERNAL_RANGES];
        virtual_bases[0] = 0xffff_8000_0020_0000;
        let converted = virtual_time_config(&runtime, &virtual_bases).unwrap();
        assert_eq!(converted.io_or_mmio_base, 0xffff_8000_0020_0120);
    }

    #[test]
    fn rejects_mmio_time_base_without_complete_range() {
        let mut runtime = state::RuntimeState::new();
        runtime.time = RuntimeTimeConfig {
            mechanism: time_mechanism::GOLDFISH_RTC,
            reserved: 0,
            io_or_mmio_base: 0x20_0ffc,
        };
        runtime.range_count = 1;
        runtime.ranges[0] = state::RangeRecord {
            physical_base: 0x20_0000,
            virtual_base: 0,
            byte_len: 0x1000,
            attributes: efi::MEMORY_RUNTIME,
        };
        assert_eq!(
            virtual_time_config(&runtime, &[0; MAX_EXTERNAL_RANGES]),
            Err(efi::Status::NOT_FOUND)
        );
    }

    #[test]
    fn transition_tail_covers_the_format_relocation_limit() {
        assert_eq!(MAX_TAIL_RELOCATIONS, MAX_RELOCATIONS);
    }

    #[test]
    fn exposed_provenance_slot_write_reaches_validated_destination() {
        let mut value = 0u64;
        let address = (&mut value as *mut u64) as usize as u64;
        // SAFETY: casting the local pointer exposed its provenance and the
        // destination is one complete writable u64.
        unsafe { write_slot_at_address(address, 0xfeed_face_dead_beef) };
        assert_eq!(value, 0xfeed_face_dead_beef);
    }
}
