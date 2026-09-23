//! Validate-then-commit SetVirtualAddressMap implementation.

use crabefi_runtime_abi::{
    MAX_EXTERNAL_RANGES, MAX_RELOCATIONS, MAX_SECTIONS, relocation_kind, section_flags,
};
use heapless::Vec;

use crate::{
    efi,
    state::{self, TimeConfig, collect_bounded},
};

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

pub fn set_virtual_address_map(
    memory_map_size: usize,
    descriptor_size: usize,
    descriptor_version: u32,
    virtual_map: *mut efi::MemoryDescriptor,
) -> Result<(), efi::Status> {
    if virtual_map.is_null()
        || descriptor_version != efi::MEMORY_DESCRIPTOR_VERSION
        || descriptor_size < core::mem::size_of::<efi::MemoryDescriptor>()
        || memory_map_size == 0
        || !memory_map_size.is_multiple_of(descriptor_size)
    {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let descriptor_count = memory_map_size / descriptor_size;
    if descriptor_count == 0 || descriptor_count > MAX_DESCRIPTORS {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let state_pointer = state::begin_virtual_transition()?;
    // SAFETY: begin_virtual_transition owns the global lease. The physical
    // state pointer is snapshotted once and is used through the whole commit.
    let runtime = unsafe { &mut *state_pointer };

    validate_descriptor_stream(virtual_map.cast(), descriptor_size, descriptor_count)
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
        })
        .inspect_err(|_| state::abort_virtual_transition())
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

/// Find the one descriptor accepted by `matches`; a second match is ambiguous.
fn unique_mapping(
    map: *const u8,
    stride: usize,
    count: usize,
    matches: impl Fn(&Mapping) -> bool,
) -> Result<Mapping, efi::Status> {
    (0..count)
        .try_fold(None, |found, index| {
            let candidate = mapping(read_descriptor(map, stride, index)?)?;
            if !matches(&candidate) {
                return Ok(found);
            }
            if found.is_some() {
                return Err(efi::Status::INVALID_PARAMETER);
            }
            Ok(Some(candidate))
        })?
        .ok_or(efi::Status::NOT_FOUND)
}

/// Whether `candidate` is a virtually mapped runtime descriptor of
/// `memory_type` covering `[physical, end)`.
fn covers_runtime(candidate: &Mapping, memory_type: u32, physical: u64, end: u64) -> bool {
    candidate.memory_type == memory_type
        && candidate.attributes & efi::MEMORY_RUNTIME != 0
        && candidate.virtual_address != 0
        && candidate.physical <= physical
        && candidate.physical_end().is_some_and(|value| value >= end)
}

fn resolve_sections(
    runtime: &state::RuntimeState,
    map: *const u8,
    stride: usize,
    count: usize,
) -> Result<Vec<Mapping, MAX_SECTIONS>, efi::Status> {
    collect_bounded(runtime.sections.iter().map(|section| {
        let expected_type = if section.flags & section_flags::EXECUTE != 0 {
            efi::RUNTIME_SERVICES_CODE
        } else {
            efi::RUNTIME_SERVICES_DATA
        };
        let section_end = section
            .physical_base
            .checked_add(u64::from(section.byte_len))
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        unique_mapping(map, stride, count, |candidate| {
            covers_runtime(candidate, expected_type, section.physical_base, section_end)
        })
    }))
}

fn resolve_ranges(
    runtime: &state::RuntimeState,
    map: *const u8,
    stride: usize,
    count: usize,
) -> Result<Vec<Mapping, MAX_EXTERNAL_RANGES>, efi::Status> {
    collect_bounded(runtime.ranges.iter().map(|range| {
        let range_end = range
            .physical_base
            .checked_add(range.byte_len)
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        unique_mapping(map, stride, count, |candidate| {
            candidate.memory_type == efi::MEMORY_MAPPED_IO
                && candidate.virtual_address != 0
                && candidate.attributes & range.attributes == range.attributes
                && candidate.physical <= range.physical_base
                && candidate.physical_end().is_some_and(|end| end >= range_end)
        })
    }))
}

fn resolve_deferred_buffer(
    runtime: &state::RuntimeState,
    map: *const u8,
    stride: usize,
    count: usize,
) -> Result<Option<Mapping>, efi::Status> {
    let Some(retained) = runtime.retained else {
        return Ok(None);
    };
    let end = retained
        .physical_base
        .checked_add(retained.size as u64)
        .ok_or(efi::Status::INVALID_PARAMETER)?;
    unique_mapping(map, stride, count, |candidate| {
        covers_runtime(
            candidate,
            efi::RUNTIME_SERVICES_DATA,
            retained.physical_base,
            end,
        )
    })
    .map(Some)
}

fn virtual_time_config(
    runtime: &state::RuntimeState,
    range_virtual_bases: &[u64],
) -> Result<TimeConfig, efi::Status> {
    let time = runtime.time;
    let Some(width) = time.mechanism.mmio_width() else {
        return Ok(time);
    };
    let physical_end = time
        .base
        .checked_add(width)
        .ok_or(efi::Status::INVALID_PARAMETER)?;
    let (range, virtual_base) = runtime
        .ranges
        .iter()
        .zip(range_virtual_bases)
        .find(|(range, _)| {
            range.physical_base <= time.base
                && range
                    .physical_base
                    .checked_add(range.byte_len)
                    .is_some_and(|end| physical_end <= end)
        })
        .ok_or(efi::Status::NOT_FOUND)?;
    let base = time
        .base
        .checked_sub(range.physical_base)
        .and_then(|offset| virtual_base.checked_add(offset))
        .ok_or(efi::Status::INVALID_PARAMETER)?;
    Ok(TimeConfig { base, ..time })
}

/// Virtual address of `physical` inside the descriptor `mapping` it.
fn virtual_base(physical: u64, mapping: &Mapping) -> Result<u64, efi::Status> {
    physical
        .checked_sub(mapping.physical)
        .and_then(|offset| mapping.virtual_address.checked_add(offset))
        .ok_or(efi::Status::INVALID_PARAMETER)
}

/// Virtual base of each physical region given the descriptor mapping it.
fn virtual_bases<const N: usize>(
    physical_bases: impl Iterator<Item = u64>,
    mappings: &[Mapping],
) -> Result<Vec<u64, N>, efi::Status> {
    collect_bounded(
        physical_bases
            .zip(mappings)
            .map(|(physical, mapping)| virtual_base(physical, mapping)),
    )
}

fn validate_and_commit(
    state_pointer: *mut state::RuntimeState,
    runtime: &mut state::RuntimeState,
    section_mappings: &[Mapping],
    range_mappings: &[Mapping],
    deferred_mapping: Option<Mapping>,
) -> Result<(), efi::Status> {
    let section_virtual_bases: Vec<u64, MAX_SECTIONS> = virtual_bases(
        runtime.sections.iter().map(|section| section.physical_base),
        section_mappings,
    )?;
    let range_virtual_bases: Vec<u64, MAX_EXTERNAL_RANGES> = virtual_bases(
        runtime.ranges.iter().map(|range| range.physical_base),
        range_mappings,
    )?;

    let virtual_time = virtual_time_config(runtime, &range_virtual_bases)?;

    let retained_virtual_base = runtime
        .retained
        .zip(deferred_mapping)
        .map(|(retained, mapping)| virtual_base(retained.physical_base, &mapping))
        .transpose()?;

    let runtime_table_start = core::ptr::addr_of!(runtime.tables.runtime) as u64;
    let runtime_table_end = runtime_table_start
        .checked_add(runtime.tables.runtime.hdr.header_size.into())
        .ok_or(efi::Status::INVALID_PARAMETER)?;
    let state_address = runtime as *mut state::RuntimeState as u64;
    let transition_tail_addresses = state::transition_tail_addresses();
    let store_address = core::ptr::addr_of!(state::RUNTIME_VARIABLE_STORE) as u64;
    let mut tail: Vec<SlotPatch, MAX_TAIL_RELOCATIONS> = Vec::new();

    // Validation pass: no writes.
    for relocation in &runtime.relocations {
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
            tail.push(SlotPatch {
                address: patch_address,
                value: virtual_target,
            })
            .map_err(|_| efi::Status::OUT_OF_RESOURCES)?;
        }
    }

    // Infallible commit begins. First publish resolved bases in image state.
    for (section, virtual_base) in runtime.sections.iter_mut().zip(&section_virtual_bases) {
        section.virtual_base = *virtual_base;
    }
    for (range, virtual_base) in runtime.ranges.iter_mut().zip(&range_virtual_bases) {
        range.virtual_base = *virtual_base;
    }
    runtime.time = virtual_time;
    if let (Some(retained), Some(base)) = (&mut runtime.retained, retained_virtual_base) {
        retained.virtual_base = base;
    }

    let sections = &runtime.sections;
    runtime.tables.convert_internal_pointers(|physical| {
        sections.iter().find_map(|section| {
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
            .find_map(|slot| {
                let offset = address.checked_sub(slot.address)?;
                slot.value.to_le_bytes().get(offset as usize).copied()
            })
            .unwrap_or(byte)
    });

    // Patch every non-tail slot while physical aliases are executable.
    commit_matching(runtime, &section_virtual_bases, |address| {
        !(address >= runtime_table_start && address < runtime_table_end)
            && !tail.iter().any(|slot| slot.address == address)
    });

    // No image state or transition atomic is accessed after this release.
    state::publish_virtual_and_unlock();
    runtime_image_commit_tail_and_return(state_pointer, tail.as_ptr(), tail.len());
    Ok(())
}

fn commit_matching(
    runtime: &state::RuntimeState,
    virtual_bases: &[u64],
    predicate: impl Fn(u64) -> bool,
) {
    for relocation in &runtime.relocations {
        let patch_index = usize::from(relocation.patch_section);
        let target_index = usize::from(relocation.target_section);
        // Mirror the validation pass so a future edit there cannot silently
        // invalidate the safety argument of the unchecked accesses below.
        debug_assert!(
            patch_index < runtime.sections.len() && target_index < runtime.sections.len(),
            "relocation section index escaped validation"
        );
        debug_assert!(
            runtime.sections.get(patch_index).is_some_and(|section| {
                state::offset_within_section(section, relocation.patch_offset, 8)
            }),
            "relocation patch slot escaped validation"
        );
        debug_assert!(
            runtime.sections.get(target_index).is_some_and(|section| {
                state::offset_within_section(section, relocation.target_offset, 1)
            }),
            "relocation target escaped validation"
        );
        // SAFETY: the preceding validation pass checked both section indices,
        // relocation offsets, and both address additions before commit began;
        // the debug assertions above pin those invariants to this loop.
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
        // SAFETY: the stack tail vector has `count` initialized entries.
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
    use crabefi_runtime_abi::TimeMechanism;

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
        runtime.sections = Vec::from_array([state::SectionRecord {
            physical_base: 0x40_0000,
            virtual_base: 0,
            image_offset: 0,
            byte_len: PAGE_SIZE as u32,
            flags: section_flags::EXECUTE,
        }]);
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
        runtime.time = TimeConfig {
            mechanism: TimeMechanism::Pl031,
            base: 0x20_0120,
        };
        runtime.ranges = Vec::from_array([state::RangeRecord {
            physical_base: 0x20_0000,
            virtual_base: 0,
            byte_len: 0x1000,
            attributes: efi::MEMORY_RUNTIME,
        }]);
        let converted = virtual_time_config(&runtime, &[0xffff_8000_0020_0000]).unwrap();
        assert_eq!(converted.base, 0xffff_8000_0020_0120);
    }

    #[test]
    fn rejects_mmio_time_base_without_complete_range() {
        let mut runtime = state::RuntimeState::new();
        runtime.time = TimeConfig {
            mechanism: TimeMechanism::GoldfishRtc,
            base: 0x20_0ffc,
        };
        runtime.ranges = Vec::from_array([state::RangeRecord {
            physical_base: 0x20_0000,
            virtual_base: 0,
            byte_len: 0x1000,
            attributes: efi::MEMORY_RUNTIME,
        }]);
        assert_eq!(
            virtual_time_config(&runtime, &[0]),
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
