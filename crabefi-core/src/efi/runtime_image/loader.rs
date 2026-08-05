//! Checked normalized-image loader and physical relocator.

use crabefi_runtime_abi::{
    LoadedSection, MAX_EXTERNAL_RANGES, RelocationImport, RuntimeHandoff, ValidatedImage,
    architecture, relocation_kind, section_flags,
};
use r_efi::efi::Status;
use sha2::{Digest, Sha256};

use crate::efi::allocator::{self, MemoryType, PAGE_SIZE};
use crate::platform::{RuntimeImageSource, RuntimePlatformConfig};

use super::bridge;
use super::client::RuntimeImageClient;

#[derive(Debug, Clone, Copy)]
pub enum LoadError {
    DigestMismatch,
    InvalidFormat(crabefi_runtime_abi::AbiError),
    InvalidLayout,
    Allocation(Status),
    Image(Status),
}

pub fn load(
    source: RuntimeImageSource<'_>,
    platform: RuntimePlatformConfig<'_>,
) -> Result<RuntimeImageClient, LoadError> {
    let digest: [u8; 32] = Sha256::digest(source.bytes).into();
    if digest != source.expected_sha256 {
        return Err(LoadError::DigestMismatch);
    }
    let image = ValidatedImage::parse(source.bytes, current_architecture())
        .map_err(LoadError::InvalidFormat)?;
    validate_layout(&image, platform.external_ranges.len())?;
    reserve_deferred_buffer(platform)?;
    let header = image.header();
    let image_pages = u64::from(header.image_size).div_ceil(PAGE_SIZE);
    let code = image.section(0).map_err(LoadError::InvalidFormat)?;
    let code_pages = u64::from(code.memory_size).div_ceil(PAGE_SIZE);
    let base = allocator::allocate_runtime_image_layout(image_pages, code_pages)
        .map_err(LoadError::Allocation)?;

    // SAFETY: the allocator returned an exclusive, contiguous image allocation.
    // Every section range was validated before allocation and covers it exactly.
    unsafe { core::ptr::write_bytes(base as *mut u8, 0, header.image_size as usize) };
    (0..usize::from(header.section_count)).try_for_each(|index| {
        let section = image.section(index).map_err(LoadError::InvalidFormat)?;
        let bytes = image
            .section_bytes(section)
            .map_err(LoadError::InvalidFormat)?;
        let destination = base
            .checked_add(u64::from(section.image_offset))
            .ok_or(LoadError::InvalidLayout)? as *mut u8;
        // SAFETY: section parsing proved source and destination ranges, and
        // normalized metadata makes sections non-overlapping.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len()) };
        Ok::<(), LoadError>(())
    })?;

    (0..usize::try_from(header.relocation_count).map_err(|_| LoadError::InvalidLayout)?)
        .try_for_each(|index| {
            let relocation = image.relocation(index).map_err(LoadError::InvalidFormat)?;
            let patch_section = image
                .section(usize::from(relocation.patch_section))
                .map_err(LoadError::InvalidFormat)?;
            let patch = base
                .checked_add(u64::from(relocation.patch_offset))
                .ok_or(LoadError::InvalidLayout)?;
            let value = base
                .checked_add(u64::from(relocation.target_offset))
                .ok_or(LoadError::InvalidLayout)?;
            let patch_relative = relocation
                .patch_offset
                .checked_sub(patch_section.image_offset)
                .ok_or(LoadError::InvalidLayout)?;
            if patch_relative
                .checked_add(8)
                .is_none_or(|end| end > patch_section.memory_size)
            {
                return Err(LoadError::InvalidLayout);
            }
            // SAFETY: parser proved an aligned, in-range Absolute64 slot.
            unsafe { (patch as *mut u64).write_unaligned(value) };
            Ok(())
        })?;
    synchronize_loaded_image(base, u64::from(header.image_size));

    let exports = image.exports().map_err(LoadError::InvalidFormat)?;
    let mut client = RuntimeImageClient::new(base, exports);
    let mut handoff = RuntimeHandoff::empty();
    handoff.architecture = current_architecture();
    handoff.image_base = base;
    handoff.image_size = header.image_size;
    handoff.section_count = header.section_count;
    handoff.range_count =
        u16::try_from(platform.external_ranges.len()).map_err(|_| LoadError::InvalidLayout)?;
    handoff.boot_bridge = bridge::dispatch as *const () as usize as u64;
    handoff.deferred_buffer_base = platform.deferred_buffer.base;
    handoff.deferred_buffer_size =
        u64::try_from(platform.deferred_buffer.size).map_err(|_| LoadError::InvalidLayout)?;
    handoff.time = platform.time;
    handoff.reset = platform.reset;
    (0..usize::from(header.section_count)).try_for_each(|index| {
        let section = image.section(index).map_err(LoadError::InvalidFormat)?;
        handoff.sections[index] = LoadedSection {
            physical_base: base + u64::from(section.image_offset),
            image_offset: section.image_offset,
            byte_len: section.memory_size,
            flags: section.flags,
            reserved: 0,
        };
        Ok::<(), LoadError>(())
    })?;
    for (destination, source) in handoff
        .ranges
        .iter_mut()
        .zip(platform.external_ranges.iter())
    {
        *destination = *source;
    }
    client.initialize(&handoff).map_err(LoadError::Image)?;
    for index in
        0..usize::try_from(header.relocation_count).map_err(|_| LoadError::InvalidLayout)?
    {
        let relocation = image.relocation(index).map_err(LoadError::InvalidFormat)?;
        client
            .import_relocation(&RelocationImport {
                patch_offset: relocation.patch_offset,
                target_offset: relocation.target_offset,
                patch_section: relocation.patch_section,
                target_section: relocation.target_section,
                kind: relocation_kind::ABSOLUTE64,
                reserved: [0; 12],
            })
            .map_err(LoadError::Image)?;
    }
    client
        .activate(super::super::boot_services::get_boot_services())
        .map_err(LoadError::Image)?;
    Ok(client)
}

fn validate_deferred_buffer(
    deferred: crate::platform::DeferredBufferConfig,
    external_ranges: &[crabefi_runtime_abi::RuntimeExternalRange],
) -> Result<(u64, u64), LoadError> {
    let base = deferred.base;
    let size = u64::try_from(deferred.size).map_err(|_| LoadError::InvalidLayout)?;
    let end = base.checked_add(size).ok_or(LoadError::InvalidLayout)?;
    if base == 0
        || size == 0
        || !base.is_multiple_of(PAGE_SIZE)
        || !size.is_multiple_of(PAGE_SIZE)
        || external_ranges.iter().any(|range| {
            let Some(range_end) = range.physical_base.checked_add(range.byte_len) else {
                return true;
            };
            base < range_end && range.physical_base < end
        })
    {
        return Err(LoadError::InvalidLayout);
    }
    Ok((base, size))
}

fn reserve_deferred_buffer(platform: RuntimePlatformConfig<'_>) -> Result<(), LoadError> {
    let (base, size) =
        validate_deferred_buffer(platform.deferred_buffer, platform.external_ranges)?;
    let pages = size / PAGE_SIZE;
    match allocator::carve_out_region(base, pages, MemoryType::RuntimeServicesData) {
        Ok(()) => Ok(()),
        Err(_) => {
            if allocator::range_has_memory_type(base, size, MemoryType::RuntimeServicesData) {
                Ok(())
            } else {
                Err(LoadError::InvalidLayout)
            }
        }
    }
}

fn validate_layout(
    image: &ValidatedImage<'_>,
    external_range_count: usize,
) -> Result<(), LoadError> {
    if external_range_count > MAX_EXTERNAL_RANGES {
        return Err(LoadError::InvalidLayout);
    }
    let header = image.header();
    let mut watermark = 0u32;
    for index in 0..usize::from(header.section_count) {
        let section = image.section(index).map_err(LoadError::InvalidFormat)?;
        if section.image_offset != watermark
            || !section.image_offset.is_multiple_of(PAGE_SIZE as u32)
            || !section.memory_size.is_multiple_of(PAGE_SIZE as u32)
        {
            return Err(LoadError::InvalidLayout);
        }
        let executable = section.flags & section_flags::EXECUTE != 0;
        if (index == 0) != executable {
            return Err(LoadError::InvalidLayout);
        }
        watermark = section.image_end().ok_or(LoadError::InvalidLayout)?;
    }
    if watermark != header.image_size {
        return Err(LoadError::InvalidLayout);
    }
    Ok(())
}

const fn current_architecture() -> u16 {
    #[cfg(target_arch = "x86_64")]
    return architecture::X86_64;
    #[cfg(target_arch = "aarch64")]
    return architecture::AARCH64;
    #[cfg(target_arch = "riscv64")]
    return architecture::RISCV64;
}

#[cfg(any(target_arch = "aarch64", test))]
const fn aarch64_cache_line_sizes(ctr_el0: u64) -> (u64, u64) {
    let instruction = 4u64 << (ctr_el0 & 0x0f);
    let data = 4u64 << ((ctr_el0 >> 16) & 0x0f);
    (data, instruction)
}

fn synchronize_loaded_image(base: u64, size: u64) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let _ = (base, size);
        // SAFETY: serializes completed relocation stores before first execution.
        core::arch::asm!("mfence", "lfence", options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let ctr_el0: u64;
        core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr_el0, options(nomem, nostack));
        let (data_stride, instruction_stride) = aarch64_cache_line_sizes(ctr_el0);
        let end = base.saturating_add(size);
        let mut address = base & !(data_stride - 1);
        while address < end {
            // SAFETY: cache maintenance may round down to the containing line;
            // it does not dereference memory outside the new image allocation.
            core::arch::asm!("dc cvau, {}", in(reg) address, options(nostack));
            address = address.saturating_add(data_stride);
        }
        core::arch::asm!("dsb ish", options(nostack));
        address = base & !(instruction_stride - 1);
        while address < end {
            core::arch::asm!("ic ivau, {}", in(reg) address, options(nostack));
            address = address.saturating_add(instruction_stride);
        }
        core::arch::asm!("dsb ish", "isb", options(nostack));
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        let _ = (base, size);
        // SAFETY: synchronizes instruction fetch with the copied image.
        core::arch::asm!("fence.i", options(nostack));
    }
}

#[cfg(test)]
mod tests {
    use super::{aarch64_cache_line_sizes, validate_deferred_buffer};
    use crate::platform::DeferredBufferConfig;
    use crabefi_runtime_abi::RuntimeExternalRange;

    #[test]
    fn decodes_independent_aarch64_cache_line_sizes() {
        assert_eq!(aarch64_cache_line_sizes(3 | (3 << 16)), (32, 32));
        assert_eq!(aarch64_cache_line_sizes(4 | (5 << 16)), (128, 64));
        assert_eq!(aarch64_cache_line_sizes(5 | (4 << 16)), (64, 128));
    }

    #[test]
    fn deferred_buffer_contract_rejects_invalid_ranges() {
        let valid = DeferredBufferConfig {
            base: 0x40_0000,
            size: 0x1_0000,
        };
        assert_eq!(
            validate_deferred_buffer(valid, &[]).ok(),
            Some((0x40_0000, 0x1_0000))
        );
        for invalid in [
            DeferredBufferConfig { base: 0, ..valid },
            DeferredBufferConfig { size: 0, ..valid },
            DeferredBufferConfig {
                base: valid.base + 1,
                ..valid
            },
            DeferredBufferConfig {
                size: valid.size - 1,
                ..valid
            },
            DeferredBufferConfig {
                base: u64::MAX - 0xfff,
                size: 0x2000,
            },
        ] {
            assert!(validate_deferred_buffer(invalid, &[]).is_err());
        }
        let overlap = RuntimeExternalRange {
            physical_base: valid.base,
            byte_len: 0x1000,
            attributes: 1 << 63,
        };
        assert!(validate_deferred_buffer(valid, &[overlap]).is_err());
    }
}
