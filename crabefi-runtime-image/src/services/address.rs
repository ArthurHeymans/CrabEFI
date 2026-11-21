use core::ffi::c_void;

use crate::{
    efi,
    state::{self, Phase},
    svam,
};

pub extern "efiapi" fn set_virtual_address_map(
    memory_map_size: usize,
    descriptor_size: usize,
    descriptor_version: u32,
    virtual_map: *mut efi::MemoryDescriptor,
) -> efi::Status {
    efi::status(svam::set_virtual_address_map(
        memory_map_size,
        descriptor_size,
        descriptor_version,
        virtual_map,
    ))
}

pub extern "efiapi" fn convert_pointer(
    debug_disposition: usize,
    address: *mut *mut c_void,
) -> efi::Status {
    efi::status(convert_address(debug_disposition, address))
}

fn convert_address(debug_disposition: usize, address: *mut *mut c_void) -> Result<(), efi::Status> {
    const OPTIONAL_POINTER: usize = 1;
    if address.is_null() || debug_disposition & !OPTIONAL_POINTER != 0 {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    // SAFETY: address is the required writable pointer-to-pointer argument.
    let physical = unsafe { address.read() } as u64;
    if physical == 0 {
        return if debug_disposition & OPTIONAL_POINTER != 0 {
            Ok(())
        } else {
            Err(efi::Status::INVALID_PARAMETER)
        };
    }
    if Phase::current() != Phase::Virtual {
        return Err(efi::Status::NOT_STARTED);
    }
    let lease = state::lease()?;
    let runtime = lease.state();
    let converted = runtime
        .sections
        .iter()
        .find_map(|section| {
            let offset = physical.checked_sub(section.physical_base)?;
            (offset < u64::from(section.byte_len))
                .then(|| section.virtual_base.checked_add(offset))?
        })
        .or_else(|| {
            runtime.ranges.iter().find_map(|range| {
                let offset = physical.checked_sub(range.physical_base)?;
                (offset < range.byte_len).then(|| range.virtual_base.checked_add(offset))?
            })
        })
        .or_else(|| {
            let retained = runtime.retained?;
            let offset = physical.checked_sub(retained.physical_base)?;
            (offset < retained.size as u64).then(|| retained.virtual_base.checked_add(offset))?
        })
        .ok_or(efi::Status::NOT_FOUND)?;
    // SAFETY: address is writable as required by the protocol call.
    unsafe { address.write(converted as *mut c_void) };
    Ok(())
}
