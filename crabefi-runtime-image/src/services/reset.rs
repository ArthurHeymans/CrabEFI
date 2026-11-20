use core::ffi::c_void;

use crate::{arch, efi, state};

pub extern "efiapi" fn reset_system(
    reset_type: efi::ResetType,
    _reset_status: efi::Status,
    _data_size: usize,
    _reset_data: *mut c_void,
) {
    arch::reset(state::reset_config(), reset_type)
}
