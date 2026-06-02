//! EFI Random Number Generator Protocol
//!
//! This protocol provides hardware random number generation to EFI applications.
//! The arch-specific implementation (e.g., x86 RDRAND) lives in `arch/`.
//!
//! Reference: UEFI Specification 2.10, Section 37.2

use r_efi::efi::{Guid, Status};

use crate::arch::rng as arch_rng;
use crate::efi::utils::allocate_protocol_with_log;

/// RNG Protocol GUID
/// {3152BCA5-EADE-433D-862E-C01CDC291F44}
pub const RNG_PROTOCOL_GUID: Guid = r_efi::protocols::rng::PROTOCOL_GUID;

/// Algorithm GUID for SP800-90 CTR-256 (default)
/// {44F0DE6E-4D8C-4045-A8C7-4DD168856B9E}
const ALGORITHM_SP800_90_CTR_256: Guid = r_efi::protocols::rng::ALGORITHM_SP800_90_CTR_256_GUID;

/// Get supported RNG algorithms
///
/// # Arguments
/// * `rng_algorithm_list_size` - On input, size of the buffer; on output, size needed/used
/// * `rng_algorithm_list` - Buffer to fill with algorithm GUIDs
///
/// # Returns
/// * `Status::SUCCESS` - Algorithms returned successfully
/// * `Status::BUFFER_TOO_SMALL` - Buffer too small, size updated with required size
extern "efiapi" fn rng_get_info(
    _this: *mut r_efi::protocols::rng::Protocol,
    rng_algorithm_list_size: *mut usize,
    rng_algorithm_list: *mut Guid,
) -> Status {
    if rng_algorithm_list_size.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let size = unsafe { *rng_algorithm_list_size };
    const REQUIRED_SIZE: usize = 1;

    if size < REQUIRED_SIZE {
        unsafe {
            *rng_algorithm_list_size = REQUIRED_SIZE;
        }
        return Status::BUFFER_TOO_SMALL;
    }

    if rng_algorithm_list.is_null() {
        return Status::INVALID_PARAMETER;
    }

    log::debug!("RNG.GetInfo()");

    unsafe {
        *rng_algorithm_list_size = REQUIRED_SIZE;
        *rng_algorithm_list = ALGORITHM_SP800_90_CTR_256;
    }

    log::debug!("  -> SUCCESS (1 algorithm)");
    Status::SUCCESS
}

/// Generate random bytes using the specified algorithm
///
/// # Arguments
/// * `rng_algorithm` - Algorithm to use (NULL for default SP800-90 CTR-256)
/// * `rng_value_length` - Number of bytes to generate
/// * `rng_value` - Buffer to fill with random bytes
///
/// # Returns
/// * `Status::SUCCESS` - Random bytes generated successfully
/// * `Status::INVALID_PARAMETER` - Invalid parameters
/// * `Status::UNSUPPORTED` - Requested algorithm not supported
/// * `Status::DEVICE_ERROR` - Hardware RNG failure
extern "efiapi" fn rng_get_rng(
    _this: *mut r_efi::protocols::rng::Protocol,
    rng_algorithm: *mut Guid,
    rng_value_length: usize,
    rng_value: *mut u8,
) -> Status {
    if rng_value.is_null() || rng_value_length == 0 {
        return Status::INVALID_PARAMETER;
    }

    log::debug!("RNG.GetRNG(length={})", rng_value_length);

    let algorithm = if rng_algorithm.is_null() {
        ALGORITHM_SP800_90_CTR_256
    } else {
        unsafe { *rng_algorithm }
    };

    if algorithm != ALGORITHM_SP800_90_CTR_256 {
        log::debug!("  -> UNSUPPORTED (algorithm not supported)");
        return Status::UNSUPPORTED;
    }

    let buffer = unsafe { core::slice::from_raw_parts_mut(rng_value, rng_value_length) };

    if !arch_rng::fill_random(buffer) {
        log::error!("RNG.GetRNG: hardware RNG failed");
        return Status::DEVICE_ERROR;
    }

    log::debug!("  -> SUCCESS (generated {} bytes)", rng_value_length);
    Status::SUCCESS
}

/// Check if the hardware RNG is available
pub fn is_supported() -> bool {
    arch_rng::is_supported()
}

/// Initialize the hardware RNG
pub fn init() {
    arch_rng::init();
}

/// Create and initialize the RNG Protocol
///
/// # Returns
/// A pointer to the protocol instance, or null on allocation failure
pub fn create_protocol() -> *mut r_efi::protocols::rng::Protocol {
    let ptr = allocate_protocol_with_log::<r_efi::protocols::rng::Protocol>("RNGProtocol", |p| {
        p.get_info = rng_get_info;
        p.get_rng = rng_get_rng;
    });

    if ptr.is_null() {
        return ptr;
    }

    log::info!("EFI_RNG_PROTOCOL installed");
    ptr
}
