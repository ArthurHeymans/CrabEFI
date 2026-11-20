//! Image-local EFI Runtime Services entry points.
//!
//! Each `extern "efiapi"` service is a thin shim that converts the `Result` of
//! its implementation into the returned status.

mod address;
mod capsule;
mod reset;
mod time;
mod variables;

pub use address::{convert_pointer, set_virtual_address_map};
#[cfg(feature = "mm")]
pub use capsule::is_capsule_staging_variable;
pub use capsule::{query_capsule_capabilities, update_capsule};
pub use reset::reset_system;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
pub use time::time_from_unix;
pub use time::{
    get_next_high_mono_count, get_time, get_wakeup_time, set_time, set_wakeup_time,
    time_is_supported,
};
#[cfg(feature = "mm")]
pub use variables::auth_timestamp_floor;
pub use variables::{
    get_next_variable_name, get_variable, prepare_retained_staging, query_variable_info,
    replay_deferred, set_variable,
};
