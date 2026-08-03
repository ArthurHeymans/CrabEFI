//! Firmware phase capability facade
//!
//! UEFI runtime-service function pointers are phase-blind, so each ABI entry
//! point must dynamically classify the call once. Below that boundary,
//! branded capability tokens make boot-state and runtime-state operations
//! distinct Rust APIs.

pub use crabefi_runtime::{BootCtx, Phase, RuntimeCtx, assert_boot};

/// Classify one call at a phase-blind UEFI ABI boundary.
#[inline]
pub fn dispatch<R>(f: impl for<'brand> FnOnce(Phase<'brand>) -> R) -> R {
    crabefi_runtime::dispatch(f)
}

/// Whether ExitBootServices has completed.
///
/// Phase-sensitive code should use [`dispatch`]. This compatibility query is
/// limited to backends not yet migrated to capability parameters.
#[inline]
pub(crate) fn is_runtime() -> bool {
    crabefi_runtime::is_runtime()
}

/// Commit the successful ExitBootServices transition.
///
/// This wrapper is intentionally crate-private; structural CI additionally
/// restricts its call site to the ExitBootServices implementation.
#[inline]
pub(crate) fn commit_exit_boot_services() {
    crabefi_runtime::commit_exit_boot_services();
}
