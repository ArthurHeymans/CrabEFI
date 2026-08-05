//! Cargo-bundled Runtime Services image.
//!
//! The selected image is generated, normalized, and audited from the runtime
//! image source in this repository. Its digest is compiled into the same
//! containing firmware image as the bytes.

use crate::RuntimeImageSource;

/// Architecture-matched Runtime Services image bundled by Cargo.
///
/// Enable the `bundled-runtime-image` feature to use this value. Platforms
/// that load or authenticate their own runtime image should construct a
/// [`RuntimeImageSource`] directly instead.
pub const BUNDLED_RUNTIME_IMAGE: RuntimeImageSource<'static> = RuntimeImageSource {
    bytes: crabefi_runtime_bundle::IMAGE,
    expected_sha256: crabefi_runtime_bundle::SHA256,
};
