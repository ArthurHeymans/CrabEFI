//! Resource limits for authenticated-variable parsing and RSA verification.

/// Maximum accepted PKCS#7 authenticated-variable envelope size.
pub const MAX_AUTHENTICATED_ENVELOPE_SIZE: usize = 48 * 1024;

/// Scratch required by one RSA exponentiation.
///
/// Each RSA verification runs in its own rewind scope, so this is also the
/// maximum authentication scratch reservation needed by a service operation.
pub const AUTH_OPERATION_SCRATCH_BOUND: usize = 16 * 1024;
