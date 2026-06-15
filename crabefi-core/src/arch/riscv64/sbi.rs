//! RISC-V Supervisor Binary Interface (SBI) call wrappers
//!
//! SBI provides the interface between S-mode (where CrabEFI runs) and
//! M-mode (OpenSBI). Calls are made via `ecall` with:
//!   - a7 = extension ID (EID)
//!   - a6 = function ID (FID)
//!   - a0..a5 = arguments
//!   - Returns: a0 = error code, a1 = value

/// SBI return value from an ecall.
#[derive(Debug, Clone, Copy)]
pub struct SbiRet {
    /// Error code: 0 = success, negative = error.
    pub error: i64,
    /// Return value (meaning depends on the call).
    pub value: i64,
}

impl SbiRet {
    /// Check if the SBI call succeeded.
    pub fn is_ok(self) -> bool {
        self.error == 0
    }
}

// ============================================================================
// SBI Extension IDs
// ============================================================================

/// Legacy putchar (extension 0x01) — widely supported fallback.
pub const SBI_EXT_LEGACY_PUTCHAR: u64 = 0x01;
/// Legacy getchar (extension 0x02).
pub const SBI_EXT_LEGACY_GETCHAR: u64 = 0x02;

/// Base extension (mandatory, extension 0x10).
pub const SBI_EXT_BASE: u64 = 0x10;
/// Timer extension (extension "TIME" = 0x54494D45).
pub const SBI_EXT_TIME: u64 = 0x54494D45;
/// IPI extension (extension "sPI" = 0x735049).
pub const SBI_EXT_IPI: u64 = 0x735049;
/// Remote fence extension (extension "RFNC" = 0x52464E43).
pub const SBI_EXT_RFENCE: u64 = 0x52464E43;
/// Hart State Management extension (extension "HSM" = 0x48534D).
pub const SBI_EXT_HSM: u64 = 0x48534D;
/// System Reset extension (extension "SRST" = 0x53525354).
pub const SBI_EXT_SRST: u64 = 0x53525354;
/// Debug Console extension (extension "DBCN" = 0x4442434E).
pub const SBI_EXT_DBCN: u64 = 0x4442434E;

// ============================================================================
// Low-level ecall
// ============================================================================

/// Perform a raw SBI ecall with up to 3 arguments.
#[inline]
pub fn sbi_call(eid: u64, fid: u64, a0: u64, a1: u64, a2: u64) -> SbiRet {
    let error: i64;
    let value: i64;
    // SAFETY: ecall is the defined SBI calling convention. The register
    // clobber list matches the SBI spec (a0-a1 are return, a2-a5 clobbered).
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") a0 as i64 => error,
            inlateout("a1") a1 as i64 => value,
            in("a2") a2,
            in("a6") fid,
            in("a7") eid,
        );
    }
    SbiRet { error, value }
}

/// Perform a legacy SBI ecall (extension < 0x10, no FID, single arg in a0).
#[inline]
fn sbi_legacy_call(eid: u64, a0: u64) -> SbiRet {
    sbi_call(eid, 0, a0, 0, 0)
}

// ============================================================================
// Base extension (0x10)
// ============================================================================

/// Get the SBI specification version.
///
/// Returns major in bits [30:24], minor in bits [23:0].
pub fn sbi_get_spec_version() -> u64 {
    sbi_call(SBI_EXT_BASE, 0, 0, 0, 0).value as u64
}

/// Get the SBI implementation ID.
pub fn sbi_get_impl_id() -> u64 {
    sbi_call(SBI_EXT_BASE, 1, 0, 0, 0).value as u64
}

/// Probe whether an SBI extension is available.
///
/// Returns non-zero if the extension is available.
pub fn sbi_probe_extension(eid: u64) -> bool {
    sbi_call(SBI_EXT_BASE, 3, eid, 0, 0).value != 0
}

// ============================================================================
// Console output
// ============================================================================

/// Write a single character via SBI legacy putchar.
///
/// This is the most widely supported console output method.
#[inline]
pub fn sbi_putchar(ch: u8) {
    sbi_legacy_call(SBI_EXT_LEGACY_PUTCHAR, ch as u64);
}

/// Write a byte buffer via the SBI Debug Console extension (DBCN).
///
/// Falls back to legacy putchar if DBCN is not available.
pub fn sbi_dbcn_write(buf: &[u8]) -> SbiRet {
    // DBCN write: FID=0, a0=num_bytes, a1=base_addr_lo, a2=base_addr_hi
    sbi_call(SBI_EXT_DBCN, 0, buf.len() as u64, buf.as_ptr() as u64, 0)
}

/// Read a single character via SBI legacy getchar.
///
/// Returns the character or -1 if no character is available.
#[inline]
pub fn sbi_getchar() -> i64 {
    sbi_legacy_call(SBI_EXT_LEGACY_GETCHAR, 0).error
}

// ============================================================================
// Timer extension
// ============================================================================

/// Set the next timer interrupt (absolute time value).
///
/// Uses the SBI TIME extension (0x54494D45), FID 0.
pub fn sbi_set_timer(stime_value: u64) {
    sbi_call(SBI_EXT_TIME, 0, stime_value, 0, 0);
}

// ============================================================================
// System Reset extension (SRST)
// ============================================================================

/// SRST reset types.
pub const SRST_SHUTDOWN: u64 = 0;
pub const SRST_COLD_REBOOT: u64 = 1;
pub const SRST_WARM_REBOOT: u64 = 2;

/// SRST reset reasons.
pub const SRST_REASON_NONE: u64 = 0;
pub const SRST_REASON_SYSTEM_FAILURE: u64 = 1;

/// Request a system reset via SBI SRST extension.
///
/// `reset_type`: 0=shutdown, 1=cold_reboot, 2=warm_reboot
/// `reason`: 0=no_reason, 1=system_failure
pub fn sbi_system_reset(reset_type: u64, reason: u64) -> SbiRet {
    sbi_call(SBI_EXT_SRST, 0, reset_type, reason, 0)
}

// ============================================================================
// Remote fence extension
// ============================================================================

/// Execute a remote FENCE.I on the specified harts.
pub fn sbi_remote_fence_i(hart_mask: u64, hart_mask_base: u64) -> SbiRet {
    sbi_call(SBI_EXT_RFENCE, 0, hart_mask, hart_mask_base, 0)
}

/// Execute a remote SFENCE.VMA on the specified harts (all addresses).
pub fn sbi_remote_sfence_vma(hart_mask: u64, hart_mask_base: u64) -> SbiRet {
    sbi_call(SBI_EXT_RFENCE, 1, hart_mask, hart_mask_base, 0)
}
