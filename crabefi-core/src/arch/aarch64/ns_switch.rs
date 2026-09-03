//! Secure-to-Non-Secure EL1 transition for ExitBootServices.
//!
//! At Secure EL1, GICv3 routes Non-Secure Group 1 interrupts (LPIs / MSI-X)
//! as FIQ. The Linux kernel only handles IRQ, so NVMe and other MSI-X devices
//! hang forever waiting for completion interrupts.
//!
//! The trampoline writes a small code sequence to a transient boot-image BSS
//! buffer. It executes and returns inside the successful ExitBootServices call,
//! before the runtime image seals the boot-image boundary:
//!
//! ```text
//!   STP  X30, XZR, [SP, #-16]!   // save return address
//!   MOV  X0, #0xC200, LSL #16    // FSTART_NS_SWITCH function ID
//!   SMC  #0                       // → EL3: SCR_EL3.NS=1, ERET back
//!   LDP  X30, XZR, [SP], #16     // restore return address
//!   RET                           // back to caller (now at NS-EL1)
//! ```
//!
//! Uses vendor-specific SMCCC function ID `0xC200_0000` handled by fstart's
//! EL3 exception vector table.

/// AArch64 machine code for the NS switch trampoline.
const TRAMPOLINE_CODE: [u32; 5] = [
    0xA9BF_7BFE, // stp x30, xzr, [sp, #-16]!
    0xD298_4000, // mov x0, #0xC200, lsl #16  (= 0xC2000000)
    0xD400_0003, // smc #0
    0xA8C1_7BFE, // ldp x30, xzr, [sp], #16
    0xD65F_03C0, // ret
];

/// Transient BootServicesData buffer used only during ExitBootServices.
static TRAMPOLINE_BUF: crate::cell::StaticMut<[u32; 5]> = crate::cell::StaticMut::new([0; 5]);

/// Transition from Secure EL1 to Non-Secure EL1.
///
/// Probes for an EL3 handler (PSCI_VERSION), writes the trampoline to RAM,
/// flushes caches, and calls it. After return, the CPU is at NS-EL1.
///
/// No-op if no EL3 exists (QEMU without `secure=on`).
pub fn install_ns_trampoline() {
    // Probe: is an EL3 handler present?
    // Our handler returns 0x10001 (PSCI v1.1). Without EL3, SMC causes
    // an undefined exception → EL1 handler returns something else.
    let psci_ver: u64;
    unsafe {
        core::arch::asm!(
            "mov x0, #0x84000000", // PSCI_VERSION
            "smc #0",
            out("x0") psci_ver,
            out("x1") _,
            out("x2") _,
            out("x3") _,
            options(nomem, nostack)
        );
    }
    if psci_ver != 0x10001 {
        return;
    }

    unsafe {
        // Write trampoline instructions to the RAM buffer.
        let buf = TRAMPOLINE_BUF.get().cast::<u32>();
        for (i, &insn) in TRAMPOLINE_CODE.iter().enumerate() {
            core::ptr::write_volatile(buf.add(i), insn);
        }

        // Cache maintenance: clean data cache, invalidate instruction cache.
        let addr = buf as usize;
        core::arch::asm!(
            "dc cvau, {addr}",
            "dsb ish",
            "ic ivau, {addr}",
            "dsb ish",
            "isb",
            addr = in(reg) addr,
            options(nostack)
        );

        // Call the trampoline. It does SMC (NS switch) then returns here.
        // After return we're at NS-EL1 — interrupt routing is fixed.
        core::arch::asm!(
            "blr {trampoline}",
            trampoline = in(reg) addr,
            out("x0") _,
            out("x1") _,
            out("x2") _,
            out("x3") _,
            options(nomem, nostack)
        );
    }
}
