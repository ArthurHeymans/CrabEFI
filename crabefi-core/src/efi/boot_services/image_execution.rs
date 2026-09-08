//! Assembly-owned image invocation frames. Exit preparation returns normally;
//! only foreign image frames are abandoned, never a suspended Rust setjmp frame.
//! Callback-depth snapshots reject Exit through intervening firmware callbacks.
//! Every firmware call into foreign callback code must use the shared guard;
//! nested image calls get their own snapshot and remain independently exitable.

use core::arch::naked_asm;

use r_efi::efi::{Handle, Status, SystemTable};

use crate::cell::LocalCell;

#[repr(C)]
pub(super) struct Context {
    sp: usize,
    pub previous: *mut Context,
    pub callback_depth: usize,
    pub handle: Handle,
    pub status: Status,
    pub data: *mut u16,
    pub size: usize,
    pub exited: bool,
}

pub(super) static CURRENT: LocalCell<*mut Context> = LocalCell::new(core::ptr::null_mut());

impl Context {
    pub fn new(handle: Handle) -> Self {
        Self {
            sp: 0,
            previous: CURRENT.get(),
            callback_depth: super::super::image_callback_depth(),
            handle,
            status: Status::SUCCESS,
            data: core::ptr::null_mut(),
            size: 0,
            exited: false,
        }
    }
}

/// Invoke an EFI entry through an assembly-owned execution frame.
///
/// # Arguments
/// `ctx` is the live context; `entry`, `handle`, and `st` describe the image call.
/// # Returns
/// The entry status on normal return; ignored after a successful Exit.
/// # Safety
/// The context must remain writable and stationary, and entry must implement
/// the EFI ABI. Non-local Exit must not skip live firmware Rust callbacks.
///
/// C ABI on x86_64-unknown-none is SysV. XMM registers are caller-saved at
/// this boundary; the foreign entry itself uses the Microsoft EFI ABI.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
pub(super) unsafe extern "C" fn invoke(
    _ctx: *mut Context,
    _entry: usize,
    _handle: Handle,
    _st: *mut SystemTable,
) -> Status {
    naked_asm!(
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "sub rsp, 40",
        "stmxcsr [rsp+32]",
        "fnstcw [rsp+36]",
        "mov [rdi], rsp",
        "mov rax, rsi",
        "mov r8, rcx",
        "mov rcx, rdx",
        "mov rdx, r8",
        "call rax",
        "ldmxcsr [rsp+32]",
        "fldcw [rsp+36]",
        "add rsp, 40",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "ret"
    );
}

// This wrapper has no Rust frame to abandon. The preparation routine returns
// either a low-half physical context pointer, zero for unstarted-image success,
// or an EFI error (high bit set). Firmware stacks reside in identity-mapped RAM.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
pub(in crate::efi::boot_services) extern "efiapi" fn exit(
    _h: Handle,
    _s: Status,
    _n: usize,
    _d: *mut u16,
) -> Status {
    naked_asm!(
        "sub rsp, 40", "call {prepare}", "add rsp, 40", "test rax, rax", "jz 2f", "js 2f",
        "mov rsp, [rax]", "xor eax, eax", "ldmxcsr [rsp+32]", "fldcw [rsp+36]",
        "add rsp, 40", "pop r15", "pop r14", "pop r13", "pop r12", "pop rbx", "pop rbp",
        "2:", "ret", prepare = sym super::prepare_exit
    );
}

/// AAPCS64 image-call boundary; same arguments, result, and safety contract as
/// the x86_64 invocation above. Preserves the ABI-defined low halves of v8–v15.
///
/// # Safety
/// Requires a live writable context and an EFI entry; Exit may skip only foreign frames.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
pub(super) unsafe extern "C" fn invoke(
    _ctx: *mut Context,
    _entry: usize,
    _handle: Handle,
    _st: *mut SystemTable,
) -> Status {
    naked_asm!(
        "sub sp, sp, #176", "stp x19, x20, [sp]", "stp x21, x22, [sp, #16]",
        "stp x23, x24, [sp, #32]", "stp x25, x26, [sp, #48]", "stp x27, x28, [sp, #64]",
        "stp x29, x30, [sp, #80]", "stp d8, d9, [sp, #96]", "stp d10, d11, [sp, #112]",
        "stp d12, d13, [sp, #128]", "stp d14, d15, [sp, #144]",
        "mrs x9, fpcr", "str x9, [sp, #160]", "mov x9, sp", "str x9, [x0]",
        "mov x9, x1", "mov x0, x2", "mov x1, x3", "blr x9", "b {restore}", restore = sym restore
    );
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn restore() {
    naked_asm!(
        "ldr x9, [sp, #160]",
        "msr fpcr, x9",
        "ldp x19, x20, [sp]",
        "ldp x21, x22, [sp, #16]",
        "ldp x23, x24, [sp, #32]",
        "ldp x25, x26, [sp, #48]",
        "ldp x27, x28, [sp, #64]",
        "ldp x29, x30, [sp, #80]",
        "ldp d8, d9, [sp, #96]",
        "ldp d10, d11, [sp, #112]",
        "ldp d12, d13, [sp, #128]",
        "ldp d14, d15, [sp, #144]",
        "add sp, sp, #176",
        "ret"
    );
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
pub(in crate::efi::boot_services) extern "efiapi" fn exit(
    _h: Handle,
    _s: Status,
    _n: usize,
    _d: *mut u16,
) -> Status {
    naked_asm!(
        "stp x29, x30, [sp, #-16]!", "bl {prepare}", "ldp x29, x30, [sp], #16",
        "cbz x0, 2f", "tbnz x0, #63, 2f", "ldr x9, [x0]", "mov sp, x9", "mov x0, #0", "b {restore}",
        "2:", "ret", prepare = sym super::prepare_exit, restore = sym restore
    );
}

// The selected riscv64gc target uses lp64d even though LTO can assemble module
// asm with a narrower ISA. Scope +d locally rather than dropping ABI saves.
// FS=Off means there is no live caller FP context: avoid FP instructions then.
/// RISC-V image-call boundary; same arguments and result as the x86_64 version.
///
/// # Safety
/// Requires a live writable context and an EFI entry; Exit may skip only foreign frames.
#[cfg(target_arch = "riscv64")]
#[unsafe(naked)]
pub(super) unsafe extern "C" fn invoke(
    _ctx: *mut Context,
    _entry: usize,
    _handle: Handle,
    _st: *mut SystemTable,
) -> Status {
    naked_asm!(
        ".option push", ".option arch, +d",
        "addi sp, sp, -224", "sd ra, 0(sp)",
        "sd s0, 8(sp)",
        "sd s1, 16(sp)",
        "sd s2, 24(sp)",
        "sd s3, 32(sp)",
        "sd s4, 40(sp)",
        "sd s5, 48(sp)",
        "sd s6, 56(sp)",
        "sd s7, 64(sp)",
        "sd s8, 72(sp)",
        "sd s9, 80(sp)",
        "sd s10, 88(sp)",
        "sd s11, 96(sp)",
        "csrr t0, sstatus", "li t1, 0x6000", "and t0, t0, t1", "sd t0, 208(sp)",
        "beqz t0, 2f",
        "fsd fs0, 104(sp)",
        "fsd fs1, 112(sp)",
        "fsd fs2, 120(sp)",
        "fsd fs3, 128(sp)",
        "fsd fs4, 136(sp)",
        "fsd fs5, 144(sp)",
        "fsd fs6, 152(sp)",
        "fsd fs7, 160(sp)",
        "fsd fs8, 168(sp)",
        "fsd fs9, 176(sp)",
        "fsd fs10, 184(sp)",
        "fsd fs11, 192(sp)",
        "frcsr t0", "sd t0, 200(sp)",
        "2:", "sd sp, 0(a0)",
        "mv t0, a1", "mv a0, a2", "mv a1, a3", "jalr t0", "tail {restore}",
        ".option pop", restore = sym restore
    );
}
#[cfg(target_arch = "riscv64")]
#[unsafe(naked)]
unsafe extern "C" fn restore() {
    naked_asm!(
        ".option push",
        ".option arch, +d",
        "ld ra, 0(sp)",
        "ld t1, 208(sp)",
        "li t2, 0x6000",
        "beqz t1, 2f",
        "csrs sstatus, t2",
        "ld t0, 200(sp)",
        "fscsr t0",
        "fld fs0, 104(sp)",
        "fld fs1, 112(sp)",
        "fld fs2, 120(sp)",
        "fld fs3, 128(sp)",
        "fld fs4, 136(sp)",
        "fld fs5, 144(sp)",
        "fld fs6, 152(sp)",
        "fld fs7, 160(sp)",
        "fld fs8, 168(sp)",
        "fld fs9, 176(sp)",
        "fld fs10, 184(sp)",
        "fld fs11, 192(sp)",
        "2:",
        "csrc sstatus, t2",
        "csrs sstatus, t1",
        "ld s0, 8(sp)",
        "ld s1, 16(sp)",
        "ld s2, 24(sp)",
        "ld s3, 32(sp)",
        "ld s4, 40(sp)",
        "ld s5, 48(sp)",
        "ld s6, 56(sp)",
        "ld s7, 64(sp)",
        "ld s8, 72(sp)",
        "ld s9, 80(sp)",
        "ld s10, 88(sp)",
        "ld s11, 96(sp)",
        "addi sp, sp, 224",
        "ret",
        ".option pop"
    );
}
#[cfg(target_arch = "riscv64")]
#[unsafe(naked)]
pub(in crate::efi::boot_services) extern "efiapi" fn exit(
    _h: Handle,
    _s: Status,
    _n: usize,
    _d: *mut u16,
) -> Status {
    naked_asm!(
        "addi sp, sp, -16", "sd ra, 0(sp)", "call {prepare}", "ld ra, 0(sp)", "addi sp, sp, 16",
        "beqz a0, 2f", "bltz a0, 2f", "ld sp, 0(a0)", "li a0, 0", "tail {restore}",
        "2:", "ret", prepare = sym super::prepare_exit, restore = sym restore
    );
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;

    // No Rust frame is skipped: the test image calls Exit from a second
    // assembly function, with an instruction trap if Exit ever returns.
    #[unsafe(naked)]
    extern "efiapi" fn image(_handle: Handle, _st: *mut SystemTable) -> Status {
        naked_asm!("sub rsp, 40", "call {helper}", "ud2", helper = sym helper);
    }

    #[unsafe(naked)]
    extern "efiapi" fn helper() {
        naked_asm!(
            "sub rsp, 40", "mov rdx, {status}", "xor r8d, r8d", "xor r9d, r9d",
            "call {exit}", "ud2", status = const Status::ABORTED.as_usize(), exit = sym exit
        );
    }

    extern "efiapi" fn outer(_handle: Handle, _st: *mut SystemTable) -> Status {
        let previous = CURRENT.get();
        crate::efi::boot_services::with_image_callback(|| {
            // A callback cannot Exit the suspended outer image through this
            // live Rust closure. It can start a new image that exits normally.
            let denied = exit(_handle, Status::ABORTED, 0, core::ptr::null_mut());
            assert_eq!(denied, Status::INVALID_PARAMETER);
            let mut inner = Context::new(2usize as Handle);
            CURRENT.set(core::ptr::addr_of_mut!(inner));
            unsafe {
                invoke(
                    core::ptr::addr_of_mut!(inner),
                    image as *const () as usize,
                    inner.handle,
                    core::ptr::null_mut(),
                );
            }
            CURRENT.set(inner.previous);
            assert_eq!(CURRENT.get(), previous);
            assert!(inner.exited);
            assert_eq!(inner.status, Status::ABORTED);
        });
        Status::SUCCESS
    }

    #[test]
    fn nested_image_exit_returns_to_matching_invocation() {
        let _guard = crate::efi::boot_services::IMAGE_EXECUTION_TEST_LOCK
            .lock()
            .unwrap();
        let mut context = Context::new(1usize as Handle);
        CURRENT.set(core::ptr::addr_of_mut!(context));
        let status = unsafe {
            invoke(
                core::ptr::addr_of_mut!(context),
                outer as *const () as usize,
                context.handle,
                core::ptr::null_mut(),
            )
        };
        CURRENT.set(context.previous);
        assert_eq!(status, Status::SUCCESS);
        assert!(!context.exited);
    }
}
