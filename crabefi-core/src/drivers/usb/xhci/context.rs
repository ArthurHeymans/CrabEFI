//! xHCI input-context builders.

use core::ptr;
use xhci::context::{self, EndpointHandler, InputControlHandler, InputHandler, SlotHandler};

impl super::XhciController {
    #[inline]
    pub(super) fn input_context_len(context_size: u8) -> usize {
        context_size as usize * 33 // input control + slot + 31 endpoint contexts
    }

    #[inline]
    pub(super) fn input_control_context<'a>(
        input: *mut u8,
        context_size: u8,
    ) -> &'a mut dyn InputControlHandler {
        // SAFETY: input points to a page-aligned, zeroed context allocation of
        // the controller-selected upstream 32- or 64-byte Input layout.
        unsafe {
            if context_size == 64 {
                (&mut *(input as *mut context::Input64Byte)).control_mut()
            } else {
                (&mut *(input as *mut context::Input32Byte)).control_mut()
            }
        }
    }

    #[inline]
    pub(super) fn input_slot_context<'a>(
        input: *mut u8,
        context_size: u8,
    ) -> &'a mut dyn SlotHandler {
        // SAFETY: same allocation and layout invariant as input_control_context.
        unsafe {
            if context_size == 64 {
                (&mut *(input as *mut context::Input64Byte))
                    .device_mut()
                    .slot_mut()
            } else {
                (&mut *(input as *mut context::Input32Byte))
                    .device_mut()
                    .slot_mut()
            }
        }
    }

    #[inline]
    pub(super) fn input_ep_context<'a>(
        input: *mut u8,
        context_size: u8,
        ep_index: usize,
    ) -> &'a mut dyn EndpointHandler {
        let dci = ep_index + 1;
        // SAFETY: callers use endpoint indices in 0..31 and the allocation is
        // an upstream Input32Byte or Input64Byte selected by HCCPARAMS1.CSZ.
        unsafe {
            if context_size == 64 {
                (&mut *(input as *mut context::Input64Byte))
                    .device_mut()
                    .endpoint_mut(dci)
            } else {
                (&mut *(input as *mut context::Input32Byte))
                    .device_mut()
                    .endpoint_mut(dci)
            }
        }
    }

    #[inline]
    pub(super) fn copy_context_payload(dst: *mut u8, src: *const u8) {
        // Only the architected first 32 bytes contain fields. The destination
        // was zeroed, so the reserved upper half of a 64-byte context stays 0.
        unsafe { ptr::copy_nonoverlapping(src, dst, 32) };
    }

    #[inline]
    pub(super) fn copy_device_slot_context(input: *mut u8, device: *const u8, context_size: u8) {
        let dst = unsafe { input.add(context_size as usize) };
        Self::copy_context_payload(dst, device);
    }

    #[inline]
    pub(super) fn copy_device_ep_context(
        input: *mut u8,
        device: *const u8,
        context_size: u8,
        ep_index: usize,
    ) {
        let dst = unsafe { input.add((ep_index + 2) * context_size as usize) };
        let src = unsafe { device.add((ep_index + 1) * context_size as usize) };
        Self::copy_context_payload(dst, src);
    }
}
