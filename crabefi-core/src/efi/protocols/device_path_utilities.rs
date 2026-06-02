//! EFI Device Path Utilities Protocol
//!
//! Implements the `EFI_DEVICE_PATH_UTILITIES_PROTOCOL` which provides utility
//! functions for creating and manipulating device paths. This protocol is
//! required by GRUB2, systemd-boot, and shim for device path manipulation.
//!
//! Reference: UEFI Specification 2.10, Section 10.3
//! Reference: EDK2 `MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.c`

use core::ffi::c_void;
use core::ptr;

use r_efi::efi::{Boolean, Guid};
use r_efi::protocols::device_path;
use r_efi::protocols::device_path_utilities;

use crate::efi::allocator;
use crate::efi::utils::allocate_protocol_with_log;

// Re-use shared helpers from device_path.rs
use super::device_path::{
    MAX_DEVICE_PATH_SIZE, MIN_NODE_LENGTH, SUBTYPE_END_INSTANCE, alloc_pool, device_path_size,
    write_end_node,
};

pub const DEVICE_PATH_UTILITIES_GUID: Guid = device_path_utilities::PROTOCOL_GUID;

/// End-of-device-path node type
const TYPE_END: u8 = 0x7F;

// ============================================================================
// Local walking helpers (protocol-specific, not worth sharing)
// ============================================================================

/// Return the length of a single device path node.
#[inline]
unsafe fn node_length(node: *const device_path::Protocol) -> u16 {
    let p = node as *const u8;
    unsafe { u16::from_le_bytes([*p.add(2), *p.add(3)]) }
}

/// Check if a node is an end-of-device-path (either end-entire or end-instance).
#[inline]
unsafe fn is_end_type(node: *const device_path::Protocol) -> bool {
    unsafe { (*(node as *const u8)) == TYPE_END }
}

/// Check if a node is an end-instance separator.
#[inline]
unsafe fn is_end_instance(node: *const device_path::Protocol) -> bool {
    let p = node as *const u8;
    unsafe { *p == TYPE_END && *p.add(1) == SUBTYPE_END_INSTANCE }
}

/// Advance to the next node in the device path.
#[inline]
unsafe fn next_node(node: *const device_path::Protocol) -> *const device_path::Protocol {
    let len = unsafe { node_length(node) } as usize;
    unsafe { (node as *const u8).add(len) as *const device_path::Protocol }
}

// ============================================================================
// Protocol function implementations
// ============================================================================

/// `GetDevicePathSize` — return total byte size of a device path including End node.
extern "efiapi" fn get_device_path_size(device_path: *const device_path::Protocol) -> usize {
    unsafe { device_path_size(device_path) }
}

/// `DuplicateDevicePath` — allocate a copy of a device path.
extern "efiapi" fn duplicate_device_path(
    device_path: *const device_path::Protocol,
) -> *mut device_path::Protocol {
    let size = unsafe { device_path_size(device_path) };
    if size == 0 {
        return ptr::null_mut();
    }
    let buf = alloc_pool(size);
    if buf.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        ptr::copy_nonoverlapping(device_path as *const u8, buf, size);
    }
    buf as *mut device_path::Protocol
}

/// `AppendDevicePath` — concatenate two device paths.
///
/// - Both NULL: returns an end-only device path.
/// - One NULL: returns a duplicate of the other.
/// - Both non-NULL: Src1 nodes + Src2 (full, including its end node).
extern "efiapi" fn append_device_path(
    src1: *const device_path::Protocol,
    src2: *const device_path::Protocol,
) -> *mut device_path::Protocol {
    if src1.is_null() && src2.is_null() {
        // Return a minimal end-only device path
        let buf = alloc_pool(MIN_NODE_LENGTH as usize);
        if buf.is_null() {
            return ptr::null_mut();
        }
        unsafe { write_end_node(buf) };
        return buf as *mut device_path::Protocol;
    }
    if src1.is_null() {
        return duplicate_device_path(src2);
    }
    if src2.is_null() {
        return duplicate_device_path(src1);
    }

    let size1 = unsafe { device_path_size(src1) };
    let size2 = unsafe { device_path_size(src2) };
    if size1 == 0 || size2 == 0 {
        return ptr::null_mut();
    }

    // Src1 without its end node + Src2 complete
    let end_size = MIN_NODE_LENGTH as usize;
    let total = (size1 - end_size) + size2;
    let buf = alloc_pool(total);
    if buf.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        // Copy Src1 without end node
        ptr::copy_nonoverlapping(src1 as *const u8, buf, size1 - end_size);
        // Copy Src2 (with its end node)
        ptr::copy_nonoverlapping(src2 as *const u8, buf.add(size1 - end_size), size2);
    }
    buf as *mut device_path::Protocol
}

/// `AppendDeviceNode` — append a single node to a device path.
///
/// Wraps the node in a temporary device path, then calls `append_device_path`.
extern "efiapi" fn append_device_node(
    device_path_ptr: *const device_path::Protocol,
    device_node: *const device_path::Protocol,
) -> *mut device_path::Protocol {
    if device_node.is_null() {
        if device_path_ptr.is_null() {
            // Both NULL: return end-only path
            let buf = alloc_pool(MIN_NODE_LENGTH as usize);
            if buf.is_null() {
                return ptr::null_mut();
            }
            unsafe { write_end_node(buf) };
            return buf as *mut device_path::Protocol;
        }
        return duplicate_device_path(device_path_ptr);
    }

    unsafe {
        let nlen = node_length(device_node) as usize;
        if !(MIN_NODE_LENGTH as usize..=MAX_DEVICE_PATH_SIZE).contains(&nlen) {
            return ptr::null_mut();
        }
        let end_size = MIN_NODE_LENGTH as usize;
        let temp_size = nlen + end_size;

        let temp = alloc_pool(temp_size);
        if temp.is_null() {
            return ptr::null_mut();
        }
        // Copy node + append end
        ptr::copy_nonoverlapping(device_node as *const u8, temp, nlen);
        write_end_node(temp.add(nlen));

        let result = append_device_path(device_path_ptr, temp as *const device_path::Protocol);

        // Free the temporary path
        let _ = allocator::free_pool(temp);

        result
    }
}

/// `AppendDevicePathInstance` — append a device path as a new instance.
///
/// Inserts an end-of-instance separator between the two paths.
extern "efiapi" fn append_device_path_instance(
    device_path_ptr: *const device_path::Protocol,
    device_path_instance: *const device_path::Protocol,
) -> *mut device_path::Protocol {
    if device_path_instance.is_null() {
        return ptr::null_mut();
    }
    if device_path_ptr.is_null() {
        return duplicate_device_path(device_path_instance);
    }

    let size1 = unsafe { device_path_size(device_path_ptr) };
    let size2 = unsafe { device_path_size(device_path_instance) };
    if size1 == 0 || size2 == 0 {
        return ptr::null_mut();
    }

    // Replace Src1's end-entire with end-instance, then append Src2
    let end_size = MIN_NODE_LENGTH as usize;
    let total = size1 + size2; // Src1 (end becomes instance-end) + Src2 (with its end)
    // Actually: size1 includes end node. We keep it but change subtype.
    // Then we append size2 after it.
    let buf = alloc_pool(total);
    if buf.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        // Copy all of Src1
        ptr::copy_nonoverlapping(device_path_ptr as *const u8, buf, size1);
        // Change the end-entire to end-instance
        let end_node = buf.add(size1 - end_size);
        *end_node.add(1) = SUBTYPE_END_INSTANCE;
        // Append Src2
        ptr::copy_nonoverlapping(device_path_instance as *const u8, buf.add(size1), size2);
    }
    buf as *mut device_path::Protocol
}

/// `GetNextDevicePathInstance` — extract the next instance from a multi-instance path.
///
/// Updates `*device_path_instance` to point past the current instance.
/// Sets `*size` to the size of the returned instance (including an end-entire node).
extern "efiapi" fn get_next_device_path_instance(
    device_path_instance: *mut *mut device_path::Protocol,
    size: *mut usize,
) -> *mut device_path::Protocol {
    if device_path_instance.is_null() || size.is_null() {
        if !size.is_null() {
            unsafe { *size = 0 };
        }
        return ptr::null_mut();
    }

    unsafe {
        let dp = *device_path_instance;
        if dp.is_null() {
            *size = 0;
            return ptr::null_mut();
        }

        let path_size = device_path_size(dp);
        if path_size == 0 {
            *size = 0;
            return ptr::null_mut();
        }

        // Walk to the end of this instance (either end-entire or end-instance),
        // but never beyond the validated path size.
        let mut node = dp as *const device_path::Protocol;
        let mut consumed = 0usize;
        while consumed < path_size && !is_end_type(node) {
            let nlen = node_length(node) as usize;
            if nlen < MIN_NODE_LENGTH as usize || consumed + nlen > path_size {
                *size = 0;
                return ptr::null_mut();
            }
            consumed += nlen;
            node = next_node(node);
        }
        if consumed >= path_size {
            *size = 0;
            return ptr::null_mut();
        }

        let end_size = MIN_NODE_LENGTH as usize;

        // Size of instance nodes (not including the end node we found) + end node we'll add
        let instance_bytes = (node as usize) - (dp as usize);
        let result_size = instance_bytes + end_size;
        *size = result_size;

        // Allocate and copy the instance
        let buf = alloc_pool(result_size);
        if buf.is_null() {
            return ptr::null_mut();
        }
        ptr::copy_nonoverlapping(dp as *const u8, buf, instance_bytes);
        write_end_node(buf.add(instance_bytes));

        // Advance past the separator
        if is_end_instance(node) {
            *device_path_instance = next_node(node) as *mut device_path::Protocol;
        } else {
            // End-entire: no more instances
            *device_path_instance = ptr::null_mut();
        }

        buf as *mut device_path::Protocol
    }
}

/// `IsDevicePathMultiInstance` — check if a device path contains instance separators.
extern "efiapi" fn is_device_path_multi_instance(
    device_path: *const device_path::Protocol,
) -> Boolean {
    if device_path.is_null() {
        return Boolean::FALSE;
    }
    unsafe {
        let path_size = device_path_size(device_path);
        if path_size == 0 {
            return Boolean::FALSE;
        }

        let mut node = device_path;
        let mut consumed = 0usize;
        while consumed < path_size {
            let p = node as *const u8;
            let ntype = *p;
            let nlen = u16::from_le_bytes([*p.add(2), *p.add(3)]) as usize;
            if nlen < MIN_NODE_LENGTH as usize || consumed + nlen > path_size {
                return Boolean::FALSE;
            }
            if ntype == TYPE_END {
                if is_end_instance(node) {
                    return Boolean::TRUE;
                }
                return Boolean::FALSE;
            }
            consumed += nlen;
            node = next_node(node);
        }
        Boolean::FALSE
    }
}

/// `CreateDeviceNode` — allocate a new device path node with specified type/subtype/length.
extern "efiapi" fn create_device_node(
    node_type: u8,
    node_sub_type: u8,
    node_length: u16,
) -> *mut device_path::Protocol {
    if node_length < MIN_NODE_LENGTH {
        return ptr::null_mut();
    }
    let buf = alloc_pool(node_length as usize);
    if buf.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        // Zero-init
        ptr::write_bytes(buf, 0, node_length as usize);
        *buf = node_type;
        *buf.add(1) = node_sub_type;
        let len_bytes = node_length.to_le_bytes();
        *buf.add(2) = len_bytes[0];
        *buf.add(3) = len_bytes[1];
    }
    buf as *mut device_path::Protocol
}

// ============================================================================
// Protocol creation
// ============================================================================

/// Create a Device Path Utilities protocol instance.
///
/// Returns a pointer suitable for `install_protocol`, or null on allocation failure.
pub fn create_protocol() -> *mut c_void {
    let proto =
        allocate_protocol_with_log::<device_path_utilities::Protocol>("DevicePathUtilities", |p| {
            p.get_device_path_size = get_device_path_size;
            p.duplicate_device_path = duplicate_device_path;
            p.append_device_path = append_device_path;
            p.append_device_node = append_device_node;
            p.append_device_path_instance = append_device_path_instance;
            p.get_next_device_path_instance = get_next_device_path_instance;
            p.is_device_path_multi_instance = is_device_path_multi_instance;
            p.create_device_node = create_device_node;
        });
    proto as *mut c_void
}
