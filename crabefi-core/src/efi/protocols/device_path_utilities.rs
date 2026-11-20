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

use alloc::vec::Vec;

use crate::efi::utils::allocate_protocol_value_with_log;

use super::device_path::{MIN_NODE_LENGTH, SUBTYPE_END_INSTANCE, alloc_pool};
use super::device_path_view::{DevicePath, Node, TYPE_END, terminated};

pub const DEVICE_PATH_UTILITIES_GUID: Guid = device_path_utilities::PROTOCOL_GUID;

// ============================================================================
// Path construction on checked views
// ============================================================================

/// `AppendDevicePath`: the first path's nodes followed by the whole second
/// path. A missing path counts as empty.
pub(crate) fn append(first: Option<DevicePath>, second: Option<DevicePath>) -> Option<Vec<u8>> {
    terminated(&[
        first.map_or(&[][..], DevicePath::body),
        second.map_or(&[][..], DevicePath::body),
    ])
}

/// `AppendDevicePathInstance`: the path, an End-Instance separator, then the
/// new instance.
pub(crate) fn append_instance(path: DevicePath, instance: DevicePath) -> Option<Vec<u8>> {
    terminated(&[path.body(), &END_INSTANCE, instance.body()])
}

/// The first instance as a complete path, and where the next one starts.
pub(crate) fn next_instance(path: DevicePath) -> Option<(Vec<u8>, Option<usize>)> {
    let (instance, rest) = path.split_first_instance();
    let next = rest.map(|rest| path.as_bytes().len() - rest.as_bytes().len());
    Some((terminated(&[instance])?, next))
}

const END_INSTANCE: [u8; 4] = [TYPE_END, SUBTYPE_END_INSTANCE, MIN_NODE_LENGTH as u8, 0];

/// Allocate `len` zeroed bytes of pool memory the caller frees, and let
/// `fill` write them.
fn publish_with(len: usize, fill: impl FnOnce(&mut [u8])) -> *mut device_path::Protocol {
    let buf = alloc_pool(len);
    if !buf.is_null() {
        // SAFETY: AllocatePool returned `len` exclusively owned bytes; they
        // are initialized before a slice is formed over them.
        let out = unsafe {
            ptr::write_bytes(buf, 0, len);
            core::slice::from_raw_parts_mut(buf, len)
        };
        fill(out);
    }
    buf.cast()
}

/// Copy `bytes` into a new pool allocation the caller frees.
fn publish(bytes: &[u8]) -> *mut device_path::Protocol {
    publish_with(bytes.len(), |out| out.copy_from_slice(bytes))
}

/// Publish a path built in memory; `None` means the heap was exhausted.
fn publish_built(bytes: Option<Vec<u8>>) -> *mut device_path::Protocol {
    bytes.map_or(ptr::null_mut(), |bytes| publish(&bytes))
}

/// A caller's path: `Ok(None)` for null, `Err` when malformed.
///
/// # Safety
/// As [`DevicePath::from_raw`]: `path` is null or points to a complete device
/// path in one live allocation that outlives `'a`. EFI entry points satisfy
/// this for the duration of the call; the view must not escape it.
unsafe fn caller_path<'a>(
    path: *const device_path::Protocol,
) -> Result<Option<DevicePath<'a>>, ()> {
    if path.is_null() {
        return Ok(None);
    }
    // SAFETY: forwarded from the caller.
    unsafe { DevicePath::from_raw(path) }.map(Some).ok_or(())
}

// ============================================================================
// Protocol function implementations
//
// SAFETY (all `caller_path` calls): EFI callers pass null or complete device
// paths that stay valid for the duration of the call, and no view outlives it.
// ============================================================================

/// `GetDevicePathSize` — return total byte size of a device path including End node.
extern "efiapi" fn get_device_path_size(device_path: *const device_path::Protocol) -> usize {
    unsafe { caller_path(device_path) }
        .ok()
        .flatten()
        .map_or(0, |path| path.as_bytes().len())
}

/// `DuplicateDevicePath` — allocate a copy of a device path.
extern "efiapi" fn duplicate_device_path(
    device_path: *const device_path::Protocol,
) -> *mut device_path::Protocol {
    match unsafe { caller_path(device_path) } {
        Ok(Some(path)) => publish(path.as_bytes()),
        _ => ptr::null_mut(),
    }
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
    match (unsafe { caller_path(src1) }, unsafe { caller_path(src2) }) {
        (Ok(first), Ok(second)) => publish_built(append(first, second)),
        _ => ptr::null_mut(),
    }
}

/// `AppendDeviceNode` — append a single node to a device path.
extern "efiapi" fn append_device_node(
    device_path_ptr: *const device_path::Protocol,
    device_node: *const device_path::Protocol,
) -> *mut device_path::Protocol {
    let Ok(path) = (unsafe { caller_path(device_path_ptr) }) else {
        return ptr::null_mut();
    };
    if device_node.is_null() {
        return publish_built(append(path, None));
    }
    // SAFETY: the caller passes a readable node of its claimed length.
    let Some(node) = (unsafe { Node::from_raw(device_node) }) else {
        return ptr::null_mut();
    };
    // Like EDK2, wrap the node in a path of its own first. An End-Entire node
    // then appends nothing; an End node with another subtype or length
    // cannot form a path and is rejected.
    let Some(wrapped) = terminated(&[node.as_bytes()]) else {
        return ptr::null_mut();
    };
    match DevicePath::parse(&wrapped) {
        Some(node) => publish_built(append(path, Some(node))),
        None => ptr::null_mut(),
    }
}

/// `AppendDevicePathInstance` — append a device path as a new instance.
extern "efiapi" fn append_device_path_instance(
    device_path_ptr: *const device_path::Protocol,
    device_path_instance: *const device_path::Protocol,
) -> *mut device_path::Protocol {
    match (unsafe { caller_path(device_path_ptr) }, unsafe {
        caller_path(device_path_instance)
    }) {
        (Ok(None), Ok(Some(instance))) => publish(instance.as_bytes()),
        (Ok(Some(path)), Ok(Some(instance))) => publish_built(append_instance(path, instance)),
        _ => ptr::null_mut(),
    }
}

/// `GetNextDevicePathInstance` — extract the next instance from a multi-instance path.
///
/// Updates `*device_path_instance` to point past the current instance.
/// Sets `*size` to the size of the returned instance (including an end-entire node).
extern "efiapi" fn get_next_device_path_instance(
    device_path_instance: *mut *mut device_path::Protocol,
    size: *mut usize,
) -> *mut device_path::Protocol {
    if size.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `size` is a caller-provided output.
    unsafe { *size = 0 };
    if device_path_instance.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a non-null in/out pointer from the caller.
    let current = unsafe { *device_path_instance };
    let Ok(Some(path)) = (unsafe { caller_path(current) }) else {
        return ptr::null_mut();
    };
    let Some((instance, next)) = next_instance(path) else {
        return ptr::null_mut();
    };
    let copy = publish(&instance);
    if copy.is_null() {
        // Leave the cursor on this instance so a retry does not skip it.
        return ptr::null_mut();
    }
    // SAFETY: caller-provided outputs; `next` lies inside the walked path.
    unsafe {
        *size = instance.len();
        *device_path_instance = match next {
            Some(offset) => current.cast::<u8>().add(offset).cast(),
            None => ptr::null_mut(),
        };
    }
    copy
}

/// `IsDevicePathMultiInstance` — check if a device path contains instance separators.
extern "efiapi" fn is_device_path_multi_instance(
    device_path: *const device_path::Protocol,
) -> Boolean {
    match unsafe { caller_path(device_path) } {
        Ok(Some(path)) if path.is_multi_instance() => Boolean::TRUE,
        _ => Boolean::FALSE,
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
    publish_with(usize::from(node_length), |node| {
        node[0] = node_type;
        node[1] = node_sub_type;
        node[2..4].copy_from_slice(&node_length.to_le_bytes());
    })
}

// ============================================================================
// Protocol creation
// ============================================================================

/// Create a Device Path Utilities protocol instance.
///
/// Returns a pointer suitable for `install_protocol`, or null on allocation failure.
pub fn create_protocol() -> *mut c_void {
    let proto = allocate_protocol_value_with_log(
        "DevicePathUtilities",
        device_path_utilities::Protocol {
            get_device_path_size,
            duplicate_device_path,
            append_device_path,
            append_device_node,
            append_device_path_instance,
            get_next_device_path_instance,
            is_device_path_multi_instance,
            create_device_node,
        },
    );
    proto as *mut c_void
}

#[cfg(test)]
mod tests {
    use super::*;

    const PCI: [u8; 6] = [0x01, 0x01, 6, 0, 0, 2];

    fn path(bytes: &[u8]) -> DevicePath<'_> {
        DevicePath::parse(bytes).unwrap()
    }

    #[test]
    fn append_and_split_instances_round_trip() {
        let one = terminated(&[&PCI]).unwrap();
        let two = terminated(&[&PCI, &PCI]).unwrap();
        assert_eq!(append(None, None), terminated(&[]));
        assert_eq!(append(Some(path(&one)), Some(path(&one))).unwrap(), two);

        let joined = append_instance(path(&one), path(&two)).unwrap();
        let joined = path(&joined);
        assert!(joined.is_multi_instance());
        let (first, next) = next_instance(joined).unwrap();
        assert_eq!(first, one);
        let rest = path(&joined.as_bytes()[next.unwrap()..]);
        assert_eq!(next_instance(rest), Some((two, None)));
    }

    #[test]
    fn paths_too_large_to_read_back_are_not_built() {
        let mut node = alloc::vec![0x04u8, 0x03];
        node.extend_from_slice(&40_000u16.to_le_bytes());
        node.resize(40_000, 0);
        let large = terminated(&[&node]).unwrap();
        let large = path(&large);
        assert_eq!(append(Some(large), Some(large)), None);
        assert_eq!(append_instance(large, large), None);
    }
}
