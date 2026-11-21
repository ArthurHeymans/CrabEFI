//! Bounded, checked views of caller-supplied device paths.
//!
//! A device path reaches firmware as a raw pointer to a chain of
//! variable-length nodes whose lengths the caller controls. [`DevicePath`]
//! and [`Node`] are built from such a pointer in one place, after the chain
//! has been walked under [`MAX_DEVICE_PATH_SIZE`]; after that, every walker
//! and formatter reads the bytes through checked slice indexing. A malformed
//! node can produce an error or a generic rendering, never a read outside the
//! path.

use alloc::vec::Vec;
use r_efi::protocols::device_path::Protocol;

use super::device_path::{
    MAX_DEVICE_PATH_SIZE, MIN_NODE_LENGTH, SUBTYPE_END_ENTIRE, SUBTYPE_END_INSTANCE,
    device_path_size,
};

/// Node type of End-Entire and End-Instance nodes.
pub(crate) const TYPE_END: u8 = 0x7F;

const HEADER: usize = MIN_NODE_LENGTH as usize;

/// A well-formed device path: nodes of at least four bytes, ending in exactly
/// one End-Entire node, with End-Instance separators allowed in between.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DevicePath<'a> {
    bytes: &'a [u8],
}

impl<'a> DevicePath<'a> {
    /// The device path at the start of `bytes`, if one ends within them and
    /// within [`MAX_DEVICE_PATH_SIZE`]. Bytes after its End-Entire node are
    /// not part of it.
    pub(crate) fn parse(bytes: &'a [u8]) -> Option<Self> {
        let bytes = &bytes[..bytes.len().min(MAX_DEVICE_PATH_SIZE)];
        let mut offset = 0;
        loop {
            let node = Node::parse(bytes.get(offset..)?)?;
            offset += node.len();
            if node.kind() == TYPE_END {
                if node.len() != HEADER {
                    return None;
                }
                match node.subtype() {
                    SUBTYPE_END_ENTIRE => {
                        return Some(Self {
                            bytes: &bytes[..offset],
                        });
                    }
                    SUBTYPE_END_INSTANCE => {}
                    _ => return None,
                }
            }
        }
    }

    /// View the device path a caller passed by pointer.
    ///
    /// # Safety
    /// `path` must be null or point to one live, initialized allocation that
    /// holds a complete device path, ending in End-Entire, and stays
    /// unmodified for `'a`. The walk is bounded by [`MAX_DEVICE_PATH_SIZE`]
    /// and rejects malformed node chains, but it trusts each header's length
    /// to stay inside that allocation: no walk can make a truncated buffer or
    /// an arbitrary pointer safe to read.
    pub(crate) unsafe fn from_raw(path: *const Protocol) -> Option<Self> {
        // SAFETY: forwarded from the caller. A nonzero size means the bounded
        // walk read exactly this many bytes and found End-Entire at the end.
        let size = unsafe { device_path_size(path) };
        if size == 0 {
            return None;
        }
        // SAFETY: the walk above read every one of these bytes.
        Self::parse(unsafe { core::slice::from_raw_parts(path.cast::<u8>(), size) })
    }

    /// The whole path, including its End-Entire node.
    pub(crate) fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// The path without its End-Entire node.
    pub(crate) fn body(self) -> &'a [u8] {
        &self.bytes[..self.bytes.len() - HEADER]
    }

    /// Every node before End-Entire, End-Instance separators included.
    pub(crate) fn nodes(self) -> impl Iterator<Item = Node<'a>> {
        let mut rest = self.body();
        core::iter::from_fn(move || {
            // `parse` checked that the body is a whole number of nodes.
            let node = Node::parse(rest)?;
            rest = &rest[node.len()..];
            Some(node)
        })
    }

    /// Whether the path has more than one instance.
    pub(crate) fn is_multi_instance(self) -> bool {
        self.nodes().any(|node| node.is_end_instance())
    }

    /// The first instance, without its terminator, and the remaining path
    /// after an End-Instance separator, if there is one.
    pub(crate) fn split_first_instance(self) -> (&'a [u8], Option<DevicePath<'a>>) {
        let mut offset = 0;
        for node in self.nodes() {
            if node.is_end_instance() {
                let rest = Self {
                    bytes: &self.bytes[offset + HEADER..],
                };
                return (&self.bytes[..offset], Some(rest));
            }
            offset += node.len();
        }
        (self.body(), None)
    }

    /// If `prefix`'s nodes start this path's first instance, the offset just
    /// past them. This is the match LocateDevicePath performs: it never
    /// consumes an instance separator.
    pub(crate) fn strip_prefix(self, prefix: DevicePath<'_>) -> Option<usize> {
        let (first, _) = self.split_first_instance();
        first
            .starts_with(prefix.body())
            .then_some(prefix.body().len())
    }
}

/// One device path node: a four-byte header and its payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Node<'a> {
    bytes: &'a [u8],
}

impl<'a> Node<'a> {
    /// The node at the start of `bytes`, if its length field is at least the
    /// header size and fits within `bytes`.
    pub(crate) fn parse(bytes: &'a [u8]) -> Option<Self> {
        let header = bytes.get(..HEADER)?;
        let len = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if len < HEADER {
            return None;
        }
        Some(Self {
            bytes: bytes.get(..len)?,
        })
    }

    /// View a single node a caller passed by pointer.
    ///
    /// # Safety
    /// `node` must be null or point to one live, initialized allocation that
    /// holds a node header followed by as many bytes as the header's length
    /// field claims, unmodified for `'a`.
    pub(crate) unsafe fn from_raw(node: *const Protocol) -> Option<Self> {
        if node.is_null() {
            return None;
        }
        // SAFETY: the caller guarantees a readable header.
        let header = unsafe { core::slice::from_raw_parts(node.cast::<u8>(), HEADER) };
        let len = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if len < HEADER {
            return None;
        }
        // SAFETY: the caller guarantees the node's claimed length is readable.
        Self::parse(unsafe { core::slice::from_raw_parts(node.cast::<u8>(), len) })
    }

    pub(crate) fn kind(self) -> u8 {
        self.bytes[0]
    }

    pub(crate) fn subtype(self) -> u8 {
        self.bytes[1]
    }

    /// Length including the header.
    pub(crate) fn len(self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Bytes after the header.
    pub(crate) fn payload(self) -> &'a [u8] {
        &self.bytes[HEADER..]
    }

    pub(crate) fn is_end_instance(self) -> bool {
        self.kind() == TYPE_END && self.subtype() == SUBTYPE_END_INSTANCE
    }

    /// `N` bytes at `offset` from the start of the node.
    pub(crate) fn field<const N: usize>(self, offset: usize) -> Option<[u8; N]> {
        self.bytes
            .get(offset..offset.checked_add(N)?)?
            .try_into()
            .ok()
    }

    pub(crate) fn u8_at(self, offset: usize) -> Option<u8> {
        self.bytes.get(offset).copied()
    }

    pub(crate) fn u16_at(self, offset: usize) -> Option<u16> {
        self.field(offset).map(u16::from_le_bytes)
    }

    pub(crate) fn u32_at(self, offset: usize) -> Option<u32> {
        self.field(offset).map(u32::from_le_bytes)
    }

    pub(crate) fn u64_at(self, offset: usize) -> Option<u64> {
        self.field(offset).map(u64::from_le_bytes)
    }
}

/// An End-Entire node.
pub(crate) const END_ENTIRE: [u8; HEADER] = [TYPE_END, SUBTYPE_END_ENTIRE, HEADER as u8, 0];

/// Build `body` followed by an End-Entire node, or `None` when the result
/// would exceed [`MAX_DEVICE_PATH_SIZE`] or the heap cannot hold it.
pub(crate) fn terminated(body: &[&[u8]]) -> Option<Vec<u8>> {
    let len = body
        .iter()
        .try_fold(HEADER, |len, part| len.checked_add(part.len()))
        // Never build a path this firmware would then refuse to read.
        .filter(|&len| len <= MAX_DEVICE_PATH_SIZE)?;
    let mut path = Vec::new();
    path.try_reserve_exact(len).ok()?;
    for part in body {
        path.extend_from_slice(part);
    }
    path.extend_from_slice(&END_ENTIRE);
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PCI: [u8; 6] = [0x01, 0x01, 6, 0, 0, 2];
    const END_INSTANCE: [u8; 4] = [TYPE_END, SUBTYPE_END_INSTANCE, 4, 0];

    #[test]
    fn parse_stops_at_end_entire_and_rejects_malformed_chains() {
        let path = terminated(&[&PCI]).unwrap();
        let mut trailing = path.clone();
        trailing.extend_from_slice(&[0xaa; 3]);
        assert_eq!(DevicePath::parse(&trailing).unwrap().as_bytes(), &path[..]);

        // Truncated, short, overlong and oddly terminated chains.
        assert_eq!(DevicePath::parse(&path[..path.len() - 1]), None);
        assert_eq!(DevicePath::parse(&[0x01, 0x01, 3, 0]), None);
        assert_eq!(DevicePath::parse(&[0x01, 0x01, 0xff, 0xff, 0, 0]), None);
        assert_eq!(
            DevicePath::parse(&[TYPE_END, SUBTYPE_END_ENTIRE, 5, 0, 0]),
            None
        );
        assert_eq!(DevicePath::parse(&[TYPE_END, 0x02, 4, 0]), None);
        assert_eq!(DevicePath::parse(&[]), None);
    }

    #[test]
    fn instances_split_at_end_instance_separators() {
        let path = terminated(&[&PCI, &END_INSTANCE, &PCI, &PCI]).unwrap();
        let path = DevicePath::parse(&path).unwrap();
        assert!(path.is_multi_instance());
        let (first, rest) = path.split_first_instance();
        assert_eq!(first, &PCI);
        let rest = rest.unwrap();
        assert!(!rest.is_multi_instance());
        assert_eq!(
            rest.split_first_instance(),
            (&[PCI, PCI].concat()[..], None)
        );
        assert_eq!(path.nodes().count(), 4);
    }

    #[test]
    fn prefixes_match_whole_nodes() {
        let long = terminated(&[&PCI, &PCI]).unwrap();
        let short = terminated(&[&PCI]).unwrap();
        let long = DevicePath::parse(&long).unwrap();
        let short = DevicePath::parse(&short).unwrap();
        assert_eq!(long.strip_prefix(short), Some(PCI.len()));
        assert_eq!(short.strip_prefix(long), None);

        // A match stops at the first instance, even against an identical
        // multi-instance path.
        let multi = terminated(&[&PCI, &END_INSTANCE, &PCI]).unwrap();
        let multi = DevicePath::parse(&multi).unwrap();
        assert_eq!(multi.strip_prefix(multi), None);
        assert_eq!(multi.strip_prefix(short), Some(PCI.len()));
    }

    #[test]
    fn fields_outside_a_node_are_absent() {
        let node = Node::parse(&PCI).unwrap();
        assert_eq!(node.u8_at(5), Some(2));
        assert_eq!(node.u16_at(5), None);
        assert_eq!(node.u64_at(usize::MAX), None);
        assert_eq!(node.payload(), &[0, 2]);
    }
}
