//! Bounded EFI path decoding and normalization, independent of device I/O.

use super::MAX_PATH_LEN;
use r_efi::efi::{Char16, Status};

pub(super) fn path_str(path: &[u8; MAX_PATH_LEN], len: usize) -> &str {
    core::str::from_utf8(&path[..len]).unwrap_or("")
}

/// # Safety
/// `src` must contain a readable null-terminated UTF-16 string, or at least
/// `MAX_PATH_LEN` readable units when the input is unterminated.
pub(super) unsafe fn utf16_to_utf8(src: *mut Char16, dst: &mut [u8]) -> Result<usize, Status> {
    if src.is_null() || dst.is_empty() {
        return Err(Status::INVALID_PARAMETER);
    }
    let mut len = 0;
    let mut terminated = false;
    let units = (0..MAX_PATH_LEN)
        .map(|index| unsafe { *src.add(index) })
        .take_while(|&unit| {
            if unit == 0 {
                terminated = true;
                false
            } else {
                true
            }
        });
    for ch in core::char::decode_utf16(units) {
        let ch = ch.map_err(|_| Status::INVALID_PARAMETER)?;
        if len + ch.len_utf8() >= dst.len() {
            return Err(Status::INVALID_PARAMETER);
        }
        len += ch.encode_utf8(&mut dst[len..]).len();
    }
    if !terminated {
        return Err(Status::INVALID_PARAMETER);
    }
    dst[len] = 0;
    Ok(len)
}

/// shim/GRUB can prepend a textual hardware device path to a file path.
pub(super) fn strip_device_path_prefix(path: &str) -> &str {
    if !["PciRoot(", "Pci(", "HD(", "Acpi("]
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return path;
    }
    path.rfind(")\\")
        .or_else(|| path.rfind(")/"))
        .map_or(path, |index| &path[index + 2..])
}

pub(super) fn build_full_path(
    parent: &[u8],
    parent_is_directory: bool,
    name: &str,
    output: &mut [u8; MAX_PATH_LEN],
) -> Result<usize, Status> {
    // File.Open on a regular file resolves relative to its containing directory.
    let parent_len = if parent_is_directory {
        parent.len()
    } else {
        parent.iter().rposition(|&byte| byte == b'/').unwrap_or(0)
    };
    let mut path = heapless::String::<MAX_PATH_LEN>::new();
    if !name.starts_with(['/', '\\']) {
        path.push_str(
            core::str::from_utf8(&parent[..parent_len]).map_err(|_| Status::INVALID_PARAMETER)?,
        )
        .map_err(|_| Status::INVALID_PARAMETER)?;
        if !path.is_empty() {
            path.push('/').map_err(|_| Status::INVALID_PARAMETER)?;
        }
    }
    path.push_str(name).map_err(|_| Status::INVALID_PARAMETER)?;
    let mut len = 0;
    for part in path
        .split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != ".")
    {
        if part == ".." {
            len = output[..len]
                .iter()
                .rposition(|&byte| byte == b'/')
                .unwrap_or(0);
            continue;
        }
        if len != 0 {
            output[len] = b'/';
            len += 1;
        }
        if len + part.len() >= output.len() {
            return Err(Status::INVALID_PARAMETER);
        }
        output[len..len + part.len()].copy_from_slice(part.as_bytes());
        len += part.len();
    }
    output[len] = 0;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn relative_absolute_and_parent_paths_are_normalized_without_truncation() {
        for (parent, directory, name, expected) in [
            ("dir/file", false, "peer", "dir/peer"),
            ("dir", true, "peer", "dir/peer"),
            ("dir", true, "../../x", "x"),
            ("dir", true, "\\root\\.\\foo\\..\\bar", "root/bar"),
        ] {
            let mut output = [0; MAX_PATH_LEN];
            let len = build_full_path(parent.as_bytes(), directory, name, &mut output).unwrap();
            assert_eq!(path_str(&output, len), expected);
        }
        assert!(
            build_full_path(&[], true, &"x".repeat(MAX_PATH_LEN), &mut [0; MAX_PATH_LEN]).is_err()
        );
    }

    #[test]
    fn utf16_is_decoded_and_requires_valid_termination() {
        let mut encoded: Vec<_> = "é😀".encode_utf16().chain(core::iter::once(0)).collect();
        let mut output = [0; MAX_PATH_LEN];
        let len = unsafe { utf16_to_utf8(encoded.as_mut_ptr(), &mut output) }.unwrap();
        assert_eq!(path_str(&output, len), "é😀");
        assert!(unsafe { utf16_to_utf8([0xd800, 0].as_mut_ptr(), &mut output) }.is_err());
        assert!(
            unsafe { utf16_to_utf8([b'x' as u16; MAX_PATH_LEN].as_mut_ptr(), &mut output) }
                .is_err()
        );
    }
}
